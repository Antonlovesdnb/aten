//! fishbowl-v2 attribution engine.
//!
//! Stitches transcript-side state (prompts, tool_calls, tool_results,
//! identifier-origin index) to kernel-side events (process_exec, eventually
//! credential_access and network_egress) so that each emitted event arrives
//! with `attributed_tool_call_id` and the four `requested_*` booleans
//! populated.
//!
//! Operating model for v0.x:
//! - The engine is configured with a single transcript file (one Claude Code
//!   session). Multi-session support is deferred — needs file watching and
//!   per-cwd session resolution that's out of scope for this milestone.
//! - On startup the engine parses the transcript and builds SessionState.
//! - `refresh()` is called periodically to fold in new transcript records.
//! - `attribute(&mut event)` mutates a kernel-side event in place: binds it
//!   to the session by matching `agent_root_pid`'s `/proc/<pid>/cwd` against
//!   the session's recorded cwd (cached after first successful match), then
//!   sets the attribution booleans using the most-recent tool_call's args
//!   plus the identifier-origin index.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use fishbowl_schema::{Event, EventKind};

pub mod session;

use session::SessionState;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub transcript_path: PathBuf,
}

pub struct AttributionEngine {
    cfg: EngineConfig,
    session: Option<SessionState>,
    /// Resolved agent_root_pid → session_id binding. Populated lazily on the
    /// first kernel event whose process cwd matches the session's cwd.
    pid_bindings: HashMap<i32, String>,
}

impl AttributionEngine {
    pub fn new(cfg: EngineConfig) -> Self {
        Self {
            cfg,
            session: None,
            pid_bindings: HashMap::new(),
        }
    }

    /// Read the transcript, build (or update) the per-session state. Call this
    /// on startup and on each refresh tick.
    pub fn refresh(&mut self) -> Result<()> {
        let (session_id, events) = session::load_sessions_from_file(&self.cfg.transcript_path)?;
        if session_id.is_empty() {
            return Ok(());
        }
        let cwd = session::cwd_from_transcript_raw(&self.cfg.transcript_path);
        match &mut self.session {
            Some(state) if state.session_id == session_id => {
                state.refresh(&events);
                if state.cwd.is_none() {
                    state.cwd = cwd;
                }
            }
            _ => {
                self.session = Some(SessionState::from_events(session_id, &events, cwd));
            }
        }
        Ok(())
    }

    /// Mutate a kernel-side event in place to fill in attribution. Currently
    /// handles `ProcessExec`; the same approach will extend to
    /// `CredentialAccess`, `NetworkEgress`, and `FileWrite` as those probes
    /// come online.
    pub fn attribute(&mut self, event: &mut Event) {
        // Snapshot the bits of session state we need for the binding decision
        // up front so we don't hold a borrow on `self.session` while we mutate
        // `self.pid_bindings`. Cheap clones (a Uuid string and an Option<cwd>).
        let (session_id, session_cwd) = match &self.session {
            Some(s) => (s.session_id.clone(), s.cwd.clone()),
            None => return,
        };

        let agent_root_pid = match &event.kind {
            EventKind::ProcessExec(p) => p.process.agent_root_pid,
            _ => None,
        };

        let bound_session = match agent_root_pid {
            Some(pid) => self.resolve_session_for_pid(pid, &session_id, session_cwd.as_deref()),
            None => None,
        };

        let Some(sid) = bound_session else {
            // Without a session binding, attribution stays empty — we still
            // emit the event so the join can happen later in the SIEM.
            return;
        };
        event.session_id = Some(sid);

        // Now we can re-borrow `self.session` immutably for the rest of the
        // attribution work; the binding-cache mutation is done.
        let Some(session) = &self.session else {
            return;
        };

        let event_ns = session::parse_rfc3339_ns(&event.timestamp).unwrap_or(i64::MAX);
        let tc = session.attribute_at(event_ns);

        match &mut event.kind {
            EventKind::ProcessExec(p) => {
                let primary_identifier = p.process.cmdline.clone();
                if let Some(tc) = tc {
                    p.attribution.attributed_tool_call_id = Some(tc.id.clone());
                    p.attribution.time_window_ms =
                        Some(((event_ns - tc.timestamp_ns).max(0) / 1_000_000) as u64);
                    p.attribution.requested_by_tool_call =
                        identifiers_appear_in(&primary_identifier, &tc.input_text);
                }
                let origins = session.origins_for_text(&primary_identifier);
                p.attribution.requested_in_user_message = origins.user_message;
                p.attribution.requested_in_assistant_message = origins.assistant_message;
                p.attribution.requested_in_tool_result = origins.tool_result;
            }
            // CredentialAccess / NetworkEgress / FileWrite follow the same
            // shape — primary identifier differs (file_path or dest_host etc).
            // Wire them when the probes land.
            _ => {}
        }
    }

    fn resolve_session_for_pid(
        &mut self,
        agent_root_pid: i32,
        session_id: &str,
        session_cwd: Option<&str>,
    ) -> Option<String> {
        if let Some(sid) = self.pid_bindings.get(&agent_root_pid) {
            return Some(sid.clone());
        }
        let session_cwd = session_cwd?;
        if session_cwd.is_empty() {
            return None;
        }
        let proc_cwd = std::fs::read_link(format!("/proc/{agent_root_pid}/cwd"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())?;
        // Match either exact or one is a path prefix of the other to absorb
        // symlink resolution variance. Simple string compare for v0.x.
        if proc_cwd == session_cwd
            || proc_cwd.starts_with(session_cwd)
            || session_cwd.starts_with(&proc_cwd)
        {
            self.pid_bindings
                .insert(agent_root_pid, session_id.to_string());
            Some(session_id.to_string())
        } else {
            None
        }
    }
}

/// Extract identifiers from `cmdline` and check whether each appears as a
/// substring of `tool_input_text`. Used for `requested_by_tool_call`. The
/// tool_input is stringified JSON, so we just substring-match — the same
/// content appears as-typed inside the JSON.
fn identifiers_appear_in(cmdline: &str, tool_input_text: &str) -> bool {
    for ident in fishbowl_transcript::extract(cmdline) {
        if tool_input_text.contains(&ident) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use fishbowl_schema::*;

    fn make_exec(cmdline: &str, agent_root_pid: i32, ts: &str) -> Event {
        Event {
            schema_version: SCHEMA_VERSION.into(),
            event_id: "test".into(),
            timestamp: ts.into(),
            monotonic_ns: None,
            platform: Platform::Linux,
            host_id: None,
            agent_id: "claude".into(),
            session_id: None,
            user_id: None,
            source: Source {
                collector: "linux_ebpf".into(),
                probe: "test".into(),
                host_pid: None,
            },
            kind: EventKind::ProcessExec(ProcessExecPayload {
                process: Process {
                    pid: 1,
                    ppid: 0,
                    start_time: "0".into(),
                    name: "node".into(),
                    path: "/usr/bin/node".into(),
                    cmdline: cmdline.into(),
                    cwd: "/home/anton/proj".into(),
                    user: "anton".into(),
                    integrity_level: None,
                    parent_chain: vec![],
                    agent_root_pid: Some(agent_root_pid),
                },
                attribution: Attribution {
                    attributed_tool_call_id: None,
                    attributed_by_descent: true,
                    requested_by_tool_call: false,
                    requested_in_user_message: false,
                    requested_in_assistant_message: false,
                    requested_in_tool_result: false,
                    time_window_ms: None,
                },
                exec_args: vec![],
                exec_envp_summary: String::new(),
            }),
        }
    }

    /// Cmdline identifier appears in the tool_call's input → requested_by_tool_call true.
    #[test]
    fn identifiers_in_tool_input_match() {
        let assert_true = identifiers_appear_in(
            "/tmp/fakeclaude 1",
            r#"{"command": "/tmp/fakeclaude 1"}"#,
        );
        assert!(assert_true);
    }

    #[test]
    fn identifiers_not_in_tool_input_no_match() {
        let assert_false = identifiers_appear_in(
            "cat /home/anton/.aws/credentials",
            r#"{"command": "npm install lodash"}"#,
        );
        assert!(!assert_false);
    }
}
