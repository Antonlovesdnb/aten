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

#[derive(Clone)]
pub struct EngineConfig {
    pub transcript_path: PathBuf,
    /// Function used to resolve the cwd of an agent-root process, called
    /// at attribution time. The default implementation reads
    /// `/proc/<pid>/cwd` — correct on Linux, returns `None` on Windows
    /// because that path doesn't exist. Windows daemons inject a
    /// PEB-walk-based resolver from `fishbowl_collector_windows::query_cwd`
    /// so the engine stays platform-agnostic.
    pub cwd_for_pid: fn(i32) -> Option<String>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            transcript_path: PathBuf::new(),
            cwd_for_pid: default_cwd_for_pid,
        }
    }
}

/// Default cwd resolver. Linux: reads `/proc/<pid>/cwd`. Everywhere else:
/// returns `None` (and the daemon is expected to inject a real resolver).
pub fn default_cwd_for_pid(pid: i32) -> Option<String> {
    let _ = pid;
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/cwd"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
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
            EventKind::CredentialAccess(c) => c.process.agent_root_pid,
            EventKind::NetworkEgress(n) => n.process.agent_root_pid,
            EventKind::FileWrite(f) => f.process.agent_root_pid,
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
            EventKind::CredentialAccess(c) => {
                // For credential_access the primary identifier is the file_path
                // itself — there's no haystack to extract from. We still run it
                // through the same normalization used for the origin index so
                // matches against transcript-side mentions of the same path
                // (which may have used `~/...` or different casing) hit.
                let path = c.file_path.clone();
                let normalized = fishbowl_transcript::normalize(&path, None);
                if let Some(tc) = tc {
                    c.attribution.attributed_tool_call_id = Some(tc.id.clone());
                    c.attribution.time_window_ms =
                        Some(((event_ns - tc.timestamp_ns).max(0) / 1_000_000) as u64);
                    // Tool-call args may reference the path verbatim, in ~/
                    // form, or by relative path. Substring-match in both the
                    // raw and normalized forms.
                    c.attribution.requested_by_tool_call = tc.input_text.contains(&path)
                        || tc.input_text.to_lowercase().contains(&normalized);
                }
                // Identifier-origin lookup: use the normalized path as the key
                // (origin index stores normalized identifiers).
                if let Some(entry) = session.identifier_index.entries.get(&normalized) {
                    for o in &entry.origins {
                        match o {
                            fishbowl_schema::Origin::UserMessage => {
                                c.attribution.requested_in_user_message = true;
                            }
                            fishbowl_schema::Origin::AssistantMessage => {
                                c.attribution.requested_in_assistant_message = true;
                            }
                            fishbowl_schema::Origin::ToolResult => {
                                c.attribution.requested_in_tool_result = true;
                            }
                        }
                    }
                }
            }
            EventKind::NetworkEgress(n) => {
                // Primary identifier for an egress event is the IP and the
                // hostname (when known). We check whatever's populated: the
                // tool_call's input or any prompt may reference either form.
                // Without TLS SNI capture, dest_host is None for v0.x; the
                // attribution falls back to IP-only matching, which is what
                // the malicious-npm demo needs (the user's prompt did not
                // mention the beacon IP).
                let ip = n.dest_ip.clone();
                let host = n.dest_host.clone().unwrap_or_default();
                if let Some(tc) = tc {
                    n.attribution.attributed_tool_call_id = Some(tc.id.clone());
                    n.attribution.time_window_ms =
                        Some(((event_ns - tc.timestamp_ns).max(0) / 1_000_000) as u64);
                    n.attribution.requested_by_tool_call =
                        tc.input_text.contains(&ip)
                            || (!host.is_empty() && tc.input_text.contains(&host));
                }
                let mut origins = session.origins_for_text(&ip);
                if !host.is_empty() {
                    let host_origins = session.origins_for_text(&host);
                    origins.user_message |= host_origins.user_message;
                    origins.assistant_message |= host_origins.assistant_message;
                    origins.tool_result |= host_origins.tool_result;
                }
                n.attribution.requested_in_user_message = origins.user_message;
                n.attribution.requested_in_assistant_message = origins.assistant_message;
                n.attribution.requested_in_tool_result = origins.tool_result;
            }
            // FileWrite probe still pending.
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
        let proc_cwd = (self.cfg.cwd_for_pid)(agent_root_pid)?;
        // Match either exact or one is a path prefix of the other to absorb
        // symlink resolution variance on Linux, and to absorb minor case /
        // separator differences on Windows where DosPath may come back with
        // a different case than the transcript-recorded cwd. Simple string
        // compare in lowercase for cross-platform robustness.
        let a = proc_cwd.to_lowercase().replace('\\', "/");
        let b = session_cwd.to_lowercase().replace('\\', "/");
        if a == b || a.starts_with(&b) || b.starts_with(&a) {
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

    /// Cmdline identifier appears in the tool_call's input → requested_by_tool_call true.
    #[test]
    fn identifiers_in_tool_input_match() {
        assert!(identifiers_appear_in(
            "/tmp/fakeclaude 1",
            r#"{"command": "/tmp/fakeclaude 1"}"#,
        ));
    }

    #[test]
    fn identifiers_not_in_tool_input_no_match() {
        assert!(!identifiers_appear_in(
            "cat /home/anton/.aws/credentials",
            r#"{"command": "npm install lodash"}"#,
        ));
    }
}
