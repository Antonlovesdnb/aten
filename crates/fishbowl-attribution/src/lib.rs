//! fishbowl-v2 attribution engine.
//!
//! Stitches transcript-side state (prompts, tool_calls, tool_results,
//! identifier-origin index) to kernel-side events (process_exec,
//! credential_access, network_egress) so that each emitted event arrives
//! with `attributed_tool_call_id` and the four `requested_*` booleans
//! populated.
//!
//! Operating model:
//! - The engine is configured with a list of transcript *paths* — either
//!   individual JSONL files or directories that are recursively scanned
//!   for `*.jsonl`. Both Claude Code (`~/.claude/projects/`) and Codex
//!   (`~/.codex/sessions/`) directory layouts are supported; dialect is
//!   auto-detected per file from its path.
//! - On each `refresh()` tick the engine walks every configured path,
//!   checks each `.jsonl` file's mtime, and re-parses any that changed.
//!   Per-session state is keyed by transcript-recorded `session_id` and
//!   kept in a `HashMap`, so multiple concurrent Claude / Codex sessions
//!   can be attributed against from the same daemon instance.
//! - `attribute(&mut event)` mutates a kernel-side event in place: looks
//!   up the agent_root_pid's cwd via the platform-specific
//!   `cwd_for_pid` resolver, finds whichever session's cwd matches, then
//!   sets the attribution booleans from that session's most-recent
//!   tool_call and identifier-origin index.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Result;
use fishbowl_schema::{Event, EventKind};
use fishbowl_transcript::detect_dialect_from_path;

pub mod session;

use session::SessionState;

#[derive(Clone)]
pub struct EngineConfig {
    /// One or more transcript sources. Each entry can be either:
    /// - A path to a single transcript JSONL file (single-session mode,
    ///   used by the legacy `--transcript` daemon flag and the
    ///   `fishbowl transcript` subcommand)
    /// - A path to a directory which is recursively scanned for
    ///   `*.jsonl` files. The service-mode config typically lists
    ///   `~/.claude/projects/` and `~/.codex/sessions/` here, and the
    ///   engine picks up every session inside.
    ///
    /// Empty vec = no transcripts loaded; the engine still runs (events
    /// pass through unattributed). Useful for kernel-only deployment.
    pub transcript_paths: Vec<PathBuf>,
    /// Function used to resolve the cwd of an agent-root process, called
    /// at attribution time. The default implementation reads
    /// `/proc/<pid>/cwd` — correct on Linux, returns `None` on Windows
    /// because that path doesn't exist. Windows daemons inject a
    /// PEB-walk-based resolver from `fishbowl_collector_windows::query_cwd`
    /// so the engine stays platform-agnostic.
    pub cwd_for_pid: fn(i32) -> Option<String>,
    /// MachineGuid (or equivalent host identifier) to stamp on
    /// transcript-derived events. The transcript reader sets host_id to
    /// None because transcripts don't carry host info; the daemon
    /// enriches at emit time. Same value the kernel collector stamps on
    /// its own events, so kernel and transcript events from the same
    /// host correlate cleanly downstream.
    pub host_id: Option<String>,
    /// Resolve the file-owner of a transcript file → `DOMAIN\username`
    /// (Windows) or `username` (Linux), used as `user_id` on
    /// transcript-derived events. The default returns None; the daemon
    /// injects a platform-specific implementation. Cached per file in
    /// the engine, so each transcript is queried once even across many
    /// refresh ticks.
    pub user_for_transcript: fn(&Path) -> Option<String>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            transcript_paths: Vec::new(),
            cwd_for_pid: default_cwd_for_pid,
            host_id: None,
            user_for_transcript: default_user_for_transcript,
        }
    }
}

/// Default user-lookup. Returns None on every platform; the daemon
/// injects a real implementation.
pub fn default_user_for_transcript(path: &Path) -> Option<String> {
    let _ = path;
    None
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

#[derive(Debug)]
struct FileMeta {
    mtime: SystemTime,
    /// File owner resolved on first sight (DOMAIN\username on Windows;
    /// username on Linux). Cached because file ownership rarely changes
    /// and the lookup is a Win32 syscall we don't want to do per event.
    user_id: Option<String>,
}

pub struct AttributionEngine {
    cfg: EngineConfig,
    sessions: HashMap<String, SessionState>,
    /// File mtime cache. Lets refresh() skip re-reading transcripts whose
    /// on-disk timestamp hasn't moved since last refresh.
    file_meta: HashMap<PathBuf, FileMeta>,
    /// Resolved agent_root_pid → session_id binding. Populated lazily on
    /// the first kernel event whose process cwd matches a session's cwd.
    pid_bindings: HashMap<i32, String>,
    /// Engine creation time (RFC 3339 ns). Transcript events with a
    /// timestamp older than this are loaded into SessionState for
    /// attribution context but NOT returned from `refresh()` — the
    /// daemon only wants to emit prompts / tool_calls / tool_results
    /// that happened *while it was running*, not the historical record
    /// of every session that existed on disk at startup.
    start_time_ns: i64,
}

impl AttributionEngine {
    pub fn new(cfg: EngineConfig) -> Self {
        let start_time_ns = chrono::Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or(i64::MIN);
        Self {
            cfg,
            sessions: HashMap::new(),
            file_meta: HashMap::new(),
            pid_bindings: HashMap::new(),
            start_time_ns,
        }
    }

    /// Walk all configured transcript paths, load any new or modified
    /// JSONL files, fold their events into the matching SessionState.
    /// Called on startup and on every poll tick (~500 ms in the daemon).
    ///
    /// Returns transcript events that are both **new since the previous
    /// refresh of that file** and **newer than the engine's start time**.
    /// The daemon emits these to its output sink alongside kernel events,
    /// giving a unified prompt-and-syscall stream. Historic transcript
    /// content (sessions that already existed on disk at startup) is
    /// silently absorbed into SessionState for attribution context but
    /// not re-emitted — restarting the service shouldn't replay history.
    pub fn refresh(&mut self) -> Result<Vec<Event>> {
        let mut new_events: Vec<Event> = Vec::new();
        for path in self.cfg.transcript_paths.clone() {
            self.refresh_path(&path, &mut new_events);
        }
        Ok(new_events)
    }

    fn refresh_path(&mut self, path: &Path, new_events: &mut Vec<Event>) {
        match std::fs::metadata(path) {
            Ok(md) if md.is_file() => {
                self.refresh_file(path.to_path_buf(), md.modified().ok(), new_events);
            }
            Ok(md) if md.is_dir() => {
                let mut files: Vec<(PathBuf, Option<SystemTime>)> = Vec::new();
                walk_jsonl(path, &mut |file| {
                    let mtime = std::fs::metadata(&file).and_then(|m| m.modified()).ok();
                    files.push((file, mtime));
                });
                for (file, mtime) in files {
                    self.refresh_file(file, mtime, new_events);
                }
            }
            _ => {} // path doesn't exist yet — fine, will appear later
        }
    }

    fn refresh_file(
        &mut self,
        file: PathBuf,
        mtime: Option<SystemTime>,
        new_events: &mut Vec<Event>,
    ) {
        // Skip files we've already loaded that haven't changed.
        if let (Some(meta), Some(mt)) = (self.file_meta.get(&file), mtime) {
            if meta.mtime >= mt {
                return;
            }
        }

        let dialect = detect_dialect_from_path(&file);
        let (session_id, events) = match session::load_sessions_from_file(&file, dialect) {
            Ok(x) => x,
            Err(_) => return, // unreadable / mid-write — try again next tick
        };
        if session_id.is_empty() {
            return;
        }
        let cwd = session::cwd_from_transcript_raw(&file, dialect);

        // Capture the "previous cursor" before mutating SessionState, so
        // we can slice out events that are new in *this* refresh tick.
        let prev_cursor = self
            .sessions
            .get(&session_id)
            .map(|s| s.processed_event_count)
            .unwrap_or(0);

        match self.sessions.get_mut(&session_id) {
            Some(state) => {
                state.refresh(&events);
                if state.cwd.is_none() {
                    state.cwd = cwd;
                }
            }
            None => {
                self.sessions.insert(
                    session_id.clone(),
                    SessionState::from_events(session_id.clone(), &events, cwd),
                );
            }
        }
        // Resolve and cache the file owner. Look it up once per file —
        // ownership is stable so we don't want to syscall on every tick.
        let user_id = match self.file_meta.get(&file) {
            Some(meta) => meta.user_id.clone(),
            None => (self.cfg.user_for_transcript)(&file),
        };
        if let Some(mt) = mtime {
            self.file_meta.insert(
                file.clone(),
                FileMeta {
                    mtime: mt,
                    user_id: user_id.clone(),
                },
            );
        }

        // Emit only the events past the prior cursor AND newer than the
        // engine's startup time. The startup-time filter is what makes a
        // service restart cheap: existing transcripts get folded into
        // SessionState but their historical contents don't replay to the
        // output sink. Stamp host_id and user_id on each — the transcript
        // reader leaves those null because they aren't in the source
        // JSONL; the daemon enriches at emit time.
        for ev in events.iter().skip(prev_cursor) {
            let Some(ts_ns) = session::parse_rfc3339_ns(&ev.timestamp) else {
                continue;
            };
            if ts_ns < self.start_time_ns {
                continue;
            }
            let mut enriched = ev.clone();
            if enriched.host_id.is_none() {
                enriched.host_id = self.cfg.host_id.clone();
            }
            if enriched.user_id.is_none() {
                enriched.user_id = user_id.clone();
            }
            new_events.push(enriched);
        }
    }

    /// Mutate a kernel-side event in place to fill in attribution. Looks
    /// up the event's agent_root_pid → session binding, then sets the
    /// tool_call ID, time window, and four `requested_*` booleans from
    /// the matched session's state.
    pub fn attribute(&mut self, event: &mut Event) {
        let agent_root_pid = match &event.kind {
            EventKind::ProcessExec(p) => p.process.agent_root_pid,
            EventKind::CredentialAccess(c) => c.process.agent_root_pid,
            EventKind::NetworkEgress(n) => n.process.agent_root_pid,
            EventKind::FileWrite(f) => f.process.agent_root_pid,
            _ => None,
        };

        let Some(pid) = agent_root_pid else { return };
        let Some(session_id) = self.resolve_session_for_pid(pid) else {
            return;
        };
        event.session_id = Some(session_id.clone());

        let Some(session) = self.sessions.get(&session_id) else {
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
                let path = c.file_path.clone();
                let normalized = fishbowl_transcript::normalize(&path, None);
                if let Some(tc) = tc {
                    c.attribution.attributed_tool_call_id = Some(tc.id.clone());
                    c.attribution.time_window_ms =
                        Some(((event_ns - tc.timestamp_ns).max(0) / 1_000_000) as u64);
                    c.attribution.requested_by_tool_call = tc.input_text.contains(&path)
                        || tc.input_text.to_lowercase().contains(&normalized);
                }
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
                let ip = n.dest_ip.clone();
                let host = n.dest_host.clone().unwrap_or_default();
                if let Some(tc) = tc {
                    n.attribution.attributed_tool_call_id = Some(tc.id.clone());
                    n.attribution.time_window_ms =
                        Some(((event_ns - tc.timestamp_ns).max(0) / 1_000_000) as u64);
                    n.attribution.requested_by_tool_call = tc.input_text.contains(&ip)
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
            _ => {}
        }
    }

    /// Resolve which session an agent_root_pid belongs to by matching the
    /// process's cwd (queried via the platform-specific resolver) against
    /// each loaded session's recorded cwd. Caches the answer on success
    /// so subsequent events from the same pid take the fast path.
    ///
    /// Normalization (lowercase + forward-slash) absorbs case / separator
    /// differences between the live cwd and the transcript cwd —
    /// `C:\Users\…` vs `c:\users\…` vs `C:/Users/…` all match.
    fn resolve_session_for_pid(&mut self, agent_root_pid: i32) -> Option<String> {
        if let Some(sid) = self.pid_bindings.get(&agent_root_pid) {
            return Some(sid.clone());
        }
        let proc_cwd = (self.cfg.cwd_for_pid)(agent_root_pid)?;
        let a = norm_cwd(&proc_cwd);
        if a.is_empty() {
            return None;
        }
        for (sid, state) in &self.sessions {
            let Some(cwd) = state.cwd.as_deref() else {
                continue;
            };
            let b = norm_cwd(cwd);
            if b.is_empty() {
                continue;
            }
            if a == b || a.starts_with(&b) || b.starts_with(&a) {
                self.pid_bindings.insert(agent_root_pid, sid.clone());
                return Some(sid.clone());
            }
        }
        None
    }

    /// How many transcript sessions are currently loaded. Useful for
    /// service startup logging.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

fn norm_cwd(s: &str) -> String {
    s.to_lowercase().replace('\\', "/").trim_end_matches('/').to_string()
}

/// Recursively walk `dir`, invoking `cb` for every `*.jsonl` file. No
/// follow-symlinks. Errors (permission denied on a subdir, etc.) are
/// swallowed silently — the daemon-tick loop should be robust to
/// transient filesystem hiccups.
fn walk_jsonl(dir: &Path, cb: &mut dyn FnMut(PathBuf)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            walk_jsonl(&path, cb);
        } else if ft.is_file() && path.extension().map_or(false, |e| e == "jsonl") {
            cb(path);
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

    #[test]
    fn cwd_normalization_absorbs_case_and_separator() {
        assert_eq!(norm_cwd(r"C:\Users\Anton\Proj"), "c:/users/anton/proj");
        assert_eq!(norm_cwd("/home/anton/proj/"), "/home/anton/proj");
        assert_eq!(norm_cwd("C:/Users/Anton/Proj/"), "c:/users/anton/proj");
    }
}
