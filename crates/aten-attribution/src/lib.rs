//! ATEN attribution engine.
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
use aten_schema::{Event, EventKind};
use aten_transcript::detect_dialect_from_path;

pub mod session;

use session::SessionState;

#[derive(Clone)]
pub struct EngineConfig {
    /// One or more transcript sources. Each entry can be either:
    /// - A path to a single transcript JSONL file (single-session mode,
    ///   used by the legacy `--transcript` daemon flag and the
    ///   `aten transcript` subcommand)
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
    /// PEB-walk-based resolver from `aten_collector_windows::query_cwd`
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
    /// Optional path to a JSON state file that persists per-transcript
    /// emission cursors across service restarts. `None` = no persistence
    /// (the engine still works; restarts replay no history because the
    /// initial-sight cursor for each new file is set to its current
    /// length). Service-mode default: `%ProgramData%\aten\state.json`.
    pub state_path: Option<PathBuf>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            transcript_paths: Vec::new(),
            cwd_for_pid: default_cwd_for_pid,
            host_id: None,
            user_for_transcript: default_user_for_transcript,
            state_path: None,
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
    mtime: Option<SystemTime>,
    /// File owner resolved on first sight (DOMAIN\username on Windows;
    /// username on Linux). Cached because file ownership rarely changes
    /// and the lookup is a Win32 syscall we don't want to do per event.
    user_id: Option<String>,
    /// Cursor — count of events already emitted to the daemon's sink.
    /// On first sight of a file that's NOT in the persisted state file,
    /// this is initialized to the file's current length, so historical
    /// content gets folded into SessionState (for attribution) but
    /// doesn't replay to the output. Across service restarts the cursor
    /// is loaded from `state.json` so emission resumes exactly where it
    /// left off, with no gap and no duplication.
    emitted_count: usize,
    /// True if this entry came from the persisted state file at startup.
    /// New files seen at runtime get `emitted_count = events.len()` on
    /// first sight; files loaded from state get whatever the file said.
    from_persisted_state: bool,
}

/// On-disk shape of `state.json`. Held to a small Serde struct so we can
/// add fields later without breaking forward-compat (unknown fields are
/// ignored on load).
#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
struct PersistedState {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    files: HashMap<PathBuf, PersistedFile>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
struct PersistedFile {
    emitted_count: usize,
}

pub struct AttributionEngine {
    cfg: EngineConfig,
    sessions: HashMap<String, SessionState>,
    /// Per-file metadata: mtime cache (for refresh skip), file owner
    /// cache, and the emission cursor that persists across restarts.
    file_meta: HashMap<PathBuf, FileMeta>,
    /// Resolved agent_root_pid → session_id binding. Populated lazily on
    /// the first kernel event whose process cwd matches a session's cwd.
    pid_bindings: HashMap<i32, String>,
    /// Dirty flag — true if emission cursors have advanced since the
    /// last `save_state()`. The daemon calls `save_state()` whenever
    /// refresh() returns events; this flag avoids writing the state
    /// file on no-op ticks.
    state_dirty: bool,
}

impl AttributionEngine {
    pub fn new(cfg: EngineConfig) -> Self {
        let mut engine = Self {
            cfg,
            sessions: HashMap::new(),
            file_meta: HashMap::new(),
            pid_bindings: HashMap::new(),
            state_dirty: false,
        };
        // Best-effort load of the persisted state file. If it doesn't
        // exist (fresh install) or can't be parsed, start clean — first
        // refresh will populate from-scratch cursors.
        if let Some(path) = engine.cfg.state_path.clone() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                if let Ok(state) = serde_json::from_str::<PersistedState>(&text) {
                    for (file, pf) in state.files {
                        engine.file_meta.insert(
                            file,
                            FileMeta {
                                mtime: None,
                                user_id: None,
                                emitted_count: pf.emitted_count,
                                from_persisted_state: true,
                            },
                        );
                    }
                }
            }
        }
        engine
    }

    /// Write the current emission cursors to `state_path` (atomic via
    /// temp + rename). No-op when no `state_path` is configured or when
    /// nothing has changed since the last save.
    pub fn save_state(&mut self) -> Result<()> {
        if !self.state_dirty {
            return Ok(());
        }
        let Some(ref path) = self.cfg.state_path else {
            self.state_dirty = false;
            return Ok(());
        };
        let mut files: HashMap<PathBuf, PersistedFile> = HashMap::new();
        for (file, meta) in &self.file_meta {
            files.insert(
                file.clone(),
                PersistedFile {
                    emitted_count: meta.emitted_count,
                },
            );
        }
        let state = PersistedState {
            version: 1,
            files,
        };
        let text = serde_json::to_string(&state)?;
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)?;
        self.state_dirty = false;
        Ok(())
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
        // Persisted-state entries have mtime=None, so they always
        // re-read on first encounter (we don't trust an old mtime
        // across restarts).
        if let (Some(meta), Some(mt)) = (self.file_meta.get(&file), mtime) {
            if let Some(prev_mt) = meta.mtime {
                if prev_mt >= mt {
                    return;
                }
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

        // Determine emission cursor:
        //  - File was loaded from state.json (`from_persisted_state`):
        //    use the persisted `emitted_count`. May be less than
        //    `events.len()` if events accrued while the service was off;
        //    we'll emit the missed ones.
        //  - File seen for the first time at runtime (no persisted
        //    state): set cursor to `events.len()` so historical content
        //    gets folded into SessionState but doesn't replay to the
        //    sink. Subsequent refreshes will emit the delta.
        let existing = self.file_meta.get(&file);
        let emit_cursor = match existing {
            Some(meta) if meta.from_persisted_state => meta.emitted_count.min(events.len()),
            Some(meta) => meta.emitted_count.min(events.len()),
            None => events.len(),
        };
        // Resolve and cache the file owner. State-loaded entries have
        // `user_id: None` (we don't persist user_id to disk), so we have
        // to actually look it up on the first refresh that touches the
        // file at runtime — not just on first-ever sight. Once cached,
        // subsequent refreshes use the cached value.
        let user_id = match existing.and_then(|m| m.user_id.clone()) {
            Some(u) => Some(u),
            None => (self.cfg.user_for_transcript)(&file),
        };

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

        // Stamp host_id and user_id on each emitted event — the transcript
        // reader leaves those null because they aren't in the source
        // JSONL; the daemon enriches at emit time.
        let prev_cursor = emit_cursor;
        for ev in events.iter().skip(prev_cursor) {
            let mut enriched = ev.clone();
            if enriched.host_id.is_none() {
                enriched.host_id = self.cfg.host_id.clone();
            }
            if enriched.user_id.is_none() {
                enriched.user_id = user_id.clone();
            }
            new_events.push(enriched);
        }

        // Update cursor + cached file metadata. If any events were
        // actually emitted past the cursor, flag state dirty so the
        // daemon's next save_state() persists this advance.
        let new_emitted_count = events.len();
        if new_emitted_count > emit_cursor {
            self.state_dirty = true;
        }
        self.file_meta.insert(
            file,
            FileMeta {
                mtime,
                user_id,
                emitted_count: new_emitted_count,
                from_persisted_state: false,
            },
        );
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
            EventKind::DnsQuery(d) => d.process.agent_root_pid,
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

        // Confidence threshold for tool_call-derived fields. Below this
        // window the binding is trustworthy; above it, the transcript-
        // flush race may have left us pointing at a stale prior
        // tool_call. Make the field semantics honest: populate when
        // confident, null otherwise. 10s comfortably covers normal
        // Claude flush cadence (<2s) while still rejecting the
        // pathological multi-minute cases.
        const ATTRIBUTION_CONFIDENCE_MS: u64 = 10_000;
        let (confident_tc, time_window_ms) = match tc {
            Some(t) => {
                let win = ((event_ns - t.timestamp_ns).max(0) / 1_000_000) as u64;
                if win <= ATTRIBUTION_CONFIDENCE_MS {
                    (Some(t), Some(win))
                } else {
                    (None, None)
                }
            }
            None => (None, None),
        };

        // Most-recent user prompt — always populate when available.
        // User prompts don't suffer the transcript-flush race that
        // delays assistant-side records, so this field is reliable
        // even when the tool_call binding isn't.
        let triggering_prompt = session
            .most_recent_user_prompt_before(event_ns)
            .map(|p| p.text.clone());

        // Extract a human-readable command from the tool_input. For
        // Bash/PowerShell-style tools that have a `command` field, use
        // that string; for everything else, the stringified input is
        // close enough.
        let triggering_command = confident_tc.map(|t| extract_command(&t.input_text));

        match &mut event.kind {
            EventKind::ProcessExec(p) => {
                let primary_identifier = p.process.cmdline.clone();
                if let Some(tc) = confident_tc {
                    p.attribution.attributed_tool_call_id = Some(tc.id.clone());
                    p.attribution.time_window_ms = time_window_ms;
                    p.attribution.requested_by_tool_call =
                        identifiers_appear_in(&primary_identifier, &tc.input_text);
                }
                p.attribution.triggering_command = triggering_command;
                p.attribution.triggering_prompt = triggering_prompt;
                let origins = session.origins_for_text(&primary_identifier);
                p.attribution.requested_in_user_message = origins.user_message;
                p.attribution.requested_in_assistant_message = origins.assistant_message;
                p.attribution.requested_in_tool_result = origins.tool_result;
            }
            EventKind::CredentialAccess(c) => {
                let path = c.file_path.clone();
                let normalized = aten_transcript::normalize(&path, None);
                if let Some(tc) = confident_tc {
                    c.attribution.attributed_tool_call_id = Some(tc.id.clone());
                    c.attribution.time_window_ms = time_window_ms;
                    c.attribution.requested_by_tool_call = tc.input_text.contains(&path)
                        || tc.input_text.to_lowercase().contains(&normalized);
                }
                c.attribution.triggering_command = triggering_command;
                c.attribution.triggering_prompt = triggering_prompt;
                if let Some(entry) = session.identifier_index.entries.get(&normalized) {
                    for o in &entry.origins {
                        match o {
                            aten_schema::Origin::UserMessage => {
                                c.attribution.requested_in_user_message = true;
                            }
                            aten_schema::Origin::AssistantMessage => {
                                c.attribution.requested_in_assistant_message = true;
                            }
                            aten_schema::Origin::ToolResult => {
                                c.attribution.requested_in_tool_result = true;
                            }
                        }
                    }
                }
            }
            EventKind::NetworkEgress(n) => {
                let ip = n.dest_ip.clone();
                let host = n.dest_host.clone().unwrap_or_default();
                if let Some(tc) = confident_tc {
                    n.attribution.attributed_tool_call_id = Some(tc.id.clone());
                    n.attribution.time_window_ms = time_window_ms;
                    n.attribution.requested_by_tool_call = tc.input_text.contains(&ip)
                        || (!host.is_empty() && tc.input_text.contains(&host));
                }
                n.attribution.triggering_command = triggering_command;
                n.attribution.triggering_prompt = triggering_prompt;
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
            EventKind::DnsQuery(d) => {
                // query_name is the primary identifier, same role dest_host
                // plays for network_egress — a lookup of a host that first
                // surfaced in a tool_result is the DNS-exfil fingerprint.
                let name = d.query_name.clone();
                if let Some(tc) = confident_tc {
                    d.attribution.attributed_tool_call_id = Some(tc.id.clone());
                    d.attribution.time_window_ms = time_window_ms;
                    // query_name is already lowercased by the collectors; the
                    // tool input is not, so lowercase it before matching (a
                    // `curl HTTPS://Host` would otherwise miss).
                    d.attribution.requested_by_tool_call =
                        tc.input_text.to_lowercase().contains(&name);
                }
                d.attribution.triggering_command = triggering_command;
                d.attribution.triggering_prompt = triggering_prompt;
                let mut origins = session.origins_for_text(&name);
                // Resolved answers may themselves be identifiers the model was
                // handed (e.g. a tool_result that named the IP directly).
                for ip in &d.answers {
                    let ip_origins = session.origins_for_text(ip);
                    origins.user_message |= ip_origins.user_message;
                    origins.assistant_message |= ip_origins.assistant_message;
                    origins.tool_result |= ip_origins.tool_result;
                }
                d.attribution.requested_in_user_message = origins.user_message;
                d.attribution.requested_in_assistant_message = origins.assistant_message;
                d.attribution.requested_in_tool_result = origins.tool_result;
            }
            EventKind::FileWrite(f) => {
                // file_path is the primary identifier, same handling as
                // credential_access: a write to a path that only ever appeared
                // in a tool_result is an injection-driven self-modification.
                let path = f.file_path.clone();
                let normalized = aten_transcript::normalize(&path, None);
                if let Some(tc) = confident_tc {
                    f.attribution.attributed_tool_call_id = Some(tc.id.clone());
                    f.attribution.time_window_ms = time_window_ms;
                    f.attribution.requested_by_tool_call = tc.input_text.contains(&path)
                        || tc.input_text.to_lowercase().contains(&normalized);
                }
                f.attribution.triggering_command = triggering_command;
                f.attribution.triggering_prompt = triggering_prompt;
                if let Some(entry) = session.identifier_index.entries.get(&normalized) {
                    for o in &entry.origins {
                        match o {
                            aten_schema::Origin::UserMessage => {
                                f.attribution.requested_in_user_message = true;
                            }
                            aten_schema::Origin::AssistantMessage => {
                                f.attribution.requested_in_assistant_message = true;
                            }
                            aten_schema::Origin::ToolResult => {
                                f.attribution.requested_in_tool_result = true;
                            }
                        }
                    }
                }
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
    ///
    /// **Tie-break when multiple sessions match the same cwd**: this is
    /// common in practice because users open Claude Code multiple times
    /// in the same project directory; the old transcript files stay
    /// around on disk. The active session (the one actually generating
    /// kernel events right now) is identified by having the most-recent
    /// tool_call timestamp. We pick that one; sessions with no tool_calls
    /// at all are treated as least-recent (effectively "stale").
    fn resolve_session_for_pid(&mut self, agent_root_pid: i32) -> Option<String> {
        if let Some(sid) = self.pid_bindings.get(&agent_root_pid) {
            return Some(sid.clone());
        }
        let proc_cwd = (self.cfg.cwd_for_pid)(agent_root_pid)?;
        let a = norm_cwd(&proc_cwd);
        if a.is_empty() {
            return None;
        }

        // Collect every session whose cwd matches, paired with its
        // latest tool_call timestamp. i64::MIN sorts sessions-with-no-
        // tool_calls last so they only win when nothing else matches.
        let mut candidates: Vec<(&String, i64)> = Vec::new();
        for (sid, state) in &self.sessions {
            let Some(cwd) = state.cwd.as_deref() else {
                continue;
            };
            let b = norm_cwd(cwd);
            if b.is_empty() {
                continue;
            }
            if a == b || a.starts_with(&b) || b.starts_with(&a) {
                let latest_tc = state
                    .tool_calls
                    .last()
                    .map(|tc| tc.timestamp_ns)
                    .unwrap_or(i64::MIN);
                candidates.push((sid, latest_tc));
            }
        }

        // Pick the session whose latest tool_call is most recent. Stable
        // tie-break by session_id so behavior is deterministic if two
        // sessions happen to have identical latest-tool_call timestamps
        // (rare but possible — multi-record transcripts can share ns).
        candidates.sort_by(|x, y| y.1.cmp(&x.1).then_with(|| x.0.cmp(y.0)));
        let winner = candidates.first().map(|(sid, _)| (*sid).clone())?;
        self.pid_bindings.insert(agent_root_pid, winner.clone());
        Some(winner)
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

/// Pull the human-readable command from a tool_call's input. Bash and
/// PowerShell-style tools nest the command in a `"command"` JSON field;
/// for everything else, the stringified input is the best we can do.
/// The intent is `triggering_command` reading as a real command string
/// for the common case, not as a raw JSON blob.
fn extract_command(input_text: &str) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(input_text) {
        if let Some(cmd) = v.get("command").and_then(|c| c.as_str()) {
            return cmd.to_string();
        }
    }
    input_text.to_string()
}

/// Extract identifiers from `cmdline` and check whether each appears as a
/// substring of `tool_input_text`. Used for `requested_by_tool_call`. The
/// tool_input is stringified JSON, so we just substring-match — the same
/// content appears as-typed inside the JSON.
fn identifiers_appear_in(cmdline: &str, tool_input_text: &str) -> bool {
    for ident in aten_transcript::extract(cmdline) {
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
