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
//!   auto-detected per file from content when possible, then path.
//! - `refresh()` stats known files and parses only complete bytes appended
//!   since the prior tick. Recursive discovery runs once per second rather
//!   than on the 100 ms tail cadence. Per-session state is keyed by the
//!   transcript-recorded `session_id`, so multiple concurrent Claude / Codex
//!   sessions can be attributed from one daemon instance.
//! - `attribute(&mut event)` mutates a kernel-side event in place: looks
//!   up the agent_root_pid's cwd via the platform-specific
//!   `cwd_for_pid` resolver, finds whichever session's cwd matches, then
//!   sets the attribution booleans from that session's most-recent
//!   tool_call and identifier-origin index.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Result;
use aten_schema::{CollectorStatusPayload, Event, EventKind, Source, SCHEMA_VERSION};
use aten_transcript::{detect_dialect, TranscriptStreamParser};

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
    len: u64,
    /// First byte not yet consumed. Only complete JSONL records advance it.
    byte_offset: u64,
    /// Retains Codex's opener-only session metadata across tail reads.
    parser: Option<TranscriptStreamParser>,
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
    /// Files found by the most recent recursive discovery pass. Normal refresh
    /// ticks only stat and tail these paths; they do not walk directory trees.
    known_files: HashSet<PathBuf>,
    last_discovery: Option<Instant>,
    /// Cache of agent_root_pid → its resolved (normalized) cwd. Only the
    /// expensive cwd lookup (`/proc/<pid>/cwd` read on Linux, PEB walk on
    /// Windows) is cached here; the session an event is attributed to is
    /// re-ranked on every event in `resolve_session_for_pid`, so the binding
    /// follows the currently-active session when multiple transcripts share a
    /// cwd. Invalidated on agent-root PID reuse (see `refresh`).
    pid_cwds: HashMap<i32, String>,
    /// Dirty flag — true if emission cursors have advanced since the
    /// last `save_state()`. The daemon calls `save_state()` whenever
    /// refresh() returns events; this flag avoids writing the state
    /// file on no-op ticks.
    state_dirty: bool,
    last_state_save: Option<Instant>,
    stats: EngineStats,
}

/// Cumulative counters for validating steady-state overhead in tests and
/// exposing it to a future health endpoint without putting logging on hot
/// paths.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EngineStats {
    pub refreshes: u64,
    pub discovery_passes: u64,
    pub files_checked: u64,
    pub bytes_read: u64,
    pub records_parsed: u64,
    pub parse_errors: u64,
    pub state_writes: u64,
}

impl AttributionEngine {
    pub fn new(cfg: EngineConfig) -> Self {
        let mut engine = Self {
            cfg,
            sessions: HashMap::new(),
            file_meta: HashMap::new(),
            known_files: HashSet::new(),
            last_discovery: None,
            pid_cwds: HashMap::new(),
            state_dirty: false,
            last_state_save: None,
            stats: EngineStats::default(),
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
                                len: 0,
                                byte_offset: 0,
                                parser: None,
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
        const SAVE_INTERVAL: Duration = Duration::from_secs(2);
        if self
            .last_state_save
            .is_some_and(|last| last.elapsed() < SAVE_INTERVAL)
        {
            return Ok(());
        }
        self.flush_state()
    }

    /// Force dirty cursors to disk, used during graceful shutdown. Normal
    /// refresh ticks call `save_state`, which batches rewrites for two seconds.
    pub fn flush_state(&mut self) -> Result<()> {
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
        let state = PersistedState { version: 1, files };
        let text = serde_json::to_string(&state)?;
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)?;
        self.state_dirty = false;
        self.last_state_save = Some(Instant::now());
        self.stats.state_writes = self.stats.state_writes.saturating_add(1);
        Ok(())
    }

    /// Discover transcript paths periodically, tail modified JSONL files, and
    /// fold only appended records into the matching SessionState.
    ///
    /// Returns transcript events that are both **new since the previous
    /// refresh of that file** and **newer than the engine's start time**.
    /// The daemon emits these to its output sink alongside kernel events,
    /// giving a unified prompt-and-syscall stream. Historic transcript
    /// content (sessions that already existed on disk at startup) is
    /// silently absorbed into SessionState for attribution context but
    /// not re-emitted — restarting the service shouldn't replay history.
    pub fn refresh(&mut self) -> Result<Vec<Event>> {
        self.stats.refreshes = self.stats.refreshes.saturating_add(1);
        let mut new_events: Vec<Event> = Vec::new();
        const DISCOVERY_INTERVAL: Duration = Duration::from_secs(1);
        let should_discover = self
            .last_discovery
            .is_none_or(|last| last.elapsed() >= DISCOVERY_INTERVAL);
        if should_discover {
            self.stats.discovery_passes = self.stats.discovery_passes.saturating_add(1);
            let mut discovered = HashSet::new();
            for path in &self.cfg.transcript_paths {
                discover_jsonl(path, &mut discovered);
            }
            self.known_files = discovered;
            self.last_discovery = Some(Instant::now());
        }

        let files: Vec<PathBuf> = self.known_files.iter().cloned().collect();
        for file in files {
            self.stats.files_checked = self.stats.files_checked.saturating_add(1);
            if let Ok(metadata) = std::fs::metadata(&file) {
                if metadata.is_file() {
                    self.refresh_file(file, &metadata, &mut new_events);
                }
            }
        }
        Ok(new_events)
    }

    fn refresh_file(
        &mut self,
        file: PathBuf,
        metadata: &std::fs::Metadata,
        new_events: &mut Vec<Event>,
    ) {
        let mtime = metadata.modified().ok();
        let len = metadata.len();
        let existing = self.file_meta.remove(&file);
        let first_sight = existing.is_none();
        let mut meta = existing.unwrap_or(FileMeta {
            mtime: None,
            len: 0,
            byte_offset: 0,
            parser: None,
            user_id: None,
            emitted_count: 0,
            from_persisted_state: false,
        });

        if meta.parser.is_some() && meta.len == len && meta.mtime.is_some() && meta.mtime >= mtime {
            self.file_meta.insert(file, meta);
            return;
        }

        let reset = meta.parser.is_none() || len < meta.byte_offset;
        let first_line = reset.then(|| first_nonempty_line(&file)).flatten();
        let dialect = detect_dialect(&file, first_line.as_deref());
        let mut parser = if reset {
            TranscriptStreamParser::new(dialect, host_platform())
        } else {
            meta.parser
                .take()
                .expect("initialized parser required for tail read")
        };
        let offset = if reset { 0 } else { meta.byte_offset };
        let (events, new_offset, bytes_read, records_parsed, parse_errors) =
            match read_appended_events(&file, offset, &mut parser) {
                Ok(result) => result,
                Err(_) => {
                    meta.parser = Some(parser);
                    self.file_meta.insert(file, meta);
                    return;
                }
            };
        self.stats.bytes_read = self.stats.bytes_read.saturating_add(bytes_read);
        self.stats.records_parsed = self.stats.records_parsed.saturating_add(records_parsed);
        self.stats.parse_errors = self.stats.parse_errors.saturating_add(parse_errors);

        // Resolve and cache the file owner. State-loaded entries have
        // `user_id: None` (we don't persist user_id to disk), so we have
        // to actually look it up on the first refresh that touches the
        // file at runtime — not just on first-ever sight. Once cached,
        // subsequent refreshes use the cached value.
        let user_id = match meta.user_id.clone() {
            Some(u) => Some(u),
            None => (self.cfg.user_for_transcript)(&file),
        };
        if parse_errors > 0 {
            new_events.push(transcript_parse_status_event(
                self.cfg.host_id.clone(),
                user_id.clone(),
                &file,
                self.stats.parse_errors,
                parse_errors,
            ));
        }

        let session_id = parser.session_id().unwrap_or_default().to_string();
        let cwd = parser.cwd().map(str::to_string);
        if !session_id.is_empty() {
            if reset && !first_sight && !meta.from_persisted_state {
                let mut state = SessionState::from_events(session_id.clone(), &events, cwd.clone());
                state.user_id = user_id.clone();
                self.sessions.insert(session_id.clone(), state);
            } else {
                match self.sessions.get_mut(&session_id) {
                    Some(state) => {
                        state.ingest(&events);
                        if state.cwd.is_none() {
                            state.cwd = cwd.clone();
                        }
                        if state.user_id.is_none() {
                            state.user_id = user_id.clone();
                        }
                    }
                    None => {
                        let mut state =
                            SessionState::from_events(session_id.clone(), &events, cwd.clone());
                        state.user_id = user_id.clone();
                        self.sessions.insert(session_id.clone(), state);
                    }
                }
            }
        }

        let emit_cursor = if reset {
            if first_sight {
                events.len()
            } else {
                meta.emitted_count.min(events.len())
            }
        } else {
            0
        };

        // Stamp host_id and user_id on each emitted event — the transcript
        // reader leaves those null because they aren't in the source
        // JSONL; the daemon enriches at emit time.
        for ev in events.iter().skip(emit_cursor) {
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
        let new_emitted_count = if reset {
            events.len()
        } else {
            meta.emitted_count.saturating_add(events.len())
        };
        if events.len() > emit_cursor {
            self.state_dirty = true;
        }
        meta.mtime = mtime;
        meta.len = len;
        meta.byte_offset = new_offset;
        meta.parser = Some(parser);
        meta.user_id = user_id;
        meta.emitted_count = new_emitted_count;
        meta.from_persisted_state = false;
        self.file_meta.insert(file, meta);
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
            EventKind::LocalIpcAccess(i) => i.process.agent_root_pid,
            _ => None,
        };

        let Some(pid) = agent_root_pid else { return };
        // If the enrolled agent root itself just execed, invalidate the cached
        // cwd for this numeric PID before resolving. This closes the common
        // PID-reuse hole where a dead agent process's PID later belongs to a
        // different process with a different cwd/session/user.
        if matches!(
            &event.kind,
            EventKind::ProcessExec(p)
                if p.process.agent_root_pid == Some(p.process.pid) && p.process.pid == pid
        ) {
            self.pid_cwds.remove(&pid);
        }

        let session_id = {
            let user_id = event_user_id(event);
            self.resolve_session_for_pid(pid, user_id)
        };
        let Some(session_id) = session_id else {
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
            .map(|p| bounded_intent(&p.text));

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
                    c.attribution.requested_by_tool_call =
                        tc.input_text.contains(&path) || tc.input_text_lower.contains(&normalized);
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
                let mut origins = session.origins_for_token(&ip);
                if !host.is_empty() {
                    let host_origins = session.origins_for_token(&host);
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
                    // query_name is already lowercased by the collectors; match
                    // against the precomputed lowercased tool input (a
                    // `curl HTTPS://Host` would otherwise miss on case).
                    d.attribution.requested_by_tool_call = tc.input_text_lower.contains(&name);
                }
                d.attribution.triggering_command = triggering_command;
                d.attribution.triggering_prompt = triggering_prompt;
                let mut origins = session.origins_for_token(&name);
                // Resolved answers may themselves be identifiers the model was
                // handed (e.g. a tool_result that named the IP directly).
                for ip in &d.answers {
                    let ip_origins = session.origins_for_token(ip);
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
                    f.attribution.requested_by_tool_call =
                        tc.input_text.contains(&path) || tc.input_text_lower.contains(&normalized);
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
            EventKind::LocalIpcAccess(i) => {
                let path = i.ipc_path.clone();
                let normalized = aten_transcript::normalize(&path, None);
                if let Some(tc) = confident_tc {
                    i.attribution.attributed_tool_call_id = Some(tc.id.clone());
                    i.attribution.time_window_ms = time_window_ms;
                    i.attribution.requested_by_tool_call =
                        tc.input_text.contains(&path) || tc.input_text_lower.contains(&normalized);
                }
                i.attribution.triggering_command = triggering_command;
                i.attribution.triggering_prompt = triggering_prompt;
                if let Some(entry) = session.identifier_index.entries.get(&normalized) {
                    for o in &entry.origins {
                        match o {
                            aten_schema::Origin::UserMessage => {
                                i.attribution.requested_in_user_message = true;
                            }
                            aten_schema::Origin::AssistantMessage => {
                                i.attribution.requested_in_assistant_message = true;
                            }
                            aten_schema::Origin::ToolResult => {
                                i.attribution.requested_in_tool_result = true;
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
    /// each loaded session's recorded cwd. Only the resolved cwd is cached
    /// per pid (the syscall is the expensive part); the session is re-ranked
    /// on every call so the binding tracks whichever matching session is
    /// currently active rather than freezing the first guess.
    ///
    /// Normalization (lowercase + forward-slash) absorbs case / separator
    /// differences between the live cwd and the transcript cwd —
    /// `C:\Users\…` vs `c:\users\…` vs `C:/Users/…` all match.
    ///
    /// **Tie-break when multiple sessions match the same cwd**: this is common
    /// in practice because users open Claude Code multiple times in the same
    /// project directory, and on shared hosts different users may work in
    /// similarly named paths. Exact user matches win first. Within compatible
    /// users, the active session is identified by the most-recent tool_call
    /// timestamp. Sessions with no tool_calls at all are treated as
    /// least-recent (effectively "stale"). Because this runs per event, a
    /// stale binding self-corrects as soon as the newly-active session in the
    /// same cwd records a tool_call.
    fn resolve_session_for_pid(
        &mut self,
        agent_root_pid: i32,
        event_user_id: Option<&str>,
    ) -> Option<String> {
        // Resolve (and cache) the agent root's cwd. Only the cwd is cached —
        // it is what the expensive platform syscall produces and it is stable
        // for a process's lifetime. The session *choice* below is deliberately
        // recomputed every call: caching the winning session permanently would
        // freeze an early, possibly-stale guess, so a kernel event could keep
        // being stamped with a session the agent has since moved on from (e.g.
        // when the user has Claude Code open in the same project dir more than
        // once). Re-ranking makes the binding track the active session.
        let a = match self.pid_cwds.get(&agent_root_pid) {
            Some(cwd) => cwd.clone(),
            None => {
                let proc_cwd = (self.cfg.cwd_for_pid)(agent_root_pid)?;
                let a = norm_cwd(&proc_cwd);
                if a.is_empty() {
                    return None;
                }
                self.pid_cwds.insert(agent_root_pid, a.clone());
                a
            }
        };

        // Collect every session whose cwd and user are compatible, paired with
        // whether the user matched exactly and the latest tool_call timestamp.
        // i64::MIN sorts sessions-with-no-tool_calls last so they only win
        // when nothing else matches.
        let mut candidates: Vec<(&String, bool, i64)> = Vec::new();
        for (sid, state) in &self.sessions {
            let Some(cwd) = state.cwd.as_deref() else {
                continue;
            };
            let b = norm_cwd(cwd);
            if b.is_empty() {
                continue;
            }
            if !cwd_matches(&a, &b) {
                continue;
            }
            let user_match = match (state.user_id.as_deref(), event_user_id) {
                (Some(session_user), Some(event_user)) if user_eq(session_user, event_user) => true,
                (Some(_), Some(_)) => continue,
                _ => false,
            };
            {
                let latest_tc = state
                    .tool_calls
                    .last()
                    .map(|tc| tc.timestamp_ns)
                    .unwrap_or(i64::MIN);
                candidates.push((sid, user_match, latest_tc));
            }
        }

        // Prefer exact user matches, then the session whose latest tool_call is
        // most recent. Stable tie-break by session_id so behavior is
        // deterministic if two sessions happen to share timestamps.
        candidates.sort_by(|x, y| {
            y.1.cmp(&x.1)
                .then_with(|| y.2.cmp(&x.2))
                .then_with(|| x.0.cmp(y.0))
        });
        candidates.first().map(|(sid, _, _)| (*sid).clone())
    }

    /// How many transcript sessions are currently loaded. Useful for
    /// service startup logging.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn stats(&self) -> EngineStats {
        self.stats
    }
}

fn norm_cwd(s: &str) -> String {
    let normalized = s.to_lowercase().replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/');
    if trimmed.is_empty() && normalized.starts_with('/') {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

fn cwd_matches(a: &str, b: &str) -> bool {
    a == b || cwd_has_prefix(a, b) || cwd_has_prefix(b, a)
}

fn cwd_has_prefix(path: &str, prefix: &str) -> bool {
    if prefix.is_empty() || prefix == "/" {
        return prefix == "/" && path.starts_with('/');
    }
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.starts_with('/'))
}

fn user_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn event_user_id(event: &Event) -> Option<&str> {
    event.user_id.as_deref().or_else(|| match &event.kind {
        EventKind::ProcessExec(p) => nonempty_user(&p.process.user),
        EventKind::CredentialAccess(c) => nonempty_user(&c.process.user),
        EventKind::NetworkEgress(n) => nonempty_user(&n.process.user),
        EventKind::DnsQuery(d) => nonempty_user(&d.process.user),
        EventKind::FileWrite(f) => nonempty_user(&f.process.user),
        EventKind::LocalIpcAccess(i) => nonempty_user(&i.process.user),
        _ => None,
    })
}

fn nonempty_user(user: &str) -> Option<&str> {
    if user.is_empty() {
        None
    } else {
        Some(user)
    }
}

fn transcript_parse_status_event(
    host_id: Option<String>,
    user_id: Option<String>,
    path: &Path,
    dropped_total: u64,
    dropped_since_last: u64,
) -> Event {
    Event {
        schema_version: SCHEMA_VERSION.to_string(),
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        monotonic_ns: None,
        platform: host_platform(),
        host_id,
        agent_id: "aten-daemon".to_string(),
        session_id: None,
        user_id,
        source: Source {
            collector: "transcript".to_string(),
            probe: "parser".to_string(),
            host_pid: None,
        },
        kind: EventKind::CollectorStatus(CollectorStatusPayload {
            dropped_total,
            dropped_since_last,
            reason: format!(
                "malformed transcript records skipped while reading {}",
                path.display()
            ),
        }),
    }
}

fn first_nonempty_line(path: &Path) -> Option<String> {
    const MAX_SNIFF_BYTES: usize = 64 * 1024;
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; MAX_SNIFF_BYTES];
    let read = file.read(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf[..read]);
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
}

/// Discover explicit transcript files and recursively scan configured
/// directories. This runs on a slower cadence than tail ingestion.
fn discover_jsonl(path: &Path, found: &mut HashSet<PathBuf>) {
    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    if metadata.is_file() {
        found.insert(path.to_path_buf());
        return;
    }
    if !metadata.is_dir() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            discover_jsonl(&child, found);
        } else if ft.is_file() && child.extension().is_some_and(|e| e == "jsonl") {
            found.insert(child);
        }
    }
}

/// Parse complete records starting at `offset`. A valid final record without a
/// newline is accepted; an incomplete final record leaves the cursor at its
/// start so the next refresh retries it after the writer finishes.
fn read_appended_events(
    path: &Path,
    offset: u64,
    parser: &mut TranscriptStreamParser,
) -> std::io::Result<(Vec<Event>, u64, u64, u64, u64)> {
    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut reader = BufReader::new(file);
    let mut events = Vec::new();
    let mut cursor = offset;
    let mut bytes = Vec::new();
    let mut bytes_read = 0u64;
    let mut records_parsed = 0u64;
    let mut parse_errors = 0u64;

    loop {
        bytes.clear();
        let read = reader.read_until(b'\n', &mut bytes)?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read.saturating_add(read as u64);
        let terminated = bytes.last() == Some(&b'\n');
        let line = String::from_utf8_lossy(&bytes);
        let line = line.trim_end_matches(['\r', '\n']).trim();
        if line.is_empty() {
            cursor = cursor.saturating_add(read as u64);
            continue;
        }

        match parser.parse_line(line) {
            Ok(parsed) => {
                events.extend(parsed);
                records_parsed = records_parsed.saturating_add(1);
                cursor = cursor.saturating_add(read as u64);
            }
            Err(error) if terminated => {
                parse_errors = parse_errors.saturating_add(1);
                eprintln!(
                    "aten: skipping malformed transcript record in {}: {error}",
                    path.display()
                );
                cursor = cursor.saturating_add(read as u64);
            }
            Err(_) => break,
        }
    }

    Ok((events, cursor, bytes_read, records_parsed, parse_errors))
}

fn host_platform() -> aten_schema::Platform {
    if cfg!(target_os = "windows") {
        aten_schema::Platform::Windows
    } else if cfg!(target_os = "macos") {
        aten_schema::Platform::Macos
    } else {
        aten_schema::Platform::Linux
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
            return bounded_intent(cmd);
        }
    }
    bounded_intent(input_text)
}

fn bounded_intent(text: &str) -> String {
    const MAX_EMBEDDED_INTENT_CHARS: usize = 4 * 1024;
    if text.chars().count() <= MAX_EMBEDDED_INTENT_CHARS {
        text.to_string()
    } else {
        text.chars().take(MAX_EMBEDDED_INTENT_CHARS).collect()
    }
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
    use std::io::Write;

    fn temp_transcript(name: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "aten-attribution-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("session.jsonl");
        (dir, file)
    }

    fn claude_prompt(id: &str, text: &str) -> String {
        let mut line = format!(
            r#"{{"type":"user","sessionId":"stream-session","uuid":"{id}","timestamp":"2026-05-27T19:08:02.110Z","cwd":"/tmp/project","message":{{"content":"{text}"}}}}"#
        );
        line.push('\n');
        line
    }

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

    #[test]
    fn cwd_prefix_matching_requires_path_boundary() {
        assert!(cwd_matches("/home/anton/proj/subdir", "/home/anton/proj"));
        assert!(cwd_matches("/home/anton/proj", "/home/anton/proj/subdir"));
        assert!(!cwd_matches("/home/anton/proj2", "/home/anton/proj"));
    }

    #[test]
    fn pid_session_binding_prefers_user_match_and_rechecks_cache() {
        fn cwd_for_test(pid: i32) -> Option<String> {
            (pid == 42).then(|| "/tmp/project".to_string())
        }

        fn state_for(session_id: &str, user_id: &str, ts: i64) -> SessionState {
            SessionState {
                session_id: session_id.to_string(),
                cwd: Some("/tmp/project".to_string()),
                user_id: Some(user_id.to_string()),
                tool_calls: vec![session::ToolCallEntry {
                    id: format!("tool-{session_id}"),
                    name: "Bash".to_string(),
                    input_text: String::new(),
                    input_text_lower: String::new(),
                    timestamp_ns: ts,
                }],
                ..Default::default()
            }
        }

        let mut engine = AttributionEngine::new(EngineConfig {
            cwd_for_pid: cwd_for_test,
            ..EngineConfig::default()
        });
        engine.sessions.insert(
            "alice-session".into(),
            state_for("alice-session", "alice", 100),
        );
        engine
            .sessions
            .insert("bob-session".into(), state_for("bob-session", "bob", 10));

        assert_eq!(
            engine.resolve_session_for_pid(42, Some("bob")).as_deref(),
            Some("bob-session")
        );
        assert_eq!(
            engine.resolve_session_for_pid(42, Some("alice")).as_deref(),
            Some("alice-session")
        );
    }

    #[test]
    fn pid_session_binding_follows_newly_active_session() {
        // Regression: two transcripts share one cwd (user opened Claude Code
        // in the same project dir twice). The pid→session binding must track
        // whichever session is currently active, not freeze the first guess —
        // otherwise kernel events keep getting stamped with a stale session
        // while transcript-side prompt events carry the live one.
        fn cwd_for_test(pid: i32) -> Option<String> {
            (pid == 42).then(|| "/tmp/project".to_string())
        }
        fn tc(id: &str, ts: i64) -> session::ToolCallEntry {
            session::ToolCallEntry {
                id: id.to_string(),
                name: "Bash".to_string(),
                input_text: String::new(),
                input_text_lower: String::new(),
                timestamp_ns: ts,
            }
        }
        fn state_with(session_id: &str, tcs: Vec<session::ToolCallEntry>) -> SessionState {
            SessionState {
                session_id: session_id.to_string(),
                cwd: Some("/tmp/project".to_string()),
                user_id: None,
                tool_calls: tcs,
                ..Default::default()
            }
        }

        let mut engine = AttributionEngine::new(EngineConfig {
            cwd_for_pid: cwd_for_test,
            ..EngineConfig::default()
        });
        engine
            .sessions
            .insert("old".into(), state_with("old", vec![tc("t-old", 100)]));
        engine
            .sessions
            .insert("new".into(), state_with("new", vec![tc("t-new", 50)]));

        // "old" is the most-recently-active session, so it wins first.
        assert_eq!(engine.resolve_session_for_pid(42, None).as_deref(), Some("old"));

        // "new" becomes active (records a newer tool_call).
        engine
            .sessions
            .get_mut("new")
            .unwrap()
            .tool_calls
            .push(tc("t-new-2", 200));

        // The binding self-corrects to the now-active session instead of
        // returning the first (previously cached) answer.
        assert_eq!(engine.resolve_session_for_pid(42, None).as_deref(), Some("new"));
    }

    #[test]
    fn refresh_tails_only_appended_bytes() {
        let (dir, file) = temp_transcript("tail");
        let initial = claude_prompt("one", "first");
        std::fs::write(&file, &initial).unwrap();

        let mut engine = AttributionEngine::new(EngineConfig {
            transcript_paths: vec![file.clone()],
            ..EngineConfig::default()
        });
        assert!(engine.refresh().unwrap().is_empty());
        assert_eq!(engine.session_count(), 1);
        let first = engine.stats();
        assert_eq!(first.bytes_read, initial.len() as u64);
        assert_eq!(first.records_parsed, 1);

        assert!(engine.refresh().unwrap().is_empty());
        let unchanged = engine.stats();
        assert_eq!(unchanged.bytes_read, first.bytes_read);
        assert_eq!(unchanged.discovery_passes, first.discovery_passes);

        let appended = claude_prompt("two", "second");
        let mut writer = std::fs::OpenOptions::new()
            .append(true)
            .open(&file)
            .unwrap();
        writer.write_all(appended.as_bytes()).unwrap();
        writer.flush().unwrap();

        let emitted = engine.refresh().unwrap();
        assert_eq!(emitted.len(), 1);
        let tailed = engine.stats();
        assert_eq!(tailed.bytes_read, first.bytes_read + appended.len() as u64);
        assert_eq!(tailed.records_parsed, 2);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn malformed_terminated_records_emit_parser_status() {
        let (dir, file) = temp_transcript("parse-status");
        std::fs::write(
            &file,
            format!("{}not-json\n", claude_prompt("one", "first")),
        )
        .unwrap();

        let mut engine = AttributionEngine::new(EngineConfig {
            transcript_paths: vec![file.clone()],
            ..EngineConfig::default()
        });
        let emitted = engine.refresh().unwrap();

        assert_eq!(engine.stats().parse_errors, 1);
        assert!(emitted.iter().any(|ev| matches!(
            &ev.kind,
            EventKind::CollectorStatus(status)
                if status.dropped_total == 1
                    && status.dropped_since_last == 1
                    && status.reason.contains("malformed transcript records")
        )));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn incomplete_record_is_retried_without_advancing_cursor() {
        let (dir, file) = temp_transcript("partial");
        let initial = claude_prompt("one", "first");
        std::fs::write(&file, &initial).unwrap();
        let mut engine = AttributionEngine::new(EngineConfig {
            transcript_paths: vec![file.clone()],
            ..EngineConfig::default()
        });
        engine.refresh().unwrap();

        let appended = claude_prompt("two", "second");
        let split = appended.len() / 2;
        let mut writer = std::fs::OpenOptions::new()
            .append(true)
            .open(&file)
            .unwrap();
        writer.write_all(&appended.as_bytes()[..split]).unwrap();
        writer.flush().unwrap();
        assert!(engine.refresh().unwrap().is_empty());

        writer.write_all(&appended.as_bytes()[split..]).unwrap();
        writer.flush().unwrap();
        assert_eq!(engine.refresh().unwrap().len(), 1);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn state_rewrites_are_batched_and_shutdown_flush_is_forced() {
        let (dir, file) = temp_transcript("state-batch");
        let state_path = dir.join("state.json");
        std::fs::write(&file, claude_prompt("one", "first")).unwrap();
        let mut engine = AttributionEngine::new(EngineConfig {
            transcript_paths: vec![file.clone()],
            state_path: Some(state_path.clone()),
            ..EngineConfig::default()
        });
        engine.refresh().unwrap();

        let mut writer = std::fs::OpenOptions::new()
            .append(true)
            .open(&file)
            .unwrap();
        writer
            .write_all(claude_prompt("two", "second").as_bytes())
            .unwrap();
        writer.flush().unwrap();
        engine.refresh().unwrap();
        engine.save_state().unwrap();
        assert_eq!(engine.stats().state_writes, 1);
        let first_state = std::fs::read(&state_path).unwrap();

        writer
            .write_all(claude_prompt("three", "third").as_bytes())
            .unwrap();
        writer.flush().unwrap();
        engine.refresh().unwrap();
        engine.save_state().unwrap();
        assert_eq!(engine.stats().state_writes, 1);
        assert_eq!(std::fs::read(&state_path).unwrap(), first_state);

        engine.flush_state().unwrap();
        assert_eq!(engine.stats().state_writes, 2);
        assert_ne!(std::fs::read(&state_path).unwrap(), first_state);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
