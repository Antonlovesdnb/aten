//! Per-session state used by the attribution engine.
//!
//! Holds everything needed to attribute a kernel event back to a Claude Code
//! session: the identifier-origin index built from prompts and tool_results,
//! the chronological tool_call timeline (used for the time-window join), and
//! the session's cwd (used to bind an agent_root_pid to this session by
//! matching against `/proc/<pid>/cwd`).

use std::collections::BTreeMap;

use aten_schema::{Event, EventKind, Origin, Role};
use aten_transcript::IdentifierIndex;
use chrono::{DateTime, Utc};

const MAX_CACHED_INTENT_CHARS: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct ToolCallEntry {
    pub id: String,
    pub name: String,
    pub input_text: String,
    /// Lowercased `input_text`, precomputed once at construction. Attribution
    /// matches the (already-lowercased) primary identifier against this on
    /// every kernel event attributed to this tool call; computing it here
    /// avoids re-lowercasing the (potentially multi-KB) input per event.
    pub input_text_lower: String,
    pub timestamp_ns: i64,
}

/// Most-recent user-prompt cache. Used to populate
/// `attribution.triggering_prompt` on kernel events — the human-readable
/// "user intent that led to this" field. User prompts don't suffer the
/// flush-latency race that delays assistant-side records, so this cache
/// is essentially always accurate at attribution time.
#[derive(Debug, Clone)]
pub struct UserPromptEntry {
    pub text: String,
    pub timestamp_ns: i64,
}

#[derive(Debug, Default)]
pub struct SessionState {
    pub session_id: String,
    pub cwd: Option<String>,
    /// Chronologically ordered by `timestamp_ns`. Append-only as new tool_calls
    /// surface on each transcript refresh.
    pub tool_calls: Vec<ToolCallEntry>,
    /// Chronologically ordered user prompts from this session. Same
    /// append-only growth pattern as `tool_calls`. Looked up by
    /// `most_recent_user_prompt_before` for the `triggering_prompt`
    /// field on kernel events.
    pub user_prompts: Vec<UserPromptEntry>,
    pub identifier_index: IdentifierIndex,
}

impl SessionState {
    /// Build a fresh state from the full set of transcript events.
    pub fn from_events(session_id: String, events: &[Event], cwd: Option<String>) -> Self {
        let mut s = SessionState {
            session_id,
            cwd,
            ..Default::default()
        };
        s.ingest(events);
        s
    }

    /// Fold a newly parsed event batch into this session. Callers pass only
    /// appended transcript records, so work and allocation scale with the
    /// delta rather than the lifetime size of the session.
    pub fn ingest(&mut self, events: &[Event]) {
        for ev in events {
            match &ev.kind {
                EventKind::ToolCall(tc) => {
                    let ts_ns = parse_rfc3339_ns(&ev.timestamp).unwrap_or(i64::MAX);
                    let input_text =
                        bounded_chars(&tc.tool_input.to_string(), MAX_CACHED_INTENT_CHARS);
                    self.tool_calls.push(ToolCallEntry {
                        id: tc.tool_call_id.clone(),
                        name: tc.tool_name.clone(),
                        input_text_lower: input_text.to_lowercase(),
                        input_text,
                        timestamp_ns: ts_ns,
                    });
                }
                EventKind::Prompt(p) if matches!(p.role, Role::User) => {
                    let ts_ns = parse_rfc3339_ns(&ev.timestamp).unwrap_or(i64::MAX);
                    self.user_prompts.push(UserPromptEntry {
                        text: bounded_chars(&p.prompt_text, MAX_CACHED_INTENT_CHARS),
                        timestamp_ns: ts_ns,
                    });
                }
                _ => {}
            }
        }
        // `attribute_at` and `most_recent_user_prompt_before` binary-search
        // these vecs with `partition_point`, which requires them ordered by
        // `timestamp_ns`. Records normally arrive append-ordered, but a
        // flush-reordered record or an unparseable timestamp (folded in as
        // `i64::MAX`) would otherwise sit out of order and corrupt the search.
        // A stable sort of the now-mostly-sorted vec is near-linear and keeps
        // the invariant the old full-reparse `refresh()` maintained.
        self.tool_calls.sort_by_key(|tc| tc.timestamp_ns);
        self.user_prompts.sort_by_key(|p| p.timestamp_ns);
        self.identifier_index.ingest(events, None);
    }

    /// Most-recent user prompt with timestamp <= `event_ns`. Returns None
    /// if no user prompt has been observed in this session yet — uncommon
    /// for live sessions (the first record is usually a user message) but
    /// possible during the very-first refresh tick after a fresh start.
    pub fn most_recent_user_prompt_before(&self, event_ns: i64) -> Option<&UserPromptEntry> {
        let idx = self
            .user_prompts
            .partition_point(|p| p.timestamp_ns <= event_ns);
        if idx == 0 {
            return None;
        }
        self.user_prompts.get(idx - 1)
    }

    /// Most-recent tool_call with timestamp <= `event_ns`. Returns None if no
    /// tool_call had emitted before the event.
    pub fn attribute_at(&self, event_ns: i64) -> Option<&ToolCallEntry> {
        // Binary search for the rightmost tool_call <= event_ns.
        let idx = self
            .tool_calls
            .partition_point(|tc| tc.timestamp_ns <= event_ns);
        if idx == 0 {
            None
        } else {
            Some(&self.tool_calls[idx - 1])
        }
    }

    /// Pull the origins (user/assistant/tool_result) of every identifier
    /// surface that appears as a substring of `text`. Same normalization rules
    /// as the transcript reader.
    pub fn origins_for_text(&self, text: &str) -> OriginsFound {
        let mut out = OriginsFound::default();
        for ident in aten_transcript::extract(text) {
            let norm = aten_transcript::normalize(&ident, None);
            self.fold_origins(&norm, &mut out);
        }
        out
    }

    /// Origins of a single, already-atomic identifier token — a destination
    /// IP/host, a DNS query name, a resolved answer. These don't need the
    /// regex `extract()` sweep `origins_for_text` runs for free-form text
    /// (a cmdline): the token is itself the identifier, so we normalize and
    /// do one O(1) index lookup, exactly as the credential/file arms do.
    /// Equivalent to `origins_for_text` for atomic tokens (extract returns
    /// such a token unchanged), but skips the per-event regex battery.
    pub fn origins_for_token(&self, token: &str) -> OriginsFound {
        let mut out = OriginsFound::default();
        let norm = aten_transcript::normalize(token, None);
        self.fold_origins(&norm, &mut out);
        out
    }

    /// Merge the origins recorded for one normalized identifier into `out`.
    fn fold_origins(&self, norm: &str, out: &mut OriginsFound) {
        if let Some(entry) = self.identifier_index.entries.get(norm) {
            for o in &entry.origins {
                match o {
                    Origin::UserMessage => out.user_message = true,
                    Origin::AssistantMessage => out.assistant_message = true,
                    Origin::ToolResult => out.tool_result = true,
                }
            }
        }
    }
}

fn bounded_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        text.chars().take(max).collect()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct OriginsFound {
    pub user_message: bool,
    pub assistant_message: bool,
    pub tool_result: bool,
}

pub fn parse_rfc3339_ns(s: &str) -> Option<i64> {
    let dt: DateTime<Utc> = s.parse().ok()?;
    dt.timestamp_nanos_opt()
}

/// Read a transcript JSONL file and return (session_id, events). Retained for
/// one-shot callers; the attribution engine uses `TranscriptStreamParser` and
/// byte offsets for live tailing.
///
/// `Platform` is derived from the build target — events get stamped with
/// the OS the *daemon* is running on, not the OS embedded in the transcript
/// (Claude Code transcripts carry no platform marker, and a Codex session
/// could in principle have been moved cross-host).
pub fn load_sessions_from_file(
    transcript_path: &std::path::Path,
    dialect: aten_transcript::TranscriptDialect,
) -> anyhow::Result<(String, Vec<Event>)> {
    let platform = if cfg!(target_os = "windows") {
        aten_schema::Platform::Windows
    } else if cfg!(target_os = "macos") {
        aten_schema::Platform::Macos
    } else {
        aten_schema::Platform::Linux
    };
    let content = std::fs::read_to_string(transcript_path)?;
    let (events, _idx) =
        aten_transcript::read_transcript_by_dialect(dialect, &content, platform, None)?;
    let session_id = events
        .iter()
        .find_map(|e| e.session_id.clone())
        .unwrap_or_default();
    Ok((session_id, events))
}

/// Extract the `cwd` from the first transcript record that carries it.
/// Claude Code records cwd on most non-metadata lines; Codex records it
/// once in the `session_meta.payload.cwd` opener.
pub fn cwd_from_transcript_raw(
    transcript_path: &std::path::Path,
    dialect: aten_transcript::TranscriptDialect,
) -> Option<String> {
    if dialect == aten_transcript::TranscriptDialect::Codex {
        return aten_transcript::codex::cwd_from_codex_transcript_raw(transcript_path);
    }
    let content = std::fs::read_to_string(transcript_path).ok()?;
    for line in content.lines() {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(cwd) = v.get("cwd").and_then(|s| s.as_str()) {
            return Some(cwd.to_string());
        }
    }
    None
}

#[allow(dead_code)]
fn _silence_unused_chrono(_x: BTreeMap<String, ()>) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_parses_to_unix_ns() {
        let ns = parse_rfc3339_ns("2026-05-27T17:52:11.219Z").unwrap();
        // 2026-05-27T17:52:11Z = 1779904331 secs (verified in collector tests).
        // .219 fractional → +219_000_000 ns.
        assert_eq!(ns, 1_779_904_331_219_000_000);
    }

    #[test]
    fn attribute_at_picks_most_recent_le() {
        let s = SessionState {
            tool_calls: vec![
                ToolCallEntry {
                    id: "t1".into(),
                    name: "Bash".into(),
                    input_text: "".into(),
                    input_text_lower: "".into(),
                    timestamp_ns: 100,
                },
                ToolCallEntry {
                    id: "t2".into(),
                    name: "Bash".into(),
                    input_text: "".into(),
                    input_text_lower: "".into(),
                    timestamp_ns: 200,
                },
                ToolCallEntry {
                    id: "t3".into(),
                    name: "Bash".into(),
                    input_text: "".into(),
                    input_text_lower: "".into(),
                    timestamp_ns: 300,
                },
            ],
            ..Default::default()
        };
        assert_eq!(s.attribute_at(150).map(|t| t.id.as_str()), Some("t1"));
        assert_eq!(s.attribute_at(200).map(|t| t.id.as_str()), Some("t2"));
        assert_eq!(s.attribute_at(250).map(|t| t.id.as_str()), Some("t2"));
        assert_eq!(s.attribute_at(99).map(|t| t.id.as_str()), None);
    }
}
