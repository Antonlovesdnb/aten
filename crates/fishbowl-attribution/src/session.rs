//! Per-session state used by the attribution engine.
//!
//! Holds everything needed to attribute a kernel event back to a Claude Code
//! session: the identifier-origin index built from prompts and tool_results,
//! the chronological tool_call timeline (used for the time-window join), and
//! the session's cwd (used to bind an agent_root_pid to this session by
//! matching against `/proc/<pid>/cwd`).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use fishbowl_schema::{Event, EventKind, Origin};
use fishbowl_transcript::IdentifierIndex;

#[derive(Debug, Clone)]
pub struct ToolCallEntry {
    pub id: String,
    pub name: String,
    pub input_text: String,
    pub timestamp_ns: i64,
}

#[derive(Debug, Default)]
pub struct SessionState {
    pub session_id: String,
    pub cwd: Option<String>,
    /// Chronologically ordered by `timestamp_ns`. Append-only as new tool_calls
    /// surface on each transcript refresh.
    pub tool_calls: Vec<ToolCallEntry>,
    pub identifier_index: IdentifierIndex,
    /// Tracks how many events from the transcript have been folded in. New
    /// refreshes only look at events past this cursor.
    pub processed_event_count: usize,
}

impl SessionState {
    /// Build a fresh state from the full set of transcript events.
    pub fn from_events(session_id: String, events: &[Event], cwd: Option<String>) -> Self {
        let mut s = SessionState {
            session_id,
            cwd,
            ..Default::default()
        };
        s.refresh(events);
        s
    }

    /// Update state from the current full event list. Append-only:
    /// only events past `processed_event_count` get folded into
    /// `tool_calls`. The identifier index is rebuilt from the full list
    /// (cheap on dev-endpoint transcript sizes) so it always reflects
    /// every prompt and tool_result ever seen.
    ///
    /// **Invariant**: `processed_event_count` always equals the full
    /// event list's length after a successful refresh — so the next
    /// call sees an accurate cursor. A prior version mistakenly set it
    /// to the delta size, which caused the engine to re-emit older
    /// events to the JSONL on every subsequent refresh (the "prompt
    /// appears 5 times" symptom).
    pub fn refresh(&mut self, events: &[Event]) {
        if events.len() <= self.processed_event_count {
            return;
        }
        for ev in &events[self.processed_event_count..] {
            if let EventKind::ToolCall(tc) = &ev.kind {
                let ts_ns = parse_rfc3339_ns(&ev.timestamp).unwrap_or(i64::MAX);
                self.tool_calls.push(ToolCallEntry {
                    id: tc.tool_call_id.clone(),
                    name: tc.tool_name.clone(),
                    input_text: tc.tool_input.to_string(),
                    timestamp_ns: ts_ns,
                });
            }
        }
        self.tool_calls.sort_by_key(|tc| tc.timestamp_ns);
        self.identifier_index = fishbowl_transcript::build_identifier_index(events, None);
        self.processed_event_count = events.len();
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
        for ident in fishbowl_transcript::extract(text) {
            let norm = fishbowl_transcript::normalize(&ident, None);
            if let Some(entry) = self.identifier_index.entries.get(&norm) {
                for o in &entry.origins {
                    match o {
                        Origin::UserMessage => out.user_message = true,
                        Origin::AssistantMessage => out.assistant_message = true,
                        Origin::ToolResult => out.tool_result = true,
                    }
                }
            }
        }
        out
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

/// Read a transcript JSONL file and return (session_id, events). Picks the
/// parser based on `dialect` — Claude Code's per-line format or Codex's
/// session_meta-rooted envelope. Used by the engine to rebuild its session
/// set on each refresh tick.
///
/// `Platform` is derived from the build target — events get stamped with
/// the OS the *daemon* is running on, not the OS embedded in the transcript
/// (Claude Code transcripts carry no platform marker, and a Codex session
/// could in principle have been moved cross-host).
pub fn load_sessions_from_file(
    transcript_path: &std::path::Path,
    dialect: fishbowl_transcript::TranscriptDialect,
) -> anyhow::Result<(String, Vec<Event>)> {
    let platform = if cfg!(target_os = "windows") {
        fishbowl_schema::Platform::Windows
    } else {
        fishbowl_schema::Platform::Linux
    };
    let content = std::fs::read_to_string(transcript_path)?;
    let (events, _idx) =
        fishbowl_transcript::read_transcript_by_dialect(dialect, &content, platform, None)?;
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
    dialect: fishbowl_transcript::TranscriptDialect,
) -> Option<String> {
    if dialect == fishbowl_transcript::TranscriptDialect::Codex {
        return fishbowl_transcript::codex::cwd_from_codex_transcript_raw(transcript_path);
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
                ToolCallEntry { id: "t1".into(), name: "Bash".into(), input_text: "".into(), timestamp_ns: 100 },
                ToolCallEntry { id: "t2".into(), name: "Bash".into(), input_text: "".into(), timestamp_ns: 200 },
                ToolCallEntry { id: "t3".into(), name: "Bash".into(), input_text: "".into(), timestamp_ns: 300 },
            ],
            ..Default::default()
        };
        assert_eq!(s.attribute_at(150).map(|t| t.id.as_str()), Some("t1"));
        assert_eq!(s.attribute_at(200).map(|t| t.id.as_str()), Some("t2"));
        assert_eq!(s.attribute_at(250).map(|t| t.id.as_str()), Some("t2"));
        assert_eq!(s.attribute_at(99).map(|t| t.id.as_str()), None);
    }
}
