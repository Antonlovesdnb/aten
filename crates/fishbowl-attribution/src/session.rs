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
        s.fold_events(events);
        s
    }

    /// Append-only update: fold in any events past the cursor. Called on every
    /// transcript refresh. Tool_calls are sorted by timestamp at the end so the
    /// binary search in `attribute_at` stays valid.
    pub fn refresh(&mut self, events: &[Event]) {
        if events.len() <= self.processed_event_count {
            return;
        }
        let new_events = &events[self.processed_event_count..];
        self.fold_events(new_events);
    }

    fn fold_events(&mut self, events: &[Event]) {
        for ev in events {
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
        // Build a fresh identifier index from all events the session has seen.
        // Cheap on dev-endpoint transcript sizes; refactor to incremental if
        // sessions get long enough that this dominates CPU.
        self.identifier_index =
            fishbowl_transcript::build_identifier_index(events, None);
        self.processed_event_count = events.len();
        self.tool_calls.sort_by_key(|tc| tc.timestamp_ns);
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

/// Read every JSONL transcript file beneath `root` and group their events by
/// `session_id`. Returns one map entry per session. Used by the engine to
/// rebuild its session set on each refresh tick.
pub fn load_sessions_from_file(transcript_path: &std::path::Path) -> anyhow::Result<(String, Vec<Event>)> {
    let content = std::fs::read_to_string(transcript_path)?;
    let (events, _idx) =
        fishbowl_transcript::read_transcript(&content, fishbowl_schema::Platform::Linux, None)?;
    let session_id = events
        .iter()
        .find_map(|e| e.session_id.clone())
        .unwrap_or_default();
    Ok((session_id, events))
}

/// Extract the `cwd` from the first transcript record that carries it.
/// Claude Code records cwd on most non-metadata lines. Re-reading the raw
/// JSONL is cheaper than going through the schema events here because the
/// schema strips the cwd field — it's a transcript-record property, not an
/// event property.
pub fn cwd_from_transcript_raw(transcript_path: &std::path::Path) -> Option<String> {
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
