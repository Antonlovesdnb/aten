//! Codex CLI transcript reader.
//!
//! Codex's session rollout files at `~/.codex/sessions/<date>/rollout-<uuid>.jsonl`
//! carry structurally similar information to Claude Code's transcripts (per-line
//! JSON of user messages, assistant responses, tool invocations, and tool
//! results) but use a different envelope shape. Records look like:
//!
//! - `{type:"session_meta", payload:{id, cwd, ...}}` — first line; the
//!   session UUID and recorded cwd live here.
//! - `{type:"event_msg", payload:{type:"user_message", message:"..."}}` — a
//!   user-typed prompt. This is the schema's `Prompt(Role::User)`.
//! - `{type:"response_item", payload:{type:"function_call", name, arguments,
//!   call_id}}` — a tool call. Maps to schema `ToolCall`.
//! - `{type:"response_item", payload:{type:"function_call_output", call_id,
//!   output}}` — the tool's result. Maps to schema `ToolResult`. Codex
//!   prefixes the output with `Exit code: N\n...`; we treat `Exit code: 0`
//!   as Success and anything else as Error.
//!
//! Deliberately minimal for v0.x — covers what the attribution engine needs
//! (user prompts for the identifier-origin index, tool calls for
//! `attributed_tool_call_id` binding). Codex's `response_item.message` with
//! role=assistant, reasoning blocks, web_search_call etc. are not parsed yet;
//! adding them is straightforward but unnecessary to land the multi-agent
//! claim for the post.

use serde::Deserialize;

use aten_schema::{
    AgentKind, AgentSessionPayload, Event, EventKind, PermissionDecisionPayload, Platform,
    PromptPayload, ResultStatus, Role, Source, ToolCallPayload, ToolResultPayload, SCHEMA_VERSION,
};

use crate::{
    build_identifier_index, decision_from_value, make_event_id, string_field, truncate,
    IdentifierIndex, COLLECTOR_NAME,
};

const CODEX_AGENT_ID: &str = "codex-cli";
const CODEX_PROBE_NAME: &str = "codex-jsonl";

#[derive(Debug, Deserialize)]
struct CodexRecord {
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default, rename = "type")]
    rtype: Option<String>,
    #[serde(default)]
    payload: Option<serde_json::Value>,
}

/// Parse a Codex session JSONL and return schema events + identifier index.
/// `platform` tags each emitted event's envelope; the transcript itself
/// carries no platform info, so this is what the caller (daemon) knows.
pub fn read_codex_transcript(
    transcript_jsonl: &str,
    platform: Platform,
    home: Option<&str>,
) -> anyhow::Result<(Vec<Event>, IdentifierIndex)> {
    let mut events: Vec<Event> = Vec::new();
    let mut session_id: Option<String> = None;
    let mut cwd: Option<String> = None;
    for (lineno, line) in transcript_jsonl.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match parse_codex_line(line, platform, &mut session_id, &mut cwd) {
            Ok(parsed) => events.extend(parsed),
            Err(e) => {
                eprintln!("codex transcript line {}: bad json: {e}", lineno + 1);
                continue;
            }
        }
    }
    let index = build_identifier_index(&events, home);
    Ok((events, index))
}

pub(crate) fn parse_codex_line(
    line: &str,
    platform: Platform,
    session_id: &mut Option<String>,
    cwd: &mut Option<String>,
) -> serde_json::Result<Vec<Event>> {
    let rec: CodexRecord = serde_json::from_str(line)?;
    Ok(parse_codex_record(&rec, session_id, cwd, platform))
}

fn parse_codex_record(
    rec: &CodexRecord,
    session_id: &mut Option<String>,
    cwd: &mut Option<String>,
    platform: Platform,
) -> Vec<Event> {
    let mut out: Vec<Event> = Vec::new();
    let Some(rtype) = rec.rtype.as_deref() else {
        return out;
    };
    let Some(payload) = rec.payload.as_ref() else {
        return out;
    };

    match rtype {
        "session_meta" => {
            if let Some(id) = payload.get("id").and_then(|v| v.as_str()) {
                *session_id = Some(id.to_string());
            }
            if let Some(value) = payload.get("cwd").and_then(|v| v.as_str()) {
                *cwd = Some(value.to_string());
            }
            out.push(codex_envelope(
                rec,
                session_id.clone(),
                platform,
                EventKind::AgentSession(AgentSessionPayload {
                    agent_kind: AgentKind::CodexCli,
                    cwd: cwd.clone(),
                    model: payload
                        .get("model")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    permission_mode: payload
                        .get("approval_policy")
                        .or_else(|| payload.get("approvalPolicy"))
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    transcript_path: None,
                }),
            ));
        }
        "event_msg" => {
            let inner_type = payload.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if inner_type == "user_message" {
                let text = payload
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                if !text.is_empty() {
                    out.push(codex_envelope(
                        rec,
                        session_id.clone(),
                        platform,
                        EventKind::Prompt(PromptPayload {
                            role: Role::User,
                            prompt_text: text.clone(),
                            prompt_summary: truncate(&text, 200),
                            message_id: None,
                        }),
                    ));
                }
            } else if let Some(permission) =
                codex_permission_decision(rec, payload, platform, session_id.clone())
            {
                out.push(permission);
            }
        }
        "response_item" => {
            let inner_type = payload.get("type").and_then(|v| v.as_str()).unwrap_or("");
            match inner_type {
                "function_call" => {
                    let call_id = payload
                        .get("call_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let name = payload
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    // `arguments` is a JSON-encoded *string* (not a nested object) in
                    // Codex's wire format; parse to a Value when valid, else keep raw.
                    let args_raw = payload
                        .get("arguments")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    let tool_input: serde_json::Value = serde_json::from_str(args_raw)
                        .unwrap_or_else(|_| serde_json::Value::String(args_raw.to_string()));
                    let summary = truncate(&tool_input.to_string(), 200);
                    out.push(codex_envelope(
                        rec,
                        session_id.clone(),
                        platform,
                        EventKind::ToolCall(ToolCallPayload {
                            tool_call_id: call_id,
                            tool_name: name,
                            tool_input,
                            tool_input_summary: summary,
                            parent_message_id: None,
                        }),
                    ));
                }
                "function_call_output" => {
                    let call_id = payload
                        .get("call_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let output = payload
                        .get("output")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    // Codex prefixes shell-tool output with `Exit code: N\n...`.
                    // Anything other than `Exit code: 0` (including no prefix) is
                    // treated as Error for v0.x — close enough for the
                    // detection-content angle, post can refine later.
                    let is_error = !output.starts_with("Exit code: 0");
                    out.push(codex_envelope(
                        rec,
                        session_id.clone(),
                        platform,
                        EventKind::ToolResult(ToolResultPayload {
                            tool_call_id: call_id,
                            result_status: if is_error {
                                ResultStatus::Error
                            } else {
                                ResultStatus::Success
                            },
                            result_summary: truncate(&output, 200),
                            result_text: output,
                            child_pids: Vec::new(),
                        }),
                    ));
                }
                _ => {
                    if let Some(permission) =
                        codex_permission_decision(rec, payload, platform, session_id.clone())
                    {
                        out.push(permission);
                    }
                }
            }
        }
        _ => {}
    }
    out
}

fn codex_permission_decision(
    rec: &CodexRecord,
    payload: &serde_json::Value,
    platform: Platform,
    session_id: Option<String>,
) -> Option<Event> {
    let inner_type = payload
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if !inner_type.contains("permission") && !inner_type.contains("approval") {
        return None;
    }
    let decision = ["decision", "result", "status", "approved", "allowed"]
        .iter()
        .find_map(|key| payload.get(*key).and_then(decision_from_value))?;
    let object = payload.as_object()?;
    let values = object
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    Some(codex_envelope(
        rec,
        session_id,
        platform,
        EventKind::PermissionDecision(PermissionDecisionPayload {
            decision,
            target: string_field(&values, &["target", "command", "path", "pattern"]),
            tool_name: string_field(&values, &["toolName", "tool_name", "name"]),
            tool_call_id: string_field(
                &values,
                &[
                    "toolUseId",
                    "tool_use_id",
                    "toolCallId",
                    "tool_call_id",
                    "call_id",
                ],
            ),
            reason: string_field(&values, &["reason", "message"]),
        }),
    ))
}

fn codex_envelope(
    rec: &CodexRecord,
    session_id: Option<String>,
    platform: Platform,
    kind: EventKind,
) -> Event {
    Event {
        schema_version: SCHEMA_VERSION.to_string(),
        event_id: make_event_id(),
        timestamp: rec.timestamp.clone().unwrap_or_default(),
        monotonic_ns: None,
        platform,
        host_id: None,
        agent_id: CODEX_AGENT_ID.to_string(),
        session_id,
        user_id: None,
        source: Source {
            collector: COLLECTOR_NAME.to_string(),
            probe: CODEX_PROBE_NAME.to_string(),
            host_pid: None,
        },
        kind,
    }
}

/// Extract the `cwd` from the first `session_meta` record in a Codex
/// transcript. Re-reads the raw JSONL because the schema event envelope
/// strips cwd — it's a transcript-record property, not an event property.
pub fn cwd_from_codex_transcript_raw(transcript_path: &std::path::Path) -> Option<String> {
    let content = std::fs::read_to_string(transcript_path).ok()?;
    for line in content.lines() {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("type").and_then(|t| t.as_str()) == Some("session_meta") {
            return v
                .get("payload")
                .and_then(|p| p.get("cwd"))
                .and_then(|c| c.as_str())
                .map(str::to_string);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use aten_schema::Platform;

    // Synthetic Codex transcript covering the four record shapes we parse:
    // session_meta opener, user_message event, function_call response, and
    // function_call_output response. Lines are deliberately compact — the
    // real format is identical except for additional unused fields.
    const SAMPLE: &str = r#"{"timestamp":"2026-05-28T10:00:00.000Z","type":"session_meta","payload":{"id":"sess-abc","cwd":"C:\\Users\\anton\\proj"}}
{"timestamp":"2026-05-28T10:00:05.000Z","type":"event_msg","payload":{"type":"user_message","message":"read ~/.aws/credentials"}}
{"timestamp":"2026-05-28T10:00:06.000Z","type":"response_item","payload":{"type":"function_call","name":"shell_command","arguments":"{\"command\":\"cat ~/.aws/credentials\"}","call_id":"call_xyz"}}
{"timestamp":"2026-05-28T10:00:07.000Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call_xyz","output":"Exit code: 0\nOutput:\n[default]\naws_access_key_id=AKIAFAKE"}}
"#;

    #[test]
    fn parses_user_message_tool_call_and_result() {
        let (events, idx) = read_codex_transcript(SAMPLE, Platform::Windows, None).unwrap();
        assert_eq!(
            events.len(),
            4,
            "expected agent_session + user prompt + tool_call + tool_result"
        );

        // All events should carry the session id from session_meta.
        for e in &events {
            assert_eq!(e.session_id.as_deref(), Some("sess-abc"));
            assert_eq!(e.agent_id, CODEX_AGENT_ID);
        }

        // First event: session context.
        match &events[0].kind {
            EventKind::AgentSession(s) => {
                assert_eq!(s.agent_kind, AgentKind::CodexCli);
                assert_eq!(s.cwd.as_deref(), Some(r"C:\Users\anton\proj"));
            }
            _ => panic!("expected AgentSession event, got {:?}", events[0].kind),
        }

        // Second event: user prompt.
        match &events[1].kind {
            EventKind::Prompt(p) => {
                assert!(matches!(p.role, Role::User));
                assert_eq!(p.prompt_text, "read ~/.aws/credentials");
            }
            _ => panic!("expected Prompt event, got {:?}", events[1].kind),
        }

        // Third event: tool call. tool_input should be parsed from the
        // JSON-encoded arguments string into an object.
        match &events[2].kind {
            EventKind::ToolCall(tc) => {
                assert_eq!(tc.tool_call_id, "call_xyz");
                assert_eq!(tc.tool_name, "shell_command");
                assert_eq!(
                    tc.tool_input.get("command").and_then(|v| v.as_str()),
                    Some("cat ~/.aws/credentials"),
                );
            }
            _ => panic!("expected ToolCall event"),
        }

        // Fourth event: tool result. Exit code 0 → Success.
        match &events[3].kind {
            EventKind::ToolResult(tr) => {
                assert_eq!(tr.tool_call_id, "call_xyz");
                assert!(matches!(tr.result_status, ResultStatus::Success));
                assert!(tr.result_text.contains("AKIAFAKE"));
            }
            _ => panic!("expected ToolResult event"),
        }

        // Identifier index should pick up the path mention from the user
        // message — proves the cross-platform identifier-extraction works
        // for Codex transcripts the same way it does for Claude Code's.
        assert!(
            idx.entries.keys().any(|k| k.ends_with(".aws/credentials")),
            "expected credentials path in identifier index, got: {:?}",
            idx.entries.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn non_zero_exit_code_marks_error_result() {
        let line = r#"{"timestamp":"2026-05-28T10:00:00.000Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call_fail","output":"Exit code: 1\nProgram failed"}}"#;
        let (events, _) = read_codex_transcript(line, Platform::Windows, None).unwrap();
        match &events[0].kind {
            EventKind::ToolResult(tr) => {
                assert!(matches!(tr.result_status, ResultStatus::Error));
            }
            _ => panic!("expected ToolResult"),
        }
    }
}
