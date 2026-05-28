//! fishbowl-v2 unified event schema (v0.2).
//!
//! These types are the canonical wire format for events emitted by every fishbowl-v2
//! collector — the Claude Code transcript reader, the Linux eBPF collector, and the
//! Windows ETW collector all produce `Event`s that serialize to the same JSONL.
//!
//! The schema's job is to make detections like the one in schema.md §1 fire identically
//! on both platforms. Field names and semantics are the contract; the per-platform
//! collector code is interchangeable behind it.
//!
//! See `schema.md` at the repo root for the design discussion, attribution model, and
//! worked examples.

use serde::{Deserialize, Serialize};

/// Wire-format version. Bumped on field semantic changes. Additive-only within 0.x.
///
/// History:
/// - 0.1: initial schema.
/// - 0.2: attribution block split into the 5-boolean shape (descent +
///   the four `requested_*`), separating user-typed origin from
///   tool-result origin for prompt-injection scenarios.
/// - 0.3: `Process.parent_chain` changed from `Vec<String>` to
///   `Vec<ParentChainEntry>` so each link carries `{pid, name}`. Order
///   is still root → immediate parent; PIDs let SIEM rules join the
///   chain against `process_exec` events emitted earlier for the same
///   ancestors.
pub const SCHEMA_VERSION: &str = "0.3";

/// One link in a process's ancestor chain. Same order semantics as the
/// old `Vec<String>` (root → immediate parent, excludes the event's own
/// process), but each entry now carries the PID so downstream joins
/// don't need to re-walk PPIDs. The last entry's `pid` should equal
/// the event's `process.ppid`; the first entry's `pid` is the
/// shallowest ancestor we could walk to within the depth cap (typically
/// 16).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentChainEntry {
    pub pid: i32,
    pub name: String,
}

/// One fishbowl event. Serializes flat — envelope fields and the per-kind payload
/// share the top level of the JSON object. `event_type` is the discriminator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub schema_version: String,
    pub event_id: String,
    pub timestamp: String,
    pub monotonic_ns: Option<u64>,
    pub platform: Platform,
    pub host_id: Option<String>,
    pub agent_id: String,
    pub session_id: Option<String>,
    pub user_id: Option<String>,
    pub source: Source,

    #[serde(flatten)]
    pub kind: EventKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Linux,
    Windows,
}

/// Debug-only provenance — never read by detection logic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    pub collector: String,
    pub probe: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_pid: Option<i32>,
}

/// The per-event-type payload. Tagged by `event_type` for serde, internally tagged
/// so the JSON stays flat (top-level fields, no nested "payload" object).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum EventKind {
    Prompt(PromptPayload),
    ToolCall(ToolCallPayload),
    ToolResult(ToolResultPayload),
    ProcessExec(ProcessExecPayload),
    ProcessExit(ProcessExitPayload),
    CredentialAccess(CredentialAccessPayload),
    NetworkEgress(NetworkEgressPayload),
    FileWrite(FileWritePayload),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Assistant,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptPayload {
    pub role: Role,
    pub prompt_text: String,
    pub prompt_summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallPayload {
    pub tool_call_id: String,
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    pub tool_input_summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_message_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ResultStatus {
    Success,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultPayload {
    pub tool_call_id: String,
    pub result_status: ResultStatus,
    pub result_summary: String,
    pub result_text: String,
    pub child_pids: Vec<i32>,
}

/// Process context for any event that originates from an observed process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Process {
    pub pid: i32,
    pub ppid: i32,
    pub start_time: String,
    pub name: String,
    pub path: String,
    pub cmdline: String,
    pub cwd: String,
    pub user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity_level: Option<String>,
    pub parent_chain: Vec<ParentChainEntry>,
    pub agent_root_pid: Option<i32>,
}

/// The schema's signature contribution. Five independent signals describing
/// *where* an observed action's primary identifier first surfaced in the session.
///
/// Detection rules combine these booleans to carve out attack classes — see
/// schema.md §9 for the attribution-cube map and the two killer detections that
/// share this attribution shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribution {
    /// The tool_call this event's process tree descends from. None if no active
    /// tool call when the process (or an ancestor) was spawned.
    pub attributed_tool_call_id: Option<String>,

    /// True if the process was spawned within an active tool call's window AND
    /// descends from the enrolled agent root.
    pub attributed_by_descent: bool,

    /// True if the event's primary identifier (file_path, dest_host, cmdline)
    /// appears in the attributed tool call's tool_input.
    pub requested_by_tool_call: bool,

    /// True if the identifier appears in any user-typed message in this session
    /// up to this event's timestamp.
    pub requested_in_user_message: bool,

    /// True if the identifier appears in any assistant message (model reasoning
    /// chains, text responses) up to this timestamp.
    pub requested_in_assistant_message: bool,

    /// True if the identifier appears in any prior tool_result content in this
    /// session. THIS IS THE PROMPT-INJECTION SIGNAL.
    pub requested_in_tool_result: bool,

    /// Milliseconds between the attributed tool call's emit and this event.
    pub time_window_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessExecPayload {
    pub process: Process,
    pub attribution: Attribution,
    pub exec_args: Vec<String>,
    pub exec_envp_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessExitPayload {
    pub process: Process,
    pub attribution: Attribution,
    pub exit_code: i32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AccessType {
    Read,
    Write,
    Open,
}

/// Credential classifier taxonomy. Runs at the collector so detection rules
/// never need to regex over file_path. Linux and Windows surface the same enum.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialClass {
    AwsCredentials,
    AzureCredentials,
    GcpCredentials,
    SshPrivateKey,
    GitCredentials,
    DpapiBlob,
    CredentialManager,
    BrowserCookies,
    KubeConfig,
    GenericDotenv,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialAccessPayload {
    pub process: Process,
    pub attribution: Attribution,
    pub file_path: String,
    pub access_type: AccessType,
    pub credential_class: CredentialClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_read: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEgressPayload {
    pub process: Process,
    pub attribution: Attribution,
    pub dest_ip: String,
    pub dest_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest_host: Option<String>,
    pub protocol: Protocol,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_sni: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileWritePayload {
    pub process: Process,
    pub attribution: Attribution,
    pub file_path: String,
    pub bytes_written: u64,
    pub is_agent_config: bool,
}

/// Where an identifier surfaced for the first time in a session. Drives the
/// `requested_in_*` booleans on Attribution. See identifier-index docs for the
/// origin precedence and prompt-injection detection logic.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    UserMessage,
    AssistantMessage,
    ToolResult,
}

/// One sighting of an identifier within a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mention {
    pub ts: String,
    pub origin: Origin,
    pub event_id: String,
}

/// All sightings of one identifier within a session, plus a precomputed
/// first-seen origin so detection queries don't need to scan the mention list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub raw_first_form: String,
    pub first_seen_ts: String,
    pub first_seen_origin: Origin,
    pub mentions: Vec<Mention>,
    pub origins: Vec<Origin>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Smoke test: the flat-JSON shape matches what the Python prototype emits
    /// and what schema.md examples show. If this breaks, the daemon and the
    /// Python prototype will produce divergent JSONL.
    #[test]
    fn prompt_event_serializes_flat() {
        let e = Event {
            schema_version: SCHEMA_VERSION.to_string(),
            event_id: "abc".to_string(),
            timestamp: "2026-05-27T17:52:06.431Z".to_string(),
            monotonic_ns: None,
            platform: Platform::Windows,
            host_id: None,
            agent_id: "claude-code".to_string(),
            session_id: Some("sess-1".to_string()),
            user_id: None,
            source: Source {
                collector: "transcript".to_string(),
                probe: "claude-code-jsonl".to_string(),
                host_pid: None,
            },
            kind: EventKind::Prompt(PromptPayload {
                role: Role::User,
                prompt_text: "hello".to_string(),
                prompt_summary: "hello".to_string(),
                message_id: Some("msg-1".to_string()),
            }),
        };

        let v: serde_json::Value = serde_json::to_value(&e).unwrap();
        assert_eq!(v["event_type"], json!("prompt"));
        assert_eq!(v["role"], json!("user"));
        assert_eq!(v["prompt_text"], json!("hello"));
        assert_eq!(v["schema_version"], json!(SCHEMA_VERSION));
    }

    #[test]
    fn tool_call_event_serializes_flat() {
        let e = Event {
            schema_version: SCHEMA_VERSION.to_string(),
            event_id: "abc".to_string(),
            timestamp: "t".to_string(),
            monotonic_ns: None,
            platform: Platform::Linux,
            host_id: None,
            agent_id: "claude-code".to_string(),
            session_id: Some("sess-1".to_string()),
            user_id: None,
            source: Source {
                collector: "transcript".to_string(),
                probe: "claude-code-jsonl".to_string(),
                host_pid: None,
            },
            kind: EventKind::ToolCall(ToolCallPayload {
                tool_call_id: "toolu_1".to_string(),
                tool_name: "Bash".to_string(),
                tool_input: json!({"command": "ls"}),
                tool_input_summary: "ls".to_string(),
                parent_message_id: None,
            }),
        };
        let v: serde_json::Value = serde_json::to_value(&e).unwrap();
        assert_eq!(v["event_type"], json!("tool_call"));
        assert_eq!(v["tool_name"], json!("Bash"));
        assert_eq!(v["tool_input"]["command"], json!("ls"));
    }

    /// The prompt-injection detection in schema.md §9.2 hinges on the
    /// requested_in_tool_result boolean being a distinct field. Confirm the
    /// attribution block deserializes the five-boolean shape.
    #[test]
    fn attribution_carries_five_booleans() {
        let json = r#"{
            "attributed_tool_call_id": "toolu_1",
            "attributed_by_descent": true,
            "requested_by_tool_call": false,
            "requested_in_user_message": false,
            "requested_in_assistant_message": true,
            "requested_in_tool_result": true,
            "time_window_ms": 92
        }"#;
        let a: Attribution = serde_json::from_str(json).unwrap();
        assert!(a.requested_in_tool_result);
        assert!(!a.requested_in_user_message);
    }

    #[test]
    fn credential_class_round_trips() {
        let v = serde_json::to_value(CredentialClass::AwsCredentials).unwrap();
        assert_eq!(v, json!("aws_credentials"));
        let back: CredentialClass = serde_json::from_value(v).unwrap();
        assert_eq!(back, CredentialClass::AwsCredentials);
    }
}
