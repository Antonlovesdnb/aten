//! Windows Event Log sink — writes aten events to the manifest-declared
//! ETW channel `ATEN/Operational`.
//!
//! This is the runtime counterpart of `eventlog/aten.man`. The provider
//! GUID, channel value, per-event IDs, Task values, and — critically — the
//! field ORDER of every event MUST match the manifest. Each event kind has its
//! own template of typed, named fields (so Event Viewer renders native
//! `<EventData>` and SIEM/WEF can address fields by XPath), with a trailing
//! `RawJson` field carrying the whole event for anything not promoted.
//!
//! Booleans are emitted as `"true"`/`"false"` strings to dodge ETW boolean
//! width ambiguity; numeric ids/ports are `Int32`. The `fields_for_*` builders
//! and the templates in aten.man are a hand-maintained contract — the
//! `field_counts_match_templates` test guards the field counts.

use std::io;

use aten_schema::{
    AccessType, CredentialClass, DnsQueryType, Event, EventKind, FileWriteClass, Protocol,
    ResultStatus, Role,
};
use windows::core::GUID;
use windows::Win32::System::Diagnostics::Etw::{
    EventRegister, EventUnregister, EventWrite, EVENT_DATA_DESCRIPTOR, EVENT_DESCRIPTOR, REGHANDLE,
};

/// Must equal the `guid` on `<provider>` in aten.man.
pub const PROVIDER_GUID: GUID = GUID::from_u128(0x0e28e4c0_89f9_4b9d_9f35_bd497b26c397);

/// Operational channel id — the `value="16"` on `<channel>` in aten.man.
const CHANNEL_OPERATIONAL: u8 = 16;

// ETW level constants (winmeta). Match the per-event `level=` in the manifest.
const LEVEL_WARNING: u8 = 3;
const LEVEL_INFORMATIONAL: u8 = 4;

/// Map an event kind to its manifest Event ID. Kept in lockstep with the
/// `value="…"` attributes in aten.man (asserted by the unit test below).
/// The manifest Task value is the same number, so this doubles as the Task.
pub fn event_id_for(kind: &EventKind) -> u16 {
    match kind {
        EventKind::ProcessExec(_) => 1,
        EventKind::ProcessExit(_) => 2,
        EventKind::CredentialAccess(_) => 3,
        EventKind::NetworkEgress(_) => 4,
        EventKind::FileWrite(_) => 5,
        EventKind::DnsQuery(_) => 6,
        EventKind::LocalIpcAccess(_) => 7,
        EventKind::AgentSession(_) => 13,
        EventKind::Prompt(_) => 10,
        EventKind::ToolCall(_) => 11,
        EventKind::ToolResult(_) => 12,
        EventKind::PermissionDecision(_) => 14,
        // Daemon/collector self-telemetry. Kept in lockstep with
        // EVT_COLLECTOR_STATUS and the `t_status` template in aten.man.
        EventKind::CollectorStatus(_) => 20,
    }
}

fn level_for(kind: &EventKind) -> u8 {
    match kind {
        EventKind::CredentialAccess(_)
        | EventKind::NetworkEgress(_)
        | EventKind::FileWrite(_)
        | EventKind::LocalIpcAccess(_)
        | EventKind::PermissionDecision(_)
        // A dropped-event marker is a warning: it means telemetry was lost.
        | EventKind::CollectorStatus(_) => LEVEL_WARNING,
        // A DNS query on its own is benign (agents resolve their own API
        // hosts constantly); the SIEM rule elevates it by joining to origin.
        _ => LEVEL_INFORMATIONAL,
    }
}

/// The `process.pid` for the generic-template kinds, or 0.
fn pid_for(kind: &EventKind) -> i32 {
    match kind {
        EventKind::ProcessExec(p) => p.process.pid,
        EventKind::ProcessExit(p) => p.process.pid,
        EventKind::CredentialAccess(p) => p.process.pid,
        EventKind::NetworkEgress(p) => p.process.pid,
        EventKind::FileWrite(p) => p.process.pid,
        EventKind::DnsQuery(p) => p.process.pid,
        EventKind::LocalIpcAccess(p) => p.process.pid,
        EventKind::AgentSession(_)
        | EventKind::Prompt(_)
        | EventKind::ToolCall(_)
        | EventKind::ToolResult(_)
        | EventKind::PermissionDecision(_)
        | EventKind::CollectorStatus(_) => 0,
    }
}

/// A registered ETW provider that writes events to `ATEN/Operational`.
pub struct EventLogSink {
    handle: REGHANDLE,
}

impl EventLogSink {
    pub fn new() -> io::Result<Self> {
        let mut handle = REGHANDLE::default();
        // SAFETY: standard EventRegister call; `handle` is a valid out-param.
        let rc = unsafe { EventRegister(&PROVIDER_GUID, None, None, &mut handle) };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        Ok(Self { handle })
    }

    /// Write one event to the channel. Best-effort: ETW drops the write if the
    /// channel isn't enabled / provider not registered, and we ignore the
    /// return code (telemetry must never block or fail the daemon).
    pub fn write_event(&self, ev: &Event) {
        let id = event_id_for(&ev.kind);
        let desc = EVENT_DESCRIPTOR {
            Id: id,
            Version: 0,
            Channel: CHANNEL_OPERATIONAL,
            Level: level_for(&ev.kind),
            Opcode: 0,
            Task: id, // manifest Task value == Event ID
            Keyword: 0,
        };

        let json = serde_json::to_string(ev).unwrap_or_default();
        let fields = fields_for(ev, &json);

        // `fields` owns the backing buffers; the descriptors borrow into it and
        // it stays alive across the EventWrite call below.
        let data: Vec<EVENT_DATA_DESCRIPTOR> = fields
            .iter()
            .map(|f| match f {
                Field::S(v) => desc_str(v),
                Field::I(i) => desc_i32(i),
                Field::U(u) => desc_u64(u),
            })
            .collect();

        // SAFETY: every descriptor points at a live buffer in `fields` with a
        // correct byte length; `data` and `fields` outlive the call.
        unsafe {
            let _ = EventWrite(self.handle, &desc, Some(&data));
        }
    }
}

impl Drop for EventLogSink {
    fn drop(&mut self) {
        if self.handle.0 != 0 {
            // SAFETY: handle came from a successful EventRegister.
            unsafe {
                let _ = EventUnregister(self.handle);
            }
        }
    }
}

// EventLogSink is safe to move across threads — the REGHANDLE is just a u64 and
// EventWrite is internally synchronised by ETW.
unsafe impl Send for EventLogSink {}

/// One template field: an already-encoded UTF-16 string, an i32, or a u64.
enum Field {
    S(Vec<u16>),
    I(i32),
    U(u64),
}

fn s(v: &str) -> Field {
    Field::S(utf16z(v))
}
fn so(v: Option<&str>) -> Field {
    Field::S(utf16z(v.unwrap_or("")))
}
fn b(v: bool) -> Field {
    Field::S(utf16z(if v { "true" } else { "false" }))
}
fn iv(v: i32) -> Field {
    Field::I(v)
}
fn uv(v: u64) -> Field {
    Field::U(v)
}

// Wire strings for the schema enums emitted as ETW template fields. Hand-mapped
// (not via serde_json) so each emitted event avoids a serde round-trip plus two
// heap allocations per enum field. The `wire_strings_match_serde` test asserts
// these stay in lockstep with the serde `rename_all` derivation, so a schema
// rename can't silently drift the channel's field values.
fn cred_class_wire(v: &CredentialClass) -> &'static str {
    match v {
        CredentialClass::AwsCredentials => "aws_credentials",
        CredentialClass::AzureCredentials => "azure_credentials",
        CredentialClass::GcpCredentials => "gcp_credentials",
        CredentialClass::SshPrivateKey => "ssh_private_key",
        CredentialClass::SshAuthorizedKeys => "ssh_authorized_keys",
        CredentialClass::GitCredentials => "git_credentials",
        CredentialClass::Netrc => "netrc",
        CredentialClass::NpmToken => "npm_token",
        CredentialClass::PypiCredentials => "pypi_credentials",
        CredentialClass::DockerConfig => "docker_config",
        CredentialClass::GithubCliToken => "github_cli_token",
        CredentialClass::DpapiBlob => "dpapi_blob",
        CredentialClass::CredentialManager => "credential_manager",
        CredentialClass::BrowserCookies => "browser_cookies",
        CredentialClass::KubeConfig => "kube_config",
        CredentialClass::GenericDotenv => "generic_dotenv",
        CredentialClass::AgentState => "agent_state",
        CredentialClass::None => "none",
    }
}

fn access_type_wire(v: &AccessType) -> &'static str {
    match v {
        AccessType::Read => "read",
        AccessType::Write => "write",
        AccessType::Open => "open",
    }
}

fn protocol_wire(v: &Protocol) -> &'static str {
    match v {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

fn dns_type_wire(v: &DnsQueryType) -> &'static str {
    match v {
        DnsQueryType::A => "a",
        DnsQueryType::Aaaa => "aaaa",
        DnsQueryType::Cname => "cname",
        DnsQueryType::Txt => "txt",
        DnsQueryType::Mx => "mx",
        DnsQueryType::Ns => "ns",
        DnsQueryType::Ptr => "ptr",
        DnsQueryType::Srv => "srv",
        DnsQueryType::Soa => "soa",
        DnsQueryType::Other => "other",
    }
}

fn write_class_wire(v: &FileWriteClass) -> &'static str {
    match v {
        FileWriteClass::AgentConfig => "agent_config",
        FileWriteClass::Executable => "executable",
        FileWriteClass::ShellProfile => "shell_profile",
        FileWriteClass::ScheduledTask => "scheduled_task",
        FileWriteClass::GitHook => "git_hook",
        FileWriteClass::StartupItem => "startup_item",
        FileWriteClass::PackageManifest => "package_manifest",
        FileWriteClass::Lockfile => "lockfile",
    }
}

fn role_wire(v: &Role) -> &'static str {
    match v {
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::System => "system",
    }
}

fn result_status_wire(v: &ResultStatus) -> &'static str {
    match v {
        ResultStatus::Success => "success",
        ResultStatus::Error => "error",
    }
}

/// Fields 1-16 shared by the kernel templates (t_proc_exec / t_cred / t_net).
fn kernel_common(ev: &Event, p: &aten_schema::Process, a: &aten_schema::Attribution) -> Vec<Field> {
    vec![
        s(&ev.timestamp),
        so(ev.host_id.as_deref()),
        s(&ev.agent_id),
        so(ev.user_id.as_deref()),
        iv(p.pid),
        iv(p.ppid),
        s(&p.name),
        s(&p.path),
        s(&p.cmdline),
        s(&p.user),
        iv(p.agent_root_pid.unwrap_or(0)),
        b(a.attributed_by_descent),
        b(a.requested_in_tool_result),
        so(a.triggering_command.as_deref()),
        so(a.triggering_prompt.as_deref()),
        s(&parent_chain_str(&p.parent_chain)),
    ]
}

/// Flatten the process ancestry to `root(pid) > … > parent(pid)` for the
/// ParentChain field. Matches the schema's root → immediate-parent order.
fn parent_chain_str(chain: &[aten_schema::ParentChainEntry]) -> String {
    chain
        .iter()
        .map(|e| format!("{}({})", e.name, e.pid))
        .collect::<Vec<_>>()
        .join(" > ")
}

/// Envelope prefix (fields 1-5) shared by the transcript templates.
fn envelope5(ev: &Event) -> Vec<Field> {
    vec![
        s(&ev.timestamp),
        so(ev.host_id.as_deref()),
        s(&ev.agent_id),
        so(ev.user_id.as_deref()),
        so(ev.session_id.as_deref()),
    ]
}

/// Build the typed field list for `ev`, in the exact order of the matching
/// template in aten.man. `RawJson` is always last.
fn fields_for(ev: &Event, json: &str) -> Vec<Field> {
    match &ev.kind {
        EventKind::ProcessExec(p) => {
            let mut f = kernel_common(ev, &p.process, &p.attribution);
            f.push(s(&p.exec_args.join(" ")));
            f.push(s(json));
            f
        }
        EventKind::CredentialAccess(p) => {
            let mut f = kernel_common(ev, &p.process, &p.attribution);
            f.push(s(&p.file_path));
            f.push(s(cred_class_wire(&p.credential_class)));
            f.push(s(access_type_wire(&p.access_type)));
            f.push(s(json));
            f
        }
        EventKind::NetworkEgress(p) => {
            let mut f = kernel_common(ev, &p.process, &p.attribution);
            f.push(s(&p.dest_ip));
            f.push(iv(p.dest_port as i32));
            f.push(s(protocol_wire(&p.protocol)));
            f.push(so(p.dest_host.as_deref()));
            f.push(s(json));
            f
        }
        EventKind::Prompt(p) => {
            let mut f = envelope5(ev);
            f.push(s(role_wire(&p.role)));
            f.push(s(&p.prompt_summary));
            f.push(s(json));
            f
        }
        EventKind::ToolCall(p) => {
            let mut f = envelope5(ev);
            f.push(s(&p.tool_name));
            f.push(s(&p.tool_call_id));
            f.push(s(&p.tool_input_summary));
            f.push(s(json));
            f
        }
        EventKind::ToolResult(p) => {
            let mut f = envelope5(ev);
            f.push(s(&p.tool_call_id));
            f.push(s(result_status_wire(&p.result_status)));
            f.push(s(&p.result_summary));
            f.push(s(json));
            f
        }
        EventKind::FileWrite(p) => {
            let mut f = kernel_common(ev, &p.process, &p.attribution);
            f.push(s(&p.file_path));
            f.push(s(write_class_wire(&p.write_class)));
            // BytesWritten as a string: the number, or "" when the probe only
            // saw the open-for-write (Option::None).
            f.push(s(&p
                .bytes_written
                .map(|n| n.to_string())
                .unwrap_or_default()));
            f.push(s(json));
            f
        }
        EventKind::DnsQuery(p) => {
            let mut f = kernel_common(ev, &p.process, &p.attribution);
            f.push(s(&p.query_name));
            f.push(s(dns_type_wire(&p.query_type)));
            // Answers flattened comma-separated; "" when only the query was seen.
            f.push(s(&p.answers.join(",")));
            f.push(s(json));
            f
        }
        // t_generic: Timestamp, HostId, AgentId, Pid, RawJson.
        EventKind::ProcessExit(_)
        | EventKind::AgentSession(_)
        | EventKind::PermissionDecision(_)
        | EventKind::LocalIpcAccess(_) => vec![
            s(&ev.timestamp),
            so(ev.host_id.as_deref()),
            s(&ev.agent_id),
            iv(pid_for(&ev.kind)),
            s(json),
        ],
        // t_status: Timestamp, HostId, AgentId, DroppedTotal,
        // DroppedSinceLast, Reason, RawJson.
        EventKind::CollectorStatus(p) => vec![
            s(&ev.timestamp),
            so(ev.host_id.as_deref()),
            s(&ev.agent_id),
            uv(p.dropped_total),
            uv(p.dropped_since_last),
            s(&p.reason),
            s(json),
        ],
    }
}

/// UTF-16, NUL-terminated (ETW UnicodeString fields include the terminator).
fn utf16z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn desc_str(buf: &[u16]) -> EVENT_DATA_DESCRIPTOR {
    EVENT_DATA_DESCRIPTOR {
        Ptr: buf.as_ptr() as u64,
        Size: std::mem::size_of_val(buf) as u32,
        ..Default::default()
    }
}

fn desc_i32(v: &i32) -> EVENT_DATA_DESCRIPTOR {
    EVENT_DATA_DESCRIPTOR {
        Ptr: v as *const i32 as u64,
        Size: std::mem::size_of::<i32>() as u32,
        ..Default::default()
    }
}

fn desc_u64(v: &u64) -> EVENT_DATA_DESCRIPTOR {
    EVENT_DATA_DESCRIPTOR {
        Ptr: v as *const u64 as u64,
        Size: std::mem::size_of::<u64>() as u32,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aten_schema::{
        AccessType, Attribution, CollectorStatusPayload, CredentialAccessPayload, CredentialClass,
        NetworkEgressPayload, Process, ProcessExecPayload, PromptPayload, Protocol, Role,
        ToolCallPayload,
    };

    fn proc() -> Process {
        Process {
            pid: 4242,
            ppid: 1,
            start_time: "0".into(),
            name: "claude.exe".into(),
            path: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            user: String::new(),
            integrity_level: None,
            parent_chain: vec![],
            agent_root_pid: Some(4242),
        }
    }
    fn attr() -> Attribution {
        Attribution {
            attributed_tool_call_id: None,
            attributed_by_descent: false,
            requested_by_tool_call: false,
            requested_in_user_message: false,
            requested_in_assistant_message: false,
            requested_in_tool_result: false,
            time_window_ms: None,
            triggering_command: None,
            triggering_prompt: None,
        }
    }
    fn ev(kind: EventKind) -> Event {
        Event {
            schema_version: "0.4".into(),
            event_id: "id".into(),
            timestamp: "2026-05-29T00:00:00Z".into(),
            monotonic_ns: None,
            platform: aten_schema::Platform::Windows,
            host_id: Some("host".into()),
            agent_id: "claude.exe".into(),
            session_id: None,
            user_id: Some("u".into()),
            source: aten_schema::Source {
                collector: "windows_etw".into(),
                probe: "x".into(),
                host_pid: Some(4242),
            },
            kind,
        }
    }

    #[test]
    fn event_ids_match_manifest() {
        let exec = EventKind::ProcessExec(ProcessExecPayload {
            process: proc(),
            attribution: attr(),
            exec_args: vec![],
            exec_envp_summary: String::new(),
            supply_chain_activity: None,
        });
        assert_eq!(event_id_for(&exec), 1);

        let cred = EventKind::CredentialAccess(CredentialAccessPayload {
            process: proc(),
            attribution: attr(),
            file_path: "C:\\x\\.aws\\credentials".into(),
            access_type: AccessType::Open,
            credential_class: CredentialClass::AwsCredentials,
            bytes_read: None,
        });
        assert_eq!(event_id_for(&cred), 3);
        assert_eq!(level_for(&cred), LEVEL_WARNING);

        let status = EventKind::CollectorStatus(CollectorStatusPayload {
            dropped_total: 10,
            dropped_since_last: 2,
            reason: "test".into(),
        });
        assert_eq!(event_id_for(&status), 20);
        assert_eq!(level_for(&status), LEVEL_WARNING);

        let ipc = EventKind::LocalIpcAccess(aten_schema::LocalIpcAccessPayload {
            process: proc(),
            attribution: attr(),
            ipc_path: r"\\.\pipe\docker_engine".into(),
            ipc_class: aten_schema::LocalIpcClass::DockerSocket,
        });
        assert_eq!(event_id_for(&ipc), 7);
        assert_eq!(level_for(&ipc), LEVEL_WARNING);
    }

    #[test]
    fn utf16z_terminates() {
        assert_eq!(utf16z("hi"), vec![0x68, 0x69, 0x00]);
    }

    #[test]
    fn parent_chain_flattens() {
        use aten_schema::ParentChainEntry;
        let chain = vec![
            ParentChainEntry {
                pid: 100,
                name: "explorer.exe".into(),
            },
            ParentChainEntry {
                pid: 200,
                name: "claude.exe".into(),
            },
        ];
        assert_eq!(
            parent_chain_str(&chain),
            "explorer.exe(100) > claude.exe(200)"
        );
        assert_eq!(parent_chain_str(&[]), "");
    }

    /// The hand-mapped wire strings MUST equal serde's `rename_all` output for
    /// every variant — otherwise the ETW channel's typed fields silently drift
    /// from the JSONL/schema wire format. Compare against serde directly so a
    /// schema rename breaks this test rather than production output.
    #[test]
    fn wire_strings_match_serde() {
        fn serde_wire<T: serde::Serialize>(v: &T) -> String {
            serde_json::to_string(v)
                .unwrap()
                .trim_matches('"')
                .to_string()
        }
        use aten_schema::{
            AccessType::*, CredentialClass::*, DnsQueryType::*, FileWriteClass::*, Protocol::*,
            ResultStatus::*, Role::*,
        };
        for v in [
            AwsCredentials,
            AzureCredentials,
            GcpCredentials,
            SshPrivateKey,
            SshAuthorizedKeys,
            GitCredentials,
            Netrc,
            NpmToken,
            PypiCredentials,
            DockerConfig,
            GithubCliToken,
            DpapiBlob,
            CredentialManager,
            BrowserCookies,
            KubeConfig,
            GenericDotenv,
            AgentState,
            CredentialClass::None,
        ] {
            assert_eq!(cred_class_wire(&v), serde_wire(&v), "{v:?}");
        }
        for v in [Read, Write, Open] {
            assert_eq!(access_type_wire(&v), serde_wire(&v), "{v:?}");
        }
        for v in [Tcp, Udp] {
            assert_eq!(protocol_wire(&v), serde_wire(&v), "{v:?}");
        }
        for v in [A, Aaaa, Cname, Txt, Mx, Ns, Ptr, Srv, Soa, Other] {
            assert_eq!(dns_type_wire(&v), serde_wire(&v), "{v:?}");
        }
        for v in [
            AgentConfig,
            Executable,
            ShellProfile,
            ScheduledTask,
            GitHook,
            StartupItem,
            PackageManifest,
            Lockfile,
        ] {
            assert_eq!(write_class_wire(&v), serde_wire(&v), "{v:?}");
        }
        for v in [User, Assistant, System] {
            assert_eq!(role_wire(&v), serde_wire(&v), "{v:?}");
        }
        for v in [Success, Error] {
            assert_eq!(result_status_wire(&v), serde_wire(&v), "{v:?}");
        }
    }

    /// The field count of each builder MUST equal its template's `<data>` count
    /// in aten.man, or Event Viewer renders garbage / truncates.
    #[test]
    fn field_counts_match_templates() {
        let cred = ev(EventKind::CredentialAccess(CredentialAccessPayload {
            process: proc(),
            attribution: attr(),
            file_path: "p".into(),
            access_type: AccessType::Open,
            credential_class: CredentialClass::AwsCredentials,
            bytes_read: None,
        }));
        // t_cred: 16 common + FilePath + CredentialClass + AccessType + RawJson.
        assert_eq!(fields_for(&cred, "{}").len(), 20);

        let net = ev(EventKind::NetworkEgress(NetworkEgressPayload {
            process: proc(),
            attribution: attr(),
            dest_ip: "1.2.3.4".into(),
            dest_port: 443,
            dest_host: None,
            protocol: Protocol::Tcp,
            tls_sni: None,
            cloud_metadata: None,
        }));
        // t_net: 16 common + DestIp + DestPort + Protocol + DestHost + RawJson.
        assert_eq!(fields_for(&net, "{}").len(), 21);

        let exec = ev(EventKind::ProcessExec(ProcessExecPayload {
            process: proc(),
            attribution: attr(),
            exec_args: vec!["a".into()],
            exec_envp_summary: String::new(),
            supply_chain_activity: None,
        }));
        // t_proc_exec: 16 common + ExecArgs + RawJson.
        assert_eq!(fields_for(&exec, "{}").len(), 18);

        let prompt = ev(EventKind::Prompt(PromptPayload {
            role: Role::User,
            prompt_text: "hi".into(),
            prompt_summary: "hi".into(),
            message_id: None,
        }));
        // t_prompt: 5 envelope + Role + PromptSummary + RawJson.
        assert_eq!(fields_for(&prompt, "{}").len(), 8);

        let call = ev(EventKind::ToolCall(ToolCallPayload {
            tool_call_id: "t".into(),
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({}),
            tool_input_summary: "x".into(),
            parent_message_id: None,
        }));
        // t_tool_call: 5 envelope + ToolName + ToolCallId + ToolInputSummary + RawJson.
        assert_eq!(fields_for(&call, "{}").len(), 9);

        let file = ev(EventKind::FileWrite(aten_schema::FileWritePayload {
            process: proc(),
            attribution: attr(),
            file_path: "C:\\x\\.claude\\settings.json".into(),
            bytes_written: Some(128),
            write_class: aten_schema::FileWriteClass::AgentConfig,
        }));
        // t_file: 16 common + FilePath + WriteClass + BytesWritten + RawJson.
        assert_eq!(fields_for(&file, "{}").len(), 20);
        assert_eq!(event_id_for(&file.kind), 5);
        assert_eq!(level_for(&file.kind), LEVEL_WARNING);

        let dns = ev(EventKind::DnsQuery(aten_schema::DnsQueryPayload {
            process: proc(),
            attribution: attr(),
            query_name: "research.attacker.com".into(),
            query_type: aten_schema::DnsQueryType::Txt,
            answers: vec!["1.2.3.4".into()],
        }));
        // t_dns: 16 common + QueryName + QueryType + Answers + RawJson.
        assert_eq!(fields_for(&dns, "{}").len(), 20);
        assert_eq!(event_id_for(&dns.kind), 6);

        let status = ev(EventKind::CollectorStatus(CollectorStatusPayload {
            dropped_total: 123,
            dropped_since_last: 4,
            reason: "pending queue full".into(),
        }));
        // t_status: Timestamp + HostId + AgentId + DroppedTotal +
        // DroppedSinceLast + Reason + RawJson.
        assert_eq!(fields_for(&status, "{}").len(), 7);
        assert_eq!(event_id_for(&status.kind), 20);

        let ipc = ev(EventKind::LocalIpcAccess(
            aten_schema::LocalIpcAccessPayload {
                process: proc(),
                attribution: attr(),
                ipc_path: "/var/run/docker.sock".into(),
                ipc_class: aten_schema::LocalIpcClass::DockerSocket,
            },
        ));
        // t_generic: Timestamp + HostId + AgentId + Pid + RawJson.
        assert_eq!(fields_for(&ipc, "{}").len(), 5);
        assert_eq!(event_id_for(&ipc.kind), 7);
    }
}
