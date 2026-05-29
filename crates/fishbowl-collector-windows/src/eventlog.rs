//! Windows Event Log sink — writes fishbowl events to the manifest-declared
//! ETW channel `Fishbowl/Operational`.
//!
//! This is the runtime counterpart of `eventlog/fishbowl.man`. The provider GUID
//! and channel value here MUST match the manifest, and `event_id_for` MUST match
//! the per-event `value="…"` in the manifest (the `event_ids_match_manifest`
//! test guards the IDs).
//!
//! Because the manifest declares an Operational channel, `EventWrite` routes
//! each event into the Windows Event Log (visible in Event Viewer, collectable
//! by WEF / SIEM agents) — an unmanifested provider would only feed live trace
//! sessions. The channel + message resources are registered separately at
//! install time (`wevtutil im`); writing requires admin and a registered
//! provider, but degrades silently (events are simply dropped by the OS if the
//! provider/channel isn't enabled).

use std::io;

use fishbowl_schema::{Event, EventKind};
use windows::core::GUID;
use windows::Win32::System::Diagnostics::Etw::{
    EventRegister, EventUnregister, EventWrite, EVENT_DATA_DESCRIPTOR, EVENT_DESCRIPTOR, REGHANDLE,
};

/// Must equal the `guid` on `<provider>` in fishbowl.man.
pub const PROVIDER_GUID: GUID = GUID::from_u128(0x0e28e4c0_89f9_4b9d_9f35_bd497b26c397);

/// Operational channel id — the `value="16"` on `<channel>` in fishbowl.man.
/// Stamped into every EVENT_DESCRIPTOR.Channel so the event routes to the log.
const CHANNEL_OPERATIONAL: u8 = 16;

// ETW level constants (winmeta). Match the per-event `level=` in the manifest.
const LEVEL_WARNING: u8 = 3;
const LEVEL_INFORMATIONAL: u8 = 4;

/// Map an event kind to its manifest Event ID. Kept in lockstep with the
/// `value="…"` attributes in fishbowl.man (asserted by the unit test below).
pub fn event_id_for(kind: &EventKind) -> u16 {
    match kind {
        EventKind::ProcessExec(_) => 1,
        EventKind::ProcessExit(_) => 2,
        EventKind::CredentialAccess(_) => 3,
        EventKind::NetworkEgress(_) => 4,
        EventKind::FileWrite(_) => 5,
        EventKind::Prompt(_) => 10,
        EventKind::ToolCall(_) => 11,
        EventKind::ToolResult(_) => 12,
    }
}

fn level_for(kind: &EventKind) -> u8 {
    match kind {
        EventKind::CredentialAccess(_) | EventKind::NetworkEgress(_) => LEVEL_WARNING,
        _ => LEVEL_INFORMATIONAL,
    }
}

/// The `process.pid` promoted into the event's `Pid` field, or 0 for the
/// transcript-derived kinds that have no process.
fn pid_for(kind: &EventKind) -> i32 {
    match kind {
        EventKind::ProcessExec(p) => p.process.pid,
        EventKind::ProcessExit(p) => p.process.pid,
        EventKind::CredentialAccess(p) => p.process.pid,
        EventKind::NetworkEgress(p) => p.process.pid,
        EventKind::FileWrite(p) => p.process.pid,
        EventKind::Prompt(_) | EventKind::ToolCall(_) | EventKind::ToolResult(_) => 0,
    }
}

/// A registered ETW provider that writes events to `Fishbowl/Operational`.
/// `EventRegister` on `new`, `EventUnregister` on `Drop`.
pub struct EventLogSink {
    handle: REGHANDLE,
}

impl EventLogSink {
    pub fn new() -> io::Result<Self> {
        let mut handle = REGHANDLE::default();
        // SAFETY: standard EventRegister call; `handle` is a valid out-param.
        let rc = unsafe { EventRegister(&PROVIDER_GUID, None, None, &mut handle) };
        // EventRegister returns a Win32 error code; 0 == ERROR_SUCCESS.
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
            Task: 0,
            Keyword: 0,
        };

        // Field order matches template `t_event`: EventJson, Pid, AgentId, HostId.
        let json = serde_json::to_string(ev).unwrap_or_default();
        let json_w = utf16z(&json);
        let pid = pid_for(&ev.kind);
        let agent_w = utf16z(&ev.agent_id);
        let host_w = utf16z(ev.host_id.as_deref().unwrap_or(""));

        let data = [
            desc_str(&json_w),
            desc_i32(&pid),
            desc_str(&agent_w),
            desc_str(&host_w),
        ];

        // SAFETY: `data` outlives the call; each descriptor points at a live
        // buffer with a correct byte length.
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

/// UTF-16, NUL-terminated (ETW UnicodeString fields include the terminator).
fn utf16z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn desc_str(buf: &[u16]) -> EVENT_DATA_DESCRIPTOR {
    EVENT_DATA_DESCRIPTOR {
        Ptr: buf.as_ptr() as u64,
        Size: (buf.len() * std::mem::size_of::<u16>()) as u32,
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

#[cfg(test)]
mod tests {
    use super::*;
    use fishbowl_schema::{
        Attribution, CredentialAccessPayload, CredentialClass, AccessType, NetworkEgressPayload,
        ProcessExecPayload, Process, Protocol,
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

    #[test]
    fn event_ids_match_manifest() {
        // These literals are the contract with fishbowl.man's value="…".
        let exec = EventKind::ProcessExec(ProcessExecPayload {
            process: proc(),
            attribution: attr(),
            exec_args: vec![],
            exec_envp_summary: String::new(),
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

        let net = EventKind::NetworkEgress(NetworkEgressPayload {
            process: proc(),
            attribution: attr(),
            dest_ip: "203.0.113.9".into(),
            dest_port: 443,
            dest_host: None,
            protocol: Protocol::Tcp,
            tls_sni: None,
        });
        assert_eq!(event_id_for(&net), 4);
        assert_eq!(level_for(&net), LEVEL_WARNING);
        assert_eq!(pid_for(&net), 4242);
    }

    #[test]
    fn utf16z_terminates() {
        let v = utf16z("hi");
        assert_eq!(v, vec![0x68, 0x69, 0x00]);
    }
}
