//! Windows-only collector implementation.
//!
//! Wires the `Microsoft-Windows-Kernel-Process` ETW provider (GUID
//! `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`) for process start events
//! (Event ID 1). Same conceptual shape as the Linux side: receive an event,
//! enrich, check enrollment, emit a schema `ProcessExec`.
//!
//! Notable gaps vs the Linux process_exec probe in this iteration:
//! - **No CommandLine.** Microsoft-Windows-Kernel-Process Event ID 1 carries
//!   ImageName but not the full command line. Fetching it requires
//!   NtQueryInformationProcess(ProcessCommandLine) after the PID is known;
//!   wired in a follow-up so we get a clean first build first.
//! - **No parent_chain.** We have ParentProcessID per event but no live
//!   process-tree walk yet. v0.5 work — needs a `WTSEnumerateProcesses` /
//!   `OpenProcess+QueryFullProcessImageName` based walker.
//! - **No user resolution.** Token-to-username via `OpenProcessToken +
//!   GetTokenInformation` is straightforward, follow-up.
//!
//! Requires admin (or SeSystemProfilePrivilege) to start an ETW session.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;
use fishbowl_schema::{
    Attribution, Event, EventKind, Platform, Process, ProcessExecPayload, Source, SCHEMA_VERSION,
};
use serde::Deserialize;

use fishbowl_collector_linux::enroll::{EnrollmentRecord, EnrollmentTable, ProcessKey};

/// Microsoft-Windows-Kernel-Process provider GUID.
const KERNEL_PROCESS_GUID: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";

/// Event IDs published by Microsoft-Windows-Kernel-Process. Only the ones we
/// currently care about are named here.
const EVENT_ID_PROCESS_START: u16 = 1;

#[derive(Debug, Clone, Deserialize)]
pub struct CollectorConfig {
    /// Image-name basenames (e.g. "claude.exe", "cursor.exe") that count as
    /// agent roots. Matched case-insensitively against the ImageName field's
    /// final path component.
    pub enrolled_agents: Vec<String>,
    /// Stable host identifier for the envelope's `host_id` field. Caller
    /// resolves — typically from HKLM `MachineGuid`.
    pub host_id: Option<String>,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            enrolled_agents: vec![
                "claude.exe".into(),
                "cursor.exe".into(),
                "codex.exe".into(),
            ],
            host_id: None,
        }
    }
}

/// Internal state shared between the ETW callback (which runs on a worker
/// thread owned by the ETW session) and the main poll loop. Boxed inside an
/// Arc so the callback closure can clone an Arc and the trait-object lifetime
/// works out.
struct SharedState {
    table: EnrollmentTable,
    /// Cache from PID to (start_time, ProcessKey). On Windows we don't have
    /// a `start_time_ticks` analog as cheap as Linux's /proc/<pid>/stat —
    /// we use the ETW event's timestamp converted to filetime as the
    /// disambiguator.
    pid_to_key: std::collections::HashMap<u32, ProcessKey>,
    events_emitted: u64,
}

impl SharedState {
    fn new() -> Self {
        Self {
            table: EnrollmentTable::new(),
            pid_to_key: std::collections::HashMap::new(),
            events_emitted: 0,
        }
    }
}

/// Public entry point. Same signature contract as the Linux side so callers
/// (the daemon) can swap collectors by `cfg(target_os = ...)`.
pub fn run<F>(config: CollectorConfig, stop: Arc<AtomicBool>, emit: F) -> Result<()>
where
    F: FnMut(Event) + Send + 'static,
{
    run_with_tick(config, stop, emit, || {})
}

/// Same as `run`, plus a `tick` callback invoked from the main thread once
/// per ~200ms — used by the daemon to refresh transcript state between
/// batches of kernel events without spawning extra threads.
///
/// The ETW callback itself runs on a thread owned by the trace session;
/// `tick` runs on the main thread. The two pieces of state we share between
/// them are `SharedState` (behind a Mutex) and the `stop` flag (Atomic).
pub fn run_with_tick<F, T>(
    config: CollectorConfig,
    stop: Arc<AtomicBool>,
    emit: F,
    mut tick: T,
) -> Result<()>
where
    F: FnMut(Event) + Send + 'static,
    T: FnMut(),
{
    let state = Arc::new(Mutex::new(SharedState::new()));
    let emit_sink: Arc<Mutex<Box<dyn FnMut(Event) + Send>>> =
        Arc::new(Mutex::new(Box::new(emit)));
    let host_id = config.host_id.clone();
    let agents = config.enrolled_agents.clone();

    let state_cb = state.clone();
    let emit_cb = emit_sink.clone();

    let provider = Provider::by_guid(KERNEL_PROCESS_GUID)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            if let Err(e) = handle_etw_event(
                record,
                locator,
                &agents,
                host_id.as_deref(),
                &state_cb,
                &emit_cb,
            ) {
                eprintln!("fishbowl-etw: callback error: {e}");
            }
        })
        .build();

    let trace = UserTrace::new()
        .named("fishbowl-v2-etw".to_string())
        .enable(provider)
        .start_and_process()
        .map_err(|e| anyhow!("start ETW user trace: {e:?}"))?;

    // ETW session is now running on its own thread; we wait for `stop` while
    // periodically calling `tick`. Reasonable polling cadence — matches the
    // Linux side's 200ms ringbuf poll.
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(200));
        tick();
    }

    if let Err(e) = trace.stop() {
        eprintln!("fishbowl-etw: trace stop error: {e:?}");
    }
    Ok(())
}

fn handle_etw_event(
    record: &EventRecord,
    locator: &SchemaLocator,
    agents: &[String],
    host_id: Option<&str>,
    state: &Arc<Mutex<SharedState>>,
    emit: &Arc<Mutex<Box<dyn FnMut(Event) + Send>>>,
) -> Result<()> {
    // Only process Process/Start events for now. The provider also publishes
    // ProcessStop (ID 2), ImageLoad (ID 5), etc.; we'll add the relevant ones
    // when we wire credential and network probes.
    if record.event_id() != EVENT_ID_PROCESS_START {
        return Ok(());
    }

    let schema = locator
        .event_schema(record)
        .map_err(|e| anyhow!("schema lookup: {e:?}"))?;
    let parser = Parser::create(record, &schema);

    let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);
    let ppid: u32 = parser.try_parse("ParentProcessID").unwrap_or(0);
    let image_name: String = parser.try_parse("ImageName").unwrap_or_default();

    if pid == 0 {
        return Ok(());
    }

    let process_key = ProcessKey {
        pid: pid as i32,
        // Use the event timestamp (FILETIME → ns since UNIX epoch) as the
        // disambiguator analog to Linux's /proc/<pid>/stat starttime. Both
        // exist solely so PID reuse can't return the previous incarnation's
        // enrollment.
        start_time_ticks: record.raw_timestamp() as u64,
    };
    let parent_key = if ppid != 0 {
        Some(ProcessKey {
            pid: ppid as i32,
            start_time_ticks: 0, // unknown; lookup is by pid for now
        })
    } else {
        None
    };

    let basename = image_basename(&image_name);
    let is_agent_root = agents
        .iter()
        .any(|n| n.eq_ignore_ascii_case(&basename));

    let mut state = state.lock().expect("state lock");
    let parent_enrolled = match parent_key {
        Some(pk) => state.pid_to_key.get(&(pk.pid as u32)).and_then(|k| state.table.get(*k)),
        None => None,
    };

    let record_enrollment: Option<EnrollmentRecord> = if is_agent_root {
        Some(state.table.enroll(process_key, None))
    } else if parent_enrolled.is_some() {
        // Re-derive parent_key with the real key from the pid_to_key cache.
        let resolved_parent_key = parent_key
            .and_then(|pk| state.pid_to_key.get(&(pk.pid as u32)).copied());
        Some(state.table.enroll(process_key, resolved_parent_key))
    } else {
        state.pid_to_key.remove(&pid);
        None
    };

    let Some(rec) = record_enrollment else {
        return Ok(());
    };

    state.pid_to_key.insert(pid, process_key);
    let agent_root_pid = Some(rec.agent_root.pid);
    let attributed_by_descent = !is_agent_root;
    state.events_emitted += 1;
    drop(state);

    let event = Event {
        schema_version: SCHEMA_VERSION.to_string(),
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: filetime_to_rfc3339(record.raw_timestamp() as u64),
        monotonic_ns: Some(record.raw_timestamp() as u64),
        platform: Platform::Windows,
        host_id: host_id.map(str::to_string),
        agent_id: if is_agent_root {
            basename.clone()
        } else {
            "agent-descendant".to_string()
        },
        session_id: None,
        user_id: None, // TODO: token-to-username
        source: Source {
            collector: "windows_etw".to_string(),
            probe: "Microsoft-Windows-Kernel-Process/ProcessStart".to_string(),
            host_pid: Some(pid as i32),
        },
        kind: EventKind::ProcessExec(ProcessExecPayload {
            process: Process {
                pid: pid as i32,
                ppid: ppid as i32,
                start_time: process_key.start_time_ticks.to_string(),
                name: basename,
                path: image_name.clone(),
                // Microsoft-Windows-Kernel-Process Event ID 1 doesn't carry
                // the command line. v0.5: fetch via
                // NtQueryInformationProcess(ProcessCommandLine).
                cmdline: String::new(),
                cwd: String::new(),
                user: String::new(),
                integrity_level: None,
                parent_chain: Vec::new(),
                agent_root_pid,
            },
            attribution: Attribution {
                attributed_tool_call_id: None,
                attributed_by_descent,
                requested_by_tool_call: false,
                requested_in_user_message: false,
                requested_in_assistant_message: false,
                requested_in_tool_result: false,
                time_window_ms: None,
            },
            exec_args: Vec::new(),
            exec_envp_summary: String::new(),
        }),
    };

    let mut emit = emit.lock().expect("emit lock");
    (emit)(event);
    Ok(())
}

/// Strip the directory portion of a Windows-style image path so we can
/// case-insensitively compare against the configured agent name list.
/// Handles both `\` (NT path) and `/` (some ETW providers emit forward
/// slashes for the device prefix).
fn image_basename(path: &str) -> String {
    path.rsplit_once(|c| c == '\\' || c == '/')
        .map(|(_, base)| base.to_string())
        .unwrap_or_else(|| path.to_string())
}

/// Convert a Windows FILETIME-style 100-ns count (since 1601-01-01) to an
/// RFC 3339 string.
fn filetime_to_rfc3339(filetime_100ns: u64) -> String {
    // FILETIME is 100ns intervals since 1601-01-01 UTC. Subtract the offset
    // to UNIX epoch (1970-01-01) — 11_644_473_600 seconds.
    const FILETIME_UNIX_OFFSET_100NS: u64 = 11_644_473_600u64 * 10_000_000;
    let unix_100ns = filetime_100ns.saturating_sub(FILETIME_UNIX_OFFSET_100NS);
    let unix_ns = (unix_100ns as i64) * 100;
    let secs = unix_ns / 1_000_000_000;
    let nsec = (unix_ns % 1_000_000_000) as u32;
    DateTime::<Utc>::from_timestamp(secs, nsec)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
        .unwrap_or_else(|| "1970-01-01T00:00:00.000000000Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_basename_strips_nt_path() {
        assert_eq!(image_basename(r"C:\Windows\System32\notepad.exe"), "notepad.exe");
        assert_eq!(image_basename(r"\Device\HarddiskVolume3\notepad.exe"), "notepad.exe");
        assert_eq!(image_basename("notepad.exe"), "notepad.exe");
    }
}
