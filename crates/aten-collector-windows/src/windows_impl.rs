//! Windows-only collector implementation.
//!
//! Wires three ETW providers on a single `UserTrace` session:
//!
//! - **Microsoft-Windows-Kernel-Process** (`{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`)
//!   for `ProcessStart` (Event ID 1) — the enrollment source. Emits schema
//!   `ProcessExec` events.
//! - **Microsoft-Windows-Kernel-File** (`{EDD08927-9CC4-4E65-B970-C2560FB5C289}`)
//!   filtered to `Create` (Event ID 12) — the credential-read detection
//!   path. Hooks file *opens* (the NT `IRP_MJ_CREATE`), not reads — same
//!   semantic as the Linux side hooking `openat`, and avoids the
//!   `FileObject`-pointer cache that Event ID 15 (Read) would require.
//!   Emits schema `CredentialAccess` events.
//! - **Microsoft-Windows-Kernel-Network** (`{7DD42A49-5329-4832-8DFD-43D979153A88}`)
//!   filtered to `TcpIp/Connect` IPv4 (Event ID 12) and IPv6 (Event ID
//!   28) — the beacon-detection path. Hooks successful three-way handshake
//!   completion, NOT `connect()` syscall return: a beacon to a dead C2
//!   won't fire here (see Event 17 follow-up below). Address-family
//!   coverage matches Linux's `connect()` BPF probe. Emits schema
//!   `NetworkEgress` events.
//!
//! All three providers share one trace session so we have one dispatcher
//! thread and one Mutex on `SharedState`. ETW does *not* guarantee
//! cross-provider ordering — a Kernel-File Create or Kernel-Network
//! Connect can arrive before its own Kernel-Process ProcessStart — so the
//! credacc and netconn handlers both fall back to a Win32 ancestor-PID
//! walk via `enrich::ancestor_pids` to recover enrollment for descendants
//! whose ProcessStart raced.
//!
//! ETW gives us pid, ppid, image path, session ID, and an integrity-level
//! SID. Everything else the schema's Process block needs (cmdline,
//! parent_chain, user) comes from a per-event Win32 query — see the
//! `enrich` module. Those queries cost ~tens of microseconds per event and
//! happen only for enrolled processes (the cheap is_agent / parent_enrolled
//! / classify filters run first), so the hot path stays well inside the
//! ETW callback budget. The `SharedState` Mutex is released *before*
//! enrichment runs; holding it across the Win32 calls would risk dropped
//! ETW events on a busy host.
//!
//! Open follow-ups (deliberately out of scope here):
//! - `Create`-disposition filtering. Kernel-File Create fires for
//!   pure-metadata opens too (Defender, Search Indexer, Explorer). Reading
//!   `CreateOptions` would let us drop `FILE_OPEN_FOR_BACKUP_INTENT` and
//!   `FILE_OPEN_REPARSE_POINT` noise.
//! - Provider-level keyword filtering for Kernel-File. Currently we accept
//!   the firehose and gate on `event_id() == 12` in the callback; fine on
//!   a dev host, may need `KERNEL_FILE_KEYWORD_*` filtering on CI/build
//!   workloads.
//! - Failed-connect coverage (`TcpIp/ConnectionAttemptFailed`, Event 17 /
//!   33). Catches beacons to dead C2s — a real malicious-package payload
//!   often blasts at multiple unreachable hosts before the working one.
//!   Successful-handshake is the v0.x signal.
//! - UDP send events (Event 42 IPv4 / 58 IPv6). Linux's `connect()` probe
//!   covers only TCP so we match for v0.x; sophisticated DNS-exfil chains
//!   would need this.
//! - TLS SNI capture via the SChannel ETW provider
//!   (`{91CC1150-71AA-47E2-A946-8ABD16D5ED7E}`). Schema §10 flags this as
//!   the prerequisite for URL-based detections; needs a separate handler
//!   that joins SChannel handshake events to Kernel-Network connects by
//!   PID + tuple.
//! - DNS-based `dest_host` resolution. Correlate Kernel-Network connects
//!   with `Microsoft-Windows-DNSClient` (`{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}`)
//!   queries by PID + IP to populate the currently-always-None field.
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
use aten_schema::{
    AccessType, Attribution, CredentialAccessPayload, CredentialClass, DnsQueryPayload,
    DnsQueryType, Event, EventKind, FileWriteClass, FileWritePayload, NetworkEgressPayload,
    Platform, Process, ProcessExecPayload, Protocol, Source, SCHEMA_VERSION,
};
use serde::Deserialize;

use aten_collector_linux::credentials;
use aten_collector_linux::enroll::{EnrollmentRecord, EnrollmentTable, ProcessKey};
use aten_collector_linux::filewrite;
use aten_collector_linux::network::{is_uninteresting, Endpoint};

use crate::enrich;

/// Microsoft-Windows-Kernel-Process provider GUID.
const KERNEL_PROCESS_GUID: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";

/// Microsoft-Windows-Kernel-File provider GUID. Manifest-based, stable
/// since Win7. Publishes file I/O events; we filter to Create only.
const KERNEL_FILE_GUID: &str = "EDD08927-9CC4-4E65-B970-C2560FB5C289";

/// Microsoft-Windows-Kernel-Network provider GUID. Publishes TCP and UDP
/// I/O events; we filter to TcpIp/Connect (V4 + V6) only.
const KERNEL_NETWORK_GUID: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";

/// Microsoft-Windows-DNS-Client provider GUID. The resolver-level view —
/// fires for every name resolution the DNS Client service performs on behalf
/// of a process, with the query name, type, and (on Event 3008) the resolved
/// results. Far cleaner than parsing UDP :53 off Kernel-Network.
const DNS_CLIENT_GUID: &str = "1C95126E-7EEA-49A9-A3FE-A378B03DDB4D";

/// Event IDs published by Microsoft-Windows-Kernel-Process. Only the ones we
/// currently care about are named here.
const EVENT_ID_PROCESS_START: u16 = 1;

/// Event ID for `IRP_MJ_CREATE` from Microsoft-Windows-Kernel-File. This is
/// the file-open event; `FileName` is in-payload (Read/Write events only
/// carry a `FileObject` pointer that requires a separate name cache).
const EVENT_ID_FILE_CREATE: u16 = 12;

/// Event IDs for `TcpIp/Connect` IPv4 (12) and IPv6 (28) from
/// Microsoft-Windows-Kernel-Network. Fires on successful three-way
/// handshake completion (not on `connect()` syscall return) — see module
/// doc for the failed-connect follow-up.
const EVENT_ID_TCP_CONNECT_V4: u16 = 12;
const EVENT_ID_TCP_CONNECT_V6: u16 = 28;

/// Microsoft-Windows-DNS-Client "DNS query completed" event. Carries
/// QueryName, QueryType (numeric qtype), QueryStatus, and QueryResults (a
/// semicolon-delimited string of resolved addresses / CNAME targets). The
/// query-*sent* event (3006) lacks results, so we key off completion.
const EVENT_ID_DNS_QUERY_COMPLETE: u16 = 3008;

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
    /// Process identity captured at ProcessStart (see `ProcInfo`). Lets the
    /// file/network handlers populate name/path/cmdline/user without racing
    /// process exit.
    proc_info: std::collections::HashMap<i32, ProcInfo>,
    events_emitted: u64,
}

impl SharedState {
    fn new() -> Self {
        Self {
            table: EnrollmentTable::new(),
            pid_to_key: std::collections::HashMap::new(),
            proc_info: std::collections::HashMap::new(),
            events_emitted: 0,
        }
    }
}

/// Process identity captured at ProcessStart, while the process is guaranteed
/// alive. The Kernel-File and Kernel-Network events only carry a PID, and a
/// short-lived agent child (e.g. `powershell -c "... | Out-Null"`) often exits
/// before the file/network ETW event is processed — a live PEB/token query then
/// returns blanks. Reading these from the cache fixes the empty
/// name/path/cmdline (and gives a real start_time) on those events.
#[derive(Clone, Default)]
struct ProcInfo {
    name: String,
    /// Already NT-path-normalized image path.
    image_path: String,
    cmdline: String,
    user: String,
    start_time_ticks: u64,
}

/// Resolve a process's identity for a Kernel-File / Kernel-Network event:
/// prefer the ProcessStart cache (populated while the process was alive), else
/// fall back to a live Win32 query (which may return blanks if the process
/// already exited). Returns `(name, normalized_image_path, cmdline, user,
/// start_time_ticks)`.
fn resolve_proc_identity(pid: u32, cached: Option<ProcInfo>) -> (String, String, String, String, u64) {
    match cached {
        Some(pi) => (pi.name, pi.image_path, pi.cmdline, pi.user, pi.start_time_ticks),
        None => {
            let image_path = enrich::query_image(pid);
            (
                image_basename(&image_path),
                enrich::normalize_nt_path(&image_path),
                enrich::query_cmdline(pid),
                enrich::query_user(pid),
                0,
            )
        }
    }
}

/// Render `start_time_ticks` (0 = unknown) as the schema's string field.
fn start_time_string(ticks: u64) -> String {
    if ticks == 0 {
        String::new()
    } else {
        ticks.to_string()
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
    let host_id_proc = config.host_id.clone();
    let host_id_file = config.host_id.clone();
    let host_id_net = config.host_id.clone();
    let agents = config.enrolled_agents.clone();

    // Pre-trace enrollment rundown. ETW only delivers `ProcessStart` for
    // processes that begin AFTER the trace is enabled, so any already-running
    // instance of an enrolled agent (e.g. a long-running `claude.exe` started
    // before this daemon, or the service starting on boot after the agent CLI
    // is already alive in a user session) would be invisible. Without the
    // rundown, `resolve_enrollment_for_pid`'s ancestor-walk fallback finds no
    // enrolled PIDs in `pid_to_key` and silently drops every credacc/network
    // event from descendants — the symptom is a completely empty JSONL.
    //
    // Each rundown-seeded process becomes its own agent root (we have no way
    // to reconstruct the parent chain from a snapshot — and even if we did, a
    // pre-existing `claude.exe` is by definition the root of its subtree from
    // the trace's point of view). The fallback walk picks up descendants
    // organically as their events fire.
    let rundown_count = {
        let mut st = state.lock().expect("state lock");
        let mut n: usize = 0;
        for (pid, image_name) in enrich::list_processes() {
            let basename = image_basename(&image_name);
            let is_match = agents.iter().any(|a| a.eq_ignore_ascii_case(&basename));
            if !is_match {
                continue;
            }
            let key = ProcessKey {
                pid: pid as i32,
                // start_time_ticks is the PID-reuse disambiguator. For
                // rundown we don't have the original ProcessStart timestamp;
                // 0 is fine because lookup is by raw PID and any subsequent
                // ProcessStart for the same PID overwrites.
                start_time_ticks: 0,
            };
            st.table.enroll(key, None);
            st.pid_to_key.insert(pid, key);
            n += 1;
        }
        n
    };

    // `.any(ALL_KEYWORDS)` is critical: ferrisetw's `Provider::by_guid` defaults
    // `MatchAnyKeyword = 0`, which under ETW semantics means "only events with
    // keyword = 0 in the manifest fire" — i.e., excludes every event that has
    // any keyword set. Microsoft-Windows-Kernel-File Event 12 (IRP_MJ_CREATE,
    // the only event with a usable FileName field on every fire) is gated by
    // `KERNEL_FILE_KEYWORD_CREATE = 0x80`, so without this the file callback
    // received the Close/Cleanup/Write firehose (all keyword = 0) but never
    // saw a Create. Symptom: process_exec and network_egress flowed but
    // credential_access never fired no matter what was read. `0xFFFFFFFF_FFFFFFFF`
    // = "enable every keyword the manifest defines" on all three providers;
    // event_id filtering inside the callbacks does the actual narrowing.
    const ALL_KEYWORDS: u64 = 0xFFFFFFFF_FFFFFFFF;

    let state_proc = state.clone();
    let emit_proc = emit_sink.clone();
    let process_provider = Provider::by_guid(KERNEL_PROCESS_GUID)
        .any(ALL_KEYWORDS)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            if let Err(e) = handle_etw_event(
                record,
                locator,
                &agents,
                host_id_proc.as_deref(),
                &state_proc,
                &emit_proc,
            ) {
                eprintln!("aten-etw: process-callback error: {e}");
            }
        })
        .build();

    let state_file = state.clone();
    let emit_file = emit_sink.clone();
    let file_provider = Provider::by_guid(KERNEL_FILE_GUID)
        .any(ALL_KEYWORDS)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            if let Err(e) = handle_file_event(
                record,
                locator,
                host_id_file.as_deref(),
                &state_file,
                &emit_file,
            ) {
                eprintln!("aten-etw: file-callback error: {e}");
            }
        })
        .build();

    let state_net = state.clone();
    let emit_net = emit_sink.clone();
    let network_provider = Provider::by_guid(KERNEL_NETWORK_GUID)
        .any(ALL_KEYWORDS)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            if let Err(e) = handle_network_event(
                record,
                locator,
                host_id_net.as_deref(),
                &state_net,
                &emit_net,
            ) {
                eprintln!("aten-etw: network-callback error: {e}");
            }
        })
        .build();

    let state_dns = state.clone();
    let emit_dns = emit_sink.clone();
    let host_id_dns = config.host_id.clone();
    let dns_provider = Provider::by_guid(DNS_CLIENT_GUID)
        .any(ALL_KEYWORDS)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            if let Err(e) = handle_dns_event(
                record,
                locator,
                host_id_dns.as_deref(),
                &state_dns,
                &emit_dns,
            ) {
                eprintln!("aten-etw: dns-callback error: {e}");
            }
        })
        .build();

    eprintln!(
        "aten-etw: trace starting. enrollment rundown seeded {rundown_count} \
         pre-existing agent process(es); new starts will enroll via ProcessStart."
    );

    let trace = UserTrace::new()
        .named("aten-etw".to_string())
        .enable(process_provider)
        .enable(file_provider)
        .enable(network_provider)
        .enable(dns_provider)
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
        eprintln!("aten-etw: trace stop error: {e:?}");
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
    // The ProcessStart event carries the command line directly — authoritative
    // and available while the process is alive, unlike a later PEB query.
    let cmdline_evt: String = parser.try_parse("CommandLine").unwrap_or_default();

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

    let mut guard = state.lock().expect("state lock");
    let parent_enrolled = match parent_key {
        Some(pk) => guard.pid_to_key.get(&(pk.pid as u32)).and_then(|k| guard.table.get(*k)),
        None => None,
    };

    let record_enrollment: Option<EnrollmentRecord> = if is_agent_root {
        Some(guard.table.enroll(process_key, None))
    } else if parent_enrolled.is_some() {
        // Re-derive parent_key with the real key from the pid_to_key cache.
        let resolved_parent_key = parent_key
            .and_then(|pk| guard.pid_to_key.get(&(pk.pid as u32)).copied());
        Some(guard.table.enroll(process_key, resolved_parent_key))
    } else {
        guard.pid_to_key.remove(&pid);
        None
    };

    let Some(rec) = record_enrollment else {
        return Ok(());
    };

    guard.pid_to_key.insert(pid, process_key);
    let agent_root_pid = Some(rec.agent_root.pid);
    let attributed_by_descent = !is_agent_root;
    guard.events_emitted += 1;
    drop(guard);

    // Per-event enrichment via Win32. Only runs for enrolled processes
    // (we returned early above if record_enrollment was None), so the cost
    // is bounded by agent activity, not by total system process churn.
    let cmdline = if !cmdline_evt.is_empty() {
        cmdline_evt
    } else {
        enrich::query_cmdline(pid)
    };
    let user = enrich::query_user(pid);
    let image_path_norm = enrich::normalize_nt_path(&image_name);
    // schema §3 caps parent_chain at 16. The chain returned excludes the
    // current process to match the Linux collector's contract.
    let parent_chain = if ppid != 0 {
        enrich::parent_chain(ppid, 16)
    } else {
        Vec::new()
    };

    // Cache this process's identity (captured while it's alive) so later
    // Kernel-File / Kernel-Network events for the same PID can populate
    // name/path/cmdline/user/start_time without a live query that races exit.
    {
        let mut st = state.lock().expect("state lock");
        st.proc_info.insert(
            pid as i32,
            ProcInfo {
                name: basename.clone(),
                image_path: image_path_norm.clone(),
                cmdline: cmdline.clone(),
                user: user.clone(),
                start_time_ticks: process_key.start_time_ticks,
            },
        );
    }

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
        user_id: if user.is_empty() { None } else { Some(user.clone()) },
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
                path: image_path_norm,
                cmdline,
                cwd: String::new(),
                user,
                integrity_level: enrich::query_integrity_level(pid),
                parent_chain,
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
                triggering_command: None,
                triggering_prompt: None,
            },
            exec_args: Vec::new(),
            exec_envp_summary: String::new(),
        }),
    };

    let mut emit = emit.lock().expect("emit lock");
    (emit)(event);
    Ok(())
}

/// Handler for Microsoft-Windows-Kernel-File events. Filters to Event ID 12
/// (Create / `IRP_MJ_CREATE`), classifies the file path, and — if the path
/// looks like credentials — resolves enrollment and emits a schema
/// `CredentialAccess` event.
///
/// Filter order is deliberate (matches the Linux side):
///   1. `event_id == 12` — cheapest possible drop, no parsing.
///   2. `credentials::classify(&file_name) != None` — microseconds, drops
///      ~99% of opens.
///   3. Enrollment lookup (fast path: `pid_to_key` hit; fallback: Win32
///      ancestor walk to recover from cross-provider ordering races).
///
/// The state Mutex is released before the per-event Win32 enrichment
/// (`enrich::query_cmdline` etc.) so a slow enrichment call can't stall the
/// ETW callback thread and silently drop kernel events.
fn handle_file_event(
    record: &EventRecord,
    locator: &SchemaLocator,
    host_id: Option<&str>,
    state: &Arc<Mutex<SharedState>>,
    emit: &Arc<Mutex<Box<dyn FnMut(Event) + Send>>>,
) -> Result<()> {
    if record.event_id() != EVENT_ID_FILE_CREATE {
        return Ok(());
    }

    let schema = locator
        .event_schema(record)
        .map_err(|e| anyhow!("schema lookup: {e:?}"))?;
    let parser = Parser::create(record, &schema);

    let file_name: String = parser.try_parse("FileName").unwrap_or_default();
    if file_name.is_empty() {
        return Ok(());
    }

    // Reject FileName values that aren't well-formed paths *before*
    // classifying. The kernel logs Create events for failed opens too, so a
    // shell that tries to open an unexpanded `$env:USERPROFILE\.aws\...`
    // (or any relative/garbage path), plus the occasional multi-KB corrupt
    // FileName from ETW parse misalignment, would otherwise match a
    // credential substring and emit a false `credential_access`. A real
    // credential path always passes this check.
    if !enrich::is_wellformed_file_path(&file_name) {
        return Ok(());
    }

    // The Kernel-File Create event packs the NtCreateFile *disposition* in the
    // high byte of CreateOptions (the long-standing FileIo convention):
    // 0=SUPERSEDE 1=OPEN 2=CREATE 3=OPEN_IF 4=OVERWRITE 5=OVERWRITE_IF. We
    // treat SUPERSEDE/CREATE/OVERWRITE/OVERWRITE_IF as write-intent. OPEN_IF
    // (3) is read-or-create and too ambiguous to count as a write.
    //
    // Safety / non-regression: if CreateOptions can't be parsed it comes back
    // 0, which makes `write_intent` false, so the event falls through to the
    // unchanged credential-read path. A write to a credential-class path is
    // therefore reported as file_write{Credential} (planting), while a read of
    // one stays credential_access (exfil) — see handle_dns_event's sibling
    // VERIFY note: the disposition packing is the field most worth a live
    // smoke-test on first run.
    let create_options: u32 = parser.try_parse("CreateOptions").unwrap_or(0);
    let disposition = (create_options >> 24) & 0xFF;
    let write_intent = create_options != 0 && matches!(disposition, 0 | 2 | 4 | 5);

    if write_intent {
        if let Some(write_class) = filewrite::classify(&file_name) {
            return emit_file_write(record, &file_name, write_class, host_id, state, emit);
        }
    }

    // Classify before doing anything PID-related — the vast majority of
    // file-create events aren't credentials and we want to drop them with
    // the minimum possible work (no Mutex acquisition, no Win32 calls).
    let class = credentials::classify(&file_name);
    if class == CredentialClass::None {
        return Ok(());
    }

    // Kernel-File Event 12 (Create) has no `ProcessID` field in its manifest
    // payload — the process info lives in the ETW event header. Using
    // `parser.try_parse("ProcessID")` silently returned 0, which then failed
    // the pid != 0 guard and dropped every credential-class file event.
    // `record.process_id()` reads `EVENT_HEADER.ProcessId` directly.
    let pid: u32 = record.process_id();
    if pid == 0 {
        return Ok(());
    }

    let mut st = state.lock().expect("state lock");
    let Some(rec) = resolve_enrollment_for_pid(pid, &mut st) else {
        return Ok(());
    };
    let agent_root_pid = Some(rec.agent_root.pid);
    let is_agent_root = rec.agent_root.pid == pid as i32;

    // Suppress the agent reading its OWN config dotenv (e.g. ~/.claude/.env)
    // at startup. That's expected behavior, not credential access, and it
    // was ~89% of all credential_access events — every one a self-read by
    // the agent root. A *descendant* reading the same file is real exfil and
    // still emits, because is_agent_root is false there. The early return
    // drops the MutexGuard without counting the event as emitted.
    if is_agent_root && credentials::is_agent_config_dotenv(&file_name) {
        return Ok(());
    }

    // Grab the cached identity (from ProcessStart) before releasing the lock.
    let cached = st.proc_info.get(&(pid as i32)).cloned();
    st.events_emitted += 1;
    drop(st);

    // Enrichment runs outside the Mutex — these calls can each take tens of
    // microseconds and there's no need to block the other ETW handler on
    // them. Prefer the ProcessStart cache so a short-lived child that has
    // already exited still gets name/path/cmdline/user (a live query would
    // race the exit and return blanks).
    let (process_name, image_path, cmdline, user, start_time_ticks) =
        resolve_proc_identity(pid, cached);
    let immediate_parent = enrich::ancestor_pids(pid, 1).first().copied().unwrap_or(0);
    let parent_chain = if immediate_parent != 0 {
        enrich::parent_chain(immediate_parent, 16)
    } else {
        Vec::new()
    };

    let event = Event {
        schema_version: SCHEMA_VERSION.to_string(),
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: filetime_to_rfc3339(record.raw_timestamp() as u64),
        monotonic_ns: Some(record.raw_timestamp() as u64),
        platform: Platform::Windows,
        host_id: host_id.map(str::to_string),
        agent_id: if is_agent_root {
            "agent-root".to_string()
        } else {
            "agent-descendant".to_string()
        },
        session_id: None,
        user_id: if user.is_empty() { None } else { Some(user.clone()) },
        source: Source {
            collector: "windows_etw".to_string(),
            probe: "Microsoft-Windows-Kernel-File/Create".to_string(),
            host_pid: Some(pid as i32),
        },
        kind: EventKind::CredentialAccess(CredentialAccessPayload {
            process: Process {
                pid: pid as i32,
                ppid: immediate_parent as i32,
                // start_time is unknown to a Kernel-File event — the
                // ProcessStart timestamp lives in the enrollment record but
                // we don't carry it through (the rec.agent_root key is the
                // *agent root's* start time, not this leaf's). Acceptable
                // for v0.x; queries that need PID-reuse disambiguation can
                // join on (pid, parent_chain) which is unique enough on a
                // single host within a sane time window.
                start_time: start_time_string(start_time_ticks),
                name: process_name,
                path: image_path,
                cmdline,
                cwd: String::new(),
                user,
                integrity_level: enrich::query_integrity_level(pid),
                parent_chain,
                agent_root_pid,
            },
            attribution: Attribution {
                attributed_tool_call_id: None,
                attributed_by_descent: !is_agent_root,
                requested_by_tool_call: false,
                requested_in_user_message: false,
                requested_in_assistant_message: false,
                requested_in_tool_result: false,
                time_window_ms: None,
                triggering_command: None,
                triggering_prompt: None,
            },
            file_path: enrich::normalize_nt_path(&file_name),
            // openat-style: the event we hook is the open itself. Matches
            // the Linux side, which also emits Open for its openat probe.
            access_type: AccessType::Open,
            credential_class: class,
            // Parity with Linux — bytes_read is always None on both
            // platforms in v0.x. Read-event byte counting is a follow-up.
            bytes_read: None,
        }),
    };

    let mut emit = emit.lock().expect("emit lock");
    (emit)(event);
    Ok(())
}

/// Emit a `FileWrite` for a write-intent Kernel-File Create whose path the
/// `filewrite` classifier flagged as sensitive. Shares the same enrollment +
/// identity plumbing as the credential handler; `bytes_written` is None because
/// the Create event we hook is the open, not the write itself.
fn emit_file_write(
    record: &EventRecord,
    file_name: &str,
    write_class: FileWriteClass,
    host_id: Option<&str>,
    state: &Arc<Mutex<SharedState>>,
    emit: &Arc<Mutex<Box<dyn FnMut(Event) + Send>>>,
) -> Result<()> {
    let pid: u32 = record.process_id();
    if pid == 0 {
        return Ok(());
    }

    let mut st = state.lock().expect("state lock");
    let Some(rec) = resolve_enrollment_for_pid(pid, &mut st) else {
        return Ok(());
    };
    let agent_root_pid = Some(rec.agent_root.pid);
    let is_agent_root = rec.agent_root.pid == pid as i32;
    let cached = st.proc_info.get(&(pid as i32)).cloned();
    st.events_emitted += 1;
    drop(st);

    let (process_name, image_path, cmdline, user, start_time_ticks) =
        resolve_proc_identity(pid, cached);
    let immediate_parent = enrich::ancestor_pids(pid, 1).first().copied().unwrap_or(0);
    let parent_chain = if immediate_parent != 0 {
        enrich::parent_chain(immediate_parent, 16)
    } else {
        Vec::new()
    };

    let event = Event {
        schema_version: SCHEMA_VERSION.to_string(),
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: filetime_to_rfc3339(record.raw_timestamp() as u64),
        monotonic_ns: Some(record.raw_timestamp() as u64),
        platform: Platform::Windows,
        host_id: host_id.map(str::to_string),
        agent_id: if is_agent_root {
            "agent-root".to_string()
        } else {
            "agent-descendant".to_string()
        },
        session_id: None,
        user_id: if user.is_empty() { None } else { Some(user.clone()) },
        source: Source {
            collector: "windows_etw".to_string(),
            probe: "Microsoft-Windows-Kernel-File/Create".to_string(),
            host_pid: Some(pid as i32),
        },
        kind: EventKind::FileWrite(FileWritePayload {
            process: Process {
                pid: pid as i32,
                ppid: immediate_parent as i32,
                start_time: start_time_string(start_time_ticks),
                name: process_name,
                path: image_path,
                cmdline,
                cwd: String::new(),
                user,
                integrity_level: enrich::query_integrity_level(pid),
                parent_chain,
                agent_root_pid,
            },
            attribution: Attribution {
                attributed_tool_call_id: None,
                attributed_by_descent: !is_agent_root,
                requested_by_tool_call: false,
                requested_in_user_message: false,
                requested_in_assistant_message: false,
                requested_in_tool_result: false,
                time_window_ms: None,
                triggering_command: None,
                triggering_prompt: None,
            },
            file_path: enrich::normalize_nt_path(file_name),
            // The Create event is the open, not the write — byte count would
            // require the Write event + a FileObject→name cache (backlog).
            bytes_written: None,
            write_class,
        }),
    };

    let mut emit = emit.lock().expect("emit lock");
    (emit)(event);
    Ok(())
}

/// Handler for Microsoft-Windows-Kernel-Network events. Filters to
/// TcpIp/Connect IPv4 (Event 12) and IPv6 (Event 28), drops loopback /
/// link-local / unspecified via the cross-platform `is_uninteresting`
/// helper, and — for the survivors — resolves enrollment and emits a
/// schema `NetworkEgress` event.
///
/// Mirrors the Linux side's `connect()` syscall probe in coverage:
/// successful outbound TCP connections, both address families, skipping
/// UDP and skipping failed-handshake attempts. Same hot-path order as the
/// credacc handler: event_id filter → cheap address filter → enrollment
/// → release Mutex → enrich → emit.
fn handle_network_event(
    record: &EventRecord,
    locator: &SchemaLocator,
    host_id: Option<&str>,
    state: &Arc<Mutex<SharedState>>,
    emit: &Arc<Mutex<Box<dyn FnMut(Event) + Send>>>,
) -> Result<()> {
    let evid = record.event_id();
    if evid != EVENT_ID_TCP_CONNECT_V4 && evid != EVENT_ID_TCP_CONNECT_V6 {
        return Ok(());
    }

    let schema = locator
        .event_schema(record)
        .map_err(|e| anyhow!("schema lookup: {e:?}"))?;
    let parser = Parser::create(record, &schema);

    let pid: u32 = parser.try_parse("PID").unwrap_or(0);
    // ETW Kernel-Network publishes `dport` (and `daddr` below) in network byte
    // order — Winsock's sockaddr convention. ferrisetw reads the field via a
    // native-endian load, so on x86_64 (LE) we see the bytes swapped relative
    // to the actual port number. `u16::from_be` swaps on LE and is a no-op on
    // BE — correct on both. Live-confirmed by smoke test: without this, a curl
    // to 1.1.1.1:443 surfaced as dest_port=47873 (= 0xBB01 = byte-swapped 443).
    let dport: u16 = u16::from_be(parser.try_parse("dport").unwrap_or(0));
    if pid == 0 || dport == 0 {
        return Ok(());
    }

    // Same wire-format gotcha for IPv4 daddr: `win:UInt32` field holding the
    // raw 4 bytes in network byte order. `to_le_bytes` pulls bytes out
    // as-stored (= wire / BE), then `Ipv4Addr::from([u8;4])` reads them as
    // octets — net result correct without us caring about host endianness.
    // Live-confirmed (1.1.1.1 round-tripped as 1.1.1.1, not 1.0.0.1).
    let endpoint = match evid {
        EVENT_ID_TCP_CONNECT_V4 => {
            let daddr: u32 = parser.try_parse("daddr").unwrap_or(0);
            Endpoint::V4 {
                ip: std::net::Ipv4Addr::from(daddr.to_le_bytes()),
                port: dport,
            }
        }
        EVENT_ID_TCP_CONNECT_V6 => {
            // IPv6 daddr is a 16-byte binary field; no byte-order concern
            // (addresses are natively byte-arrays).
            let bytes: Vec<u8> = parser.try_parse("daddr").unwrap_or_default();
            if bytes.len() != 16 {
                return Ok(());
            }
            let arr: [u8; 16] = bytes
                .as_slice()
                .try_into()
                .expect("16-byte slice → [u8;16] is infallible");
            Endpoint::V6 {
                ip: std::net::Ipv6Addr::from(arr),
                port: dport,
            }
        }
        _ => unreachable!("event_id pre-filtered above"),
    };

    if is_uninteresting(&endpoint) {
        return Ok(());
    }

    let mut st = state.lock().expect("state lock");
    let Some(rec) = resolve_enrollment_for_pid(pid, &mut st) else {
        return Ok(());
    };
    let agent_root_pid = Some(rec.agent_root.pid);
    let is_agent_root = rec.agent_root.pid == pid as i32;
    let cached = st.proc_info.get(&(pid as i32)).cloned();
    st.events_emitted += 1;
    drop(st);

    // Prefer the ProcessStart cache (see the file handler) over a live query
    // that would race a short-lived child's exit.
    let (process_name, image_path, cmdline, user, start_time_ticks) =
        resolve_proc_identity(pid, cached);
    let immediate_parent = enrich::ancestor_pids(pid, 1).first().copied().unwrap_or(0);
    let parent_chain = if immediate_parent != 0 {
        enrich::parent_chain(immediate_parent, 16)
    } else {
        Vec::new()
    };

    let (dest_ip, dest_port) = match &endpoint {
        Endpoint::V4 { ip, port } => (ip.to_string(), *port),
        Endpoint::V6 { ip, port } => (ip.to_string(), *port),
        Endpoint::Other => unreachable!("filtered by is_uninteresting"),
    };

    let event = Event {
        schema_version: SCHEMA_VERSION.to_string(),
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: filetime_to_rfc3339(record.raw_timestamp() as u64),
        monotonic_ns: Some(record.raw_timestamp() as u64),
        platform: Platform::Windows,
        host_id: host_id.map(str::to_string),
        agent_id: if is_agent_root {
            "agent-root".to_string()
        } else {
            "agent-descendant".to_string()
        },
        session_id: None,
        user_id: if user.is_empty() { None } else { Some(user.clone()) },
        source: Source {
            collector: "windows_etw".to_string(),
            probe: "Microsoft-Windows-Kernel-Network/TcpIp-Connect".to_string(),
            host_pid: Some(pid as i32),
        },
        kind: EventKind::NetworkEgress(NetworkEgressPayload {
            process: Process {
                pid: pid as i32,
                ppid: immediate_parent as i32,
                start_time: start_time_string(start_time_ticks),
                name: process_name,
                path: image_path,
                cmdline,
                cwd: String::new(),
                user,
                integrity_level: enrich::query_integrity_level(pid),
                parent_chain,
                agent_root_pid,
            },
            attribution: Attribution {
                attributed_tool_call_id: None,
                attributed_by_descent: !is_agent_root,
                requested_by_tool_call: false,
                requested_in_user_message: false,
                requested_in_assistant_message: false,
                requested_in_tool_result: false,
                time_window_ms: None,
                triggering_command: None,
                triggering_prompt: None,
            },
            dest_ip,
            dest_port,
            // Linux emits None too — DNS resolution would require correlating
            // with a separate provider (DNSClient on Windows / a DNS uprobe
            // on Linux). Documented as a backlog item.
            dest_host: None,
            protocol: Protocol::Tcp,
            // Same parity story for TLS SNI capture (SChannel ETW on
            // Windows; SSL_write uprobe on Linux).
            tls_sni: None,
        }),
    };

    let mut emit = emit.lock().expect("emit lock");
    (emit)(event);
    Ok(())
}

/// Handler for Microsoft-Windows-DNS-Client events. Filters to Event 3008
/// (query completed), which carries the query name, numeric qtype, and the
/// resolved results. Same hot-path order as the other kernel handlers:
/// event_id filter → parse → enrollment (PID via the event header) → release
/// Mutex → enrich → emit a schema `DnsQuery`.
///
/// VERIFY (first live run): the exact field names ("QueryName", "QueryType",
/// "QueryResults") and the QueryResults delimiter format are from the
/// DNS-Client manifest; confirm against a real capture and adjust
/// `parse_dns_results` if the separator differs across Windows builds.
fn handle_dns_event(
    record: &EventRecord,
    locator: &SchemaLocator,
    host_id: Option<&str>,
    state: &Arc<Mutex<SharedState>>,
    emit: &Arc<Mutex<Box<dyn FnMut(Event) + Send>>>,
) -> Result<()> {
    if record.event_id() != EVENT_ID_DNS_QUERY_COMPLETE {
        return Ok(());
    }

    let schema = locator
        .event_schema(record)
        .map_err(|e| anyhow!("schema lookup: {e:?}"))?;
    let parser = Parser::create(record, &schema);

    let query_name_raw: String = parser.try_parse("QueryName").unwrap_or_default();
    if query_name_raw.is_empty() {
        return Ok(());
    }
    let qtype: u32 = parser.try_parse("QueryType").unwrap_or(0);
    let query_results: String = parser.try_parse("QueryResults").unwrap_or_default();

    // DNS-Client events carry the requesting PID in the event header, not the
    // payload (same as Kernel-File Create).
    let pid: u32 = record.process_id();
    if pid == 0 {
        return Ok(());
    }

    let mut st = state.lock().expect("state lock");
    let Some(rec) = resolve_enrollment_for_pid(pid, &mut st) else {
        return Ok(());
    };
    let agent_root_pid = Some(rec.agent_root.pid);
    let is_agent_root = rec.agent_root.pid == pid as i32;
    let cached = st.proc_info.get(&(pid as i32)).cloned();
    st.events_emitted += 1;
    drop(st);

    let (process_name, image_path, cmdline, user, start_time_ticks) =
        resolve_proc_identity(pid, cached);
    let immediate_parent = enrich::ancestor_pids(pid, 1).first().copied().unwrap_or(0);
    let parent_chain = if immediate_parent != 0 {
        enrich::parent_chain(immediate_parent, 16)
    } else {
        Vec::new()
    };

    let query_name = query_name_raw.trim_end_matches('.').to_lowercase();
    let answers = parse_dns_results(&query_results);

    let event = Event {
        schema_version: SCHEMA_VERSION.to_string(),
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: filetime_to_rfc3339(record.raw_timestamp() as u64),
        monotonic_ns: Some(record.raw_timestamp() as u64),
        platform: Platform::Windows,
        host_id: host_id.map(str::to_string),
        agent_id: if is_agent_root {
            "agent-root".to_string()
        } else {
            "agent-descendant".to_string()
        },
        session_id: None,
        user_id: if user.is_empty() { None } else { Some(user.clone()) },
        source: Source {
            collector: "windows_etw".to_string(),
            probe: "Microsoft-Windows-DNS-Client/QueryComplete".to_string(),
            host_pid: Some(pid as i32),
        },
        kind: EventKind::DnsQuery(DnsQueryPayload {
            process: Process {
                pid: pid as i32,
                ppid: immediate_parent as i32,
                start_time: start_time_string(start_time_ticks),
                name: process_name,
                path: image_path,
                cmdline,
                cwd: String::new(),
                user,
                integrity_level: enrich::query_integrity_level(pid),
                parent_chain,
                agent_root_pid,
            },
            attribution: Attribution {
                attributed_tool_call_id: None,
                attributed_by_descent: !is_agent_root,
                requested_by_tool_call: false,
                requested_in_user_message: false,
                requested_in_assistant_message: false,
                requested_in_tool_result: false,
                time_window_ms: None,
                triggering_command: None,
                triggering_prompt: None,
            },
            query_name,
            query_type: dns_qtype(qtype),
            answers,
        }),
    };

    let mut emit = emit.lock().expect("emit lock");
    (emit)(event);
    Ok(())
}

/// Map a numeric DNS qtype to the schema enum. Covers the common record types;
/// everything else collapses to `Other` (raw qtype stays in RawJson).
fn dns_qtype(qtype: u32) -> DnsQueryType {
    match qtype {
        1 => DnsQueryType::A,
        28 => DnsQueryType::Aaaa,
        5 => DnsQueryType::Cname,
        16 => DnsQueryType::Txt,
        15 => DnsQueryType::Mx,
        2 => DnsQueryType::Ns,
        12 => DnsQueryType::Ptr,
        33 => DnsQueryType::Srv,
        6 => DnsQueryType::Soa,
        _ => DnsQueryType::Other,
    }
}

/// Parse the DNS-Client `QueryResults` blob into resolved answers. The field is
/// a `;`-delimited list whose entries are either a bare address or a
/// `type: <n> <data>` form (CNAME chains carry the type prefix). We take the
/// last whitespace-separated token of each non-empty entry.
fn parse_dns_results(results: &str) -> Vec<String> {
    results
        .split(';')
        .filter_map(|seg| {
            let seg = seg.trim();
            if seg.is_empty() {
                return None;
            }
            // "type:  5 cname.example.com" → "cname.example.com"; a bare
            // "93.184.216.34" → itself.
            Some(seg.split_whitespace().last().unwrap_or(seg).to_string())
        })
        .collect()
}

/// Resolve enrollment for a PID seen on a kernel-side event (file/network),
/// mirroring `resolve_enrollment` on the Linux side.
///
/// Fast path: direct `pid_to_key` hit. Fallback: Win32 ancestor walk —
/// needed because ETW does not guarantee cross-provider ordering, so a
/// Kernel-File Create from a freshly-spawned descendant can race ahead of
/// its own Kernel-Process ProcessStart. The first ancestor PID found in
/// `pid_to_key` enrolls the leaf; we cache the leaf so the next event from
/// it takes the fast path.
///
/// Caller must hold the `SharedState` Mutex.
fn resolve_enrollment_for_pid(pid: u32, st: &mut SharedState) -> Option<EnrollmentRecord> {
    if let Some(key) = st.pid_to_key.get(&pid).copied() {
        if let Some(rec) = st.table.get(key) {
            return Some(rec);
        }
    }
    for ancestor in enrich::ancestor_pids(pid, 16) {
        if let Some(key) = st.pid_to_key.get(&ancestor).copied() {
            if let Some(rec) = st.table.get(key) {
                // Inherit the ancestor's ProcessKey so future events from
                // this PID hit the fast path. Note: this re-uses the
                // ancestor's start_time_ticks; PID-reuse disambiguation
                // still works because the leaf gets its own entry and any
                // later ProcessStart for the same PID will overwrite.
                st.pid_to_key.insert(pid, key);
                return Some(rec);
            }
        }
    }
    None
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

    #[test]
    fn dns_qtype_maps_common_types() {
        assert_eq!(dns_qtype(1), DnsQueryType::A);
        assert_eq!(dns_qtype(28), DnsQueryType::Aaaa);
        assert_eq!(dns_qtype(16), DnsQueryType::Txt);
        assert_eq!(dns_qtype(5), DnsQueryType::Cname);
        assert_eq!(dns_qtype(999), DnsQueryType::Other);
    }

    #[test]
    fn dns_results_parse_both_forms() {
        // Bare addresses.
        assert_eq!(
            parse_dns_results("93.184.216.34;93.184.216.35;"),
            vec!["93.184.216.34", "93.184.216.35"]
        );
        // CNAME-chain "type: n data" entries — take the trailing token.
        assert_eq!(
            parse_dns_results("type:  5 cdn.example.com;type:  1 93.184.216.34;"),
            vec!["cdn.example.com", "93.184.216.34"]
        );
        // Empty / whitespace-only → no answers.
        assert!(parse_dns_results("").is_empty());
        assert!(parse_dns_results(";  ;").is_empty());
    }
}
