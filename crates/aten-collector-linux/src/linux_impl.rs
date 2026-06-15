//! Linux-only collector implementation. Everything in this module is gated
//! at the crate root via `#[cfg(target_os = "linux")]`; the workspace can
//! build on Windows hosts without pulling libbpf.

use std::cell::Cell;
use std::cell::RefCell;
use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use aten_schema::{
    AccessType, Attribution, CredentialAccessPayload, CredentialClass, DnsQueryPayload,
    DnsQueryType, Event, EventKind, FileWriteClass, FileWritePayload, NetworkEgressPayload,
    Platform, Process, ProcessExecPayload, Protocol, Source, SCHEMA_VERSION,
};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{OpenObject, UprobeOpts};
use plain::Plain;
use serde::Deserialize;

use crate::enroll::{self, EnrollmentRecord, EnrollmentTable, ProcessKey};
use crate::network::{self, Endpoint};
use crate::proc;
use crate::skel_connect::*;
use crate::skel_credacc::*;
use crate::skel_dns::*;
use crate::skel_execve::*;
use crate::{credentials, filewrite};

const TASK_COMM_LEN: usize = 16;
const MAX_FILENAME_LEN: usize = 256;

/// Mirror of the BPF program's `struct exec_event`. Must stay byte-compatible
/// with `src/bpf/execve.bpf.c`. `plain::Plain` lets us read the ringbuf bytes
/// without unsafe transmute. We don't derive `Default` because Rust stdlib's
/// Default impls for `[u8; N]` only go up to N=32 — we initialize via zeroed().
#[repr(C)]
#[derive(Copy, Clone)]
struct RawExecEvent {
    timestamp_ns: u64,
    pid: u32,
    uid: u32,
    comm: [u8; TASK_COMM_LEN],
    filename: [u8; MAX_FILENAME_LEN],
}
unsafe impl Plain for RawExecEvent {}

impl RawExecEvent {
    fn zeroed() -> Self {
        // SAFETY: every field is a plain-old-data type with a valid all-zeros
        // representation.
        unsafe { std::mem::zeroed() }
    }
}

/// Mirror of the BPF program's `struct credacc_event` in `credacc.bpf.c`.
#[repr(C)]
#[derive(Copy, Clone)]
struct RawCredaccEvent {
    timestamp_ns: u64,
    pid: u32,
    uid: u32,
    flags: i32,
    comm: [u8; TASK_COMM_LEN],
    filename: [u8; MAX_FILENAME_LEN],
}
unsafe impl Plain for RawCredaccEvent {}

impl RawCredaccEvent {
    fn zeroed() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

/// Mirror of the BPF program's `struct connect_event` in `connect.bpf.c`.
#[repr(C)]
#[derive(Copy, Clone)]
struct RawConnectEvent {
    timestamp_ns: u64,
    pid: u32,
    uid: u32,
    addrlen: u32,
    comm: [u8; TASK_COMM_LEN],
    sockaddr: [u8; 28],
}
unsafe impl Plain for RawConnectEvent {}

impl RawConnectEvent {
    fn zeroed() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

/// Mirror of the BPF program's `struct dns_event` in `dns.bpf.c`.
#[repr(C)]
#[derive(Copy, Clone)]
struct RawDnsEvent {
    timestamp_ns: u64,
    pid: u32,
    uid: u32,
    comm: [u8; TASK_COMM_LEN],
    qname: [u8; MAX_FILENAME_LEN],
}
unsafe impl Plain for RawDnsEvent {}

impl RawDnsEvent {
    fn zeroed() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

/// State shared between the three probe handlers. The exec handler maintains
/// `pid_to_key` so the credacc and connect handlers can look up a process's
/// enrollment record in O(1) without a /proc/<pid>/stat read on every event.
#[derive(Debug, Default)]
struct SharedState {
    table: EnrollmentTable,
    /// pid → ProcessKey, populated on each enrolled exec, removed on each
    /// non-enrolled exec so PID reuse doesn't return a stale binding.
    pid_to_key: HashMap<i32, ProcessKey>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CollectorConfig {
    /// Process `comm` names that count as agent roots. The kernel's `comm` is
    /// capped at 15 chars (TASK_COMM_LEN - 1), so configure names accordingly.
    pub enrolled_agents: Vec<String>,
    /// Hostname or other stable identifier for the envelope's `host_id` field.
    /// Caller resolves this — typically from `/etc/machine-id`.
    pub host_id: Option<String>,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            enrolled_agents: vec![
                "claude".into(),
                "cursor".into(),
                "codex".into(),
            ],
            host_id: None,
        }
    }
}

/// One-shot bootstrap and run loop. `emit` is invoked for every emitted
/// schema event; the caller decides where it goes (stdout, file, network).
/// Returns when `stop` is set.
pub fn run<F>(config: CollectorConfig, stop: Arc<AtomicBool>, emit: F) -> Result<()>
where
    F: FnMut(Event),
{
    run_with_tick(config, stop, emit, || {})
}

/// Same as `run`, plus a `tick` callback invoked once per poll cycle (~200ms).
/// The daemon uses this to refresh transcript-side state between batches of
/// kernel events without needing a second thread.
pub fn run_with_tick<F, T>(
    config: CollectorConfig,
    stop: Arc<AtomicBool>,
    emit: F,
    mut tick: T,
) -> Result<()>
where
    F: FnMut(Event),
    T: FnMut(),
{
    // libbpf-rs 0.24 requires the caller to own an `OpenObject` slot for
    // each skeleton's lifetime — we keep them on the stack via MaybeUninit.
    let mut exec_obj: MaybeUninit<OpenObject> = MaybeUninit::uninit();
    let mut cred_obj: MaybeUninit<OpenObject> = MaybeUninit::uninit();
    let mut conn_obj: MaybeUninit<OpenObject> = MaybeUninit::uninit();
    let mut dns_obj: MaybeUninit<OpenObject> = MaybeUninit::uninit();

    let exec_skel = ExecveSkelBuilder::default()
        .open(&mut exec_obj)
        .context("open execve skeleton")?;
    let mut exec_skel = exec_skel.load().context("load execve BPF")?;
    exec_skel.attach().context("attach execve BPF")?;

    let cred_skel = CredaccSkelBuilder::default()
        .open(&mut cred_obj)
        .context("open credacc skeleton")?;
    let mut cred_skel = cred_skel.load().context("load credacc BPF")?;
    cred_skel.attach().context("attach credacc BPF")?;

    let conn_skel = ConnectSkelBuilder::default()
        .open(&mut conn_obj)
        .context("open connect skeleton")?;
    let mut conn_skel = conn_skel.load().context("load connect BPF")?;
    conn_skel.attach().context("attach connect BPF")?;

    // The DNS probe is a sleepable uprobe on libc's getaddrinfo. Its whole
    // setup is BEST-EFFORT: a kernel without sleepable uprobes / the
    // bpf_copy_from_user_str kfunc (< 6.11) fails at LOAD, and that must NOT
    // take down the other three probes. open / load / attach failures all
    // degrade to "no dns_query" instead of aborting the collector. It doesn't
    // auto-attach by section name (uprobes need a binary+offset), so we attach
    // by hand to the resolved libc path for all processes (pid -1; userspace
    // filters by enrollment). Keep `_dns_link` alive for the run loop; dropping
    // it detaches the probe.
    let dns_skel = match DnsSkelBuilder::default()
        .open(&mut dns_obj)
        .and_then(|s| s.load())
    {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!(
                "aten-ebpf: dns probe unavailable ({e}); dns_query disabled \
                 (execve/credacc/connect unaffected)"
            );
            None
        }
    };
    let _dns_link = match dns_skel.as_ref() {
        Some(skel) => match libc_path() {
            Some(path) => {
                let opts = UprobeOpts {
                    func_name: "getaddrinfo".to_string(),
                    ..Default::default()
                };
                match skel
                    .progs
                    .handle_getaddrinfo
                    .attach_uprobe_with_opts(-1, &path, 0, opts)
                {
                    Ok(link) => Some(link),
                    Err(e) => {
                        eprintln!("aten-ebpf: getaddrinfo uprobe attach failed ({e}); dns_query disabled");
                        None
                    }
                }
            }
            None => {
                eprintln!("aten-ebpf: no libc with getaddrinfo found; dns_query disabled");
                None
            }
        },
        None => None,
    };

    let state = RefCell::new(SharedState::default());
    let emit_cell = RefCell::new(emit);
    let host_id = config.host_id.clone();
    let had_error: Cell<Option<anyhow::Error>> = Cell::new(None);

    let exec_maps = &exec_skel.maps;
    let cred_maps = &cred_skel.maps;
    let conn_maps = &conn_skel.maps;
    // None when the DNS probe failed to load/attach (see above) — the consumer
    // is then simply not registered.
    let dns_maps = dns_skel.as_ref().map(|s| &s.maps);
    let mut builder = libbpf_rs::RingBufferBuilder::new();

    let exec_handle = |bytes: &[u8]| -> i32 {
        let mut state = state.borrow_mut();
        let mut emit = emit_cell.borrow_mut();
        if let Err(e) = handle_exec_event(
            bytes,
            &config,
            &mut state,
            host_id.as_deref(),
            &mut *emit,
        ) {
            had_error.set(Some(e));
            return 1;
        }
        0
    };

    let cred_handle = |bytes: &[u8]| -> i32 {
        let mut state = state.borrow_mut();
        let mut emit = emit_cell.borrow_mut();
        if let Err(e) = handle_credacc_event(
            bytes,
            &mut state,
            host_id.as_deref(),
            &mut *emit,
        ) {
            had_error.set(Some(e));
            return 1;
        }
        0
    };

    let conn_handle = |bytes: &[u8]| -> i32 {
        let mut state = state.borrow_mut();
        let mut emit = emit_cell.borrow_mut();
        if let Err(e) = handle_connect_event(
            bytes,
            &mut state,
            host_id.as_deref(),
            &mut *emit,
        ) {
            had_error.set(Some(e));
            return 1;
        }
        0
    };

    builder
        .add(&exec_maps.events, exec_handle)
        .context("add execve ringbuf consumer")?;
    builder
        .add(&cred_maps.cred_events, cred_handle)
        .context("add credacc ringbuf consumer")?;
    builder
        .add(&conn_maps.connect_events, conn_handle)
        .context("add connect ringbuf consumer")?;
    // Only register the DNS consumer if its probe loaded. Defined here so the
    // closure isn't dead code when DNS is disabled.
    if let Some(dns_maps) = dns_maps {
        let dns_handle = |bytes: &[u8]| -> i32 {
            let mut state = state.borrow_mut();
            let mut emit = emit_cell.borrow_mut();
            if let Err(e) = handle_dns_event(
                bytes,
                &mut state,
                host_id.as_deref(),
                &mut *emit,
            ) {
                had_error.set(Some(e));
                return 1;
            }
            0
        };
        builder
            .add(&dns_maps.dns_events, dns_handle)
            .context("add dns ringbuf consumer")?;
    }
    let ringbuf = builder.build().context("build ringbuf")?;

    while !stop.load(Ordering::Relaxed) {
        match ringbuf.poll(Duration::from_millis(200)) {
            Ok(_) => {}
            Err(e) if e.kind() == libbpf_rs::ErrorKind::Interrupted => continue,
            Err(e) => return Err(anyhow!("ringbuf poll: {e}")),
        }
        if let Some(err) = had_error.take() {
            return Err(err);
        }
        tick();
    }

    Ok(())
}

fn handle_exec_event<F>(
    bytes: &[u8],
    config: &CollectorConfig,
    state: &mut SharedState,
    host_id: Option<&str>,
    emit: &mut F,
) -> Result<()>
where
    F: FnMut(Event),
{
    if bytes.len() < std::mem::size_of::<RawExecEvent>() {
        return Ok(());
    }
    let mut raw = RawExecEvent::zeroed();
    plain::copy_from_bytes(&mut raw, bytes)
        .map_err(|_| anyhow!("ringbuf record size mismatch"))?;

    let pid = raw.pid as i32;
    let comm = nul_str(&raw.comm).to_string();
    let filename = nul_str(&raw.filename).to_string();

    // Enrich from /proc. The process is brand new (we're handling its exec)
    // so /proc/<pid>/ should exist; if it doesn't, the process died in the
    // 50us between exec and now and we move on.
    let snap = proc::snapshot(pid);
    if snap.start_time_ticks == 0 {
        return Ok(());
    }
    let key = ProcessKey {
        pid,
        start_time_ticks: snap.start_time_ticks,
    };

    let parent_key = if snap.ppid > 0 {
        let parent_snap = proc::snapshot(snap.ppid);
        if parent_snap.start_time_ticks > 0 {
            Some(ProcessKey {
                pid: snap.ppid,
                start_time_ticks: parent_snap.start_time_ticks,
            })
        } else {
            None
        }
    } else {
        None
    };

    let is_agent_root_match = config.enrolled_agents.iter().any(|n| n == &comm);
    let parent_enrolled = parent_key.and_then(|pk| state.table.get(pk));

    let record = if is_agent_root_match {
        Some(state.table.enroll(key, None))
    } else if parent_enrolled.is_some() {
        Some(state.table.enroll(key, parent_key))
    } else {
        None
    };

    match record {
        Some(_) => {
            state.pid_to_key.insert(pid, key);
        }
        None => {
            state.pid_to_key.remove(&pid);
        }
    }

    let Some(record) = record else {
        return Ok(());
    };

    let chain = proc::parent_chain(pid, 16);
    let attributed_by_descent = !is_agent_root_match;
    let agent_root_pid = Some(record.agent_root.pid);

    let event = Event {
        schema_version: SCHEMA_VERSION.to_string(),
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: rfc3339_from_boot_ns(raw.timestamp_ns),
        monotonic_ns: Some(raw.timestamp_ns),
        platform: Platform::Linux,
        host_id: host_id.map(str::to_string),
        agent_id: comm_to_agent_id(&comm, &config.enrolled_agents, &record),
        session_id: None,
        user_id: Some(snap.user.clone()),
        source: Source {
            collector: "linux_ebpf".to_string(),
            probe: "tracepoint/sched/sched_process_exec".to_string(),
            host_pid: Some(pid),
        },
        kind: EventKind::ProcessExec(ProcessExecPayload {
            process: Process {
                pid,
                ppid: snap.ppid,
                start_time: snap.start_time_ticks.to_string(),
                name: comm.clone(),
                path: if snap.exe_path.is_empty() {
                    filename.clone()
                } else {
                    snap.exe_path.clone()
                },
                cmdline: snap.cmdline.clone(),
                cwd: snap.cwd.clone(),
                user: snap.user.clone(),
                integrity_level: None,
                parent_chain: chain,
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
            exec_args: argv_from_cmdline(&snap.cmdline),
            exec_envp_summary: String::new(),
        }),
    };

    emit(event);
    Ok(())
}

fn handle_credacc_event<F>(
    bytes: &[u8],
    state: &mut SharedState,
    host_id: Option<&str>,
    emit: &mut F,
) -> Result<()>
where
    F: FnMut(Event),
{
    if bytes.len() < std::mem::size_of::<RawCredaccEvent>() {
        return Ok(());
    }
    let mut raw = RawCredaccEvent::zeroed();
    plain::copy_from_bytes(&mut raw, bytes)
        .map_err(|_| anyhow!("ringbuf record size mismatch"))?;

    let pid = raw.pid as i32;
    let filename = nul_str(&raw.filename);
    let bpf_comm = nul_str(&raw.comm).to_string();

    // Write-intent opens to a sensitive path become file_write (mirrors the
    // Windows Create-disposition split). A read-intent open of a credential
    // file stays credential_access below. Classify before any enrollment work,
    // same drop-99%-cheaply ordering as the credential path.
    if is_write_intent(raw.flags) {
        if let Some(write_class) = filewrite::classify(filename) {
            return emit_file_write(&raw, filename, write_class, state, host_id, emit);
        }
    }

    // 99%+ of opens are not credentials — classify FIRST, then check enrollment.
    let class = credentials::classify(filename);
    if class == CredentialClass::None {
        return Ok(());
    }

    let record = match resolve_enrollment(pid, state) {
        Some(r) => r,
        None => return Ok(()),
    };

    let abs_path = absolutize(filename, pid);

    let snap = proc::snapshot(pid);
    let chain = proc::parent_chain(pid, 16);
    let is_agent_root = record.agent_root.pid == pid;
    let attributed_by_descent = !is_agent_root;

    // Suppress the agent reading its OWN config dotenv (e.g. ~/.claude/.env)
    // at startup — expected behavior, not credential access. Only when the
    // reader IS the agent root; a descendant reading the same file is real
    // exfil (descent=true) and still emits. Mirrors the Windows collector.
    if is_agent_root && credentials::is_agent_config_dotenv(&abs_path) {
        return Ok(());
    }

    let process_name = if !snap.comm.is_empty() {
        snap.comm.clone()
    } else {
        bpf_comm.clone()
    };
    let user = if !snap.user.is_empty() {
        snap.user.clone()
    } else {
        raw.uid.to_string()
    };

    let access_type = access_type_from_flags(raw.flags);

    let event = Event {
        schema_version: SCHEMA_VERSION.to_string(),
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: rfc3339_from_boot_ns(raw.timestamp_ns),
        monotonic_ns: Some(raw.timestamp_ns),
        platform: Platform::Linux,
        host_id: host_id.map(str::to_string),
        agent_id: "agent-descendant".to_string(),
        session_id: None,
        user_id: Some(user.clone()),
        source: Source {
            collector: "linux_ebpf".to_string(),
            probe: "tracepoint/syscalls/sys_enter_openat".to_string(),
            host_pid: Some(pid),
        },
        kind: EventKind::CredentialAccess(CredentialAccessPayload {
            process: Process {
                pid,
                ppid: snap.ppid,
                start_time: snap.start_time_ticks.to_string(),
                name: process_name,
                path: snap.exe_path.clone(),
                cmdline: snap.cmdline.clone(),
                cwd: snap.cwd.clone(),
                user,
                integrity_level: None,
                parent_chain: chain,
                agent_root_pid: Some(record.agent_root.pid),
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
            file_path: abs_path,
            access_type,
            credential_class: class,
            bytes_read: None,
        }),
    };

    emit(event);
    Ok(())
}

/// Emit a `FileWrite` for a write-intent openat whose path the `filewrite`
/// classifier flagged as sensitive. Shares the credential handler's enrollment
/// + /proc enrichment; `bytes_written` is None because the openat probe sees
/// the open, not the write.
fn emit_file_write<F>(
    raw: &RawCredaccEvent,
    filename: &str,
    write_class: FileWriteClass,
    state: &mut SharedState,
    host_id: Option<&str>,
    emit: &mut F,
) -> Result<()>
where
    F: FnMut(Event),
{
    let pid = raw.pid as i32;

    let record = match resolve_enrollment(pid, state) {
        Some(r) => r,
        None => return Ok(()),
    };

    let is_agent_root = record.agent_root.pid == pid;

    // Suppress the agent ROOT writing its OWN config surface — expected
    // behavior, not a signal. A descendant writing the agent's config (e.g. a
    // prompt-injected tool run) is the persistence vector and still emits.
    // Mirrors the credential self-read suppression.
    if is_agent_root && write_class == FileWriteClass::AgentConfig {
        return Ok(());
    }

    let abs_path = absolutize(filename, pid);
    let snap = proc::snapshot(pid);
    let chain = proc::parent_chain(pid, 16);
    let attributed_by_descent = !is_agent_root;

    let bpf_comm = nul_str(&raw.comm).to_string();
    let process_name = if !snap.comm.is_empty() {
        snap.comm.clone()
    } else {
        bpf_comm
    };
    let user = if !snap.user.is_empty() {
        snap.user.clone()
    } else {
        raw.uid.to_string()
    };

    let event = Event {
        schema_version: SCHEMA_VERSION.to_string(),
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: rfc3339_from_boot_ns(raw.timestamp_ns),
        monotonic_ns: Some(raw.timestamp_ns),
        platform: Platform::Linux,
        host_id: host_id.map(str::to_string),
        agent_id: if is_agent_root {
            "agent-root".to_string()
        } else {
            "agent-descendant".to_string()
        },
        session_id: None,
        user_id: Some(user.clone()),
        source: Source {
            collector: "linux_ebpf".to_string(),
            probe: "tracepoint/syscalls/sys_enter_openat".to_string(),
            host_pid: Some(pid),
        },
        kind: EventKind::FileWrite(FileWritePayload {
            process: Process {
                pid,
                ppid: snap.ppid,
                start_time: snap.start_time_ticks.to_string(),
                name: process_name,
                path: snap.exe_path.clone(),
                cmdline: snap.cmdline.clone(),
                cwd: snap.cwd.clone(),
                user,
                integrity_level: None,
                parent_chain: chain,
                agent_root_pid: Some(record.agent_root.pid),
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
            file_path: abs_path,
            bytes_written: None,
            write_class,
        }),
    };

    emit(event);
    Ok(())
}

fn handle_dns_event<F>(
    bytes: &[u8],
    state: &mut SharedState,
    host_id: Option<&str>,
    emit: &mut F,
) -> Result<()>
where
    F: FnMut(Event),
{
    if bytes.len() < std::mem::size_of::<RawDnsEvent>() {
        return Ok(());
    }
    let mut raw = RawDnsEvent::zeroed();
    plain::copy_from_bytes(&mut raw, bytes)
        .map_err(|_| anyhow!("ringbuf record size mismatch"))?;

    let pid = raw.pid as i32;
    let qname = nul_str(&raw.qname).trim_end_matches('.').to_lowercase();
    if qname.is_empty() {
        return Ok(());
    }

    let record = match resolve_enrollment(pid, state) {
        Some(r) => r,
        None => return Ok(()),
    };

    let snap = proc::snapshot(pid);
    let chain = proc::parent_chain(pid, 16);
    let is_agent_root = record.agent_root.pid == pid;
    let attributed_by_descent = !is_agent_root;

    let bpf_comm = nul_str(&raw.comm).to_string();
    let process_name = if !snap.comm.is_empty() {
        snap.comm.clone()
    } else {
        bpf_comm
    };
    let user = if !snap.user.is_empty() {
        snap.user.clone()
    } else {
        raw.uid.to_string()
    };

    let event = Event {
        schema_version: SCHEMA_VERSION.to_string(),
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: rfc3339_from_boot_ns(raw.timestamp_ns),
        monotonic_ns: Some(raw.timestamp_ns),
        platform: Platform::Linux,
        host_id: host_id.map(str::to_string),
        agent_id: if is_agent_root {
            "agent-root".to_string()
        } else {
            "agent-descendant".to_string()
        },
        session_id: None,
        user_id: Some(user.clone()),
        source: Source {
            collector: "linux_ebpf".to_string(),
            probe: "uprobe/libc:getaddrinfo".to_string(),
            host_pid: Some(pid),
        },
        kind: EventKind::DnsQuery(DnsQueryPayload {
            process: Process {
                pid,
                ppid: snap.ppid,
                start_time: snap.start_time_ticks.to_string(),
                name: process_name,
                path: snap.exe_path.clone(),
                cmdline: snap.cmdline.clone(),
                cwd: snap.cwd.clone(),
                user,
                integrity_level: None,
                parent_chain: chain,
                agent_root_pid: Some(record.agent_root.pid),
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
            query_name: qname,
            // getaddrinfo resolves A and AAAA together — the wire qtype isn't
            // visible at this layer, so we tag Other. Answers would need a
            // uretprobe walking struct addrinfo (backlog); empty for now.
            query_type: DnsQueryType::Other,
            answers: Vec::new(),
        }),
    };

    emit(event);
    Ok(())
}

/// Find the EnrollmentRecord for `pid`, falling back to a /proc walk if the
/// fast-path `pid_to_key` lookup misses (race with the exec ringbuf).
fn resolve_enrollment(pid: i32, state: &mut SharedState) -> Option<EnrollmentRecord> {
    if let Some(key) = state.pid_to_key.get(&pid).copied() {
        if let Some(r) = state.table.get(key) {
            return Some(r);
        }
    }

    let snap = proc::snapshot(pid);
    if snap.start_time_ticks == 0 {
        return None;
    }
    let my_key = ProcessKey {
        pid,
        start_time_ticks: snap.start_time_ticks,
    };
    if let Some(r) = state.table.get(my_key) {
        state.pid_to_key.insert(pid, my_key);
        return Some(r);
    }

    const MAX_WALK: usize = 16;
    let mut current_ppid = snap.ppid;
    for _ in 0..MAX_WALK {
        if current_ppid <= 0 {
            break;
        }
        let psnap = proc::snapshot(current_ppid);
        if psnap.start_time_ticks == 0 {
            break;
        }
        let pkey = ProcessKey {
            pid: current_ppid,
            start_time_ticks: psnap.start_time_ticks,
        };
        if state.table.get(pkey).is_some() {
            let record = state.table.enroll(my_key, Some(pkey));
            state.pid_to_key.insert(pid, my_key);
            return Some(record);
        }
        if current_ppid == 1 {
            break;
        }
        current_ppid = psnap.ppid;
    }
    None
}

fn handle_connect_event<F>(
    bytes: &[u8],
    state: &mut SharedState,
    host_id: Option<&str>,
    emit: &mut F,
) -> Result<()>
where
    F: FnMut(Event),
{
    if bytes.len() < std::mem::size_of::<RawConnectEvent>() {
        return Ok(());
    }
    let mut raw = RawConnectEvent::zeroed();
    plain::copy_from_bytes(&mut raw, bytes)
        .map_err(|_| anyhow!("ringbuf record size mismatch"))?;

    let pid = raw.pid as i32;
    let endpoint = network::parse_sockaddr(&raw.sockaddr);

    if network::is_uninteresting(&endpoint) {
        return Ok(());
    }

    let record = match resolve_enrollment(pid, state) {
        Some(r) => r,
        None => return Ok(()),
    };

    let (dest_ip_str, dest_port, protocol) = match &endpoint {
        Endpoint::V4 { ip, port } => (ip.to_string(), *port, Protocol::Tcp),
        Endpoint::V6 { ip, port } => (ip.to_string(), *port, Protocol::Tcp),
        Endpoint::Other => return Ok(()),
    };

    let snap = proc::snapshot(pid);
    let chain = proc::parent_chain(pid, 16);
    let is_agent_root = record.agent_root.pid == pid;
    let attributed_by_descent = !is_agent_root;

    let bpf_comm = nul_str(&raw.comm).to_string();
    let process_name = if !snap.comm.is_empty() {
        snap.comm.clone()
    } else {
        bpf_comm.clone()
    };
    let user = if !snap.user.is_empty() {
        snap.user.clone()
    } else {
        raw.uid.to_string()
    };

    let event = Event {
        schema_version: SCHEMA_VERSION.to_string(),
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: rfc3339_from_boot_ns(raw.timestamp_ns),
        monotonic_ns: Some(raw.timestamp_ns),
        platform: Platform::Linux,
        host_id: host_id.map(str::to_string),
        agent_id: "agent-descendant".to_string(),
        session_id: None,
        user_id: Some(user.clone()),
        source: Source {
            collector: "linux_ebpf".to_string(),
            probe: "tracepoint/syscalls/sys_enter_connect".to_string(),
            host_pid: Some(pid),
        },
        kind: EventKind::NetworkEgress(NetworkEgressPayload {
            process: Process {
                pid,
                ppid: snap.ppid,
                start_time: snap.start_time_ticks.to_string(),
                name: process_name,
                path: snap.exe_path.clone(),
                cmdline: snap.cmdline.clone(),
                cwd: snap.cwd.clone(),
                user,
                integrity_level: None,
                parent_chain: chain,
                agent_root_pid: Some(record.agent_root.pid),
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
            dest_ip: dest_ip_str,
            dest_port,
            dest_host: None,
            protocol,
            tls_sni: None,
        }),
    };

    emit(event);
    Ok(())
}

fn absolutize(filename: &str, pid: i32) -> String {
    if filename.starts_with('/') {
        return filename.to_string();
    }
    if let Ok(cwd) = std::fs::read_link(format!("/proc/{pid}/cwd")) {
        let cwd_str = cwd.to_string_lossy();
        return format!("{cwd_str}/{filename}");
    }
    filename.to_string()
}

fn access_type_from_flags(flags: i32) -> AccessType {
    // openat flags: O_RDONLY=0, O_WRONLY=1, O_RDWR=2 occupy the bottom 2 bits.
    const O_ACCMODE: i32 = 3;
    match flags & O_ACCMODE {
        0 => AccessType::Read,
        1 | 2 => AccessType::Write,
        _ => AccessType::Open,
    }
}

/// True when an openat's flags indicate intent to modify the file: a writable
/// access mode (O_WRONLY/O_RDWR) or a creating/truncating open. O_RDONLY opens
/// (including O_RDONLY|O_CLOEXEC reads of a credential file) are not writes.
fn is_write_intent(flags: i32) -> bool {
    const O_ACCMODE: i32 = 3;
    const O_CREAT: i32 = 0o100;
    const O_TRUNC: i32 = 0o1000;
    let accmode = flags & O_ACCMODE;
    accmode == 1 || accmode == 2 || (flags & (O_CREAT | O_TRUNC)) != 0
}

/// Locate the libc shared object that exports `getaddrinfo`, for the DNS
/// uprobe. Checks the common glibc multi-arch locations; returns the first that
/// exists. None on a static-musl host (where the uprobe simply won't attach).
fn libc_path() -> Option<String> {
    const CANDIDATES: &[&str] = &[
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/aarch64-linux-gnu/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib/aarch64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib/libc.so.6",
    ];
    CANDIDATES
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(|p| p.to_string())
}

fn nul_str(buf: &[u8]) -> &str {
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..len]).unwrap_or("")
}

fn argv_from_cmdline(cmdline: &str) -> Vec<String> {
    cmdline
        .split(' ')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Convert CLOCK_BOOTTIME nanoseconds (what `bpf_ktime_get_boot_ns()` returns)
/// to a wall-clock RFC 3339 string.
fn rfc3339_from_boot_ns(boot_ns: u64) -> String {
    use std::sync::OnceLock;
    static BOOT_WALL_NS: OnceLock<i128> = OnceLock::new();
    let boot_wall_ns = *BOOT_WALL_NS.get_or_init(|| {
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
        let mono = (ts.tv_sec as i128) * 1_000_000_000 + (ts.tv_nsec as i128);
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i128)
            .unwrap_or(0);
        wall - mono
    });
    let wall_ns = boot_wall_ns + (boot_ns as i128);
    let secs = (wall_ns / 1_000_000_000) as i64;
    let nsec = (wall_ns % 1_000_000_000) as u32;
    format_rfc3339(secs, nsec)
}

fn format_rfc3339(secs: i64, nsec: u32) -> String {
    let (year, month, day, hour, minute, second) = unix_to_civil(secs);
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nsec:09}Z"
    )
}

fn unix_to_civil(unix_secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let z = unix_secs.div_euclid(86_400) + 719_468;
    let secs_of_day = unix_secs.rem_euclid(86_400) as u32;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    (year as i32, month, day, hour, minute, second)
}

fn comm_to_agent_id(
    comm: &str,
    enrolled: &[String],
    _record: &enroll::EnrollmentRecord,
) -> String {
    if enrolled.iter().any(|n| n == comm) {
        return comm.to_string();
    }
    "agent-descendant".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nul_str_truncates_at_first_null() {
        let mut buf = [0u8; 16];
        buf[..5].copy_from_slice(b"claud");
        assert_eq!(nul_str(&buf), "claud");
    }

    #[test]
    fn argv_from_cmdline_splits_on_space() {
        let argv = argv_from_cmdline("npm install lodash");
        assert_eq!(argv, vec!["npm", "install", "lodash"]);
    }

    #[test]
    fn unix_to_civil_known_date() {
        // 2026-05-27T17:52:11Z → 1_779_904_331
        let (y, m, d, h, mi, s) = unix_to_civil(1_779_904_331);
        assert_eq!((y, m, d, h, mi, s), (2026, 5, 27, 17, 52, 11));
    }

    #[test]
    fn write_intent_distinguishes_read_from_write() {
        const O_RDONLY: i32 = 0;
        const O_WRONLY: i32 = 1;
        const O_RDWR: i32 = 2;
        const O_CREAT: i32 = 0o100;
        const O_TRUNC: i32 = 0o1000;
        const O_CLOEXEC: i32 = 0o2000000;
        // Reads (incl. the credential-exfil case: O_RDONLY|O_CLOEXEC).
        assert!(!is_write_intent(O_RDONLY));
        assert!(!is_write_intent(O_RDONLY | O_CLOEXEC));
        // Writes / creations / truncations.
        assert!(is_write_intent(O_WRONLY));
        assert!(is_write_intent(O_RDWR));
        assert!(is_write_intent(O_WRONLY | O_CREAT | O_TRUNC));
        assert!(is_write_intent(O_RDONLY | O_CREAT)); // creating, still a write
    }
}
