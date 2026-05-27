//! Linux eBPF collector.
//!
//! Attaches two tracepoints:
//! - `sched/sched_process_exec` → `ProcessExec` events
//! - `syscalls/sys_enter_openat` → `CredentialAccess` events (after the
//!   userspace classifier maps the path to a real credential class)
//!
//! Both probes share an enrollment state machine: only processes that are
//! enrolled agent CLIs or descendants of one produce events. The exec probe
//! drives enrollment (it sees every new process); the openat probe consults
//! the same `EnrollmentTable` via a side-table `pid_to_key` that the exec
//! handler maintains.
//!
//! The attribution block on emitted events sets `attributed_by_descent = true`
//! for enrolled descendants. The other attribution fields are placeholders
//! until the daemon's attribution engine wires together transcript tool_calls
//! and the identifier index.
//!
//! Requires CAP_BPF + CAP_PERFMON. Run as root for v0.x.

pub mod credentials;
pub mod enroll;
pub mod proc;

mod skel_execve {
    #![allow(clippy::all)]
    #![allow(dead_code)]
    #![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/execve.skel.rs"));
}

mod skel_credacc {
    #![allow(clippy::all)]
    #![allow(dead_code)]
    #![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/credacc.skel.rs"));
}

use std::cell::Cell;
use std::cell::RefCell;
use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use fishbowl_schema::{
    AccessType, Attribution, CredentialAccessPayload, CredentialClass, Event, EventKind, Platform,
    Process, ProcessExecPayload, Source, SCHEMA_VERSION,
};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::OpenObject;
use plain::Plain;
use serde::Deserialize;

use crate::enroll::{EnrollmentTable, EnrollmentRecord, ProcessKey};
use crate::skel_credacc::*;
use crate::skel_execve::*;

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

/// State shared between the two probe handlers. The exec handler maintains
/// `pid_to_key` so the credacc handler can look up a process's enrollment
/// record in O(1) without a /proc/<pid>/stat read on every open.
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

    let state = RefCell::new(SharedState::default());
    let emit_cell = RefCell::new(emit);
    let host_id = config.host_id.clone();
    let had_error: Cell<Option<anyhow::Error>> = Cell::new(None);

    let exec_maps = &exec_skel.maps;
    let cred_maps = &cred_skel.maps;
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

    builder
        .add(&exec_maps.events, exec_handle)
        .context("add execve ringbuf consumer")?;
    builder
        .add(&cred_maps.cred_events, cred_handle)
        .context("add credacc ringbuf consumer")?;
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
        // /proc/<pid>/stat unreadable — process gone. Drop.
        return Ok(());
    }
    let key = ProcessKey {
        pid,
        start_time_ticks: snap.start_time_ticks,
    };

    // Enrollment decision.
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

    // Maintain pid_to_key so the credacc handler can look up enrollment in
    // O(1). Invalidate on non-enrolled execs to avoid PID-reuse stale binds.
    match record {
        Some(_) => {
            state.pid_to_key.insert(pid, key);
        }
        None => {
            state.pid_to_key.remove(&pid);
        }
    }

    let Some(record) = record else {
        return Ok(()); // Not interesting — drop.
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
            },
            exec_args: argv_from_cmdline(&snap.cmdline),
            exec_envp_summary: String::new(),
        }),
    };

    emit(event);
    Ok(())
}

/// Handle one credential-access ringbuf record. Drop fast for the 99%+ of
/// opens that aren't from an enrolled process tree or aren't credential
/// paths; only emit the small minority that pass both filters.
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

    // Order matters here. 99%+ of all opens on a Linux box are not credential
    // paths, and `credentials::classify` is a handful of substring checks on
    // a ≤256-byte string — sub-microsecond. Doing it FIRST lets us drop the
    // overwhelming majority of events before paying for any /proc lookup.
    //
    // The enrollment check is the expensive one (possible /proc walk to
    // resolve a freshly-spawned descendant the exec ringbuf hasn't reported
    // yet — see `resolve_enrollment`). We only reach it for credential-class
    // opens, which on a dev endpoint is a small handful per minute.
    let class = credentials::classify(filename);
    if class == CredentialClass::None {
        return Ok(());
    }

    let record = match resolve_enrollment(pid, state) {
        Some(r) => r,
        None => return Ok(()),
    };

    // Resolve the absolute path. The kernel gives us the syscall arg, which
    // may be relative (e.g. `.aws/credentials` from a process whose cwd is
    // $HOME). Use /proc/<pid>/cwd to normalize to an absolute path so the
    // attribution engine's identifier match and the schema's file_path field
    // are both unambiguous.
    let abs_path = absolutize(filename, pid);

    let snap = proc::snapshot(pid);
    let chain = proc::parent_chain(pid, 16);
    let is_agent_root = record.agent_root.pid == pid;
    let attributed_by_descent = !is_agent_root;

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
        user_id: Some(snap.user.clone()),
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
                name: snap.comm.clone(),
                path: snap.exe_path.clone(),
                cmdline: snap.cmdline.clone(),
                cwd: snap.cwd.clone(),
                user: snap.user.clone(),
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

/// Find the EnrollmentRecord for `pid`, falling back to a /proc walk if the
/// fast-path `pid_to_key` lookup misses (race with the exec ringbuf). Caches
/// any successful /proc-walk hit back into `pid_to_key` so subsequent opens
/// from the same pid are O(1).
fn resolve_enrollment(pid: i32, state: &mut SharedState) -> Option<EnrollmentRecord> {
    if let Some(key) = state.pid_to_key.get(&pid).copied() {
        if let Some(r) = state.table.get(key) {
            return Some(r);
        }
    }

    // Slow path: read /proc/<pid>/stat for start_time + ppid, then walk up.
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

    // Walk up to MAX_WALK ancestors. Each hop is a /proc/<pid>/stat read.
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
            // Found an enrolled ancestor — promote `pid` to be a tracked
            // descendant carrying the same agent_root. Cache for next time.
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

#[allow(dead_code)]
fn _silence_unused(_r: EnrollmentRecord) {}

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
/// to a wall-clock RFC 3339 string. We snapshot boot wall-time at startup as
/// `(wall_now - monotonic_now_since_boot)`. Drift across one run is ms-scale,
/// acceptable for v0.x where the schema's `timestamp` is informational and
/// `monotonic_ns` is the source of truth for intra-tick ordering.
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
    // Minimal RFC 3339 UTC formatter. Avoids pulling in chrono just for this.
    let (year, month, day, hour, minute, second) = unix_to_civil(secs);
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nsec:09}Z"
    )
}

/// Howard Hinnant's "civil_from_days" algorithm, slightly inlined. Converts a
/// Unix timestamp (seconds since 1970-01-01 UTC) into a civil date.
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

/// Pick an agent_id label for an emitted event. If this event IS the agent
/// root (the freshly-exec'd `claude`/`cursor`/etc.), label it with the comm.
/// If it's a descendant, label it with the root's comm — but we don't store
/// the root's comm in the table, so for v0.x we just use the matched name or
/// a generic "agent". This is good enough for the demo and gets refined when
/// the attribution engine lands.
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
        // (20600 days since epoch * 86400 + 17*3600 + 52*60 + 11)
        let (y, m, d, h, mi, s) = unix_to_civil(1_779_904_331);
        assert_eq!((y, m, d, h, mi, s), (2026, 5, 27, 17, 52, 11));
    }
}
