//! Linux eBPF process_exec collector.
//!
//! Attaches a tracepoint to `sched/sched_process_exec`, consumes exec events
//! from a ringbuf, applies userspace enrollment filtering (only emit when the
//! process is an enrolled agent CLI or a descendant of one), and produces
//! schema v0.2 `ProcessExec` events.
//!
//! The attribution block on emitted events sets `attributed_by_descent = true`
//! for enrolled descendants. The other attribution fields are placeholders
//! until the daemon's attribution engine wires together transcript tool_calls
//! (timing windows) and the identifier index (origin booleans).
//!
//! Requires CAP_BPF + CAP_PERFMON. Run as root for v0.x.

pub mod enroll;
pub mod proc;

mod skel {
    #![allow(clippy::all)]
    #![allow(dead_code)]
    #![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/execve.skel.rs"));
}

use std::cell::Cell;
use std::cell::RefCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use fishbowl_schema::{
    Attribution, Event, EventKind, Platform, Process, ProcessExecPayload, Source, SCHEMA_VERSION,
};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::OpenObject;
use plain::Plain;
use serde::Deserialize;

use crate::enroll::{EnrollmentTable, ProcessKey};
use crate::skel::*;

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
pub fn run<F>(config: CollectorConfig, stop: Arc<AtomicBool>, mut emit: F) -> Result<()>
where
    F: FnMut(Event),
{
    let skel_builder = ExecveSkelBuilder::default();
    // libbpf-rs 0.24 requires the caller to own an `OpenObject` slot for the
    // skeleton's lifetime — we keep it on the stack via MaybeUninit.
    let mut open_object: MaybeUninit<OpenObject> = MaybeUninit::uninit();
    let open_skel = skel_builder
        .open(&mut open_object)
        .context("open BPF skeleton")?;
    let mut skel = open_skel.load().context("load BPF program")?;
    skel.attach().context("attach BPF program")?;

    let table = RefCell::new(EnrollmentTable::new());
    let emit_cell = RefCell::new(emit);
    let host_id = config.host_id.clone();
    // Shared error sink. The ringbuf callback stores into `had_error`; the
    // outer loop drains it after each poll. `Cell` because both sides hold
    // shared references and `Option<anyhow::Error>::default()` is `None`.
    let had_error: Cell<Option<anyhow::Error>> = Cell::new(None);

    // In libbpf-rs 0.24 the generated skeleton exposes maps as a struct
    // field, not a method.
    let maps = &skel.maps;
    let mut builder = libbpf_rs::RingBufferBuilder::new();

    let handle = |bytes: &[u8]| -> i32 {
        let mut table = table.borrow_mut();
        let mut emit = emit_cell.borrow_mut();
        if let Err(e) = handle_event(
            bytes,
            &config,
            &mut table,
            host_id.as_deref(),
            &mut *emit,
        ) {
            had_error.set(Some(e));
            return 1;
        }
        0
    };

    builder
        .add(&maps.events, handle)
        .context("add ringbuf consumer")?;
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
    }

    Ok(())
}

fn handle_event<F>(
    bytes: &[u8],
    config: &CollectorConfig,
    table: &mut EnrollmentTable,
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
    let parent_enrolled = parent_key.and_then(|pk| table.get(pk));

    let record = if is_agent_root_match {
        Some(table.enroll(key, None))
    } else if parent_enrolled.is_some() {
        Some(table.enroll(key, parent_key))
    } else {
        None
    };

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
