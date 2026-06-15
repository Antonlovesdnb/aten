//! macOS collector core: the run loop, shared enrollment state, and the
//! envelope helpers shared by the ESF and netflow-IPC producers.
//!
//! ## Threading model
//!
//! Unlike the Linux collector (which polls a ringbuf inline on the calling
//! thread), the macOS event producers run on threads we don't own — the ESF
//! framework's dispatch queue and the netflow IPC listener thread. So this
//! takes the *Windows* shape of the contract (`F: FnMut(Event) + Send +
//! 'static`). All producers funnel finished `Event`s through a bounded
//! `mpsc::sync_channel` to a single consumer — the calling thread — which is
//! the only place `emit` and `tick` are ever called. No `Mutex` around `emit`,
//! no lock contention on the hot path.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::Deserialize;

use aten_collector_linux::enroll::{EnrollmentRecord, EnrollmentTable, ProcessKey};
use aten_schema::{Attribution, Event, Process};

use crate::netflow_ipc;
use crate::procinfo::{self, ProcSnapshot};

/// Mirrors the Linux/Windows `CollectorConfig` so the daemon drives all three
/// collectors through one shape.
#[derive(Debug, Clone, Deserialize)]
pub struct CollectorConfig {
    /// Process basenames that count as agent roots, e.g. `["claude","codex"]`.
    pub enrolled_agents: Vec<String>,
    /// Stable host identifier for the envelope's `host_id`.
    pub host_id: Option<String>,
}

/// Enrollment state shared across the ESF handlers and the netflow IPC thread.
/// Behind an `Arc<Mutex<…>>` because the producers are on different OS threads
/// (the Linux collector uses a single-threaded `RefCell` form; we can't).
pub struct SharedState {
    pub table: EnrollmentTable,
    /// Fast path: bare pid → key, so the hot handlers skip the libproc walk.
    pub pid_to_key: HashMap<i32, ProcessKey>,
    pub events_seen: u64,
}

impl SharedState {
    fn new() -> Self {
        Self {
            table: EnrollmentTable::new(),
            pid_to_key: HashMap::new(),
            events_seen: 0,
        }
    }
}

/// What producers send to the consumer. Events are boxed because `Event` is
/// large and we don't want big channel nodes.
pub enum Msg {
    Event(Box<Event>),
    #[allow(dead_code)]
    Fatal(anyhow::Error),
}

/// Drain at most this many events before yielding to `tick()`, so an event
/// flood can't starve the daemon's transcript refresh.
const DRAIN_BATCH: usize = 256;

pub fn run<F>(config: CollectorConfig, stop: Arc<AtomicBool>, emit: F) -> Result<()>
where
    F: FnMut(Event) + Send + 'static,
{
    run_with_tick(config, stop, emit, || {})
}

pub fn run_with_tick<F, T>(
    config: CollectorConfig,
    stop: Arc<AtomicBool>,
    mut emit: F,
    mut tick: T,
) -> Result<()>
where
    F: FnMut(Event) + Send + 'static,
    T: FnMut(),
{
    let (tx, rx) = mpsc::sync_channel::<Msg>(4096);
    let state = Arc::new(Mutex::new(SharedState::new()));

    // Seed already-running agents — ESF NOTIFY_EXEC only fires post-subscribe.
    {
        let mut st = state.lock().expect("state lock");
        let seeded = procinfo::rundown(&config.enrolled_agents, &mut st.table, &mut st.pid_to_key);
        eprintln!("aten-macos: enrollment rundown seeded {seeded} agent root(s)");
    }

    // ESF producer (exec + open). Entitlement-gated; behind the `esf` feature so
    // the netflow path can still run where ESF is denied.
    #[cfg(feature = "esf")]
    let _es_guard = {
        match crate::esf::start(config.clone(), state.clone(), tx.clone()) {
            Ok(guard) => Some(guard),
            Err(e) => {
                // NOT_PERMITTED (missing entitlement) is the common case in
                // dev mode — degrade to netflow-only rather than abort.
                eprintln!("aten-macos: ESF disabled ({e:#}); running netflow-only");
                None
            }
        }
    };

    // Network producer (sysext flows over UDS).
    let _ipc_guard = netflow_ipc::spawn(config.clone(), state.clone(), tx.clone(), stop.clone())?;

    eprintln!(
        "aten-macos: collector started (agents = {:?})",
        config.enrolled_agents
    );

    // Consumer loop on the calling thread — the only `emit`/`tick` site.
    let mut last_tick = Instant::now();
    let tick_every = Duration::from_millis(200);
    while !stop.load(Ordering::Relaxed) {
        // Drain a bounded batch without blocking.
        let mut drained = 0usize;
        while drained < DRAIN_BATCH {
            match rx.try_recv() {
                Ok(Msg::Event(ev)) => {
                    emit(*ev);
                    drained += 1;
                }
                Ok(Msg::Fatal(e)) => return Err(e),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
            }
        }

        // If nothing was waiting, block briefly so we don't spin.
        if drained == 0 {
            match rx.recv_timeout(tick_every) {
                Ok(Msg::Event(ev)) => emit(*ev),
                Ok(Msg::Fatal(e)) => return Err(e),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
            }
        }

        if last_tick.elapsed() >= tick_every {
            tick();
            last_tick = Instant::now();
        }
    }
    Ok(())
    // _es_guard and _ipc_guard drop here: ESF unsubscribes, IPC thread joins.
}

/// Find the `EnrollmentRecord` for `pid`, falling back to a libproc ancestor
/// walk when the fast-path `pid_to_key` lookup misses (the ESF-deliver /
/// IPC-arrival race where an open or flow beats the descendant's own EXEC).
/// Direct analog of `linux_impl::resolve_enrollment`.
pub fn resolve_enrollment(pid: i32, state: &mut SharedState) -> Option<EnrollmentRecord> {
    if let Some(key) = state.pid_to_key.get(&pid).copied() {
        if let Some(r) = state.table.get(key) {
            return Some(r);
        }
    }

    let my_key = procinfo::process_key(pid)?;
    if let Some(r) = state.table.get(my_key) {
        state.pid_to_key.insert(pid, my_key);
        return Some(r);
    }

    const MAX_WALK: usize = 16;
    let mut current = procinfo::snapshot(pid);
    for _ in 0..MAX_WALK {
        let ppid = current.ppid;
        if ppid <= 0 {
            break;
        }
        if let Some(pkey) = procinfo::process_key(ppid) {
            if state.table.get(pkey).is_some() {
                let record = state.table.enroll(my_key, Some(pkey));
                state.pid_to_key.insert(pid, my_key);
                return Some(record);
            }
        }
        if ppid == 1 {
            break;
        }
        current = procinfo::snapshot(ppid);
    }
    None
}

/// Build a `Process` block from a libproc snapshot. Used by the open and
/// network handlers (the exec handler builds `Process` straight from the ESF
/// message instead).
pub fn process_from_snapshot(
    snap: &ProcSnapshot,
    agent_root_pid: Option<i32>,
    parent_chain: Vec<aten_schema::ParentChainEntry>,
) -> Process {
    Process {
        pid: snap.pid,
        ppid: snap.ppid,
        start_time: snap.start_time_ticks.to_string(),
        name: snap.comm.clone(),
        path: snap.exe_path.clone(),
        cmdline: snap.cmdline.clone(),
        cwd: snap.cwd.clone(),
        user: snap.user.clone(),
        integrity_level: None,
        parent_chain,
        agent_root_pid,
    }
}

/// The collector-side `Attribution`: only the enrollment-derived
/// `attributed_by_descent` is known here. The daemon's attribution engine fills
/// the transcript-correlation fields (`attributed_tool_call_id`,
/// `requested_in_*`, `triggering_*`) in its post-event buffer. Identical to the
/// block every Linux/Windows kernel event ships.
pub fn descent_attribution(attributed_by_descent: bool) -> Attribution {
    Attribution {
        attributed_tool_call_id: None,
        attributed_by_descent,
        requested_by_tool_call: false,
        requested_in_user_message: false,
        requested_in_assistant_message: false,
        requested_in_tool_result: false,
        time_window_ms: None,
        triggering_command: None,
        triggering_prompt: None,
    }
}

/// Wall-clock timestamp for the envelope, RFC3339 with millis. macOS kernel
/// events are processed near-instantly, so now() is an accurate event time.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Monotonic nanoseconds since boot, for cross-event ordering. macOS analog of
/// the Linux `CLOCK_BOOTTIME` ns the eBPF probes stamp.
pub fn monotonic_ns() -> Option<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid timespec; CLOCK_UPTIME_RAW is the macOS monotonic
    // since-boot clock.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_UPTIME_RAW, &mut ts) };
    if rc != 0 {
        return None;
    }
    Some((ts.tv_sec as u64).wrapping_mul(1_000_000_000).wrapping_add(ts.tv_nsec as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descent_attribution_only_sets_descent() {
        let a = descent_attribution(true);
        assert!(a.attributed_by_descent);
        assert!(a.attributed_tool_call_id.is_none());
        assert!(!a.requested_in_tool_result);
        assert!(a.triggering_prompt.is_none());
    }

    #[test]
    fn rfc3339_has_z_suffix() {
        let s = now_rfc3339();
        assert!(s.ends_with('Z'), "expected UTC Z suffix, got {s}");
    }
}
