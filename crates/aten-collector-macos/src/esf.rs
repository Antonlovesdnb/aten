//! EndpointSecurity producer: `NOTIFY_EXEC` → `ProcessExec`,
//! `NOTIFY_OPEN` → `CredentialAccess`.
//!
//! The ES framework delivers messages on a dispatch queue it manages, so once
//! the `Client` is created and subscribed we just keep it alive (the returned
//! `EsfGuard` is held by `run_with_tick` for the collector's lifetime). The
//! handler clones every field it needs out of the borrowed `Message` before
//! returning — the message is freed afterward — and ships a finished `Event`
//! through the channel.
//!
//! We subscribe only to NOTIFY (never AUTH) events, so there's no kernel
//! response deadline and the handler can never block a syscall. Producers use
//! `try_send` (drop-on-full) so a stalled consumer can't wedge the ES queue.
//!
//! ## API-surface note (verify on macOS)
//!
//! This is written against the `endpoint-sec` 0.4 documented API but compiled
//! for the first time on the Mac. The spots most likely to need a one-line
//! adjustment are tagged `VERIFY:` — event-type constant paths, the
//! `set_runtime_version` location, and the `EventOpen` file accessor name.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};

use aten_collector_linux::credentials::{self};
use aten_collector_linux::enroll::ProcessKey;
use aten_schema::{
    AccessType, CredentialAccessPayload, CredentialClass, Event, EventKind, Platform,
    ProcessExecPayload, Source, SCHEMA_VERSION,
};

use endpoint_sec::sys::es_event_type_t;
use endpoint_sec::{Client, Event as EsEvent, Message};

use crate::macos_impl::{self, CollectorConfig, Msg, SharedState};
use crate::procinfo;

/// Keeps the ES client alive. Dropping it unsubscribes and disconnects.
pub struct EsfGuard {
    _client: Client<'static>,
}

/// Create the ES client, subscribe to exec + open, and return a guard that
/// keeps it running. Returns `Err` (typically NOT_PERMITTED — missing
/// entitlement) so the caller can degrade to netflow-only.
pub fn start(
    config: CollectorConfig,
    state: Arc<Mutex<SharedState>>,
    tx: SyncSender<Msg>,
    dropped: Arc<AtomicU64>,
) -> Result<EsfGuard> {
    // Required before any other ES call so version-gated client operations
    // match the host instead of endpoint-sec's conservative 10.15 default.
    let (major, minor, patch) = macos_version();
    endpoint_sec::version::set_runtime_version(major, minor, patch);

    let handler = move |_client: &mut Client<'_>, msg: Message| {
        // A panic inside the handler must not unwind into the ES framework.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handle_message(&msg, &config, &state, &tx, &dropped);
        }));
    };

    let mut client = Client::new(handler).map_err(|e| anyhow!("es_new_client failed: {e:?}"))?;
    client
        .subscribe(&[
            es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXEC,
            es_event_type_t::ES_EVENT_TYPE_NOTIFY_OPEN,
            es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXIT,
        ])
        .map_err(|e| anyhow!("es_subscribe failed: {e:?}"))?;

    Ok(EsfGuard { _client: client })
}

fn handle_message(
    msg: &Message,
    config: &CollectorConfig,
    state: &Arc<Mutex<SharedState>>,
    tx: &SyncSender<Msg>,
    dropped: &AtomicU64,
) {
    match msg.event() {
        Some(EsEvent::NotifyExec(exec)) => {
            if let Some(ev) = build_exec_event(&exec, config, state) {
                send_event(tx, ev, dropped);
            }
        }
        Some(EsEvent::NotifyOpen(open)) => {
            if let Some(ev) = build_open_event(msg, &open, config, state) {
                send_event(tx, ev, dropped);
            }
        }
        Some(EsEvent::NotifyExit(_)) => {
            let pid = msg.process().audit_token().pid();
            if let Ok(mut st) = state.lock() {
                if let Some(key) = st.pid_to_key.remove(&pid) {
                    st.table.forget(key);
                    st.proc_cache.remove(&key);
                }
            }
        }
        _ => {}
    }
}

fn send_event(tx: &SyncSender<Msg>, event: Event, dropped: &AtomicU64) {
    if tx.try_send(Msg::Event(Box::new(event))).is_err() {
        let count = dropped.fetch_add(1, Ordering::Relaxed) + 1;
        if count.is_power_of_two() {
            eprintln!("aten-macos: producer queue full; dropped {count} event(s)");
        }
    }
}

/// `NOTIFY_EXEC` → enrollment + `ProcessExec`. Builds `Process` from the rich
/// `es_process_t` (the `target` of the exec — the new image), avoiding a
/// libproc round-trip on the hot path; only `parent_chain` uses libproc.
fn build_exec_event(
    exec: &endpoint_sec::EventExec,
    config: &CollectorConfig,
    state: &Arc<Mutex<SharedState>>,
) -> Option<Event> {
    let target = exec.target();
    let token = target.audit_token();
    let pid = token.pid();
    let euid = token.euid();
    let ppid = target.ppid();
    let exe_path = osstr_to_string(target.executable().path());
    let name = procinfo::basename(&exe_path);
    let start_secs = systemtime_to_epoch_secs(target.start_time());
    let key = ProcessKey {
        pid,
        start_time_ticks: start_secs,
    };

    let is_root = procinfo::is_enrolled_agent(&name, &exe_path, &config.enrolled_agents);

    // Enrollment decision under the lock; drop it before libproc enrichment.
    let agent_root_pid = {
        let mut st = state.lock().ok()?;
        let parent_key = st.pid_to_key.get(&ppid).copied();
        let record = if is_root {
            st.table.enroll(key, None)
        } else if let Some(pk) = parent_key.filter(|pk| st.table.contains(*pk)) {
            st.table.enroll(key, Some(pk))
        } else {
            return None; // not an agent and no enrolled parent → drop
        };
        st.pid_to_key.insert(pid, key);
        st.events_seen += 1;
        record.agent_root.pid
    };

    let args: Vec<String> = exec.args().map(osstr_to_string).collect();
    let cmdline = args.join(" ");
    let cwd = exec
        .cwd()
        .map(|f| osstr_to_string(f.path()))
        .unwrap_or_default();
    let user = procinfo::username_for_uid(euid).unwrap_or_else(|| euid.to_string());
    let parent_chain = if ppid > 0 {
        procinfo::parent_chain(pid, 16)
    } else {
        Vec::new()
    };

    let process = aten_schema::Process {
        pid,
        ppid,
        start_time: start_secs.to_string(),
        name: name.clone(),
        path: exe_path,
        cmdline,
        cwd,
        user: user.clone(),
        integrity_level: None,
        parent_chain,
        agent_root_pid: Some(agent_root_pid),
    };

    Some(Event {
        schema_version: SCHEMA_VERSION.to_string(),
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: macos_impl::now_rfc3339(),
        monotonic_ns: macos_impl::monotonic_ns(),
        platform: Platform::Macos,
        host_id: config.host_id.clone(),
        agent_id: if is_root {
            name
        } else {
            "agent-descendant".to_string()
        },
        session_id: None,
        user_id: if user.is_empty() { None } else { Some(user) },
        source: Source {
            collector: "macos_esf".to_string(),
            probe: "EndpointSecurity/ES_EVENT_TYPE_NOTIFY_EXEC".to_string(),
            host_pid: Some(pid),
        },
        kind: EventKind::ProcessExec(ProcessExecPayload {
            process,
            attribution: macos_impl::descent_attribution(!is_root),
            exec_args: args,
            exec_envp_summary: String::new(),
        }),
    })
}

/// `NOTIFY_OPEN` → `CredentialAccess`, but only for paths that classify as a
/// credential AND whose opener is an enrolled agent/descendant. Mirrors
/// `linux_impl::handle_credacc_event`, including the agent-config-dotenv
/// self-read suppression (landed in commit 370eac5).
fn build_open_event(
    msg: &Message,
    open: &endpoint_sec::EventOpen,
    config: &CollectorConfig,
    state: &Arc<Mutex<SharedState>>,
) -> Option<Event> {
    // VERIFY: EventOpen file accessor — `file()` per es_event_open_t.file.
    let path = osstr_to_string(open.file().path());
    let write_intent = open_flags_write_intent(open.fflag());

    // Classify FIRST — the vast majority of opens aren't credentials, and we
    // want to drop them before taking the lock or touching libproc.
    let class = credentials::classify_for_access(&path, write_intent);
    if class == CredentialClass::None {
        return None;
    }

    let pid = msg.process().audit_token().pid();

    let record = {
        let mut st = state.lock().ok()?;
        macos_impl::resolve_enrollment(pid, &mut st)?
    };
    let cached = macos_impl::process_enrichment(pid, state);
    let is_agent_root = record.agent_root.pid == pid;

    // Suppress the agent reading its OWN config dotenv at startup; a descendant
    // reading the same file is real exfil and still emits.
    if is_agent_root && credentials::is_agent_config_dotenv(&path) {
        return None;
    }

    let snap = cached.snapshot;
    let process =
        macos_impl::process_from_snapshot(&snap, Some(record.agent_root.pid), cached.parent_chain);
    let user = snap.user.clone();

    Some(Event {
        schema_version: SCHEMA_VERSION.to_string(),
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: macos_impl::now_rfc3339(),
        monotonic_ns: macos_impl::monotonic_ns(),
        platform: Platform::Macos,
        host_id: config.host_id.clone(),
        agent_id: "agent-descendant".to_string(),
        session_id: None,
        user_id: if user.is_empty() { None } else { Some(user) },
        source: Source {
            collector: "macos_esf".to_string(),
            probe: "EndpointSecurity/ES_EVENT_TYPE_NOTIFY_OPEN".to_string(),
            host_pid: Some(pid),
        },
        kind: EventKind::CredentialAccess(CredentialAccessPayload {
            process,
            attribution: macos_impl::descent_attribution(!is_agent_root),
            file_path: path,
            access_type: if write_intent {
                AccessType::Write
            } else {
                AccessType::Open
            },
            credential_class: class,
            bytes_read: None,
        }),
    })
}

fn open_flags_write_intent(flags: i32) -> bool {
    let accmode = flags & libc::O_ACCMODE;
    accmode == libc::O_WRONLY
        || accmode == libc::O_RDWR
        || flags & (libc::O_APPEND | libc::O_TRUNC | libc::O_CREAT) != 0
}

/// `SystemTime` → seconds since the UNIX epoch, matching
/// `proc_bsdinfo.pbi_start_tvsec` so `ProcessKey`s collide across the ESF and
/// netflow sources for the same process incarnation (see `procinfo` docs).
fn systemtime_to_epoch_secs(t: Option<std::time::SystemTime>) -> u64 {
    t.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn osstr_to_string(s: &std::ffi::OsStr) -> String {
    s.to_string_lossy().into_owned()
}

/// Read the product version once at collector startup. `endpoint-sec` uses
/// this to avoid invoking APIs newer than the running host. Fall back to the
/// framework's minimum supported version if `sw_vers` is unavailable.
fn macos_version() -> (u64, u64, u64) {
    let output = std::process::Command::new("/usr/bin/sw_vers")
        .arg("-productVersion")
        .output();
    let version = output
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok());
    let mut parts = version
        .as_deref()
        .unwrap_or("10.15.0")
        .trim()
        .split('.')
        .filter_map(|part| part.parse::<u64>().ok());
    let major = parts.next().unwrap_or(10);
    let minor = parts.next().unwrap_or(15);
    let patch = parts.next().unwrap_or(0);
    if major < 10 || (major == 10 && minor < 15) {
        (10, 15, 0)
    } else {
        (major, minor, patch)
    }
}
