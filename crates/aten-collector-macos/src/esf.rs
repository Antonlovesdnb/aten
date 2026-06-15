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

use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};

use aten_collector_linux::credentials::{self};
use aten_collector_linux::enroll::ProcessKey;
use aten_schema::{
    AccessType, CredentialAccessPayload, CredentialClass, Event, EventKind, Platform,
    ProcessExecPayload, Source, SCHEMA_VERSION,
};

use endpoint_sec::{Client, Event as EsEvent, Message};
// VERIFY: event-type constants live in the -sys crate, re-exported here.
use endpoint_sec::sys::es_event_type_t::{
    ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_OPEN,
};

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
) -> Result<EsfGuard> {
    // VERIFY: required before any other ES call so version-gated accessors
    // (e.g. EventExec::cwd) behave correctly.
    endpoint_sec::version::set_runtime_version();

    let handler = move |_client: &mut Client<'_>, msg: Message| {
        // A panic inside the handler must not unwind into the ES framework.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handle_message(&msg, &config, &state, &tx);
        }));
    };

    let mut client = Client::new(handler).map_err(|e| anyhow!("es_new_client failed: {e:?}"))?;
    client
        .subscribe(&[ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_OPEN])
        .map_err(|e| anyhow!("es_subscribe failed: {e:?}"))?;

    Ok(EsfGuard { _client: client })
}

fn handle_message(
    msg: &Message,
    config: &CollectorConfig,
    state: &Arc<Mutex<SharedState>>,
    tx: &SyncSender<Msg>,
) {
    match msg.event() {
        Some(EsEvent::NotifyExec(exec)) => {
            if let Some(ev) = build_exec_event(&exec, config, state) {
                let _ = tx.try_send(Msg::Event(Box::new(ev)));
            }
        }
        Some(EsEvent::NotifyOpen(open)) => {
            if let Some(ev) = build_open_event(msg, &open, config, state) {
                let _ = tx.try_send(Msg::Event(Box::new(ev)));
            }
        }
        _ => {}
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

    // Classify FIRST — the vast majority of opens aren't credentials, and we
    // want to drop them before taking the lock or touching libproc.
    let class = credentials::classify(&path);
    if class == CredentialClass::None {
        return None;
    }

    let pid = msg.process().audit_token().pid();

    let record = {
        let mut st = state.lock().ok()?;
        macos_impl::resolve_enrollment(pid, &mut st)?
    };
    let is_agent_root = record.agent_root.pid == pid;

    // Suppress the agent reading its OWN config dotenv at startup; a descendant
    // reading the same file is real exfil and still emits.
    if is_agent_root && credentials::is_agent_config_dotenv(&path) {
        return None;
    }

    let snap = procinfo::snapshot(pid);
    let chain = procinfo::parent_chain(pid, 16);
    let process =
        macos_impl::process_from_snapshot(&snap, Some(record.agent_root.pid), chain);
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
            // ESF open carries the requested fflag; deriving RO/RW from it is a
            // refinement. v0.x reports Open (the credential class is the signal).
            access_type: AccessType::Open,
            credential_class: class,
            bytes_read: None,
        }),
    })
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
