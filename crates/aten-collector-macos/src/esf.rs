//! EndpointSecurity producer: `NOTIFY_EXEC` → `ProcessExec`,
//! `NOTIFY_OPEN` → `CredentialAccess` / `FileWrite`, and
//! `NOTIFY_UIPC_CONNECT` → `LocalIpcAccess`.
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
//! The ESF API surface here is compile-checked against `endpoint-sec` 0.4.x on
//! macOS; runtime use still requires root plus the EndpointSecurity entitlement.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};

use aten_collector_linux::credentials::{self};
use aten_collector_linux::enroll::ProcessKey;
use aten_collector_linux::filewrite;
use aten_schema::{
    AccessType, CredentialAccessPayload, CredentialClass, Event, EventKind, FileWriteClass,
    FileWritePayload, LocalIpcAccessPayload, Platform, ProcessExecPayload, ProcessExitPayload,
    Source, SCHEMA_VERSION,
};

use endpoint_sec::sys::es_event_type_t;
use endpoint_sec::{Client, Event as EsEvent, Message};

use crate::macos_impl::{self, CollectorConfig, Msg, SharedState};
use crate::procinfo;

/// Keeps the ES client alive. Dropping it unsubscribes and disconnects.
pub struct EsfGuard {
    _client: Client<'static>,
}

/// Create the ES client, subscribe to the NOTIFY events we need, and return a
/// guard that keeps it running. Returns `Err` (typically NOT_PERMITTED — missing
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
            es_event_type_t::ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT,
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
        Some(EsEvent::NotifyUipcConnect(uipc)) => {
            if let Some(ev) = build_uipc_connect_event(msg, &uipc, config, state) {
                send_event(tx, ev, dropped);
            }
        }
        Some(EsEvent::NotifyExit(exit)) => {
            if let Some(ev) = build_exit_event(msg, &exit, config, state) {
                send_event(tx, ev, dropped);
            }
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
    let supply_chain_activity =
        aten_collector_linux::supply_chain::classify_process(&name, &cmdline, &args);
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
            supply_chain_activity,
        }),
    })
}

/// `NOTIFY_OPEN` → `FileWrite` for sensitive write-intent paths, otherwise
/// `CredentialAccess` for credential paths. Only enrolled agents/descendants
/// emit. Mirrors `linux_impl::handle_credacc_event`, including the
/// agent-config-dotenv self-read suppression for credential reads.
fn build_open_event(
    msg: &Message,
    open: &endpoint_sec::EventOpen,
    config: &CollectorConfig,
    state: &Arc<Mutex<SharedState>>,
) -> Option<Event> {
    let path = osstr_to_string(open.file().path());
    let write_intent = open_flags_write_intent(open.fflag());

    // Classify FIRST — the vast majority of opens aren't credentials, and we
    // want to drop them before taking the lock or touching libproc.
    let action = classify_open_path(&path, write_intent);
    let OpenPathAction::Credential(class) = action else {
        if let OpenPathAction::FileWrite(write_class) = action {
            return build_file_write_event(msg, &path, write_class, config, state);
        }
        return None;
    };

    build_credential_access_event(msg, &path, write_intent, class, config, state)
}

fn build_credential_access_event(
    msg: &Message,
    path: &str,
    write_intent: bool,
    class: CredentialClass,
    config: &CollectorConfig,
    state: &Arc<Mutex<SharedState>>,
) -> Option<Event> {
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
    if is_agent_root && credentials::is_agent_config_dotenv(path) {
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
        agent_id: if is_agent_root {
            "agent-root".to_string()
        } else {
            "agent-descendant".to_string()
        },
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
            file_path: path.to_string(),
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

fn build_file_write_event(
    msg: &Message,
    path: &str,
    write_class: FileWriteClass,
    config: &CollectorConfig,
    state: &Arc<Mutex<SharedState>>,
) -> Option<Event> {
    let pid = msg.process().audit_token().pid();

    let record = {
        let mut st = state.lock().ok()?;
        macos_impl::resolve_enrollment(pid, &mut st)?
    };
    let cached = macos_impl::process_enrichment(pid, state);
    let is_agent_root = record.agent_root.pid == pid;
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
        agent_id: if is_agent_root {
            "agent-root".to_string()
        } else {
            "agent-descendant".to_string()
        },
        session_id: None,
        user_id: if user.is_empty() { None } else { Some(user) },
        source: Source {
            collector: "macos_esf".to_string(),
            probe: "EndpointSecurity/ES_EVENT_TYPE_NOTIFY_OPEN".to_string(),
            host_pid: Some(pid),
        },
        kind: EventKind::FileWrite(FileWritePayload {
            process,
            attribution: macos_impl::descent_attribution(!is_agent_root),
            file_path: path.to_string(),
            bytes_written: None,
            write_class,
        }),
    })
}

fn build_uipc_connect_event(
    msg: &Message,
    uipc: &endpoint_sec::EventUipcConnect,
    config: &CollectorConfig,
    state: &Arc<Mutex<SharedState>>,
) -> Option<Event> {
    let path = osstr_to_string(uipc.file().path());
    let ipc_class = aten_collector_linux::ipc::classify(&path)?;
    build_local_ipc_event(
        msg,
        &path,
        ipc_class,
        "EndpointSecurity/ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT",
        config,
        state,
    )
}

fn build_local_ipc_event(
    msg: &Message,
    path: &str,
    ipc_class: aten_schema::LocalIpcClass,
    probe: &str,
    config: &CollectorConfig,
    state: &Arc<Mutex<SharedState>>,
) -> Option<Event> {
    let pid = msg.process().audit_token().pid();

    let record = {
        let mut st = state.lock().ok()?;
        macos_impl::resolve_enrollment(pid, &mut st)?
    };
    let cached = macos_impl::process_enrichment(pid, state);
    let is_agent_root = record.agent_root.pid == pid;
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
        agent_id: if is_agent_root {
            "agent-root".to_string()
        } else {
            "agent-descendant".to_string()
        },
        session_id: None,
        user_id: if user.is_empty() { None } else { Some(user) },
        source: Source {
            collector: "macos_esf".to_string(),
            probe: probe.to_string(),
            host_pid: Some(pid),
        },
        kind: EventKind::LocalIpcAccess(LocalIpcAccessPayload {
            process,
            attribution: macos_impl::descent_attribution(!is_agent_root),
            ipc_path: path.to_string(),
            ipc_class,
        }),
    })
}

fn build_exit_event(
    msg: &Message,
    exit: &endpoint_sec::EventExit,
    config: &CollectorConfig,
    state: &Arc<Mutex<SharedState>>,
) -> Option<Event> {
    let es_proc = msg.process();
    let pid = es_proc.audit_token().pid();
    let record = {
        let mut st = state.lock().ok()?;
        macos_impl::resolve_enrollment(pid, &mut st)?
    };
    let is_agent_root = record.agent_root.pid == pid;
    let parent_chain = if es_proc.ppid() > 0 {
        procinfo::parent_chain(pid, 16)
    } else {
        Vec::new()
    };
    let process = process_from_es_process(&es_proc, Some(record.agent_root.pid), parent_chain);
    let user = process.user.clone();

    Some(Event {
        schema_version: SCHEMA_VERSION.to_string(),
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: macos_impl::now_rfc3339(),
        monotonic_ns: macos_impl::monotonic_ns(),
        platform: Platform::Macos,
        host_id: config.host_id.clone(),
        agent_id: if is_agent_root {
            "agent-root".to_string()
        } else {
            "agent-descendant".to_string()
        },
        session_id: None,
        user_id: if user.is_empty() { None } else { Some(user) },
        source: Source {
            collector: "macos_esf".to_string(),
            probe: "EndpointSecurity/ES_EVENT_TYPE_NOTIFY_EXIT".to_string(),
            host_pid: Some(pid),
        },
        kind: EventKind::ProcessExit(ProcessExitPayload {
            process,
            attribution: macos_impl::descent_attribution(!is_agent_root),
            exit_code: exit.stat(),
        }),
    })
}

fn process_from_es_process(
    process: &endpoint_sec::Process<'_>,
    agent_root_pid: Option<i32>,
    parent_chain: Vec<aten_schema::ParentChainEntry>,
) -> aten_schema::Process {
    let token = process.audit_token();
    let pid = token.pid();
    let euid = token.euid();
    let exe_path = osstr_to_string(process.executable().path());
    let name = procinfo::basename(&exe_path);
    let start_secs = systemtime_to_epoch_secs(process.start_time());
    let user = procinfo::username_for_uid(euid).unwrap_or_else(|| euid.to_string());

    aten_schema::Process {
        pid,
        ppid: process.ppid(),
        start_time: start_secs.to_string(),
        name,
        path: exe_path,
        cmdline: String::new(),
        cwd: String::new(),
        user,
        integrity_level: None,
        parent_chain,
        agent_root_pid,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenPathAction {
    FileWrite(FileWriteClass),
    Credential(CredentialClass),
    Drop,
}

fn classify_open_path(path: &str, write_intent: bool) -> OpenPathAction {
    if write_intent {
        if let Some(write_class) = filewrite::classify(path) {
            return OpenPathAction::FileWrite(write_class);
        }
    }
    let credential_class = credentials::classify_for_access(path, write_intent);
    if credential_class == CredentialClass::None {
        OpenPathAction::Drop
    } else {
        OpenPathAction::Credential(credential_class)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use aten_schema::{CredentialClass, FileWriteClass};

    #[test]
    fn open_path_classifier_prioritizes_sensitive_writes() {
        assert_eq!(
            classify_open_path("/Users/anton/.zshrc", true),
            OpenPathAction::FileWrite(FileWriteClass::ShellProfile)
        );
        assert_eq!(
            classify_open_path("/Users/anton/.aws/credentials", true),
            OpenPathAction::Credential(CredentialClass::AwsCredentials)
        );
        assert_eq!(
            classify_open_path("/Users/anton/project/src/main.rs", true),
            OpenPathAction::Drop
        );
    }

    #[test]
    fn open_flags_detect_write_intent() {
        assert!(open_flags_write_intent(libc::O_WRONLY));
        assert!(open_flags_write_intent(libc::O_RDWR));
        assert!(open_flags_write_intent(libc::O_CREAT));
        assert!(!open_flags_write_intent(libc::O_RDONLY));
    }
}
