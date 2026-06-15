//! Windows service mode for ATEN.
//!
//! Three entry points:
//! - `run_service_dispatcher()`: invoked by `aten service` (which is
//!   what the SCM launches once the service is installed). Hands control
//!   to Windows' service-control dispatcher, which then calls
//!   `ffi_service_main` once per service start.
//! - `install_service()`: invoked by `aten install`. Registers the
//!   service with the SCM, sets it to auto-start, drops a default
//!   config.toml in `%ProgramData%\aten\` if none exists, and starts
//!   the service.
//! - `uninstall_service()`: invoked by `aten uninstall`. Stops the
//!   service if running, then deletes it from the SCM. Leaves the
//!   config / events.jsonl behind on disk so the user can inspect them.
//!
//! The service runs as `LocalSystem` (the default for SCM-installed
//! services). That gives admin rights for ETW + cross-process PEB reads
//! without prompting; the cost is that events get tagged
//! `user: SYSTEM` rather than the user whose Claude/Codex session
//! triggered them. Hardened mode (dedicated service account with just
//! the privileges we need) is a follow-up.
//!
//! Service-mode logging: `stderr` in service context has nowhere to go
//! (SCM doesn't attach a console). `slog!()` writes timestamped lines to
//! `%ProgramData%\aten\service.log` instead. eprintln! calls from
//! deep collector code are still lost, but the start/stop/error path
//! covered here is what the user inspects when diagnosing.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::config;

pub(crate) const SERVICE_NAME: &str = "atensvc";
const SERVICE_DISPLAY: &str = "ATEN AI agent telemetry";
const SERVICE_DESCRIPTION: &str =
    "Detects credential reads and outbound connections by AI agent processes \
     (Claude Code, Codex) via ETW kernel providers. Logs to \
     %ProgramData%\\aten\\events.jsonl.";

/// The ETW instrumentation manifest, embedded so `install` can write a fresh
/// copy to %ProgramData% and register it without shipping the source file. Its
/// resourceFileName/messageFileName point at
/// `%ProgramData%\aten\aten_events.dll` — exactly where install copies
/// the compiled resource DLL.
const EVENT_MANIFEST: &str =
    include_str!("../../aten-collector-windows/eventlog/aten.man");

/// Filenames inside `%ProgramData%\aten`.
const MANIFEST_FILE: &str = "aten.man";
const EVENT_DLL_FILE: &str = "aten_events.dll";
/// ETW provider name (matches `<provider name=…>` in aten.man). Used to
/// detect an existing registration on the upgrade path.
const PROVIDER_NAME: &str = "ATEN";

// ===== Service-mode logging ===================================================

static SERVICE_LOG: OnceLock<Mutex<std::fs::File>> = OnceLock::new();

fn init_service_log() -> Result<()> {
    let dir = config::windows_program_data_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join("service.log");
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    let _ = SERVICE_LOG.set(Mutex::new(file));
    Ok(())
}

/// Write a timestamped line to the service log. Best-effort — if the log
/// hasn't been opened (or open failed), the call is a no-op. The service
/// can't usefully report this kind of error back to anyone, so dropping
/// is the right choice.
pub(crate) fn slog(line: &str) {
    if let Some(m) = SERVICE_LOG.get() {
        if let Ok(mut f) = m.lock() {
            let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            let _ = writeln!(f, "[{ts}] {line}");
            let _ = f.flush();
        }
    }
}

// ===== Service entry point ====================================================

/// Hand control to the Windows service-control dispatcher. Blocks until
/// SCM calls our service main and that returns. Called by
/// `aten service` when launched by SCM after `sc start atensvc`
/// (or as part of `aten install`).
pub fn run_service_dispatcher() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| anyhow!("service_dispatcher::start failed: {e}"))?;
    Ok(())
}

windows_service::define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    // Log file is our only diagnostic channel from inside the service —
    // open it first so any later error has somewhere to land.
    let _ = init_service_log();
    slog("service_main entry");
    if let Err(e) = service_main_impl() {
        slog(&format!("service_main_impl error: {e:#}"));
    }
    slog("service_main exit");
}

fn service_main_impl() -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_handler = stop.clone();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                slog("received stop/shutdown from SCM");
                stop_for_handler.store(true, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .map_err(|e| anyhow!("service_control_handler::register failed: {e}"))?;

    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .map_err(|e| anyhow!("set_service_status(Running) failed: {e}"))?;

    // Build inputs from the config file only — no CLI overrides when
    // running as a service. If the config has no transcript sources, the
    // engine still emits kernel events; they just won't carry session_id
    // / attributed_tool_call_id.
    let mut inputs = crate::resolve_daemon_inputs(
        None,
        Vec::new(),
        Vec::new(),
        None,
        None,
        None, // sink: service mode reads output.sink from the config file
        &["claude.exe", "cursor.exe", "codex.exe"],
    )?;
    // Service mode defaults to writing the events JSONL to ProgramData
    // when the config doesn't specify a path. CLI mode kept stdout as the
    // default since there's a human watching.
    if inputs.out_path.is_none() {
        inputs.out_path = Some(config::default_output_path());
    }
    slog(&format!(
        "service inputs: agents={:?}, transcript_paths={:?}, out={:?}",
        inputs.agents, inputs.transcript_paths, inputs.out_path,
    ));

    let result = crate::run_daemon_loop_windows(inputs, stop);
    if let Err(ref e) = result {
        slog(&format!("daemon loop returned error: {e:#}"));
    } else {
        slog("daemon loop returned cleanly");
    }

    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: if result.is_ok() {
            ServiceExitCode::Win32(0)
        } else {
            ServiceExitCode::Win32(1)
        },
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    });

    result
}

// ===== Install / uninstall ====================================================

/// Run `wevtutil` with `args`, suppressing its console output (we narrate via
/// our own `[aten …]` lines). `Some(true)` = exit 0, `Some(false)` = ran
/// but failed, `None` = couldn't spawn (wevtutil missing).
fn wevtutil(args: &[&std::ffi::OsStr]) -> Option<bool> {
    std::process::Command::new("wevtutil")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()
        .map(|s| s.success())
}

/// True if the ATEN publisher is already registered (`wevtutil gp` succeeds
/// only for an installed publisher) — i.e. this install is an upgrade.
fn publisher_registered() -> bool {
    matches!(
        wevtutil(&[
            std::ffi::OsStr::new("gp"),
            std::ffi::OsStr::new(PROVIDER_NAME),
        ]),
        Some(true)
    )
}

/// Register (or re-register) the ATEN Event Log channel.
///
/// Upgrade path is the tricky part: once the channel is registered, the
/// Windows Event Log service maps the resource DLL and keeps a handle on it, so
/// overwriting the canonical `aten_events.dll` in place fails with a sharing
/// violation. We therefore (1) `wevtutil um` any existing registration to drop
/// the publisher, then (2) try to stage the new DLL at the canonical name and,
/// if that's still locked, fall back to a fresh versioned filename and register
/// *that* — sidestepping the lock without force-restarting the EventLog service
/// (which would cycle its dependents). Stale DLLs are pruned best-effort.
///
/// Best-effort throughout: any failure is logged and non-fatal so the service
/// still installs and the daemon can fall back to the JSONL sink.
fn register_event_manifest(dir: &std::path::Path) -> Result<()> {
    let man_path = dir.join(MANIFEST_FILE);
    std::fs::write(&man_path, EVENT_MANIFEST)
        .with_context(|| format!("write {}", man_path.display()))?;

    let Some(dll_src) = locate_event_dll() else {
        eprintln!(
            "[aten install] {EVENT_DLL_FILE} not found next to the binary — \
             skipping Event Log registration. Build it with \
             crates/aten-collector-windows/eventlog/build-manifest.ps1 and \
             place it beside aten.exe, then re-run install. JSONL output is unaffected."
        );
        return Ok(());
    };

    // Upgrade: unregister the previous publisher first so the EventLog service
    // releases its handle on the old resource DLL.
    let upgrading = publisher_registered();
    if upgrading {
        let _ = wevtutil(&[std::ffi::OsStr::new("um"), man_path.as_os_str()]);
        eprintln!("[aten install] upgrade: unregistered previous Event Log publisher");
    }

    let Some(dll_dst) = stage_event_dll(dir, &dll_src) else {
        eprintln!(
            "[aten install] {EVENT_DLL_FILE} is in use and no writable fallback name was \
             available — left the existing Event Log channel registered. A reboot (or EventLog \
             service restart) frees the old DLL; JSONL output is unaffected meanwhile."
        );
        return Ok(());
    };

    let ok = wevtutil(&[
        std::ffi::OsStr::new("im"),
        man_path.as_os_str(),
        std::ffi::OsStr::new(&format!("/rf:{}", dll_dst.display())),
        std::ffi::OsStr::new(&format!("/mf:{}", dll_dst.display())),
    ]);
    match ok {
        Some(true) => {
            let verb = if upgrading { "updated" } else { "registered" };
            eprintln!(
                "[aten install] {verb} Event Log channel ATEN/Operational (resources: {})",
                dll_dst.file_name().unwrap_or_default().to_string_lossy()
            );
            if upgrading {
                eprintln!(
                    "[aten install] note: already-open Event Viewer windows cache the old \
                     schema — reopen Event Viewer to see the updated fields."
                );
            }
        }
        Some(false) => eprintln!(
            "[aten install] wevtutil im failed; Event Log channel not registered \
             (run as admin). JSONL output is unaffected."
        ),
        None => eprintln!("[aten install] could not run wevtutil; skipping channel"),
    }

    prune_stale_event_dlls(dir, &dll_dst);
    Ok(())
}

/// Copy the resource DLL into `dir`. Prefer the canonical name; if it's locked
/// (an active registration still maps the previous copy), stage under a fresh
/// `aten_events.<millis>.dll` and return that. `None` if neither works.
fn stage_event_dll(dir: &std::path::Path, src: &std::path::Path) -> Option<std::path::PathBuf> {
    let canonical = dir.join(EVENT_DLL_FILE);
    if std::fs::copy(src, &canonical).is_ok() {
        return Some(canonical);
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let versioned = dir.join(format!("aten_events.{stamp}.dll"));
    if std::fs::copy(src, &versioned).is_ok() {
        return Some(versioned);
    }
    None
}

/// Remove `aten_events*.dll` files in `dir` other than `keep`. Best-effort:
/// the currently-registered DLL (and any still mapped by the EventLog service)
/// is locked and silently skipped.
fn prune_stale_event_dlls(dir: &std::path::Path, keep: &std::path::Path) {
    let keep_name = keep.file_name().unwrap_or_default().to_os_string();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name == keep_name {
            continue;
        }
        let s = name.to_string_lossy();
        if s.starts_with("aten_events") && s.ends_with(".dll") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Best-effort unregister of the Event Log channel + prune of staged resource
/// DLLs. The manifest copy in ProgramData is what `wevtutil um` needs.
fn unregister_event_manifest(dir: &std::path::Path) {
    let man_path = dir.join(MANIFEST_FILE);
    if !man_path.exists() {
        return;
    }
    match wevtutil(&[std::ffi::OsStr::new("um"), man_path.as_os_str()]) {
        Some(true) => {
            eprintln!("[aten uninstall] removed Event Log channel ATEN/Operational")
        }
        Some(false) => eprintln!("[aten uninstall] wevtutil um failed (non-fatal)"),
        None => eprintln!("[aten uninstall] could not run wevtutil (non-fatal)"),
    }
    // After um the service releases the DLL handles; drop the staged DLLs.
    // (keep = a non-existent sentinel so all aten_events*.dll are pruned.)
    prune_stale_event_dlls(dir, &dir.join("__none__"));
}

/// Find the compiled resource DLL: next to the running binary first (deploy
/// layout), then the collector crate's `eventlog/` dir relative to the binary
/// (cargo `target/<profile>/` dev layout: ../../crates/.../eventlog).
fn locate_event_dll() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe_dir = exe.parent()?;
    let candidates = [
        exe_dir.join(EVENT_DLL_FILE),
        exe_dir.join(format!(
            "../../crates/aten-collector-windows/eventlog/{EVENT_DLL_FILE}"
        )),
    ];
    candidates.into_iter().find(|p| p.exists())
}

pub fn install_service() -> Result<()> {
    let mgr = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .with_context(|| "connect to Service Control Manager — needs admin")?;

    let exe = std::env::current_exe().context("locate own binary path")?;

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        // SCM invokes the binary with this argv-tail when launching the
        // service. Our main.rs dispatches `Service` -> service_dispatcher::start.
        launch_arguments: vec![OsString::from("service")],
        dependencies: Vec::new(),
        // None = LocalSystem. Hardened-mode (dedicated account with
        // specific privileges) is a follow-up backlog item.
        account_name: None,
        account_password: None,
    };

    // Idempotent: if the service already exists (an upgrade / re-run), open and
    // update it instead of erroring out. Need STOP + QUERY_STATUS too so we can
    // restart it at the end to pick up the new binary/config.
    let access = ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::QUERY_STATUS;
    let (service, upgrading) = match mgr.open_service(SERVICE_NAME, access) {
        Ok(svc) => {
            eprintln!("[aten install] service '{SERVICE_NAME}' already exists — upgrading");
            // Point the existing registration at the current binary/launch args
            // in case the install location changed.
            if let Err(e) = svc.change_config(&info) {
                eprintln!("[aten install] could not update service config (non-fatal): {e}");
            }
            (svc, true)
        }
        Err(_) => {
            let svc = mgr
                .create_service(&info, access)
                .with_context(|| "create_service")?;
            eprintln!("[aten install] registered service '{SERVICE_NAME}'");
            (svc, false)
        }
    };
    service
        .set_description(SERVICE_DESCRIPTION)
        .ok(); // non-fatal if it fails

    // Drop a default config if none exists yet. Discovers the *current
    // user's* Claude/Codex transcript dirs by looking at USERPROFILE,
    // since the service runs as LocalSystem and wouldn't otherwise know
    // which user to watch.
    let dir = config::windows_program_data_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let cfg_path = dir.join("config.toml");
    if !cfg_path.exists() {
        let user_profile =
            std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Default".to_string());
        let claude_dir = format!("{user_profile}\\.claude\\projects");
        let codex_dir = format!("{user_profile}\\.codex\\sessions");
        let events_path = dir.join("events.jsonl");
        let body = format!(
            "# ATEN service config. Edit and restart the service:\n\
             #   sc stop {SERVICE_NAME} && sc start {SERVICE_NAME}\n\
             \n\
             [daemon]\n\
             agents = [\"claude.exe\", \"cursor.exe\", \"codex.exe\"]\n\
             \n\
             [transcripts]\n\
             # Recursively scanned for *.jsonl. Dialect (Claude / Codex) auto-detected per file.\n\
             watch_dirs = [\n\
             {INDENT}\"{claude}\",\n\
             {INDENT}\"{codex}\",\n\
             ]\n\
             \n\
             [output]\n\
             # sink: jsonl | eventlog | both. 'both' writes the ATEN/Operational\n\
             # Event Log channel AND a JSONL backup file.\n\
             sink = \"both\"\n\
             file_path = \"{out}\"\n",
            INDENT = "    ",
            claude = claude_dir.replace('\\', "\\\\"),
            codex = codex_dir.replace('\\', "\\\\"),
            out = events_path.display().to_string().replace('\\', "\\\\"),
        );
        std::fs::write(&cfg_path, body).with_context(|| format!("write {}", cfg_path.display()))?;
        eprintln!("[aten install] wrote default config to {}", cfg_path.display());
    } else {
        eprintln!("[aten install] preserved existing config {}", cfg_path.display());
    }

    // Register the Event Log channel (best-effort; non-fatal if the resource
    // DLL hasn't been built). Done before starting the service so the channel
    // exists when the daemon's eventlog sink registers its provider.
    if let Err(e) = register_event_manifest(&dir) {
        eprintln!("[aten install] Event Log registration error (non-fatal): {e:#}");
    }

    // On upgrade the old binary may still be running — stop it first so the
    // restart below launches the new one. (Fresh install: it's already stopped.)
    if upgrading {
        if let Ok(status) = service.query_status() {
            if status.current_state != ServiceState::Stopped {
                let _ = service.stop();
                for _ in 0..20 {
                    std::thread::sleep(Duration::from_millis(250));
                    if matches!(
                        service.query_status().map(|s| s.current_state),
                        Ok(ServiceState::Stopped)
                    ) {
                        break;
                    }
                }
            }
        }
    }

    // Start it now. If start fails, the service is still registered and
    // can be started later with `sc start atensvc`.
    match service.start::<&str>(&[]) {
        Ok(_) => eprintln!("[aten install] service '{SERVICE_NAME}' started"),
        Err(e) => eprintln!("[aten install] service registered but start failed: {e}"),
    }
    Ok(())
}

pub fn uninstall_service() -> Result<()> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .with_context(|| "connect to Service Control Manager — needs admin")?;

    let service = mgr
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .with_context(|| format!("open service '{SERVICE_NAME}'"))?;

    // Best-effort stop. If it's not running, that's fine.
    let status = service
        .query_status()
        .with_context(|| "query service status")?;
    if status.current_state != ServiceState::Stopped {
        eprintln!("[aten uninstall] stopping service…");
        let _ = service.stop();
        // Brief wait so the SCM transitions through StopPending; if it
        // stalls we delete anyway and Windows will tear down the process.
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(250));
            if let Ok(s) = service.query_status() {
                if s.current_state == ServiceState::Stopped {
                    break;
                }
            }
        }
    }

    service.delete().with_context(|| "delete service")?;
    eprintln!("[aten uninstall] service '{SERVICE_NAME}' removed");

    // Best-effort removal of the Event Log channel.
    unregister_event_manifest(&config::windows_program_data_dir());
    eprintln!(
        "[aten uninstall] left in place: {} (config + events log)",
        config::windows_program_data_dir().display()
    );
    Ok(())
}
