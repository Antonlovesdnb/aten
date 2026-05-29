//! Windows service mode for fishbowl-v2.
//!
//! Three entry points:
//! - `run_service_dispatcher()`: invoked by `fishbowl service` (which is
//!   what the SCM launches once the service is installed). Hands control
//!   to Windows' service-control dispatcher, which then calls
//!   `ffi_service_main` once per service start.
//! - `install_service()`: invoked by `fishbowl install`. Registers the
//!   service with the SCM, sets it to auto-start, drops a default
//!   config.toml in `%ProgramData%\fishbowl\` if none exists, and starts
//!   the service.
//! - `uninstall_service()`: invoked by `fishbowl uninstall`. Stops the
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
//! `%ProgramData%\fishbowl\service.log` instead. eprintln! calls from
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

pub(crate) const SERVICE_NAME: &str = "fishbowlsvc";
const SERVICE_DISPLAY: &str = "fishbowl-v2 AI agent telemetry";
const SERVICE_DESCRIPTION: &str =
    "Detects credential reads and outbound connections by AI agent processes \
     (Claude Code, Codex) via ETW kernel providers. Logs to \
     %ProgramData%\\fishbowl\\events.jsonl.";

/// The ETW instrumentation manifest, embedded so `install` can write a fresh
/// copy to %ProgramData% and register it without shipping the source file. Its
/// resourceFileName/messageFileName point at
/// `%ProgramData%\fishbowl\fishbowl_events.dll` — exactly where install copies
/// the compiled resource DLL.
const EVENT_MANIFEST: &str =
    include_str!("../../fishbowl-collector-windows/eventlog/fishbowl.man");

/// Filenames inside `%ProgramData%\fishbowl`.
const MANIFEST_FILE: &str = "fishbowl.man";
const EVENT_DLL_FILE: &str = "fishbowl_events.dll";

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
/// `fishbowl service` when launched by SCM after `sc start fishbowlsvc`
/// (or as part of `fishbowl install`).
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

/// Register the Fishbowl Event Log channel: write the manifest to ProgramData,
/// copy the compiled resource DLL next to it, and `wevtutil im` it. Best-effort
/// — a failure (e.g. the DLL wasn't built yet) is logged and non-fatal, so the
/// service still installs and the daemon can fall back to the JSONL sink.
///
/// The DLL is located next to the installed binary (deploy convention) or, for
/// dev runs from a cargo target dir, in the collector crate's `eventlog/` dir.
fn register_event_manifest(dir: &std::path::Path) -> Result<()> {
    let man_path = dir.join(MANIFEST_FILE);
    let dll_dst = dir.join(EVENT_DLL_FILE);
    std::fs::write(&man_path, EVENT_MANIFEST)
        .with_context(|| format!("write {}", man_path.display()))?;

    let Some(dll_src) = locate_event_dll() else {
        eprintln!(
            "[fishbowl install] {EVENT_DLL_FILE} not found next to the binary — \
             skipping Event Log registration. Build it with \
             crates/fishbowl-collector-windows/eventlog/build-manifest.ps1 and \
             place it beside fishbowl.exe, then re-run install. JSONL output is unaffected."
        );
        return Ok(());
    };
    std::fs::copy(&dll_src, &dll_dst)
        .with_context(|| format!("copy {} -> {}", dll_src.display(), dll_dst.display()))?;

    let status = std::process::Command::new("wevtutil")
        .arg("im")
        .arg(&man_path)
        .arg(format!("/rf:{}", dll_dst.display()))
        .arg(format!("/mf:{}", dll_dst.display()))
        .status();
    match status {
        Ok(s) if s.success() => {
            eprintln!("[fishbowl install] registered Event Log channel Fishbowl/Operational");
        }
        Ok(s) => eprintln!(
            "[fishbowl install] wevtutil im exited with {s}; Event Log channel not registered \
             (run as admin). JSONL output is unaffected."
        ),
        Err(e) => eprintln!("[fishbowl install] could not run wevtutil ({e}); skipping channel"),
    }
    Ok(())
}

/// Best-effort unregister of the Event Log channel. The manifest copy in
/// ProgramData is what `wevtutil um` needs; leave it on disk afterward.
fn unregister_event_manifest(dir: &std::path::Path) {
    let man_path = dir.join(MANIFEST_FILE);
    if !man_path.exists() {
        return;
    }
    match std::process::Command::new("wevtutil")
        .arg("um")
        .arg(&man_path)
        .status()
    {
        Ok(s) if s.success() => {
            eprintln!("[fishbowl uninstall] removed Event Log channel Fishbowl/Operational")
        }
        Ok(s) => eprintln!("[fishbowl uninstall] wevtutil um exited with {s} (non-fatal)"),
        Err(e) => eprintln!("[fishbowl uninstall] could not run wevtutil ({e}) (non-fatal)"),
    }
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
            "../../crates/fishbowl-collector-windows/eventlog/{EVENT_DLL_FILE}"
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

    let service = mgr
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .with_context(|| "create_service")?;
    service
        .set_description(SERVICE_DESCRIPTION)
        .ok(); // non-fatal if it fails
    eprintln!("[fishbowl install] registered service '{SERVICE_NAME}'");

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
            "# fishbowl-v2 service config. Edit and restart the service:\n\
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
             # sink: jsonl | eventlog | both. 'both' writes the Fishbowl/Operational\n\
             # Event Log channel AND a JSONL backup file.\n\
             sink = \"both\"\n\
             file_path = \"{out}\"\n",
            INDENT = "    ",
            claude = claude_dir.replace('\\', "\\\\"),
            codex = codex_dir.replace('\\', "\\\\"),
            out = events_path.display().to_string().replace('\\', "\\\\"),
        );
        std::fs::write(&cfg_path, body).with_context(|| format!("write {}", cfg_path.display()))?;
        eprintln!("[fishbowl install] wrote default config to {}", cfg_path.display());
    } else {
        eprintln!("[fishbowl install] preserved existing config {}", cfg_path.display());
    }

    // Register the Event Log channel (best-effort; non-fatal if the resource
    // DLL hasn't been built). Done before starting the service so the channel
    // exists when the daemon's eventlog sink registers its provider.
    if let Err(e) = register_event_manifest(&dir) {
        eprintln!("[fishbowl install] Event Log registration error (non-fatal): {e:#}");
    }

    // Start it now. If start fails, the service is still registered and
    // can be started later with `sc start fishbowlsvc`.
    match service.start::<&str>(&[]) {
        Ok(_) => eprintln!("[fishbowl install] service '{SERVICE_NAME}' started"),
        Err(e) => eprintln!("[fishbowl install] service registered but start failed: {e}"),
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
        eprintln!("[fishbowl uninstall] stopping service…");
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
    eprintln!("[fishbowl uninstall] service '{SERVICE_NAME}' removed");

    // Best-effort removal of the Event Log channel.
    unregister_event_manifest(&config::windows_program_data_dir());
    eprintln!(
        "[fishbowl uninstall] left in place: {} (config + events log)",
        config::windows_program_data_dir().display()
    );
    Ok(())
}
