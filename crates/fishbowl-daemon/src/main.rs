//! fishbowl-v2 daemon entrypoint.
//!
//! Today this is a thin CLI that exercises the transcript reader so we have
//! end-to-end JSONL output to validate the schema against. It will grow to host
//! the always-on Linux eBPF and Windows ETW collectors that consult the
//! identifier index produced by the transcript reader to populate kernel-event
//! attribution.
//!
//! Subcommands:
//! - `fishbowl version` — prints schema and crate version
//! - `fishbowl transcript <path>` — parses a Claude Code transcript JSONL,
//!   writes events JSONL + identifier index JSON

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use fishbowl_schema::Platform;

mod config;
#[cfg(target_os = "windows")]
mod service;

/// Merged inputs for a daemon run, after layering CLI flags over the
/// config file. Returned from `resolve_daemon_inputs` so the two
/// platform-specific `run_daemon` impls share parsing logic.
pub(crate) struct DaemonInputs {
    /// Transcript files + directories the engine will read.
    pub transcript_paths: Vec<PathBuf>,
    /// Image basenames (Windows) or `comm` strings (Linux) to enroll.
    pub agents: Vec<String>,
    /// Where to write the event JSONL. `None` = stdout.
    pub out_path: Option<PathBuf>,
}

/// Merge config file + CLI flags into a single set of daemon inputs.
/// Precedence: CLI flag > config file > built-in default.
pub(crate) fn resolve_daemon_inputs(
    config_path: Option<PathBuf>,
    cli_transcripts: Vec<PathBuf>,
    cli_watch_dirs: Vec<PathBuf>,
    cli_agents: Option<Vec<String>>,
    cli_out: Option<PathBuf>,
    default_agents: &[&str],
) -> Result<DaemonInputs> {
    let cfg_path = config_path.unwrap_or_else(config::default_config_path);
    let cfg = config::ConfigFile::load_or_default(&cfg_path)
        .with_context(|| format!("loading config {}", cfg_path.display()))?;

    let mut transcript_paths: Vec<PathBuf> = Vec::new();
    transcript_paths.extend(cfg.transcripts.files);
    transcript_paths.extend(cfg.transcripts.watch_dirs);
    transcript_paths.extend(cli_transcripts);
    transcript_paths.extend(cli_watch_dirs);

    let agents = cli_agents
        .or_else(|| {
            if cfg.daemon.agents.is_empty() {
                None
            } else {
                Some(cfg.daemon.agents)
            }
        })
        .unwrap_or_else(|| default_agents.iter().map(|s| s.to_string()).collect());

    let out_path = cli_out.or(cfg.output.file_path);

    Ok(DaemonInputs {
        transcript_paths,
        agents,
        out_path,
    })
}

#[derive(Parser)]
#[command(name = "fishbowl", version, about = "fishbowl-v2 daemon CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print crate + schema versions.
    Version,
    /// Read a Claude Code transcript JSONL and emit schema events + identifier index.
    Transcript {
        /// Path to a Claude Code session transcript (e.g.
        /// `~/.claude/projects/<encoded-cwd>/<session-uuid>.jsonl`).
        transcript: PathBuf,
        /// Output path for emitted events JSONL. Defaults to
        /// `<transcript-stem>.events.jsonl` beside the input.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Output path for the identifier-origin index JSON. Defaults to
        /// `<transcript-stem>.idx.json` beside the input.
        #[arg(long)]
        idx: Option<PathBuf>,
    },
    /// Run the Linux eBPF process-exec collector. Requires root or CAP_BPF+CAP_PERFMON.
    #[cfg(target_os = "linux")]
    CollectLinux {
        /// Process `comm` names to enroll as agent roots. Comma-separated.
        /// Default: claude,cursor,codex.
        #[arg(long, value_delimiter = ',')]
        agents: Option<Vec<String>>,
        /// Stop after this many seconds. Default: run until SIGINT.
        #[arg(long)]
        duration_secs: Option<u64>,
        /// Append emitted events as JSONL to this file. Default: stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Register the daemon as a Windows service (`fishbowlsvc`). Drops a
    /// default config.toml in `%ProgramData%\fishbowl\` if none exists,
    /// pointing at the current user's Claude/Codex transcript dirs.
    /// Service runs as LocalSystem and auto-starts on boot. Needs admin.
    #[cfg(target_os = "windows")]
    Install,
    /// Stop and unregister the `fishbowlsvc` service. Leaves config and
    /// the events JSONL on disk so you can inspect them after the
    /// service is gone. Needs admin.
    #[cfg(target_os = "windows")]
    Uninstall,
    /// Service entry point. Invoked by SCM (not by humans typing).
    /// `fishbowl install` registers this subcommand as the service's
    /// launch argument; SCM then calls `fishbowl service` when it starts
    /// the service. Hands control to the Windows service-control
    /// dispatcher which blocks until the service stops.
    #[cfg(target_os = "windows")]
    Service,
    /// Run the Windows ETW collector. Requires admin. Hooks
    /// Microsoft-Windows-Kernel-Process (ProcessStart),
    /// Microsoft-Windows-Kernel-File (Create), and
    /// Microsoft-Windows-Kernel-Network (TcpIp/Connect V4 + V6); emits
    /// schema `ProcessExec`, `CredentialAccess`, and `NetworkEgress`
    /// events with cmdline + parent_chain + user enrichment.
    #[cfg(target_os = "windows")]
    CollectWindows {
        /// Image-name basenames to enroll as agent roots (e.g. claude.exe).
        #[arg(long, value_delimiter = ',')]
        agents: Option<Vec<String>>,
        #[arg(long)]
        duration_secs: Option<u64>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Run the macOS collector. Needs root + the EndpointSecurity client
    /// entitlement (see macos/devsetup.md). Subscribes to ESF NOTIFY_EXEC /
    /// NOTIFY_OPEN for `ProcessExec` / `CredentialAccess`, and listens on a
    /// Unix-domain socket for `NetworkEgress` flow records from the
    /// NEFilterDataProvider system extension.
    #[cfg(target_os = "macos")]
    CollectMacos {
        /// Process basenames to enroll as agent roots (e.g. claude,codex).
        #[arg(long, value_delimiter = ',')]
        agents: Option<Vec<String>>,
        #[arg(long)]
        duration_secs: Option<u64>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Run the full daemon: kernel collector + transcript reader + attribution.
    /// On Linux uses eBPF (needs root or CAP_BPF+CAP_PERFMON); on Windows uses
    /// ETW (needs admin); on macOS uses EndpointSecurity + a NetworkExtension
    /// system extension (needs root + entitlements). Same subcommand on every
    /// platform; the build picks the right collector via `cfg(target_os = ...)`.
    ///
    /// Transcript sources are merged from three places (later overrides):
    /// the config file (`[transcripts] watch_dirs = [...]`, `files = [...]`),
    /// then any `--watch-dir` and `--transcript` flags on the command line.
    /// All of them are passed to the attribution engine as a single list.
    Daemon {
        /// TOML config path. Defaults to the platform install location
        /// (`%ProgramData%\fishbowl\config.toml` on Windows). Missing
        /// file is OK — treated as an empty config.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Add a transcript JSONL file to attribute against. Repeatable.
        /// Single-session pinning convenience; service mode uses watch
        /// directories instead.
        #[arg(long)]
        transcript: Vec<PathBuf>,
        /// Add a directory to scan recursively for `*.jsonl` transcripts.
        /// Repeatable. Use this to point at `~/.claude/projects` and
        /// `~/.codex/sessions` for ambient multi-session capture.
        #[arg(long)]
        watch_dir: Vec<PathBuf>,
        /// Process names to enroll as agent roots. Comma-separated.
        /// Overrides config file. On Linux matches `comm` (e.g.
        /// `claude,cursor,codex`); on Windows matches image basename
        /// (e.g. `claude.exe,cursor.exe,codex.exe`).
        #[arg(long, value_delimiter = ',')]
        agents: Option<Vec<String>>,
        /// Stop after this many seconds. Default: run until SIGINT / Ctrl-C.
        #[arg(long)]
        duration_secs: Option<u64>,
        /// Append emitted events as JSONL to this file. Overrides config
        /// file. Default if neither is set: stdout (CLI) or the platform
        /// default events.jsonl path (service mode).
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Version => {
            println!(
                "fishbowl {} (schema v{})",
                env!("CARGO_PKG_VERSION"),
                fishbowl_schema::SCHEMA_VERSION
            );
        }
        Command::Transcript {
            transcript,
            out,
            idx,
        } => run_transcript(transcript, out, idx)?,
        #[cfg(target_os = "linux")]
        Command::CollectLinux {
            agents,
            duration_secs,
            out,
        } => run_collect_linux(agents, duration_secs, out)?,
        Command::Daemon {
            config,
            transcript,
            watch_dir,
            agents,
            duration_secs,
            out,
        } => run_daemon(config, transcript, watch_dir, agents, duration_secs, out)?,
        #[cfg(target_os = "windows")]
        Command::Install => service::install_service()?,
        #[cfg(target_os = "windows")]
        Command::Uninstall => service::uninstall_service()?,
        #[cfg(target_os = "windows")]
        Command::Service => service::run_service_dispatcher()?,
        #[cfg(target_os = "windows")]
        Command::CollectWindows {
            agents,
            duration_secs,
            out,
        } => run_collect_windows(agents, duration_secs, out)?,
        #[cfg(target_os = "macos")]
        Command::CollectMacos {
            agents,
            duration_secs,
            out,
        } => run_collect_macos(agents, duration_secs, out)?,
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn run_daemon(
    config_path: Option<PathBuf>,
    transcripts: Vec<PathBuf>,
    watch_dirs: Vec<PathBuf>,
    agents: Option<Vec<String>>,
    duration_secs: Option<u64>,
    out: Option<PathBuf>,
) -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let inputs = resolve_daemon_inputs(
        config_path,
        transcripts,
        watch_dirs,
        agents,
        out,
        &["claude.exe", "cursor.exe", "codex.exe"],
    )?;

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc_set_handler(move || stop.store(true, Ordering::Relaxed));
    }
    if let Some(secs) = duration_secs {
        let stop = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            stop.store(true, Ordering::Relaxed);
        });
    }

    run_daemon_loop_windows(inputs, stop)
}

/// The Windows daemon loop, factored out so it can be driven from both the
/// CLI (`fishbowl daemon ...`) and the Windows service entry point
/// (where the stop signal comes from SCM events rather than Ctrl-C).
///
/// Sets up the attribution engine, opens the JSONL sink, and runs the
/// ETW collector's run_with_tick which blocks until `stop` is set.
#[cfg(target_os = "windows")]
pub(crate) fn run_daemon_loop_windows(
    inputs: DaemonInputs,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use fishbowl_attribution::{AttributionEngine, EngineConfig};

    let host_id = read_machine_guid_windows();
    let cfg = fishbowl_collector_windows::CollectorConfig {
        enrolled_agents: inputs.agents.clone(),
        host_id: host_id.clone(),
    };

    // Shared between the ETW callback thread (emit closure → `attribute`) and
    // the main thread (tick closure → `refresh`). Arc<Mutex<_>> rather than
    // RefCell because the Windows collector's emit closure must be
    // `Send + 'static` (ferrisetw runs callbacks on a thread it owns).
    let engine = Arc::new(Mutex::new(AttributionEngine::new(EngineConfig {
        cwd_for_pid: windows_cwd_for_pid,
        transcript_paths: inputs.transcript_paths.clone(),
        host_id: host_id.clone(),
        user_for_transcript: windows_user_for_transcript,
        state_path: Some(config::windows_program_data_dir().join("state.json")),
    })));
    // Initial refresh: load every transcript file on disk into SessionState
    // for attribution context. The returned Vec is empty because every
    // event's timestamp is older than the engine's just-set start_time_ns.
    let _ = engine.lock().expect("engine lock").refresh()?;
    let loaded = engine.lock().expect("engine lock").session_count();

    let sink: Box<dyn Write + Send> = match inputs.out_path {
        Some(ref path) => {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            Box::new(std::io::BufWriter::new(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?,
            ))
        }
        None => Box::new(std::io::BufWriter::new(std::io::stdout())),
    };
    let sink = Arc::new(Mutex::new(sink));

    eprintln!(
        "fishbowl daemon starting (agents = {:?}, transcript sources = {}, sessions loaded = {})",
        cfg.enrolled_agents,
        inputs.transcript_paths.len(),
        loaded,
    );

    // 100ms refresh tick — transcript poll cadence.
    let refresh_every = Duration::from_millis(100);
    // 500ms attribution buffer. Kernel events fire concurrently with the
    // agent CLI's write of the corresponding tool_call record to the
    // transcript file; the transcript write may not even be on disk yet
    // when the kernel event arrives. Holding the event briefly before
    // calling engine.attribute() gives the polling refresh time to
    // catch up, so the attributed_tool_call_id ends up pointing at the
    // ACTUAL triggering tool_call instead of the previous one.
    //
    // The cost is 500ms of latency from kernel event to JSONL write.
    // Acceptable for security telemetry (Sysmon / SIEM forwarders all
    // tolerate seconds-level lag). On clean shutdown the remaining
    // buffered events get a final drain so we don't lose anything.
    // 2-second attribution buffer. 500ms covered the common case but
    // wasn't long enough when Claude Code batched several transcript
    // records before flushing — the kernel event would arrive, age out,
    // and attribute against the previous tool_call because the actual
    // triggering tool_call wasn't on disk yet. 2s catches essentially
    // every realistic flush cadence we've observed. Latency cost is
    // negligible for security telemetry (still well under any SIEM
    // forwarder's batching interval).
    let attribution_delay = Duration::from_millis(2000);
    let last_refresh = std::cell::Cell::new(Instant::now());

    // Shared between the ETW callback thread (pushes) and the main
    // thread (drains). Each entry is (received_at, event). Drain order
    // is FIFO by received_at.
    let pending: Arc<Mutex<std::collections::VecDeque<(Instant, fishbowl_schema::Event)>>> =
        Arc::new(Mutex::new(std::collections::VecDeque::new()));

    let pending_emit = pending.clone();
    let engine_tick = engine.clone();
    let pending_tick = pending.clone();
    let sink_tick = sink.clone();
    fishbowl_collector_windows::run_with_tick(
        cfg,
        stop.clone(),
        move |event| {
            // ETW callback runs on a ferrisetw-owned thread. Just enqueue;
            // attribution + sink write happen on the main thread under
            // the tick callback below, where transcript refresh has had
            // a chance to fold in new tool_calls.
            let mut q = pending_emit.lock().expect("pending lock");
            q.push_back((Instant::now(), event));
        },
        || {
            // Transcript refresh tick.
            if last_refresh.get().elapsed() >= refresh_every {
                let result = {
                    let mut eng = engine_tick.lock().expect("engine lock");
                    let r = eng.refresh();
                    let _ = eng.save_state();
                    r
                };
                if let Ok(new_events) = result {
                    if !new_events.is_empty() {
                        let mut s = sink_tick.lock().expect("sink lock");
                        for ev in new_events {
                            if let Ok(line) = serde_json::to_string(&ev) {
                                let _ = writeln!(s, "{line}");
                            }
                        }
                        let _ = s.flush();
                    }
                }
                last_refresh.set(Instant::now());
            }

            // Drain any pending kernel events that have aged past
            // `attribution_delay`. Each gets attributed against the
            // engine's current session state (which is up-to-date as of
            // the most recent refresh, including potentially the
            // tool_call that triggered the event), then written.
            let now = Instant::now();
            let drained: Vec<fishbowl_schema::Event> = {
                let mut q = pending_tick.lock().expect("pending lock");
                let mut out = Vec::new();
                while let Some((t, _)) = q.front() {
                    if now.duration_since(*t) >= attribution_delay {
                        if let Some((_, ev)) = q.pop_front() {
                            out.push(ev);
                        }
                    } else {
                        break;
                    }
                }
                out
            };
            if !drained.is_empty() {
                let mut eng = engine_tick.lock().expect("engine lock");
                let mut s = sink_tick.lock().expect("sink lock");
                for mut ev in drained {
                    eng.attribute(&mut ev);
                    if let Ok(line) = serde_json::to_string(&ev) {
                        let _ = writeln!(s, "{line}");
                    }
                }
                let _ = s.flush();
            }
        },
    )?;

    // Final drain on shutdown — flush any buffered events that haven't
    // aged out yet. Without this, the last ~500ms of kernel activity
    // before a service stop would be lost.
    let remaining: Vec<fishbowl_schema::Event> = {
        let mut q = pending.lock().expect("pending lock");
        q.drain(..).map(|(_, ev)| ev).collect()
    };
    if !remaining.is_empty() {
        let mut eng = engine.lock().expect("engine lock");
        let mut s = sink.lock().expect("sink lock");
        for mut ev in remaining {
            eng.attribute(&mut ev);
            if let Ok(line) = serde_json::to_string(&ev) {
                let _ = writeln!(s, "{line}");
            }
        }
        let _ = s.flush();
    }

    eprintln!("fishbowl daemon stopped");
    Ok(())
}

#[cfg(target_os = "windows")]
fn run_collect_windows(
    agents: Option<Vec<String>>,
    duration_secs: Option<u64>,
    out: Option<PathBuf>,
) -> Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let cfg = fishbowl_collector_windows::CollectorConfig {
        enrolled_agents: agents.unwrap_or_else(|| {
            vec!["claude.exe".into(), "cursor.exe".into(), "codex.exe".into()]
        }),
        host_id: read_machine_guid_windows(),
    };

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc_set_handler(move || stop.store(true, Ordering::Relaxed));
    }
    if let Some(secs) = duration_secs {
        let stop = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            stop.store(true, Ordering::Relaxed);
        });
    }

    let sink: Box<dyn Write + Send> = match out {
        Some(path) => Box::new(std::io::BufWriter::new(std::fs::File::create(path)?)),
        None => Box::new(std::io::BufWriter::new(std::io::stdout())),
    };
    let sink = std::sync::Arc::new(std::sync::Mutex::new(sink));
    let sink_for_emit = sink.clone();

    eprintln!(
        "fishbowl windows collector starting (agents = {:?})",
        cfg.enrolled_agents
    );

    fishbowl_collector_windows::run(cfg, stop, move |event| {
        let mut s = sink_for_emit.lock().expect("sink lock");
        if let Ok(line) = serde_json::to_string(&event) {
            let _ = writeln!(s, "{line}");
            let _ = s.flush();
        }
    })?;

    eprintln!("fishbowl windows collector stopped");
    Ok(())
}

/// Bridge between the attribution engine's cross-platform `fn(i32) -> Option<String>`
/// signature and the collector's Win32 PEB-walking `query_cwd(pid: u32)`.
/// Negative or zero PIDs are non-meaningful on Windows; return early.
#[cfg(target_os = "windows")]
fn windows_cwd_for_pid(pid: i32) -> Option<String> {
    if pid <= 0 {
        return None;
    }
    fishbowl_collector_windows::query_cwd(pid as u32)
}

/// Bridge to the collector's `file_owner` so the attribution engine can
/// stamp `user_id` on transcript-derived events. Cached per-file in the
/// engine, so the Win32 cost is paid once per transcript regardless of
/// how many events that transcript ultimately produces.
#[cfg(target_os = "windows")]
fn windows_user_for_transcript(path: &std::path::Path) -> Option<String> {
    fishbowl_collector_windows::file_owner(path)
}

#[cfg(target_os = "windows")]
fn read_machine_guid_windows() -> Option<String> {
    // HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid. Returns None if the
    // registry call fails (e.g. unusual ACLs); the envelope just stays empty.
    //
    // `reg query` output looks like:
    //   <blank>
    //   HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography
    //       MachineGuid    REG_SZ    a1b2c3d4-...
    //
    // Find the value line specifically (the one containing both the value
    // name and the type marker) and pull the last whitespace-separated
    // token. A previous version naïvely returned the first ">30 char" token
    // it saw — which was the registry KEY path on line 2, not the GUID.
    std::process::Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ])
        .output()
        .ok()
        .and_then(|out| {
            let text = String::from_utf8_lossy(&out.stdout);
            text.lines()
                .find(|l| l.contains("MachineGuid") && l.contains("REG_SZ"))
                .and_then(|l| l.split_whitespace().last().map(str::to_string))
                .filter(|s| s.len() > 30)
        })
}

#[cfg(target_os = "windows")]
fn ctrlc_set_handler<F: FnMut() + Send + 'static>(mut handler: F) {
    // Minimal Ctrl-C handler using Windows SetConsoleCtrlHandler. We avoid
    // adding the `ctrlc` crate since one boolean toggle is the entire job.
    use std::sync::OnceLock;
    static HANDLER: OnceLock<std::sync::Mutex<Option<Box<dyn FnMut() + Send>>>> = OnceLock::new();
    let slot = HANDLER.get_or_init(|| std::sync::Mutex::new(None));
    *slot.lock().expect("ctrlc slot") = Some(Box::new(move || handler()));

    unsafe extern "system" fn raw(_ctrl_type: u32) -> windows::core::BOOL {
        if let Some(slot) = HANDLER.get() {
            if let Ok(mut g) = slot.lock() {
                if let Some(h) = g.as_mut() {
                    h();
                }
            }
        }
        windows::core::BOOL(1) // TRUE — handled
    }
    unsafe {
        use windows::Win32::System::Console::SetConsoleCtrlHandler;
        let _ = SetConsoleCtrlHandler(Some(raw), true);
    }
}

#[cfg(target_os = "linux")]
fn run_collect_linux(
    agents: Option<Vec<String>>,
    duration_secs: Option<u64>,
    out: Option<PathBuf>,
) -> Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let cfg = fishbowl_collector_linux::CollectorConfig {
        enrolled_agents: agents.unwrap_or_else(|| {
            vec!["claude".into(), "cursor".into(), "codex".into()]
        }),
        host_id: read_machine_id(),
    };

    let stop = Arc::new(AtomicBool::new(false));

    // SIGINT handler — single line via signal-hook-style raw libc, no extra
    // dep. Sets `stop`; the collector's poll loop notices on the next tick.
    {
        let stop = stop.clone();
        static mut STOP_PTR: *const AtomicBool = std::ptr::null();
        // SAFETY: STOP_PTR is set exactly once before sigaction is installed,
        // and the handler reads it through Arc semantics on Linux atomics —
        // which are async-signal-safe in practice for this access pattern.
        unsafe {
            STOP_PTR = Arc::as_ptr(&stop);
            extern "C" fn handler(_sig: libc::c_int) {
                // SAFETY: see above
                unsafe {
                    if !STOP_PTR.is_null() {
                        (*STOP_PTR).store(true, Ordering::Relaxed);
                    }
                }
            }
            libc::signal(libc::SIGINT, handler as *const () as libc::sighandler_t);
            libc::signal(libc::SIGTERM, handler as *const () as libc::sighandler_t);
        }
    }

    // Optional duration cap: spawn a thread that flips `stop` after N seconds.
    if let Some(secs) = duration_secs {
        let stop = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            stop.store(true, Ordering::Relaxed);
        });
    }

    let sink: Box<dyn Write + Send> = match out {
        Some(path) => Box::new(std::io::BufWriter::new(std::fs::File::create(path)?)),
        None => Box::new(std::io::BufWriter::new(std::io::stdout())),
    };
    let sink = std::sync::Mutex::new(sink);

    eprintln!("fishbowl collector starting (agents = {:?})", cfg.enrolled_agents);

    fishbowl_collector_linux::run(cfg, stop, |event| {
        let mut s = sink.lock().expect("sink lock");
        if let Ok(line) = serde_json::to_string(&event) {
            let _ = writeln!(s, "{line}");
            let _ = s.flush();
        }
    })?;

    eprintln!("fishbowl collector stopped");
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_machine_id() -> Option<String> {
    std::fs::read_to_string("/etc/machine-id")
        .ok()
        .map(|s| s.trim().to_string())
}

/// Linux equivalent of `windows_user_for_transcript`. Resolves a
/// transcript file's owner uid → `uid:NNN` so `user_id` on transcript
/// events lines up with kernel events' `user_id`. Username resolution
/// via `getpwuid` is a follow-up — the raw uid is enough to correlate
/// in v0.x.
#[cfg(target_os = "linux")]
fn linux_user_for_transcript(path: &std::path::Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path)
        .ok()
        .map(|m| format!("uid:{}", m.uid()))
}

#[cfg(target_os = "linux")]
fn run_daemon(
    config_path: Option<PathBuf>,
    transcripts: Vec<PathBuf>,
    watch_dirs: Vec<PathBuf>,
    agents: Option<Vec<String>>,
    duration_secs: Option<u64>,
    out: Option<PathBuf>,
) -> Result<()> {
    use std::cell::RefCell;
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use fishbowl_attribution::{AttributionEngine, EngineConfig};

    let inputs = resolve_daemon_inputs(
        config_path,
        transcripts,
        watch_dirs,
        agents,
        out,
        &["claude", "cursor", "codex"],
    )?;

    let cfg = fishbowl_collector_linux::CollectorConfig {
        enrolled_agents: inputs.agents.clone(),
        host_id: read_machine_id(),
    };

    // Build the attribution engine and seed it from the transcript paths.
    let engine = AttributionEngine::new(EngineConfig {
        cwd_for_pid: fishbowl_attribution::default_cwd_for_pid,
        transcript_paths: inputs.transcript_paths.clone(),
        host_id: read_machine_id(),
        user_for_transcript: linux_user_for_transcript,
        state_path: Some(std::path::PathBuf::from("/var/lib/fishbowl/state.json")),
    });
    let engine = RefCell::new(engine);
    // Initial refresh — loads transcript history into SessionState for
    // attribution; returned Vec is empty (every event is older than
    // start_time_ns).
    let _ = engine.borrow_mut().refresh()?;
    let loaded = engine.borrow().session_count();

    let stop = Arc::new(AtomicBool::new(false));
    install_signal_handlers(&stop);
    if let Some(secs) = duration_secs {
        let stop = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            stop.store(true, Ordering::Relaxed);
        });
    }

    let sink: Box<dyn Write + Send> = match inputs.out_path {
        Some(ref path) => {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            Box::new(std::io::BufWriter::new(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?,
            ))
        }
        None => Box::new(std::io::BufWriter::new(std::io::stdout())),
    };
    let sink = std::sync::Mutex::new(sink);

    // 100ms refresh tick + 500ms attribution buffer. See the matching
    // Windows daemon comment block for the rationale — kernel events
    // can fire concurrently with the transcript write, so we buffer
    // briefly to give attribution a chance to bind to the correct
    // tool_call.
    let refresh_every = Duration::from_millis(100);
    // 2-second attribution buffer. 500ms covered the common case but
    // wasn't long enough when Claude Code batched several transcript
    // records before flushing — the kernel event would arrive, age out,
    // and attribute against the previous tool_call because the actual
    // triggering tool_call wasn't on disk yet. 2s catches essentially
    // every realistic flush cadence we've observed. Latency cost is
    // negligible for security telemetry (still well under any SIEM
    // forwarder's batching interval).
    let attribution_delay = Duration::from_millis(2000);
    let last_refresh = std::cell::Cell::new(Instant::now());
    let pending: std::cell::RefCell<std::collections::VecDeque<(Instant, fishbowl_schema::Event)>> =
        std::cell::RefCell::new(std::collections::VecDeque::new());

    eprintln!(
        "fishbowl daemon starting (agents = {:?}, transcript sources = {}, sessions loaded = {})",
        cfg.enrolled_agents,
        inputs.transcript_paths.len(),
        loaded,
    );

    fishbowl_collector_linux::run_with_tick(
        cfg,
        stop,
        |event| {
            // Enqueue; attribution + sink write happen in the tick
            // callback after the attribution_delay window has elapsed.
            pending.borrow_mut().push_back((Instant::now(), event));
        },
        || {
            if last_refresh.get().elapsed() >= refresh_every {
                let result = {
                    let mut eng = engine.borrow_mut();
                    let r = eng.refresh();
                    let _ = eng.save_state();
                    r
                };
                if let Ok(new_events) = result {
                    if !new_events.is_empty() {
                        let mut s = sink.lock().expect("sink lock");
                        for ev in new_events {
                            if let Ok(line) = serde_json::to_string(&ev) {
                                let _ = writeln!(s, "{line}");
                            }
                        }
                        let _ = s.flush();
                    }
                }
                last_refresh.set(Instant::now());
            }

            // Drain kernel events aged past `attribution_delay`.
            let now = Instant::now();
            let mut drained: Vec<fishbowl_schema::Event> = Vec::new();
            {
                let mut q = pending.borrow_mut();
                while let Some((t, _)) = q.front() {
                    if now.duration_since(*t) >= attribution_delay {
                        if let Some((_, ev)) = q.pop_front() {
                            drained.push(ev);
                        }
                    } else {
                        break;
                    }
                }
            }
            if !drained.is_empty() {
                let mut eng = engine.borrow_mut();
                let mut s = sink.lock().expect("sink lock");
                for mut ev in drained {
                    eng.attribute(&mut ev);
                    if let Ok(line) = serde_json::to_string(&ev) {
                        let _ = writeln!(s, "{line}");
                    }
                }
                let _ = s.flush();
            }
        },
    )?;

    // Final drain on shutdown.
    let remaining: Vec<fishbowl_schema::Event> =
        pending.borrow_mut().drain(..).map(|(_, ev)| ev).collect();
    if !remaining.is_empty() {
        let mut eng = engine.borrow_mut();
        let mut s = sink.lock().expect("sink lock");
        for mut ev in remaining {
            eng.attribute(&mut ev);
            if let Ok(line) = serde_json::to_string(&ev) {
                let _ = writeln!(s, "{line}");
            }
        }
        let _ = s.flush();
    }

    eprintln!("fishbowl daemon stopped");
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn install_signal_handlers(stop: &std::sync::Arc<std::sync::atomic::AtomicBool>) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let stop = stop.clone();
    static mut STOP_PTR: *const AtomicBool = std::ptr::null();
    unsafe {
        STOP_PTR = std::sync::Arc::as_ptr(&stop);
        extern "C" fn handler(_sig: libc::c_int) {
            unsafe {
                if !STOP_PTR.is_null() {
                    (*STOP_PTR).store(true, Ordering::Relaxed);
                }
            }
        }
        libc::signal(libc::SIGINT, handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handler as *const () as libc::sighandler_t);
    }
    // Leak the Arc clone on purpose: the signal handler holds a raw pointer
    // into it for the lifetime of the process. Without the leak the Arc could
    // drop and free its inner allocation while the handler is registered.
    std::mem::forget(stop);
}

// ===========================================================================
// macOS
//
// Structurally identical to the Linux daemon — same collector contract, same
// attribution engine, same buffering — differing only in the collector crate
// (`fishbowl_collector_macos`), the host_id source, the cwd/user resolvers, and
// the state path. Kept as a parallel block (rather than sharing code with the
// Linux path) to match the repo's existing per-OS split and avoid touching the
// Linux/Windows daemons.
// ===========================================================================

/// Stable host identifier for the envelope. Uses the hostname for v0.x;
/// `IOPlatformUUID` (via `ioreg -d2 -c IOPlatformExpertDevice`) is a more
/// durable refinement.
#[cfg(target_os = "macos")]
fn macos_host_id() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: gethostname writes a NUL-terminated name into our buffer.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let name = String::from_utf8_lossy(&buf[..end]).trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// macOS analog of `linux_user_for_transcript` — the transcript file's owner
/// username, so `user_id` on transcript events lines up with kernel events.
#[cfg(target_os = "macos")]
fn macos_user_for_transcript(path: &std::path::Path) -> Option<String> {
    fishbowl_collector_macos::file_owner(path)
}

/// Adapter so the attribution engine's `cwd_for_pid` fn-pointer can reach the
/// macOS collector's libproc-based cwd lookup.
#[cfg(target_os = "macos")]
fn macos_cwd_for_pid(pid: i32) -> Option<String> {
    fishbowl_collector_macos::query_cwd(pid as u32)
}

/// One-shot macOS collector (`fishbowl collect-macos`): emits raw events to a
/// sink with no attribution. Mirrors `run_collect_linux`.
#[cfg(target_os = "macos")]
fn run_collect_macos(
    agents: Option<Vec<String>>,
    duration_secs: Option<u64>,
    out: Option<PathBuf>,
) -> Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let cfg = fishbowl_collector_macos::CollectorConfig {
        enrolled_agents: agents
            .unwrap_or_else(|| vec!["claude".into(), "cursor".into(), "codex".into()]),
        host_id: macos_host_id(),
    };

    let stop = Arc::new(AtomicBool::new(false));
    install_signal_handlers(&stop);
    if let Some(secs) = duration_secs {
        let stop = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            stop.store(true, Ordering::Relaxed);
        });
    }

    let sink: Box<dyn Write + Send> = match out {
        Some(path) => Box::new(std::io::BufWriter::new(std::fs::File::create(path)?)),
        None => Box::new(std::io::BufWriter::new(std::io::stdout())),
    };
    let sink = std::sync::Mutex::new(sink);

    eprintln!(
        "fishbowl collector starting (agents = {:?})",
        cfg.enrolled_agents
    );

    fishbowl_collector_macos::run(cfg, stop, move |event| {
        let mut s = sink.lock().expect("sink lock");
        if let Ok(line) = serde_json::to_string(&event) {
            let _ = writeln!(s, "{line}");
            let _ = s.flush();
        }
    })?;

    eprintln!("fishbowl collector stopped");
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_daemon(
    config_path: Option<PathBuf>,
    transcripts: Vec<PathBuf>,
    watch_dirs: Vec<PathBuf>,
    agents: Option<Vec<String>>,
    duration_secs: Option<u64>,
    out: Option<PathBuf>,
) -> Result<()> {
    use std::cell::RefCell;
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use fishbowl_attribution::{AttributionEngine, EngineConfig};

    let inputs = resolve_daemon_inputs(
        config_path,
        transcripts,
        watch_dirs,
        agents,
        out,
        &["claude", "cursor", "codex"],
    )?;

    let cfg = fishbowl_collector_macos::CollectorConfig {
        enrolled_agents: inputs.agents.clone(),
        host_id: macos_host_id(),
    };

    let engine = AttributionEngine::new(EngineConfig {
        cwd_for_pid: macos_cwd_for_pid,
        transcript_paths: inputs.transcript_paths.clone(),
        host_id: macos_host_id(),
        user_for_transcript: macos_user_for_transcript,
        state_path: Some(std::path::PathBuf::from(
            "/Library/Application Support/fishbowl/state.json",
        )),
    });
    let engine = RefCell::new(engine);
    let _ = engine.borrow_mut().refresh()?;
    let loaded = engine.borrow().session_count();

    let stop = Arc::new(AtomicBool::new(false));
    install_signal_handlers(&stop);
    if let Some(secs) = duration_secs {
        let stop = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            stop.store(true, Ordering::Relaxed);
        });
    }

    let sink: Box<dyn Write + Send> = match inputs.out_path {
        Some(ref path) => {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            Box::new(std::io::BufWriter::new(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?,
            ))
        }
        None => Box::new(std::io::BufWriter::new(std::io::stdout())),
    };
    let sink = std::sync::Mutex::new(sink);

    // Same 100ms refresh / 2s attribution buffer as the Linux daemon — see the
    // rationale in `run_daemon` (linux). Kernel events can fire concurrently
    // with the transcript write, so we buffer briefly before attributing.
    let refresh_every = Duration::from_millis(100);
    let attribution_delay = Duration::from_millis(2000);
    let last_refresh = std::cell::Cell::new(Instant::now());
    let pending: std::cell::RefCell<std::collections::VecDeque<(Instant, fishbowl_schema::Event)>> =
        std::cell::RefCell::new(std::collections::VecDeque::new());

    eprintln!(
        "fishbowl daemon starting (agents = {:?}, transcript sources = {}, sessions loaded = {})",
        cfg.enrolled_agents,
        inputs.transcript_paths.len(),
        loaded,
    );

    fishbowl_collector_macos::run_with_tick(
        cfg,
        stop,
        move |event| {
            pending.borrow_mut().push_back((Instant::now(), event));
        },
        || {
            if last_refresh.get().elapsed() >= refresh_every {
                let result = {
                    let mut eng = engine.borrow_mut();
                    let r = eng.refresh();
                    let _ = eng.save_state();
                    r
                };
                if let Ok(new_events) = result {
                    if !new_events.is_empty() {
                        let mut s = sink.lock().expect("sink lock");
                        for ev in new_events {
                            if let Ok(line) = serde_json::to_string(&ev) {
                                let _ = writeln!(s, "{line}");
                            }
                        }
                        let _ = s.flush();
                    }
                }
                last_refresh.set(Instant::now());
            }

            let now = Instant::now();
            let mut drained: Vec<fishbowl_schema::Event> = Vec::new();
            {
                let mut q = pending.borrow_mut();
                while let Some((t, _)) = q.front() {
                    if now.duration_since(*t) >= attribution_delay {
                        if let Some((_, ev)) = q.pop_front() {
                            drained.push(ev);
                        }
                    } else {
                        break;
                    }
                }
            }
            if !drained.is_empty() {
                let mut eng = engine.borrow_mut();
                let mut s = sink.lock().expect("sink lock");
                for mut ev in drained {
                    eng.attribute(&mut ev);
                    if let Ok(line) = serde_json::to_string(&ev) {
                        let _ = writeln!(s, "{line}");
                    }
                }
                let _ = s.flush();
            }
        },
    )?;

    let remaining: Vec<fishbowl_schema::Event> =
        pending.borrow_mut().drain(..).map(|(_, ev)| ev).collect();
    if !remaining.is_empty() {
        let mut eng = engine.borrow_mut();
        let mut s = sink.lock().expect("sink lock");
        for mut ev in remaining {
            eng.attribute(&mut ev);
            if let Ok(line) = serde_json::to_string(&ev) {
                let _ = writeln!(s, "{line}");
            }
        }
        let _ = s.flush();
    }

    eprintln!("fishbowl daemon stopped");
    Ok(())
}

fn detect_platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else {
        Platform::Linux
    }
}

fn run_transcript(
    transcript: PathBuf,
    out: Option<PathBuf>,
    idx: Option<PathBuf>,
) -> Result<()> {
    let content = fs::read_to_string(&transcript)
        .with_context(|| format!("read {}", transcript.display()))?;

    let platform = detect_platform();
    let dialect = fishbowl_transcript::detect_dialect_from_path(&transcript);
    let (events, index) =
        fishbowl_transcript::read_transcript_by_dialect(dialect, &content, platform, None)?;

    let out_path = out.unwrap_or_else(|| transcript.with_extension("events.jsonl"));
    let idx_path = idx.unwrap_or_else(|| transcript.with_extension("idx.json"));

    {
        let mut writer = std::io::BufWriter::new(
            fs::File::create(&out_path)
                .with_context(|| format!("create {}", out_path.display()))?,
        );
        use std::io::Write;
        for ev in &events {
            serde_json::to_writer(&mut writer, ev)?;
            writeln!(writer)?;
        }
    }

    fs::write(&idx_path, serde_json::to_string_pretty(&index)?)
        .with_context(|| format!("write {}", idx_path.display()))?;

    let mut by_type: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for ev in &events {
        let key = match &ev.kind {
            fishbowl_schema::EventKind::Prompt(_) => "prompt",
            fishbowl_schema::EventKind::ToolCall(_) => "tool_call",
            fishbowl_schema::EventKind::ToolResult(_) => "tool_result",
            fishbowl_schema::EventKind::ProcessExec(_) => "process_exec",
            fishbowl_schema::EventKind::ProcessExit(_) => "process_exit",
            fishbowl_schema::EventKind::CredentialAccess(_) => "credential_access",
            fishbowl_schema::EventKind::NetworkEgress(_) => "network_egress",
            fishbowl_schema::EventKind::FileWrite(_) => "file_write",
        };
        *by_type.entry(key).or_insert(0) += 1;
    }

    eprintln!("wrote {} events to {}", events.len(), out_path.display());
    for (k, n) in &by_type {
        eprintln!("  {k}: {n}");
    }
    eprintln!(
        "wrote {} identifiers to {}",
        index.len(),
        idx_path.display()
    );
    Ok(())
}
