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
    /// Run the full daemon: kernel collector + transcript reader + attribution.
    /// On Linux uses eBPF (needs root or CAP_BPF+CAP_PERFMON); on Windows uses
    /// ETW (needs admin). Same subcommand on both platforms; the build picks
    /// the right collector via `cfg(target_os = ...)`.
    Daemon {
        /// Path to a Claude Code session transcript JSONL. The daemon binds
        /// kernel-side events to this session by matching the agent root
        /// process's cwd against the transcript's recorded cwd.
        #[arg(long)]
        transcript: PathBuf,
        /// Process names to enroll as agent roots. Comma-separated. On Linux
        /// matches `comm` (e.g. `claude,cursor,codex`); on Windows matches
        /// image basename (e.g. `claude.exe,cursor.exe,codex.exe`).
        #[arg(long, value_delimiter = ',')]
        agents: Option<Vec<String>>,
        /// Stop after this many seconds.
        #[arg(long)]
        duration_secs: Option<u64>,
        /// Append emitted events as JSONL to this file. Default: stdout.
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
            transcript,
            agents,
            duration_secs,
            out,
        } => run_daemon(transcript, agents, duration_secs, out)?,
        #[cfg(target_os = "windows")]
        Command::CollectWindows {
            agents,
            duration_secs,
            out,
        } => run_collect_windows(agents, duration_secs, out)?,
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn run_daemon(
    transcript: PathBuf,
    agents: Option<Vec<String>>,
    duration_secs: Option<u64>,
    out: Option<PathBuf>,
) -> Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use fishbowl_attribution::{AttributionEngine, EngineConfig};

    let cfg = fishbowl_collector_windows::CollectorConfig {
        enrolled_agents: agents.unwrap_or_else(|| {
            vec!["claude.exe".into(), "cursor.exe".into(), "codex.exe".into()]
        }),
        host_id: read_machine_guid_windows(),
    };

    // Shared between the ETW callback thread (emit closure → `attribute`) and
    // the main thread (tick closure → `refresh`). Arc<Mutex<_>> rather than
    // RefCell because the Windows collector's emit closure must be
    // `Send + 'static` (ferrisetw runs callbacks on a thread it owns).
    //
    // `cwd_for_pid` is wired to the collector's PEB-walking `query_cwd` so
    // attribution can bind an agent_root_pid (which on Windows isn't
    // queryable via /proc) to a transcript session by cwd match.
    let engine = Arc::new(Mutex::new(AttributionEngine::new(EngineConfig {
        cwd_for_pid: windows_cwd_for_pid,
        dialect: fishbowl_transcript::detect_dialect_from_path(&transcript),
        transcript_path: transcript.clone(),
    })));
    engine.lock().expect("engine lock").refresh()?;

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
    let sink = Arc::new(Mutex::new(sink));

    eprintln!(
        "fishbowl daemon starting (agents = {:?}, transcript = {})",
        cfg.enrolled_agents,
        transcript.display()
    );

    let refresh_every = Duration::from_millis(500);
    let last_refresh = std::cell::Cell::new(Instant::now());

    let engine_emit = engine.clone();
    let sink_emit = sink.clone();
    fishbowl_collector_windows::run_with_tick(
        cfg,
        stop,
        move |mut event| {
            engine_emit
                .lock()
                .expect("engine lock")
                .attribute(&mut event);
            let mut s = sink_emit.lock().expect("sink lock");
            if let Ok(line) = serde_json::to_string(&event) {
                let _ = writeln!(s, "{line}");
                let _ = s.flush();
            }
        },
        || {
            if last_refresh.get().elapsed() >= refresh_every {
                if let Err(e) = engine.lock().expect("engine lock").refresh() {
                    eprintln!("transcript refresh failed: {e}");
                }
                last_refresh.set(Instant::now());
            }
        },
    )?;

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

#[cfg(target_os = "windows")]
fn read_machine_guid_windows() -> Option<String> {
    // HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid. Returns None if the
    // registry call fails (e.g. unusual ACLs); the envelope just stays empty.
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
                .find_map(|l| l.split_whitespace().last().map(str::to_string))
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

#[cfg(target_os = "linux")]
fn run_daemon(
    transcript: PathBuf,
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

    let cfg = fishbowl_collector_linux::CollectorConfig {
        enrolled_agents: agents.unwrap_or_else(|| {
            vec!["claude".into(), "cursor".into(), "codex".into()]
        }),
        host_id: read_machine_id(),
    };

    // Build the attribution engine and seed it from the transcript.
    let engine = AttributionEngine::new(EngineConfig {
        cwd_for_pid: fishbowl_attribution::default_cwd_for_pid,
        dialect: fishbowl_transcript::detect_dialect_from_path(&transcript),
        transcript_path: transcript.clone(),
    });
    let engine = RefCell::new(engine);
    engine.borrow_mut().refresh()?;

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

    let refresh_every = Duration::from_millis(500);
    let last_refresh = std::cell::Cell::new(Instant::now());

    eprintln!(
        "fishbowl daemon starting (agents = {:?}, transcript = {})",
        cfg.enrolled_agents,
        transcript.display()
    );

    fishbowl_collector_linux::run_with_tick(
        cfg,
        stop,
        |mut event| {
            engine.borrow_mut().attribute(&mut event);
            let mut s = sink.lock().expect("sink lock");
            if let Ok(line) = serde_json::to_string(&event) {
                let _ = writeln!(s, "{line}");
                let _ = s.flush();
            }
        },
        || {
            if last_refresh.get().elapsed() >= refresh_every {
                if let Err(e) = engine.borrow_mut().refresh() {
                    eprintln!("transcript refresh failed: {e}");
                }
                last_refresh.set(Instant::now());
            }
        },
    )?;

    eprintln!("fishbowl daemon stopped");
    Ok(())
}

#[cfg(target_os = "linux")]
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

fn detect_platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
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
