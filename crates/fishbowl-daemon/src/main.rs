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
use fishbowl_transcript::read_transcript;

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
    }
    Ok(())
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
    let (events, index) = read_transcript(&content, platform, None)?;

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
