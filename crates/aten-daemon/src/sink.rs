//! Output sinks for daemon events.
//!
//! The daemon historically wrote events as JSONL to a file or stdout. This adds
//! a pluggable `EventSink` so events can also (or instead) go to the Windows
//! Event Log's `ATEN/Operational` channel, selected via `output.sink`
//! (`jsonl` | `eventlog` | `both`). The Event Log path is Windows-only; off
//! Windows, `eventlog`/`both` warn and fall back to JSONL.
//!
//! The sink takes a `&Event` (not raw bytes) so the Event Log writer can map
//! each `EventKind` to its manifest Event ID; the JSONL sink just serializes.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use aten_schema::Event;

/// Which output(s) the daemon writes to. Parsed from `output.sink` / `--sink`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SinkKind {
    #[default]
    Jsonl,
    EventLog,
    Both,
}

impl SinkKind {
    /// Parse the config/CLI string. Returns `None` for unrecognised values so
    /// the caller can warn and default.
    pub fn parse(s: &str) -> Option<SinkKind> {
        match s.trim().to_ascii_lowercase().as_str() {
            "jsonl" | "json" | "file" => Some(SinkKind::Jsonl),
            "eventlog" | "event_log" | "etw" | "winlog" => Some(SinkKind::EventLog),
            "both" | "all" => Some(SinkKind::Both),
            _ => None,
        }
    }
}

/// One destination for emitted events. Implementations serialize/route as they
/// see fit; `emit` must never panic or block the daemon (telemetry is
/// best-effort).
pub trait EventSink: Send {
    fn emit(&mut self, ev: &Event);
    fn flush(&mut self) {}
}

/// JSONL to a file (create + append) or stdout — the original behaviour.
pub struct JsonlSink {
    w: Option<Box<dyn Write + Send>>,
    out_path: Option<PathBuf>,
    bytes_written: u64,
    max_bytes: u64,
    rotations: usize,
}

impl JsonlSink {
    const DEFAULT_MAX_BYTES: u64 = 100 * 1024 * 1024;
    const DEFAULT_ROTATIONS: usize = 5;

    /// Open the JSONL destination. `Some(path)` appends (creating parents);
    /// `None` writes to stdout.
    pub fn open(out_path: Option<&Path>) -> Result<Self> {
        let w: Box<dyn Write + Send> = match out_path {
            Some(path) => {
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
        let bytes_written = out_path
            .and_then(|path| std::fs::metadata(path).ok())
            .map_or(0, |metadata| metadata.len());
        Ok(Self {
            w: Some(w),
            out_path: out_path.map(Path::to_path_buf),
            bytes_written,
            max_bytes: Self::DEFAULT_MAX_BYTES,
            rotations: Self::DEFAULT_ROTATIONS,
        })
    }

    fn rotate(&mut self) -> Result<()> {
        let Some(path) = self.out_path.clone() else {
            return Ok(());
        };
        if let Some(mut writer) = self.w.take() {
            let _ = writer.flush();
        }
        for index in (1..self.rotations).rev() {
            let source = rotated_path(&path, index);
            let destination = rotated_path(&path, index + 1);
            if source.exists() {
                let _ = std::fs::remove_file(&destination);
                let _ = std::fs::rename(source, destination);
            }
        }
        if self.rotations > 0 && path.exists() {
            let destination = rotated_path(&path, 1);
            let _ = std::fs::remove_file(&destination);
            std::fs::rename(&path, destination)?;
        }
        let writer: Box<dyn Write + Send> = Box::new(std::io::BufWriter::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?,
        ));
        self.w = Some(writer);
        self.bytes_written = 0;
        Ok(())
    }

    #[cfg(test)]
    fn open_with_limits(out_path: &Path, max_bytes: u64, rotations: usize) -> Result<Self> {
        let mut sink = Self::open(Some(out_path))?;
        sink.max_bytes = max_bytes;
        sink.rotations = rotations;
        Ok(sink)
    }
}

impl EventSink for JsonlSink {
    fn emit(&mut self, ev: &Event) {
        if let Ok(line) = serde_json::to_string(ev) {
            let record_bytes = line.len().saturating_add(1) as u64;
            if self.out_path.is_some()
                && self.bytes_written > 0
                && self.bytes_written.saturating_add(record_bytes) > self.max_bytes
            {
                if let Err(error) = self.rotate() {
                    eprintln!("aten: output rotation failed: {error:#}");
                }
            }
            if let Some(writer) = self.w.as_mut() {
                let _ = writeln!(writer, "{line}");
                self.bytes_written = self.bytes_written.saturating_add(record_bytes);
            }
        }
    }
    fn flush(&mut self) {
        if let Some(writer) = self.w.as_mut() {
            let _ = writer.flush();
        }
    }
}

fn rotated_path(path: &Path, index: usize) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(format!(".{index}"));
    PathBuf::from(value)
}

/// Windows Event Log sink — adapts the collector crate's `EventLogSink` (which
/// owns the ETW provider registration) to the `EventSink` trait.
#[cfg(target_os = "windows")]
pub struct WinEventLogSink {
    inner: aten_collector_windows::EventLogSink,
}

#[cfg(target_os = "windows")]
impl WinEventLogSink {
    pub fn new() -> Result<Self> {
        Ok(Self {
            inner: aten_collector_windows::EventLogSink::new()?,
        })
    }
}

#[cfg(target_os = "windows")]
impl EventSink for WinEventLogSink {
    fn emit(&mut self, ev: &Event) {
        self.inner.write_event(ev);
    }
}

/// Fan out to several sinks (the `both` mode).
#[cfg(target_os = "windows")]
pub struct Tee(pub Vec<Box<dyn EventSink>>);

#[cfg(target_os = "windows")]
impl EventSink for Tee {
    fn emit(&mut self, ev: &Event) {
        for s in &mut self.0 {
            s.emit(ev);
        }
    }
    fn flush(&mut self) {
        for s in &mut self.0 {
            s.flush();
        }
    }
}

/// Build the configured sink. `out_path` is the JSONL destination (ignored by
/// the pure `eventlog` mode). On non-Windows, `eventlog`/`both` warn and fall
/// back to JSONL.
pub fn build_sink(kind: SinkKind, out_path: Option<&Path>) -> Result<Box<dyn EventSink>> {
    match kind {
        SinkKind::Jsonl => Ok(Box::new(JsonlSink::open(out_path)?)),
        #[cfg(target_os = "windows")]
        SinkKind::EventLog => Ok(Box::new(WinEventLogSink::new()?)),
        #[cfg(target_os = "windows")]
        SinkKind::Both => {
            let mut sinks: Vec<Box<dyn EventSink>> = vec![Box::new(JsonlSink::open(out_path)?)];
            match WinEventLogSink::new() {
                Ok(s) => sinks.push(Box::new(s)),
                Err(e) => eprintln!(
                    "aten: eventlog sink unavailable ({e}); writing JSONL only. \
                     Is the ATEN manifest registered (aten install)?"
                ),
            }
            Ok(Box::new(Tee(sinks)))
        }
        #[cfg(not(target_os = "windows"))]
        SinkKind::EventLog | SinkKind::Both => {
            eprintln!("aten: 'eventlog'/'both' sink is Windows-only; falling back to jsonl");
            Ok(Box::new(JsonlSink::open(out_path)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aten_schema::{EventKind, Platform, PromptPayload, Role, Source, SCHEMA_VERSION};

    fn event(id: &str) -> Event {
        Event {
            schema_version: SCHEMA_VERSION.to_string(),
            event_id: id.to_string(),
            timestamp: "2026-06-18T00:00:00Z".to_string(),
            monotonic_ns: None,
            platform: Platform::Macos,
            host_id: None,
            agent_id: "test".to_string(),
            session_id: None,
            user_id: None,
            source: Source {
                collector: "test".to_string(),
                probe: "rotation".to_string(),
                host_pid: None,
            },
            kind: EventKind::Prompt(PromptPayload {
                role: Role::User,
                prompt_text: "x".repeat(128),
                prompt_summary: "rotation".to_string(),
                message_id: None,
            }),
        }
    }

    #[test]
    fn sink_kind_parses_aliases() {
        assert_eq!(SinkKind::parse("jsonl"), Some(SinkKind::Jsonl));
        assert_eq!(SinkKind::parse("EventLog"), Some(SinkKind::EventLog));
        assert_eq!(SinkKind::parse("etw"), Some(SinkKind::EventLog));
        assert_eq!(SinkKind::parse("both"), Some(SinkKind::Both));
        assert_eq!(SinkKind::parse("nonsense"), None);
        assert_eq!(SinkKind::default(), SinkKind::Jsonl);
    }

    #[test]
    fn jsonl_sink_rotates_and_retains_bounded_generations() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aten-sink-{unique}"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");
        let mut sink = JsonlSink::open_with_limits(&path, 1, 2).unwrap();
        sink.emit(&event("one"));
        sink.emit(&event("two"));
        sink.emit(&event("three"));
        sink.flush();

        assert!(path.exists());
        assert!(rotated_path(&path, 1).exists());
        assert!(rotated_path(&path, 2).exists());
        assert!(!rotated_path(&path, 3).exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
