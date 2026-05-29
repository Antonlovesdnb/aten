//! Output sinks for daemon events.
//!
//! The daemon historically wrote events as JSONL to a file or stdout. This adds
//! a pluggable `EventSink` so events can also (or instead) go to the Windows
//! Event Log's `Fishbowl/Operational` channel, selected via `output.sink`
//! (`jsonl` | `eventlog` | `both`). The Event Log path is Windows-only; off
//! Windows, `eventlog`/`both` warn and fall back to JSONL.
//!
//! The sink takes a `&Event` (not raw bytes) so the Event Log writer can map
//! each `EventKind` to its manifest Event ID; the JSONL sink just serializes.

use std::io::Write;
use std::path::Path;

use anyhow::Result;
use fishbowl_schema::Event;

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
    w: Box<dyn Write + Send>,
}

impl JsonlSink {
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
        Ok(Self { w })
    }
}

impl EventSink for JsonlSink {
    fn emit(&mut self, ev: &Event) {
        if let Ok(line) = serde_json::to_string(ev) {
            let _ = writeln!(self.w, "{line}");
        }
    }
    fn flush(&mut self) {
        let _ = self.w.flush();
    }
}

/// Windows Event Log sink — adapts the collector crate's `EventLogSink` (which
/// owns the ETW provider registration) to the `EventSink` trait.
#[cfg(target_os = "windows")]
pub struct WinEventLogSink {
    inner: fishbowl_collector_windows::EventLogSink,
}

#[cfg(target_os = "windows")]
impl WinEventLogSink {
    pub fn new() -> Result<Self> {
        Ok(Self {
            inner: fishbowl_collector_windows::EventLogSink::new()?,
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
pub struct Tee(pub Vec<Box<dyn EventSink>>);

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
                    "fishbowl: eventlog sink unavailable ({e}); writing JSONL only. \
                     Is the Fishbowl manifest registered (fishbowl install)?"
                ),
            }
            Ok(Box::new(Tee(sinks)))
        }
        #[cfg(not(target_os = "windows"))]
        SinkKind::EventLog | SinkKind::Both => {
            eprintln!("fishbowl: 'eventlog'/'both' sink is Windows-only; falling back to jsonl");
            Ok(Box::new(JsonlSink::open(out_path)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sink_kind_parses_aliases() {
        assert_eq!(SinkKind::parse("jsonl"), Some(SinkKind::Jsonl));
        assert_eq!(SinkKind::parse("EventLog"), Some(SinkKind::EventLog));
        assert_eq!(SinkKind::parse("etw"), Some(SinkKind::EventLog));
        assert_eq!(SinkKind::parse("both"), Some(SinkKind::Both));
        assert_eq!(SinkKind::parse("nonsense"), None);
        assert_eq!(SinkKind::default(), SinkKind::Jsonl);
    }
}
