//! Windows ETW collector.
//!
//! Attaches to the `Microsoft-Windows-Kernel-Process` ETW provider for
//! process-exec events. Two more providers (`-Kernel-File`,
//! `-Kernel-Network`) will land in subsequent iterations alongside the
//! credential and network probes; the structural shape is identical to the
//! Linux side.
//!
//! Reuses cross-platform modules from `aten-collector-linux`:
//! - `enroll` — enrollment state machine (pure Rust, platform-agnostic)
//! - `credentials` — credential-path classifier (path patterns are tested
//!   for both POSIX and Windows separator styles)
//! - `network` — sockaddr parsing for connect()-style events
//!
//! ## Cross-platform note
//!
//! The collector code is gated to `cfg(target_os = "windows")` so the
//! workspace builds on Linux too.

#[cfg(target_os = "windows")]
mod enrich;
#[cfg(target_os = "windows")]
mod eventlog;
#[cfg(target_os = "windows")]
mod windows_impl;

#[cfg(target_os = "windows")]
pub use windows_impl::{run, run_with_tick, CollectorConfig};

/// Windows Event Log sink: writes events to the manifest-declared
/// `ATEN/Operational` ETW channel. Re-exported so the daemon can select it
/// via `output.sink = eventlog|both` without taking a direct ETW dependency.
#[cfg(target_os = "windows")]
pub use eventlog::EventLogSink;

/// Query the working directory of an arbitrary running process by walking
/// its PEB. Re-exported so the daemon can inject a Windows cwd resolver
/// into the attribution engine without that crate taking a direct Win32
/// dependency.
#[cfg(target_os = "windows")]
pub fn query_cwd(pid: u32) -> Option<String> {
    enrich::query_cwd(pid)
}

/// Look up the file owner on disk and return `DOMAIN\username`. Same
/// reason for the re-export as `query_cwd` — the daemon stamps the
/// returned name as `user_id` on transcript-derived events.
#[cfg(target_os = "windows")]
pub fn file_owner(path: &std::path::Path) -> Option<String> {
    enrich::file_owner(path)
}
