//! Windows ETW collector.
//!
//! Attaches to the `Microsoft-Windows-Kernel-Process` ETW provider for
//! process-exec events. Two more providers (`-Kernel-File`,
//! `-Kernel-Network`) will land in subsequent iterations alongside the
//! credential and network probes; the structural shape is identical to the
//! Linux side.
//!
//! Reuses cross-platform modules from `fishbowl-collector-linux`:
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
mod windows_impl;

#[cfg(target_os = "windows")]
pub use windows_impl::{run, run_with_tick, CollectorConfig};
