//! macOS EndpointSecurity + NetworkExtension collector.
//!
//! Produces macOS-native `aten_schema::Event`s for enrolled agent processes:
//! `ProcessExec`, `ProcessExit`, `CredentialAccess`, `FileWrite`,
//! `LocalIpcAccess`, and `NetworkEgress`.
//!
//! - **ProcessExec + ProcessExit + CredentialAccess + FileWrite +
//!   LocalIpcAccess** come from the EndpointSecurity framework (ESF) via the
//!   `endpoint-sec` crate: `NOTIFY_EXEC`, `NOTIFY_EXIT`, `NOTIFY_OPEN`, and
//!   `NOTIFY_UIPC_CONNECT`. In-process, like the other collectors.
//! - **NetworkEgress** can't come from ESF (it has no TCP/IP connect event —
//!   only UNIX-domain `uipc_connect`). It arrives from a *separate* process: a
//!   Swift `NEFilterDataProvider` system extension that observes socket flows
//!   and ships `{pid, remote_ip, port, protocol, timestamp}` records to this
//!   collector over a Unix-domain socket (see `netflow_ipc`). This collector
//!   owns the enrollment table, so it does the enrollment lookup + process
//!   enrichment for those flows itself.
//!
//! Reuses the cross-platform modules from `aten-collector-linux` exactly as
//! the Windows collector does:
//! - `enroll` — the enrollment state machine (`EnrollmentTable` / `ProcessKey`)
//! - `credentials` — the credential-path classifier + `is_agent_config_dotenv`
//! - `network` — `Endpoint` + `is_uninteresting`
//!
//! ## Cross-platform note
//!
//! Every module is gated to `cfg(target_os = "macos")` so the workspace builds
//! on Windows/Linux without pulling EndpointSecurity / libproc — mirroring the
//! Linux crate's eBPF gating (`collector-linux/src/lib.rs`).

#[cfg(target_os = "macos")]
mod macos_impl;
#[cfg(target_os = "macos")]
mod netflow_ipc;
#[cfg(target_os = "macos")]
mod procinfo;

#[cfg(all(target_os = "macos", feature = "esf"))]
mod esf;

#[cfg(target_os = "macos")]
pub use macos_impl::{run, run_with_tick, CollectorConfig};

/// Working directory of an arbitrary running process, via libproc
/// `PROC_PIDVNODEPATHINFO`. Re-exported so the daemon can inject a macOS cwd
/// resolver into the attribution engine — the analog of the Windows PEB walk
/// (`collector-windows` `query_cwd`) and the Linux `/proc/<pid>/cwd` read.
#[cfg(target_os = "macos")]
pub fn query_cwd(pid: u32) -> Option<String> {
    procinfo::query_cwd(pid as i32)
}

/// Owner (`username`) of a file on disk, via `stat` + `getpwuid_r`. Same reason
/// for the re-export as `query_cwd`: the daemon stamps it as `user_id` on
/// transcript-derived events.
#[cfg(target_os = "macos")]
pub fn file_owner(path: &std::path::Path) -> Option<String> {
    procinfo::file_owner(path)
}
