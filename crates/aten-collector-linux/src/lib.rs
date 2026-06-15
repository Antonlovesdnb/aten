//! Linux eBPF collector.
//!
//! Attaches three tracepoints:
//! - `sched/sched_process_exec` → `ProcessExec` events
//! - `syscalls/sys_enter_openat` → `CredentialAccess` events
//! - `syscalls/sys_enter_connect` → `NetworkEgress` events
//!
//! All three probes share an enrollment state machine: only processes that are
//! enrolled agent CLIs or descendants of one produce events. The exec probe
//! drives enrollment (it sees every new process); the openat and connect
//! probes consult the same `EnrollmentTable` via a side-table `pid_to_key`
//! that the exec handler maintains, with a /proc-walk fallback when the
//! ringbuf race leaves a descendant unbound.
//!
//! Requires CAP_BPF + CAP_PERFMON. Run as root for v0.x.
//!
//! ## Cross-platform note
//!
//! The collector code is gated to `cfg(target_os = "linux")` so the
//! workspace can build on Windows hosts without pulling libbpf. The
//! cross-platform helper modules (`enroll`, `credentials`, `network`) stay
//! accessible on every platform — they're pure Rust and the Windows ETW
//! collector reuses them.

pub mod credentials;
pub mod enroll;
pub mod filewrite;
pub mod network;

#[cfg(target_os = "linux")]
pub mod proc;

#[cfg(target_os = "linux")]
mod skel_execve {
    #![allow(clippy::all)]
    #![allow(dead_code)]
    #![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/execve.skel.rs"));
}

#[cfg(target_os = "linux")]
mod skel_credacc {
    #![allow(clippy::all)]
    #![allow(dead_code)]
    #![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/credacc.skel.rs"));
}

#[cfg(target_os = "linux")]
mod skel_connect {
    #![allow(clippy::all)]
    #![allow(dead_code)]
    #![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/connect.skel.rs"));
}

#[cfg(target_os = "linux")]
mod skel_dns {
    #![allow(clippy::all)]
    #![allow(dead_code)]
    #![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/dns.skel.rs"));
}

#[cfg(target_os = "linux")]
mod linux_impl;

#[cfg(target_os = "linux")]
pub use linux_impl::{run, run_with_tick, CollectorConfig};
