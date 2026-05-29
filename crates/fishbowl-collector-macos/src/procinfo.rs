//! libproc-based process enrichment — the macOS analog of the Linux crate's
//! `proc.rs` (`/proc/<pid>/…` reads). macOS has no `/proc`, so process context
//! comes from `proc_pidpath` / `proc_pidinfo` via the `libproc` crate.
//!
//! Two callers need this:
//!  - the ESF open-handler and the netflow IPC handler, which start from a bare
//!    `pid` and must reconstruct the full `Process` block; and
//!  - the daemon bridges `query_cwd` / `file_owner`.
//!
//! The ESF *exec* handler does NOT use this — it builds `Process` directly from
//! the rich `es_process_t` in the message (see `esf.rs`), avoiding a libproc
//! round-trip on the hot exec path.
//!
//! ## start_time convention
//!
//! `ProcessKey` needs a `start_time` that is identical no matter which source
//! observed the process, or PID-reuse disambiguation breaks. Both sources
//! expose **epoch seconds**: `proc_bsdinfo.pbi_start_tvsec` here, and
//! `es_process_t.start_time` (a `SystemTime`) in `esf.rs`. We standardise on
//! epoch seconds (`start_time_ticks` holds seconds-since-epoch on macOS).

use std::path::Path;

use fishbowl_collector_linux::enroll::{EnrollmentTable, ProcessKey};
use fishbowl_schema::ParentChainEntry;

use libproc::libproc::bsd_info::BSDInfo;
use libproc::libproc::proc_pid::{self, pidinfo, ProcType};

/// Best-effort snapshot of a process. Anything that fails to read becomes an
/// empty string / 0 — callers must never panic on a process that exited
/// between observation and our libproc read. Same contract as the Linux
/// `proc::ProcSnapshot`.
#[derive(Debug, Default, Clone)]
pub struct ProcSnapshot {
    pub pid: i32,
    pub ppid: i32,
    pub comm: String,
    pub exe_path: String,
    pub cmdline: String,
    pub cwd: String,
    pub user: String,
    /// Seconds since the UNIX epoch (see module docs on the convention).
    pub start_time_ticks: u64,
}

pub fn snapshot(pid: i32) -> ProcSnapshot {
    let exe_path = proc_pid::pidpath(pid).unwrap_or_default();
    let (ppid, uid, start_time_ticks, comm) = match pidinfo::<BSDInfo>(pid, 0) {
        Ok(bi) => (
            bi.pbi_ppid as i32,
            bi.pbi_uid,
            bi.pbi_start_tvsec,
            cstr_array_to_string(&bi.pbi_name).or_else(|| cstr_array_to_string(&bi.pbi_comm)),
        ),
        Err(_) => (0, 0, 0, None),
    };
    let comm = comm
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| basename(&exe_path));

    ProcSnapshot {
        pid,
        ppid,
        comm,
        exe_path,
        // proc_pidinfo can read argv via KERN_PROCARGS2, but that parse is
        // fiddly and size-limited; the Windows credacc/network paths also ship
        // an empty cmdline. Acceptable v0.x parity; revisit if a detection
        // needs argv on macOS network/credential events.
        cmdline: String::new(),
        cwd: query_cwd(pid).unwrap_or_default(),
        user: username_for_uid(uid).unwrap_or_else(|| uid.to_string()),
        start_time_ticks,
    }
}

/// Walk up the process tree from `pid`, returning one `ParentChainEntry` per
/// ancestor in root → immediate-parent order, excluding `pid` itself. Stops at
/// PID 1, an unreadable parent, or `max_depth` hops. Mirrors
/// `proc::parent_chain` (Linux) and `enrich::parent_chain` (Windows).
pub fn parent_chain(pid: i32, max_depth: usize) -> Vec<ParentChainEntry> {
    let mut chain: Vec<ParentChainEntry> = Vec::new();
    let mut current = pid;
    for _ in 0..max_depth {
        let snap = snapshot(current);
        if snap.ppid <= 0 || snap.ppid == current {
            break;
        }
        let parent = snapshot(snap.ppid);
        if parent.comm.is_empty() {
            break;
        }
        chain.push(ParentChainEntry {
            pid: snap.ppid,
            name: parent.comm.clone(),
        });
        if snap.ppid == 1 {
            break;
        }
        current = snap.ppid;
    }
    chain.reverse();
    chain
}

/// `ProcessKey` for an already-running process, via libproc. Returns `None` if
/// the BSD info can't be read (process gone). Used by the netflow IPC handler,
/// which only ever has a bare pid.
pub fn process_key(pid: i32) -> Option<ProcessKey> {
    match pidinfo::<BSDInfo>(pid, 0) {
        Ok(bi) if bi.pbi_start_tvsec != 0 => Some(ProcessKey {
            pid,
            start_time_ticks: bi.pbi_start_tvsec,
        }),
        _ => None,
    }
}

/// Seed the enrollment table with agents that were already running before the
/// ESF subscription started — ESF `NOTIFY_EXEC` only fires for execs *after*
/// `es_subscribe`, so without this a long-lived agent (and its children) is
/// never enrolled. Same rationale as the Windows rundown
/// (`windows_impl.rs` `list_processes`). Returns the number of roots seeded.
pub fn rundown(
    enrolled_agents: &[String],
    table: &mut EnrollmentTable,
    pid_to_key: &mut std::collections::HashMap<i32, ProcessKey>,
) -> usize {
    let pids = match proc_pid::listpids(ProcType::ProcAllPIDS) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    // First pass: enroll the roots (so children can find them in pass two).
    let mut seeded = 0usize;
    for &pid in &pids {
        let pid = pid as i32;
        let snap = snapshot(pid);
        if snap.start_time_ticks == 0 {
            continue;
        }
        if is_enrolled_agent(&snap.comm, &snap.exe_path, enrolled_agents) {
            let key = ProcessKey {
                pid,
                start_time_ticks: snap.start_time_ticks,
            };
            table.enroll(key, None);
            pid_to_key.insert(pid, key);
            seeded += 1;
        }
    }
    seeded
}

/// Match an agent root the same way the kernel-event handlers do: by the
/// process's `comm`/basename against the configured agent names. Exposed so the
/// ESF exec handler and the rundown share one definition.
pub fn is_enrolled_agent(comm: &str, exe_path: &str, enrolled_agents: &[String]) -> bool {
    let base = if comm.is_empty() {
        basename(exe_path)
    } else {
        comm.to_string()
    };
    enrolled_agents.iter().any(|a| a == &base)
}

/// Current working directory of `pid`, via `proc_pidinfo(PROC_PIDVNODEPATHINFO)`
/// — the macOS equivalent of `/proc/<pid>/cwd`. The daemon's attribution engine
/// uses this to bind a kernel event's process to a transcript session by cwd.
pub fn query_cwd(pid: i32) -> Option<String> {
    use libproc::libproc::proc_pid::pidinfo;
    use libproc::libproc::task_info::VnodePathInfo; // NOTE: verify module path on macOS
    match pidinfo::<VnodePathInfo>(pid, 0) {
        Ok(vpi) => {
            let s = cstr_array_to_string(&vpi.pvi_cdir.vip_path)?;
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }
        Err(_) => None,
    }
}

/// Owner (`username`) of a file on disk: `stat` → `st_uid` → `getpwuid_r`. The
/// daemon stamps this as `user_id` on transcript-derived events (the macOS
/// analog of the Windows `file_owner` SID lookup).
pub fn file_owner(path: &Path) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated path; `st` is a zeroed stat buffer.
    if unsafe { libc::stat(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    username_for_uid(st.st_uid)
}

/// Resolve a UID to a username via `getpwuid_r`. Identical pattern to
/// `proc::username_for_uid` in the Linux crate. Public so the ESF exec handler
/// can resolve the euid from the audit token without a full snapshot.
pub fn username_for_uid(uid: u32) -> Option<String> {
    use std::ffi::CStr;
    let mut buf: Vec<libc::c_char> = vec![0; 4096];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: standard getpwuid_r buffer dance; not called from a signal handler.
    let rc = unsafe {
        libc::getpwuid_r(
            uid as libc::uid_t,
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr(pwd.pw_name) };
    Some(name.to_string_lossy().into_owned())
}

/// Last path component, separator-agnostic. macOS paths use `/`, but be lenient.
pub fn basename(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_string()
}

/// Convert a fixed-size C `char` array (NUL-terminated) to a Rust `String`.
fn cstr_array_to_string(arr: &[libc::c_char]) -> Option<String> {
    let bytes: Vec<u8> = arr
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    if bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_handles_both_separators() {
        assert_eq!(basename("/usr/local/bin/claude"), "claude");
        assert_eq!(basename("claude"), "claude");
        assert_eq!(basename(""), "");
    }

    #[test]
    fn is_enrolled_agent_matches_comm_then_basename() {
        let agents = vec!["claude".to_string(), "codex".to_string()];
        assert!(is_enrolled_agent("claude", "/usr/local/bin/claude", &agents));
        // comm empty → fall back to exe basename.
        assert!(is_enrolled_agent("", "/opt/homebrew/bin/codex", &agents));
        assert!(!is_enrolled_agent("bash", "/bin/bash", &agents));
    }

    #[test]
    fn cstr_array_roundtrip() {
        let arr: Vec<libc::c_char> = b"claude\0\0\0".iter().map(|&b| b as libc::c_char).collect();
        assert_eq!(cstr_array_to_string(&arr).as_deref(), Some("claude"));
        let empty: Vec<libc::c_char> = vec![0; 4];
        assert_eq!(cstr_array_to_string(&empty), None);
    }
}
