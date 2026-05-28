//! /proc parsing helpers.
//!
//! The eBPF program intentionally emits only what the kernel cheaply gives us
//! (pid, comm, filename). Everything else the schema needs for the Process
//! block comes from /proc, which is fast to read on dev-endpoint exec rates.
//!
//! Note on PID reuse: the schema uses (pid, start_time) as the disambiguator.
//! `start_time` here is the process's start time relative to boot, parsed
//! from /proc/<pid>/stat field 22 (`starttime` in clock ticks). We render it
//! as a plain integer string for v0.x — converting to RFC 3339 against the
//! system's boot time + clock-tick rate is a follow-up.

use std::fs;
use std::path::PathBuf;

use fishbowl_schema::ParentChainEntry;

/// Best-effort snapshot of /proc/<pid>/ for one process. Anything that fails
/// to read becomes an empty string — collectors should never panic on a
/// process that disappeared between exec and our /proc read.
#[derive(Debug, Default, Clone)]
pub struct ProcSnapshot {
    pub pid: i32,
    pub ppid: i32,
    pub comm: String,
    pub exe_path: String,
    pub cmdline: String,
    pub cwd: String,
    pub user: String,
    pub start_time_ticks: u64,
}

pub fn snapshot(pid: i32) -> ProcSnapshot {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let comm = read_trim(root.join("comm"));
    let exe_path = read_link(root.join("exe"));
    let cmdline = read_cmdline(root.join("cmdline"));
    let cwd = read_link(root.join("cwd"));
    let (ppid, start_time_ticks) = parse_stat(root.join("stat"));
    let user = parse_uid_to_username(root.join("status"));

    ProcSnapshot {
        pid,
        ppid,
        comm,
        exe_path,
        cmdline,
        cwd,
        user,
        start_time_ticks,
    }
}

/// Walk up the process tree from `pid` and return one `ParentChainEntry`
/// per ancestor in root → immediate-parent order. Stops at PID 1, when
/// a parent can't be read, or after `max_depth` hops (schema caps at
/// 16). The result excludes `pid` itself. Each entry carries `{pid, name}`
/// so downstream rules can join the chain against `process_exec` events
/// emitted earlier for the same ancestors without re-walking PPIDs.
pub fn parent_chain(pid: i32, max_depth: usize) -> Vec<ParentChainEntry> {
    let mut chain: Vec<ParentChainEntry> = Vec::new();
    let mut current = pid;
    for _ in 0..max_depth {
        let snap = snapshot(current);
        if snap.ppid <= 0 || snap.ppid == current {
            break;
        }
        let parent_snap = snapshot(snap.ppid);
        if parent_snap.comm.is_empty() {
            break;
        }
        chain.push(ParentChainEntry {
            pid: snap.ppid,
            name: parent_snap.comm.clone(),
        });
        if snap.ppid == 1 {
            break;
        }
        current = snap.ppid;
    }
    chain.reverse();
    chain
}

fn read_trim(path: PathBuf) -> String {
    fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim_end_matches('\n').to_string())
        .unwrap_or_default()
}

fn read_link(path: PathBuf) -> String {
    fs::read_link(&path)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn read_cmdline(path: PathBuf) -> String {
    // /proc/<pid>/cmdline joins argv with NUL bytes, ends with a NUL.
    fs::read(&path)
        .map(|bytes| {
            let mut joined: Vec<u8> = Vec::with_capacity(bytes.len());
            for (i, b) in bytes.iter().enumerate() {
                if *b == 0 {
                    if i + 1 == bytes.len() {
                        break;
                    }
                    joined.push(b' ');
                } else {
                    joined.push(*b);
                }
            }
            String::from_utf8_lossy(&joined).into_owned()
        })
        .unwrap_or_default()
}

/// Parse fields 4 (ppid) and 22 (starttime) from /proc/<pid>/stat. Field 2 is
/// the comm wrapped in literal parens, which may itself contain spaces — so
/// we find the LAST `)` and tokenize what follows.
fn parse_stat(path: PathBuf) -> (i32, u64) {
    let content = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return (0, 0),
    };
    let Some(end_comm) = content.rfind(')') else {
        return (0, 0);
    };
    let after = &content[end_comm + 1..];
    let fields: Vec<&str> = after.split_whitespace().collect();
    // After the comm, /proc/<pid>/stat field 3 (state) starts at index 0.
    // PPid is field 4 → index 1; starttime is field 22 → index 19.
    let ppid = fields.get(1).and_then(|s| s.parse::<i32>().ok()).unwrap_or(0);
    let start_time = fields
        .get(19)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    (ppid, start_time)
}

/// Read the Uid: line from /proc/<pid>/status and resolve to a username via
/// libc. Falls back to the numeric UID string if the lookup fails.
fn parse_uid_to_username(path: PathBuf) -> String {
    let content = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    let uid_line = content
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .unwrap_or("");
    // Format: "Uid:\t<real>\t<effective>\t<saved>\t<filesystem>"
    let uid = uid_line
        .split_whitespace()
        .nth(2) // effective uid — the one that ran the exec
        .and_then(|s| s.parse::<u32>().ok());
    let Some(uid) = uid else {
        return String::new();
    };
    username_for_uid(uid).unwrap_or_else(|| uid.to_string())
}

fn username_for_uid(uid: u32) -> Option<String> {
    // SAFETY: getpwuid_r needs a libc::passwd buffer + a char scratch buffer.
    // Standard pattern; not async-signal-safe but we never call this from a
    // signal handler.
    use std::ffi::CStr;
    let mut buf: Vec<libc::c_char> = vec![0; 4096];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
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
