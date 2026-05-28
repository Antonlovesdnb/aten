//! Windows-only process enrichment helpers.
//!
//! ETW's `Microsoft-Windows-Kernel-Process` Event ID 1 gives us pid, ppid,
//! image path, session ID, and an integrity-level SID — but not the command
//! line, the parent process tree by name, or the user behind the token.
//! Sysmon ships those fields out of the box; we get parity by issuing three
//! small queries per enrolled process right after the start event:
//!
//! 1. `NtQueryInformationProcess(ProcessCommandLineInformation)` for the
//!    UNICODE_STRING command line. Cheap on a process handle with
//!    `PROCESS_QUERY_LIMITED_INFORMATION`.
//! 2. `OpenProcess + NtQueryInformationProcess(ProcessBasicInformation)
//!    + QueryFullProcessImageNameW` per hop while walking PPIDs up to the
//!    enrolled agent root. Capped at 16 hops to match schema §3.
//! 3. `OpenProcessToken(TOKEN_QUERY) + GetTokenInformation(TokenUser)
//!    + LookupAccountSidW` for `DOMAIN\username`.
//!
//! Every helper returns an empty string on failure rather than an error —
//! short-lived descendants (npm-installed binaries that fork-exec-exit in
//! microseconds) can disappear between the ETW event firing and our query
//! running, and a missing field shouldn't drop the whole event.
//!
//! No cache yet. Each ProcessStart triggers up to ~16 OpenProcess calls for
//! the parent-chain walk; that's ~tens of microseconds even on a busy host
//! and well below the ETW callback's natural latency. If profiling shows
//! the chain-walk dominating, a `(pid, creation_filetime) -> (name, ppid)`
//! cache is the obvious next step (PID-only cache is unsafe because of
//! Windows PID reuse — start time disambiguates).

use std::ffi::c_void;
use std::mem;

use windows::core::{PCWSTR, PWSTR};
use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, TokenUser, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

/// `ProcessBasicInformation` — documented, stable. Returns the
/// `PROCESS_BASIC_INFORMATION` struct whose last field is the PPID.
const PROCESS_BASIC_INFORMATION_CLASS: PROCESSINFOCLASS = PROCESSINFOCLASS(0);

/// `ProcessCommandLineInformation` — not in the public Windows SDK enum but
/// stable since Win8.1. Returns a `UNICODE_STRING` followed by the wide-char
/// command-line bytes the struct's `Buffer` field points at.
const PROCESS_COMMAND_LINE_INFORMATION: PROCESSINFOCLASS = PROCESSINFOCLASS(60);

/// `STATUS_INFO_LENGTH_MISMATCH` — returned by `NtQueryInformationProcess`
/// when the supplied buffer is too small; `ReturnLength` is set to the
/// required size so we can re-allocate and retry.
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;

/// PID 0 is the System Idle Process; PID 4 is the System process. Neither
/// has an openable handle from user mode, and neither can be the parent of
/// anything we care about — stop the walk if we see them.
const PID_IDLE: u32 = 0;
const PID_SYSTEM: u32 = 4;

/// In-memory layout of `UNICODE_STRING` as returned by
/// `ProcessCommandLineInformation`. The `Buffer` pointer points inside the
/// same allocation we passed in, so reading through it is safe for the
/// lifetime of that allocation.
#[repr(C)]
struct UnicodeString {
    length: u16,           // bytes, not chars; excludes null terminator
    maximum_length: u16,
    _padding: u32,         // on x86_64; harmless on x86 where Buffer follows directly
    buffer: *mut u16,
}

/// In-memory layout of `PROCESS_BASIC_INFORMATION`. We only read the last
/// field but need the full layout to size the query correctly.
#[repr(C)]
struct ProcessBasicInformation {
    exit_status: i32,
    peb_base_address: *mut c_void,
    affinity_mask: usize,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

/// RAII wrapper that calls `CloseHandle` on drop. We open one of these per
/// PID we enrich; the ETW callback is hot enough that leaking handles would
/// be visible within seconds.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

fn open_query_handle(pid: u32) -> Option<OwnedHandle> {
    if pid == PID_IDLE || pid == PID_SYSTEM {
        return None;
    }
    unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .ok()
            .map(OwnedHandle)
    }
}

/// Fetch the full command line for `pid`. Empty string on failure.
pub fn query_cmdline(pid: u32) -> String {
    let Some(h) = open_query_handle(pid) else {
        return String::new();
    };

    // Start with a 4 KiB buffer — covers the vast majority of command lines.
    // Grow on STATUS_INFO_LENGTH_MISMATCH; cap at 64 KiB to bound a hostile
    // process that reports an absurd size.
    let mut buf = vec![0u8; 4096];
    let mut return_len: u32 = 0;
    let status = unsafe {
        NtQueryInformationProcess(
            h.0,
            PROCESS_COMMAND_LINE_INFORMATION,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            &mut return_len,
        )
    };

    let final_status = if status.0 == STATUS_INFO_LENGTH_MISMATCH {
        if (return_len as usize) > 64 * 1024 {
            return String::new();
        }
        buf.resize(return_len as usize, 0);
        unsafe {
            NtQueryInformationProcess(
                h.0,
                PROCESS_COMMAND_LINE_INFORMATION,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut return_len,
            )
        }
    } else {
        status
    };

    if final_status.0 != 0 {
        return String::new();
    }
    if (return_len as usize) < mem::size_of::<UnicodeString>() {
        return String::new();
    }

    // SAFETY: the kernel populated `buf` with a UNICODE_STRING followed by
    // its backing wide-char buffer, with `Buffer` pointing into the same
    // allocation. `buf` lives until the end of this function.
    let us = unsafe { &*(buf.as_ptr() as *const UnicodeString) };
    if us.length == 0 || us.buffer.is_null() {
        return String::new();
    }
    let nchars = (us.length as usize) / 2;
    let slice = unsafe { std::slice::from_raw_parts(us.buffer, nchars) };
    String::from_utf16_lossy(slice)
}

/// Public wrapper: full image path for `pid`. Returns empty on failure.
/// Used by handlers that need to populate `Process.path` / `Process.name`
/// without already having a handle (Kernel-File / Kernel-Network events
/// carry only `ProcessID`, not an image).
pub fn query_image(pid: u32) -> String {
    let Some(h) = open_query_handle(pid) else {
        return String::new();
    };
    query_image_path(&h)
}

fn query_image_path(h: &OwnedHandle) -> String {
    // 1024 wide chars = 2048 bytes, enough for MAX_PATH (260) plus the
    // long-path prefix. Bump on retry if a process actually returns
    // ERROR_INSUFFICIENT_BUFFER (rare in practice — long-path-aware tools
    // are still uncommon on Win11 even with the registry opt-in).
    let mut buf: Vec<u16> = vec![0; 1024];
    let mut size: u32 = buf.len() as u32;
    let res = unsafe {
        QueryFullProcessImageNameW(
            h.0,
            PROCESS_NAME_FORMAT(0), // 0 = Win32 path format
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        )
    };
    if res.is_err() {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..size as usize])
}

fn query_ppid(h: &OwnedHandle) -> Option<u32> {
    let mut pbi: ProcessBasicInformation = unsafe { mem::zeroed() };
    let mut ret: u32 = 0;
    let status = unsafe {
        NtQueryInformationProcess(
            h.0,
            PROCESS_BASIC_INFORMATION_CLASS,
            &mut pbi as *mut _ as *mut c_void,
            mem::size_of::<ProcessBasicInformation>() as u32,
            &mut ret,
        )
    };
    if status.0 != 0 {
        return None;
    }
    Some(pbi.inherited_from_unique_process_id as u32)
}

/// Walk PPIDs upward and return ancestor PIDs in newest → oldest order
/// (i.e. immediate parent first), capped at `max_depth` hops. The result
/// excludes `start_pid` itself.
///
/// Used by the credential-access (and future network-egress) handlers when
/// an ETW Kernel-File / Kernel-Network event arrives for a PID whose
/// ProcessStart we haven't processed yet — ETW does not guarantee
/// cross-provider ordering, so a Create from a freshly-spawned descendant
/// can race ahead of its own ProcessStart. The caller checks each ancestor
/// PID against `pid_to_key` and inherits enrollment from the first match.
///
/// Stops on the same conditions as `parent_chain` (PID 0/4, self-loop,
/// OpenProcess failure).
pub fn ancestor_pids(start_pid: u32, max_depth: usize) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::new();
    let mut pid = start_pid;
    for _ in 0..max_depth {
        if pid == PID_IDLE || pid == PID_SYSTEM {
            break;
        }
        let Some(h) = open_query_handle(pid) else {
            break;
        };
        let Some(parent) = query_ppid(&h) else {
            break;
        };
        if parent == pid || parent == PID_IDLE || parent == PID_SYSTEM {
            break;
        }
        out.push(parent);
        pid = parent;
    }
    out
}

/// Fetch the current working directory for `pid` by walking the target
/// process's PEB → `RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.DosPath`
/// via `ReadProcessMemory`. Returns `None` if the process is gone, has
/// already exited, the target is a protected/system process we can't read,
/// or any of the layered reads fails.
///
/// Used by the attribution engine on Windows to bind an `agent_root_pid`
/// to a transcript session by matching the agent root's cwd against the
/// recorded session cwd — the same logic the Linux side gets from
/// `/proc/<pid>/cwd`. There is no documented Win32 API for "cwd of an
/// arbitrary process"; the PEB walk is the standard approach (used by
/// Process Hacker, sysinternals, etc.).
///
/// 64-bit-only — `PEB.ProcessParameters` is at offset 0x20 and
/// `RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.DosPath` is at offset
/// 0x38 in the x86_64 layout. 32-bit (WoW64) processes have a different
/// PEB and aren't currently supported; the daemon's own architecture
/// matches what we deploy on (x86_64).
pub fn query_cwd(pid: u32) -> Option<String> {
    if pid == PID_IDLE || pid == PID_SYSTEM {
        return None;
    }

    // PROCESS_VM_READ is required for ReadProcessMemory; the limited-info
    // bit covers the NtQueryInformationProcess call.
    let h: OwnedHandle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        )
        .ok()
        .map(OwnedHandle)?
    };

    // Step 1: get PEB base address from PROCESS_BASIC_INFORMATION.
    let mut pbi: ProcessBasicInformation = unsafe { mem::zeroed() };
    let mut ret_len: u32 = 0;
    let status = unsafe {
        NtQueryInformationProcess(
            h.0,
            PROCESS_BASIC_INFORMATION_CLASS,
            &mut pbi as *mut _ as *mut c_void,
            mem::size_of::<ProcessBasicInformation>() as u32,
            &mut ret_len,
        )
    };
    if status.0 != 0 || pbi.peb_base_address.is_null() {
        return None;
    }

    // Step 2: read ProcessParameters pointer from PEB. Offset 0x20 on x86_64.
    const PEB_PROCESS_PARAMETERS_OFFSET: usize = 0x20;
    let mut process_parameters: *mut c_void = std::ptr::null_mut();
    let mut bytes_read: usize = 0;
    let pp_addr = unsafe { pbi.peb_base_address.byte_add(PEB_PROCESS_PARAMETERS_OFFSET) };
    if unsafe {
        ReadProcessMemory(
            h.0,
            pp_addr,
            &mut process_parameters as *mut _ as *mut c_void,
            mem::size_of::<*mut c_void>(),
            Some(&mut bytes_read),
        )
    }
    .is_err()
        || process_parameters.is_null()
    {
        return None;
    }

    // Step 3: read CurrentDirectory.DosPath UNICODE_STRING from
    // RTL_USER_PROCESS_PARAMETERS. Offset 0x38 on x86_64.
    const RTL_USER_PROCESS_PARAMETERS_CURRENT_DIRECTORY_OFFSET: usize = 0x38;
    let mut us: UnicodeString = unsafe { mem::zeroed() };
    let us_addr = unsafe {
        process_parameters.byte_add(RTL_USER_PROCESS_PARAMETERS_CURRENT_DIRECTORY_OFFSET)
    };
    if unsafe {
        ReadProcessMemory(
            h.0,
            us_addr,
            &mut us as *mut _ as *mut c_void,
            mem::size_of::<UnicodeString>(),
            Some(&mut bytes_read),
        )
    }
    .is_err()
        || us.length == 0
        || us.buffer.is_null()
    {
        return None;
    }

    // Step 4: read the cwd string from the UNICODE_STRING.Buffer in the
    // target process. Length is in bytes, not chars; sanity-cap to bound a
    // hostile/corrupt process advertising an absurd size.
    let length_bytes = us.length as usize;
    if length_bytes > 32 * 1024 {
        return None;
    }
    let nchars = length_bytes / 2;
    let mut buf: Vec<u16> = vec![0u16; nchars];
    if unsafe {
        ReadProcessMemory(
            h.0,
            us.buffer as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            length_bytes,
            Some(&mut bytes_read),
        )
    }
    .is_err()
    {
        return None;
    }

    // CurrentDirectory.DosPath conventionally has a trailing `\` on Windows
    // (e.g. `C:\Users\anton\`). Trim it for clean comparison against the
    // transcript's recorded cwd, which doesn't.
    let mut s = String::from_utf16_lossy(&buf);
    if s.ends_with('\\') {
        s.pop();
    }
    Some(s)
}

/// Enumerate currently-running processes, returning `(pid, image_basename)`
/// pairs. Used by the pre-trace enrollment rundown: ETW only delivers
/// `ProcessStart` for processes that begin AFTER the trace is enabled, so
/// long-running agents (e.g. a `claude.exe` started before the daemon
/// service) are invisible to the enrollment table without an explicit
/// snapshot at startup.
///
/// Uses the Toolhelp32 snapshot API — one syscall to enumerate, no
/// per-process `OpenProcess`. Image name comes from `PROCESSENTRY32W::szExeFile`
/// (already the basename, no path).
pub fn list_processes() -> Vec<(u32, String)> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let mut out: Vec<(u32, String)> = Vec::new();
    let snap = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(h) if !h.is_invalid() => h,
        _ => return out,
    };
    let _owner = OwnedHandle(snap);

    let mut entry = PROCESSENTRY32W {
        dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    if unsafe { Process32FirstW(snap, &mut entry) }.is_ok() {
        loop {
            let wide = &entry.szExeFile;
            let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
            let name = String::from_utf16_lossy(&wide[..len]);
            if !name.is_empty() {
                out.push((entry.th32ProcessID, name));
            }
            if unsafe { Process32NextW(snap, &mut entry) }.is_err() {
                break;
            }
        }
    }
    out
}

/// Walk PPIDs upward starting from `start_ppid`. Returns ancestor basenames
/// in root → leaf order, capped at `max_depth` hops. The result excludes the
/// caller's own process to match the Linux collector's contract (see
/// `fishbowl_collector_linux::proc::parent_chain`).
///
/// Stops on: hitting PID 0/4, a PPID self-loop, or `OpenProcess` failing
/// (likely a process that exited between hops — a normal race, not an
/// error).
pub fn parent_chain(start_ppid: u32, max_depth: usize) -> Vec<String> {
    let mut chain: Vec<String> = Vec::new();
    let mut pid = start_ppid;
    for _ in 0..max_depth {
        if pid == PID_IDLE || pid == PID_SYSTEM {
            break;
        }
        let Some(h) = open_query_handle(pid) else {
            break;
        };
        let image = query_image_path(&h);
        if image.is_empty() {
            break;
        }
        chain.push(basename(&image));
        let Some(parent) = query_ppid(&h) else {
            break;
        };
        if parent == pid {
            break;
        }
        pid = parent;
    }
    chain.reverse();
    chain
}

/// Resolve the process token's primary user to `DOMAIN\username`. Empty
/// string on failure (token rights denied, account no longer exists, etc.).
pub fn query_user(pid: u32) -> String {
    let Some(proc_h) = open_query_handle(pid) else {
        return String::new();
    };

    let mut token: HANDLE = HANDLE::default();
    let res = unsafe { OpenProcessToken(proc_h.0, TOKEN_QUERY, &mut token) };
    if res.is_err() {
        return String::new();
    }
    let token = OwnedHandle(token);

    // Sizing call: TOKEN_USER is fixed-size but the trailing SID is
    // variable-length, so the kernel tells us the total.
    let mut len: u32 = 0;
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut len) };
    if len == 0 || (len as usize) > 64 * 1024 {
        return String::new();
    }

    let mut buf = vec![0u8; len as usize];
    let res = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut c_void),
            len,
            &mut len,
        )
    };
    if res.is_err() {
        return String::new();
    }

    // SAFETY: GetTokenInformation populated `buf` with a TOKEN_USER followed
    // by the variable-length SID. The struct's `Sid` field points into the
    // same allocation, valid until `buf` is dropped.
    let token_user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let sid = token_user.User.Sid;
    if sid.0.is_null() {
        return String::new();
    }

    // 256 wide chars covers DOMAIN\username well past UPN_LENGTH (1024 wide
    // chars worst-case for fully-qualified domain users). If a real
    // deployment surfaces an ERROR_INSUFFICIENT_BUFFER here we'll just emit
    // an empty user — acceptable for v0.x; the chain/cmdline/path are still
    // informative.
    let mut name_buf: Vec<u16> = vec![0; 256];
    let mut domain_buf: Vec<u16> = vec![0; 256];
    let mut name_len = name_buf.len() as u32;
    let mut domain_len = domain_buf.len() as u32;
    let mut sid_type = SID_NAME_USE::default();
    let res = unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain_buf.as_mut_ptr())),
            &mut domain_len,
            &mut sid_type,
        )
    };
    if res.is_err() {
        return String::new();
    }

    let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
    let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);
    if domain.is_empty() {
        name
    } else {
        format!("{domain}\\{name}")
    }
}

fn basename(path: &str) -> String {
    path.rsplit_once(|c| c == '\\' || c == '/')
        .map(|(_, base)| base.to_string())
        .unwrap_or_else(|| path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_strips_win32_path() {
        assert_eq!(basename(r"C:\Windows\System32\notepad.exe"), "notepad.exe");
        assert_eq!(basename(r"\Device\HarddiskVolume3\notepad.exe"), "notepad.exe");
        assert_eq!(basename("notepad.exe"), "notepad.exe");
        assert_eq!(basename(""), "");
    }

    /// Smoke test that runs against the test process itself. Only useful as
    /// a sanity check on the calling convention — full integration coverage
    /// lives in the daemon's collect-windows demo.
    #[test]
    fn enriches_self_process() {
        let pid = std::process::id();
        let cmdline = query_cmdline(pid);
        // The test runner's cmdline is unlikely to be empty.
        assert!(!cmdline.is_empty(), "expected own cmdline to be readable");
        let user = query_user(pid);
        assert!(!user.is_empty(), "expected own user to resolve");
        // parent_chain from our own PPID should produce at least one entry
        // (whatever spawned cargo test).
        let chain = parent_chain(get_own_ppid(), 16);
        assert!(!chain.is_empty(), "expected at least one ancestor");
    }

    fn get_own_ppid() -> u32 {
        let pid = std::process::id();
        let h = open_query_handle(pid).expect("open self");
        query_ppid(&h).expect("ppid of self")
    }

    #[test]
    fn ancestor_pids_returns_immediate_parent_first() {
        let chain = ancestor_pids(std::process::id(), 16);
        assert!(!chain.is_empty(), "expected at least one ancestor PID");
        // The first entry should be our direct parent, matching what
        // get_own_ppid returns.
        assert_eq!(chain[0], get_own_ppid());
    }
}
