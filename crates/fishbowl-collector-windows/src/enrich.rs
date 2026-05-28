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

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem;
use std::sync::OnceLock;

use fishbowl_schema::ParentChainEntry;
use windows::core::{PCWSTR, PWSTR};
use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, TokenIntegrityLevel, TokenUser, SID_NAME_USE,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{GetLogicalDriveStringsW, QueryDosDeviceW};
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

/// Fetch the integrity level of `pid`'s primary token, returning the schema
/// string form (`"low"`, `"medium"`, `"high"`, `"system"`). Returns `None`
/// when the process is gone, we can't open its token, or the SID's RID
/// doesn't match a documented integrity level.
///
/// Implementation:
///   - `OpenProcessToken(handle, TOKEN_QUERY)` — needs only QUERY rights
///     on the process (covered by the existing `open_query_handle`).
///   - `GetTokenInformation(token, TokenIntegrityLevel, ...)` returns a
///     `TOKEN_MANDATORY_LABEL` whose `Label.Sid` is the integrity SID.
///     The last sub-authority (RID) of that SID is the integrity level
///     constant.
///
/// The four documented RIDs (`SECURITY_MANDATORY_*_RID`):
///   0x1000 low, 0x2000 medium, 0x3000 high, 0x4000 system.
/// Anything else (untrusted, medium+, protected high) maps to `None` for
/// v0.x — the schema enum only carries the common four.
pub fn query_integrity_level(pid: u32) -> Option<String> {
    use windows::Win32::Security::{GetSidSubAuthority, GetSidSubAuthorityCount, PSID};

    let h = open_query_handle(pid)?;

    // OpenProcessToken with TOKEN_QUERY.
    let mut token: HANDLE = HANDLE::default();
    let ok = unsafe { OpenProcessToken(h.0, TOKEN_QUERY, &mut token) };
    if ok.is_err() || token.is_invalid() {
        return None;
    }
    let _token_guard = OwnedHandle(token);

    // Sized query — first call with zero buffer tells us required size.
    let mut needed: u32 = 0;
    let _ = unsafe {
        GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut needed)
    };
    if needed == 0 {
        return None;
    }
    let mut buf: Vec<u8> = vec![0u8; needed as usize];
    let mut written: u32 = 0;
    if unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(buf.as_mut_ptr() as *mut c_void),
            buf.len() as u32,
            &mut written,
        )
    }
    .is_err()
        || written == 0
    {
        return None;
    }

    // Cast the buffer to TOKEN_MANDATORY_LABEL and pull the RID from the SID's
    // last sub-authority.
    if (buf.len() as usize) < mem::size_of::<TOKEN_MANDATORY_LABEL>() {
        return None;
    }
    let tml = unsafe { &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
    let sid: PSID = tml.Label.Sid;
    if sid.0.is_null() {
        return None;
    }
    let count_ptr = unsafe { GetSidSubAuthorityCount(sid) };
    if count_ptr.is_null() {
        return None;
    }
    let count = unsafe { *count_ptr };
    if count == 0 {
        return None;
    }
    let rid_ptr = unsafe { GetSidSubAuthority(sid, (count - 1) as u32) };
    if rid_ptr.is_null() {
        return None;
    }
    let rid = unsafe { *rid_ptr };
    Some(integrity_rid_to_str(rid).to_string())
}

/// Map a mandatory-label SID RID to the schema enum string. Values from
/// `winnt.h` `SECURITY_MANDATORY_*_RID`. Anything outside the documented
/// four maps to `"unknown"` for visibility (rather than dropping the
/// field) — useful for noticing AppContainer / protected-process cases.
fn integrity_rid_to_str(rid: u32) -> &'static str {
    match rid {
        0x0000..=0x0FFF => "untrusted",
        0x1000..=0x1FFF => "low",
        0x2000..=0x2FFF => "medium",
        0x3000..=0x3FFF => "high",
        0x4000..=u32::MAX => "system",
    }
}

/// Build a map from NT device path (lowercased, no trailing separator) to
/// the Win32 drive letter (e.g. `\device\harddiskvolume9` → `C:`). Used to
/// rewrite ETW Kernel-File `FileName` values from NT-namespace form to a
/// human-readable drive-letter path. Built once on first use and cached.
fn drive_map() -> &'static HashMap<String, String> {
    static MAP: OnceLock<HashMap<String, String>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut out: HashMap<String, String> = HashMap::new();
        // GetLogicalDriveStringsW writes NUL-separated entries like
        // "A:\0C:\0D:\0\0". 512 is comfortably larger than any realistic
        // drive-list payload (each entry is 4 chars).
        let mut buf = vec![0u16; 512];
        let n = unsafe { GetLogicalDriveStringsW(Some(&mut buf)) } as usize;
        if n == 0 || n > buf.len() {
            return out;
        }
        for chunk in buf[..n].split(|&c| c == 0) {
            if chunk.is_empty() {
                continue;
            }
            // chunk is like "C:\". Strip the trailing "\" — QueryDosDeviceW
            // expects just "C:" without the separator.
            let letter_raw = String::from_utf16_lossy(chunk);
            let letter = letter_raw.trim_end_matches('\\').to_string();
            if letter.len() != 2 {
                continue;
            }
            let letter_wide: Vec<u16> = letter.encode_utf16().chain(std::iter::once(0)).collect();
            let mut dev_buf = vec![0u16; 1024];
            let dev_len = unsafe {
                QueryDosDeviceW(PCWSTR(letter_wide.as_ptr()), Some(&mut dev_buf))
            };
            if dev_len == 0 {
                continue;
            }
            // dev_buf contains the device path followed by a NUL. Trim.
            let dev = String::from_utf16_lossy(
                &dev_buf[..dev_len.saturating_sub(1).min(dev_buf.len() as u32) as usize],
            );
            let dev_key = dev.trim_end_matches('\0').trim_end_matches('\\').to_lowercase();
            if !dev_key.is_empty() {
                out.insert(dev_key, letter);
            }
        }
        out
    })
}

/// Rewrite an NT-namespace device path (`\Device\HarddiskVolume9\Users\...`)
/// to the equivalent Win32 drive-letter path (`C:\Users\...`). Returns the
/// input unchanged when no device prefix matches — covers paths that
/// already use drive letters, UNC paths, and unmapped devices.
///
/// Lowercase comparison; preserves the suffix's original case in output.
pub fn normalize_nt_path(nt_path: &str) -> String {
    if !nt_path.starts_with('\\') {
        return nt_path.to_string();
    }
    let lower = nt_path.to_lowercase();
    for (device, letter) in drive_map().iter() {
        if let Some(rest) = lower.strip_prefix(device.as_str()) {
            // Device prefix must be followed by `\` so we don't match
            // `\Device\HarddiskVolume9X` against `\Device\HarddiskVolume9`.
            if rest.starts_with('\\') {
                let suffix = &nt_path[device.len()..];
                return format!("{letter}{suffix}");
            }
        }
    }
    nt_path.to_string()
}

/// Look up the owner of a file on disk and return `DOMAIN\username`.
/// Used by the daemon to stamp `user_id` on transcript-derived events
/// (Claude Code / Codex JSONLs live in a user's home dir; the file
/// owner is therefore the user who launched the agent session).
///
/// Returns `None` when the path doesn't exist, the daemon lacks
/// permission to read its security descriptor, or the owner SID can't
/// be resolved to a name (e.g. SID belongs to a since-deleted account).
pub fn file_owner(path: &std::path::Path) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSID, PSECURITY_DESCRIPTOR,
    };

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut owner_sid: PSID = PSID::default();
    let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();

    let res = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            OBJECT_SECURITY_INFORMATION(OWNER_SECURITY_INFORMATION.0),
            Some(&mut owner_sid),
            None,
            None,
            None,
            &mut sd,
        )
    };
    if res.is_err() || owner_sid.0.is_null() {
        return None;
    }

    // Resolve SID -> "DOMAIN\name". The buffers are sized for typical
    // domain/user lengths; LookupAccountSidW returns the required size
    // in *_len on ERROR_INSUFFICIENT_BUFFER, but 256 covers every real
    // domain\username on a Windows host.
    let mut name = [0u16; 256];
    let mut domain = [0u16; 256];
    let mut name_len: u32 = name.len() as u32;
    let mut domain_len: u32 = domain.len() as u32;
    let mut sid_use: SID_NAME_USE = SID_NAME_USE::default();
    let ok = unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            owner_sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut sid_use,
        )
    };

    // GetNamedSecurityInfoW allocates the SECURITY_DESCRIPTOR; we have
    // to free it whether or not LookupAccountSidW succeeded.
    if !sd.0.is_null() {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sd.0 as *mut _)));
        }
    }
    if ok.is_err() {
        return None;
    }

    let name_str = String::from_utf16_lossy(&name[..name_len as usize]);
    let domain_str = String::from_utf16_lossy(&domain[..domain_len as usize]);
    if domain_str.is_empty() {
        Some(name_str)
    } else {
        Some(format!("{domain_str}\\{name_str}"))
    }
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

/// Walk PPIDs upward starting from `start_ppid`. Returns one
/// `ParentChainEntry` per ancestor in root → immediate-parent order,
/// capped at `max_depth` hops. The result excludes the caller's own
/// process to match the Linux collector's contract.
///
/// Stops on: hitting PID 0/4, a PPID self-loop, or `OpenProcess`
/// failing (likely a process that exited between hops — a normal race,
/// not an error).
pub fn parent_chain(start_ppid: u32, max_depth: usize) -> Vec<ParentChainEntry> {
    let mut chain: Vec<ParentChainEntry> = Vec::new();
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
        chain.push(ParentChainEntry {
            pid: pid as i32,
            name: basename(&image),
        });
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
