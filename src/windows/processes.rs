//! Read-only enumeration of processes running under the Windows sandbox identity.

#[cfg(windows)]
use std::io;

/// How a process token relates to the sandbox identity.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SandboxIdentityMatch {
    /// The token belongs to the sandbox identity group.
    Yes,
    /// The token was inspected and does not belong to the sandbox identity.
    No,
    /// The caller cannot inspect this process token.
    Unknown,
}

/// Returns the process IDs whose token contains `group_sid`, plus the count of
/// processes this caller could not inspect.
///
/// The lookup is read-only. It never opens a process for termination and never
/// mutates any state, so it can run before a repair decision is made.
#[cfg(windows)]
pub(crate) fn pids_with_token_group(group_sid: &[u8]) -> io::Result<(Vec<u32>, usize)> {
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_NO_MORE_FILES, GetLastError, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };

    if group_sid.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sandbox identity is unavailable",
        ));
    }
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let mut pids = Vec::new();
    let mut uninspectable = 0usize;
    let result = (|| -> io::Result<()> {
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if unsafe { Process32FirstW(snapshot, &mut entry) } == 0 {
            return Err(io::Error::last_os_error());
        }
        loop {
            let pid = entry.th32ProcessID;
            if pid != 0 {
                match process_identity_match(pid, group_sid)? {
                    SandboxIdentityMatch::Yes => pids.push(pid),
                    SandboxIdentityMatch::No => {}
                    SandboxIdentityMatch::Unknown => uninspectable += 1,
                }
            }
            if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
                if unsafe { GetLastError() } != ERROR_NO_MORE_FILES {
                    return Err(io::Error::last_os_error());
                }
                break;
            }
        }
        Ok(())
    })();
    unsafe {
        CloseHandle(snapshot);
    }
    result.map(|()| (pids, uninspectable))
}

#[cfg(windows)]
fn process_identity_match(pid: u32, group_sid: &[u8]) -> io::Result<SandboxIdentityMatch> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Ok(SandboxIdentityMatch::Unknown);
    }
    let mut token: HANDLE = std::ptr::null_mut();
    let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    if opened == 0 {
        unsafe {
            CloseHandle(process);
        }
        return Ok(SandboxIdentityMatch::Unknown);
    }
    let matched = unsafe { token_contains_group(token, group_sid) };
    unsafe {
        CloseHandle(token);
        CloseHandle(process);
    }
    Ok(match matched {
        Some(true) => SandboxIdentityMatch::Yes,
        Some(false) => SandboxIdentityMatch::No,
        None => SandboxIdentityMatch::Unknown,
    })
}

/// # Safety
/// `token` must be a valid token handle with `TOKEN_QUERY` access.
#[cfg(windows)]
unsafe fn token_contains_group(
    token: windows_sys::Win32::Foundation::HANDLE,
    group_sid: &[u8],
) -> Option<bool> {
    use std::ffi::c_void;
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, SID_AND_ATTRIBUTES, TokenGroups,
    };

    let mut needed: u32 = 0;
    unsafe {
        GetTokenInformation(token, TokenGroups, std::ptr::null_mut(), 0, &mut needed);
    }
    if (needed as usize) < std::mem::size_of::<u32>() {
        return None;
    }
    let mut buffer = vec![0u8; needed as usize];
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenGroups,
            buffer.as_mut_ptr().cast::<c_void>(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 || (needed as usize) < std::mem::size_of::<u32>() {
        return None;
    }
    let group_count = u32::from_ne_bytes(buffer.get(0..4)?.try_into().ok()?) as usize;
    let buffer_start = buffer.as_ptr() as usize;
    let buffer_end = buffer_start.checked_add(buffer.len())?;
    let after_count = buffer_start.checked_add(std::mem::size_of::<u32>())?;
    let align = std::mem::align_of::<SID_AND_ATTRIBUTES>();
    let aligned = after_count.checked_add(align - 1)? & !(align - 1);
    let groups_end =
        aligned.checked_add(group_count.checked_mul(std::mem::size_of::<SID_AND_ATTRIBUTES>())?)?;
    if aligned < buffer_start || groups_end > buffer_end {
        return None;
    }
    let groups = aligned as *const SID_AND_ATTRIBUTES;
    for index in 0..group_count {
        let entry = unsafe { std::ptr::read_unaligned(groups.add(index)) };
        if entry.Sid.is_null() {
            continue;
        }
        let matched = unsafe { EqualSid(entry.Sid, group_sid.as_ptr() as *mut c_void) };
        if matched != 0 {
            return Some(true);
        }
    }
    Some(false)
}
