//! Read-only enumeration of processes running under the Windows sandbox identity.

#[cfg(windows)]
use std::io;

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SandboxIdentityMatch {
    /// The process primary user SID is the sandbox user SID.
    Yes,
    /// The process primary user SID was inspected and is not the sandbox user SID.
    No,
    /// The process primary user SID could not be inspected.
    Unknown,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UninspectableOwner {
    wts_sid_null: bool,
    token_error_code: Option<i32>,
}

#[cfg(windows)]
struct OwnedHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}

/// Enumerates every Windows session and reports processes whose primary user
/// SID is the sole user configured in the sandbox identity group.
///
/// WTS process records provide owner SIDs. If a record has no usable SID, its
/// process token is queried directly. Full session enumeration requires an
/// elevated Administrators token. Any incomplete session, group, or process
/// record is an error or an uninspectable process; callers must keep the
/// execution gate closed in either case.
#[cfg(windows)]
pub(crate) fn pids_with_sandbox_identity_group(
    group_name: &str,
    expected_user_sid: &[u8],
) -> io::Result<(Vec<u32>, usize)> {
    let (pids, uninspectable) = census_sandbox_identity_group(group_name, expected_user_sid)?;
    Ok((pids, uninspectable.len()))
}

#[cfg(windows)]
fn census_sandbox_identity_group(
    group_name: &str,
    expected_user_sid: &[u8],
) -> io::Result<(Vec<u32>, Vec<UninspectableOwner>)> {
    if expected_user_sid.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sandbox identity is unavailable",
        ));
    }
    if !current_process_is_elevated_admin()? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "complete process inspection requires an elevated token",
        ));
    }
    validate_sandbox_group_membership(group_name, expected_user_sid)?;

    let sessions = session_ids()?;
    let mut pids = Vec::new();
    let mut uninspectable = Vec::new();
    for session_id in sessions {
        let (session_pids, session_uninspectable) =
            pids_with_sandbox_user_in_session(session_id, expected_user_sid)?;
        pids.extend(session_pids);
        uninspectable.extend(session_uninspectable);
    }
    Ok((pids, uninspectable))
}

#[cfg(windows)]
fn current_process_is_elevated_admin() -> io::Result<bool> {
    codex_windows_sandbox::current_process_is_elevated()
        .map_err(|error| io::Error::other(error.to_string()))
}

#[cfg(windows)]
fn process_user_sid_from_token(process_id: u32) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

    match process_user_sid_from_token_inner(process_id) {
        Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
            if current_thread_has_impersonation_token()? {
                Err(error)
            } else {
                process_user_sid_from_token_with_debug_privilege(process_id)
            }
        }
        result => result,
    }
}

#[cfg(windows)]
fn current_thread_has_impersonation_token() -> io::Result<bool> {
    use windows_sys::Win32::Foundation::{ERROR_NO_TOKEN, GetLastError};
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    let mut token = std::ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0 {
        let _token = OwnedHandle(token);
        return Ok(true);
    }
    let error = unsafe { GetLastError() };
    if error == ERROR_NO_TOKEN {
        Ok(false)
    } else {
        Err(io::Error::from_raw_os_error(error as i32))
    }
}

#[cfg(windows)]
fn process_user_sid_from_token_inner(process_id: u32) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError};
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let _process = OwnedHandle(process);

    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _token = OwnedHandle(token);

    let mut needed = 0u32;
    let queried =
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
    let query_error = unsafe { GetLastError() };
    if queried != 0
        || query_error != ERROR_INSUFFICIENT_BUFFER
        || (needed as usize) < std::mem::size_of::<TOKEN_USER>()
    {
        return Err(if queried == 0 {
            io::Error::from_raw_os_error(query_error as i32)
        } else {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows process token returned an invalid user record",
            )
        });
    }

    let mut user_buffer = vec![0u8; needed as usize];
    let mut returned = 0u32;
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            user_buffer.as_mut_ptr().cast(),
            needed,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if (returned as usize) < std::mem::size_of::<TOKEN_USER>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows process token returned an incomplete user record",
        ));
    }

    // SAFETY: GetTokenInformation returned a complete TOKEN_USER record.
    let token_user = unsafe { std::ptr::read_unaligned(user_buffer.as_ptr().cast::<TOKEN_USER>()) };
    sid_bytes(token_user.User.Sid).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows process token returned an invalid user SID",
        )
    })
}

#[cfg(windows)]
fn process_user_sid_from_token_with_debug_privilege(process_id: u32) -> io::Result<Vec<u8>> {
    std::thread::Builder::new()
        .name("process-owner-inspection".to_owned())
        .spawn(move || process_user_sid_from_token_with_debug_privilege_on_thread(process_id))
        .map_err(io::Error::other)?
        .join()
        .map_err(|_| io::Error::other("process owner inspection thread panicked"))?
}

#[cfg(windows)]
fn process_user_sid_from_token_with_debug_privilege_on_thread(
    process_id: u32,
) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::{
        ERROR_NO_TOKEN, ERROR_NOT_ALL_ASSIGNED, ERROR_SUCCESS, GetLastError, LUID, SetLastError,
    };
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, DuplicateTokenEx, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
        SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED, SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenImpersonation,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken, SetThreadToken,
    };

    let mut thread_token = std::ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut thread_token) } != 0 {
        let _unexpected_token = OwnedHandle(thread_token);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "process owner inspection worker unexpectedly has an impersonation token",
        ));
    }
    let thread_token_error = unsafe { GetLastError() };
    if thread_token_error != ERROR_NO_TOKEN {
        return Err(io::Error::from_raw_os_error(thread_token_error as i32));
    }

    let mut process_token = std::ptr::null_mut();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY,
            &mut process_token,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let _process_token = OwnedHandle(process_token);

    let mut debug_token = std::ptr::null_mut();
    if unsafe {
        DuplicateTokenEx(
            process_token,
            TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE | TOKEN_QUERY,
            std::ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut debug_token,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let debug_token = OwnedHandle(debug_token);

    let mut privilege_luid = LUID::default();
    if unsafe { LookupPrivilegeValueW(std::ptr::null(), SE_DEBUG_NAME, &mut privilege_luid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let privilege = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: privilege_luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    unsafe { SetLastError(ERROR_SUCCESS) };
    if unsafe {
        AdjustTokenPrivileges(
            debug_token.0,
            0,
            &privilege,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let adjust_error = unsafe { GetLastError() };
    if adjust_error == ERROR_NOT_ALL_ASSIGNED {
        return Err(io::Error::from_raw_os_error(adjust_error as i32));
    }
    if adjust_error != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(adjust_error as i32));
    }

    if unsafe { SetThreadToken(std::ptr::null(), debug_token.0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = process_user_sid_from_token_inner(process_id);
    if unsafe { SetThreadToken(std::ptr::null(), std::ptr::null_mut()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // The duplicate token is discarded when this worker returns; the original
    // process token and its privilege state are never modified.
    result
}

#[cfg(windows)]
fn process_user_sid_from_wts_or_token(
    wts_sid: windows_sys::Win32::Security::PSID,
    process_id: u32,
    session_id: u32,
) -> io::Result<Vec<u8>> {
    if !wts_sid.is_null() {
        return sid_bytes(wts_sid).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows process enumeration returned an invalid owner SID",
            )
        });
    }
    if is_kernel_system_process(process_id, session_id) {
        return local_system_sid();
    }
    process_user_sid_from_token(process_id)
}

#[cfg(windows)]
fn is_kernel_system_process(process_id: u32, session_id: u32) -> bool {
    process_id == 4 && session_id == 0
}

#[cfg(windows)]
fn local_system_sid() -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, SECURITY_MAX_SID_SIZE, WinLocalSystemSid,
    };

    let mut buffer = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_size = buffer.len() as u32;
    if unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut sid_size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if sid_size == 0 || sid_size as usize > buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid well-known SID size",
        ));
    }
    let sid = sid_bytes(buffer.as_ptr().cast_mut().cast()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid well-known SID",
        )
    })?;
    if sid.len() != sid_size as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows well-known SID size did not match its record",
        ));
    }
    Ok(sid)
}

#[cfg(windows)]
fn validate_sandbox_group_membership(group_name: &str, expected_user_sid: &[u8]) -> io::Result<()> {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        LOCALGROUP_MEMBERS_INFO_2, MAX_PREFERRED_LENGTH, NERR_Success, NetApiBufferFree,
        NetLocalGroupGetMembers,
    };
    use windows_sys::Win32::Security::{IsValidSid, SidTypeUser};

    let group_name = group_name.encode_utf16().chain([0]).collect::<Vec<_>>();
    let mut resume_handle = 0usize;
    let mut member_sids = Vec::new();
    let mut expected_total = None;
    loop {
        let mut buffer = std::ptr::null_mut::<u8>();
        let mut entries_read = 0u32;
        let mut total_entries = 0u32;
        let previous_resume_handle = resume_handle;
        let status = unsafe {
            NetLocalGroupGetMembers(
                std::ptr::null(),
                group_name.as_ptr(),
                2,
                &mut buffer,
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            )
        };
        if status != NERR_Success && status != ERROR_MORE_DATA {
            if !buffer.is_null() {
                unsafe {
                    NetApiBufferFree(buffer.cast::<c_void>());
                }
            }
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if expected_total.is_none() {
            // NetLocalGroupGetMembers reports the entries available from the
            // current resume position. On the first call that is the complete
            // group, even if the API requires multiple pages.
            expected_total = Some(total_entries as usize);
        }

        let parsed = if entries_read > 0 && buffer.is_null() {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sandbox identity group membership is unavailable",
            ))
        } else {
            let entries = if entries_read == 0 {
                &[][..]
            } else {
                // SAFETY: NetLocalGroupGetMembers returns `entries_read` entries
                // of LOCALGROUP_MEMBERS_INFO_2 for level 2 in this buffer.
                unsafe {
                    std::slice::from_raw_parts(
                        buffer.cast::<LOCALGROUP_MEMBERS_INFO_2>(),
                        entries_read as usize,
                    )
                }
            };
            let mut result = Ok(());
            for entry in entries {
                if entry.lgrmi2_sidusage != SidTypeUser
                    || entry.lgrmi2_sid.is_null()
                    || unsafe { IsValidSid(entry.lgrmi2_sid) } == 0
                {
                    result = Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "sandbox identity group contains an unsupported member",
                    ));
                    break;
                }
                let Some(sid) = sid_bytes(entry.lgrmi2_sid) else {
                    result = Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "sandbox identity group member SID is unavailable",
                    ));
                    break;
                };
                member_sids.push(sid);
            }
            result
        };
        let free_status = if buffer.is_null() {
            NERR_Success
        } else {
            unsafe { NetApiBufferFree(buffer.cast::<c_void>()) }
        };
        if free_status != NERR_Success {
            return Err(io::Error::from_raw_os_error(free_status as i32));
        }
        parsed?;

        if status == NERR_Success {
            break;
        }
        if entries_read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sandbox identity group membership enumeration did not advance",
            ));
        }
        if resume_handle == previous_resume_handle {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sandbox identity group membership enumeration did not advance",
            ));
        }
    }

    if expected_total != Some(member_sids.len())
        || member_sids.len() != 1
        || member_sids[0].as_slice() != expected_user_sid
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sandbox identity group does not match the configured single identity",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn session_ids() -> io::Result<Vec<u32>> {
    use windows_sys::Win32::System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSEnumerateSessionsW, WTSFreeMemory,
        WTSListen,
    };

    let mut buffer = std::ptr::null_mut::<WTS_SESSION_INFOW>();
    let mut count = 0u32;
    if unsafe { WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut buffer, &mut count) }
        == 0
    {
        if !buffer.is_null() {
            unsafe { WTSFreeMemory(buffer.cast()) };
        }
        return Err(io::Error::last_os_error());
    }
    if count == 0 || buffer.is_null() {
        if !buffer.is_null() {
            unsafe { WTSFreeMemory(buffer.cast()) };
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows session enumeration returned no sessions",
        ));
    }

    // SAFETY: WTSEnumerateSessionsW returns `count` session records in this buffer.
    let records = unsafe { std::slice::from_raw_parts(buffer, count as usize) };
    let mut sessions = records
        .iter()
        .filter(|record| record.State != WTSListen)
        .map(|record| record.SessionId)
        .collect::<Vec<_>>();
    unsafe { WTSFreeMemory(buffer.cast()) };
    sessions.sort_unstable();
    sessions.dedup();
    if sessions.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows session enumeration returned no process sessions",
        ));
    }
    Ok(sessions)
}

#[cfg(windows)]
fn pids_with_sandbox_user_in_session(
    session_id: u32,
    expected_user_sid: &[u8],
) -> io::Result<(Vec<u32>, Vec<UninspectableOwner>)> {
    use windows_sys::Win32::System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTS_PROCESS_INFO_EXW, WTSEnumerateProcessesExW,
        WTSFreeMemoryExW, WTSTypeProcessInfoLevel1,
    };

    let mut level = 1u32;
    let mut buffer = std::ptr::null_mut::<u16>();
    let mut count = 0u32;
    if unsafe {
        WTSEnumerateProcessesExW(
            WTS_CURRENT_SERVER_HANDLE,
            &mut level,
            session_id,
            &mut buffer,
            &mut count,
        )
    } == 0
    {
        if !buffer.is_null() {
            unsafe {
                WTSFreeMemoryExW(WTSTypeProcessInfoLevel1, buffer.cast(), count);
            }
        }
        return Err(io::Error::last_os_error());
    }
    if level != 1 || (count > 0 && buffer.is_null()) {
        if !buffer.is_null() {
            unsafe {
                WTSFreeMemoryExW(WTSTypeProcessInfoLevel1, buffer.cast(), count);
            }
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows process enumeration returned an invalid record set",
        ));
    }

    let result = if count == 0 {
        Ok((Vec::new(), Vec::new()))
    } else {
        // SAFETY: WTSEnumerateProcessesExW at level 1 returns `count` records.
        let records = unsafe {
            std::slice::from_raw_parts(buffer.cast::<WTS_PROCESS_INFO_EXW>(), count as usize)
        };
        let mut pids = Vec::new();
        let mut uninspectable = Vec::new();
        let mut error = None;
        for record in records {
            if record.SessionId != session_id {
                error = Some(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Windows process record escaped its enumerated session",
                ));
                break;
            }
            if record.ProcessId == 0 {
                continue;
            }
            match process_user_sid_from_wts_or_token(
                record.pUserSid,
                record.ProcessId,
                record.SessionId,
            ) {
                Ok(process_sid) => {
                    match sandbox_identity_match(Some(&process_sid), expected_user_sid) {
                        SandboxIdentityMatch::Yes => pids.push(record.ProcessId),
                        SandboxIdentityMatch::No => {}
                        SandboxIdentityMatch::Unknown => uninspectable.push(UninspectableOwner {
                            wts_sid_null: record.pUserSid.is_null(),
                            token_error_code: None,
                        }),
                    }
                }
                Err(error) => uninspectable.push(UninspectableOwner {
                    wts_sid_null: record.pUserSid.is_null(),
                    token_error_code: error.raw_os_error(),
                }),
            }
        }
        match error {
            Some(error) => Err(error),
            None => Ok((pids, uninspectable)),
        }
    };
    if !buffer.is_null() {
        let free_status =
            unsafe { WTSFreeMemoryExW(WTSTypeProcessInfoLevel1, buffer.cast(), count) };
        if free_status == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    result
}

#[cfg(windows)]
fn sid_bytes(sid: windows_sys::Win32::Security::PSID) -> Option<Vec<u8>> {
    use windows_sys::Win32::Security::{GetLengthSid, IsValidSid, SECURITY_MAX_SID_SIZE};

    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return None;
    }
    let length = unsafe { GetLengthSid(sid) } as usize;
    if length == 0 || length > SECURITY_MAX_SID_SIZE as usize {
        return None;
    }
    // SAFETY: IsValidSid/GetLengthSid validated the OS-owned SID range.
    Some(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec())
}

#[cfg(windows)]
fn sandbox_identity_match(
    process_user_sid: Option<&[u8]>,
    expected_user_sid: &[u8],
) -> SandboxIdentityMatch {
    match process_user_sid {
        Some(sid) if sid == expected_user_sid => SandboxIdentityMatch::Yes,
        Some(_) => SandboxIdentityMatch::No,
        None => SandboxIdentityMatch::Unknown,
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::{SandboxIdentityMatch, sandbox_identity_match};

    #[test]
    fn process_owner_sid_is_matched_against_the_single_sandbox_identity() {
        let sandbox_sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let other_sid = [1, 1, 0, 0, 0, 0, 0, 5, 19, 0, 0, 0];
        assert_eq!(
            sandbox_identity_match(Some(&sandbox_sid), &sandbox_sid),
            SandboxIdentityMatch::Yes
        );
        assert_eq!(
            sandbox_identity_match(Some(&other_sid), &sandbox_sid),
            SandboxIdentityMatch::No
        );
        assert_eq!(
            sandbox_identity_match(None, &sandbox_sid),
            SandboxIdentityMatch::Unknown
        );
    }

    #[test]
    fn current_process_elevation_check_accepts_the_effective_token() {
        super::current_process_is_elevated_admin()
            .expect("CheckTokenMembership should accept the current effective token");
    }

    #[test]
    fn process_token_fallback_reads_the_current_process_owner_sid() {
        let process_id = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() };
        let user_sid = super::process_user_sid_from_token(process_id)
            .expect("current process owner SID should be readable from its primary token");

        assert!(!user_sid.is_empty());
    }

    #[test]
    fn missing_wts_owner_sid_falls_back_to_the_process_token() {
        let process_id = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() };
        let expected_sid = super::process_user_sid_from_token(process_id)
            .expect("current process owner SID should be readable from its primary token");
        let actual_sid =
            super::process_user_sid_from_wts_or_token(std::ptr::null_mut(), process_id, u32::MAX)
                .expect("missing WTS owner SID should use the process token");

        assert_eq!(actual_sid, expected_sid);
    }

    #[test]
    fn missing_system_process_sid_uses_the_well_known_system_identity() {
        let actual_sid = super::process_user_sid_from_wts_or_token(std::ptr::null_mut(), 4, 0)
            .expect("the protected System process has a well-known owner SID");
        let expected_sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

        assert_eq!(actual_sid, expected_sid);
        assert!(super::is_kernel_system_process(4, 0));
        assert!(!super::is_kernel_system_process(4, 1));
        assert!(!super::is_kernel_system_process(5, 0));
    }

    #[test]
    #[ignore = "requires a prepared Windows sandbox identity and elevated Administrator token"]
    fn live_process_census_enumerates_every_session_without_unknown_owners() {
        let sandbox_user_sid =
            codex_windows_sandbox::resolve_sid(codex_windows_sandbox::SANDBOX_USERNAME)
                .expect("prepared sandbox identity");
        let (pids, uninspectable) = super::census_sandbox_identity_group(
            codex_windows_sandbox::SANDBOX_USERS_GROUP,
            &sandbox_user_sid,
        )
        .expect("complete elevated process census");

        assert!(
            uninspectable.is_empty(),
            "complete process census must expose every process owner; diagnostics: {uninspectable:?}"
        );
        let unique_pids = pids.iter().collect::<std::collections::HashSet<_>>();
        assert_eq!(
            unique_pids.len(),
            pids.len(),
            "session enumeration must not duplicate process IDs"
        );
    }
}
