use crate::winutil::to_wide;
use anyhow::Result;
use anyhow::anyhow;
use std::ffi::c_void;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LUID;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::AdjustTokenPrivileges;
use windows_sys::Win32::Security::Authorization::EXPLICIT_ACCESS_W;
use windows_sys::Win32::Security::Authorization::GRANT_ACCESS;
use windows_sys::Win32::Security::Authorization::SetEntriesInAclW;
use windows_sys::Win32::Security::Authorization::TRUSTEE_IS_SID;
use windows_sys::Win32::Security::Authorization::TRUSTEE_IS_UNKNOWN;
use windows_sys::Win32::Security::Authorization::TRUSTEE_W;
use windows_sys::Win32::Security::CopySid;
use windows_sys::Win32::Security::CreateRestrictedToken;
use windows_sys::Win32::Security::CreateWellKnownSid;
use windows_sys::Win32::Security::GetLengthSid;
use windows_sys::Win32::Security::GetTokenInformation;
use windows_sys::Win32::Security::LookupPrivilegeValueW;
use windows_sys::Win32::Security::SetTokenInformation;

use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::Security::SID_AND_ATTRIBUTES;
use windows_sys::Win32::Security::TOKEN_ADJUST_DEFAULT;
use windows_sys::Win32::Security::TOKEN_ADJUST_PRIVILEGES;
use windows_sys::Win32::Security::TOKEN_ADJUST_SESSIONID;
use windows_sys::Win32::Security::TOKEN_ASSIGN_PRIMARY;
use windows_sys::Win32::Security::TOKEN_DUPLICATE;
use windows_sys::Win32::Security::TOKEN_PRIVILEGES;
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::Security::TOKEN_USER;
use windows_sys::Win32::Security::TokenDefaultDacl;
use windows_sys::Win32::Security::TokenGroups;
use windows_sys::Win32::Security::TokenUser;
use windows_sys::Win32::Security::WinLocalSystemSid;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

const DISABLE_MAX_PRIVILEGE: u32 = 0x01;
const LUA_TOKEN: u32 = 0x04;
const WRITE_RESTRICTED: u32 = 0x08;
const GENERIC_ALL: u32 = 0x1000_0000;
const WIN_WORLD_SID: i32 = 1;
const SE_GROUP_LOGON_ID: u32 = 0xC0000000;

#[repr(C)]
struct TokenDefaultDaclInfo {
    default_dacl: *mut ACL,
}

/// Sets a permissive default DACL so sandboxed processes can create pipes/IPC objects
/// without hitting ACCESS_DENIED when PowerShell builds pipelines.
unsafe fn set_default_dacl(h_token: HANDLE, sids: &[*mut c_void]) -> Result<()> {
    if sids.is_empty() {
        return Ok(());
    }
    let entries: Vec<EXPLICIT_ACCESS_W> = sids
        .iter()
        .map(|sid| EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: 0,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: *sid as *mut u16,
            },
        })
        .collect();
    let mut p_new_dacl: *mut ACL = std::ptr::null_mut();
    let res = SetEntriesInAclW(
        entries.len() as u32,
        entries.as_ptr(),
        std::ptr::null_mut(),
        &mut p_new_dacl,
    );
    if res != ERROR_SUCCESS {
        return Err(anyhow!("SetEntriesInAclW failed: {res}"));
    }
    let mut info = TokenDefaultDaclInfo {
        default_dacl: p_new_dacl,
    };
    let ok = SetTokenInformation(
        h_token,
        TokenDefaultDacl,
        &mut info as *mut _ as *mut c_void,
        std::mem::size_of::<TokenDefaultDaclInfo>() as u32,
    );
    if ok == 0 {
        let err = GetLastError();
        if !p_new_dacl.is_null() {
            LocalFree(p_new_dacl as HLOCAL);
        }
        return Err(anyhow!(
            "SetTokenInformation(TokenDefaultDacl) failed: {err}",
        ));
    }
    if !p_new_dacl.is_null() {
        LocalFree(p_new_dacl as HLOCAL);
    }
    Ok(())
}

unsafe fn well_known_sid(kind: i32) -> Result<Vec<u8>> {
    let mut size: u32 = 0;
    CreateWellKnownSid(kind, std::ptr::null_mut(), std::ptr::null_mut(), &mut size);
    let mut buf: Vec<u8> = vec![0u8; size as usize];
    let ok = CreateWellKnownSid(
        kind,
        std::ptr::null_mut(),
        buf.as_mut_ptr() as *mut c_void,
        &mut size,
    );
    if ok == 0 {
        return Err(anyhow!("CreateWellKnownSid failed: {}", GetLastError()));
    }
    Ok(buf)
}

pub unsafe fn world_sid() -> Result<Vec<u8>> {
    well_known_sid(WIN_WORLD_SID)
}

/// Restrict default ACLs for objects created by the elevated command runner to SYSTEM and its
/// logon session.
///
/// # Safety
/// Must run before the command runner creates worker threads or other child-visible objects.
pub unsafe fn restrict_current_token_default_dacl_to_logon_sid() -> Result<()> {
    let token = get_current_token_for_restriction()?;
    let result = (|| {
        let mut logon_sid = get_logon_sid_bytes(token)?;
        let mut system_sid = well_known_sid(WinLocalSystemSid)?;
        set_default_dacl(
            token,
            &[
                logon_sid.as_mut_ptr().cast(),
                system_sid.as_mut_ptr().cast(),
            ],
        )
    })();
    CloseHandle(token);
    result
}

/// # Safety
/// Caller is responsible for freeing the returned SID with `LocalFree`.
pub unsafe fn convert_string_sid_to_sid(s: &str) -> Option<*mut c_void> {
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSidToSidW(StringSid: *const u16, Sid: *mut *mut c_void) -> i32;
    }
    let mut psid: *mut c_void = std::ptr::null_mut();
    let ok = unsafe { ConvertStringSidToSidW(to_wide(s).as_ptr(), &mut psid) };
    if ok != 0 { Some(psid) } else { None }
}

/// Owns a SID allocated by `ConvertStringSidToSidW` and releases it with `LocalFree`.
pub struct LocalSid {
    psid: *mut c_void,
}

impl LocalSid {
    pub fn from_string(sid: &str) -> Result<Self> {
        let psid = unsafe { convert_string_sid_to_sid(sid) }
            .ok_or_else(|| anyhow!("invalid SID string: {sid}"))?;
        Ok(Self { psid })
    }

    pub fn as_ptr(&self) -> *mut c_void {
        self.psid
    }
}

impl Drop for LocalSid {
    fn drop(&mut self) {
        if !self.psid.is_null() {
            unsafe {
                LocalFree(self.psid as HLOCAL);
            }
        }
    }
}

/// # Safety
/// Caller must close the returned token handle.
pub unsafe fn get_current_token_for_restriction() -> Result<HANDLE> {
    let desired = TOKEN_DUPLICATE
        | TOKEN_QUERY
        | TOKEN_ASSIGN_PRIMARY
        | TOKEN_ADJUST_DEFAULT
        | TOKEN_ADJUST_SESSIONID
        | TOKEN_ADJUST_PRIVILEGES;
    let mut h: HANDLE = 0;
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(
            ProcessHandle: HANDLE,
            DesiredAccess: u32,
            TokenHandle: *mut HANDLE,
        ) -> i32;
    }
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), desired, &mut h) };
    if ok == 0 {
        return Err(anyhow!("OpenProcessToken failed: {}", GetLastError()));
    }
    Ok(h)
}

pub unsafe fn get_logon_sid_bytes(h_token: HANDLE) -> Result<Vec<u8>> {
    unsafe fn scan_token_groups_for_logon(h: HANDLE) -> Option<Vec<u8>> {
        let mut needed: u32 = 0;
        GetTokenInformation(h, TokenGroups, std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            return None;
        }
        let mut buf: Vec<u8> = vec![0u8; needed as usize];
        let ok = GetTokenInformation(
            h,
            TokenGroups,
            buf.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        );
        if ok == 0 || (needed as usize) < std::mem::size_of::<u32>() {
            return None;
        }
        let group_count = std::ptr::read_unaligned(buf.as_ptr() as *const u32) as usize;
        // TOKEN_GROUPS layout is: DWORD GroupCount; SID_AND_ATTRIBUTES Groups[];
        // On 64-bit, Groups is aligned to pointer alignment after 4-byte GroupCount.
        let after_count = unsafe { buf.as_ptr().add(std::mem::size_of::<u32>()) } as usize;
        let align = std::mem::align_of::<SID_AND_ATTRIBUTES>();
        let aligned = (after_count + (align - 1)) & !(align - 1);
        let groups_ptr = aligned as *const SID_AND_ATTRIBUTES;
        for i in 0..group_count {
            let entry: SID_AND_ATTRIBUTES = std::ptr::read_unaligned(groups_ptr.add(i));
            if (entry.Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID {
                let sid = entry.Sid;
                let sid_len = GetLengthSid(sid);
                if sid_len == 0 {
                    return None;
                }
                let mut out = vec![0u8; sid_len as usize];
                if CopySid(sid_len, out.as_mut_ptr() as *mut c_void, sid) == 0 {
                    return None;
                }
                return Some(out);
            }
        }
        None
    }

    if let Some(v) = scan_token_groups_for_logon(h_token) {
        return Ok(v);
    }

    #[repr(C)]
    struct TOKEN_LINKED_TOKEN {
        linked_token: HANDLE,
    }
    const TOKEN_LINKED_TOKEN_CLASS: i32 = 19; // TokenLinkedToken
    let mut ln_needed: u32 = 0;
    GetTokenInformation(
        h_token,
        TOKEN_LINKED_TOKEN_CLASS,
        std::ptr::null_mut(),
        0,
        &mut ln_needed,
    );
    if ln_needed >= std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32 {
        let mut ln_buf: Vec<u8> = vec![0u8; ln_needed as usize];
        let ok = GetTokenInformation(
            h_token,
            TOKEN_LINKED_TOKEN_CLASS,
            ln_buf.as_mut_ptr() as *mut c_void,
            ln_needed,
            &mut ln_needed,
        );
        if ok != 0 {
            let lt: TOKEN_LINKED_TOKEN =
                std::ptr::read_unaligned(ln_buf.as_ptr() as *const TOKEN_LINKED_TOKEN);
            if lt.linked_token != 0 {
                let res = scan_token_groups_for_logon(lt.linked_token);
                CloseHandle(lt.linked_token);
                if let Some(v) = res {
                    return Ok(v);
                }
            }
        }
    }

    Err(anyhow!("Logon SID not present on token"))
}

/// Returns a copy of the user SID from a token.
///
/// # Safety
/// `h_token` must be a valid token handle with `TOKEN_QUERY` access.
pub(crate) unsafe fn get_user_sid_bytes(h_token: HANDLE) -> Result<Vec<u8>> {
    let mut needed: u32 = 0;
    GetTokenInformation(h_token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    if needed == 0 {
        return Err(anyhow!("TokenUser size query returned 0"));
    }
    let mut user_buf: Vec<u8> = vec![0u8; needed as usize];
    let ok = GetTokenInformation(
        h_token,
        TokenUser,
        user_buf.as_mut_ptr() as *mut c_void,
        needed,
        &mut needed,
    );
    if ok == 0 || (needed as usize) < std::mem::size_of::<TOKEN_USER>() {
        return Err(anyhow!(
            "GetTokenInformation(TokenUser) failed: {}",
            GetLastError()
        ));
    }
    let token_user: TOKEN_USER = std::ptr::read_unaligned(user_buf.as_ptr() as *const TOKEN_USER);
    let sid_len = GetLengthSid(token_user.User.Sid);
    if sid_len == 0 {
        return Err(anyhow!(
            "GetLengthSid(TokenUser) failed: {}",
            GetLastError()
        ));
    }
    let mut user_sid_bytes = vec![0u8; sid_len as usize];
    if CopySid(
        sid_len,
        user_sid_bytes.as_mut_ptr() as *mut c_void,
        token_user.User.Sid,
    ) == 0
    {
        return Err(anyhow!("CopySid(TokenUser) failed: {}", GetLastError()));
    }
    Ok(user_sid_bytes)
}

unsafe fn enable_single_privilege(h_token: HANDLE, name: &str) -> Result<()> {
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    let ok = LookupPrivilegeValueW(std::ptr::null(), to_wide(name).as_ptr(), &mut luid);
    if ok == 0 {
        return Err(anyhow!("LookupPrivilegeValueW failed: {}", GetLastError()));
    }
    let mut tp: TOKEN_PRIVILEGES = std::mem::zeroed();
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = 0x00000002; // SE_PRIVILEGE_ENABLED
    let ok2 = AdjustTokenPrivileges(
        h_token,
        0,
        &tp,
        0,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    if ok2 == 0 {
        return Err(anyhow!("AdjustTokenPrivileges failed: {}", GetLastError()));
    }
    let err = GetLastError();
    if err != 0 {
        return Err(anyhow!("AdjustTokenPrivileges error {err}"));
    }
    Ok(())
}

/// # Safety
/// Caller must close the returned token handle.
pub unsafe fn create_readonly_token_with_cap(
    psid_capability: *mut c_void,
) -> Result<(HANDLE, *mut c_void)> {
    let base = get_current_token_for_restriction()?;
    let res = create_readonly_token_with_cap_from(base, psid_capability);
    CloseHandle(base);
    res
}

/// # Safety
/// Caller must close the returned token handle; base_token must be a valid primary token.
pub unsafe fn create_readonly_token_with_cap_from(
    base_token: HANDLE,
    psid_capability: *mut c_void,
) -> Result<(HANDLE, *mut c_void)> {
    let new_token = create_token_with_caps_from(
        base_token,
        &[psid_capability],
        /*disable_logon_sid*/ false,
        /*restrict_reads*/ false,
    )?;
    Ok((new_token, psid_capability))
}

/// Create a restricted token that includes all provided capability SIDs.
///
/// # Safety
/// Caller must close the returned token handle; base_token must be a valid primary token.
pub unsafe fn create_workspace_write_token_with_caps_from(
    base_token: HANDLE,
    psid_capabilities: &[*mut c_void],
) -> Result<HANDLE> {
    create_token_with_caps_from(
        base_token,
        psid_capabilities,
        /*disable_logon_sid*/ false,
        /*restrict_reads*/ false,
    )
}

/// Create a write-restricted token for the elevated sandbox backend.
///
/// The dedicated sandbox account remains the token user for account-scoped network policy, but it
/// must not participate in the restricting access check. Otherwise a stale account ACE can bypass
/// the active-root capability boundary.
///
/// # Safety
/// Caller must close the returned token handle; base_token must be a valid primary token.
pub unsafe fn create_elevated_workspace_write_token_with_caps_from(
    base_token: HANDLE,
    psid_capabilities: &[*mut c_void],
) -> Result<HANDLE> {
    create_token_with_caps_from(
        base_token,
        psid_capabilities,
        /*disable_logon_sid*/ true,
        /*restrict_reads*/ false,
    )
}

/// Create a restricted token that includes all provided capability SIDs.
///
/// # Safety
/// Caller must close the returned token handle; base_token must be a valid primary token.
pub unsafe fn create_readonly_token_with_caps_from(
    base_token: HANDLE,
    psid_capabilities: &[*mut c_void],
) -> Result<HANDLE> {
    create_token_with_caps_from(
        base_token,
        psid_capabilities,
        /*disable_logon_sid*/ false,
        /*restrict_reads*/ false,
    )
}

/// Create a read-only token for the elevated sandbox backend.
///
/// The sandbox account remains the token user for account-scoped network policy, but only active
/// capability SIDs may satisfy the restricting access check.
///
/// # Safety
/// Caller must close the returned token handle; base_token must be a valid primary token.
pub unsafe fn create_elevated_readonly_token_with_caps_from(
    base_token: HANDLE,
    psid_capabilities: &[*mut c_void],
) -> Result<HANDLE> {
    create_token_with_caps_from(
        base_token,
        psid_capabilities,
        /*disable_logon_sid*/ true,
        /*restrict_reads*/ false,
    )
}

unsafe fn create_token_with_caps_from(
    base_token: HANDLE,
    psid_capabilities: &[*mut c_void],
    disable_logon_sid: bool,
    restrict_reads: bool,
) -> Result<HANDLE> {
    if psid_capabilities.is_empty() {
        return Err(anyhow!("no capability SIDs provided"));
    }
    let mut logon_sid_bytes = get_logon_sid_bytes(base_token)?;
    let psid_logon = logon_sid_bytes.as_mut_ptr() as *mut c_void;
    let mut everyone = world_sid()?;
    let psid_everyone = everyone.as_mut_ptr() as *mut c_void;
    let mut entries: Vec<SID_AND_ATTRIBUTES> =
        vec![std::mem::zeroed(); psid_capabilities.len() + 2];
    for (i, psid) in psid_capabilities.iter().enumerate() {
        entries[i].Sid = *psid;
        entries[i].Attributes = 0;
    }
    let logon_idx = psid_capabilities.len();
    entries[logon_idx].Sid = psid_logon;
    entries[logon_idx].Attributes = 0;
    entries[logon_idx + 1].Sid = psid_everyone;
    entries[logon_idx + 1].Attributes = 0;
    let mut disabled_sids = if disable_logon_sid {
        vec![SID_AND_ATTRIBUTES {
            Sid: psid_logon,
            Attributes: 0,
        }]
    } else {
        Vec::new()
    };

    let mut new_token: HANDLE = 0;
    let flags =
        DISABLE_MAX_PRIVILEGE | LUA_TOKEN | if restrict_reads { 0 } else { WRITE_RESTRICTED };
    let ok = CreateRestrictedToken(
        base_token,
        flags,
        disabled_sids.len() as u32,
        if disabled_sids.is_empty() {
            std::ptr::null()
        } else {
            disabled_sids.as_mut_ptr()
        },
        0,
        std::ptr::null(),
        entries.len() as u32,
        entries.as_mut_ptr(),
        &mut new_token,
    );
    if ok == 0 {
        return Err(anyhow!("CreateRestrictedToken failed: {}", GetLastError()));
    }

    let mut dacl_sids: Vec<*mut c_void> = Vec::with_capacity(psid_capabilities.len() + 2);
    dacl_sids.push(psid_logon);
    dacl_sids.push(psid_everyone);
    dacl_sids.extend_from_slice(psid_capabilities);
    set_default_dacl(new_token, &dacl_sids)?;

    enable_single_privilege(new_token, "SeChangeNotifyPrivilege")?;
    Ok(new_token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::EqualSid;
    use windows_sys::Win32::Security::TOKEN_GROUPS;
    use windows_sys::Win32::Security::TokenRestrictedSids;

    type ElevatedTokenFactory = unsafe fn(HANDLE, &[*mut c_void]) -> Result<HANDLE>;

    unsafe fn token_has_restricting_sid(token: HANDLE, sid: *mut c_void) -> Result<bool> {
        let mut needed = 0;
        GetTokenInformation(
            token,
            TokenRestrictedSids,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
        if needed == 0 {
            return Err(anyhow!("TokenRestrictedSids size query returned 0"));
        }

        let mut buffer = vec![0u8; needed as usize];
        if GetTokenInformation(
            token,
            TokenRestrictedSids,
            buffer.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        ) == 0
        {
            return Err(anyhow!(
                "GetTokenInformation(TokenRestrictedSids) failed: {}",
                GetLastError()
            ));
        }

        let groups = buffer.as_ptr() as *const TOKEN_GROUPS;
        let entries = std::ptr::addr_of!((*groups).Groups) as *const SID_AND_ATTRIBUTES;
        for index in 0..(*groups).GroupCount as usize {
            if EqualSid((*entries.add(index)).Sid, sid) != 0 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    unsafe fn assert_capability_is_restricting_but_user_is_not(factory: ElevatedTokenFactory) {
        let cap = LocalSid::from_string("S-1-5-21-1-2-3-1001").expect("synthetic capability SID");
        let base = get_current_token_for_restriction().expect("open base token");
        let user_sid_bytes = get_user_sid_bytes(base).expect("read base token user SID");
        let user_sid = user_sid_bytes.as_ptr() as *mut c_void;
        let token = factory(base, &[cap.as_ptr()]);
        CloseHandle(base);
        let token = token.expect("create elevated restricted token");

        assert!(
            token_has_restricting_sid(token, cap.as_ptr()).expect("inspect capability SID"),
            "active capability SID must participate in the restricting access check"
        );
        assert!(
            !token_has_restricting_sid(token, user_sid).expect("inspect sandbox user SID"),
            "sandbox user SID must not bypass the active capability boundary"
        );
        CloseHandle(token);
    }

    #[test]
    fn elevated_tokens_do_not_restrict_with_sandbox_user_sid() {
        unsafe {
            assert_capability_is_restricting_but_user_is_not(
                create_elevated_readonly_token_with_caps_from,
            );
            assert_capability_is_restricting_but_user_is_not(
                create_elevated_workspace_write_token_with_caps_from,
            );
        }
    }
}
