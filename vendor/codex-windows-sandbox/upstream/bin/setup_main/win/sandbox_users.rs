use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand::RngCore;
use rand::SeedableRng;
use rand::rngs::SmallRng;
use serde::Serialize;
use std::ffi::OsStr;
use std::ffi::c_void;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::Foundation::GENERIC_WRITE;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::NetworkManagement::NetManagement::LOCALGROUP_INFO_1;
use windows_sys::Win32::NetworkManagement::NetManagement::LOCALGROUP_MEMBERS_INFO_3;
use windows_sys::Win32::NetworkManagement::NetManagement::NERR_Success;
use windows_sys::Win32::NetworkManagement::NetManagement::NetLocalGroupAdd;
use windows_sys::Win32::NetworkManagement::NetManagement::NetLocalGroupAddMembers;
use windows_sys::Win32::NetworkManagement::NetManagement::NetLocalGroupDel;
use windows_sys::Win32::NetworkManagement::NetManagement::NetUserAdd;
use windows_sys::Win32::NetworkManagement::NetManagement::NetUserDel;
use windows_sys::Win32::NetworkManagement::NetManagement::NetUserSetInfo;
use windows_sys::Win32::NetworkManagement::NetManagement::UF_DONT_EXPIRE_PASSWD;
use windows_sys::Win32::NetworkManagement::NetManagement::UF_SCRIPT;
use windows_sys::Win32::NetworkManagement::NetManagement::USER_INFO_1;
use windows_sys::Win32::NetworkManagement::NetManagement::USER_INFO_1003;
use windows_sys::Win32::NetworkManagement::NetManagement::USER_PRIV_USER;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::Authorization::SDDL_REVISION_1;
use windows_sys::Win32::Security::CopySid;
use windows_sys::Win32::Security::GetLengthSid;
use windows_sys::Win32::Security::LookupAccountNameW;
use windows_sys::Win32::Security::LookupAccountSidW;
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Security::SID_NAME_USE;
use windows_sys::Win32::Storage::FileSystem::CREATE_NEW;
use windows_sys::Win32::Storage::FileSystem::CreateFileW;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
use windows_sys::Win32::System::Registry::HKEY;
use windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE;
use windows_sys::Win32::System::Registry::KEY_WRITE;
use windows_sys::Win32::System::Registry::REG_OPTION_NON_VOLATILE;
use windows_sys::Win32::System::Registry::RegCloseKey;
use windows_sys::Win32::System::Registry::RegCreateKeyExW;
use windows_sys::Win32::System::Registry::RegDeleteValueW;

use codex_windows_sandbox::SANDBOX_USERS_GROUP;
use codex_windows_sandbox::SETUP_VERSION;
use codex_windows_sandbox::SetupErrorCode;
use codex_windows_sandbox::SetupFailure;
use codex_windows_sandbox::dpapi_protect;
use codex_windows_sandbox::sandbox_dir;
use codex_windows_sandbox::sandbox_secrets_dir;
use codex_windows_sandbox::string_from_sid_bytes;
use codex_windows_sandbox::to_wide;

const LEGACY_SANDBOX_USERNAMES: &[&str] = &["RunSealSandboxOffline", "RunSealSandboxOnline"];
const LEGACY_SANDBOX_NETWORK_GROUP: &str = "RunSealSandboxNetwork";
const SANDBOX_USERS_GROUP_COMMENT: &str = "RunSeal sandbox internal group (managed)";
const NERR_GROUP_NOT_FOUND: u32 = 2220;
const NERR_USER_NOT_FOUND: u32 = 2221;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const USERLIST_KEY_PATH: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList";

pub fn legacy_sandbox_usernames() -> &'static [&'static str] {
    LEGACY_SANDBOX_USERNAMES
}
const SID_ADMINISTRATORS: &str = "S-1-5-32-544";
const SID_USERS: &str = "S-1-5-32-545";
const SID_AUTHENTICATED_USERS: &str = "S-1-5-11";
const SID_EVERYONE: &str = "S-1-1-0";
const SID_SYSTEM: &str = "S-1-5-18";

pub fn ensure_sandbox_users_group(log: &mut dyn Write) -> Result<()> {
    remove_legacy_sandbox_network_group(log)?;
    ensure_local_group(SANDBOX_USERS_GROUP, SANDBOX_USERS_GROUP_COMMENT, log)
}

fn remove_legacy_sandbox_network_group(log: &mut dyn Write) -> Result<()> {
    let name = to_wide(LEGACY_SANDBOX_NETWORK_GROUP);
    let status = unsafe { NetLocalGroupDel(std::ptr::null(), name.as_ptr()) };
    if status == 0 {
        super::log_line(
            log,
            &format!("removed legacy local group {LEGACY_SANDBOX_NETWORK_GROUP}"),
        )?;
        return Ok(());
    }
    if status == NERR_GROUP_NOT_FOUND {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "NetLocalGroupDel failed for {LEGACY_SANDBOX_NETWORK_GROUP} code {status}"
    ))
}

pub fn resolve_sandbox_users_group_sid() -> Result<Vec<u8>> {
    resolve_sid(SANDBOX_USERS_GROUP)
}

pub fn provision_sandbox_users(
    codex_home: &Path,
    sandbox_username: &str,
    log: &mut dyn Write,
) -> Result<()> {
    ensure_sandbox_users_group(log)?;
    super::log_line(
        log,
        &format!("ensuring single sandbox user {sandbox_username}"),
    )?;
    let sandbox_password = random_password();
    ensure_sandbox_user(sandbox_username, &sandbox_password, log)?;
    write_secrets(codex_home, sandbox_username, &sandbox_password)?;
    Ok(())
}

pub fn cleanup_legacy_sandbox_state(codex_home: &Path, log: &mut dyn Write) -> Result<()> {
    remove_legacy_state_file(
        &sandbox_secrets_dir(codex_home).join("sandbox_users.json"),
        log,
    )?;
    remove_legacy_state_file(&sandbox_dir(codex_home).join("setup_marker.json"), log)?;
    remove_legacy_state_file(&sandbox_dir(codex_home).join("sandbox_users.json"), log)?;
    remove_legacy_hidden_user_entries(log)?;
    for username in LEGACY_SANDBOX_USERNAMES {
        delete_legacy_user(username, log)?;
    }
    Ok(())
}

fn remove_legacy_state_file(path: &Path, log: &mut dyn Write) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            super::log_line(
                log,
                &format!("removed legacy sandbox state file {}", path.display()),
            )?;
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperLegacyUserCleanupFailed,
            format!(
                "remove legacy sandbox state file {} failed: {err}",
                path.display()
            ),
        ))),
    }
}

fn delete_legacy_user(username: &str, log: &mut dyn Write) -> Result<()> {
    let username_w = to_wide(OsStr::new(username));
    let status = unsafe { NetUserDel(std::ptr::null(), username_w.as_ptr()) };
    if status == NERR_Success {
        super::log_line(log, &format!("deleted legacy sandbox user {username}"))?;
        return Ok(());
    }
    if status == NERR_USER_NOT_FOUND {
        super::log_line(log, &format!("legacy sandbox user {username} absent"))?;
        return Ok(());
    }
    Err(anyhow::Error::new(SetupFailure::new(
        SetupErrorCode::HelperLegacyUserCleanupFailed,
        format!(
            "delete legacy sandbox user {username} failed with code {status}; close processes running as that user and rerun setup"
        ),
    )))
}

fn remove_legacy_hidden_user_entries(log: &mut dyn Write) -> Result<()> {
    let key = create_userlist_key_for_cleanup()?;
    for username in LEGACY_SANDBOX_USERNAMES {
        let username_w = to_wide(OsStr::new(username));
        let status = unsafe { RegDeleteValueW(key, username_w.as_ptr()) };
        if status == 0 {
            super::log_line(
                log,
                &format!("removed legacy UserList entry for {username}"),
            )?;
        } else if status == ERROR_FILE_NOT_FOUND {
            super::log_line(log, &format!("legacy UserList entry for {username} absent"))?;
        } else {
            unsafe {
                RegCloseKey(key);
            }
            return Err(anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperLegacyUserCleanupFailed,
                format!("remove legacy UserList entry for {username} failed with code {status}"),
            )));
        }
    }
    unsafe {
        RegCloseKey(key);
    }
    Ok(())
}

fn create_userlist_key_for_cleanup() -> Result<HKEY> {
    let key_path = to_wide(USERLIST_KEY_PATH);
    let mut key: HKEY = 0;
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            key_path.as_ptr(),
            0,
            std::ptr::null_mut(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            std::ptr::null_mut(),
            &mut key,
            std::ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperLegacyUserCleanupFailed,
            format!("open Winlogon UserList for legacy cleanup failed with code {status}"),
        )));
    }
    Ok(key)
}

pub fn ensure_sandbox_user(username: &str, password: &str, log: &mut dyn Write) -> Result<()> {
    ensure_local_user(username, password, log)?;
    ensure_local_group_member(SANDBOX_USERS_GROUP, username)?;
    Ok(())
}

pub fn ensure_local_user(name: &str, password: &str, log: &mut dyn Write) -> Result<()> {
    let name_w = to_wide(OsStr::new(name));
    let pwd_w = to_wide(OsStr::new(password));
    unsafe {
        let info = USER_INFO_1 {
            usri1_name: name_w.as_ptr() as *mut u16,
            usri1_password: pwd_w.as_ptr() as *mut u16,
            usri1_password_age: 0,
            usri1_priv: USER_PRIV_USER,
            usri1_home_dir: std::ptr::null_mut(),
            usri1_comment: std::ptr::null_mut(),
            usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD,
            usri1_script_path: std::ptr::null_mut(),
        };
        let status = NetUserAdd(
            std::ptr::null(),
            1,
            &info as *const _ as *mut u8,
            std::ptr::null_mut(),
        );
        if status != NERR_Success {
            // Try update password via level 1003.
            let pw_info = USER_INFO_1003 {
                usri1003_password: pwd_w.as_ptr() as *mut u16,
            };
            let upd = NetUserSetInfo(
                std::ptr::null(),
                name_w.as_ptr(),
                1003,
                &pw_info as *const _ as *mut u8,
                std::ptr::null_mut(),
            );
            if upd != NERR_Success {
                super::log_line(log, &format!("NetUserSetInfo failed for {name} code {upd}"))?;
                return Err(anyhow::Error::new(SetupFailure::new(
                    SetupErrorCode::HelperUserCreateOrUpdateFailed,
                    format!("failed to create/update user {name}, code {status}/{upd}"),
                )));
            }
        }

        // Ensure the principal is a regular local user account.
        if let Ok(group_name) = lookup_account_name_for_sid(SID_USERS) {
            let group = to_wide(OsStr::new(&group_name));
            let member = LOCALGROUP_MEMBERS_INFO_3 {
                lgrmi3_domainandname: name_w.as_ptr() as *mut u16,
            };
            let _ = NetLocalGroupAddMembers(
                std::ptr::null(),
                group.as_ptr(),
                3,
                &member as *const _ as *mut u8,
                1,
            );
        } else {
            super::log_line(
                log,
                "LookupAccountSidW failed for Users SID; skipping Users group membership",
            )?;
        }
    }
    Ok(())
}

pub fn ensure_local_group(name: &str, comment: &str, log: &mut dyn Write) -> Result<()> {
    const ERROR_ALIAS_EXISTS: u32 = 1379;
    const NERR_GROUP_EXISTS: u32 = 2223;

    let name_w = to_wide(OsStr::new(name));
    let comment_w = to_wide(OsStr::new(comment));
    unsafe {
        let info = LOCALGROUP_INFO_1 {
            lgrpi1_name: name_w.as_ptr() as *mut u16,
            lgrpi1_comment: comment_w.as_ptr() as *mut u16,
        };
        let mut parm_err: u32 = 0;
        let status = NetLocalGroupAdd(
            std::ptr::null(),
            1,
            &info as *const _ as *mut u8,
            &mut parm_err as *mut _,
        );
        if status != NERR_Success && status != ERROR_ALIAS_EXISTS && status != NERR_GROUP_EXISTS {
            super::log_line(
                log,
                &format!("NetLocalGroupAdd failed for {name} code {status} parm_err={parm_err}"),
            )?;
            return Err(anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperUsersGroupCreateFailed,
                format!("failed to create local group {name}, code {status}"),
            )));
        }
    }
    Ok(())
}

pub fn ensure_local_group_member(group_name: &str, member_name: &str) -> Result<()> {
    // If the member is already in the group, NetLocalGroupAddMembers may
    // return an error code. We don't care.
    let group_w = to_wide(OsStr::new(group_name));
    let member_w = to_wide(OsStr::new(member_name));
    unsafe {
        let member = LOCALGROUP_MEMBERS_INFO_3 {
            lgrmi3_domainandname: member_w.as_ptr() as *mut u16,
        };
        let _ = NetLocalGroupAddMembers(
            std::ptr::null(),
            group_w.as_ptr(),
            3,
            &member as *const _ as *mut u8,
            1,
        );
    }
    Ok(())
}

pub fn resolve_sid(name: &str) -> Result<Vec<u8>> {
    if let Some(sid_str) = well_known_sid_str(name) {
        return sid_bytes_from_string(sid_str);
    }
    let name_w = to_wide(OsStr::new(name));
    let mut sid_buffer = vec![0u8; 68];
    let mut sid_len: u32 = sid_buffer.len() as u32;
    let mut domain: Vec<u16> = Vec::new();
    let mut domain_len: u32 = 0;
    let mut use_type: SID_NAME_USE = 0;
    loop {
        let ok = unsafe {
            LookupAccountNameW(
                std::ptr::null(),
                name_w.as_ptr(),
                sid_buffer.as_mut_ptr() as *mut c_void,
                &mut sid_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut use_type,
            )
        };
        if ok != 0 {
            sid_buffer.truncate(sid_len as usize);
            return Ok(sid_buffer);
        }
        let err = unsafe { GetLastError() };
        if err == ERROR_INSUFFICIENT_BUFFER {
            sid_buffer.resize(sid_len as usize, 0);
            domain.resize(domain_len as usize, 0);
            continue;
        }
        return Err(anyhow::anyhow!(
            "LookupAccountNameW failed for {name}: {err}"
        ));
    }
}

fn well_known_sid_str(name: &str) -> Option<&'static str> {
    match name {
        "Administrators" => Some(SID_ADMINISTRATORS),
        "Users" => Some(SID_USERS),
        "Authenticated Users" => Some(SID_AUTHENTICATED_USERS),
        "Everyone" => Some(SID_EVERYONE),
        "SYSTEM" => Some(SID_SYSTEM),
        _ => None,
    }
}

fn sid_bytes_from_string(sid_str: &str) -> Result<Vec<u8>> {
    let sid_w = to_wide(OsStr::new(sid_str));
    let mut psid: *mut c_void = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut psid) } == 0 {
        return Err(anyhow::anyhow!(
            "ConvertStringSidToSidW failed for {sid_str}: {}",
            unsafe { GetLastError() }
        ));
    }
    let sid_len = unsafe { GetLengthSid(psid) };
    if sid_len == 0 {
        unsafe {
            LocalFree(psid as _);
        }
        return Err(anyhow::anyhow!("GetLengthSid failed for {sid_str}"));
    }
    let mut out = vec![0u8; sid_len as usize];
    let ok = unsafe { CopySid(sid_len, out.as_mut_ptr() as *mut c_void, psid) };
    unsafe {
        LocalFree(psid as _);
    }
    if ok == 0 {
        return Err(anyhow::anyhow!("CopySid failed for {sid_str}"));
    }
    Ok(out)
}

fn lookup_account_name_for_sid(sid_str: &str) -> Result<String> {
    let sid_w = to_wide(OsStr::new(sid_str));
    let mut psid: *mut c_void = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut psid) } == 0 {
        return Err(anyhow::anyhow!(
            "ConvertStringSidToSidW failed for {sid_str}: {}",
            unsafe { GetLastError() }
        ));
    }
    let mut name_len: u32 = 0;
    let mut domain_len: u32 = 0;
    let mut use_type: SID_NAME_USE = 0;
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            psid,
            std::ptr::null_mut(),
            &mut name_len,
            std::ptr::null_mut(),
            &mut domain_len,
            &mut use_type,
        )
    };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        if err != ERROR_INSUFFICIENT_BUFFER {
            unsafe {
                LocalFree(psid as _);
            }
            return Err(anyhow::anyhow!(
                "LookupAccountSidW preflight failed for {sid_str}: {err}"
            ));
        }
    }
    let mut name_buf: Vec<u16> = vec![0u16; name_len as usize];
    let mut domain_buf: Vec<u16> = vec![0u16; domain_len as usize];
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            psid,
            name_buf.as_mut_ptr(),
            &mut name_len,
            domain_buf.as_mut_ptr(),
            &mut domain_len,
            &mut use_type,
        )
    };
    unsafe {
        LocalFree(psid as _);
    }
    if ok == 0 {
        return Err(anyhow::anyhow!(
            "LookupAccountSidW failed for {sid_str}: {}",
            unsafe { GetLastError() }
        ));
    }
    let name = String::from_utf16_lossy(&name_buf);
    Ok(name.trim_end_matches('\0').to_string())
}

pub fn sid_bytes_to_psid(sid: &[u8]) -> Result<*mut c_void> {
    let sid_str = string_from_sid_bytes(sid).map_err(anyhow::Error::msg)?;
    let sid_w = to_wide(OsStr::new(&sid_str));
    let mut psid: *mut c_void = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut psid) } == 0 {
        return Err(anyhow::anyhow!(
            "ConvertStringSidToSidW failed: {}",
            unsafe { GetLastError() }
        ));
    }
    Ok(psid)
}

fn random_password() -> String {
    const CHARS: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
    let mut rng = SmallRng::from_entropy();
    let mut buf = [0u8; 24];
    rng.fill_bytes(&mut buf);
    buf.iter()
        .map(|b| {
            let idx = (*b as usize) % CHARS.len();
            CHARS[idx] as char
        })
        .collect()
}

#[derive(Serialize)]
struct SandboxUserRecord {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct SandboxUsersFile {
    version: u32,
    user: SandboxUserRecord,
}

#[derive(Serialize)]
struct SetupMarker {
    version: u32,
    sandbox_username: String,
    created_at: String,
    proxy_ports: Vec<u16>,
    allow_local_binding: bool,
    appcontainer_sid: Option<String>,
    read_roots: Vec<PathBuf>,
    write_roots: Vec<PathBuf>,
}

fn write_secrets(codex_home: &Path, sandbox_user: &str, sandbox_pwd: &str) -> Result<()> {
    let secrets_dir = sandbox_secrets_dir(codex_home);
    std::fs::create_dir_all(&secrets_dir).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperUsersFileWriteFailed,
            format!(
                "failed to create secrets dir {}: {err}",
                secrets_dir.display()
            ),
        ))
    })?;
    let sandbox_blob = dpapi_protect(sandbox_pwd.as_bytes()).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperDpapiProtectFailed,
            format!("dpapi protect failed for sandbox user: {err}"),
        ))
    })?;
    let users = SandboxUsersFile {
        version: SETUP_VERSION,
        user: SandboxUserRecord {
            username: sandbox_user.to_string(),
            password: BASE64.encode(sandbox_blob),
        },
    };
    let users_path = secrets_dir.join("sandbox_users.json");
    let users_json = serde_json::to_vec_pretty(&users).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperUsersFileWriteFailed,
            format!("serialize sandbox users failed: {err}"),
        ))
    })?;
    std::fs::write(&users_path, users_json).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperUsersFileWriteFailed,
            format!(
                "write sandbox users file {} failed: {err}",
                users_path.display()
            ),
        ))
    })?;
    Ok(())
}

// Create the final marker path with its protected ACL before provisioning begins. The empty file
// intentionally fails readiness checks while setup is in progress, and sandbox users cannot read,
// modify, or replace it. Once every setup step succeeds, `commit_setup_marker` writes the valid
// marker contents without changing the file's ACL.
pub(super) fn prepare_setup_marker(codex_home: &Path, real_user: &str) -> Result<()> {
    let marker_path = sandbox_dir(codex_home).join("setup_marker.json");
    match std::fs::remove_file(&marker_path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperSetupMarkerWriteFailed,
                format!(
                    "remove setup marker file {} failed: {err}",
                    marker_path.display()
                ),
            )));
        }
    }

    let real_user_sid = resolve_sid(real_user)
        .and_then(|sid| string_from_sid_bytes(&sid).map_err(anyhow::Error::msg))
        .map_err(|err| {
            anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperSetupMarkerWriteFailed,
                format!("resolve real user SID for setup marker failed: {err}"),
            ))
        })?;
    let sddl = to_wide(format!(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{real_user_sid})"
    ));
    let mut security_descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut security_descriptor,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSetupMarkerWriteFailed,
            format!(
                "create setup marker security descriptor failed: {}",
                unsafe { GetLastError() }
            ),
        )));
    }

    let security_attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security_descriptor,
        bInheritHandle: 0,
    };
    let marker_path_wide = to_wide(marker_path.as_os_str());
    let marker_handle = unsafe {
        CreateFileW(
            marker_path_wide.as_ptr(),
            GENERIC_WRITE,
            /*dwsharemode*/ 0,
            &security_attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            /*htemplatefile*/ 0,
        )
    };
    let create_error = unsafe { GetLastError() };
    unsafe {
        LocalFree(security_descriptor as _);
    }
    if marker_handle == INVALID_HANDLE_VALUE {
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSetupMarkerWriteFailed,
            format!(
                "create protected setup marker file {} failed: {}",
                marker_path.display(),
                create_error
            ),
        )));
    }
    unsafe {
        CloseHandle(marker_handle);
    }
    Ok(())
}

pub(super) fn commit_setup_marker(
    codex_home: &Path,
    sandbox_user: &str,
    proxy_ports: &[u16],
    allow_local_binding: bool,
    appcontainer_sid: Option<&str>,
) -> Result<()> {
    let marker = SetupMarker {
        version: SETUP_VERSION,
        sandbox_username: sandbox_user.to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        proxy_ports: proxy_ports.to_vec(),
        allow_local_binding,
        appcontainer_sid: appcontainer_sid.map(str::to_owned),
        read_roots: Vec::new(),
        write_roots: Vec::new(),
    };
    let marker_path = sandbox_dir(codex_home).join("setup_marker.json");
    let marker_json = serde_json::to_vec_pretty(&marker).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSetupMarkerWriteFailed,
            format!("serialize setup marker failed: {err}"),
        ))
    })?;
    std::fs::write(&marker_path, marker_json).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSetupMarkerWriteFailed,
            format!(
                "write setup marker file {} failed: {err}",
                marker_path.display()
            ),
        ))
    })?;
    Ok(())
}
