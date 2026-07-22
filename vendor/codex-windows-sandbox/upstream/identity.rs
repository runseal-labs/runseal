use crate::dpapi;
use crate::logging::debug_log;
use crate::resolved_permissions::ResolvedWindowsSandboxPermissions;
use crate::setup::SandboxUserRecord;
use crate::setup::SandboxUsersFile;
use crate::setup::SetupMarker;
use crate::setup::gather_read_roots;
use crate::setup::gather_write_roots_for_permissions;
use crate::setup::run_elevated_network_setup_with_proxy_settings;
use crate::setup::run_elevated_setup_with_proxy_settings;
use crate::setup::run_setup_refresh_with_overrides_and_proxy_settings;
use crate::setup::sandbox_proxy_settings_from_env;
use crate::setup::sandbox_users_path;
use crate::setup::setup_marker_path;
use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::LOGON32_LOGON_INTERACTIVE;
use windows_sys::Win32::Security::LOGON32_PROVIDER_DEFAULT;
use windows_sys::Win32::Security::LogonUserW;

const SANDBOX_SETUP_LOCK_NAME: &str = "runseal-windows-sandbox-runtime-setup";

#[derive(Debug, Clone)]
struct SandboxIdentity {
    username: String,
    password: String,
}

#[derive(Debug, Clone)]
pub struct SandboxCreds {
    pub username: String,
    pub password: String,
}

fn validate_sandbox_identity(identity: &SandboxIdentity) -> Result<(), u32> {
    let username = crate::winutil::to_wide(&identity.username);
    let domain = crate::winutil::to_wide(".");
    let password = crate::winutil::to_wide(&identity.password);
    let mut token: HANDLE = 0;
    let ok = unsafe {
        LogonUserW(
            username.as_ptr(),
            domain.as_ptr(),
            password.as_ptr(),
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    };
    if ok == 0 {
        return Err(unsafe { GetLastError() });
    }
    if token != 0 {
        unsafe {
            CloseHandle(token);
        }
    }
    Ok(())
}

/// Returns true when the on-disk setup artifacts exist and match the current
/// setup version.
///
/// This is a coarse readiness check; `require_logon_sandbox_creds` performs the
/// additional runtime validation for sandbox proxy/firewall settings.
pub fn sandbox_setup_is_complete(codex_home: &Path) -> bool {
    let marker_ok = matches!(load_marker(codex_home), Ok(Some(marker)) if marker.version_matches());
    if !marker_ok {
        return false;
    }
    matches!(load_users(codex_home), Ok(Some(users)) if users.version_matches())
}

fn load_marker(codex_home: &Path) -> Result<Option<SetupMarker>> {
    let path = setup_marker_path(codex_home);
    let marker = match fs::read_to_string(&path) {
        Ok(contents) => match serde_json::from_str::<SetupMarker>(&contents) {
            Ok(m) => Some(m),
            Err(err) => {
                debug_log(
                    &format!("sandbox setup marker parse failed: {err}"),
                    Some(codex_home),
                );
                None
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            debug_log(
                &format!("sandbox setup marker read failed: {err}"),
                Some(codex_home),
            );
            None
        }
    };
    Ok(marker)
}

fn load_users(codex_home: &Path) -> Result<Option<SandboxUsersFile>> {
    let path = sandbox_users_path(codex_home);
    let file = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            debug_log(
                &format!("sandbox users read failed: {err}"),
                Some(codex_home),
            );
            return Ok(None);
        }
    };
    match serde_json::from_str::<SandboxUsersFile>(&file) {
        Ok(users) => Ok(Some(users)),
        Err(err) => {
            debug_log(
                &format!("sandbox users parse failed: {err}"),
                Some(codex_home),
            );
            Ok(None)
        }
    }
}

fn decode_password(record: &SandboxUserRecord) -> Result<String> {
    let blob = BASE64_STANDARD
        .decode(record.password.as_bytes())
        .context("base64 decode password")?;
    let decrypted = dpapi::unprotect(&blob)?;
    let pwd = String::from_utf8(decrypted).context("sandbox password not utf-8")?;
    Ok(pwd)
}

fn select_identity(codex_home: &Path) -> Result<Option<SandboxIdentity>> {
    let _marker = match load_marker(codex_home)? {
        Some(m) if m.version_matches() => m,
        _ => return Ok(None),
    };
    let users = match load_users(codex_home)? {
        Some(u) if u.version_matches() => u,
        _ => return Ok(None),
    };
    let chosen = users.user;
    let password = decode_password(&chosen)?;
    Ok(Some(SandboxIdentity {
        username: chosen.username,
        password,
    }))
}

#[allow(clippy::too_many_arguments)]
pub fn require_logon_sandbox_creds(
    permissions: &ResolvedWindowsSandboxPermissions,
    command_cwd: &Path,
    env_map: &HashMap<String, String>,
    codex_home: &Path,
    read_roots_override: Option<&[PathBuf]>,
    read_roots_include_platform_defaults: bool,
    write_roots_override: Option<&[PathBuf]>,
    deny_write_paths_override: &[PathBuf],
    proxy_enforced: bool,
    sandbox_proxy_settings_override: Option<&crate::setup::SandboxProxySettings>,
    read_cap_sid: Option<&str>,
) -> Result<SandboxCreds> {
    // ponytail: one global setup lock; use per-home locks only if preparation latency is measurable.
    let setup_lock = named_lock::NamedLock::create(SANDBOX_SETUP_LOCK_NAME)
        .context("create Windows sandbox setup lock")?;
    let setup_guard = setup_lock
        .lock()
        .context("acquire Windows sandbox setup lock")?;
    let sandbox_dir = crate::setup::sandbox_dir(codex_home);
    let needed_read = read_roots_override
        .map(<[PathBuf]>::to_vec)
        .unwrap_or_else(|| gather_read_roots(command_cwd, permissions, env_map, codex_home));
    let needed_write = write_roots_override
        .map(<[PathBuf]>::to_vec)
        .unwrap_or_else(|| gather_write_roots_for_permissions(permissions, command_cwd, env_map));
    let desired_sandbox_proxy_settings = sandbox_proxy_settings_override
        .cloned()
        .unwrap_or_else(|| sandbox_proxy_settings_from_env(env_map));
    let desired_appcontainer_sid = Some(crate::ensure_appcontainer_profile_sid()?);
    // NOTE: Do not add CODEX_HOME/.sandbox to `needed_write`; it must remain non-writable by the
    // restricted capability token. The setup helper's `lock_sandbox_dir` is responsible for
    // granting the sandbox group access to this directory without granting the capability SID.
    let mut setup_reason: Option<String> = None;

    let mut refresh_network_only = false;
    let mut identity = match load_marker(codex_home)? {
        Some(marker) if marker.version_matches() => {
            if let Some(reason) = marker.request_mismatch_reason(
                &desired_sandbox_proxy_settings,
                desired_appcontainer_sid.as_deref(),
            ) {
                setup_reason = Some(reason);
                refresh_network_only = true;
                let selected = select_identity(codex_home)?;
                if selected.is_none() {
                    setup_reason = Some(
                        "sandbox users missing or incompatible with marker version".to_string(),
                    );
                    refresh_network_only = false;
                }
                selected
            } else {
                let selected = select_identity(codex_home)?;
                if selected.is_none() {
                    setup_reason = Some(
                        "sandbox users missing or incompatible with marker version".to_string(),
                    );
                }
                selected
            }
        }
        _ => {
            setup_reason = Some("sandbox setup marker missing or incompatible".to_string());
            None
        }
    };

    if refresh_network_only {
        if let Some(reason) = &setup_reason {
            crate::logging::log_note(
                &format!("sandbox network refresh required: {reason}"),
                Some(&sandbox_dir),
            );
        } else {
            crate::logging::log_note("sandbox network refresh required", Some(&sandbox_dir));
        }
        run_elevated_network_setup_with_proxy_settings(
            crate::setup::SandboxSetupRequest {
                permissions,
                command_cwd,
                env_map,
                codex_home,
                proxy_enforced,
            },
            crate::setup::SetupRootOverrides {
                read_roots: Some(needed_read.clone()),
                read_roots_include_platform_defaults,
                write_roots: Some(needed_write.clone()),
                deny_write_paths: Some(deny_write_paths_override.to_vec()),
                read_cap_sid: read_cap_sid.map(str::to_owned),
            },
            &desired_sandbox_proxy_settings,
        )?;
    }

    if identity.is_none() {
        if let Some(reason) = &setup_reason {
            crate::logging::log_note(
                &format!("sandbox setup required: {reason}"),
                Some(&sandbox_dir),
            );
        } else {
            crate::logging::log_note("sandbox setup required", Some(&sandbox_dir));
        }
        run_elevated_setup_with_proxy_settings(
            crate::setup::SandboxSetupRequest {
                permissions,
                command_cwd,
                env_map,
                codex_home,
                proxy_enforced,
            },
            crate::setup::SetupRootOverrides {
                read_roots: Some(needed_read.clone()),
                read_roots_include_platform_defaults,
                write_roots: Some(needed_write.clone()),
                deny_write_paths: Some(deny_write_paths_override.to_vec()),
                read_cap_sid: read_cap_sid.map(str::to_owned),
            },
            &desired_sandbox_proxy_settings,
        )?;
        identity = select_identity(codex_home)?;
    }
    if let Some((selected, code)) = identity.as_ref().and_then(|selected| {
        validate_sandbox_identity(selected)
            .err()
            .map(|code| (selected, code))
    }) {
        crate::logging::log_note(
            &format!(
                "sandbox setup required: stored sandbox credentials failed logon for {} with code {code}",
                selected.username
            ),
            Some(&sandbox_dir),
        );
        run_elevated_setup_with_proxy_settings(
            crate::setup::SandboxSetupRequest {
                permissions,
                command_cwd,
                env_map,
                codex_home,
                proxy_enforced,
            },
            crate::setup::SetupRootOverrides {
                read_roots: Some(needed_read.clone()),
                read_roots_include_platform_defaults,
                write_roots: Some(needed_write.clone()),
                deny_write_paths: Some(deny_write_paths_override.to_vec()),
                read_cap_sid: read_cap_sid.map(str::to_owned),
            },
            &desired_sandbox_proxy_settings,
        )?;
        identity = select_identity(codex_home)?;
        if let Some(selected) = identity.as_ref() {
            validate_sandbox_identity(selected).map_err(|retry_code| {
                anyhow!(
                    "stored sandbox credentials are invalid after reprovision for {}: LogonUserW failed with code {retry_code}",
                    selected.username
                )
            })?;
        }
    }
    // Reconcile ACLs while the cross-process setup lock is held. The refresh layer caches exact
    // prepared requests, so repeated commands with the same policy avoid launching the helper.
    run_setup_refresh_with_overrides_and_proxy_settings(
        crate::setup::SandboxSetupRequest {
            permissions,
            command_cwd,
            env_map,
            codex_home,
            proxy_enforced,
        },
        crate::setup::SetupRootOverrides {
            read_roots: Some(needed_read),
            read_roots_include_platform_defaults,
            write_roots: Some(needed_write),
            deny_write_paths: Some(deny_write_paths_override.to_vec()),
            read_cap_sid: read_cap_sid.map(str::to_owned),
        },
        &desired_sandbox_proxy_settings,
    )?;
    drop(setup_guard);
    let identity = identity.ok_or_else(|| {
        anyhow!(
            "Windows sandbox setup is missing or out of date; rerun the sandbox setup with elevation"
        )
    })?;
    Ok(SandboxCreds {
        username: identity.username,
        password: identity.password,
    })
}
