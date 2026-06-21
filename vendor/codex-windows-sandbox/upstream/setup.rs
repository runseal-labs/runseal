use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use crate::allow::AllowDenyPaths;
use crate::allow::compute_allow_paths_for_permissions;
use crate::helper_materialization::bundled_executable_path_for_exe;
use crate::helper_materialization::helper_bin_dir;
use crate::helper_materialization::resolve_exe_for_launch;
use crate::helper_materialization::try_resolve_exe_for_launch;
use crate::identity::sandbox_setup_is_complete;
use crate::logging::current_log_file_path;
use crate::logging::log_note;
use crate::path_normalization::canonical_path_key;
use crate::path_normalization::canonicalize_path;
use crate::resolved_permissions::ResolvedWindowsSandboxPermissions;
use crate::setup_error::SetupErrorCode;
use crate::setup_error::SetupFailure;
use crate::setup_error::clear_setup_error_report;
use crate::setup_error::failure;
use crate::setup_error::read_setup_error_report;
use crate::ssh_config_dependencies::ssh_config_dependency_paths;
use anyhow::Result;
use anyhow::anyhow;
use codex_protocol::models::PermissionProfile;
use codex_utils_absolute_path::AbsolutePathBuf;

use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Security::AllocateAndInitializeSid;
use windows_sys::Win32::Security::CheckTokenMembership;
use windows_sys::Win32::Security::FreeSid;
use windows_sys::Win32::Security::SECURITY_NT_AUTHORITY;
use windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode;

pub const SETUP_VERSION: u32 = 6;
pub const SANDBOX_USERNAME: &str = "RunSealSandbox";
const SECURITY_BUILTIN_DOMAIN_RID: u32 = 0x0000_0020;
const DOMAIN_ALIAS_RID_ADMINS: u32 = 0x0000_0220;
const SETUP_EXE_FILENAME: &str = "runseal-windows-sandbox-setup.exe";
const SETUP_PAYLOAD_DIRNAME: &str = "payloads";
const SETUP_PAYLOAD_FILE_PREFIX: &str = "setup-payload-";
const SETUP_PAYLOAD_FILE_SUFFIX: &str = ".json";
const SETUP_ERROR_MODE_FLAGS: u32 = 0x0001 | 0x0002;
const PROTECTED_WRITABLE_CHILDREN: &[&str] = &[".git", ".agents", ".codex"];
const USERPROFILE_ROOT_EXCLUSIONS: &[&str] = &[
    ".ssh",
    ".tsh",
    ".brev",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".config",
    ".npm",
    ".pki",
    ".terraform.d",
];
const WINDOWS_PLATFORM_DEFAULT_READ_ROOTS: &[&str] = &[
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
];

pub fn sandbox_dir(codex_home: &Path) -> PathBuf {
    codex_home.join(".sandbox")
}

pub fn sandbox_bin_dir(codex_home: &Path) -> PathBuf {
    codex_home.join(".sandbox-bin")
}

pub fn sandbox_secrets_dir(codex_home: &Path) -> PathBuf {
    codex_home.join(".sandbox-secrets")
}

pub fn setup_marker_path(codex_home: &Path) -> PathBuf {
    sandbox_dir(codex_home).join("setup_marker.json")
}

pub fn sandbox_users_path(codex_home: &Path) -> PathBuf {
    sandbox_secrets_dir(codex_home).join("sandbox_users.json")
}

pub struct SandboxSetupRequest<'a> {
    pub permissions: &'a ResolvedWindowsSandboxPermissions,
    pub command_cwd: &'a Path,
    pub env_map: &'a HashMap<String, String>,
    pub codex_home: &'a Path,
    pub proxy_enforced: bool,
}

#[derive(Default)]
pub struct SetupRootOverrides {
    pub read_roots: Option<Vec<PathBuf>>,
    pub read_roots_include_platform_defaults: bool,
    pub write_roots: Option<Vec<PathBuf>>,
    pub deny_read_paths: Option<Vec<PathBuf>>,
    pub deny_write_paths: Option<Vec<PathBuf>>,
}

pub fn run_setup_refresh(
    permission_profile: &PermissionProfile,
    workspace_roots: &[AbsolutePathBuf],
    command_cwd: &Path,
    env_map: &HashMap<String, String>,
    codex_home: &Path,
    proxy_enforced: bool,
) -> Result<()> {
    let Ok(permissions) =
        ResolvedWindowsSandboxPermissions::try_from_permission_profile_for_workspace_roots(
            permission_profile,
            workspace_roots,
        )
    else {
        return Ok(());
    };
    run_setup_refresh_inner(
        SandboxSetupRequest {
            permissions: &permissions,
            command_cwd,
            env_map,
            codex_home,
            proxy_enforced,
        },
        SetupRootOverrides::default(),
    )
}

pub fn run_setup_refresh_with_overrides(
    request: SandboxSetupRequest<'_>,
    overrides: SetupRootOverrides,
) -> Result<()> {
    run_setup_refresh_inner(request, overrides)
}

pub fn run_setup_refresh_with_extra_read_roots(
    permission_profile: &PermissionProfile,
    workspace_roots: &[AbsolutePathBuf],
    command_cwd: &Path,
    env_map: &HashMap<String, String>,
    codex_home: &Path,
    extra_read_roots: Vec<PathBuf>,
    proxy_enforced: bool,
) -> Result<()> {
    let Ok(permissions) =
        ResolvedWindowsSandboxPermissions::try_from_permission_profile_for_workspace_roots(
            permission_profile,
            workspace_roots,
        )
    else {
        return Ok(());
    };
    let mut read_roots = gather_read_roots(command_cwd, &permissions, env_map, codex_home);
    read_roots.extend(extra_read_roots);
    run_setup_refresh_inner(
        SandboxSetupRequest {
            permissions: &permissions,
            command_cwd,
            env_map,
            codex_home,
            proxy_enforced,
        },
        SetupRootOverrides {
            read_roots: Some(read_roots),
            read_roots_include_platform_defaults: false,
            write_roots: Some(Vec::new()),
            deny_read_paths: None,
            deny_write_paths: None,
        },
    )
}

fn run_setup_refresh_inner(
    request: SandboxSetupRequest<'_>,
    overrides: SetupRootOverrides,
) -> Result<()> {
    if !request.permissions.is_enforceable_by_windows_sandbox() {
        anyhow::bail!("unsupported filesystem permissions for Windows sandbox setup");
    }
    let (read_roots, write_roots) = build_payload_roots(&request, &overrides);
    let deny_read_paths = build_payload_deny_read_paths(overrides.deny_read_paths);
    let deny_write_paths =
        build_payload_deny_write_paths(&request, &write_roots, overrides.deny_write_paths);
    let network_guard =
        SandboxNetworkGuard::from_permissions(request.permissions, request.proxy_enforced);
    let sandbox_proxy_settings = sandbox_proxy_settings_from_env(request.env_map, network_guard);
    let payload = ElevationPayload {
        version: SETUP_VERSION,
        sandbox_username: SANDBOX_USERNAME.to_string(),
        codex_home: request.codex_home.to_path_buf(),
        command_cwd: request.command_cwd.to_path_buf(),
        read_roots,
        write_roots,
        deny_read_paths,
        deny_write_paths,
        proxy_ports: sandbox_proxy_settings.proxy_ports,
        allow_local_binding: sandbox_proxy_settings.allow_local_binding,
        otel: None,
        real_user: std::env::var("USERNAME").unwrap_or_else(|_| "Administrators".to_string()),
        mode: SetupMode::Full,
        refresh_only: true,
    };
    let json = serde_json::to_vec(&payload)?;
    let payload_path = write_setup_payload_file(request.codex_home, json.as_slice())?;
    let exe = find_setup_exe(request.codex_home);
    let sbx_dir = sandbox_dir(request.codex_home);
    let log_path = current_log_file_path(&sbx_dir);
    let cleared_report = match clear_setup_error_report(request.codex_home) {
        Ok(()) => true,
        Err(err) => {
            log_note(
                &format!("setup refresh: failed to clear setup_error.json before launch: {err}"),
                Some(&sbx_dir),
            );
            false
        }
    };
    // Refresh should never request elevation; ensure verb isn't set and we don't trigger UAC.
    let mut cmd = Command::new(&exe);
    cmd.arg("--payload-file")
        .arg(&payload_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let cwd = std::env::current_dir().unwrap_or_else(|_| request.codex_home.to_path_buf());
    log_note(
        &format!(
            "setup refresh: spawning {} (cwd={}, payload_file={}, payload_len={})",
            exe.display(),
            cwd.display(),
            payload_path.display(),
            json.len()
        ),
        Some(&sbx_dir),
    );
    let status = with_suppressed_windows_error_dialogs(|| cmd.status());
    let _ = remove_setup_payload_file(&payload_path);
    let status = status.map_err(|err| {
        let message = format!(
            "setup refresh failed to launch helper: helper={}, cwd={}, log={}, payload_file={}, error={err}",
            exe.display(),
            cwd.display(),
            log_path.display(),
            payload_path.display()
        );
        log_note(&format!("setup refresh: {message}"), Some(&sbx_dir));
        failure(SetupErrorCode::OrchestratorHelperLaunchFailed, message)
    })?;
    if !status.success() {
        log_note(
            &format!("setup refresh: exited with status {status:?}"),
            Some(&sbx_dir),
        );
        return Err(report_helper_failure(
            request.codex_home,
            cleared_report,
            status.code(),
        ));
    }
    if let Err(err) = clear_setup_error_report(request.codex_home) {
        log_note(
            &format!("setup refresh: failed to clear setup_error.json after success: {err}"),
            Some(&sbx_dir),
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetupMarker {
    pub version: u32,
    pub sandbox_username: String,
    pub created_at: String,
    pub proxy_ports: Vec<u16>,
    pub allow_local_binding: bool,
}

impl SetupMarker {
    pub fn version_matches(&self) -> bool {
        self.version == SETUP_VERSION
    }

    pub(crate) fn request_mismatch_reason(
        &self,
        network_guard: SandboxNetworkGuard,
        sandbox_proxy_settings: &SandboxProxySettings,
    ) -> Option<String> {
        if !network_guard.uses_network_guard() {
            return None;
        }
        if self.proxy_ports == sandbox_proxy_settings.proxy_ports
            && self.allow_local_binding == sandbox_proxy_settings.allow_local_binding
        {
            return None;
        }
        Some(format!(
            "sandbox network guard settings changed (stored_ports={:?}, desired_ports={:?}, stored_allow_local_binding={}, desired_allow_local_binding={})",
            self.proxy_ports,
            sandbox_proxy_settings.proxy_ports,
            self.allow_local_binding,
            sandbox_proxy_settings.allow_local_binding
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxUserRecord {
    pub username: String,
    /// DPAPI-encrypted password blob, base64 encoded.
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxUsersFile {
    pub version: u32,
    pub user: SandboxUserRecord,
}

impl SandboxUsersFile {
    pub fn version_matches(&self) -> bool {
        self.version == SETUP_VERSION
    }
}

fn is_elevated() -> Result<bool> {
    unsafe {
        let mut administrators_group: *mut c_void = std::ptr::null_mut();
        let ok = AllocateAndInitializeSid(
            &SECURITY_NT_AUTHORITY,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut administrators_group,
        );
        if ok == 0 {
            return Err(anyhow!(
                "AllocateAndInitializeSid failed: {}",
                GetLastError()
            ));
        }
        let mut is_member = 0i32;
        let check = CheckTokenMembership(0, administrators_group, &mut is_member as *mut _);
        FreeSid(administrators_group as *mut _);
        if check == 0 {
            return Err(anyhow!("CheckTokenMembership failed: {}", GetLastError()));
        }
        Ok(is_member != 0)
    }
}

pub fn current_process_is_elevated() -> Result<bool> {
    is_elevated()
}

fn canonical_existing(paths: &[PathBuf]) -> Vec<PathBuf> {
    paths
        .iter()
        .filter_map(|p| {
            if !p.exists() {
                return None;
            }
            Some(dunce::canonicalize(p).unwrap_or_else(|_| p.clone()))
        })
        .collect()
}

fn profile_read_roots(user_profile: &Path) -> Vec<PathBuf> {
    let entries = match std::fs::read_dir(user_profile) {
        Ok(entries) => entries,
        Err(_) => return vec![user_profile.to_path_buf()],
    };

    entries
        .filter_map(Result::ok)
        .map(|entry| (entry.file_name(), entry.path()))
        .filter(|(name, _)| {
            let name = name.to_string_lossy();
            !USERPROFILE_ROOT_EXCLUSIONS
                .iter()
                .any(|excluded| name.eq_ignore_ascii_case(excluded))
        })
        .map(|(_, path)| path)
        .collect()
}

fn gather_helper_read_roots(codex_home: &Path) -> Vec<PathBuf> {
    let helper_dir = helper_bin_dir(codex_home);
    let _ = std::fs::create_dir_all(&helper_dir);
    vec![helper_dir]
}

fn gather_full_read_roots_for_permissions(
    command_cwd: &Path,
    permissions: &ResolvedWindowsSandboxPermissions,
    env_map: &HashMap<String, String>,
    codex_home: &Path,
) -> Vec<PathBuf> {
    let mut roots = gather_helper_read_roots(codex_home);
    roots.extend(
        WINDOWS_PLATFORM_DEFAULT_READ_ROOTS
            .iter()
            .map(PathBuf::from),
    );
    if let Ok(up) = std::env::var("USERPROFILE") {
        roots.extend(profile_read_roots(Path::new(&up)));
    }
    roots.push(command_cwd.to_path_buf());
    roots.extend(
        permissions
            .writable_roots_for_cwd(command_cwd, env_map)
            .into_iter()
            .map(|root| root.root),
    );
    canonical_existing(&roots)
}

pub(crate) fn gather_read_roots(
    command_cwd: &Path,
    permissions: &ResolvedWindowsSandboxPermissions,
    env_map: &HashMap<String, String>,
    codex_home: &Path,
) -> Vec<PathBuf> {
    if permissions.has_full_disk_read_access() {
        return gather_full_read_roots_for_permissions(
            command_cwd,
            permissions,
            env_map,
            codex_home,
        );
    }

    let mut roots = gather_helper_read_roots(codex_home);
    if permissions.include_platform_defaults() {
        roots.extend(
            WINDOWS_PLATFORM_DEFAULT_READ_ROOTS
                .iter()
                .map(PathBuf::from),
        );
    }
    roots.extend(permissions.readable_roots_for_cwd(command_cwd));
    canonical_existing(&roots)
}

pub(crate) fn gather_write_roots_for_permissions(
    permissions: &ResolvedWindowsSandboxPermissions,
    command_cwd: &Path,
    env_map: &HashMap<String, String>,
) -> Vec<PathBuf> {
    let roots = permissions
        .writable_roots_for_cwd(command_cwd, env_map)
        .into_iter()
        .map(|root| root.root)
        .collect::<Vec<_>>();
    let mut dedup: HashSet<PathBuf> = HashSet::new();
    let mut out: Vec<PathBuf> = Vec::new();
    for r in canonical_existing(&roots) {
        if dedup.insert(r.clone()) {
            out.push(r);
        }
    }
    out
}

pub(crate) fn effective_write_roots_for_setup(
    permissions: &ResolvedWindowsSandboxPermissions,
    command_cwd: &Path,
    env_map: &HashMap<String, String>,
    codex_home: &Path,
    write_roots_override: Option<&[PathBuf]>,
) -> Vec<PathBuf> {
    effective_write_roots_for_permissions(
        permissions,
        command_cwd,
        env_map,
        codex_home,
        write_roots_override,
    )
}

pub(crate) fn effective_write_roots_for_permissions(
    permissions: &ResolvedWindowsSandboxPermissions,
    command_cwd: &Path,
    env_map: &HashMap<String, String>,
    codex_home: &Path,
    write_roots_override: Option<&[PathBuf]>,
) -> Vec<PathBuf> {
    let write_roots = if let Some(roots) = write_roots_override {
        canonical_existing(roots)
    } else {
        gather_write_roots_for_permissions(permissions, command_cwd, env_map)
    };
    let write_roots = expand_user_profile_root(write_roots);
    let write_roots = filter_user_profile_root(write_roots);
    let write_roots = filter_user_profile_root_exclusions(write_roots);
    let write_roots = filter_ssh_config_dependency_roots(write_roots);
    filter_sensitive_write_roots(write_roots, codex_home)
}

#[derive(Serialize)]
struct ElevationPayload {
    version: u32,
    sandbox_username: String,
    codex_home: PathBuf,
    command_cwd: PathBuf,
    read_roots: Vec<PathBuf>,
    write_roots: Vec<PathBuf>,
    #[serde(default)]
    deny_read_paths: Vec<PathBuf>,
    #[serde(default)]
    deny_write_paths: Vec<PathBuf>,
    proxy_ports: Vec<u16>,
    #[serde(default)]
    allow_local_binding: bool,
    otel: Option<codex_otel::StatsigMetricsSettings>,
    real_user: String,
    mode: SetupMode,
    #[serde(default)]
    refresh_only: bool,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SetupMode {
    Full,
    ProvisionOnly,
    NetworkOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SandboxProxySettings {
    pub proxy_ports: Vec<u16>,
    pub allow_local_binding: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SandboxNetworkGuard {
    Guarded,
    Direct,
}

impl SandboxNetworkGuard {
    pub(crate) fn from_permissions(
        permissions: &ResolvedWindowsSandboxPermissions,
        proxy_enforced: bool,
    ) -> Self {
        if proxy_enforced || !permissions.network_policy().is_enabled() {
            Self::Guarded
        } else {
            Self::Direct
        }
    }

    pub(crate) fn uses_network_guard(self) -> bool {
        matches!(self, Self::Guarded)
    }
}

const ALLOW_LOCAL_BINDING_ENV_KEY: &str = "RUNSEAL_NETWORK_ALLOW_LOCAL_BINDING";
const RUNSEAL_MANAGED_PROXY_PORT: u16 = 43129;

pub(crate) fn sandbox_proxy_settings_from_env(
    env_map: &HashMap<String, String>,
    network_guard: SandboxNetworkGuard,
) -> SandboxProxySettings {
    if !network_guard.uses_network_guard() {
        return SandboxProxySettings {
            proxy_ports: vec![],
            allow_local_binding: false,
        };
    }
    let allow_local_binding = env_map
        .get(ALLOW_LOCAL_BINDING_ENV_KEY)
        .is_some_and(|value| value == "1");
    SandboxProxySettings {
        // RunSeal MVP: one managed proxy listener keeps firewall state static.
        proxy_ports: if allow_local_binding {
            vec![]
        } else {
            vec![RUNSEAL_MANAGED_PROXY_PORT]
        },
        allow_local_binding,
    }
}

fn setup_payload_dir(codex_home: &Path) -> PathBuf {
    sandbox_dir(codex_home).join(SETUP_PAYLOAD_DIRNAME)
}

fn setup_payload_request_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{}-{nanos}", std::process::id())
}

fn setup_payload_path(codex_home: &Path, request_id: &str) -> PathBuf {
    setup_payload_dir(codex_home).join(format!(
        "{SETUP_PAYLOAD_FILE_PREFIX}{request_id}{SETUP_PAYLOAD_FILE_SUFFIX}"
    ))
}

fn write_setup_payload_file(codex_home: &Path, payload_json: &[u8]) -> Result<PathBuf> {
    let dir = setup_payload_dir(codex_home);
    std::fs::create_dir_all(&dir).map_err(|err| {
        failure(
            SetupErrorCode::OrchestratorSandboxDirCreateFailed,
            format!(
                "failed to create setup payload dir {}: {err}",
                dir.display()
            ),
        )
    })?;

    for attempt in 0..16 {
        let request_id = format!("{}-{attempt}", setup_payload_request_id());
        let path = setup_payload_path(codex_home, &request_id);
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(failure(
                    SetupErrorCode::OrchestratorPayloadSerializeFailed,
                    format!(
                        "failed to create setup payload file {}: {err}",
                        path.display()
                    ),
                ));
            }
        };
        file.write_all(payload_json).map_err(|err| {
            failure(
                SetupErrorCode::OrchestratorPayloadSerializeFailed,
                format!(
                    "failed to write setup payload file {}: {err}",
                    path.display()
                ),
            )
        })?;
        file.flush().map_err(|err| {
            failure(
                SetupErrorCode::OrchestratorPayloadSerializeFailed,
                format!(
                    "failed to flush setup payload file {}: {err}",
                    path.display()
                ),
            )
        })?;
        return Ok(path);
    }

    Err(failure(
        SetupErrorCode::OrchestratorPayloadSerializeFailed,
        format!(
            "failed to create unique setup payload file in {}",
            dir.display()
        ),
    ))
}

fn remove_setup_payload_file(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn find_setup_exe(codex_home: &Path) -> PathBuf {
    if let Some(setup_exe) = find_setup_exe_source() {
        return resolve_exe_for_launch(&setup_exe, codex_home);
    }
    setup_exe_fallback(codex_home)
}

fn find_setup_exe_source() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    find_setup_exe_for_current_exe(&exe)
}

fn find_setup_exe_for_current_exe(exe: &Path) -> Option<PathBuf> {
    bundled_executable_path_for_exe(exe, SETUP_EXE_FILENAME)
}

fn setup_exe_fallback(codex_home: &Path) -> PathBuf {
    helper_bin_dir(codex_home).join(SETUP_EXE_FILENAME)
}

fn refresh_setup_exe_for_home(codex_home: &Path) -> Result<PathBuf> {
    let setup_exe = find_setup_exe_source().ok_or_else(|| {
        failure(
            SetupErrorCode::OrchestratorHelperLaunchFailed,
            format!(
                "setup helper source {SETUP_EXE_FILENAME} was not found next to current executable"
            ),
        )
    })?;
    try_resolve_exe_for_launch(&setup_exe, codex_home).map_err(|err| {
        failure(
            SetupErrorCode::OrchestratorHelperLaunchFailed,
            format!(
                "failed to refresh setup helper under {}: {err:#}",
                helper_bin_dir(codex_home).display()
            ),
        )
    })
}

fn report_helper_failure(
    codex_home: &Path,
    cleared_report: bool,
    exit_code: Option<i32>,
) -> anyhow::Error {
    let exit_detail = format!("setup helper exited with status {exit_code:?}");
    if !cleared_report {
        return failure(SetupErrorCode::OrchestratorHelperExitNonzero, exit_detail);
    }
    match read_setup_error_report(codex_home) {
        Ok(Some(report)) => anyhow::Error::new(SetupFailure::from_report(report)),
        Ok(None) => failure(SetupErrorCode::OrchestratorHelperExitNonzero, exit_detail),
        Err(err) => failure(
            SetupErrorCode::OrchestratorHelperReportReadFailed,
            format!("{exit_detail}; failed to read setup_error.json: {err}"),
        ),
    }
}

fn verify_setup_completed(codex_home: &Path) -> Result<()> {
    if sandbox_setup_is_complete(codex_home) {
        Ok(())
    } else {
        Err(failure(
            SetupErrorCode::OrchestratorHelperIncomplete,
            "setup helper exited successfully before setup completed",
        ))
    }
}

const SCHEDULED_SETUP_TASK_NAME: &str = r"\RunSeal\WindowsSandboxSetup";
const SCHEDULED_SETUP_PAYLOAD_PREFIX: &str = "setup-task-payload-";
const SCHEDULED_SETUP_RESULT_PREFIX: &str = "setup-task-result-";
static SCHEDULED_SETUP_REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Deserialize)]
struct ScheduledSetupTaskResult {
    request_id: String,
    payload_sha256: String,
    ok: bool,
    message: Option<String>,
}

fn scheduled_setup_request_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let sequence = SCHEDULED_SETUP_REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{nanos}-{sequence}", std::process::id())
}

fn scheduled_setup_broker_home(fallback: &Path) -> PathBuf {
    if let Some(path) = absolute_env_path("RUNSEAL_WINDOWS_SANDBOX_SETUP_BROKER_HOME") {
        return path;
    }
    if let Some(user_data_dir) = absolute_env_path("RUNSEAL_USER_DATA_DIR") {
        return user_data_dir.join("windows-sandbox");
    }
    if let Some(appdata) = absolute_env_path("APPDATA") {
        return appdata.join("RunSeal").join("windows-sandbox");
    }
    fallback.to_path_buf()
}

fn absolute_env_path(key: &str) -> Option<PathBuf> {
    absolute_path_from_env_value(std::env::var_os(key))
}

fn absolute_path_from_env_value(value: Option<std::ffi::OsString>) -> Option<PathBuf> {
    value.map(PathBuf::from).filter(|path| path.is_absolute())
}

fn with_suppressed_windows_error_dialogs<T>(f: impl FnOnce() -> T) -> T {
    let previous_error_mode = unsafe { SetErrorMode(SETUP_ERROR_MODE_FLAGS) };
    let result = f();
    unsafe {
        SetErrorMode(previous_error_mode);
    }
    result
}

fn scheduled_setup_payload_path(codex_home: &Path, request_id: &str) -> PathBuf {
    sandbox_dir(codex_home).join(format!("{SCHEDULED_SETUP_PAYLOAD_PREFIX}{request_id}.json"))
}

fn scheduled_setup_result_path(codex_home: &Path, request_id: &str) -> PathBuf {
    sandbox_dir(codex_home).join(format!("{SCHEDULED_SETUP_RESULT_PREFIX}{request_id}.json"))
}

fn validate_scheduled_setup_result(
    result: &ScheduledSetupTaskResult,
    request_id: &str,
    payload_sha256: &str,
    result_path: &Path,
) -> Result<()> {
    if result.request_id == request_id && result.payload_sha256 == payload_sha256 {
        return Ok(());
    }
    Err(failure(
        SetupErrorCode::OrchestratorHelperLaunchFailed,
        format!(
            "scheduled setup result {} did not match request",
            result_path.display()
        ),
    ))
}

fn scheduled_setup_payload_sha256(payload_json: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(payload_json))
}

fn remove_scheduled_setup_result_file(path: &Path) -> Result<()> {
    remove_setup_payload_file(path).map_err(|err| {
        failure(
            SetupErrorCode::OrchestratorHelperLaunchFailed,
            format!(
                "failed to remove stale scheduled setup result {}: {err}",
                path.display()
            ),
        )
    })
}

fn write_scheduled_setup_payload_file(
    broker_home: &Path,
    request_id: &str,
    payload_json: &[u8],
) -> Result<PathBuf> {
    let payload_path = scheduled_setup_payload_path(broker_home, request_id);
    if let Some(parent) = payload_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            failure(
                SetupErrorCode::OrchestratorSandboxDirCreateFailed,
                format!(
                    "failed to create setup task dir {}: {err}",
                    parent.display()
                ),
            )
        })?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&payload_path)
        .map_err(|err| {
            failure(
                SetupErrorCode::OrchestratorHelperLaunchFailed,
                format!(
                    "failed to create scheduled setup payload {}: {err}",
                    payload_path.display()
                ),
            )
        })?;
    file.write_all(payload_json).map_err(|err| {
        failure(
            SetupErrorCode::OrchestratorHelperLaunchFailed,
            format!(
                "failed to write scheduled setup payload {}: {err}",
                payload_path.display()
            ),
        )
    })?;
    file.flush().map_err(|err| {
        failure(
            SetupErrorCode::OrchestratorHelperLaunchFailed,
            format!(
                "failed to flush scheduled setup payload {}: {err}",
                payload_path.display()
            ),
        )
    })?;
    Ok(payload_path)
}

fn normalized_scheduled_task_text(value: &str) -> String {
    value.replace('\\', "/").to_ascii_lowercase()
}

fn decode_scheduled_task_xml_text(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn scheduled_setup_task_command_path(xml: &str) -> Option<PathBuf> {
    let start = xml.find("<Command>")? + "<Command>".len();
    let end = xml[start..].find("</Command>")?;
    let command = decode_scheduled_task_xml_text(xml[start..start + end].trim());
    (!command.is_empty()).then(|| PathBuf::from(command))
}

fn scheduled_setup_task_command_is_setup_helper(xml: &str, broker_home: &Path) -> bool {
    scheduled_setup_task_command_path(xml).is_some_and(|path| {
        path.is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.eq_ignore_ascii_case(SETUP_EXE_FILENAME))
            && path_is_under_dir(&path, &sandbox_bin_dir(broker_home))
    })
}

fn path_is_under_dir(path: &Path, dir: &Path) -> bool {
    let path_key = canonical_path_key(path);
    let dir_key = canonical_path_key(dir);
    let dir_prefix = format!("{}/", dir_key.trim_end_matches('/'));
    path_key.starts_with(&dir_prefix)
}

fn scheduled_setup_task_arguments(xml: &str) -> Option<String> {
    let start = xml.find("<Arguments>")? + "<Arguments>".len();
    let end = xml[start..].find("</Arguments>")?;
    Some(decode_scheduled_task_xml_text(
        xml[start..start + end].trim(),
    ))
}

fn scheduled_setup_task_targets_broker_home(xml: &str, broker_home: &Path) -> bool {
    let Some(arguments) = scheduled_setup_task_arguments(xml) else {
        return false;
    };
    let Some(rest) = arguments.trim().strip_prefix("--task-run") else {
        return false;
    };
    let broker_arg = rest.trim().trim_matches('"');
    normalized_scheduled_task_text(broker_arg)
        == normalized_scheduled_task_text(&broker_home.to_string_lossy())
}

fn scheduled_setup_task_is_usable(broker_home: &Path) -> bool {
    let output = with_suppressed_windows_error_dialogs(|| {
        Command::new("schtasks.exe")
            .args(["/Query", "/TN", SCHEDULED_SETUP_TASK_NAME, "/XML"])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
    });

    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }

    let xml = decode_scheduled_task_xml_text(&String::from_utf8_lossy(&output.stdout));
    scheduled_setup_task_targets_broker_home(&xml, broker_home)
        && scheduled_setup_task_command_is_setup_helper(&xml, broker_home)
}

fn try_run_setup_exe_via_scheduled_task(
    payload_json: &[u8],
    codex_home: &Path,
    cleared_report: bool,
) -> Result<()> {
    let request_id = scheduled_setup_request_id();
    let broker_home = scheduled_setup_broker_home(codex_home);
    let _broker_exe = refresh_setup_exe_for_home(&broker_home)?;
    if !scheduled_setup_task_is_usable(&broker_home) {
        return Err(failure(
            SetupErrorCode::OrchestratorHelperLaunchFailed,
            format!(
                "scheduled setup task is not usable for broker home {}",
                broker_home.display()
            ),
        ));
    }

    let result_path = scheduled_setup_result_path(&broker_home, &request_id);
    remove_scheduled_setup_result_file(&result_path)?;
    let payload_sha256 = scheduled_setup_payload_sha256(payload_json);
    let payload_path = write_scheduled_setup_payload_file(&broker_home, &request_id, payload_json)?;

    let output = with_suppressed_windows_error_dialogs(|| {
        Command::new("schtasks.exe")
            .args(["/Run", "/TN", SCHEDULED_SETUP_TASK_NAME])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
    })
    .map_err(|err| {
        failure(
            SetupErrorCode::OrchestratorHelperLaunchFailed,
            format!("failed to run scheduled setup task: {err}"),
        )
    })?;
    if !output.status.success() {
        let _ = remove_setup_payload_file(&payload_path);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(failure(
            SetupErrorCode::OrchestratorHelperLaunchFailed,
            format!(
                "scheduled setup task launch failed with status {:?}: {}",
                output.status.code(),
                stderr.trim()
            ),
        ));
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
    loop {
        match std::fs::read_to_string(&result_path) {
            Ok(contents) => {
                let result: ScheduledSetupTaskResult =
                    serde_json::from_str(&contents).map_err(|err| {
                        let _ = remove_setup_payload_file(&payload_path);
                        let _ = remove_setup_payload_file(&result_path);
                        failure(
                            SetupErrorCode::OrchestratorHelperLaunchFailed,
                            format!(
                                "failed to parse scheduled setup result {}: {err}",
                                result_path.display()
                            ),
                        )
                    })?;
                if let Err(err) = validate_scheduled_setup_result(
                    &result,
                    &request_id,
                    &payload_sha256,
                    &result_path,
                ) {
                    let _ = remove_setup_payload_file(&payload_path);
                    let _ = remove_setup_payload_file(&result_path);
                    return Err(err);
                }
                let _ = std::fs::remove_file(&payload_path);
                let _ = std::fs::remove_file(&result_path);
                if result.ok {
                    verify_setup_completed(codex_home)?;
                    if let Err(err) = clear_setup_error_report(codex_home) {
                        log_note(
                            &format!(
                                "setup orchestrator: failed to clear setup_error.json after scheduled task success: {err}"
                            ),
                            Some(&sandbox_dir(codex_home)),
                        );
                    }
                    return Ok(());
                }
                if cleared_report {
                    return Err(report_helper_failure(codex_home, cleared_report, Some(1)));
                }
                return Err(failure(
                    SetupErrorCode::OrchestratorHelperExitNonzero,
                    result
                        .message
                        .unwrap_or_else(|| "scheduled setup task failed".to_string()),
                ));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(failure(
                    SetupErrorCode::OrchestratorHelperLaunchFailed,
                    format!(
                        "failed to read scheduled setup result {}: {err}",
                        result_path.display()
                    ),
                ));
            }
        }
        if std::time::Instant::now() >= deadline {
            let _ = remove_setup_payload_file(&payload_path);
            return Err(failure(
                SetupErrorCode::OrchestratorHelperLaunchFailed,
                "scheduled setup task timed out".to_string(),
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

fn run_setup_exe(
    payload: &ElevationPayload,
    needs_elevation: bool,
    codex_home: &Path,
) -> Result<()> {
    let exe = find_setup_exe(codex_home);
    let payload_json = serde_json::to_string(payload).map_err(|err| {
        failure(
            SetupErrorCode::OrchestratorPayloadSerializeFailed,
            format!("failed to serialize elevation payload: {err}"),
        )
    })?;
    let cleared_report = match clear_setup_error_report(codex_home) {
        Ok(()) => true,
        Err(err) => {
            log_note(
                &format!(
                    "setup orchestrator: failed to clear setup_error.json before launch: {err}"
                ),
                Some(&sandbox_dir(codex_home)),
            );
            false
        }
    };

    if !needs_elevation {
        let payload_path = write_setup_payload_file(codex_home, payload_json.as_bytes())?;
        let status = with_suppressed_windows_error_dialogs(|| {
            Command::new(&exe)
                .arg("--payload-file")
                .arg(&payload_path)
                .creation_flags(0x08000000) // CREATE_NO_WINDOW
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
        });
        let _ = remove_setup_payload_file(&payload_path);
        let status = status.map_err(|err| {
            failure(
                SetupErrorCode::OrchestratorHelperLaunchFailed,
                format!(
                    "failed to launch setup helper (non-elevated): payload_file={}, error={err}",
                    payload_path.display()
                ),
            )
        })?;
        if !status.success() {
            return Err(report_helper_failure(
                codex_home,
                cleared_report,
                status.code(),
            ));
        }
        verify_setup_completed(codex_home)?;
        if let Err(err) = clear_setup_error_report(codex_home) {
            log_note(
                &format!(
                    "setup orchestrator: failed to clear setup_error.json after success: {err}"
                ),
                Some(&sandbox_dir(codex_home)),
            );
        }
        return Ok(());
    }

    try_run_setup_exe_via_scheduled_task(payload_json.as_bytes(), codex_home, cleared_report)
        .map_err(|err| {
            log_note(
                &format!(
                    "setup orchestrator: scheduled setup task unavailable; interactive elevation is disabled: {err}"
                ),
                Some(&sandbox_dir(codex_home)),
            );
            err
        })
}

pub fn run_elevated_setup(
    request: SandboxSetupRequest<'_>,
    overrides: SetupRootOverrides,
) -> Result<()> {
    if !request.permissions.is_enforceable_by_windows_sandbox() {
        anyhow::bail!("unsupported filesystem permissions for Windows sandbox setup");
    }
    // Ensure the shared sandbox directory exists before we send it to the elevated helper.
    let sbx_dir = sandbox_dir(request.codex_home);
    std::fs::create_dir_all(&sbx_dir).map_err(|err| {
        failure(
            SetupErrorCode::OrchestratorSandboxDirCreateFailed,
            format!("failed to create sandbox dir {}: {err}", sbx_dir.display()),
        )
    })?;
    let (read_roots, write_roots) = build_payload_roots(&request, &overrides);
    let deny_read_paths = build_payload_deny_read_paths(overrides.deny_read_paths);
    let deny_write_paths =
        build_payload_deny_write_paths(&request, &write_roots, overrides.deny_write_paths);
    let network_guard =
        SandboxNetworkGuard::from_permissions(request.permissions, request.proxy_enforced);
    let sandbox_proxy_settings = sandbox_proxy_settings_from_env(request.env_map, network_guard);
    let payload = ElevationPayload {
        version: SETUP_VERSION,
        sandbox_username: SANDBOX_USERNAME.to_string(),
        codex_home: request.codex_home.to_path_buf(),
        command_cwd: request.command_cwd.to_path_buf(),
        read_roots,
        write_roots,
        deny_read_paths,
        deny_write_paths,
        proxy_ports: sandbox_proxy_settings.proxy_ports,
        allow_local_binding: sandbox_proxy_settings.allow_local_binding,
        real_user: std::env::var("USERNAME").unwrap_or_else(|_| "Administrators".to_string()),
        otel: codex_otel::global_statsig_metrics_settings(),
        mode: SetupMode::Full,
        refresh_only: false,
    };
    let needs_elevation = !is_elevated().map_err(|err| {
        failure(
            SetupErrorCode::OrchestratorElevationCheckFailed,
            format!("failed to determine elevation state: {err}"),
        )
    })?;
    run_setup_exe(&payload, needs_elevation, request.codex_home)
}

pub fn run_elevated_network_setup(
    request: SandboxSetupRequest<'_>,
    overrides: SetupRootOverrides,
) -> Result<()> {
    if !request.permissions.is_enforceable_by_windows_sandbox() {
        anyhow::bail!("unsupported filesystem permissions for Windows sandbox setup");
    }
    let sbx_dir = sandbox_dir(request.codex_home);
    std::fs::create_dir_all(&sbx_dir).map_err(|err| {
        failure(
            SetupErrorCode::OrchestratorSandboxDirCreateFailed,
            format!("failed to create sandbox dir {}: {err}", sbx_dir.display()),
        )
    })?;
    let (read_roots, write_roots) = build_payload_roots(&request, &overrides);
    let deny_read_paths = build_payload_deny_read_paths(overrides.deny_read_paths);
    let deny_write_paths =
        build_payload_deny_write_paths(&request, &write_roots, overrides.deny_write_paths);
    let network_guard =
        SandboxNetworkGuard::from_permissions(request.permissions, request.proxy_enforced);
    let sandbox_proxy_settings = sandbox_proxy_settings_from_env(request.env_map, network_guard);
    let payload = ElevationPayload {
        version: SETUP_VERSION,
        sandbox_username: SANDBOX_USERNAME.to_string(),
        codex_home: request.codex_home.to_path_buf(),
        command_cwd: request.command_cwd.to_path_buf(),
        read_roots,
        write_roots,
        deny_read_paths,
        deny_write_paths,
        proxy_ports: sandbox_proxy_settings.proxy_ports,
        allow_local_binding: sandbox_proxy_settings.allow_local_binding,
        real_user: std::env::var("USERNAME").unwrap_or_else(|_| "Administrators".to_string()),
        otel: codex_otel::global_statsig_metrics_settings(),
        mode: SetupMode::NetworkOnly,
        refresh_only: false,
    };
    let needs_elevation = !is_elevated().map_err(|err| {
        failure(
            SetupErrorCode::OrchestratorElevationCheckFailed,
            format!("failed to determine elevation state: {err}"),
        )
    })?;
    run_setup_exe(&payload, needs_elevation, request.codex_home)
}

pub fn run_elevated_provisioning_setup(codex_home: &Path, real_user: &str) -> Result<()> {
    let sbx_dir = sandbox_dir(codex_home);
    std::fs::create_dir_all(&sbx_dir).map_err(|err| {
        failure(
            SetupErrorCode::OrchestratorSandboxDirCreateFailed,
            format!("failed to create sandbox dir {}: {err}", sbx_dir.display()),
        )
    })?;
    let needs_elevation = !is_elevated().map_err(|err| {
        failure(
            SetupErrorCode::OrchestratorElevationCheckFailed,
            format!("failed to determine elevation state: {err}"),
        )
    })?;
    let payload = ElevationPayload {
        version: SETUP_VERSION,
        sandbox_username: SANDBOX_USERNAME.to_string(),
        codex_home: codex_home.to_path_buf(),
        command_cwd: codex_home.to_path_buf(),
        read_roots: Vec::new(),
        write_roots: Vec::new(),
        deny_read_paths: Vec::new(),
        deny_write_paths: Vec::new(),
        proxy_ports: Vec::new(),
        allow_local_binding: false,
        otel: codex_otel::global_statsig_metrics_settings(),
        real_user: real_user.to_string(),
        mode: SetupMode::ProvisionOnly,
        refresh_only: false,
    };
    run_setup_exe(&payload, needs_elevation, codex_home)
}

pub fn provisioning_setup_broker_is_available(codex_home: &Path) -> bool {
    let broker_home = scheduled_setup_broker_home(codex_home);
    scheduled_setup_task_is_usable(&broker_home)
}

fn build_payload_roots(
    request: &SandboxSetupRequest<'_>,
    overrides: &SetupRootOverrides,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let write_roots = effective_write_roots_for_setup(
        request.permissions,
        request.command_cwd,
        request.env_map,
        request.codex_home,
        overrides.write_roots.as_deref(),
    );
    let mut read_roots = if let Some(roots) = overrides.read_roots.as_deref() {
        // An explicit override is the split policy's complete readable set. Keep only the
        // helper/platform roots the elevated setup needs; do not re-add legacy cwd/full-read roots.
        let mut read_roots = gather_helper_read_roots(request.codex_home);
        if overrides.read_roots_include_platform_defaults {
            read_roots.extend(
                WINDOWS_PLATFORM_DEFAULT_READ_ROOTS
                    .iter()
                    .map(PathBuf::from),
            );
        }
        read_roots.extend(roots.iter().cloned());
        canonical_existing(&read_roots)
    } else {
        gather_read_roots(
            request.command_cwd,
            request.permissions,
            request.env_map,
            request.codex_home,
        )
    };
    read_roots = expand_user_profile_root(read_roots);
    read_roots = filter_user_profile_root(read_roots);
    read_roots = filter_user_profile_root_exclusions(read_roots);
    read_roots = filter_ssh_config_dependency_roots(read_roots);
    (read_roots, write_roots)
}

fn build_payload_deny_write_paths(
    request: &SandboxSetupRequest<'_>,
    write_roots: &[PathBuf],
    explicit_deny_write_paths: Option<Vec<PathBuf>>,
) -> Vec<PathBuf> {
    let allow_deny_paths: AllowDenyPaths = compute_allow_paths_for_permissions(
        request.permissions,
        request.command_cwd,
        request.env_map,
    );
    let mut deny_write_paths: Vec<PathBuf> = explicit_deny_write_paths
        .unwrap_or_default()
        .into_iter()
        .map(|path| canonicalize_path(&path))
        .collect();
    deny_write_paths.extend(allow_deny_paths.deny);
    deny_write_paths.extend(existing_protected_children_for_roots(
        &allow_deny_paths.allow,
    ));
    let write_root_keys = write_roots
        .iter()
        .map(|root| canonical_path_key(root))
        .collect::<HashSet<_>>();
    deny_write_paths.retain(|path| !write_root_keys.contains(&canonical_path_key(path)));
    deny_write_paths
}

fn existing_protected_children_for_roots(roots: &HashSet<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut protected = Vec::new();
    for root in roots {
        for child in PROTECTED_WRITABLE_CHILDREN {
            let path = root.join(child);
            if !path.exists() {
                continue;
            }
            let path = canonicalize_path(&path);
            if seen.insert(path.clone()) {
                protected.push(path);
            }
        }
    }
    protected
}

fn build_payload_deny_read_paths(explicit_deny_read_paths: Option<Vec<PathBuf>>) -> Vec<PathBuf> {
    // Keep the configured spelling here so the ACL layer can plan both the
    // lexical path and any existing canonical target for reparse-point aliases.
    explicit_deny_read_paths.unwrap_or_default()
}

fn expand_user_profile_root(roots: Vec<PathBuf>) -> Vec<PathBuf> {
    let Ok(user_profile) = std::env::var("USERPROFILE") else {
        return roots;
    };
    expand_user_profile_root_for(roots, Path::new(&user_profile))
}

fn expand_user_profile_root_for(roots: Vec<PathBuf>, user_profile: &Path) -> Vec<PathBuf> {
    let user_profile_key = canonical_path_key(user_profile);
    let mut expanded = Vec::new();
    for root in roots {
        if canonical_path_key(&root) == user_profile_key {
            expanded.extend(profile_read_roots(user_profile));
        } else {
            expanded.push(root);
        }
    }

    expanded.sort_by_key(|root| canonical_path_key(root));
    expanded.dedup_by(|a, b| canonical_path_key(a.as_path()) == canonical_path_key(b.as_path()));
    expanded
}

fn filter_user_profile_root(mut roots: Vec<PathBuf>) -> Vec<PathBuf> {
    let Ok(user_profile) = std::env::var("USERPROFILE") else {
        return roots;
    };
    let user_profile_key = canonical_path_key(Path::new(&user_profile));
    roots.retain(|root| canonical_path_key(root) != user_profile_key);
    roots
}

fn filter_user_profile_root_exclusions(mut roots: Vec<PathBuf>) -> Vec<PathBuf> {
    let Ok(user_profile) = std::env::var("USERPROFILE") else {
        return roots;
    };
    let user_profile = Path::new(&user_profile);
    roots.retain(|root| !is_user_profile_root_exclusion(root, user_profile));
    roots
}

fn is_user_profile_root_exclusion(root: &Path, user_profile: &Path) -> bool {
    let root_key = canonical_path_key(root);
    let profile_key = canonical_path_key(user_profile);
    let profile_prefix = format!("{}/", profile_key.trim_end_matches('/'));
    let Some(relative_key) = root_key.strip_prefix(&profile_prefix) else {
        return false;
    };
    let Some(child_name) = relative_key
        .split('/')
        .next()
        .filter(|name| !name.is_empty())
    else {
        return false;
    };

    USERPROFILE_ROOT_EXCLUSIONS
        .iter()
        .any(|excluded| child_name.eq_ignore_ascii_case(excluded))
}

fn filter_ssh_config_dependency_roots(mut roots: Vec<PathBuf>) -> Vec<PathBuf> {
    let Ok(user_profile) = std::env::var("USERPROFILE") else {
        return roots;
    };
    let user_profile = Path::new(&user_profile);
    let dependency_paths = ssh_config_dependency_paths(user_profile);
    roots.retain(|root| !is_ssh_config_dependency_root(root, user_profile, &dependency_paths));
    roots
}

fn is_ssh_config_dependency_root(
    root: &Path,
    user_profile: &Path,
    dependency_paths: &[PathBuf],
) -> bool {
    let Some(child_name) = user_profile_child_name(root, user_profile) else {
        return false;
    };

    dependency_paths.iter().any(|path| {
        user_profile_child_name(path, user_profile)
            .is_some_and(|dependency_child| child_name.eq_ignore_ascii_case(&dependency_child))
    })
}

fn user_profile_child_name(path: &Path, user_profile: &Path) -> Option<String> {
    let root_key = canonical_path_key(path);
    let profile_key = canonical_path_key(user_profile);
    let profile_prefix = format!("{}/", profile_key.trim_end_matches('/'));
    let relative_key = root_key.strip_prefix(&profile_prefix)?;
    relative_key
        .split('/')
        .next()
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

fn filter_sensitive_write_roots(mut roots: Vec<PathBuf>, codex_home: &Path) -> Vec<PathBuf> {
    // Never grant capability write access to CODEX_HOME or anything under CODEX_HOME/.sandbox,
    // CODEX_HOME/.sandbox-bin, or CODEX_HOME/.sandbox-secrets. These locations contain sandbox
    // control/state and helper binaries and must remain tamper-resistant.
    let codex_home_key = canonical_path_key(codex_home);
    let sbx_dir_key = canonical_path_key(&sandbox_dir(codex_home));
    let sbx_dir_prefix = format!("{}/", sbx_dir_key.trim_end_matches('/'));
    let sbx_bin_dir_key = canonical_path_key(&sandbox_bin_dir(codex_home));
    let sbx_bin_dir_prefix = format!("{}/", sbx_bin_dir_key.trim_end_matches('/'));
    let secrets_dir_key = canonical_path_key(&sandbox_secrets_dir(codex_home));
    let secrets_dir_prefix = format!("{}/", secrets_dir_key.trim_end_matches('/'));

    roots.retain(|root| {
        let key = canonical_path_key(root);
        key != codex_home_key
            && key != sbx_dir_key
            && !key.starts_with(&sbx_dir_prefix)
            && key != sbx_bin_dir_key
            && !key.starts_with(&sbx_bin_dir_prefix)
            && key != secrets_dir_key
            && !key.starts_with(&secrets_dir_prefix)
    });
    roots
}

#[cfg(test)]
mod tests {
    use super::WINDOWS_PLATFORM_DEFAULT_READ_ROOTS;
    use super::absolute_path_from_env_value;
    use super::build_payload_roots;
    use super::find_setup_exe_for_current_exe;
    use super::gather_full_read_roots_for_permissions;
    use super::gather_read_roots;
    use super::profile_read_roots;
    use super::remove_setup_payload_file;
    use super::sandbox_proxy_settings_from_env;
    use super::setup_exe_fallback;
    use super::setup_payload_dir;
    use super::verify_setup_completed;
    use super::write_setup_payload_file;
    use crate::helper_materialization::BIN_DIRNAME;
    use crate::helper_materialization::RESOURCES_DIRNAME;
    use crate::helper_materialization::helper_bin_dir;
    use crate::resolved_permissions::ResolvedWindowsSandboxPermissions;
    use crate::setup_error::SetupErrorCode;
    use crate::setup_error::SetupErrorReport;
    use crate::setup_error::extract_failure;
    use crate::setup_error::write_setup_error_report;
    use codex_protocol::models::PermissionProfile;
    use codex_protocol::permissions::NetworkSandboxPolicy;
    use codex_utils_absolute_path::AbsolutePathBuf;
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;
    use std::collections::HashSet;
    use std::fs;
    use std::path::Path;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn canonical_windows_platform_default_roots() -> Vec<PathBuf> {
        WINDOWS_PLATFORM_DEFAULT_READ_ROOTS
            .iter()
            .map(|path| dunce::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path)))
            .collect()
    }

    #[test]
    fn setup_completion_requires_ready_artifacts() {
        let codex_home = TempDir::new().expect("tempdir");
        let err = verify_setup_completed(codex_home.path())
            .expect_err("missing setup artifacts should fail");

        assert_eq!(
            extract_failure(&err).map(|failure| failure.code),
            Some(SetupErrorCode::OrchestratorHelperIncomplete)
        );
    }

    #[test]
    fn setup_payload_file_is_written_under_sandbox_payload_dir_and_removed() {
        let tmp = TempDir::new().expect("tempdir");
        let codex_home = tmp.path().join("codex-home");
        let payload = br#"{"version":6}"#;

        let path = write_setup_payload_file(codex_home.as_path(), payload).expect("payload file");

        assert!(path.starts_with(setup_payload_dir(codex_home.as_path())));
        assert_eq!(path.extension().and_then(|ext| ext.to_str()), Some("json"));
        assert_eq!(fs::read(&path).expect("read payload file"), payload);

        remove_setup_payload_file(&path).expect("remove payload file");
        assert!(!path.exists());
        remove_setup_payload_file(&path).expect("remove missing payload file");
    }

    #[test]
    fn scheduled_setup_paths_are_under_broker_sandbox_dir() {
        let tmp = TempDir::new().expect("tempdir");
        let broker_home = tmp.path().join("runseal-broker");

        let payload_path = super::scheduled_setup_payload_path(&broker_home, "req-1");
        let result_path = super::scheduled_setup_result_path(&broker_home, "req-1");

        assert!(payload_path.starts_with(super::sandbox_dir(&broker_home)));
        assert!(result_path.starts_with(super::sandbox_dir(&broker_home)));
        assert_eq!(
            payload_path.file_name().and_then(|name| name.to_str()),
            Some("setup-task-payload-req-1.json")
        );
        assert_eq!(
            result_path.file_name().and_then(|name| name.to_str()),
            Some("setup-task-result-req-1.json")
        );
    }

    #[test]
    fn scheduled_setup_payload_file_does_not_overwrite_existing_request() {
        let tmp = TempDir::new().expect("tempdir");
        let broker_home = tmp.path().join("runseal-broker");
        let request_id = "req-1";

        let path = super::write_scheduled_setup_payload_file(&broker_home, request_id, b"first")
            .expect("write payload");
        let err = super::write_scheduled_setup_payload_file(&broker_home, request_id, b"second")
            .expect_err("existing payload must fail closed");

        assert_eq!(fs::read(&path).expect("read payload"), b"first");
        assert_eq!(
            extract_failure(&err).map(|failure| failure.code),
            Some(SetupErrorCode::OrchestratorHelperLaunchFailed)
        );
    }

    #[test]
    fn stale_scheduled_setup_result_is_removed_before_launch() {
        let tmp = TempDir::new().expect("tempdir");
        let broker_home = tmp.path().join("runseal-broker");
        let result_path = super::scheduled_setup_result_path(&broker_home, "req-1");
        fs::create_dir_all(result_path.parent().expect("result parent")).expect("result dir");
        fs::write(&result_path, br#"{"ok":true}"#).expect("write stale result");

        super::remove_scheduled_setup_result_file(&result_path).expect("remove stale result");

        assert!(!result_path.exists());
        super::remove_scheduled_setup_result_file(&result_path).expect("ignore missing result");
    }

    #[test]
    fn scheduled_setup_request_id_includes_process_local_sequence() {
        let request_id = super::scheduled_setup_request_id();
        let parts = request_id.split('-').collect::<Vec<_>>();

        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], std::process::id().to_string());
        assert!(parts[1].parse::<u128>().is_ok());
        assert!(parts[2].parse::<u64>().is_ok());
    }

    #[test]
    fn scheduled_setup_result_requires_request_binding() {
        let result: super::ScheduledSetupTaskResult = serde_json::from_str(
            r#"{"request_id":"req-1","payload_sha256":"sha256:abc","ok":true,"message":null}"#,
        )
        .expect("parse result");
        let missing_hash = serde_json::from_str::<super::ScheduledSetupTaskResult>(
            r#"{"request_id":"req-1","ok":true,"message":null}"#,
        );
        let missing_request = serde_json::from_str::<super::ScheduledSetupTaskResult>(
            r#"{"payload_sha256":"sha256:abc","ok":true,"message":null}"#,
        );

        assert_eq!(result.request_id, "req-1");
        assert_eq!(result.payload_sha256, "sha256:abc");
        assert!(missing_hash.is_err());
        assert!(missing_request.is_err());
    }

    #[test]
    fn scheduled_setup_result_rejects_mismatched_request_id() {
        let result: super::ScheduledSetupTaskResult = serde_json::from_str(
            r#"{"request_id":"other","payload_sha256":"sha256:abc","ok":true,"message":null}"#,
        )
        .expect("parse result");
        let err = super::validate_scheduled_setup_result(
            &result,
            "req-1",
            "sha256:abc",
            Path::new("setup-task-result-req-1.json"),
        )
        .expect_err("mismatched result must fail closed");

        assert_eq!(
            extract_failure(&err).map(|failure| failure.code),
            Some(SetupErrorCode::OrchestratorHelperLaunchFailed)
        );
    }

    #[test]
    fn scheduled_setup_result_rejects_mismatched_payload_hash() {
        let result: super::ScheduledSetupTaskResult = serde_json::from_str(
            r#"{"request_id":"req-1","payload_sha256":"sha256:other","ok":true,"message":null}"#,
        )
        .expect("parse result");
        let err = super::validate_scheduled_setup_result(
            &result,
            "req-1",
            &super::scheduled_setup_payload_sha256(b"payload"),
            Path::new("setup-task-result-req-1.json"),
        )
        .expect_err("mismatched payload hash must fail closed");

        assert_eq!(
            extract_failure(&err).map(|failure| failure.code),
            Some(SetupErrorCode::OrchestratorHelperLaunchFailed)
        );
    }

    #[test]
    fn scheduled_setup_task_text_normalization_matches_windows_paths() {
        assert_eq!(
            super::normalized_scheduled_task_text(r"C:\Users\Me\AppData\Roaming\RunSeal"),
            "c:/users/me/appdata/roaming/runseal"
        );
    }

    #[test]
    fn scheduled_setup_task_command_path_extracts_helper_path() {
        let tmp = TempDir::new().expect("tempdir");
        let helper = tmp.path().join("runseal-windows-sandbox-setup.exe");
        fs::write(&helper, b"helper").expect("write helper");
        let xml = format!(
            "<Task><Actions><Exec><Command>{}</Command></Exec></Actions></Task>",
            helper.display()
        );

        assert_eq!(super::scheduled_setup_task_command_path(&xml), Some(helper));
    }

    #[test]
    fn scheduled_setup_task_command_path_decodes_xml_entities() {
        let tmp = TempDir::new().expect("tempdir");
        let helper_dir = tmp.path().join("runseal & broker");
        fs::create_dir_all(&helper_dir).expect("create helper dir");
        let helper = helper_dir.join("runseal-windows-sandbox-setup.exe");
        fs::write(&helper, b"helper").expect("write helper");
        let encoded_helper = helper.display().to_string().replace('&', "&amp;");
        let xml = format!(
            "<Task><Actions><Exec><Command>{encoded_helper}</Command></Exec></Actions></Task>"
        );

        assert_eq!(super::scheduled_setup_task_command_path(&xml), Some(helper));
    }

    #[test]
    fn scheduled_setup_task_command_must_be_setup_helper() {
        let tmp = TempDir::new().expect("tempdir");
        let broker_home = tmp.path().join("runseal-broker");
        let broker_bin = helper_bin_dir(&broker_home);
        fs::create_dir_all(&broker_bin).expect("create broker bin");
        let helper = broker_bin.join("runseal-windows-sandbox-setup.exe");
        let other = broker_bin.join("not-runseal.exe");
        let stale_helper = tmp
            .path()
            .join("stale-workspace")
            .join("runseal-windows-sandbox-setup.exe");
        fs::create_dir_all(stale_helper.parent().expect("stale helper parent"))
            .expect("create stale helper dir");
        fs::write(&helper, b"helper").expect("write helper");
        fs::write(&other, b"other").expect("write other");
        fs::write(&stale_helper, b"stale").expect("write stale helper");
        let helper_xml = format!(
            "<Task><Actions><Exec><Command>{}</Command></Exec></Actions></Task>",
            helper.display()
        );
        let other_xml = format!(
            "<Task><Actions><Exec><Command>{}</Command></Exec></Actions></Task>",
            other.display()
        );
        let stale_xml = format!(
            "<Task><Actions><Exec><Command>{}</Command></Exec></Actions></Task>",
            stale_helper.display()
        );

        assert!(super::scheduled_setup_task_command_is_setup_helper(
            &helper_xml,
            &broker_home
        ));
        assert!(!super::scheduled_setup_task_command_is_setup_helper(
            &other_xml,
            &broker_home
        ));
        assert!(!super::scheduled_setup_task_command_is_setup_helper(
            &stale_xml,
            &broker_home
        ));
    }

    #[test]
    fn scheduled_setup_task_arguments_match_exact_broker_home() {
        let broker_home = PathBuf::from(r"C:\runseal\broker");
        let matching_xml = r#"<Task><Actions><Exec><Arguments>--task-run "C:\runseal\broker"</Arguments></Exec></Actions></Task>"#;
        let prefix_xml = r#"<Task><Actions><Exec><Arguments>--task-run "C:\runseal\broker-old"</Arguments></Exec></Actions></Task>"#;
        let missing_arguments_xml = r#"<Task><Actions><Exec><Command>C:\runseal\broker\.sandbox-bin\runseal-windows-sandbox-setup.exe</Command></Exec></Actions><Description>--task-run C:\runseal\broker</Description></Task>"#;

        assert!(super::scheduled_setup_task_targets_broker_home(
            matching_xml,
            &broker_home
        ));
        assert!(!super::scheduled_setup_task_targets_broker_home(
            prefix_xml,
            &broker_home
        ));
        assert!(!super::scheduled_setup_task_targets_broker_home(
            missing_arguments_xml,
            &broker_home
        ));
    }

    fn permissions_for(
        permission_profile: &PermissionProfile,
        workspace_roots: &[AbsolutePathBuf],
    ) -> ResolvedWindowsSandboxPermissions {
        ResolvedWindowsSandboxPermissions::try_from_permission_profile_for_workspace_roots(
            permission_profile,
            workspace_roots,
        )
        .expect("managed permission profile")
    }

    fn workspace_roots_for(root: &Path) -> Vec<AbsolutePathBuf> {
        vec![AbsolutePathBuf::from_absolute_path(root).expect("absolute workspace root")]
    }

    fn workspace_write_profile(
        writable_roots: &[AbsolutePathBuf],
        exclude_tmpdir_env_var: bool,
        exclude_slash_tmp: bool,
    ) -> PermissionProfile {
        PermissionProfile::workspace_write_with(
            writable_roots,
            NetworkSandboxPolicy::Restricted,
            exclude_tmpdir_env_var,
            exclude_slash_tmp,
        )
    }

    #[test]
    fn report_helper_failure_uses_setup_error_report_when_clear_succeeded() {
        let tmp = TempDir::new().expect("tempdir");
        let codex_home = tmp.path().join("codex-home");
        write_setup_error_report(
            codex_home.as_path(),
            &SetupErrorReport {
                code: super::SetupErrorCode::HelperFirewallPolicyAccessFailed,
                message: "firewall policy unavailable".to_string(),
            },
        )
        .expect("write setup error report");

        let err = super::report_helper_failure(
            codex_home.as_path(),
            /*cleared_report*/ true,
            /*exit_code*/ Some(1),
        );

        let failure = extract_failure(&err).expect("structured setup failure");
        assert_eq!(
            &super::SetupFailure::new(
                super::SetupErrorCode::HelperFirewallPolicyAccessFailed,
                "firewall policy unavailable",
            ),
            failure
        );
    }

    #[test]
    fn report_helper_failure_ignores_setup_error_report_when_clear_failed() {
        let tmp = TempDir::new().expect("tempdir");
        let codex_home = tmp.path().join("codex-home");
        write_setup_error_report(
            codex_home.as_path(),
            &SetupErrorReport {
                code: super::SetupErrorCode::HelperFirewallPolicyAccessFailed,
                message: "stale report".to_string(),
            },
        )
        .expect("write setup error report");

        let err = super::report_helper_failure(
            codex_home.as_path(),
            /*cleared_report*/ false,
            /*exit_code*/ Some(1),
        );

        let failure = extract_failure(&err).expect("structured setup failure");
        assert_eq!(
            &super::SetupFailure::new(
                super::SetupErrorCode::OrchestratorHelperExitNonzero,
                "setup helper exited with status Some(1)",
            ),
            failure
        );
    }

    #[test]
    fn setup_refresh_skips_profiles_without_managed_filesystem_permissions() {
        let tmp = TempDir::new().expect("tempdir");
        let command_cwd = tmp.path().join("workspace");
        let codex_home = tmp.path().join("codex-home");
        fs::create_dir_all(&command_cwd).expect("create workspace");
        let workspace_roots = workspace_roots_for(command_cwd.as_path());

        for permission_profile in [
            PermissionProfile::Disabled,
            PermissionProfile::External {
                network: NetworkSandboxPolicy::Restricted,
            },
        ] {
            super::run_setup_refresh(
                &permission_profile,
                workspace_roots.as_slice(),
                command_cwd.as_path(),
                &HashMap::new(),
                codex_home.as_path(),
                /*proxy_enforced*/ false,
            )
            .expect("unsupported profiles do not need setup refresh");

            super::run_setup_refresh_with_extra_read_roots(
                &permission_profile,
                workspace_roots.as_slice(),
                command_cwd.as_path(),
                &HashMap::new(),
                codex_home.as_path(),
                vec![command_cwd.clone()],
                /*proxy_enforced*/ false,
            )
            .expect("unsupported profiles do not need setup refresh");
        }
    }

    #[test]
    fn setup_exe_lookup_checks_package_resource_dir_for_bin_exe() {
        let tmp = TempDir::new().expect("tempdir");
        let package_dir = tmp.path().join("package");
        let bin_dir = package_dir.join(BIN_DIRNAME);
        let resources_dir = package_dir.join(RESOURCES_DIRNAME);
        fs::create_dir_all(&bin_dir).expect("create bin dir");
        fs::create_dir_all(&resources_dir).expect("create resources dir");
        let exe = bin_dir.join("codex.exe");
        let setup_exe = resources_dir.join("runseal-windows-sandbox-setup.exe");
        fs::write(&exe, b"codex").expect("write exe");
        fs::write(&setup_exe, b"setup").expect("write setup");

        let resolved = find_setup_exe_for_current_exe(&exe).expect("setup exe");

        assert_eq!(resolved, setup_exe);
    }

    #[test]
    fn setup_exe_fallback_stays_under_sandbox_bin() {
        let codex_home = Path::new(r"C:\Users\example\.codex");

        assert_eq!(
            helper_bin_dir(codex_home).join("runseal-windows-sandbox-setup.exe"),
            setup_exe_fallback(codex_home)
        );
    }

    #[test]
    fn scheduled_setup_env_paths_must_be_absolute() {
        assert_eq!(
            absolute_path_from_env_value(Some(std::ffi::OsString::from(r"C:\runseal\broker"))),
            Some(PathBuf::from(r"C:\runseal\broker"))
        );
        assert_eq!(
            absolute_path_from_env_value(Some(std::ffi::OsString::from(r"relative\broker"))),
            None
        );
    }

    #[test]
    fn sandbox_proxy_settings_ignore_proxy_env_without_network_guard() {
        let mut env = HashMap::new();
        env.insert(
            "HTTP_PROXY".to_string(),
            "http://127.0.0.1:8080".to_string(),
        );
        env.insert(
            "RUNSEAL_NETWORK_ALLOW_LOCAL_BINDING".to_string(),
            "1".to_string(),
        );

        assert_eq!(
            sandbox_proxy_settings_from_env(&env, super::SandboxNetworkGuard::Direct),
            super::SandboxProxySettings {
                proxy_ports: vec![],
                allow_local_binding: false,
            }
        );
    }

    #[test]
    fn sandbox_proxy_settings_use_static_proxy_port_for_network_guard() {
        let mut env = HashMap::new();
        env.insert(
            "HTTP_PROXY".to_string(),
            "http://127.0.0.1:8080".to_string(),
        );
        env.insert(
            "ALL_PROXY".to_string(),
            "socks5h://127.0.0.1:1081".to_string(),
        );
        env.insert(
            "RUNSEAL_NETWORK_ALLOW_LOCAL_BINDING".to_string(),
            "1".to_string(),
        );

        assert_eq!(
            sandbox_proxy_settings_from_env(&env, super::SandboxNetworkGuard::Guarded),
            super::SandboxProxySettings {
                proxy_ports: vec![],
                allow_local_binding: true,
            }
        );

        env.insert(
            "RUNSEAL_NETWORK_ALLOW_LOCAL_BINDING".to_string(),
            "0".to_string(),
        );

        assert_eq!(
            sandbox_proxy_settings_from_env(&env, super::SandboxNetworkGuard::Guarded),
            super::SandboxProxySettings {
                proxy_ports: vec![super::RUNSEAL_MANAGED_PROXY_PORT],
                allow_local_binding: false,
            }
        );
    }

    #[test]
    fn setup_marker_request_mismatch_reason_ignores_proxy_drift_without_network_guard() {
        let marker = super::SetupMarker {
            version: super::SETUP_VERSION,
            sandbox_username: "sandbox".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            proxy_ports: vec![3128],
            allow_local_binding: false,
        };
        let desired = super::SandboxProxySettings {
            proxy_ports: vec![1081, 8080],
            allow_local_binding: true,
        };

        assert_eq!(
            marker.request_mismatch_reason(super::SandboxNetworkGuard::Direct, &desired),
            None
        );
    }

    #[test]
    fn setup_marker_request_mismatch_reason_reports_local_binding_drift() {
        let marker = super::SetupMarker {
            version: super::SETUP_VERSION,
            sandbox_username: "sandbox".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            proxy_ports: vec![super::RUNSEAL_MANAGED_PROXY_PORT],
            allow_local_binding: false,
        };
        let desired = super::SandboxProxySettings {
            proxy_ports: vec![],
            allow_local_binding: true,
        };

        assert_eq!(
            marker.request_mismatch_reason(super::SandboxNetworkGuard::Guarded, &desired),
            Some(
                "sandbox network guard settings changed (stored_ports=[43129], desired_ports=[], stored_allow_local_binding=false, desired_allow_local_binding=true)"
                    .to_string()
            )
        );
    }

    #[test]
    fn setup_marker_requires_network_guard_fields() {
        let marker = serde_json::json!({
            "version": super::SETUP_VERSION,
            "sandbox_username": "sandbox",
            "created_at": "2026-01-01T00:00:00Z"
        });

        assert!(serde_json::from_value::<super::SetupMarker>(marker).is_err());
    }

    #[test]
    fn profile_read_roots_excludes_configured_top_level_entries() {
        let tmp = TempDir::new().expect("tempdir");
        let user_profile = tmp.path();
        let allowed_dir = user_profile.join("Documents");
        let allowed_file = user_profile.join("settings.json");
        let excluded_dir = user_profile.join(".ssh");
        let excluded_tsh = user_profile.join(".tsh");
        let excluded_case_variant = user_profile.join(".AWS");

        fs::create_dir_all(&allowed_dir).expect("create allowed dir");
        fs::write(&allowed_file, "safe").expect("create allowed file");
        fs::create_dir_all(&excluded_dir).expect("create excluded dir");
        fs::create_dir_all(&excluded_tsh).expect("create excluded tsh dir");
        fs::create_dir_all(&excluded_case_variant).expect("create excluded case variant");

        let roots = profile_read_roots(user_profile);
        let actual: HashSet<PathBuf> = roots.into_iter().collect();
        let expected: HashSet<PathBuf> = [allowed_dir, allowed_file].into_iter().collect();

        assert_eq!(expected, actual);
    }

    #[test]
    fn profile_read_roots_falls_back_to_profile_root_when_enumeration_fails() {
        let tmp = TempDir::new().expect("tempdir");
        let missing_profile = tmp.path().join("missing-user-profile");

        let roots = profile_read_roots(&missing_profile);

        assert_eq!(vec![missing_profile], roots);
    }

    #[test]
    fn is_user_profile_root_exclusion_blocks_configured_children() {
        let tmp = TempDir::new().expect("tempdir");
        let user_profile = tmp.path().join("user-profile");
        let documents = user_profile.join("Documents");
        let app_data = user_profile.join("AppData");
        let ssh_child = user_profile.join(".ssh").join("config");
        let tsh_child = user_profile.join(".tsh").join("keys");
        let other_root = tmp.path().join("other-root");
        fs::create_dir_all(&documents).expect("create documents");
        fs::create_dir_all(&app_data).expect("create app data");
        fs::create_dir_all(&ssh_child).expect("create ssh child");
        fs::create_dir_all(&tsh_child).expect("create tsh child");
        fs::create_dir_all(&other_root).expect("create other root");

        assert!(!super::is_user_profile_root_exclusion(
            &documents,
            &user_profile
        ));
        assert!(!super::is_user_profile_root_exclusion(
            &app_data,
            &user_profile
        ));
        assert!(super::is_user_profile_root_exclusion(
            &ssh_child,
            &user_profile
        ));
        assert!(super::is_user_profile_root_exclusion(
            &tsh_child,
            &user_profile
        ));
        assert!(!super::is_user_profile_root_exclusion(
            &other_root,
            &user_profile
        ));
    }

    #[test]
    fn is_ssh_config_dependency_root_blocks_config_dependencies() {
        let tmp = TempDir::new().expect("tempdir");
        let user_profile = tmp.path().join("user-profile");
        let documents = user_profile.join("Documents");
        let ssh_dir = user_profile.join(".ssh");
        let key_dir = user_profile.join(".keys");
        let include_dir = user_profile.join(".included");
        let other_root = tmp.path().join("other-root");
        fs::create_dir_all(&documents).expect("create documents");
        fs::create_dir_all(&ssh_dir).expect("create .ssh");
        fs::create_dir_all(&key_dir).expect("create key dir");
        fs::create_dir_all(&include_dir).expect("create include dir");
        fs::create_dir_all(&other_root).expect("create other root");
        fs::write(
            ssh_dir.join("config"),
            "IdentityFile ~/.keys/id_ed25519\nInclude ~/.included/config\n",
        )
        .expect("write ssh config");
        fs::write(key_dir.join("id_ed25519"), "").expect("write key");
        fs::write(include_dir.join("config"), "User git\n").expect("write included config");

        let dependency_paths = super::ssh_config_dependency_paths(&user_profile);

        assert!(!super::is_ssh_config_dependency_root(
            &documents,
            &user_profile,
            &dependency_paths
        ));
        assert!(super::is_ssh_config_dependency_root(
            &key_dir,
            &user_profile,
            &dependency_paths
        ));
        assert!(super::is_ssh_config_dependency_root(
            &include_dir.join("config"),
            &user_profile,
            &dependency_paths
        ));
        assert!(!super::is_ssh_config_dependency_root(
            &other_root,
            &user_profile,
            &dependency_paths
        ));
    }

    #[test]
    fn expand_user_profile_root_for_replaces_profile_root_with_children() {
        let tmp = TempDir::new().expect("tempdir");
        let user_profile = tmp.path().join("user-profile");
        let documents = user_profile.join("Documents");
        let excluded = user_profile.join(".local");
        let other_root = tmp.path().join("other-root");
        fs::create_dir_all(&documents).expect("create documents");
        fs::create_dir_all(&excluded).expect("create excluded dir");
        fs::create_dir_all(&other_root).expect("create other root");

        let roots = super::expand_user_profile_root_for(
            vec![user_profile.clone(), other_root.clone()],
            &user_profile,
        );
        let actual: HashSet<PathBuf> = roots.into_iter().collect();
        let expected: HashSet<PathBuf> = [documents, excluded, other_root].into_iter().collect();

        assert_eq!(expected, actual);
    }

    #[test]
    fn expanded_write_roots_still_drop_protected_codex_home() {
        let tmp = TempDir::new().expect("tempdir");
        let user_profile = tmp.path().join("user-profile");
        let codex_home = user_profile.join("CodexHome");
        let documents = user_profile.join("Documents");
        fs::create_dir_all(&codex_home).expect("create codex home");
        fs::create_dir_all(&documents).expect("create documents");

        let mut roots =
            super::expand_user_profile_root_for(vec![user_profile.clone()], &user_profile);
        let user_profile_key = super::canonical_path_key(&user_profile);
        roots.retain(|root| super::canonical_path_key(root) != user_profile_key);
        roots.retain(|root| !super::is_user_profile_root_exclusion(root, &user_profile));
        let roots = super::filter_sensitive_write_roots(roots, &codex_home);

        assert_eq!(vec![documents], roots);
    }

    #[test]
    fn gather_read_roots_includes_helper_bin_dir() {
        let tmp = TempDir::new().expect("tempdir");
        let codex_home = tmp.path().join("codex-home");
        let command_cwd = tmp.path().join("workspace");
        fs::create_dir_all(&command_cwd).expect("create workspace");
        let permission_profile = PermissionProfile::read_only();
        let workspace_roots = workspace_roots_for(command_cwd.as_path());
        let permissions = permissions_for(&permission_profile, workspace_roots.as_slice());

        let roots = gather_read_roots(&command_cwd, &permissions, &HashMap::new(), &codex_home);
        let expected =
            dunce::canonicalize(helper_bin_dir(&codex_home)).expect("canonical helper dir");

        assert!(roots.contains(&expected));
    }

    #[test]
    fn workspace_write_roots_remain_readable() {
        let tmp = TempDir::new().expect("tempdir");
        let codex_home = tmp.path().join("codex-home");
        let command_cwd = tmp.path().join("workspace");
        let writable_root = tmp.path().join("extra-write-root");
        fs::create_dir_all(&command_cwd).expect("create workspace");
        fs::create_dir_all(&writable_root).expect("create writable root");
        let writable_roots = vec![
            AbsolutePathBuf::from_absolute_path(&writable_root).expect("absolute writable root"),
        ];
        let permission_profile = workspace_write_profile(
            &writable_roots,
            /*exclude_tmpdir_env_var*/ true,
            /*exclude_slash_tmp*/ true,
        );
        let workspace_roots = workspace_roots_for(command_cwd.as_path());
        let permissions = permissions_for(&permission_profile, workspace_roots.as_slice());

        let roots = gather_read_roots(&command_cwd, &permissions, &HashMap::new(), &codex_home);
        let expected_writable =
            dunce::canonicalize(&writable_root).expect("canonical writable root");

        assert!(roots.contains(&expected_writable));
    }

    #[test]
    fn build_payload_roots_preserves_helper_roots_when_read_override_is_provided() {
        let tmp = TempDir::new().expect("tempdir");
        let codex_home = tmp.path().join("codex-home");
        let workspace_root = tmp.path().join("workspace-root");
        let command_cwd = tmp.path().join("workspace");
        let readable_root = tmp.path().join("docs");
        fs::create_dir_all(&workspace_root).expect("create workspace root");
        fs::create_dir_all(&command_cwd).expect("create workspace");
        fs::create_dir_all(&readable_root).expect("create readable root");
        let permission_profile = PermissionProfile::read_only();
        let workspace_roots = workspace_roots_for(workspace_root.as_path());
        let permissions = permissions_for(&permission_profile, workspace_roots.as_slice());

        let (read_roots, write_roots) = build_payload_roots(
            &super::SandboxSetupRequest {
                permissions: &permissions,
                command_cwd: &command_cwd,
                env_map: &HashMap::new(),
                codex_home: &codex_home,
                proxy_enforced: false,
            },
            &super::SetupRootOverrides {
                read_roots: Some(vec![readable_root.clone()]),
                read_roots_include_platform_defaults: true,
                write_roots: None,
                deny_read_paths: None,
                deny_write_paths: None,
            },
        );
        let expected_helper =
            dunce::canonicalize(helper_bin_dir(&codex_home)).expect("canonical helper dir");
        let expected_cwd = dunce::canonicalize(&command_cwd).expect("canonical workspace");
        let expected_readable =
            dunce::canonicalize(&readable_root).expect("canonical readable root");

        assert_eq!(write_roots, Vec::<PathBuf>::new());
        assert!(read_roots.contains(&expected_helper));
        assert!(!read_roots.contains(&expected_cwd));
        assert!(read_roots.contains(&expected_readable));
        assert!(
            canonical_windows_platform_default_roots()
                .into_iter()
                .all(|path| read_roots.contains(&path))
        );
    }

    #[test]
    fn build_payload_roots_replaces_full_read_policy_when_read_override_is_provided() {
        let tmp = TempDir::new().expect("tempdir");
        let codex_home = tmp.path().join("codex-home");
        let workspace_root = tmp.path().join("workspace-root");
        let command_cwd = tmp.path().join("workspace");
        let readable_root = tmp.path().join("docs");
        fs::create_dir_all(&workspace_root).expect("create workspace root");
        fs::create_dir_all(&command_cwd).expect("create workspace");
        fs::create_dir_all(&readable_root).expect("create readable root");
        let permission_profile = PermissionProfile::read_only();
        let workspace_roots = workspace_roots_for(workspace_root.as_path());
        let permissions = permissions_for(&permission_profile, workspace_roots.as_slice());

        let (read_roots, write_roots) = build_payload_roots(
            &super::SandboxSetupRequest {
                permissions: &permissions,
                command_cwd: &command_cwd,
                env_map: &HashMap::new(),
                codex_home: &codex_home,
                proxy_enforced: false,
            },
            &super::SetupRootOverrides {
                read_roots: Some(vec![readable_root.clone()]),
                read_roots_include_platform_defaults: false,
                write_roots: None,
                deny_read_paths: None,
                deny_write_paths: None,
            },
        );
        let expected_helper =
            dunce::canonicalize(helper_bin_dir(&codex_home)).expect("canonical helper dir");
        let expected_cwd = dunce::canonicalize(&command_cwd).expect("canonical workspace");
        let expected_readable =
            dunce::canonicalize(&readable_root).expect("canonical readable root");

        assert_eq!(write_roots, Vec::<PathBuf>::new());
        assert!(read_roots.contains(&expected_helper));
        assert!(!read_roots.contains(&expected_cwd));
        assert!(read_roots.contains(&expected_readable));
        assert!(
            canonical_windows_platform_default_roots()
                .into_iter()
                .all(|path| !read_roots.contains(&path))
        );
    }

    #[test]
    fn effective_write_roots_match_payload_filtering_for_overrides() {
        let tmp = TempDir::new().expect("tempdir");
        let codex_home = tmp.path().join("codex-home");
        let command_cwd = tmp.path().join("workspace");
        let extra_root = tmp.path().join("extra-root");
        let sandbox_root = super::sandbox_dir(&codex_home);
        fs::create_dir_all(&codex_home).expect("create codex home");
        fs::create_dir_all(&command_cwd).expect("create workspace");
        fs::create_dir_all(&extra_root).expect("create extra root");
        fs::create_dir_all(&sandbox_root).expect("create sandbox root");
        let permission_profile = workspace_write_profile(
            &[],
            /*exclude_tmpdir_env_var*/ true,
            /*exclude_slash_tmp*/ true,
        );
        let workspace_roots = workspace_roots_for(command_cwd.as_path());
        let permissions = permissions_for(&permission_profile, workspace_roots.as_slice());
        let override_roots = vec![
            command_cwd.clone(),
            extra_root.clone(),
            codex_home.clone(),
            sandbox_root.clone(),
        ];
        let request = super::SandboxSetupRequest {
            permissions: &permissions,
            command_cwd: &command_cwd,
            env_map: &HashMap::new(),
            codex_home: &codex_home,
            proxy_enforced: false,
        };
        let overrides = super::SetupRootOverrides {
            read_roots: None,
            read_roots_include_platform_defaults: false,
            write_roots: Some(override_roots.clone()),
            deny_read_paths: None,
            deny_write_paths: None,
        };

        let effective_write_roots = super::effective_write_roots_for_setup(
            &permissions,
            &command_cwd,
            &HashMap::new(),
            &codex_home,
            Some(&override_roots),
        );
        let (payload_read_roots, payload_write_roots) = build_payload_roots(&request, &overrides);

        let expected_workspace = dunce::canonicalize(&command_cwd).expect("canonical workspace");
        let expected_extra = dunce::canonicalize(&extra_root).expect("canonical extra root");
        let forbidden_codex_home = dunce::canonicalize(&codex_home).expect("canonical codex home");
        let forbidden_sandbox = dunce::canonicalize(&sandbox_root).expect("canonical sandbox root");
        assert_eq!(effective_write_roots, payload_write_roots);
        assert!(payload_read_roots.contains(&expected_workspace));
        assert!(effective_write_roots.contains(&expected_workspace));
        assert!(effective_write_roots.contains(&expected_extra));
        assert!(!effective_write_roots.contains(&forbidden_codex_home));
        assert!(!effective_write_roots.contains(&forbidden_sandbox));
    }

    #[test]
    fn effective_write_roots_use_runtime_workspace_roots_for_workspace_root() {
        let tmp = TempDir::new().expect("tempdir");
        let codex_home = tmp.path().join("codex-home");
        let workspace_root = tmp.path().join("workspace");
        let command_cwd = workspace_root.join("subdir");
        fs::create_dir_all(&codex_home).expect("create codex home");
        fs::create_dir_all(&command_cwd).expect("create command cwd");

        let permission_profile = workspace_write_profile(
            &[],
            /*exclude_tmpdir_env_var*/ true,
            /*exclude_slash_tmp*/ true,
        );
        let workspace_roots = workspace_roots_for(workspace_root.as_path());
        let permissions = permissions_for(&permission_profile, workspace_roots.as_slice());

        let effective_write_roots = super::effective_write_roots_for_setup(
            &permissions,
            &command_cwd,
            &HashMap::new(),
            &codex_home,
            /*write_roots_override*/ None,
        );

        assert_eq!(
            effective_write_roots,
            vec![dunce::canonicalize(&workspace_root).expect("canonical workspace root")]
        );
    }

    #[test]
    fn payload_deny_write_paths_merge_explicit_and_protected_children() {
        let tmp = TempDir::new().expect("tempdir");
        let codex_home = tmp.path().join("codex-home");
        let command_cwd = tmp.path().join("workspace");
        let extra_write_root = tmp.path().join("extra-write-root");
        let command_git = command_cwd.join(".git");
        let extra_codex = extra_write_root.join(".codex");
        let explicit_deny = tmp.path().join("explicit-deny");
        let mistaken_root_deny = command_cwd.clone();
        fs::create_dir_all(&command_git).expect("create command .git");
        fs::create_dir_all(&extra_codex).expect("create extra .codex");
        let writable_roots = vec![
            AbsolutePathBuf::from_absolute_path(&extra_write_root).expect("absolute writable root"),
        ];
        let permission_profile = workspace_write_profile(
            &writable_roots,
            /*exclude_tmpdir_env_var*/ true,
            /*exclude_slash_tmp*/ true,
        );
        let workspace_roots = workspace_roots_for(command_cwd.as_path());
        let permissions = permissions_for(&permission_profile, workspace_roots.as_slice());
        let request = super::SandboxSetupRequest {
            permissions: &permissions,
            command_cwd: &command_cwd,
            env_map: &HashMap::new(),
            codex_home: &codex_home,
            proxy_enforced: false,
        };

        let write_roots = vec![
            dunce::canonicalize(&command_cwd).expect("canonical command cwd"),
            dunce::canonicalize(&extra_write_root).expect("canonical extra write root"),
        ];
        let deny_write_paths = super::build_payload_deny_write_paths(
            &request,
            &write_roots,
            Some(vec![explicit_deny.clone(), mistaken_root_deny]),
        );

        assert_eq!(
            [
                dunce::canonicalize(&command_git).expect("canonical command .git"),
                dunce::canonicalize(&extra_codex).expect("canonical extra .codex"),
                explicit_deny,
            ]
            .into_iter()
            .collect::<HashSet<PathBuf>>(),
            deny_write_paths.into_iter().collect()
        );
    }

    #[test]
    fn full_read_roots_preserve_legacy_platform_defaults() {
        let tmp = TempDir::new().expect("tempdir");
        let codex_home = tmp.path().join("codex-home");
        let command_cwd = tmp.path().join("workspace");
        fs::create_dir_all(&command_cwd).expect("create workspace");
        let permission_profile = PermissionProfile::read_only();
        let workspace_roots = workspace_roots_for(command_cwd.as_path());
        let permissions = permissions_for(&permission_profile, workspace_roots.as_slice());

        let roots = gather_full_read_roots_for_permissions(
            &command_cwd,
            &permissions,
            &HashMap::new(),
            &codex_home,
        );

        assert!(
            canonical_windows_platform_default_roots()
                .into_iter()
                .all(|path| roots.contains(&path))
        );
    }

    #[test]
    fn build_payload_deny_read_paths_preserves_explicit_paths() {
        let tmp = TempDir::new().expect("tempdir");
        let existing = tmp.path().join("secret.env");
        let missing = tmp.path().join("future.env");
        fs::write(&existing, "secret").expect("write existing");

        assert_eq!(
            super::build_payload_deny_read_paths(Some(vec![existing.clone(), missing.clone()])),
            vec![existing, missing]
        );
    }
}
