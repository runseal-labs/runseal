mod firewall;
mod read_acl_mutex;

use anyhow::Context;
use anyhow::Result;
use codex_otel::StatsigMetricsSettings;
use codex_windows_sandbox::LocalSid;
use codex_windows_sandbox::SETUP_VERSION;
use codex_windows_sandbox::SetupErrorCode;
use codex_windows_sandbox::SetupErrorReport;
use codex_windows_sandbox::SetupFailure;
use codex_windows_sandbox::add_deny_write_ace;
use codex_windows_sandbox::appcontainer_write_capability_sid;
use codex_windows_sandbox::canonicalize_path;
use codex_windows_sandbox::clear_legacy_persistent_deny_read_acls;
use codex_windows_sandbox::convert_string_sid_to_sid;
use codex_windows_sandbox::ensure_allow_mask_aces_with_inheritance;
use codex_windows_sandbox::ensure_allow_write_aces;
use codex_windows_sandbox::ensure_appcontainer_loopback_exemption;
use codex_windows_sandbox::extract_setup_failure;
use codex_windows_sandbox::hide_newly_created_users;
use codex_windows_sandbox::install_wfp_filters;
use codex_windows_sandbox::is_command_cwd_root;
use codex_windows_sandbox::log_note;
use codex_windows_sandbox::log_writer;
use codex_windows_sandbox::path_mask_allows;
use codex_windows_sandbox::protect_dacl_from_inheritance;
use codex_windows_sandbox::revoke_allow_write_ace;
use codex_windows_sandbox::revoke_deny_read_ace;
use codex_windows_sandbox::sandbox_bin_dir;
use codex_windows_sandbox::sandbox_dir;
use codex_windows_sandbox::sandbox_secrets_dir;
use codex_windows_sandbox::string_from_sid_bytes;
use codex_windows_sandbox::to_wide;
use codex_windows_sandbox::workspace_appcontainer_write_capability_sid;
use codex_windows_sandbox::workspace_write_cap_sid_for_root;
use codex_windows_sandbox::workspace_write_root_overlaps_path;
use codex_windows_sandbox::write_setup_error_report;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::mpsc;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::Authorization::EXPLICIT_ACCESS_W;
use windows_sys::Win32::Security::Authorization::GRANT_ACCESS;
use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
use windows_sys::Win32::Security::Authorization::SetEntriesInAclW;
use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
use windows_sys::Win32::Security::Authorization::TRUSTEE_IS_SID;
use windows_sys::Win32::Security::Authorization::TRUSTEE_W;
use windows_sys::Win32::Security::CONTAINER_INHERIT_ACE;
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::OBJECT_INHERIT_ACE;
use windows_sys::Win32::Storage::FileSystem::DELETE;
use windows_sys::Win32::Storage::FileSystem::FILE_DELETE_CHILD;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_EXECUTE;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE;
use windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode;

const DENY_ACCESS: i32 = 3;
const SETUP_HELPER_NONINTERACTIVE_ERROR_MODE: u32 = 0x0001 | 0x0002 | 0x8000;

mod sandbox_users;
mod setup_runtime_bin;
use read_acl_mutex::acquire_read_acl_mutex;
use read_acl_mutex::read_acl_mutex_exists;
use sandbox_users::cleanup_legacy_sandbox_state;
use sandbox_users::commit_setup_marker;
use sandbox_users::legacy_sandbox_usernames;
use sandbox_users::prepare_setup_marker;
use sandbox_users::provision_sandbox_users;
use sandbox_users::resolve_sandbox_users_group_sid;
use sandbox_users::resolve_sid;
use sandbox_users::sid_bytes_to_psid;

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Payload {
    version: u32,
    sandbox_username: String,
    codex_home: PathBuf,
    command_cwd: PathBuf,
    read_roots: Vec<PathBuf>,
    write_roots: Vec<PathBuf>,
    #[serde(default)]
    deny_write_paths: Vec<PathBuf>,
    #[serde(default)]
    read_cap_sid: Option<String>,
    #[serde(default)]
    appcontainer_sid: Option<String>,
    proxy_ports: Vec<u16>,
    #[serde(default)]
    allow_local_binding: bool,
    #[serde(default)]
    otel: Option<StatsigMetricsSettings>,
    real_user: String,
    #[serde(default)]
    mode: SetupMode,
    #[serde(default)]
    refresh_only: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
enum SetupMode {
    #[default]
    Full,
    ProvisionOnly,
    NetworkOnly,
    ReadAclsOnly,
}

const SCHEDULED_SETUP_TASK_NAME: &str = r"\RunSeal\WindowsSandboxSetup";
const SCHEDULED_SETUP_PAYLOAD_PREFIX: &str = "setup-task-payload-";
const SCHEDULED_SETUP_RESULT_PREFIX: &str = "setup-task-result-";
const SETUP_PAYLOAD_DIRNAME: &str = "payloads";
const SETUP_PAYLOAD_FILE_PREFIX: &str = "setup-payload-";
const SETUP_PAYLOAD_FILE_SUFFIX: &str = ".json";

#[derive(Debug, Serialize)]
struct ScheduledSetupTaskResult {
    ok: bool,
    message: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum SetupInvocation {
    TaskRun(PathBuf),
    PayloadFile(PathBuf),
}

fn log_line(log: &mut dyn Write, msg: &str) -> Result<()> {
    let ts = chrono::Utc::now().to_rfc3339();
    writeln!(log, "[{ts}] {msg}").map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperLogFailed,
            format!("failed to write setup log line: {err}"),
        ))
    })?;
    Ok(())
}

fn workspace_write_cap_sids_for_path(
    codex_home: &Path,
    command_cwd: &Path,
    write_roots: &[PathBuf],
    path: &Path,
    appcontainer: bool,
) -> Result<Vec<String>> {
    let mut sid_strs = Vec::new();
    for root in write_roots {
        if workspace_write_root_overlaps_path(root, path) {
            sid_strs.push(workspace_write_cap_sid_for_root(
                codex_home,
                command_cwd,
                root,
            )?);
        }
    }
    if sid_strs.is_empty() {
        if write_roots.is_empty() {
            sid_strs.push(workspace_write_cap_sid_for_root(
                codex_home,
                command_cwd,
                command_cwd,
            )?);
        } else {
            for root in write_roots {
                sid_strs.push(workspace_write_cap_sid_for_root(
                    codex_home,
                    command_cwd,
                    root,
                )?);
            }
        }
    }
    if appcontainer {
        sid_strs
            .into_iter()
            .map(|sid| appcontainer_write_capability_sid(&sid))
            .collect()
    } else {
        Ok(sid_strs)
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
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create setup payload dir {}", dir.display()))?;
    for attempt in 0..16 {
        let request_id = format!("{}-{attempt}", setup_payload_request_id());
        let path = setup_payload_path(codex_home, &request_id);
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("failed to create setup payload file {}", path.display())
                });
            }
        };
        file.write_all(payload_json)
            .with_context(|| format!("failed to write setup payload file {}", path.display()))?;
        file.flush()
            .with_context(|| format!("failed to flush setup payload file {}", path.display()))?;
        return Ok(path);
    }
    anyhow::bail!(
        "failed to create unique setup payload file in {}",
        dir.display()
    );
}

fn remove_setup_payload_file(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn spawn_read_acl_helper(payload: &Payload, _log: &mut dyn Write) -> Result<()> {
    let mut read_payload = payload.clone();
    read_payload.mode = SetupMode::ReadAclsOnly;
    read_payload.refresh_only = true;
    let payload_json = serde_json::to_vec(&read_payload)?;
    let payload_path = write_setup_payload_file(&payload.codex_home, payload_json.as_slice())?;
    let exe = std::env::current_exe().context("locate setup helper")?;
    let spawn_result = Command::new(&exe)
        .arg("--payload-file")
        .arg(&payload_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .spawn();
    if let Err(err) = spawn_result {
        let _ = remove_setup_payload_file(&payload_path);
        return Err(err).with_context(|| {
            format!(
                "spawn read ACL helper with payload file {}",
                payload_path.display()
            )
        });
    }
    Ok(())
}

struct ReadAclSubjects<'a> {
    sandbox_group_psid: *mut c_void,
    rx_psids: &'a [*mut c_void],
    platform_read_psids: &'a [*mut c_void],
    read_cap_psid: Option<*mut c_void>,
}

fn apply_read_acls(
    read_roots: &[PathBuf],
    subjects: &ReadAclSubjects<'_>,
    log: &mut dyn Write,
    refresh_errors: &mut Vec<String>,
    access_mask: u32,
    access_label: &str,
    inheritance: u32,
) -> Result<()> {
    for root in read_roots {
        if !root.exists() {
            log_line(
                log,
                &format!("{access_label} root {} missing; skipping", root.display()),
            )?;
            continue;
        }
        let builtin_has = read_mask_allows_or_log(
            root,
            subjects.rx_psids,
            /*label*/ None,
            access_mask,
            access_label,
            refresh_errors,
            log,
        )?;
        if !builtin_has {
            let sandbox_has = read_mask_allows_or_log(
                root,
                &[subjects.sandbox_group_psid],
                Some("sandbox_group"),
                access_mask,
                access_label,
                refresh_errors,
                log,
            )?;
            if !sandbox_has {
                log_line(
                    log,
                    &format!(
                        "granting {access_label} ACE to {} for sandbox users",
                        root.display()
                    ),
                )?;
                if let Err(err) = unsafe {
                    ensure_allow_mask_aces_with_inheritance(
                        root,
                        &[subjects.sandbox_group_psid],
                        access_mask,
                        inheritance,
                    )
                } {
                    refresh_errors.push(format!(
                        "grant {access_label} ACE failed on {} for sandbox_group: {err}",
                        root.display()
                    ));
                    log_line(
                        log,
                        &format!(
                            "grant {access_label} ACE failed on {} for sandbox_group: {err}",
                            root.display()
                        ),
                    )?;
                }
            }
        }

        let Some(read_cap_psid) = subjects.read_cap_psid else {
            continue;
        };
        if is_native_appcontainer_platform_root(root) {
            log_line(
                log,
                &format!(
                    "using native AppContainer platform ACLs for {}",
                    root.display()
                ),
            )?;
            continue;
        }
        let platform_has = read_mask_allows_or_log(
            root,
            subjects.platform_read_psids,
            Some("platform_read"),
            access_mask,
            access_label,
            refresh_errors,
            log,
        )?;
        let read_cap_has = read_mask_allows_or_log(
            root,
            &[read_cap_psid],
            Some("workspace_read_cap"),
            access_mask,
            access_label,
            refresh_errors,
            log,
        )?;
        if platform_has || read_cap_has {
            continue;
        }
        log_line(
            log,
            &format!(
                "granting {access_label} ACE to {} for workspace read capability",
                root.display()
            ),
        )?;
        if let Err(err) = unsafe {
            ensure_allow_mask_aces_with_inheritance(
                root,
                &[read_cap_psid],
                access_mask,
                inheritance,
            )
        } {
            refresh_errors.push(format!(
                "grant {access_label} ACE failed on {} for workspace_read_cap: {err}",
                root.display()
            ));
            log_line(
                log,
                &format!(
                    "grant {access_label} ACE failed on {} for workspace_read_cap: {err}",
                    root.display()
                ),
            )?;
        }
    }
    Ok(())
}

fn is_native_appcontainer_platform_root(path: &Path) -> bool {
    let canonical = codex_windows_sandbox::canonical_path_key(path);
    [
        Some(PathBuf::from(r"C:\Windows")),
        std::env::var_os("ProgramFiles").map(PathBuf::from),
        std::env::var_os("ProgramFiles(x86)").map(PathBuf::from),
    ]
    .into_iter()
    .flatten()
    .any(|root| {
        let root = codex_windows_sandbox::canonical_path_key(&root);
        canonical == root
            || canonical
                .strip_prefix(&root)
                .is_some_and(|suffix| suffix.starts_with('/'))
    })
}

fn read_mask_allows_or_log(
    root: &Path,
    psids: &[*mut c_void],
    label: Option<&str>,
    read_mask: u32,
    access_label: &str,
    refresh_errors: &mut Vec<String>,
    log: &mut dyn Write,
) -> Result<bool> {
    match path_mask_allows(root, psids, read_mask, /*require_all_bits*/ true) {
        Ok(has) => Ok(has),
        Err(e) => {
            let label_suffix = label
                .map(|value| format!(" for {value}"))
                .unwrap_or_default();
            refresh_errors.push(format!(
                "{access_label} mask check failed on {}{}: {}",
                root.display(),
                label_suffix,
                e
            ));
            log_line(
                log,
                &format!(
                    "{access_label} mask check failed on {}{}: {}; continuing",
                    root.display(),
                    label_suffix,
                    e
                ),
            )?;
            Ok(false)
        }
    }
}

fn lock_sandbox_dir(
    dir: &Path,
    real_user: &str,
    sandbox_group_sid: &[u8],
    sandbox_group_access_mode: i32,
    sandbox_group_mask: u32,
    real_user_mask: u32,
    _log: &mut dyn Write,
) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let system_sid = resolve_sid("SYSTEM")?;
    let admins_sid = resolve_sid("Administrators")?;
    let real_sid = resolve_sid(real_user)?;
    let entries = [
        (
            sandbox_group_sid.to_vec(),
            sandbox_group_mask,
            sandbox_group_access_mode,
        ),
        (
            system_sid,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
            GRANT_ACCESS,
        ),
        (
            admins_sid,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
            GRANT_ACCESS,
        ),
        (real_sid, real_user_mask, GRANT_ACCESS),
    ];
    unsafe {
        let mut eas: Vec<EXPLICIT_ACCESS_W> = Vec::new();
        let mut sids: Vec<*mut c_void> = Vec::new();
        for (sid_bytes, mask, access_mode) in entries.iter().map(|(s, m, a)| (s, *m, *a)) {
            let sid_str = string_from_sid_bytes(sid_bytes).map_err(anyhow::Error::msg)?;
            let sid_w = to_wide(OsStr::new(&sid_str));
            let mut psid: *mut c_void = std::ptr::null_mut();
            if ConvertStringSidToSidW(sid_w.as_ptr(), &mut psid) == 0 {
                return Err(anyhow::anyhow!(
                    "ConvertStringSidToSidW failed: {}",
                    GetLastError()
                ));
            }
            sids.push(psid);
            eas.push(EXPLICIT_ACCESS_W {
                grfAccessPermissions: mask,
                grfAccessMode: access_mode,
                grfInheritance: OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: std::ptr::null_mut(),
                    MultipleTrusteeOperation: 0,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_SID,
                    ptstrName: psid as *mut u16,
                },
            });
        }
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        let set = SetEntriesInAclW(
            eas.len() as u32,
            eas.as_ptr(),
            std::ptr::null_mut(),
            &mut new_dacl,
        );
        if set != 0 {
            return Err(anyhow::anyhow!(
                "SetEntriesInAclW sandbox dir failed: {set}",
            ));
        }
        let path_w = to_wide(dir.as_os_str());
        let res = SetNamedSecurityInfoW(
            path_w.as_ptr() as *mut u16,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new_dacl,
            std::ptr::null_mut(),
        );
        if res != 0 {
            return Err(anyhow::anyhow!(
                "SetNamedSecurityInfoW sandbox dir failed: {res}",
            ));
        }
        if !new_dacl.is_null() {
            LocalFree(new_dacl as HLOCAL);
        }
        for sid in sids {
            if !sid.is_null() {
                LocalFree(sid as HLOCAL);
            }
        }
    }
    Ok(())
}

pub fn main() -> Result<()> {
    // Return setup failures to the caller instead of allowing OS error dialogs.
    unsafe { SetErrorMode(SETUP_HELPER_NONINTERACTIVE_ERROR_MODE) };

    let ret = real_main();
    if let Err(e) = &ret {
        // Best-effort: log unexpected top-level errors.
        if let Ok(codex_home) = std::env::var("CODEX_HOME") {
            let sbx_dir = sandbox_dir(Path::new(&codex_home));
            let _ = std::fs::create_dir_all(&sbx_dir);
            if let Some(mut f) = log_writer(&sbx_dir) {
                let _ = writeln!(
                    f,
                    "[{}] top-level error: {}",
                    chrono::Utc::now().to_rfc3339(),
                    e
                );
            }
        }
    }
    ret
}

fn real_main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_setup_invocation(&args)? {
        SetupInvocation::TaskRun(path) => run_scheduled_setup_task(&path),
        SetupInvocation::PayloadFile(path) => run_payload_file(&path),
    }
}

fn parse_setup_invocation(args: &[String]) -> Result<SetupInvocation> {
    match args {
        [flag, path] if flag == "--task-run" => Ok(SetupInvocation::TaskRun(PathBuf::from(path))),
        [flag, path] if flag == "--payload-file" => {
            Ok(SetupInvocation::PayloadFile(PathBuf::from(path)))
        }
        _ => Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperRequestArgsFailed,
            "expected --payload-file <path> or --task-run <broker-home>",
        ))),
    }
}

fn run_scheduled_setup_task(broker_home: &Path) -> Result<()> {
    let sbx_dir = sandbox_dir(broker_home);
    std::fs::create_dir_all(&sbx_dir).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSandboxDirCreateFailed,
            format!("failed to create sandbox dir {}: {err}", sbx_dir.display()),
        ))
    })?;
    let mut log = log_writer(&sbx_dir).ok_or_else(|| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperLogFailed,
            format!("open log in {} failed", sbx_dir.display()),
        ))
    })?;
    let mut processed = 0usize;
    for entry in std::fs::read_dir(&sbx_dir).with_context(|| {
        format!(
            "failed to read scheduled setup payload dir {}",
            sbx_dir.display()
        )
    })? {
        let entry = entry?;
        let path = entry.path();
        let Some(request_id) = setup_task_request_id(&path) else {
            continue;
        };
        processed += 1;
        let payload_json = match std::fs::read(&path) {
            Ok(contents) => contents,
            Err(err) => {
                let result_path = scheduled_setup_result_path(broker_home, &request_id);
                let result = ScheduledSetupTaskResult {
                    ok: false,
                    message: Some(format!("failed to read scheduled setup payload: {err}")),
                };
                let _ = std::fs::write(&result_path, serde_json::to_vec(&result)?);
                continue;
            }
        };
        let result = run_payload_json(payload_json.as_slice());
        let task_result = match result {
            Ok(()) => ScheduledSetupTaskResult {
                ok: true,
                message: None,
            },
            Err(err) => ScheduledSetupTaskResult {
                ok: false,
                message: Some(err.to_string()),
            },
        };
        let result_path = scheduled_setup_result_path(broker_home, &request_id);
        std::fs::write(&result_path, serde_json::to_vec(&task_result)?).with_context(|| {
            format!(
                "failed to write scheduled setup result {}",
                result_path.display()
            )
        })?;
        let _ = std::fs::remove_file(&path);
    }
    log_line(
        &mut log,
        &format!("scheduled setup task processed {processed} payload(s)"),
    )?;
    Ok(())
}

fn run_payload_file(payload_path: &Path) -> Result<()> {
    let payload_json = std::fs::read(payload_path).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperRequestArgsFailed,
            format!(
                "failed to read payload file {}: {err}",
                payload_path.display()
            ),
        ))
    })?;
    let _ = remove_setup_payload_file(payload_path);
    run_payload_json(payload_json.as_slice())
}

fn run_payload_json(payload_json: &[u8]) -> Result<()> {
    let payload: Payload = serde_json::from_slice(payload_json).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperRequestArgsFailed,
            format!("failed to parse payload json: {err}"),
        ))
    })?;
    if payload.version != SETUP_VERSION {
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperRequestArgsFailed,
            format!(
                "setup version mismatch: expected {SETUP_VERSION}, got {}",
                payload.version
            ),
        )));
    }
    let sbx_dir = sandbox_dir(&payload.codex_home);
    std::fs::create_dir_all(&sbx_dir).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSandboxDirCreateFailed,
            format!("failed to create sandbox dir {}: {err}", sbx_dir.display()),
        ))
    })?;
    let mut log = log_writer(&sbx_dir).ok_or_else(|| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperLogFailed,
            format!("open log in {} failed", sbx_dir.display()),
        ))
    })?;
    let result = run_setup(&payload, &mut log, &sbx_dir);
    if let Err(err) = &result {
        let _ = log_line(&mut log, &format!("setup error: {err:?}"));
        log_note(&format!("setup error: {err:?}"), Some(sbx_dir.as_path()));
        let failure = extract_setup_failure(err)
            .map(|f| SetupFailure::new(f.code, f.message.clone()))
            .unwrap_or_else(|| {
                SetupFailure::new(SetupErrorCode::HelperUnknownError, err.to_string())
            });
        let report = SetupErrorReport {
            code: failure.code,
            message: failure.message,
        };
        if let Err(write_err) = write_setup_error_report(&payload.codex_home, &report) {
            let _ = log_line(
                &mut log,
                &format!("setup error report write failed: {write_err}"),
            );
            log_note(
                &format!("setup error report write failed: {write_err}"),
                Some(sbx_dir.as_path()),
            );
        }
    }
    result
}

fn run_setup(payload: &Payload, log: &mut dyn Write, sbx_dir: &Path) -> Result<()> {
    let writes_setup_marker = !payload.refresh_only && payload.mode != SetupMode::ReadAclsOnly;
    let provisions_identity =
        !payload.refresh_only && matches!(payload.mode, SetupMode::Full | SetupMode::ProvisionOnly);
    log_line(
        log,
        &format!(
            "Windows sandbox model: single low-privilege user {} with proxy-only egress",
            payload.sandbox_username
        ),
    )?;
    if provisions_identity {
        cleanup_legacy_sandbox_state(&payload.codex_home, log)?;
        firewall::remove_legacy_sandbox_rules(log)?;
        prepare_setup_marker(&payload.codex_home, &payload.real_user)?;
    }
    match payload.mode {
        SetupMode::ReadAclsOnly => run_read_acl_only(payload, log),
        SetupMode::ProvisionOnly => run_provision_only(payload, log, sbx_dir),
        SetupMode::NetworkOnly => run_network_only(payload, log, sbx_dir),
        SetupMode::Full => run_setup_full(payload, log, sbx_dir),
    }?;
    if writes_setup_marker {
        commit_setup_marker(
            &payload.codex_home,
            &payload.sandbox_username,
            &payload.proxy_ports,
            payload.allow_local_binding,
            payload.appcontainer_sid.as_deref(),
        )?;
        log_setup_diagnostics(payload, log)?;
    }
    Ok(())
}

fn log_setup_diagnostics(payload: &Payload, log: &mut dyn Write) -> Result<()> {
    let sandbox_sid = resolve_sid(&payload.sandbox_username)
        .and_then(|sid| string_from_sid_bytes(&sid).map_err(anyhow::Error::msg))
        .unwrap_or_else(|err| format!("unresolved:{err}"));
    let group_sid = resolve_sandbox_users_group_sid()
        .and_then(|sid| string_from_sid_bytes(&sid).map_err(anyhow::Error::msg))
        .unwrap_or_else(|err| format!("unresolved:{err}"));
    let users_path = sandbox_secrets_dir(&payload.codex_home).join("sandbox_users.json");
    let marker_path = sandbox_dir(&payload.codex_home).join("setup_marker.json");
    log_line(
        log,
        &format!(
            "diagnose sandbox_identity user={} sid={} group=RunSealSandboxUsers group_sid={} secrets_exists={} marker_exists={} marker_version={} proxy_ports={:?} allow_local_binding={}",
            payload.sandbox_username,
            sandbox_sid,
            group_sid,
            users_path.exists(),
            marker_path.exists(),
            SETUP_VERSION,
            payload.proxy_ports,
            payload.allow_local_binding
        ),
    )?;
    for legacy_username in legacy_sandbox_usernames() {
        let legacy_present = resolve_sid(legacy_username).is_ok();
        log_line(
            log,
            &format!(
                "diagnose legacy_sandbox_user user={legacy_username} present={legacy_present}"
            ),
        )?;
    }
    Ok(())
}

fn run_read_acl_only(payload: &Payload, log: &mut dyn Write) -> Result<()> {
    let _read_acl_guard = acquire_read_acl_mutex()?;
    log_line(log, "applying read ACLs")?;
    let sandbox_group_sid = resolve_sandbox_users_group_sid()?;
    let sandbox_group_psid = sid_bytes_to_psid(&sandbox_group_sid)?;
    let mut refresh_errors: Vec<String> = Vec::new();
    if !payload.read_roots.is_empty() {
        let users_sid = resolve_sid("Users")?;
        let users_psid = sid_bytes_to_psid(&users_sid)?;
        let auth_sid = resolve_sid("Authenticated Users")?;
        let auth_psid = sid_bytes_to_psid(&auth_sid)?;
        let everyone_sid = resolve_sid("Everyone")?;
        let everyone_psid = sid_bytes_to_psid(&everyone_sid)?;
        let rx_psids = vec![users_psid, auth_psid, everyone_psid];
        let read_cap_sid = payload
            .read_cap_sid
            .as_deref()
            .map(LocalSid::from_string)
            .transpose()?;
        let all_application_packages = read_cap_sid
            .as_ref()
            .map(|_| LocalSid::from_string("S-1-15-2-1"))
            .transpose()?;
        let platform_read_psids = if read_cap_sid.is_some() {
            let mut psids = vec![users_psid, everyone_psid];
            if let Some(sid) = all_application_packages.as_ref() {
                psids.push(sid.as_ptr());
            }
            psids
        } else {
            Vec::new()
        };
        let subjects = ReadAclSubjects {
            sandbox_group_psid,
            rx_psids: &rx_psids,
            platform_read_psids: &platform_read_psids,
            read_cap_psid: read_cap_sid.as_ref().map(LocalSid::as_ptr),
        };
        apply_read_acls(
            &payload.read_roots,
            &subjects,
            log,
            &mut refresh_errors,
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
            "read",
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        )?;
        unsafe {
            if !users_psid.is_null() {
                LocalFree(users_psid as HLOCAL);
            }
            if !auth_psid.is_null() {
                LocalFree(auth_psid as HLOCAL);
            }
            if !everyone_psid.is_null() {
                LocalFree(everyone_psid as HLOCAL);
            }
        }
    }
    unsafe {
        if !sandbox_group_psid.is_null() {
            LocalFree(sandbox_group_psid as HLOCAL);
        }
    }
    if !refresh_errors.is_empty() {
        log_line(
            log,
            &format!("read ACL run completed with errors: {refresh_errors:?}"),
        )?;
        if payload.refresh_only || payload.read_cap_sid.is_some() {
            anyhow::bail!("read ACL run had errors");
        }
    }
    log_line(log, "read ACL run completed")?;
    Ok(())
}

fn provision_and_hide_sandbox_user(
    payload: &Payload,
    log: &mut dyn Write,
    sbx_dir: &Path,
) -> Result<()> {
    let provision_result =
        provision_sandbox_users(&payload.codex_home, &payload.sandbox_username, log);
    if let Err(err) = provision_result {
        if extract_setup_failure(&err).is_some() {
            return Err(err);
        }
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperUserProvisionFailed,
            format!("provision sandbox users failed: {err}"),
        )));
    }
    let users = vec![payload.sandbox_username.clone()];
    hide_newly_created_users(&users, sbx_dir);
    Ok(())
}

fn configure_sandbox_network(
    payload: &Payload,
    sandbox_sid_str: &str,
    log: &mut dyn Write,
) -> Result<()> {
    if let Some(appcontainer_sid) = payload.appcontainer_sid.as_deref() {
        ensure_appcontainer_loopback_exemption(appcontainer_sid).map_err(|err| {
            anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperFirewallRuleCreateOrAddFailed,
                format!("ensure AppContainer loopback exemption failed: {err}"),
            ))
        })?;
    }
    let proxy_allowlist_result = firewall::ensure_sandbox_proxy_allowlist(
        sandbox_sid_str,
        &payload.proxy_ports,
        payload.allow_local_binding,
        log,
    );
    if let Err(err) = proxy_allowlist_result {
        if extract_setup_failure(&err).is_some() {
            return Err(err);
        }
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperFirewallRuleCreateOrAddFailed,
            format!("ensure sandbox proxy allowlist failed: {err}"),
        )));
    }
    let firewall_result = firewall::ensure_sandbox_outbound_block(sandbox_sid_str, log);
    if let Err(err) = firewall_result {
        if extract_setup_failure(&err).is_some() {
            return Err(err);
        }
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperFirewallRuleCreateOrAddFailed,
            format!("ensure sandbox outbound block failed: {err}"),
        )));
    }
    install_wfp_filters(
        &payload.codex_home,
        &payload.sandbox_username,
        payload.appcontainer_sid.as_deref(),
        &payload.proxy_ports,
        payload.otel.as_ref(),
        |message| {
            let _ = log_line(log, message);
        },
    )?;
    Ok(())
}

fn quote_task_arg(arg: &str) -> String {
    let needs = arg.is_empty()
        || arg
            .chars()
            .any(|c| matches!(c, ' ' | '\t' | '\n' | '\r' | '"'));
    if !needs {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut bs = 0;
    for ch in arg.chars() {
        match ch {
            '\\' => {
                bs += 1;
            }
            '"' => {
                out.push_str(&"\\".repeat(bs * 2 + 1));
                out.push('"');
                bs = 0;
            }
            _ => {
                if bs > 0 {
                    out.push_str(&"\\".repeat(bs));
                    bs = 0;
                }
                out.push(ch);
            }
        }
    }
    if bs > 0 {
        out.push_str(&"\\".repeat(bs * 2));
    }
    out.push('"');
    out
}

fn scheduled_setup_result_path(codex_home: &Path, request_id: &str) -> PathBuf {
    sandbox_dir(codex_home).join(format!("{SCHEDULED_SETUP_RESULT_PREFIX}{request_id}.json"))
}

fn setup_task_request_id(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy();
    let rest = name.strip_prefix(SCHEDULED_SETUP_PAYLOAD_PREFIX)?;
    let request_id = rest.strip_suffix(".json")?;
    (!request_id.is_empty()).then(|| request_id.to_string())
}

fn ensure_scheduled_setup_task(codex_home: &Path, log: &mut dyn Write) -> Result<()> {
    let exe = std::env::current_exe().context("locate setup helper for scheduled task")?;
    let broker_home = codex_home.to_path_buf();
    let task_command = format!(
        "{} --task-run {}",
        quote_task_arg(&exe.to_string_lossy()),
        quote_task_arg(&broker_home.to_string_lossy())
    );
    let output = Command::new("schtasks.exe")
        .args([
            "/Create",
            "/TN",
            SCHEDULED_SETUP_TASK_NAME,
            "/TR",
            &task_command,
            "/SC",
            "ONCE",
            "/ST",
            "00:00",
            "/RL",
            "HIGHEST",
            "/F",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .context("run schtasks /Create")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "schtasks /Create failed with status {:?}: {}",
            output.status.code(),
            stderr.trim()
        );
    }
    log_line(
        log,
        &format!(
            "scheduled setup task configured name={SCHEDULED_SETUP_TASK_NAME} broker_home={}",
            broker_home.display()
        ),
    )?;
    Ok(())
}

fn lock_persistent_sandbox_dirs(
    payload: &Payload,
    sandbox_group_sid: &[u8],
    log: &mut dyn Write,
) -> Result<()> {
    lock_sandbox_dir(
        &sandbox_dir(&payload.codex_home),
        &payload.real_user,
        sandbox_group_sid,
        GRANT_ACCESS,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE,
        log,
    )
    .map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSandboxLockFailed,
            format!(
                "lock sandbox dir {} failed: {err}",
                sandbox_dir(&payload.codex_home).display()
            ),
        ))
    })?;
    lock_sandbox_dir(
        &sandbox_secrets_dir(&payload.codex_home),
        &payload.real_user,
        sandbox_group_sid,
        DENY_ACCESS,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE,
        log,
    )
    .map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSandboxLockFailed,
            format!(
                "lock sandbox secrets dir {} failed: {err}",
                sandbox_secrets_dir(&payload.codex_home).display()
            ),
        ))
    })?;
    let legacy_users = sandbox_dir(&payload.codex_home).join("sandbox_users.json");
    if legacy_users.exists() {
        let _ = std::fs::remove_file(&legacy_users);
    }
    Ok(())
}

fn lock_sandbox_bin_dir(
    payload: &Payload,
    sandbox_group_sid: &[u8],
    log: &mut dyn Write,
) -> Result<()> {
    lock_sandbox_dir(
        &sandbox_bin_dir(&payload.codex_home),
        &payload.real_user,
        sandbox_group_sid,
        GRANT_ACCESS,
        FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
        log,
    )
    .map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSandboxLockFailed,
            format!(
                "lock sandbox bin dir {} failed: {err}",
                sandbox_bin_dir(&payload.codex_home).display()
            ),
        ))
    })
}

fn run_provision_only(payload: &Payload, log: &mut dyn Write, sbx_dir: &Path) -> Result<()> {
    provision_and_hide_sandbox_user(payload, log, sbx_dir)?;
    let sandbox_sid = resolve_sid(&payload.sandbox_username).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSidResolveFailed,
            format!(
                "resolve SID for sandbox user {} failed: {err}",
                payload.sandbox_username
            ),
        ))
    })?;
    let sandbox_sid_str = string_from_sid_bytes(&sandbox_sid).map_err(anyhow::Error::msg)?;

    let sandbox_group_sid = resolve_sandbox_users_group_sid().map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSidResolveFailed,
            format!("resolve sandbox users group SID failed: {err}"),
        ))
    })?;

    configure_sandbox_network(payload, &sandbox_sid_str, log)?;

    lock_sandbox_bin_dir(payload, &sandbox_group_sid, log)?;
    lock_persistent_sandbox_dirs(payload, &sandbox_group_sid, log)?;
    log_note("setup provisioning binary completed", Some(sbx_dir));
    Ok(())
}

fn run_network_only(payload: &Payload, log: &mut dyn Write, sbx_dir: &Path) -> Result<()> {
    let sandbox_sid = resolve_sid(&payload.sandbox_username).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSidResolveFailed,
            format!(
                "resolve SID for sandbox user {} failed: {err}",
                payload.sandbox_username
            ),
        ))
    })?;
    let sandbox_sid_str = string_from_sid_bytes(&sandbox_sid).map_err(anyhow::Error::msg)?;
    configure_sandbox_network(payload, &sandbox_sid_str, log)?;
    log_note("setup network binary completed", Some(sbx_dir));
    Ok(())
}

fn run_setup_full(payload: &Payload, log: &mut dyn Write, sbx_dir: &Path) -> Result<()> {
    let refresh_only = payload.refresh_only;
    if !refresh_only {
        provision_and_hide_sandbox_user(payload, log, sbx_dir)?;
    }
    let sandbox_sid = resolve_sid(&payload.sandbox_username).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSidResolveFailed,
            format!(
                "resolve SID for sandbox user {} failed: {err}",
                payload.sandbox_username
            ),
        ))
    })?;
    let sandbox_sid_str = string_from_sid_bytes(&sandbox_sid).map_err(anyhow::Error::msg)?;

    let sandbox_group_sid = resolve_sandbox_users_group_sid().map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSidResolveFailed,
            format!("resolve sandbox users group SID failed: {err}"),
        ))
    })?;
    let sandbox_group_psid = sid_bytes_to_psid(&sandbox_group_sid).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSidResolveFailed,
            format!("convert sandbox users group SID to PSID failed: {err}"),
        ))
    })?;
    let sandbox_group_sid_str =
        string_from_sid_bytes(&sandbox_group_sid).map_err(anyhow::Error::msg)?;
    let sandbox_user_psid = sid_bytes_to_psid(&sandbox_sid).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSidResolveFailed,
            format!("convert sandbox user SID to PSID failed: {err}"),
        ))
    })?;

    let mut refresh_errors: Vec<String> = Vec::new();
    if !refresh_only {
        configure_sandbox_network(payload, &sandbox_sid_str, log)?;
    }

    if payload.appcontainer_sid.is_some() {
        unsafe { protect_dacl_from_inheritance(&payload.codex_home) }.with_context(|| {
            format!(
                "protect workspace-contained runtime root {} from host-private deny inheritance",
                payload.codex_home.display()
            )
        })?;
        unsafe { revoke_deny_read_ace(&payload.codex_home, sandbox_group_psid) }.with_context(
            || {
                format!(
                    "remove inherited sandbox deny-read ACE from workspace-contained runtime root {}",
                    payload.codex_home.display()
                )
            },
        )?;
    }

    let removed_deny_read_paths =
        unsafe { clear_legacy_persistent_deny_read_acls(&payload.codex_home) }
            .context("clear legacy deny-read ACLs")?;
    if removed_deny_read_paths != 0 {
        log_line(
            log,
            &format!("removed {removed_deny_read_paths} legacy deny-read ACLs"),
        )?;
    }

    if payload.read_roots.is_empty() {
        log_line(log, "no read roots to grant; skipping read ACL helper")?;
    } else if payload.read_cap_sid.is_some() {
        // Contained tokens enforce read restrictions before process creation,
        // so their capability grants cannot be delegated to the background helper.
        run_read_acl_only(payload, log)?;
    } else {
        match read_acl_mutex_exists() {
            Ok(true) => {
                log_line(log, "read ACL helper already running; skipping spawn")?;
            }
            Ok(false) => {
                spawn_read_acl_helper(payload, log).map_err(|err| {
                    anyhow::Error::new(SetupFailure::new(
                        SetupErrorCode::HelperReadAclHelperSpawnFailed,
                        format!("spawn read ACL helper failed: {err}"),
                    ))
                })?;
            }
            Err(err) => {
                log_line(
                    log,
                    &format!("read ACL mutex check failed: {err}; spawning anyway"),
                )?;
                spawn_read_acl_helper(payload, log).map_err(|spawn_err| {
                    anyhow::Error::new(SetupFailure::new(
                        SetupErrorCode::HelperReadAclHelperSpawnFailed,
                        format!(
                            "spawn read ACL helper failed after mutex error {err}: {spawn_err}"
                        ),
                    ))
                })?;
            }
        }
    }

    setup_runtime_bin::ensure_runseal_packaged_resources_readable(
        sandbox_group_psid,
        &mut refresh_errors,
        log,
    )?;

    if refresh_only {
        setup_runtime_bin::ensure_codex_app_runtime_bin_readable(
            sandbox_group_psid,
            &mut refresh_errors,
            log,
        )?;
    }

    let write_mask =
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE | FILE_DELETE_CHILD;
    let mut grant_tasks: Vec<(PathBuf, Vec<String>)> = Vec::new();

    let mut seen_deny_paths: HashSet<PathBuf> = HashSet::new();
    let mut seen_write_roots: HashSet<PathBuf> = HashSet::new();
    let canonical_command_cwd = canonicalize_path(&payload.command_cwd);

    for root in &payload.write_roots {
        if !seen_write_roots.insert(root.clone()) {
            continue;
        }
        if !root.exists() {
            log_line(
                log,
                &format!("write root {} missing; skipping", root.display()),
            )?;
            continue;
        }
        match unsafe { revoke_deny_read_ace(root, sandbox_group_psid) } {
            Ok(true) => log_line(
                log,
                &format!(
                    "removed stale deny-read ACE from write root {}",
                    root.display()
                ),
            )?,
            Ok(false) => {}
            Err(err) => {
                refresh_errors.push(format!(
                    "deny-read cleanup failed on write root {}: {}",
                    root.display(),
                    err
                ));
                log_line(
                    log,
                    &format!(
                        "deny-read cleanup failed on write root {}: {}; continuing",
                        root.display(),
                        err
                    ),
                )?;
            }
        }
        match unsafe { revoke_allow_write_ace(root, sandbox_user_psid) } {
            Ok(true) => log_line(
                log,
                &format!(
                    "removed stale sandbox user write ACE from write root {}",
                    root.display()
                ),
            )?,
            Ok(false) => {}
            Err(err) => {
                refresh_errors.push(format!(
                    "sandbox user write cleanup failed on write root {}: {}",
                    root.display(),
                    err
                ));
                log_line(
                    log,
                    &format!(
                        "sandbox user write cleanup failed on write root {}: {}; continuing",
                        root.display(),
                        err
                    ),
                )?;
            }
        }
        let mut need_grant = false;
        let is_command_cwd = is_command_cwd_root(root, &canonical_command_cwd);
        let cap_label = if is_command_cwd {
            "workspace_cap"
        } else {
            "root_cap"
        };
        let root_cap_sid_str = if payload.read_cap_sid.is_some() {
            workspace_appcontainer_write_capability_sid(
                &payload.codex_home,
                &payload.command_cwd,
                root,
            )?
        } else {
            workspace_write_cap_sid_for_root(&payload.codex_home, &payload.command_cwd, root)?
        };
        let root_cap_psid = unsafe {
            convert_string_sid_to_sid(&root_cap_sid_str)
                .ok_or_else(|| anyhow::anyhow!("convert write root capability SID failed"))?
        };
        let cap_has = match path_mask_allows(
            root,
            &[root_cap_psid],
            write_mask,
            /*require_all_bits*/ true,
        ) {
            Ok(h) => h,
            Err(e) => {
                refresh_errors.push(format!(
                    "write mask check failed on {} for {cap_label}: {}",
                    root.display(),
                    e
                ));
                log_line(
                    log,
                    &format!(
                        "write mask check failed on {} for {cap_label}: {}; continuing",
                        root.display(),
                        e
                    ),
                )?;
                false
            }
        };
        let group_has = match path_mask_allows(
            root,
            &[sandbox_group_psid],
            write_mask,
            /*require_all_bits*/ true,
        ) {
            Ok(h) => h,
            Err(e) => {
                refresh_errors.push(format!(
                    "write mask check failed on {} for sandbox_group: {}",
                    root.display(),
                    e
                ));
                log_line(
                    log,
                    &format!(
                        "write mask check failed on {} for sandbox_group: {}; continuing",
                        root.display(),
                        e
                    ),
                )?;
                false
            }
        };
        if !cap_has || !group_has {
            need_grant = true;
        }
        unsafe {
            LocalFree(root_cap_psid as HLOCAL);
        }
        if need_grant {
            log_line(log, &format!("granting write ACEs to {}", root.display()))?;
            grant_tasks.push((
                root.clone(),
                vec![sandbox_group_sid_str.clone(), root_cap_sid_str],
            ));
        }
    }

    let (tx, rx) = mpsc::channel::<(PathBuf, Result<bool>)>();
    std::thread::scope(|scope| {
        for (root, sid_strings) in grant_tasks {
            let tx = tx.clone();
            scope.spawn(move || {
                // Convert SID strings to psids locally in this thread.
                let mut psids: Vec<*mut c_void> = Vec::new();
                for sid_str in &sid_strings {
                    if let Some(psid) = unsafe { convert_string_sid_to_sid(sid_str) } {
                        psids.push(psid);
                    } else {
                        let _ = tx.send((root.clone(), Err(anyhow::anyhow!("convert SID failed"))));
                        return;
                    }
                }

                let res = unsafe { ensure_allow_write_aces(&root, &psids) };

                for psid in psids {
                    unsafe {
                        LocalFree(psid as HLOCAL);
                    }
                }
                let _ = tx.send((root, res));
            });
        }
        drop(tx);
        for (root, res) in rx {
            match res {
                Ok(_) => {}
                Err(e) => {
                    refresh_errors.push(format!("write ACE failed on {}: {}", root.display(), e));
                    if log_line(
                        log,
                        &format!("write ACE grant failed on {}: {}", root.display(), e),
                    )
                    .is_err()
                    {
                        // ignore log errors inside scoped thread
                    }
                }
            }
        }
    });

    for path in &payload.deny_write_paths {
        if !seen_deny_paths.insert(path.clone()) {
            continue;
        }

        // These are deny-write carveouts, not deny-read paths. They may come from explicit
        // read-only-under-a-writable-root carveouts in the transformed sandbox policy, or from
        // legacy protected children such as `.git`, `.codex`, and `.agents`.
        //
        // Deny ACEs attach to filesystem objects; if an explicit policy carveout does not exist
        // during setup, the sandbox could otherwise create it later under a writable parent and
        // bypass the carveout. Materialize missing carveouts as directories so the deny-write ACL
        // is present before the command starts. Legacy protected children are filtered before
        // payload creation, so this should not create sentinel directories in a workspace.
        if !path.exists() {
            std::fs::create_dir_all(path)
                .with_context(|| format!("failed to create deny-write path {}", path.display()))?;
        }

        if payload.read_cap_sid.is_some() {
            unsafe { protect_dacl_from_inheritance(path) }
                .with_context(|| format!("failed to protect deny-write path {}", path.display()))?;
        }

        let mut deny_sid_strs = workspace_write_cap_sids_for_path(
            &payload.codex_home,
            &payload.command_cwd,
            &payload.write_roots,
            path,
            payload.read_cap_sid.is_some(),
        )?;
        if let Some(appcontainer_sid) = payload.appcontainer_sid.as_ref() {
            deny_sid_strs.push(appcontainer_sid.clone());
        }
        for deny_sid_str in deny_sid_strs {
            let deny_psid = unsafe {
                convert_string_sid_to_sid(&deny_sid_str)
                    .ok_or_else(|| anyhow::anyhow!("convert deny capability SID failed"))?
            };

            if payload.read_cap_sid.is_some() {
                unsafe { revoke_allow_write_ace(path, deny_psid) }.with_context(|| {
                    format!(
                        "failed to remove inherited AppContainer write ACE from {}",
                        path.display()
                    )
                })?;
            }

            match unsafe { add_deny_write_ace(path, deny_psid) } {
                Ok(true) => {
                    log_line(
                        log,
                        &format!("applied deny ACE to protect {}", path.display()),
                    )?;
                }
                Ok(false) => {}
                Err(err) => {
                    refresh_errors.push(format!("deny ACE failed on {}: {err}", path.display()));
                    log_line(
                        log,
                        &format!("deny ACE failed on {}: {err}", path.display()),
                    )?;
                }
            }
            unsafe {
                LocalFree(deny_psid as HLOCAL);
            }
        }
    }

    lock_sandbox_bin_dir(payload, &sandbox_group_sid, log)?;

    if refresh_only {
        log_line(
            log,
            &format!(
                "setup refresh: processed {} write roots (read roots delegated); errors={:?}",
                payload.write_roots.len(),
                refresh_errors
            ),
        )?;
    }
    if !refresh_only {
        lock_persistent_sandbox_dirs(payload, &sandbox_group_sid, log)?;
        if let Err(err) = ensure_scheduled_setup_task(&payload.codex_home, log) {
            log_line(
                log,
                &format!("scheduled setup task configure failed: {err:?}"),
            )?;
        }
    }

    unsafe {
        if !sandbox_user_psid.is_null() {
            LocalFree(sandbox_user_psid as HLOCAL);
        }
    }
    unsafe {
        if !sandbox_group_psid.is_null() {
            LocalFree(sandbox_group_psid as HLOCAL);
        }
    }
    if refresh_only && !refresh_errors.is_empty() {
        log_line(
            log,
            &format!("setup refresh completed with errors: {refresh_errors:?}"),
        )?;
        anyhow::bail!("setup refresh had errors");
    }
    log_note("setup binary completed", Some(sbx_dir));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Payload;
    use super::SETUP_VERSION;
    use super::SetupInvocation;
    use super::parse_setup_invocation;
    use super::run_payload_file;
    use super::setup_task_request_id;
    use super::workspace_write_cap_sids_for_path;
    use codex_otel::StatsigMetricsSettings;
    use codex_windows_sandbox::load_or_create_cap_sids;
    use codex_windows_sandbox::workspace_write_cap_sid_for_root;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;

    fn payload_json() -> serde_json::Value {
        json!({
            "version": SETUP_VERSION,
            "sandbox_username": "RunSealSandbox",
            "codex_home": "C:\\codex-home",
            "command_cwd": "C:\\workspace",
            "read_roots": [],
            "write_roots": [],
            "proxy_ports": [],
            "real_user": "User",
        })
    }

    #[test]
    fn payload_defaults_otel_absent() {
        let payload: Payload = serde_json::from_value(payload_json()).expect("payload");

        assert_eq!(payload.otel, None);
    }

    #[test]
    fn payload_accepts_provision_only_mode() {
        let mut payload = payload_json();
        payload["mode"] = json!("provision-only");
        let payload: Payload = serde_json::from_value(payload).expect("payload");

        assert_eq!(payload.mode, super::SetupMode::ProvisionOnly);
    }

    #[test]
    fn payload_accepts_network_only_mode() {
        let mut payload = payload_json();
        payload["mode"] = json!("network-only");
        let payload: Payload = serde_json::from_value(payload).expect("payload");

        assert_eq!(payload.mode, super::SetupMode::NetworkOnly);
    }

    #[test]
    fn payload_accepts_otel_settings() {
        let mut payload = payload_json();
        payload["otel"] = json!({
            "environment": "prod",
        });
        let payload: Payload = serde_json::from_value(payload).expect("payload");

        assert_eq!(
            payload.otel,
            Some(StatsigMetricsSettings {
                environment: "prod".to_string(),
            })
        );
    }

    #[test]
    fn setup_invocation_parses_payload_file_and_task_run_modes() {
        let payload_args = vec![
            "--payload-file".to_string(),
            r"C:\sandbox\payloads\setup-payload-1.json".to_string(),
        ];
        assert_eq!(
            parse_setup_invocation(&payload_args).expect("payload invocation"),
            SetupInvocation::PayloadFile(PathBuf::from(
                r"C:\sandbox\payloads\setup-payload-1.json"
            ))
        );

        let task_args = vec!["--task-run".to_string(), r"C:\broker".to_string()];
        assert_eq!(
            parse_setup_invocation(&task_args).expect("task invocation"),
            SetupInvocation::TaskRun(PathBuf::from(r"C:\broker"))
        );

        let legacy_args = vec![r"eyJ2ZXJzaW9uIjoxMH0=".to_string()];
        assert!(parse_setup_invocation(&legacy_args).is_err());
    }

    #[test]
    fn payload_file_is_removed_after_read_even_when_json_is_invalid() {
        let temp = tempfile::tempdir().expect("tempdir");
        let payload_path = temp.path().join("setup-payload-invalid.json");
        fs::write(&payload_path, b"{not-json").expect("write invalid payload");

        let err = run_payload_file(&payload_path).expect_err("invalid json should fail");

        assert!(!payload_path.exists());
        assert!(err.to_string().contains("failed to parse payload json"));
    }

    #[test]
    fn scheduled_setup_payload_scan_uses_json_suffix() {
        assert_eq!(
            setup_task_request_id(PathBuf::from("setup-task-payload-123.json").as_path()),
            Some("123".to_string())
        );
        assert_eq!(
            setup_task_request_id(PathBuf::from("setup-task-payload-123.b64").as_path()),
            None
        );
    }

    #[test]
    fn deny_path_under_active_root_uses_only_matching_root_sid() {
        let temp = tempfile::tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let workspace = temp.path().join("workspace");
        let active_root = temp.path().join("active-root");
        let stale_root = temp.path().join("stale-root");
        let deny_path = active_root.join("protected");
        fs::create_dir_all(&codex_home).expect("create codex home");
        fs::create_dir_all(&workspace).expect("create workspace");
        fs::create_dir_all(&active_root).expect("create active root");
        fs::create_dir_all(&stale_root).expect("create stale root");
        fs::create_dir_all(&deny_path).expect("create deny path");

        let stale_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &stale_root)
            .expect("stale sid");
        let active_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &active_root)
            .expect("active sid");
        let workspace_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &workspace)
            .expect("workspace sid");
        let caps = load_or_create_cap_sids(&codex_home).expect("load caps");

        let deny_sids = workspace_write_cap_sids_for_path(
            &codex_home,
            &workspace,
            &[workspace.clone(), active_root],
            &deny_path,
            false,
        )
        .expect("deny sids");

        assert_eq!(deny_sids, vec![active_sid]);
        assert!(!deny_sids.contains(&workspace_sid));
        assert!(!deny_sids.contains(&stale_sid));
        assert!(!deny_sids.contains(&caps.workspace));
    }

    #[test]
    fn deny_path_outside_active_roots_falls_back_to_all_active_root_sids() {
        let temp = tempfile::tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let workspace = temp.path().join("workspace");
        let active_root = temp.path().join("active-root");
        let stale_root = temp.path().join("stale-root");
        let deny_path = temp.path().join("outside-deny");
        fs::create_dir_all(&codex_home).expect("create codex home");
        fs::create_dir_all(&workspace).expect("create workspace");
        fs::create_dir_all(&active_root).expect("create active root");
        fs::create_dir_all(&stale_root).expect("create stale root");
        fs::create_dir_all(&deny_path).expect("create deny path");

        let stale_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &stale_root)
            .expect("stale sid");
        let active_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &active_root)
            .expect("active sid");
        let workspace_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &workspace)
            .expect("workspace sid");
        let caps = load_or_create_cap_sids(&codex_home).expect("load caps");

        let deny_sids = workspace_write_cap_sids_for_path(
            &codex_home,
            &workspace,
            &[workspace.clone(), active_root],
            &deny_path,
            false,
        )
        .expect("deny sids");

        assert_eq!(deny_sids.len(), 2);
        assert!(deny_sids.contains(&workspace_sid));
        assert!(deny_sids.contains(&active_sid));
        assert!(!deny_sids.contains(&stale_sid));
        assert!(!deny_sids.contains(&caps.workspace));
    }

    #[test]
    fn deny_path_includes_nested_active_root_sid() {
        let temp = tempfile::tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let workspace = temp.path().join("workspace");
        let protected_dir = workspace.join(".codex");
        let nested_root = protected_dir.join("nested-root");
        fs::create_dir_all(&codex_home).expect("create codex home");
        fs::create_dir_all(&workspace).expect("create workspace");
        fs::create_dir_all(&nested_root).expect("create nested root");

        let workspace_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &workspace)
            .expect("workspace sid");
        let nested_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &nested_root)
            .expect("nested sid");

        let deny_sids = workspace_write_cap_sids_for_path(
            &codex_home,
            &workspace,
            &[workspace.clone(), nested_root],
            &protected_dir,
            false,
        )
        .expect("deny sids");

        assert_eq!(deny_sids, vec![workspace_sid, nested_sid]);
    }
}
