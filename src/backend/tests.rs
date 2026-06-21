use super::{
    BackendFeature, CapabilityStatus, ExecutionEnv, ExecutionStdin, LinuxCommunityBackend,
    MacosExperimentalBackend, RUNTIME_ROOT_MARKER, SandboxBackend, WindowsFilesystemAclDriver,
    WindowsFilesystemAclSubject, WindowsReferenceBackend, apply_private_filesystem_acl_transaction,
    cleanup_child_after_setup_error, environment_runtime_json, execute_windows_sandbox_plan,
    minimal_environment, missing_backend_features, path_string, policy_transition_busy_reason,
    spawn_local_command,
};
#[cfg(windows)]
use super::{
    POLICY_TRANSITION_BUSY_REASON, WindowsKillOnCloseJob, WindowsSandboxPolicyCohortKey,
    collect_workspace_contained_profile_denies, public_windows_setup_unavailable_reason,
    windows_explicit_deny_read_paths, windows_sandbox_command,
    windows_sandbox_execution_gate_for_key, windows_sandbox_path_key,
    windows_sandbox_workspace_roots_for_plan, windows_sandbox_write_roots_for_plan,
    windows_sensitive_profile_deny_read_paths_for_profile,
};
use crate::policy::{NetworkMode, normalize_policy};
use crate::windows::policy::{
    WindowsFilesystemAccess, WindowsFilesystemAclEntry, WindowsFilesystemAclPlan,
    WindowsFilesystemAclTransactionPlan, WindowsFilesystemRule, WindowsFilesystemRuleSource,
    WindowsHostRoots,
};
use serde_json::{Value, json};
#[cfg(windows)]
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::sync::{MutexGuard, OnceLock};
#[cfg(windows)]
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[cfg(windows)]
fn windows_sandbox_gate_test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap()
}

#[cfg(unix)]
fn symlink_dir_for_test(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(unix)]
fn symlink_file_for_test(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn symlink_dir_for_test(target: &Path, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_dir(target, link)
}

#[cfg(windows)]
fn symlink_file_for_test(target: &Path, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

#[cfg(windows)]
#[test]
fn windows_setup_unavailable_reason_hides_vendor_code() {
    assert_eq!(
        public_windows_setup_unavailable_reason(concat!("orchestrator_", "helper_launch_failed")),
        "windows sandbox setup unavailable; run `runseal setup windows-sandbox` to install or repair"
    );
}

#[cfg(windows)]
#[test]
fn windows_sandbox_execution_gate_allows_same_policy_and_rejects_mixed_policy() -> io::Result<()> {
    let _test_lock = windows_sandbox_gate_test_lock();
    let policy_a = WindowsSandboxPolicyCohortKey {
        policy_hash: "hash-a".to_string(),
    };
    let policy_b = WindowsSandboxPolicyCohortKey {
        policy_hash: "hash-b".to_string(),
    };

    let guard = windows_sandbox_execution_gate_for_key(policy_a.clone())?;
    let same_policy_guard = windows_sandbox_execution_gate_for_key(policy_a)?;
    drop(same_policy_guard);

    let err = match windows_sandbox_execution_gate_for_key(policy_b.clone()) {
        Ok(_) => return Err(io::Error::other("mixed-policy execution was not rejected")),
        Err(err) => err,
    };
    assert_eq!(
        policy_transition_busy_reason(&err),
        Some(POLICY_TRANSITION_BUSY_REASON)
    );

    drop(guard);

    let next_policy_guard = windows_sandbox_execution_gate_for_key(policy_b)?;
    drop(next_policy_guard);
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_explicit_deny_paths_feed_deny_read_overrides() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    let secret = tmp.path().join("secret");
    fs::create_dir_all(&cwd)?;
    fs::create_dir_all(&secret)?;
    let policy = normalize_policy(
        &json!({
            "version": "runseal.policy/v1",
            "sandbox_level": "workspace-write",
            "filesystem": {
                "write": [cwd],
                "deny": [secret],
            },
        }),
        &cwd,
        None,
    )
    .unwrap();
    let plan = WindowsReferenceBackend.fail_closed_plan("exec_explicit_deny", &cwd, &policy);
    let deny_keys = windows_explicit_deny_read_paths(&plan)
        .iter()
        .map(|path| windows_sandbox_path_key(path.as_path()))
        .collect::<HashSet<_>>();

    assert!(deny_keys.contains(&windows_sandbox_path_key(&secret)));
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_sensitive_profile_denies_include_credential_roots() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let profile = tmp.path().join("profile");
    let ssh = profile.join(".ssh");
    let codex = profile.join(".codex");
    let config = profile.join(".config");
    let roaming = profile.join("AppData").join("Roaming");
    let workspace = profile.join("workspace");
    for dir in [&ssh, &codex, &config, &roaming, &workspace] {
        fs::create_dir_all(dir)?;
    }

    let deny_paths = windows_sensitive_profile_deny_read_paths_for_profile(
        &profile,
        std::slice::from_ref(&workspace),
    );
    let deny_keys = deny_paths
        .iter()
        .map(|path| windows_sandbox_path_key(path.as_path()))
        .collect::<HashSet<_>>();

    assert!(deny_keys.contains(&windows_sandbox_path_key(&ssh)));
    assert!(deny_keys.contains(&windows_sandbox_path_key(&codex)));
    assert!(deny_keys.contains(&windows_sandbox_path_key(&config)));
    assert!(deny_keys.contains(&windows_sandbox_path_key(&roaming)));
    assert!(!deny_keys.contains(&windows_sandbox_path_key(&workspace)));
    Ok(())
}

#[cfg(windows)]
#[test]
fn workspace_contained_profile_denies_skip_allowed_workspace_branches() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let profile = tmp.path().join("profile");
    let workspace = profile.join("workspace");
    let documents = profile.join("Documents");
    let appdata = profile.join("AppData");
    let local = appdata.join("Local");
    let sandbox_temp = local.join("Temp").join("runseal");
    let roaming = appdata.join("Roaming");
    for dir in [&workspace, &documents, &sandbox_temp, &roaming] {
        fs::create_dir_all(dir)?;
    }

    let allowed_roots = vec![workspace.clone(), sandbox_temp.clone()];
    let mut deny_paths = Vec::new();
    let mut seen = HashSet::new();
    collect_workspace_contained_profile_denies(
        &profile,
        &allowed_roots,
        &mut deny_paths,
        &mut seen,
    );
    let deny_keys = deny_paths
        .iter()
        .map(|path| windows_sandbox_path_key(path.as_path()))
        .collect::<HashSet<_>>();

    assert!(deny_keys.contains(&windows_sandbox_path_key(&documents)));
    assert!(deny_keys.contains(&windows_sandbox_path_key(&roaming)));
    assert!(!deny_keys.contains(&windows_sandbox_path_key(&workspace)));
    assert!(!deny_keys.contains(&windows_sandbox_path_key(&sandbox_temp)));
    assert!(!deny_keys.contains(&windows_sandbox_path_key(&appdata)));
    assert!(!deny_keys.contains(&windows_sandbox_path_key(&local)));
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_sandbox_command_resolves_program_from_path_and_pathext() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let bin = tmp.path().join("bin");
    fs::create_dir_all(&bin)?;
    let tool = bin.join("tool.EXE");
    fs::write(&tool, b"")?;
    let env_map = HashMap::from([
        ("PATH".to_string(), bin.to_string_lossy().into_owned()),
        ("PATHEXT".to_string(), ".EXE;.CMD".to_string()),
    ]);
    let command = vec!["tool".to_string(), "--version".to_string()];

    let resolved = windows_sandbox_command(&command, &env_map);

    assert_eq!(resolved[0], tool.to_string_lossy());
    assert_eq!(resolved[1], "--version");
    Ok(())
}

#[derive(Default)]
struct RecordingAclDriver {
    events: Vec<String>,
    subjects: Vec<String>,
    fail_on_capture_root: Option<String>,
    fail_on_apply_root: Option<String>,
    fail_rollback: bool,
}

fn effective_environment_value(environment: &[(OsString, OsString)], key: &str) -> Option<String> {
    environment
        .iter()
        .rev()
        .find(|(candidate, _)| candidate.to_string_lossy().eq_ignore_ascii_case(key))
        .map(|(_, value)| value.to_string_lossy().into_owned())
}

impl WindowsFilesystemAclDriver for RecordingAclDriver {
    fn capture_rollback(&mut self, root: &str) -> io::Result<()> {
        self.events.push(format!("capture:{root}"));
        if self
            .fail_on_capture_root
            .as_deref()
            .is_some_and(|failed_root| failed_root == root)
        {
            return Err(io::Error::other(format!("capture failed for {root}")));
        }
        Ok(())
    }

    fn apply_entry(
        &mut self,
        subject: WindowsFilesystemAclSubject,
        entry: &WindowsFilesystemAclEntry,
    ) -> io::Result<()> {
        self.events.push(format!("apply:{}", entry.root()));
        self.subjects.push(subject.as_str().to_string());
        if self
            .fail_on_apply_root
            .as_deref()
            .is_some_and(|root| root == entry.root())
        {
            return Err(io::Error::other(format!(
                "apply failed for {}",
                entry.root()
            )));
        }
        Ok(())
    }

    fn rollback(&mut self) -> io::Result<()> {
        self.events.push("rollback".to_string());
        if self.fail_rollback {
            return Err(io::Error::other("rollback failed"));
        }
        Ok(())
    }
}

fn long_running_child() -> io::Result<std::process::Child> {
    let mut command = if cfg!(windows) {
        let mut command = std::process::Command::new("cmd");
        command.args(["/C", "ping -n 5 127.0.0.1 >NUL"]);
        command
    } else {
        let mut command = std::process::Command::new("sh");
        command.args(["-c", "sleep 5"]);
        command
    };
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
}

fn expected_windows_reference_supported_features() -> &'static [BackendFeature] {
    if cfg!(windows) {
        &[
            BackendFeature::FilesystemPolicy,
            BackendFeature::RuntimeRoots,
            BackendFeature::RuntimeEnvironment,
            BackendFeature::ProcessIsolation,
            BackendFeature::ProcessCleanup,
            BackendFeature::DirectNetworkDeny,
            BackendFeature::NetworkDisabled,
            BackendFeature::NetworkProxy,
            BackendFeature::ManagedProxy,
            BackendFeature::PolicyEpoch,
        ]
    } else {
        &[
            BackendFeature::RuntimeRoots,
            BackendFeature::RuntimeEnvironment,
            BackendFeature::ProcessCleanup,
        ]
    }
}

fn assert_probe_schema(probe: &Value, capability: &str, mechanism: &str) {
    assert_eq!(probe["capability"], capability);
    assert_eq!(probe["mechanism"], mechanism);
    assert_eq!(probe["status"], "unsupported");
    assert_eq!(probe["diagnostic_only"], true);
    assert!(probe.get("path").is_none());
    assert!(probe.get("argv").is_none());
    assert!(probe.get("private").is_none());
}

#[test]
fn missing_features_excludes_supported_backend_features() {
    let cwd = PathBuf::from("/workspace");
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();

    assert_eq!(
        missing_backend_features(&policy, &[BackendFeature::FilesystemPolicy]),
        vec![
            BackendFeature::RuntimeRoots,
            BackendFeature::RuntimeEnvironment,
            BackendFeature::ProcessIsolation,
            BackendFeature::ProcessCleanup,
            BackendFeature::DirectNetworkDeny,
            BackendFeature::NetworkProxy,
            BackendFeature::ManagedProxy,
        ]
    );
}

#[test]
fn capability_status_words_match_public_contract() {
    let statuses = CapabilityStatus::ALL.map(CapabilityStatus::as_str);
    assert_eq!(
        statuses,
        [
            "supported",
            "experimental",
            "unsupported",
            "unavailable",
            "requires_setup"
        ]
    );
}

#[test]
fn resource_limits_require_backend_feature() {
    let cwd = PathBuf::from("/workspace");
    let policy = normalize_policy(
        &json!({
            "version": "runseal.policy/v1",
            "resources": {
                "memory_bytes": 2147483648u64,
                "cpu_percent": 200
            }
        }),
        &cwd,
        Some(NetworkMode::Disabled),
    )
    .unwrap();

    assert!(
        policy
            .required_backend_feature_names()
            .contains(&"resource_limits")
    );
    assert!(missing_backend_features(&policy, &[]).contains(&BackendFeature::ResourceLimits));
}

#[test]
fn danger_full_access_requires_no_sandbox_backend_features() {
    let cwd = PathBuf::from("/workspace");
    let policy = normalize_policy(
        &json!("danger-full-access"),
        &cwd,
        Some(NetworkMode::Disabled),
    )
    .unwrap();

    assert!(missing_backend_features(&policy, &[]).is_empty());
    assert!(policy.allows_local_execution());
}

#[test]
fn windows_reference_does_not_compile_sandboxed_policy_as_local_execution() {
    let cwd = PathBuf::from("/workspace");
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();

    let result = WindowsReferenceBackend.compile_plan("exec_sandboxed", &cwd, &policy);
    #[cfg(windows)]
    let plan = result.unwrap();
    #[cfg(not(windows))]
    let plan = {
        let err = result.unwrap_err();
        assert_eq!(err.code, "BACKEND_CAPABILITY_MISSING");
        err.plan.map(|plan| *plan).unwrap()
    };

    assert_eq!(
        plan.enforcement,
        if cfg!(windows) {
            "windows-sandbox"
        } else {
            "fail-closed-preview"
        }
    );
    assert_ne!(plan.enforcement, "local-execution");
}

#[test]
fn local_spawn_rejects_sandboxed_plan() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let plan = WindowsReferenceBackend.fail_closed_plan("exec_no_local_spawn", &cwd, &policy);

    let err = spawn_local_command(
        &plan,
        &["runseal-command-that-must-not-start".to_string()],
        &cwd,
        ExecutionStdin::Empty,
        &ExecutionEnv::default(),
        None,
    )
    .unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    assert!(err.to_string().contains("refusing to spawn sandboxed plan"));
    Ok(())
}

#[test]
fn linux_skeleton_reports_community_track_without_sandbox_features() {
    assert_eq!(LinuxCommunityBackend.name(), "runseal-linux-community");
    assert_eq!(LinuxCommunityBackend.status(), "future-community");
    assert!(LinuxCommunityBackend.supported_features().is_empty());
    let capabilities = LinuxCommunityBackend.capabilities_json();
    assert_eq!(capabilities["features"]["process_isolation"], false);
    let probes = capabilities["capability_probes"].as_array().unwrap();
    assert_eq!(probes.len(), 8);
    assert_probe_schema(&probes[0], "filesystem_policy", "landlock");
    assert_probe_schema(&probes[1], "process_isolation", "user_namespaces");
    assert_probe_schema(&probes[2], "process_isolation", "mount_namespaces");
    assert_probe_schema(&probes[3], "process_isolation", "pid_namespaces");
    assert_probe_schema(&probes[4], "network_disabled", "network_namespaces");
    assert_probe_schema(&probes[5], "process_isolation", "seccomp");
    assert_probe_schema(&probes[6], "process_isolation", "bubblewrap");
    assert_probe_schema(
        &probes[7],
        "process_isolation",
        "unprivileged_user_namespaces",
    );
}

#[test]
fn linux_skeleton_fails_closed_for_sandboxed_policy() {
    let cwd = PathBuf::from("/workspace");
    let policy = normalize_policy(&json!("read-only"), &cwd, None).unwrap();

    let err = LinuxCommunityBackend
        .compile_plan("exec_linux_read_only", &cwd, &policy)
        .unwrap_err();

    assert_eq!(err.code, "BACKEND_CAPABILITY_MISSING");
    assert_eq!(err.support, "unsupported");
    assert_eq!(err.backend, LinuxCommunityBackend.name());
    let plan = err
        .plan
        .as_deref()
        .expect("Linux failure must include plan");
    assert_eq!(plan.backend, LinuxCommunityBackend.name());
    assert_eq!(plan.platform, "linux");
    assert_eq!(plan.enforcement, "fail-closed-preview");
    assert_eq!(plan.sandbox_level, "read-only");
    assert!(
        plan.runtime_root
            .as_deref()
            .unwrap()
            .ends_with("exec_linux_read_only")
    );
    assert_eq!(plan.process_boundary, "platform-sandbox");
    assert_eq!(plan.network_direct_egress, "deny");
    let public_plan = plan.json().to_string();
    assert!(!public_plan.contains("bubblewrap"));
    assert!(!public_plan.contains("landlock"));
    assert!(!public_plan.contains("namespace"));
}

#[test]
fn macos_skeleton_reports_experimental_track_without_sandbox_features() {
    assert_eq!(
        MacosExperimentalBackend.name(),
        "runseal-macos-experimental"
    );
    assert_eq!(MacosExperimentalBackend.status(), "experimental");
    assert!(MacosExperimentalBackend.supported_features().is_empty());
    let capabilities = MacosExperimentalBackend.capabilities_json();
    assert_eq!(capabilities["features"]["process_isolation"], false);
    let probes = capabilities["capability_probes"].as_array().unwrap();
    assert_eq!(probes.len(), 6);
    assert_probe_schema(&probes[0], "filesystem_policy", "sandbox_exec");
    assert_probe_schema(&probes[1], "filesystem_policy", "sandbox_exec_executable");
    assert_probe_schema(&probes[2], "platform_version", "macos_version");
    assert_probe_schema(&probes[3], "filesystem_policy", "temporary_profile");
    assert_probe_schema(&probes[4], "filesystem_policy", "canonical_paths");
    assert_probe_schema(&probes[5], "filesystem_policy", "symlink_path_model");
}

#[test]
fn macos_skeleton_fails_closed_for_sandboxed_policy() {
    let cwd = PathBuf::from("/workspace");
    let policy = normalize_policy(&json!("read-only"), &cwd, None).unwrap();

    let err = MacosExperimentalBackend
        .compile_plan("exec_macos_read_only", &cwd, &policy)
        .unwrap_err();

    assert_eq!(err.code, "BACKEND_CAPABILITY_MISSING");
    assert_eq!(err.support, "unsupported");
    assert_eq!(err.backend, MacosExperimentalBackend.name());
}

#[test]
fn windows_fail_closed_preview_includes_runtime_write_roots() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();

    let plan = WindowsReferenceBackend.fail_closed_plan("exec_preview", &cwd, &policy);

    assert!(plan.filesystem_write.contains(&path_string(&cwd)));
    for root in [
        plan.runtime_root.as_deref(),
        plan.profile_root.as_deref(),
        plan.synthetic_home.as_deref(),
        plan.temp_root.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        assert!(
            plan.filesystem_write.iter().any(|item| item == root),
            "filesystem.write must include runtime write root {root}"
        );
    }
    assert_eq!(plan.enforcement, "fail-closed-preview");
    assert_eq!(
        WindowsReferenceBackend.supported_features(),
        expected_windows_reference_supported_features()
    );
    Ok(())
}

#[test]
fn windows_fail_closed_preview_includes_runtime_environment_redirects() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("read-only"), &cwd, None).unwrap();

    let plan = WindowsReferenceBackend.fail_closed_plan("exec_env", &cwd, &policy);
    let runtime_env = environment_runtime_json(&plan.environment_runtime);

    assert_eq!(
        runtime_env["RUNSEAL_HOME"],
        json!(plan.synthetic_home.as_ref().unwrap())
    );
    assert_eq!(
        runtime_env["RUNSEAL_TMP"],
        json!(plan.temp_root.as_ref().unwrap())
    );
    assert_eq!(
        runtime_env["HOME"],
        json!(plan.synthetic_home.as_ref().unwrap())
    );
    assert_eq!(
        runtime_env["USERPROFILE"],
        json!(plan.profile_root.as_ref().unwrap())
    );
    assert_eq!(runtime_env["TEMP"], json!(plan.temp_root.as_ref().unwrap()));
    assert_eq!(runtime_env["TMP"], json!(plan.temp_root.as_ref().unwrap()));
    assert!(
        runtime_env["APPDATA"]
            .as_str()
            .unwrap_or_default()
            .contains("AppData")
    );
    assert!(
        runtime_env["LOCALAPPDATA"]
            .as_str()
            .unwrap_or_default()
            .contains("AppData")
    );
    Ok(())
}

#[test]
fn windows_fail_closed_preview_includes_proxy_network_guard() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();

    let plan = WindowsReferenceBackend.fail_closed_plan("exec_proxy", &cwd, &policy);

    assert_eq!(plan.network_mode, "proxy");
    assert_eq!(plan.network_direct_egress, "deny");
    assert_eq!(plan.network_managed_proxy, "required");
    assert!(plan.environment_proxy);
    assert_eq!(plan.process_boundary, "restricted-local-process");
    assert_eq!(plan.process_identity, "low-privilege");
    assert_eq!(plan.process_cleanup, "process-tree");
    assert_eq!(
        plan.private_process_sandbox_user_model,
        "single-sandbox-user"
    );
    assert_eq!(plan.private_process_token, "restricted-token");
    assert_eq!(plan.private_process_job, "kill-on-close-job");
    assert_eq!(plan.private_setup_account_name, "RunSealSandbox");
    assert_eq!(plan.private_setup_group_name, "RunSealSandboxUsers");
    assert_eq!(
        plan.private_setup_identity_artifacts,
        "single-sandbox-user-artifacts"
    );
    let private_setup_payload =
        serde_json::from_str::<Value>(plan.private_setup_payload.as_deref().unwrap()).unwrap();
    assert_eq!(
        private_setup_payload["codex_home"],
        json!(path_string(&cwd.join(".runseal").join("sandbox")))
    );
    assert_ne!(
        private_setup_payload["codex_home"],
        json!(plan.runtime_root.as_ref().unwrap())
    );
    assert_ne!(
        private_setup_payload["codex_home"],
        json!(plan.synthetic_home.as_ref().unwrap())
    );
    assert_eq!(private_setup_payload["sandbox_username"], "RunSealSandbox");
    assert!(private_setup_payload["real_user"].is_string());
    assert_eq!(private_setup_payload["refresh_only"], false);
    assert_eq!(private_setup_payload.get("sandbox_home"), None);
    assert_eq!(private_setup_payload.get("network"), None);
    assert_eq!(plan.filesystem_protected, vec!["workspace_metadata"]);
    let plan_json = plan.json();
    let public_plan = plan_json.to_string();
    assert!(!public_plan.contains("single-sandbox-user"));
    assert!(!public_plan.contains("RunSealSandbox"));
    assert!(!public_plan.contains("RunSealSandboxUsers"));
    assert!(!public_plan.contains("restricted-token"));
    assert!(!public_plan.contains("kill-on-close-job"));
    assert!(!public_plan.contains("single-sandbox-user-artifacts"));
    assert_eq!(
        plan_json["filesystem"]["protected"],
        json!(["workspace_metadata"])
    );
    assert_eq!(
        plan_json["process"],
        json!({
            "boundary": "restricted-local-process",
            "identity": "low-privilege",
            "cleanup": "process-tree",
        })
    );
    assert_eq!(plan_json["setup"]["requires_runtime_roots"], true);
    assert_eq!(plan_json["setup"]["requires_runtime_environment"], true);
    assert_eq!(plan_json["setup"]["requires_runtime_cleanup"], true);
    assert_eq!(plan_json["setup"]["requires_network_guard"], true);
    assert_eq!(plan_json["setup"]["requires_managed_proxy"], true);
    assert_eq!(plan_json["setup"]["requires_process_boundary"], true);
    assert_eq!(plan_json["setup"]["fail_closed_on_setup_error"], true);
    assert_eq!(
        WindowsReferenceBackend.supported_features(),
        expected_windows_reference_supported_features()
    );
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_sandbox_workspace_roots_include_runtime_roots() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let plan = WindowsReferenceBackend.fail_closed_plan("exec_vendor_roots", &cwd, &policy);

    let roots = windows_sandbox_workspace_roots_for_plan(&cwd, &plan)?;
    let root_keys = roots
        .iter()
        .map(|root| windows_sandbox_path_key(root.as_path()))
        .collect::<HashSet<_>>();

    assert_eq!(roots.len(), 5);
    for root in [
        path_string(&cwd),
        plan.runtime_root.clone().unwrap(),
        plan.profile_root.clone().unwrap(),
        plan.synthetic_home.clone().unwrap(),
        plan.temp_root.unwrap(),
    ] {
        assert!(root_keys.contains(&windows_sandbox_path_key(Path::new(&root))));
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_sandbox_write_roots_include_runtime_roots() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let plan = WindowsReferenceBackend.fail_closed_plan("exec_vendor_write_roots", &cwd, &policy);

    let roots = windows_sandbox_write_roots_for_plan(&plan)
        .into_iter()
        .map(|root| windows_sandbox_path_key(&root))
        .collect::<HashSet<_>>();

    for root in [
        path_string(&cwd),
        plan.runtime_root.clone().unwrap(),
        plan.profile_root.clone().unwrap(),
        plan.synthetic_home.clone().unwrap(),
        plan.temp_root.unwrap(),
    ] {
        assert!(roots.contains(&windows_sandbox_path_key(Path::new(&root))));
    }
    Ok(())
}

#[test]
fn runtime_environment_redirects_override_minimal_environment() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let plan = WindowsReferenceBackend.fail_closed_plan("exec_runtime_env", &cwd, &policy);

    let environment = minimal_environment(&plan);

    for (key, value) in &plan.environment_runtime {
        assert_eq!(
            effective_environment_value(&environment, key).as_deref(),
            Some(value.as_str()),
            "runtime environment value must win for {key}"
        );
    }
    assert_eq!(
        effective_environment_value(&environment, "RUNSEAL_HOME").as_deref(),
        plan.synthetic_home.as_deref()
    );
    assert_eq!(
        effective_environment_value(&environment, "TEMP").as_deref(),
        plan.temp_root.as_deref()
    );
    Ok(())
}

#[test]
fn windows_fail_closed_preview_includes_workspace_containment_protection() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-contained"), &cwd, None).unwrap();

    let plan = WindowsReferenceBackend.fail_closed_plan("exec_contained", &cwd, &policy);
    let plan_json = plan.json();

    assert_eq!(
        plan.filesystem_protected,
        vec!["workspace_metadata", "host_profile", "credential_roots"]
    );
    assert_eq!(
        plan_json["filesystem"]["protected"],
        json!(["workspace_metadata", "host_profile", "credential_roots"])
    );
    assert!(
        plan_json["filesystem"]["protected"]
            .as_array()
            .expect("protected labels must be an array")
            .iter()
            .all(Value::is_string)
    );
    Ok(())
}

#[test]
fn windows_fail_closed_preview_keeps_private_host_roots_out_of_json() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-contained"), &cwd, None).unwrap();
    let private_profile = "C:/Users/RunSealPrivateProfile";
    let host_roots = WindowsHostRoots::new(
        Some(private_profile.to_string()),
        Some(format!("{private_profile}/AppData/Roaming")),
        Some(format!("{private_profile}/AppData/Local")),
    );

    let plan = WindowsReferenceBackend.fail_closed_plan_with_host_roots(
        "exec_private",
        &cwd,
        &policy,
        host_roots,
    );

    assert!(
        plan.private_filesystem_deny
            .iter()
            .any(|root| root == private_profile)
    );
    assert!(plan.private_filesystem_rules.iter().any(|rule| {
        rule.access == WindowsFilesystemAccess::Deny && rule.root == private_profile
    }));
    let public_plan = plan.json().to_string();
    assert!(!public_plan.contains("RunSealPrivateProfile"));
    assert_eq!(
        plan.json()["filesystem"]["protected"],
        json!(["workspace_metadata", "host_profile", "credential_roots"])
    );
    Ok(())
}

#[test]
fn filesystem_rule_setup_rejects_non_concrete_roots() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan = WindowsReferenceBackend.fail_closed_plan("exec_rules", &cwd, &policy);

    for invalid_root in [
        "",
        "*",
        "/",
        "C:\\",
        "C:relative",
        "relative\\path",
        "../outside",
    ] {
        plan.private_filesystem_rules = vec![WindowsFilesystemRule {
            access: WindowsFilesystemAccess::ReadWrite,
            source: WindowsFilesystemRuleSource::PolicyWrite,
            root: invalid_root.to_string(),
        }];
        let err = plan.prepare_filesystem_rules().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string()
                .contains("invalid private filesystem rule root")
        );
    }
    Ok(())
}

#[test]
fn filesystem_rule_setup_requires_existing_allowed_roots() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let missing = cwd.join("missing");
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan = WindowsReferenceBackend.fail_closed_plan("exec_existing", &cwd, &policy);
    plan.private_filesystem_rules = vec![WindowsFilesystemRule {
        access: WindowsFilesystemAccess::ReadWrite,
        source: WindowsFilesystemRuleSource::PolicyWrite,
        root: path_string(&missing),
    }];

    let err = plan.prepare_filesystem_rules().unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("must exist before setup"));

    let file_root = cwd.join("file-root");
    fs::write(&file_root, b"not a directory")?;
    plan.private_filesystem_rules = vec![WindowsFilesystemRule {
        access: WindowsFilesystemAccess::ReadOnly,
        source: WindowsFilesystemRuleSource::PolicyRead,
        root: path_string(&file_root),
    }];
    let err = plan.prepare_filesystem_rules().unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("must be a directory"));

    fs::create_dir_all(&missing)?;
    plan.private_filesystem_rules = vec![WindowsFilesystemRule {
        access: WindowsFilesystemAccess::ReadWrite,
        source: WindowsFilesystemRuleSource::PolicyWrite,
        root: path_string(&missing),
    }];
    let prepared = plan.prepare_filesystem_rules()?;

    assert_eq!(prepared, vec![path_string(&missing)]);
    Ok(())
}

#[test]
fn filesystem_rule_setup_allows_absent_deny_roots() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let missing = cwd.join(".git");
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan = WindowsReferenceBackend.fail_closed_plan("exec_absent_deny", &cwd, &policy);
    plan.private_filesystem_rules = vec![WindowsFilesystemRule {
        access: WindowsFilesystemAccess::Deny,
        source: WindowsFilesystemRuleSource::ProtectedDeny,
        root: path_string(&missing),
    }];

    let prepared = plan.prepare_filesystem_rules()?;

    assert_eq!(prepared, vec![path_string(&missing)]);
    Ok(())
}

#[test]
fn filesystem_rule_setup_uses_injected_acl_driver() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan = WindowsReferenceBackend.fail_closed_plan("exec_driver", &cwd, &policy);
    plan.private_filesystem_rules = vec![WindowsFilesystemRule {
        access: WindowsFilesystemAccess::ReadWrite,
        source: WindowsFilesystemRuleSource::PolicyWrite,
        root: path_string(&cwd),
    }];
    let mut driver = RecordingAclDriver::default();

    let prepared = plan.prepare_filesystem_rules_with_driver(&mut driver)?;

    assert_eq!(prepared, vec![path_string(&cwd)]);
    assert_eq!(
        driver.events,
        vec![
            format!("capture:{}", path_string(&cwd)),
            format!("apply:{}", path_string(&cwd)),
        ]
    );
    assert_eq!(
        driver.subjects,
        vec!["single-sandbox-user-restricted-token"]
    );
    Ok(())
}

#[test]
fn filesystem_rule_setup_rejects_unbound_acl_subject() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan = WindowsReferenceBackend.fail_closed_plan("exec_unbound_acl", &cwd, &policy);
    plan.private_process_token = "none";
    plan.private_filesystem_rules = vec![WindowsFilesystemRule {
        access: WindowsFilesystemAccess::ReadWrite,
        source: WindowsFilesystemRuleSource::PolicyWrite,
        root: path_string(&cwd),
    }];

    let err = plan.prepare_filesystem_rules().unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(
        err.to_string()
            .contains("require a single sandbox user restricted process identity")
    );
    Ok(())
}

#[test]
fn filesystem_rule_setup_reports_deduplicated_rollback_roots() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan = WindowsReferenceBackend.fail_closed_plan("exec_rollback_roots", &cwd, &policy);
    plan.private_filesystem_rules = vec![
        WindowsFilesystemRule {
            access: WindowsFilesystemAccess::Deny,
            source: WindowsFilesystemRuleSource::ProtectedDeny,
            root: "C:/Workspace/.Git/".to_string(),
        },
        WindowsFilesystemRule {
            access: WindowsFilesystemAccess::Deny,
            source: WindowsFilesystemRuleSource::ProtectedDeny,
            root: "c:\\workspace\\.git".to_string(),
        },
    ];
    let mut driver = RecordingAclDriver::default();

    let prepared = plan.prepare_filesystem_rules_with_driver(&mut driver)?;

    assert_eq!(prepared, vec!["C:/Workspace/.Git/"]);
    assert_eq!(
        driver.events,
        vec![
            "capture:C:/Workspace/.Git/",
            "apply:C:/Workspace/.Git/",
            "apply:c:\\workspace\\.git",
        ]
    );
    assert_eq!(
        driver.subjects,
        vec![
            "single-sandbox-user-restricted-token",
            "single-sandbox-user-restricted-token"
        ]
    );
    Ok(())
}

#[test]
fn sandbox_setup_reports_runtime_and_filesystem_roots() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan = WindowsReferenceBackend.fail_closed_plan("exec_setup_roots", &cwd, &policy);
    plan.private_filesystem_rules = vec![WindowsFilesystemRule {
        access: WindowsFilesystemAccess::ReadWrite,
        source: WindowsFilesystemRuleSource::PolicyWrite,
        root: path_string(&cwd),
    }];
    let runtime_root = path_string(Path::new(plan.runtime_root.as_ref().unwrap()));

    let setup = plan.prepare_sandbox_setup()?;
    let prepared = setup.prepared_roots();

    assert!(prepared.iter().any(|root| root == &runtime_root));
    assert!(prepared.iter().any(|root| root == &path_string(&cwd)));
    setup.cleanup(&plan)?;
    Ok(())
}

#[test]
fn prepared_sandbox_cleanup_uses_setup_driver_state() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan =
        WindowsReferenceBackend.fail_closed_plan("exec_setup_driver_state", &cwd, &policy);
    plan.private_filesystem_rules = vec![WindowsFilesystemRule {
        access: WindowsFilesystemAccess::ReadWrite,
        source: WindowsFilesystemRuleSource::PolicyWrite,
        root: path_string(&cwd),
    }];
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    let setup = plan.prepare_sandbox_setup_with_driver(Box::new(RecordingAclDriver {
        fail_rollback: true,
        ..RecordingAclDriver::default()
    }))?;

    let err = setup
        .cleanup(&plan)
        .expect_err("cleanup must use setup driver rollback state");

    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert!(err.to_string().contains("rollback failed"));
    assert!(runtime_root.exists());
    plan.cleanup_runtime_roots()?;
    Ok(())
}

#[test]
fn sandbox_cleanup_rolls_back_filesystem_rules_before_runtime_tree() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan = WindowsReferenceBackend.fail_closed_plan("exec_cleanup_setup", &cwd, &policy);
    plan.private_filesystem_rules = vec![WindowsFilesystemRule {
        access: WindowsFilesystemAccess::ReadWrite,
        source: WindowsFilesystemRuleSource::PolicyWrite,
        root: path_string(&cwd),
    }];
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    plan.prepare_runtime_roots()?;
    let mut driver = RecordingAclDriver::default();

    let cleaned = plan.cleanup_sandbox_setup_with_driver(&mut driver)?;

    assert_eq!(driver.events, vec!["rollback"]);
    assert_eq!(cleaned, vec![path_string(&cwd), path_string(&runtime_root)]);
    assert!(!runtime_root.exists());
    Ok(())
}

#[test]
fn sandbox_cleanup_reports_deduplicated_rollback_roots() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan = WindowsReferenceBackend.fail_closed_plan("exec_cleanup_dedupe", &cwd, &policy);
    plan.private_filesystem_rules = vec![
        WindowsFilesystemRule {
            access: WindowsFilesystemAccess::Deny,
            source: WindowsFilesystemRuleSource::ProtectedDeny,
            root: "C:/Workspace/.Git/".to_string(),
        },
        WindowsFilesystemRule {
            access: WindowsFilesystemAccess::Deny,
            source: WindowsFilesystemRuleSource::ProtectedDeny,
            root: "c:\\workspace\\.git".to_string(),
        },
    ];
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    plan.prepare_runtime_roots()?;
    let mut driver = RecordingAclDriver::default();

    let cleaned = plan.cleanup_sandbox_setup_with_driver(&mut driver)?;

    assert_eq!(driver.events, vec!["rollback"]);
    assert_eq!(
        cleaned,
        vec!["C:/Workspace/.Git/".to_string(), path_string(&runtime_root)]
    );
    assert!(!runtime_root.exists());
    Ok(())
}

#[test]
fn sandbox_cleanup_preserves_runtime_tree_after_filesystem_rollback_failure() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan = WindowsReferenceBackend.fail_closed_plan("exec_cleanup_failure", &cwd, &policy);
    plan.private_filesystem_rules = vec![WindowsFilesystemRule {
        access: WindowsFilesystemAccess::ReadWrite,
        source: WindowsFilesystemRuleSource::PolicyWrite,
        root: path_string(&cwd),
    }];
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    plan.prepare_runtime_roots()?;
    let mut driver = RecordingAclDriver {
        fail_rollback: true,
        ..RecordingAclDriver::default()
    };

    let err = plan
        .cleanup_sandbox_setup_with_driver(&mut driver)
        .expect_err("filesystem rollback failure must fail cleanup");

    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert!(err.to_string().contains("rollback failed"));
    assert_eq!(driver.events, vec!["rollback"]);
    assert!(runtime_root.exists());
    plan.cleanup_runtime_roots()?;
    Ok(())
}

#[cfg(windows)]
#[test]
fn sandbox_execution_cleans_runtime_tree_after_vendor_home_prepare_failure() -> io::Result<()> {
    let _test_lock = windows_sandbox_gate_test_lock();
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(cwd.join(".runseal"))?;
    fs::write(cwd.join(".runseal").join("sandbox"), b"not a directory")?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let plan = WindowsReferenceBackend.fail_closed_plan("exec_vendor_home_failure", &cwd, &policy);
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    let command = vec![
        "cmd.exe".to_string(),
        "/C".to_string(),
        "echo ok".to_string(),
    ];

    let err = execute_windows_sandbox_plan(
        &plan,
        &command,
        &cwd,
        ExecutionStdin::Empty,
        &ExecutionEnv::default(),
        None,
    )
    .expect_err("vendor sandbox home preparation must fail");

    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    assert!(!runtime_root.exists());
    Ok(())
}

#[test]
fn cleanup_child_after_setup_error_preserves_setup_error() -> io::Result<()> {
    let child = long_running_child()?;

    let err = cleanup_child_after_setup_error(child, io::Error::other("setup failed"));

    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert_eq!(err.to_string(), "setup failed");
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_kill_on_close_job_terminates_child_process() -> io::Result<()> {
    let job = WindowsKillOnCloseJob::new()?;
    let mut child = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 30; exit 7"])
        .spawn()?;

    job.assign_child(&child)?;
    let started = Instant::now();
    drop(job);
    child.wait()?;

    assert!(
        started.elapsed() < Duration::from_secs(5),
        "kill-on-close job should terminate child before the command exits naturally"
    );
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_kill_on_close_job_leaves_unassigned_process_running() -> io::Result<()> {
    let job = WindowsKillOnCloseJob::new()?;
    let mut assigned = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 30; exit 7"])
        .spawn()?;
    let mut unassigned = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 30; exit 9"])
        .spawn()?;

    job.assign_child(&assigned)?;
    let started = Instant::now();
    drop(job);
    assigned.wait()?;
    let elapsed = started.elapsed();
    let unassigned_still_running = unassigned.try_wait()?.is_none();
    if unassigned_still_running {
        unassigned.kill()?;
    }
    let _ = unassigned.wait();

    assert!(
        elapsed < Duration::from_secs(5),
        "kill-on-close job should terminate only the assigned child promptly"
    );
    assert!(
        unassigned_still_running,
        "kill-on-close job must not terminate unrelated processes"
    );
    Ok(())
}

#[test]
fn filesystem_acl_transaction_executor_captures_before_apply() -> io::Result<()> {
    let rules = vec![
        WindowsFilesystemRule {
            access: WindowsFilesystemAccess::Deny,
            source: WindowsFilesystemRuleSource::ProtectedDeny,
            root: "C:/Workspace/.git".to_string(),
        },
        WindowsFilesystemRule {
            access: WindowsFilesystemAccess::ReadWrite,
            source: WindowsFilesystemRuleSource::PolicyWrite,
            root: "C:/Workspace".to_string(),
        },
    ];
    let acl_plan = WindowsFilesystemAclPlan::from_rules(&rules);
    let transaction = WindowsFilesystemAclTransactionPlan::from_acl_plan(&acl_plan);
    let mut driver = RecordingAclDriver::default();

    apply_private_filesystem_acl_transaction(
        &transaction,
        Some(WindowsFilesystemAclSubject::SingleSandboxUserRestrictedToken),
        &mut driver,
    )?;

    assert_eq!(
        driver.events,
        vec![
            "capture:C:/Workspace/.git",
            "apply:C:/Workspace/.git",
            "capture:C:/Workspace",
            "apply:C:/Workspace",
        ]
    );
    Ok(())
}

#[test]
fn filesystem_acl_transaction_executor_rolls_back_after_apply_failure() {
    let rules = vec![
        WindowsFilesystemRule {
            access: WindowsFilesystemAccess::Deny,
            source: WindowsFilesystemRuleSource::ProtectedDeny,
            root: "C:/Workspace/.git".to_string(),
        },
        WindowsFilesystemRule {
            access: WindowsFilesystemAccess::ReadWrite,
            source: WindowsFilesystemRuleSource::PolicyWrite,
            root: "C:/Workspace".to_string(),
        },
    ];
    let acl_plan = WindowsFilesystemAclPlan::from_rules(&rules);
    let transaction = WindowsFilesystemAclTransactionPlan::from_acl_plan(&acl_plan);
    let mut driver = RecordingAclDriver {
        events: Vec::new(),
        fail_on_apply_root: Some("C:/Workspace".to_string()),
        ..RecordingAclDriver::default()
    };

    let err = apply_private_filesystem_acl_transaction(
        &transaction,
        Some(WindowsFilesystemAclSubject::SingleSandboxUserRestrictedToken),
        &mut driver,
    )
    .expect_err("apply failure must be returned");

    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert!(err.to_string().contains("apply failed for C:/Workspace"));
    assert_eq!(
        driver.events,
        vec![
            "capture:C:/Workspace/.git",
            "apply:C:/Workspace/.git",
            "capture:C:/Workspace",
            "apply:C:/Workspace",
            "rollback",
        ]
    );
}

#[test]
fn filesystem_acl_transaction_executor_does_not_rollback_after_capture_failure() {
    let rules = vec![
        WindowsFilesystemRule {
            access: WindowsFilesystemAccess::Deny,
            source: WindowsFilesystemRuleSource::ProtectedDeny,
            root: "C:/Workspace/.git".to_string(),
        },
        WindowsFilesystemRule {
            access: WindowsFilesystemAccess::ReadWrite,
            source: WindowsFilesystemRuleSource::PolicyWrite,
            root: "C:/Workspace".to_string(),
        },
    ];
    let acl_plan = WindowsFilesystemAclPlan::from_rules(&rules);
    let transaction = WindowsFilesystemAclTransactionPlan::from_acl_plan(&acl_plan);
    let mut driver = RecordingAclDriver {
        fail_on_capture_root: Some("C:/Workspace/.git".to_string()),
        ..RecordingAclDriver::default()
    };

    let err = apply_private_filesystem_acl_transaction(
        &transaction,
        Some(WindowsFilesystemAclSubject::SingleSandboxUserRestrictedToken),
        &mut driver,
    )
    .expect_err("capture failure must be returned");

    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert!(
        err.to_string()
            .contains("capture failed for C:/Workspace/.git")
    );
    assert_eq!(driver.events, vec!["capture:C:/Workspace/.git"]);
}

#[test]
fn filesystem_acl_transaction_executor_reports_rollback_failure() {
    let rules = vec![
        WindowsFilesystemRule {
            access: WindowsFilesystemAccess::Deny,
            source: WindowsFilesystemRuleSource::ProtectedDeny,
            root: "C:/Workspace/.git".to_string(),
        },
        WindowsFilesystemRule {
            access: WindowsFilesystemAccess::ReadWrite,
            source: WindowsFilesystemRuleSource::PolicyWrite,
            root: "C:/Workspace".to_string(),
        },
    ];
    let acl_plan = WindowsFilesystemAclPlan::from_rules(&rules);
    let transaction = WindowsFilesystemAclTransactionPlan::from_acl_plan(&acl_plan);
    let mut driver = RecordingAclDriver {
        fail_on_apply_root: Some("C:/Workspace".to_string()),
        fail_rollback: true,
        ..RecordingAclDriver::default()
    };

    let err = apply_private_filesystem_acl_transaction(
        &transaction,
        Some(WindowsFilesystemAclSubject::SingleSandboxUserRestrictedToken),
        &mut driver,
    )
    .expect_err("rollback failure must be returned");

    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert!(
        err.to_string()
            .contains("private filesystem ACL transaction failed")
    );
    assert!(err.to_string().contains("apply failed for C:/Workspace"));
    assert!(err.to_string().contains("rollback failed"));
    assert_eq!(
        driver.events,
        vec![
            "capture:C:/Workspace/.git",
            "apply:C:/Workspace/.git",
            "capture:C:/Workspace",
            "apply:C:/Workspace",
            "rollback",
        ]
    );
}

#[test]
fn filesystem_rule_setup_rejects_inconsistent_acl_sources() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan = WindowsReferenceBackend.fail_closed_plan("exec_inconsistent_acl", &cwd, &policy);
    plan.private_filesystem_rules = vec![WindowsFilesystemRule {
        access: WindowsFilesystemAccess::Deny,
        source: WindowsFilesystemRuleSource::PolicyWrite,
        root: path_string(&cwd),
    }];

    let err = plan.prepare_filesystem_rules().unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(
        err.to_string()
            .contains("inconsistent private filesystem ACL entry")
    );
    Ok(())
}

#[test]
fn sandbox_setup_cleans_runtime_tree_after_filesystem_rule_failure() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan = WindowsReferenceBackend.fail_closed_plan("exec_bad_rule", &cwd, &policy);
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    plan.private_filesystem_rules.push(WindowsFilesystemRule {
        access: WindowsFilesystemAccess::Deny,
        source: WindowsFilesystemRuleSource::ProtectedDeny,
        root: "*".to_string(),
    });

    let Err(err) = plan.prepare_sandbox_setup() else {
        panic!("bad filesystem rule must fail sandbox setup");
    };

    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(!runtime_root.exists());
    Ok(())
}

#[test]
fn sandbox_setup_rejects_incomplete_process_boundary_before_creating_runtime_tree() -> io::Result<()>
{
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan =
        WindowsReferenceBackend.fail_closed_plan("exec_bad_process_boundary", &cwd, &policy);
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    plan.private_process_token = "none";

    let Err(err) = plan.prepare_sandbox_setup() else {
        panic!("incomplete process boundary must fail sandbox setup");
    };

    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("restricted process boundary"));
    assert!(!runtime_root.exists());
    Ok(())
}

#[test]
fn sandbox_setup_rejects_incomplete_network_guard_before_runtime_tree() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan =
        WindowsReferenceBackend.fail_closed_plan("exec_bad_network_guard", &cwd, &policy);
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    plan.network_managed_proxy = "none";

    let Err(err) = plan.prepare_sandbox_setup() else {
        panic!("incomplete network guard must fail sandbox setup");
    };

    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("network guard"));
    assert!(!runtime_root.exists());
    Ok(())
}

#[test]
fn sandbox_setup_rejects_non_single_user_model_before_runtime_tree() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan = WindowsReferenceBackend.fail_closed_plan("exec_bad_user_model", &cwd, &policy);
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    plan.private_process_sandbox_user_model = "multiple-sandbox-users";

    let Err(err) = plan.prepare_sandbox_setup() else {
        panic!("non-single sandbox user model must fail sandbox setup");
    };

    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("single sandbox user"));
    assert!(!runtime_root.exists());
    Ok(())
}

#[test]
fn sandbox_setup_rejects_non_single_user_setup_artifacts_before_runtime_tree() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan =
        WindowsReferenceBackend.fail_closed_plan("exec_bad_user_artifacts", &cwd, &policy);
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    plan.private_setup_identity_artifacts = "multiple-sandbox-user-artifacts";

    let Err(err) = plan.prepare_sandbox_setup() else {
        panic!("non-single sandbox user setup artifacts must fail sandbox setup");
    };

    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("setup identity artifacts"));
    assert!(!runtime_root.exists());
    Ok(())
}

#[test]
fn sandbox_setup_rejects_missing_single_user_setup_payload_before_runtime_tree() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan =
        WindowsReferenceBackend.fail_closed_plan("exec_missing_setup_payload", &cwd, &policy);
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    plan.private_setup_payload = None;

    let Err(err) = plan.prepare_sandbox_setup() else {
        panic!("missing single-user setup payload must fail sandbox setup");
    };

    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("setup identity artifacts"));
    assert!(!runtime_root.exists());
    Ok(())
}

#[test]
fn sandbox_setup_rejects_unexpected_setup_account_before_runtime_tree() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan =
        WindowsReferenceBackend.fail_closed_plan("exec_bad_setup_account", &cwd, &policy);
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    plan.private_setup_account_name = "OtherSandboxUser";

    let Err(err) = plan.prepare_sandbox_setup() else {
        panic!("unexpected setup account must fail sandbox setup");
    };

    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("setup identity artifacts"));
    assert!(!runtime_root.exists());
    Ok(())
}

#[test]
fn runtime_setup_refuses_invalid_execution_id_before_creating_runtime_tree() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let plan = WindowsReferenceBackend.fail_closed_plan("../outside", &cwd, &policy);

    let err = plan.prepare_runtime_roots().unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(!cwd.join(".runseal").join("outside").exists());
    Ok(())
}

#[test]
fn runtime_setup_refuses_plan_outside_workspace_runtime_dir() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let outside = tmp.path().join("outside-runtime");
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan = WindowsReferenceBackend.fail_closed_plan("exec_outside_setup", &cwd, &policy);
    plan.runtime_root = Some(path_string(&outside));

    let err = plan.prepare_runtime_roots().unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(!outside.exists());
    Ok(())
}

#[test]
fn runtime_setup_refuses_child_root_outside_workspace_runtime_dir() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let outside = tmp.path().join("outside-profile");
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan =
        WindowsReferenceBackend.fail_closed_plan("exec_outside_child_setup", &cwd, &policy);
    plan.profile_root = Some(path_string(&outside));

    let err = plan.prepare_runtime_roots().unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(!outside.exists());
    Ok(())
}

#[test]
fn runtime_setup_refuses_environment_root_outside_workspace_runtime_dir() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let outside = tmp.path().join("outside-env");
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan =
        WindowsReferenceBackend.fail_closed_plan("exec_outside_env_setup", &cwd, &policy);
    plan.environment_runtime
        .push(("RUNSEAL_BAD".to_string(), path_string(&outside)));

    let err = plan.prepare_runtime_roots().unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(!outside.exists());
    Ok(())
}

#[test]
fn runtime_setup_allows_windows_home_drive_environment_components() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan = WindowsReferenceBackend.fail_closed_plan("exec_home_components", &cwd, &policy);
    plan.environment_runtime
        .push(("HOMEDRIVE".to_string(), "C:".to_string()));
    plan.environment_runtime
        .push(("HOMEPATH".to_string(), "\\sandbox\\profile".to_string()));

    let prepared = plan.prepare_runtime_roots()?;

    assert!(!prepared.iter().any(|root| root == "C:"));
    assert!(!prepared.iter().any(|root| root == "\\sandbox\\profile"));
    plan.cleanup_runtime_roots()?;
    Ok(())
}

#[test]
fn runtime_setup_refuses_mismatched_runtime_marker() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let plan = WindowsReferenceBackend.fail_closed_plan("exec_setup_marker", &cwd, &policy);
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    fs::create_dir_all(&runtime_root)?;
    fs::write(runtime_root.join(RUNTIME_ROOT_MARKER), b"exec_other")?;

    let err = plan.prepare_runtime_roots().unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(runtime_root.exists());
    Ok(())
}

#[test]
fn runtime_setup_cleans_fresh_runtime_tree_after_marker_write_failure() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan = WindowsReferenceBackend.fail_closed_plan("exec_marker_dir", &cwd, &policy);
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    plan.profile_root = Some(path_string(&runtime_root.join(RUNTIME_ROOT_MARKER)));

    let err = plan.prepare_runtime_roots().unwrap_err();

    assert!(!err.to_string().contains("runtime cleanup failed"), "{err}");
    assert!(!runtime_root.exists());
    Ok(())
}

#[cfg(any(unix, windows))]
#[test]
fn runtime_setup_refuses_symlinked_runtime_marker() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let plan = WindowsReferenceBackend.fail_closed_plan("exec_setup_marker_symlink", &cwd, &policy);
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    fs::create_dir_all(&runtime_root)?;
    let marker_target = tmp.path().join("marker-target");
    fs::write(&marker_target, plan.execution_id.as_bytes())?;
    if let Err(err) = symlink_file_for_test(&marker_target, &runtime_root.join(RUNTIME_ROOT_MARKER))
    {
        if err.kind() == io::ErrorKind::PermissionDenied {
            return Ok(());
        }
        return Err(err);
    }

    let err = plan.prepare_runtime_roots().unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(runtime_root.exists());
    Ok(())
}

#[cfg(any(unix, windows))]
#[test]
fn runtime_setup_refuses_existing_runtime_tree_symlink_entry() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let plan = WindowsReferenceBackend.fail_closed_plan("exec_setup_tree_symlink", &cwd, &policy);
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    fs::create_dir_all(&runtime_root)?;
    fs::write(
        runtime_root.join(RUNTIME_ROOT_MARKER),
        plan.execution_id.as_bytes(),
    )?;
    let target = tmp.path().join("outside-target");
    fs::write(&target, b"external")?;
    if let Err(err) = symlink_file_for_test(&target, &runtime_root.join("linked-file")) {
        if err.kind() == io::ErrorKind::PermissionDenied {
            return Ok(());
        }
        return Err(err);
    }

    let err = plan.prepare_runtime_roots().unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(runtime_root.exists());
    Ok(())
}

#[cfg(any(unix, windows))]
#[test]
fn runtime_setup_refuses_symlink_ancestor_before_creating_runtime_tree() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let outside = tmp.path().join("outside-env");
    fs::create_dir_all(&outside)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan =
        WindowsReferenceBackend.fail_closed_plan("exec_symlink_env_setup", &cwd, &policy);
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    fs::create_dir_all(&runtime_root)?;
    fs::write(
        runtime_root.join(RUNTIME_ROOT_MARKER),
        plan.execution_id.as_bytes(),
    )?;
    let link = runtime_root.join("link");
    if let Err(err) = symlink_dir_for_test(&outside, &link) {
        if err.kind() == io::ErrorKind::PermissionDenied {
            return Ok(());
        }
        return Err(err);
    }
    plan.environment_runtime.push((
        "RUNSEAL_LINKED".to_string(),
        path_string(&link.join("child")),
    ));

    let err = plan.prepare_runtime_roots().unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(!outside.join("child").exists());
    Ok(())
}

#[cfg(any(unix, windows))]
#[test]
fn runtime_setup_refuses_runtime_parent_symlink_before_creating_runtime_tree() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(cwd.join(".runseal"))?;
    let outside = tmp.path().join("outside-runtime-parent");
    fs::create_dir_all(&outside)?;
    let link = cwd.join(".runseal").join("runtime");
    if let Err(err) = symlink_dir_for_test(&outside, &link) {
        if err.kind() == io::ErrorKind::PermissionDenied {
            return Ok(());
        }
        return Err(err);
    }
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let plan =
        WindowsReferenceBackend.fail_closed_plan("exec_runtime_parent_symlink", &cwd, &policy);

    let err = plan.prepare_runtime_roots().unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(!outside.join("exec_runtime_parent_symlink").exists());
    Ok(())
}

#[test]
fn runtime_cleanup_removes_prepared_runtime_tree() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let plan = WindowsReferenceBackend.fail_closed_plan("exec_cleanup", &cwd, &policy);
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());

    let prepared = plan.prepare_runtime_roots()?;
    assert!(runtime_root.join(RUNTIME_ROOT_MARKER).is_file());
    let prepared_len = prepared.len();
    let mut unique_prepared = prepared;
    unique_prepared.sort();
    unique_prepared.dedup();
    assert_eq!(prepared_len, unique_prepared.len());
    assert!(
        runtime_root
            .join("profile")
            .join("AppData")
            .join("Roaming")
            .is_dir()
    );
    assert!(
        runtime_root
            .join("profile")
            .join("AppData")
            .join("Local")
            .is_dir()
    );

    let cleaned = plan.cleanup_runtime_roots()?;

    assert_eq!(cleaned, vec![path_string(&runtime_root)]);
    assert!(!runtime_root.exists());
    Ok(())
}

#[test]
fn runtime_cleanup_refuses_unmarked_runtime_tree() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let plan = WindowsReferenceBackend.fail_closed_plan("exec_unmarked", &cwd, &policy);
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    fs::create_dir_all(&runtime_root)?;

    let err = plan.cleanup_runtime_roots().unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(runtime_root.exists());
    Ok(())
}

#[test]
fn runtime_cleanup_refuses_mismatched_runtime_marker() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let plan = WindowsReferenceBackend.fail_closed_plan("exec_marker", &cwd, &policy);
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    fs::create_dir_all(&runtime_root)?;
    fs::write(runtime_root.join(RUNTIME_ROOT_MARKER), b"exec_other")?;

    let err = plan.cleanup_runtime_roots().unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(runtime_root.exists());
    Ok(())
}

#[cfg(any(unix, windows))]
#[test]
fn runtime_cleanup_refuses_symlinked_runtime_marker() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let plan =
        WindowsReferenceBackend.fail_closed_plan("exec_cleanup_marker_symlink", &cwd, &policy);
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    fs::create_dir_all(&runtime_root)?;
    let marker_target = tmp.path().join("marker-target");
    fs::write(&marker_target, plan.execution_id.as_bytes())?;
    if let Err(err) = symlink_file_for_test(&marker_target, &runtime_root.join(RUNTIME_ROOT_MARKER))
    {
        if err.kind() == io::ErrorKind::PermissionDenied {
            return Ok(());
        }
        return Err(err);
    }

    let err = plan.cleanup_runtime_roots().unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(runtime_root.exists());
    Ok(())
}

#[cfg(any(unix, windows))]
#[test]
fn runtime_cleanup_refuses_runtime_tree_symlink_entry() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(&cwd)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let plan = WindowsReferenceBackend.fail_closed_plan("exec_cleanup_tree_symlink", &cwd, &policy);
    let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
    fs::create_dir_all(&runtime_root)?;
    fs::write(
        runtime_root.join(RUNTIME_ROOT_MARKER),
        plan.execution_id.as_bytes(),
    )?;
    let target = tmp.path().join("outside-target");
    fs::write(&target, b"external")?;
    if let Err(err) = symlink_file_for_test(&target, &runtime_root.join("linked-file")) {
        if err.kind() == io::ErrorKind::PermissionDenied {
            return Ok(());
        }
        return Err(err);
    }

    let err = plan.cleanup_runtime_roots().unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(runtime_root.exists());
    Ok(())
}

#[test]
fn runtime_cleanup_refuses_plan_outside_workspace_runtime_dir() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    let outside = tmp.path().join("outside-runtime");
    fs::create_dir_all(&cwd)?;
    fs::create_dir_all(&outside)?;
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let mut plan = WindowsReferenceBackend.fail_closed_plan("exec_outside", &cwd, &policy);
    fs::write(
        outside.join(RUNTIME_ROOT_MARKER),
        plan.execution_id.as_bytes(),
    )?;
    plan.runtime_root = Some(path_string(&outside));

    let err = plan.cleanup_runtime_roots().unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(outside.exists());
    Ok(())
}

#[cfg(any(unix, windows))]
#[test]
fn runtime_cleanup_refuses_runtime_parent_symlink() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().join("workspace");
    fs::create_dir_all(cwd.join(".runseal"))?;
    let outside = tmp.path().join("outside-runtime-parent");
    fs::create_dir_all(&outside)?;
    let link = cwd.join(".runseal").join("runtime");
    if let Err(err) = symlink_dir_for_test(&outside, &link) {
        if err.kind() == io::ErrorKind::PermissionDenied {
            return Ok(());
        }
        return Err(err);
    }
    let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
    let plan =
        WindowsReferenceBackend.fail_closed_plan("exec_cleanup_parent_symlink", &cwd, &policy);
    let outside_runtime = outside.join("exec_cleanup_parent_symlink");
    fs::create_dir_all(&outside_runtime)?;
    fs::write(
        outside_runtime.join(RUNTIME_ROOT_MARKER),
        plan.execution_id.as_bytes(),
    )?;

    let err = plan.cleanup_runtime_roots().unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(outside_runtime.exists());
    Ok(())
}
