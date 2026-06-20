use super::*;
use std::time::Duration;

impl WindowsReferenceBackend {
    pub(super) fn fail_closed_plan(
        self,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> PlatformSandboxPlan {
        self.fail_closed_plan_with_host_roots(
            execution_id,
            cwd,
            policy,
            WindowsHostRoots::from_current_environment(),
        )
    }

    pub(super) fn fail_closed_plan_with_host_roots(
        self,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
        host_roots: WindowsHostRoots,
    ) -> PlatformSandboxPlan {
        let runtime_root = cwd.join(".runseal").join("runtime").join(execution_id);
        let profile_root = runtime_root.join("profile");
        let synthetic_home = runtime_root.join("home");
        let temp_root = runtime_root.join("temp");
        let windows_policy = WindowsPolicyPlan::from_policy_runtime_and_host_roots(
            policy,
            Some(WindowsRuntimeRoots::new(
                path_string(&runtime_root),
                path_string(&profile_root),
                path_string(&synthetic_home),
                path_string(&temp_root),
            )),
            host_roots,
        );
        let private_filesystem_deny = windows_policy.filesystem.private_protected_roots.clone();
        let private_filesystem_rules = windows_policy.filesystem.enforcement_rules();
        let private_process_sandbox_user_model = windows_policy.process.sandbox_user_model.as_str();
        let private_setup_account_name = windows_policy
            .process
            .sandbox_user_model
            .local_account_name();
        let private_setup_group_name = windows_policy.process.sandbox_user_model.local_group_name();
        let private_setup_identity_artifacts = windows_policy
            .process
            .sandbox_user_model
            .setup_identity_artifacts();
        let private_process_token = windows_policy.process.token.as_str();
        let private_process_job = windows_policy.process.job.as_str();
        let vendor_profile = WindowsVendorSandboxProfile::from_policy(policy);
        let vendor_sandbox_home = vendor_sandbox_home(cwd);
        let private_setup_payload = vendor_profile.single_user_setup_payload(
            &vendor_sandbox_home,
            cwd,
            &windows_setup_real_user(),
        );
        #[cfg(windows)]
        let private_vendor_permission_profile = vendor_profile
            .permission_profile()
            .ok()
            .and_then(|profile| serde_json::to_string(&profile).ok());
        #[cfg(not(windows))]
        let private_vendor_permission_profile = None;
        let filesystem_write = windows_policy.filesystem.effective_write_roots();

        PlatformSandboxPlan {
            backend: self.name(),
            backend_status: self.status(),
            platform: self.platform(),
            execution_id: execution_id.to_string(),
            policy_id: policy.id.clone(),
            policy_hash: policy.hash(),
            sandbox_level: policy.sandbox_level.as_str(),
            enforcement: "fail-closed-preview",
            cwd: path_string(cwd),
            runtime_root: Some(path_string(&runtime_root)),
            profile_root: Some(path_string(&profile_root)),
            synthetic_home: Some(path_string(&synthetic_home)),
            temp_root: Some(path_string(&temp_root)),
            filesystem_read: windows_policy.filesystem.read_roots,
            filesystem_write,
            filesystem_deny: windows_policy.filesystem.protected_roots,
            filesystem_protected: protected_filesystem_labels(policy),
            private_filesystem_deny,
            private_filesystem_rules,
            process_boundary: windows_policy.process.boundary.as_str(),
            process_identity: windows_policy.process.identity.as_str(),
            process_cleanup: windows_policy.process.cleanup.as_str(),
            private_process_sandbox_user_model,
            private_process_token,
            private_process_job,
            private_setup_account_name,
            private_setup_group_name,
            private_setup_identity_artifacts,
            private_setup_payload: private_setup_payload.map(|payload| payload.to_string()),
            private_vendor_permission_profile,
            network_mode: windows_policy.network.guard.as_str(),
            network_direct_egress: windows_policy.network.direct_egress.as_str(),
            network_managed_proxy: windows_policy.network.managed_proxy.as_str(),
            environment_inherit: policy.environment.inherit.clone(),
            environment_scrub: policy.environment.scrub.clone(),
            environment_proxy: windows_policy.network.inject_proxy_environment,
            environment_runtime: windows_policy.environment.runtime,
            required_backend_features: policy.required_backend_feature_names(),
        }
    }
}

pub(super) fn has_single_user_setup_payload(payload: Option<&str>) -> bool {
    let Some(payload) = payload else {
        return false;
    };
    let Ok(payload) = serde_json::from_str::<Value>(payload) else {
        return false;
    };

    payload.get("sandbox_username").and_then(Value::as_str) == Some("RunSealSandbox")
        && payload.get("codex_home").and_then(Value::as_str).is_some()
        && payload.get("command_cwd").and_then(Value::as_str).is_some()
        && payload.get("real_user").and_then(Value::as_str).is_some()
        && payload.get("sandbox_home").is_none()
        && payload.get("network").is_none()
        && payload.get("offline_username").is_none()
        && payload.get("online_username").is_none()
}

fn windows_setup_real_user() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "Administrators".to_string())
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsReferenceBackend;

#[cfg(windows)]
const WINDOWS_REFERENCE_SUPPORTED_FEATURES: &[BackendFeature] = &[
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
    BackendFeature::SetupReadiness,
    BackendFeature::StdinBytes,
    BackendFeature::StdinFile,
    BackendFeature::AuditJsonl,
];

#[cfg(not(windows))]
const WINDOWS_REFERENCE_SUPPORTED_FEATURES: &[BackendFeature] = &[
    BackendFeature::RuntimeRoots,
    BackendFeature::RuntimeEnvironment,
    BackendFeature::ProcessCleanup,
    BackendFeature::SetupReadiness,
    BackendFeature::StdinBytes,
    BackendFeature::StdinFile,
    BackendFeature::AuditJsonl,
];

impl SandboxBackend for WindowsReferenceBackend {
    fn name(&self) -> &'static str {
        "runseal-windows-reference"
    }

    fn status(&self) -> &'static str {
        if cfg!(windows) {
            "reference"
        } else {
            "scaffold"
        }
    }

    fn platform(&self) -> &'static str {
        "windows"
    }

    fn supported_features(&self) -> &'static [BackendFeature] {
        WINDOWS_REFERENCE_SUPPORTED_FEATURES
    }

    fn compile_plan(
        &self,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Result<PlatformSandboxPlan, BackendError> {
        if policy.allows_local_execution() {
            Ok(PlatformSandboxPlan::local_execution(
                self,
                execution_id,
                cwd,
                policy,
            ))
        } else {
            let mut plan = self.fail_closed_plan(execution_id, cwd, policy);
            if self.missing_features(policy).is_empty() {
                plan.enforcement = "windows-sandbox";
                Ok(plan)
            } else {
                Err(BackendError::unsupported_with_plan(
                    self,
                    policy,
                    Some(plan),
                ))
            }
        }
    }

    fn execute_plan(
        &self,
        plan: &PlatformSandboxPlan,
        command: &[String],
        cwd: &Path,
        stdin: ExecutionStdin,
        env: &ExecutionEnv,
        timeout: Option<Duration>,
    ) -> io::Result<BackendExecutionOutput> {
        if plan.is_sandbox_enforced() {
            return execute_windows_sandbox_plan(plan, command, cwd, stdin, env, timeout);
        }
        spawn_local_command(plan, command, cwd, stdin, env, timeout)
    }

    fn capabilities_json(&self) -> Value {
        capabilities_json_for(
            self,
            &[
                "Windows reference backend enforces sandboxed policies with OS-native process, filesystem, and network boundaries",
                "RunSeal policy, plan, audit, and conformance surfaces stay platform-neutral",
                "runtime roots are created, marked, and cleaned with containment checks",
                "runtime environment redirects are injected into sandboxed child environments",
                "process cleanup terminates sandboxed process trees when the parent exits",
                "filesystem and network enforcement fail closed when setup is unavailable",
            ],
        )
    }
}

#[cfg(windows)]
pub(super) fn execute_windows_sandbox_plan(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
) -> io::Result<BackendExecutionOutput> {
    let _execution_guard = windows_sandbox_execution_gate(plan)?;
    let _runtime_root = required_plan_path(plan.runtime_root.as_deref(), "runtime_root")?;
    let stdin_bytes = match stdin {
        ExecutionStdin::Empty => None,
        ExecutionStdin::Bytes(bytes) | ExecutionStdin::File(bytes) => Some(bytes),
    };
    let vendor_sandbox_home = vendor_sandbox_home(cwd);
    let workspace_roots = windows_sandbox_workspace_roots_for_plan(cwd, plan)?;
    let write_roots_override = windows_sandbox_write_roots_for_plan(plan);
    let permission_profile = plan.vendor_permission_profile()?;
    plan.prepare_runtime_roots()?;

    let result = (|| {
        prepare_vendor_sandbox_home(cwd, &vendor_sandbox_home)?;
        let managed_proxy = if plan.network_managed_proxy == "required" {
            Some(ManagedSandboxProxy::start().map_err(|err| {
                io::Error::other(BackendUnavailableError {
                    reason: format!("windows managed proxy unavailable: {err}"),
                })
            })?)
        } else {
            None
        };
        let mut events = if managed_proxy.is_some() {
            vec![json!({
                "type": "execution.network.proxy_ready",
                "time": timestamp_now(),
                "decision": "ready",
                "network": {
                    "mode": plan.network_mode,
                    "direct_egress": plan.network_direct_egress,
                    "managed_proxy": plan.network_managed_proxy,
                },
            })]
        } else {
            Vec::new()
        };
        let env_map = sandbox_environment(plan, env, managed_proxy.as_ref());
        let workspace_contained = plan.sandbox_level == SandboxLevel::WorkspaceContained.as_str();
        let deny_read_paths =
            windows_sandbox_deny_read_paths(&workspace_roots, plan, &env_map, workspace_contained)?;
        let sandbox_command = windows_sandbox_command(command, &env_map);

        let capture =
            codex_windows_sandbox::run_windows_sandbox_capture_for_permission_profile_elevated(
                codex_windows_sandbox::ElevatedSandboxProfileCaptureRequest {
                    permission_profile: &permission_profile,
                    workspace_roots: workspace_roots.as_slice(),
                    codex_home: &vendor_sandbox_home,
                    command: sandbox_command,
                    cwd,
                    env_map,
                    stdin_bytes,
                    timeout_ms: timeout.map(duration_millis_u64),
                    cancellation: None,
                    use_private_desktop: false,
                    proxy_enforced: plan.network_managed_proxy == "required",
                    read_roots_override: None,
                    read_roots_include_platform_defaults: workspace_contained,
                    write_roots_override: Some(write_roots_override.as_slice()),
                    deny_read_paths_override: deny_read_paths.as_slice(),
                    deny_write_paths_override: &[],
                },
            )
            .map_err(|err| {
                if let Some(failure) = codex_windows_sandbox::extract_setup_failure(&err) {
                    return io::Error::other(BackendUnavailableError {
                        reason: public_windows_setup_unavailable_reason(failure.code.as_str()),
                    });
                }
                io::Error::other(err.to_string())
            })?;
        if let Some(managed_proxy) = &managed_proxy {
            events.extend(managed_proxy.drain_events());
        }
        Ok((capture, events))
    })();
    let cleanup = plan.cleanup_runtime_roots();

    let (capture, events) = match (result, cleanup) {
        (Ok(capture), Ok(_)) => capture,
        (Err(err), Ok(_)) => return Err(err),
        (Ok(_), Err(err)) => return Err(err),
        (Err(run_err), Err(cleanup_err)) => {
            return Err(io::Error::other(format!(
                "sandbox execution failed ({run_err}); runtime cleanup failed ({cleanup_err})"
            )));
        }
    };

    Ok(BackendExecutionOutput {
        output: Output {
            status: std::process::ExitStatus::from_raw(capture.exit_code as u32),
            stdout: capture.stdout,
            stderr: capture.stderr,
        },
        timed_out: capture.timed_out,
        events,
    })
}

#[cfg(windows)]
pub(super) fn windows_sandbox_write_roots_for_plan(plan: &PlatformSandboxPlan) -> Vec<PathBuf> {
    plan.filesystem_write.iter().map(PathBuf::from).collect()
}

#[cfg(windows)]
pub(super) fn windows_sandbox_workspace_roots_for_plan(
    cwd: &Path,
    plan: &PlatformSandboxPlan,
) -> io::Result<Vec<AbsolutePathBuf>> {
    let mut roots = Vec::new();
    let mut seen = HashSet::new();
    for root in [
        Some(cwd.to_path_buf()),
        plan.runtime_root.as_deref().map(PathBuf::from),
        plan.profile_root.as_deref().map(PathBuf::from),
        plan.synthetic_home.as_deref().map(PathBuf::from),
        plan.temp_root.as_deref().map(PathBuf::from),
    ]
    .into_iter()
    .flatten()
    {
        if !seen.insert(windows_sandbox_path_key(&root)) {
            continue;
        }
        roots.push(
            AbsolutePathBuf::from_absolute_path_checked(&root).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "invalid Windows sandbox workspace root {}: {err}",
                        root.display()
                    ),
                )
            })?,
        );
    }
    Ok(roots)
}

#[cfg(windows)]
pub(super) fn windows_sandbox_command(
    command: &[String],
    env_map: &HashMap<String, String>,
) -> Vec<String> {
    let Some((program, args)) = command.split_first() else {
        return Vec::new();
    };
    let mut resolved = Vec::with_capacity(command.len());
    resolved
        .push(resolve_windows_sandbox_program(program, env_map).unwrap_or_else(|| program.clone()));
    resolved.extend(args.iter().cloned());
    resolved
}

#[cfg(windows)]
fn resolve_windows_sandbox_program(
    program: &str,
    env_map: &HashMap<String, String>,
) -> Option<String> {
    let program_path = Path::new(program);
    if program_path.is_absolute() || program.contains('\\') || program.contains('/') {
        return Some(program.to_string());
    }

    let path_env = windows_environment_value(env_map, "PATH")
        .map(str::to_string)
        .or_else(|| std::env::var("PATH").ok())?;
    let pathext = windows_environment_value(env_map, "PATHEXT")
        .map(str::to_string)
        .or_else(|| std::env::var("PATHEXT").ok())
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_string());
    let candidate_names = windows_executable_candidate_names(program, &pathext);

    for dir in std::env::split_paths(&path_env) {
        for name in &candidate_names {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }

    None
}

#[cfg(windows)]
fn windows_environment_value<'a>(
    env_map: &'a HashMap<String, String>,
    key: &str,
) -> Option<&'a str> {
    env_map
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.as_str())
}

#[cfg(windows)]
fn windows_executable_candidate_names(program: &str, pathext: &str) -> Vec<String> {
    if Path::new(program).extension().is_some() {
        return vec![program.to_string()];
    }

    let mut names = Vec::new();
    for ext in pathext.split(';') {
        let ext = ext.trim();
        if ext.is_empty() {
            continue;
        }
        if ext.starts_with('.') {
            names.push(format!("{program}{ext}"));
        } else {
            names.push(format!("{program}.{ext}"));
        }
    }
    names.push(program.to_string());
    names
}

#[cfg(windows)]
fn windows_sandbox_deny_read_paths(
    workspace_roots: &[AbsolutePathBuf],
    plan: &PlatformSandboxPlan,
    env_map: &HashMap<String, String>,
    workspace_contained: bool,
) -> io::Result<Vec<AbsolutePathBuf>> {
    let mut deny_paths = windows_explicit_deny_read_paths(plan);
    deny_paths.extend(windows_sensitive_profile_deny_read_paths(
        workspace_roots,
        plan,
        env_map,
    ));
    if workspace_contained {
        deny_paths.extend(windows_workspace_contained_deny_read_paths(
            workspace_roots,
            plan,
            env_map,
        )?);
    }
    Ok(deduplicate_absolute_paths(deny_paths))
}

#[cfg(windows)]
pub(super) fn windows_explicit_deny_read_paths(plan: &PlatformSandboxPlan) -> Vec<AbsolutePathBuf> {
    plan.filesystem_deny
        .iter()
        .map(PathBuf::from)
        .filter(|path| path.is_absolute() && path.exists())
        .filter_map(|path| AbsolutePathBuf::from_absolute_path_checked(path).ok())
        .collect()
}

#[cfg(windows)]
fn windows_sensitive_profile_deny_read_paths(
    workspace_roots: &[AbsolutePathBuf],
    plan: &PlatformSandboxPlan,
    env_map: &HashMap<String, String>,
) -> Vec<AbsolutePathBuf> {
    let Some(user_profile) = std::env::var_os("USERPROFILE").map(PathBuf::from) else {
        return Vec::new();
    };
    let allowed_roots = windows_allowed_roots(workspace_roots, plan, env_map);
    windows_sensitive_profile_deny_read_paths_for_profile(&user_profile, &allowed_roots)
}

#[cfg(windows)]
pub(super) fn windows_sensitive_profile_deny_read_paths_for_profile(
    user_profile: &Path,
    allowed_roots: &[PathBuf],
) -> Vec<AbsolutePathBuf> {
    [
        user_profile.join(".ssh"),
        user_profile.join(".codex"),
        user_profile.join(".config"),
        user_profile.join("AppData").join("Roaming"),
    ]
    .into_iter()
    .filter(|path| path.exists())
    .filter(|path| !is_allowed_or_inside_allowed_root(path, allowed_roots))
    .filter_map(|path| AbsolutePathBuf::from_absolute_path_checked(path).ok())
    .collect()
}

#[cfg(windows)]
fn windows_workspace_contained_deny_read_paths(
    workspace_roots: &[AbsolutePathBuf],
    plan: &PlatformSandboxPlan,
    env_map: &HashMap<String, String>,
) -> io::Result<Vec<AbsolutePathBuf>> {
    let Some(user_profile) = std::env::var_os("USERPROFILE").map(PathBuf::from) else {
        return Ok(Vec::new());
    };
    let allowed_roots = windows_allowed_roots(workspace_roots, plan, env_map);

    let mut deny_paths = Vec::new();
    let mut seen = HashSet::new();
    collect_workspace_contained_profile_denies(
        &user_profile,
        &allowed_roots,
        &mut deny_paths,
        &mut seen,
    );
    Ok(deny_paths)
}

#[cfg(windows)]
fn windows_allowed_roots(
    workspace_roots: &[AbsolutePathBuf],
    plan: &PlatformSandboxPlan,
    env_map: &HashMap<String, String>,
) -> Vec<PathBuf> {
    let mut allowed_roots = workspace_roots
        .iter()
        .map(AbsolutePathBuf::as_path)
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    for root in &plan.filesystem_write {
        let root = PathBuf::from(root);
        if root.is_absolute() {
            allowed_roots.push(root);
        }
    }
    for key in ["TEMP", "TMP"] {
        if let Some(value) = env_map.get(key) {
            let root = PathBuf::from(value);
            if root.is_absolute() {
                allowed_roots.push(root);
            }
        }
    }
    allowed_roots
}

#[cfg(windows)]
fn deduplicate_absolute_paths(paths: Vec<AbsolutePathBuf>) -> Vec<AbsolutePathBuf> {
    let mut deny_paths = Vec::new();
    let mut seen = HashSet::new();
    for path in paths {
        if seen.insert(windows_sandbox_path_key(path.as_path())) {
            deny_paths.push(path);
        }
    }
    deny_paths
}

#[cfg(windows)]
pub(super) fn collect_workspace_contained_profile_denies(
    root: &Path,
    allowed_roots: &[PathBuf],
    deny_paths: &mut Vec<AbsolutePathBuf>,
    seen: &mut HashSet<String>,
) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if is_allowed_or_inside_allowed_root(&path, allowed_roots) {
            continue;
        }
        if contains_allowed_root(&path, allowed_roots) {
            collect_workspace_contained_profile_denies(&path, allowed_roots, deny_paths, seen);
            continue;
        }
        let Ok(absolute) = AbsolutePathBuf::from_absolute_path_checked(&path) else {
            continue;
        };
        if seen.insert(windows_sandbox_path_key(absolute.as_path())) {
            deny_paths.push(absolute);
        }
    }
}

#[cfg(windows)]
fn is_allowed_or_inside_allowed_root(path: &Path, allowed_roots: &[PathBuf]) -> bool {
    let path_key = windows_sandbox_path_key(path);
    allowed_roots.iter().any(|root| {
        let root_key = windows_sandbox_path_key(root);
        path_key == root_key || path_key.starts_with(&format!("{root_key}\\"))
    })
}

#[cfg(windows)]
fn contains_allowed_root(path: &Path, allowed_roots: &[PathBuf]) -> bool {
    let path_key = windows_sandbox_path_key(path);
    allowed_roots.iter().any(|root| {
        let root_key = windows_sandbox_path_key(root);
        root_key.starts_with(&format!("{path_key}\\"))
    })
}

#[cfg(windows)]
pub(super) fn windows_sandbox_path_key(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

#[cfg(not(windows))]
fn execute_windows_sandbox_plan(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
) -> io::Result<BackendExecutionOutput> {
    spawn_local_command(plan, command, cwd, stdin, env, timeout)
}

#[cfg(windows)]
fn required_plan_path(value: Option<&str>, name: &'static str) -> io::Result<PathBuf> {
    value.map(PathBuf::from).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("sandboxed plan is missing {name}"),
        )
    })
}

#[cfg(windows)]
pub(crate) fn windows_sandbox_home(cwd: &Path) -> PathBuf {
    cwd.join(".runseal").join("sandbox")
}

fn vendor_sandbox_home(cwd: &Path) -> PathBuf {
    cwd.join(".runseal").join("sandbox")
}

#[cfg(windows)]
fn prepare_vendor_sandbox_home(cwd: &Path, home: &Path) -> io::Result<()> {
    let expected = normalize_lexical(&vendor_sandbox_home(cwd));
    if normalize_lexical(home) != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to prepare sandbox home outside planned workspace directory: {}",
                home.display()
            ),
        ));
    }
    validate_runtime_root_ancestors(&expected, cwd, "prepare")?;
    fs::create_dir_all(home)?;
    validate_runtime_tree_has_no_symlinks(home, "prepare")
}

#[cfg(windows)]
fn sandbox_environment(
    plan: &PlatformSandboxPlan,
    env: &ExecutionEnv,
    managed_proxy: Option<&ManagedSandboxProxy>,
) -> HashMap<String, String> {
    let mut result = HashMap::new();
    for (key, value) in minimal_environment(plan) {
        result.insert(
            key.to_string_lossy().into_owned(),
            value.to_string_lossy().into_owned(),
        );
    }
    result.extend(env.entries.iter().cloned());
    if let Some(proxy) = managed_proxy {
        for (key, value) in proxy.environment() {
            result.insert(key, value);
        }
    }
    result
}

#[cfg(windows)]
fn duration_millis_u64(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}
