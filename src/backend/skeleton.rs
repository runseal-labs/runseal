use super::*;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default)]
pub struct LocalBackend;

impl SandboxBackend for LocalBackend {
    fn name(&self) -> &'static str {
        "runseal-local"
    }

    fn status(&self) -> &'static str {
        "local-baseline"
    }

    fn platform(&self) -> &'static str {
        host_platform()
    }

    fn supported_features(&self) -> &'static [BackendFeature] {
        &[]
    }

    fn compile_plan(
        &self,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Result<PlatformSandboxPlan, BackendError> {
        compile_local_execution_or_unsupported(self, execution_id, cwd, policy)
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
        spawn_local_command(plan, command, cwd, stdin, env, timeout)
    }

    fn capabilities_json(&self) -> Value {
        capabilities_json_for(
            self,
            &[
                "danger-full-access is explicit local execution with no sandbox guarantee",
                "sandboxed policies require a platform backend and fail closed in this build",
            ],
        )
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct MacosExperimentalBackend;

impl SandboxBackend for MacosExperimentalBackend {
    fn name(&self) -> &'static str {
        "runseal-macos-experimental"
    }

    fn status(&self) -> &'static str {
        "experimental"
    }

    fn platform(&self) -> &'static str {
        "macos"
    }

    fn supported_features(&self) -> &'static [BackendFeature] {
        &[]
    }

    fn compile_plan(
        &self,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Result<PlatformSandboxPlan, BackendError> {
        compile_macos_plan(self, execution_id, cwd, policy)
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
        execute_macos_plan(plan, command, cwd, stdin, env, timeout)
    }

    fn capabilities_json(&self) -> Value {
        let mut payload = capabilities_json_for(
            self,
            &[
                "macOS backend is an experimental contribution track",
                "unsupported sandboxed policies fail closed until conformance tests prove enforcement",
            ],
        );
        payload["sandbox_levels"]["read-only"] = json!(CapabilityStatus::Supported.as_str());
        payload["sandbox_levels"]["workspace-write"] = json!(CapabilityStatus::Supported.as_str());
        payload["sandbox_levels"]["workspace-contained"] =
            json!(CapabilityStatus::Unsupported.as_str());
        payload["network_modes"]["disabled"] = json!(CapabilityStatus::Supported.as_str());
        mark_portable_disabled_features_experimental(&mut payload);
        payload["capability_probes"] = crate::macos::capability_probe::capability_probes();
        payload
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxCommunityBackend;

impl SandboxBackend for LinuxCommunityBackend {
    fn name(&self) -> &'static str {
        "runseal-linux-community"
    }

    fn status(&self) -> &'static str {
        "experimental"
    }

    fn platform(&self) -> &'static str {
        "linux"
    }

    fn supported_features(&self) -> &'static [BackendFeature] {
        &[]
    }

    fn compile_plan(
        &self,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Result<PlatformSandboxPlan, BackendError> {
        compile_linux_plan(self, execution_id, cwd, policy)
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
        execute_linux_plan(plan, command, cwd, stdin, env, timeout)
    }

    fn capabilities_json(&self) -> Value {
        let mut payload = capabilities_json_for(
            self,
            &[
                "Linux backend is an experimental contribution track for portable sandboxing",
                "unsupported sandboxed policies fail closed until conformance tests prove enforcement",
            ],
        );
        payload["backend_status"] = json!(self.status());
        payload["sandbox_levels"]["read-only"] = json!(CapabilityStatus::Supported.as_str());
        payload["sandbox_levels"]["workspace-write"] = json!(CapabilityStatus::Supported.as_str());
        payload["sandbox_levels"]["workspace-contained"] =
            json!(CapabilityStatus::Unsupported.as_str());
        payload["network_modes"]["disabled"] = json!(CapabilityStatus::Supported.as_str());
        mark_portable_disabled_features_experimental(&mut payload);
        payload["capability_probes"] = crate::linux::capability_probe::capability_probes();
        payload
    }
}

fn mark_portable_disabled_features_experimental(payload: &mut Value) {
    for feature in [
        "filesystem_policy",
        "runtime_roots",
        "runtime_environment",
        "process_isolation",
        "process_cleanup",
        "direct_network_deny",
        "network_disabled",
        "policy_epoch",
    ] {
        payload["features"][feature] = json!(true);
        payload["feature_statuses"][feature] = json!(CapabilityStatus::Experimental.as_str());
    }
}
fn compile_local_execution_or_unsupported(
    backend: &dyn SandboxBackend,
    execution_id: &str,
    cwd: &Path,
    policy: &SandboxPolicy,
) -> Result<PlatformSandboxPlan, BackendError> {
    if policy.allows_local_execution() {
        Ok(PlatformSandboxPlan::local_execution(
            backend,
            execution_id,
            cwd,
            policy,
        ))
    } else {
        Err(BackendError::unsupported(backend, policy))
    }
}

fn compile_macos_plan(
    backend: &dyn SandboxBackend,
    execution_id: &str,
    cwd: &Path,
    policy: &SandboxPolicy,
) -> Result<PlatformSandboxPlan, BackendError> {
    if policy.allows_local_execution() {
        return Ok(PlatformSandboxPlan::local_execution(
            backend,
            execution_id,
            cwd,
            policy,
        ));
    }
    if policy.sandbox_level == SandboxLevel::ReadOnly && portable_network_mode(policy) {
        return Ok(PlatformSandboxPlan::macos_read_only_experimental(
            backend,
            execution_id,
            cwd,
            policy,
        ));
    }
    if policy.sandbox_level == SandboxLevel::WorkspaceWrite && portable_network_mode(policy) {
        return Ok(PlatformSandboxPlan::macos_workspace_write_experimental(
            backend,
            execution_id,
            cwd,
            policy,
        ));
    }
    Err(BackendError::unsupported_with_plan(
        backend,
        policy,
        Some(PlatformSandboxPlan::portable_fail_closed_preview(
            backend,
            execution_id,
            cwd,
            policy,
        )),
    ))
}

fn compile_linux_plan(
    backend: &dyn SandboxBackend,
    execution_id: &str,
    cwd: &Path,
    policy: &SandboxPolicy,
) -> Result<PlatformSandboxPlan, BackendError> {
    if policy.allows_local_execution() {
        return Ok(PlatformSandboxPlan::local_execution(
            backend,
            execution_id,
            cwd,
            policy,
        ));
    }
    if policy.sandbox_level == SandboxLevel::ReadOnly && portable_network_mode(policy) {
        return Ok(PlatformSandboxPlan::linux_read_only_experimental(
            backend,
            execution_id,
            cwd,
            policy,
        ));
    }
    if policy.sandbox_level == SandboxLevel::WorkspaceWrite && portable_network_mode(policy) {
        return Ok(PlatformSandboxPlan::linux_workspace_write_experimental(
            backend,
            execution_id,
            cwd,
            policy,
        ));
    }
    Err(BackendError::unsupported_with_plan(
        backend,
        policy,
        Some(PlatformSandboxPlan::portable_fail_closed_preview(
            backend,
            execution_id,
            cwd,
            policy,
        )),
    ))
}

fn portable_network_mode(policy: &SandboxPolicy) -> bool {
    matches!(
        policy.network.mode,
        NetworkMode::Unmanaged | NetworkMode::Disabled
    )
}

fn execute_linux_plan(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
) -> io::Result<BackendExecutionOutput> {
    if !plan.is_sandbox_enforced() {
        return spawn_local_command(plan, command, cwd, stdin, env, timeout);
    }
    if plan.enforcement != "linux-experimental" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported Linux sandbox enforcement",
        ));
    }
    plan.prepare_runtime_roots()?;
    let output = spawn_linux_bwrap(plan, command, cwd, stdin, env, timeout);
    let cleanup = plan.cleanup_runtime_roots();
    match (output, cleanup) {
        (Ok(output), Ok(_)) => Ok(output),
        (Err(err), Ok(_)) => Err(err),
        (Ok(_), Err(err)) => Err(err),
        (Err(output_err), Err(cleanup_err)) => Err(io::Error::other(format!(
            "Linux sandbox execution failed ({output_err}); runtime cleanup failed ({cleanup_err})"
        ))),
    }
}

fn execute_macos_plan(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
) -> io::Result<BackendExecutionOutput> {
    if !plan.is_sandbox_enforced() {
        return spawn_local_command(plan, command, cwd, stdin, env, timeout);
    }
    if plan.enforcement != "macos-experimental" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported macOS sandbox enforcement",
        ));
    }
    plan.prepare_runtime_roots()?;
    let output = spawn_macos_sandbox_exec(plan, command, cwd, stdin, env, timeout);
    let cleanup = plan.cleanup_runtime_roots();
    match (output, cleanup) {
        (Ok(output), Ok(_)) => Ok(output),
        (Err(err), Ok(_)) => Err(err),
        (Ok(_), Err(err)) => Err(err),
        (Err(output_err), Err(cleanup_err)) => Err(io::Error::other(format!(
            "macOS sandbox execution failed ({output_err}); runtime cleanup failed ({cleanup_err})"
        ))),
    }
}

fn spawn_macos_sandbox_exec(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
) -> io::Result<BackendExecutionOutput> {
    let profile = macos_profile(plan, cwd)?;
    let mut sandbox_command = vec![
        "/usr/bin/sandbox-exec".to_string(),
        "-p".to_string(),
        profile,
    ];
    sandbox_command.extend(command.iter().cloned());

    let mut runner_plan = plan.clone();
    runner_plan.enforcement = "local-execution";
    runner_plan.process_boundary = "local-process";
    runner_plan.process_cleanup = "direct-child";
    spawn_local_command(&runner_plan, &sandbox_command, cwd, stdin, env, timeout)
}

fn macos_profile(plan: &PlatformSandboxPlan, cwd: &Path) -> io::Result<String> {
    let mut writable_roots = Vec::new();
    if plan.sandbox_level == SandboxLevel::WorkspaceWrite.as_str() {
        writable_roots.push(format!(
            "(subpath \"{}\")",
            macos_profile_path_literal(cwd)?
        ));
    }
    for root in [
        plan.runtime_root.as_deref(),
        plan.profile_root.as_deref(),
        plan.synthetic_home.as_deref(),
        plan.temp_root.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        writable_roots.push(format!(
            "(subpath \"{}\")",
            macos_profile_path_literal(root)?
        ));
    }
    if writable_roots.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "macOS plan requires writable roots",
        ));
    }
    let mut profile = format!(
        "(version 1)(deny default)(allow process*)(allow sysctl-read)(allow mach-lookup)(allow file-read*)(allow file-write* {})",
        writable_roots.join(" ")
    );
    if plan.network_direct_egress == "unmanaged" {
        profile.push_str("(allow network*)");
    }
    if plan.sandbox_level == SandboxLevel::WorkspaceWrite.as_str() {
        for protected in PROTECTED_WORKSPACE_SUBPATHS {
            let protected_root = cwd.join(protected);
            if protected_root.exists() {
                profile.push_str(&format!(
                    "(deny file-write* (subpath \"{}\"))",
                    macos_profile_path_literal(&protected_root)?
                ));
            }
        }
    }
    Ok(profile)
}

fn macos_profile_path_literal(path: impl AsRef<Path>) -> io::Result<String> {
    let path = std::fs::canonicalize(path)?;
    Ok(macos_profile_literal(&path_string(&path)))
}

fn macos_profile_literal(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn spawn_linux_bwrap(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
) -> io::Result<BackendExecutionOutput> {
    let mut bwrap_command = vec!["bwrap".to_string()];
    bwrap_command.extend(["--ro-bind".to_string(), "/".to_string(), "/".to_string()]);
    if plan.sandbox_level == SandboxLevel::WorkspaceWrite.as_str() {
        bwrap_command.extend(["--bind".to_string(), path_string(cwd), path_string(cwd)]);
    }
    for root in [
        plan.runtime_root.as_deref(),
        plan.profile_root.as_deref(),
        plan.synthetic_home.as_deref(),
        plan.temp_root.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        bwrap_command.extend(["--bind".to_string(), root.to_string(), root.to_string()]);
    }
    if plan.sandbox_level == SandboxLevel::WorkspaceWrite.as_str() {
        for protected in PROTECTED_WORKSPACE_SUBPATHS {
            let protected_root = cwd.join(protected);
            if protected_root.exists() {
                bwrap_command.extend([
                    "--ro-bind".to_string(),
                    path_string(&protected_root),
                    path_string(&protected_root),
                ]);
            }
        }
    }
    bwrap_command.extend([
        "--proc".to_string(),
        "/proc".to_string(),
        "--dev".to_string(),
        "/dev".to_string(),
        "--tmpfs".to_string(),
        "/run".to_string(),
        "--unshare-user".to_string(),
        "--unshare-pid".to_string(),
        "--unshare-ipc".to_string(),
        "--unshare-uts".to_string(),
        "--die-with-parent".to_string(),
        "--clearenv".to_string(),
        "--setenv".to_string(),
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    ]);
    if plan.network_direct_egress != "unmanaged" {
        bwrap_command.push("--unshare-net".to_string());
    }
    for (key, value) in &plan.environment_runtime {
        bwrap_command.extend(["--setenv".to_string(), key.clone(), value.clone()]);
    }
    for (key, value) in &env.entries {
        bwrap_command.extend(["--setenv".to_string(), key.clone(), value.clone()]);
    }
    bwrap_command.extend(["--chdir".to_string(), path_string(cwd), "--".to_string()]);
    bwrap_command.extend(command.iter().cloned());

    let mut runner_plan = plan.clone();
    runner_plan.enforcement = "local-execution";
    runner_plan.process_boundary = "local-process";
    runner_plan.process_cleanup = "direct-child";
    spawn_local_command(&runner_plan, &bwrap_command, cwd, stdin, env, timeout)
}
