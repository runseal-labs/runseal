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
        compile_portable_preview_or_local(self, execution_id, cwd, policy)
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
        let mut payload = capabilities_json_for(
            self,
            &[
                "macOS backend is an experimental contribution track",
                "sandboxed policies fail closed until conformance tests prove enforcement",
            ],
        );
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
                "Linux backend is an experimental contribution track for read-only sandboxing",
                "unsupported sandboxed policies fail closed until conformance tests prove enforcement",
            ],
        );
        payload["backend_status"] = json!(self.status());
        payload["sandbox_levels"]["read-only"] = json!(CapabilityStatus::Experimental.as_str());
        payload["network_modes"]["disabled"] = json!(CapabilityStatus::Experimental.as_str());
        payload["capability_probes"] = crate::linux::capability_probe::capability_probes();
        payload
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

fn compile_portable_preview_or_local(
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
    if policy.sandbox_level == SandboxLevel::ReadOnly
        && policy.network.mode == NetworkMode::Disabled
    {
        return Ok(PlatformSandboxPlan::linux_read_only_experimental(
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
    if plan.enforcement != "linux-read-only-experimental" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported Linux sandbox enforcement",
        ));
    }
    plan.prepare_runtime_roots()?;
    let output = spawn_linux_bwrap_read_only(plan, command, cwd, stdin, env, timeout);
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

fn spawn_linux_bwrap_read_only(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
) -> io::Result<BackendExecutionOutput> {
    let mut bwrap_command = vec![
        "bwrap".to_string(),
        "--ro-bind".to_string(),
        "/".to_string(),
        "/".to_string(),
    ];
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
        "--unshare-net".to_string(),
        "--die-with-parent".to_string(),
        "--clearenv".to_string(),
        "--setenv".to_string(),
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    ]);
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
