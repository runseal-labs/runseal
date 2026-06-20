use super::*;
use std::time::Duration;

const CONTROL_FEATURES: &[BackendFeature] = &[
    BackendFeature::SetupReadiness,
    BackendFeature::StdinBytes,
    BackendFeature::StdinFile,
    BackendFeature::AuditJsonl,
];

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
        CONTROL_FEATURES
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
        CONTROL_FEATURES
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
        let mut payload = capabilities_json_for(
            self,
            &[
                "macOS backend is an experimental contribution track",
                "sandboxed policies fail closed until conformance tests prove enforcement",
            ],
        );
        payload["capability_probes"] = crate::macos::capability_probe::payload();
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
        "future-community"
    }

    fn platform(&self) -> &'static str {
        "linux"
    }

    fn supported_features(&self) -> &'static [BackendFeature] {
        CONTROL_FEATURES
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
        let mut payload = capabilities_json_for(
            self,
            &[
                "Linux backend is a future community contribution track",
                "sandboxed policies fail closed until conformance tests prove enforcement",
            ],
        );
        payload["capability_probes"] = crate::linux::capability_probe::payload();
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
