use super::capability::missing_backend_features;
use super::error::BackendError;
use super::execution::BackendExecutionOutput;
use super::plan::PlatformSandboxPlan;
use super::skeleton::{LinuxCommunityBackend, LocalBackend, MacosExperimentalBackend};
use super::windows::WindowsReferenceBackend;
use crate::execution::{ExecutionCancellation, ExecutionEnv, ExecutionStdin};
use crate::policy::{BackendFeature, SandboxPolicy};
use serde_json::Value;
use std::io;
use std::path::Path;
use std::time::Duration;

pub trait SandboxBackend {
    fn name(&self) -> &'static str;
    fn status(&self) -> &'static str;
    fn platform(&self) -> &'static str;
    fn supported_features(&self) -> &'static [BackendFeature];
    fn missing_features(&self, policy: &SandboxPolicy) -> Vec<BackendFeature> {
        missing_backend_features(policy, self.supported_features())
    }
    fn missing_feature_names(&self, policy: &SandboxPolicy) -> Vec<&'static str> {
        self.missing_features(policy)
            .into_iter()
            .map(BackendFeature::as_str)
            .collect()
    }
    fn compile_plan(
        &self,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Result<PlatformSandboxPlan, BackendError>;
    #[expect(
        clippy::too_many_arguments,
        reason = "RunSeal keeps cancellation as one control bit until more fields arrive"
    )]
    fn execute_plan(
        &self,
        plan: &PlatformSandboxPlan,
        command: &[String],
        cwd: &Path,
        stdin: ExecutionStdin,
        env: &ExecutionEnv,
        timeout: Option<Duration>,
        cancellation: Option<ExecutionCancellation>,
    ) -> io::Result<BackendExecutionOutput>;
    fn capabilities_json(&self) -> Value;
}

#[derive(Clone, Copy, Debug)]
pub enum ActiveBackend {
    Local(LocalBackend),
    WindowsReference(WindowsReferenceBackend),
    MacosExperimental(MacosExperimentalBackend),
    LinuxCommunity(LinuxCommunityBackend),
}

impl ActiveBackend {
    fn as_backend(&self) -> &dyn SandboxBackend {
        match self {
            Self::Local(backend) => backend,
            Self::WindowsReference(backend) => backend,
            Self::MacosExperimental(backend) => backend,
            Self::LinuxCommunity(backend) => backend,
        }
    }
}

impl SandboxBackend for ActiveBackend {
    fn name(&self) -> &'static str {
        self.as_backend().name()
    }

    fn status(&self) -> &'static str {
        self.as_backend().status()
    }

    fn platform(&self) -> &'static str {
        self.as_backend().platform()
    }

    fn supported_features(&self) -> &'static [BackendFeature] {
        self.as_backend().supported_features()
    }

    fn compile_plan(
        &self,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Result<PlatformSandboxPlan, BackendError> {
        self.as_backend().compile_plan(execution_id, cwd, policy)
    }

    fn execute_plan(
        &self,
        plan: &PlatformSandboxPlan,
        command: &[String],
        cwd: &Path,
        stdin: ExecutionStdin,
        env: &ExecutionEnv,
        timeout: Option<Duration>,
        cancellation: Option<ExecutionCancellation>,
    ) -> io::Result<BackendExecutionOutput> {
        self.as_backend()
            .execute_plan(plan, command, cwd, stdin, env, timeout, cancellation)
    }

    fn capabilities_json(&self) -> Value {
        self.as_backend().capabilities_json()
    }
}
