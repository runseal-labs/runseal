use crate::policy::{SandboxLevel, SandboxPolicy};
use serde_json::{Value, json};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityStatus {
    Supported,
    Unsupported,
}

impl CapabilityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Unsupported => "unsupported",
        }
    }

    pub fn is_supported(self) -> bool {
        self == Self::Supported
    }
}

/// Platform execution boundary for RunSeal sandbox policies.
///
/// Implementations compile a normalized policy into a platform plan, report the
/// capabilities they can actually enforce, and execute only plans they support.
pub trait SandboxBackend {
    fn name(&self) -> &'static str;
    fn status(&self) -> &'static str;
    fn platform(&self) -> &'static str;
    fn supports_policy(&self, policy: &SandboxPolicy) -> CapabilityStatus;
    fn compile_plan(
        &self,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Result<PlatformSandboxPlan, BackendError>;
    fn execute_plan(
        &self,
        plan: &PlatformSandboxPlan,
        command: &[String],
        cwd: &Path,
    ) -> io::Result<Output>;
    fn capabilities_json(&self) -> Value;
}

#[derive(Clone, Copy, Debug)]
pub enum ActiveBackend {
    Local(LocalBackend),
    WindowsReference(WindowsReferenceBackend),
}

impl SandboxBackend for ActiveBackend {
    fn name(&self) -> &'static str {
        match self {
            Self::Local(backend) => backend.name(),
            Self::WindowsReference(backend) => backend.name(),
        }
    }

    fn status(&self) -> &'static str {
        match self {
            Self::Local(backend) => backend.status(),
            Self::WindowsReference(backend) => backend.status(),
        }
    }

    fn platform(&self) -> &'static str {
        match self {
            Self::Local(backend) => backend.platform(),
            Self::WindowsReference(backend) => backend.platform(),
        }
    }

    fn supports_policy(&self, policy: &SandboxPolicy) -> CapabilityStatus {
        match self {
            Self::Local(backend) => backend.supports_policy(policy),
            Self::WindowsReference(backend) => backend.supports_policy(policy),
        }
    }

    fn compile_plan(
        &self,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Result<PlatformSandboxPlan, BackendError> {
        match self {
            Self::Local(backend) => backend.compile_plan(execution_id, cwd, policy),
            Self::WindowsReference(backend) => backend.compile_plan(execution_id, cwd, policy),
        }
    }

    fn execute_plan(
        &self,
        plan: &PlatformSandboxPlan,
        command: &[String],
        cwd: &Path,
    ) -> io::Result<Output> {
        match self {
            Self::Local(backend) => backend.execute_plan(plan, command, cwd),
            Self::WindowsReference(backend) => backend.execute_plan(plan, command, cwd),
        }
    }

    fn capabilities_json(&self) -> Value {
        match self {
            Self::Local(backend) => backend.capabilities_json(),
            Self::WindowsReference(backend) => backend.capabilities_json(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformSandboxPlan {
    pub backend: &'static str,
    pub backend_status: &'static str,
    pub platform: &'static str,
    pub execution_id: String,
    pub policy_id: String,
    pub policy_hash: String,
    pub sandbox_level: &'static str,
    pub enforcement: &'static str,
    pub cwd: String,
    pub runtime_root: Option<String>,
    pub profile_root: Option<String>,
    pub synthetic_home: Option<String>,
    pub temp_root: Option<String>,
    pub filesystem_read: Vec<String>,
    pub filesystem_write: Vec<String>,
    pub filesystem_deny: Vec<String>,
    pub network_mode: &'static str,
}

impl PlatformSandboxPlan {
    fn local_execution(
        backend: &dyn SandboxBackend,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Self {
        Self {
            backend: backend.name(),
            backend_status: backend.status(),
            platform: backend.platform(),
            execution_id: execution_id.to_string(),
            policy_id: policy.id.clone(),
            policy_hash: policy.hash(),
            sandbox_level: policy.sandbox_level.as_str(),
            enforcement: "local-execution",
            cwd: path_string(cwd),
            runtime_root: None,
            profile_root: None,
            synthetic_home: None,
            temp_root: None,
            filesystem_read: policy.filesystem.read.clone(),
            filesystem_write: policy.filesystem.write.clone(),
            filesystem_deny: policy.filesystem.deny.clone(),
            network_mode: policy.network.mode.as_str(),
        }
    }

    pub fn json(&self) -> Value {
        json!({
            "backend": {
                "name": self.backend,
                "status": self.backend_status,
                "platform": self.platform,
            },
            "execution_id": self.execution_id,
            "policy_id": self.policy_id,
            "policy_hash": self.policy_hash,
            "sandbox_level": self.sandbox_level,
            "enforcement": self.enforcement,
            "cwd": self.cwd.clone(),
            "runtime_root": self.runtime_root.clone(),
            "profile_root": self.profile_root.clone(),
            "synthetic_home": self.synthetic_home.clone(),
            "temp_root": self.temp_root.clone(),
            "filesystem": {
                "read": self.filesystem_read.clone(),
                "write": self.filesystem_write.clone(),
                "deny": self.filesystem_deny.clone(),
            },
            "network": {
                "mode": self.network_mode,
            }
        })
    }

    pub fn prepare_runtime_roots(&self) -> io::Result<Vec<String>> {
        let mut prepared = Vec::new();
        for root in [
            self.runtime_root.as_ref(),
            self.profile_root.as_ref(),
            self.synthetic_home.as_ref(),
            self.temp_root.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            fs::create_dir_all(root)?;
            prepared.push(root.clone());
        }
        Ok(prepared)
    }

    pub fn cleanup_runtime_roots(&self) -> io::Result<Vec<String>> {
        let Some(runtime_root) = &self.runtime_root else {
            return Ok(Vec::new());
        };
        if Path::new(runtime_root).exists() {
            fs::remove_dir_all(runtime_root)?;
            Ok(vec![runtime_root.clone()])
        } else {
            Ok(Vec::new())
        }
    }

    pub fn is_sandbox_enforced(&self) -> bool {
        self.enforcement != "local-execution"
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendError {
    pub code: &'static str,
    pub reason: String,
    pub backend: &'static str,
    pub backend_status: &'static str,
    pub platform: &'static str,
    pub support: &'static str,
    pub plan: Option<Box<PlatformSandboxPlan>>,
}

impl BackendError {
    fn unsupported(backend: &dyn SandboxBackend, policy: &SandboxPolicy) -> Self {
        Self::unsupported_with_plan(backend, policy, None)
    }

    fn unsupported_with_plan(
        backend: &dyn SandboxBackend,
        policy: &SandboxPolicy,
        plan: Option<PlatformSandboxPlan>,
    ) -> Self {
        Self {
            code: "BACKEND_CAPABILITY_MISSING",
            reason: format!(
                "backend {} cannot enforce policy {} in this build",
                backend.name(),
                policy.id
            ),
            backend: backend.name(),
            backend_status: backend.status(),
            platform: backend.platform(),
            support: CapabilityStatus::Unsupported.as_str(),
            plan: plan.map(Box::new),
        }
    }

    pub fn details_json(&self) -> Value {
        let mut details = json!({
            "backend": {
                "name": self.backend,
                "status": self.backend_status,
                "platform": self.platform,
            },
            "support": self.support,
        });

        if let (Some(details), Some(plan)) = (details.as_object_mut(), self.plan.as_deref()) {
            details.insert("platform_plan".to_string(), plan.json());
        }

        details
    }
}

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

    fn supports_policy(&self, policy: &SandboxPolicy) -> CapabilityStatus {
        if policy.sandbox_level == SandboxLevel::DangerFullAccess {
            CapabilityStatus::Supported
        } else {
            CapabilityStatus::Unsupported
        }
    }

    fn compile_plan(
        &self,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Result<PlatformSandboxPlan, BackendError> {
        if self.supports_policy(policy).is_supported() {
            Ok(PlatformSandboxPlan::local_execution(
                self,
                execution_id,
                cwd,
                policy,
            ))
        } else {
            Err(BackendError::unsupported(self, policy))
        }
    }

    fn execute_plan(
        &self,
        _plan: &PlatformSandboxPlan,
        command: &[String],
        cwd: &Path,
    ) -> io::Result<Output> {
        spawn_local_command(command, cwd)
    }

    fn capabilities_json(&self) -> Value {
        json!({
            "backend": self.name(),
            "backend_status": self.status(),
            "platform": self.platform(),
            "features": {
                "local_execution": true,
                "filesystem_policy": false,
                "network_disabled": false,
                "network_proxy": false,
                "resource_limits": false,
                "audit_jsonl": true,
                "otel_export": false,
            },
            "sandbox_levels": {
                "read-only": CapabilityStatus::Unsupported.as_str(),
                "workspace-contained": CapabilityStatus::Unsupported.as_str(),
                "workspace-write": CapabilityStatus::Unsupported.as_str(),
                "danger-full-access": CapabilityStatus::Supported.as_str(),
            },
            "network_modes": {
                "disabled": CapabilityStatus::Unsupported.as_str(),
                "proxy": CapabilityStatus::Unsupported.as_str(),
            },
            "notes": [
                "danger-full-access is explicit local execution with no sandbox guarantee",
                "sandboxed policies require a platform backend and fail closed in this build"
            ]
        })
    }
}

impl WindowsReferenceBackend {
    fn fail_closed_plan(
        self,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> PlatformSandboxPlan {
        let runtime_root = cwd.join(".runseal").join("runtime").join(execution_id);
        let profile_root = runtime_root.join("profile");
        let synthetic_home = runtime_root.join("home");
        let temp_root = runtime_root.join("temp");

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
            filesystem_read: policy.filesystem.read.clone(),
            filesystem_write: policy.filesystem.write.clone(),
            filesystem_deny: policy.filesystem.deny.clone(),
            network_mode: policy.network.mode.as_str(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsReferenceBackend;

impl SandboxBackend for WindowsReferenceBackend {
    fn name(&self) -> &'static str {
        "runseal-windows-reference"
    }

    fn status(&self) -> &'static str {
        "scaffold"
    }

    fn platform(&self) -> &'static str {
        "windows"
    }

    fn supports_policy(&self, policy: &SandboxPolicy) -> CapabilityStatus {
        if policy.sandbox_level == SandboxLevel::DangerFullAccess {
            CapabilityStatus::Supported
        } else {
            CapabilityStatus::Unsupported
        }
    }

    fn compile_plan(
        &self,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Result<PlatformSandboxPlan, BackendError> {
        if self.supports_policy(policy).is_supported() {
            Ok(PlatformSandboxPlan::local_execution(
                self,
                execution_id,
                cwd,
                policy,
            ))
        } else {
            let plan = self.fail_closed_plan(execution_id, cwd, policy);
            Err(BackendError::unsupported_with_plan(
                self,
                policy,
                Some(plan),
            ))
        }
    }

    fn execute_plan(
        &self,
        _plan: &PlatformSandboxPlan,
        command: &[String],
        cwd: &Path,
    ) -> io::Result<Output> {
        spawn_local_command(command, cwd)
    }

    fn capabilities_json(&self) -> Value {
        json!({
            "backend": self.name(),
            "backend_status": self.status(),
            "platform": self.platform(),
            "features": {
                "local_execution": true,
                "filesystem_policy": false,
                "network_disabled": false,
                "network_proxy": false,
                "resource_limits": false,
                "audit_jsonl": true,
                "otel_export": false,
            },
            "sandbox_levels": {
                "read-only": CapabilityStatus::Unsupported.as_str(),
                "workspace-contained": CapabilityStatus::Unsupported.as_str(),
                "workspace-write": CapabilityStatus::Unsupported.as_str(),
                "danger-full-access": CapabilityStatus::Supported.as_str(),
            },
            "network_modes": {
                "disabled": CapabilityStatus::Unsupported.as_str(),
                "proxy": CapabilityStatus::Unsupported.as_str(),
            },
            "notes": [
                "Windows reference backend scaffold is present",
                "filesystem and network enforcement are not implemented yet",
                "sandboxed policies fail closed until conformance tests prove enforcement"
            ]
        })
    }
}

pub fn active_backend() -> ActiveBackend {
    if cfg!(windows) {
        ActiveBackend::WindowsReference(WindowsReferenceBackend)
    } else {
        ActiveBackend::Local(LocalBackend)
    }
}

fn host_platform() -> &'static str {
    match std::env::consts::OS {
        "windows" => "windows",
        "macos" => "macos",
        "linux" => "linux",
        _ => "unknown",
    }
}

fn path_string(path: &Path) -> String {
    PathBuf::from(path).to_string_lossy().to_string()
}

fn spawn_local_command(command: &[String], cwd: &Path) -> io::Result<Output> {
    Command::new(&command[0])
        .args(&command[1..])
        .current_dir(cwd)
        .output()
}
