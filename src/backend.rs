use crate::policy::{BackendFeature, SandboxPolicy};
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
    fn supported_features(&self) -> &'static [BackendFeature];
    fn supports_policy(&self, policy: &SandboxPolicy) -> CapabilityStatus {
        if policy.allows_local_execution() || self.missing_features(policy).is_empty() {
            CapabilityStatus::Supported
        } else {
            CapabilityStatus::Unsupported
        }
    }
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
    ) -> io::Result<Output> {
        self.as_backend().execute_plan(plan, command, cwd)
    }

    fn capabilities_json(&self) -> Value {
        self.as_backend().capabilities_json()
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
    pub required_backend_features: Vec<&'static str>,
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
            required_backend_features: policy.required_backend_feature_names(),
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
            },
            "required_backend_features": self.required_backend_features.clone(),
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
    pub missing_features: Vec<&'static str>,
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
            missing_features: backend.missing_feature_names(policy),
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
            "missing_features": self.missing_features.clone(),
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
        _plan: &PlatformSandboxPlan,
        command: &[String],
        cwd: &Path,
    ) -> io::Result<Output> {
        spawn_local_command(command, cwd)
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
            required_backend_features: policy.required_backend_feature_names(),
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

    fn supported_features(&self) -> &'static [BackendFeature] {
        &[]
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
        capabilities_json_for(
            self,
            &[
                "Windows reference backend scaffold is present",
                "filesystem and network enforcement are not implemented yet",
                "sandboxed policies fail closed until conformance tests prove enforcement",
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
        compile_local_execution_or_unsupported(self, execution_id, cwd, policy)
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
        capabilities_json_for(
            self,
            &[
                "macOS backend is an experimental contribution track",
                "sandboxed policies fail closed until conformance tests prove enforcement",
            ],
        )
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
        _plan: &PlatformSandboxPlan,
        command: &[String],
        cwd: &Path,
    ) -> io::Result<Output> {
        spawn_local_command(command, cwd)
    }

    fn capabilities_json(&self) -> Value {
        capabilities_json_for(
            self,
            &[
                "Linux backend is a future community contribution track",
                "sandboxed policies fail closed until conformance tests prove enforcement",
            ],
        )
    }
}

pub fn active_backend() -> ActiveBackend {
    if cfg!(windows) {
        ActiveBackend::WindowsReference(WindowsReferenceBackend)
    } else if cfg!(target_os = "macos") {
        ActiveBackend::MacosExperimental(MacosExperimentalBackend)
    } else if cfg!(target_os = "linux") {
        ActiveBackend::LinuxCommunity(LinuxCommunityBackend)
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

fn compile_local_execution_or_unsupported(
    backend: &dyn SandboxBackend,
    execution_id: &str,
    cwd: &Path,
    policy: &SandboxPolicy,
) -> Result<PlatformSandboxPlan, BackendError> {
    if backend.supports_policy(policy).is_supported() {
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

fn capabilities_json_for(backend: &dyn SandboxBackend, notes: &[&'static str]) -> Value {
    let supported_features = backend.supported_features();
    json!({
        "backend": backend.name(),
        "backend_status": backend.status(),
        "platform": backend.platform(),
        "features": {
            "local_execution": true,
            "filesystem_policy": supported_features.contains(&BackendFeature::FilesystemPolicy),
            "network_disabled": supported_features.contains(&BackendFeature::NetworkDisabled),
            "network_proxy": supported_features.contains(&BackendFeature::NetworkProxy),
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
        "notes": notes,
    })
}

fn missing_backend_features(
    policy: &SandboxPolicy,
    supported_features: &[BackendFeature],
) -> Vec<BackendFeature> {
    policy
        .required_backend_features()
        .into_iter()
        .filter(|feature| !supported_features.contains(feature))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{NetworkMode, normalize_policy};
    use serde_json::json;
    use std::path::PathBuf;

    #[test]
    fn missing_features_excludes_supported_backend_features() {
        let cwd = PathBuf::from("/workspace");
        let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();

        assert_eq!(
            missing_backend_features(&policy, &[BackendFeature::FilesystemPolicy]),
            vec![BackendFeature::NetworkProxy]
        );
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
        assert!(LocalBackend.supports_policy(&policy).is_supported());
    }

    #[test]
    fn linux_skeleton_reports_community_track_without_sandbox_features() {
        assert_eq!(LinuxCommunityBackend.name(), "runseal-linux-community");
        assert_eq!(LinuxCommunityBackend.status(), "future-community");
        assert!(LinuxCommunityBackend.supported_features().is_empty());
    }

    #[test]
    fn macos_skeleton_reports_experimental_track_without_sandbox_features() {
        assert_eq!(
            MacosExperimentalBackend.name(),
            "runseal-macos-experimental"
        );
        assert_eq!(MacosExperimentalBackend.status(), "experimental");
        assert!(MacosExperimentalBackend.supported_features().is_empty());
    }
}
