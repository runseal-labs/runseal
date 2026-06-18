use crate::policy::{
    BackendFeature, SandboxLevel, SandboxPolicy, matches_environment_scrub_pattern,
};
use crate::windows::policy::{
    WindowsFilesystemAclPlan, WindowsFilesystemAclTransactionPlan, WindowsFilesystemRule,
    WindowsHostRoots, WindowsPolicyPlan, WindowsRuntimeRoots,
};
use crate::windows::vendor_adapter::WindowsVendorSandboxProfile;
mod filesystem;
#[cfg(windows)]
mod managed_proxy;
mod process;
mod runtime;

use filesystem::{
    WindowsFilesystemAclDriver, WindowsFilesystemAclSubject,
    apply_private_filesystem_acl_transaction, new_windows_filesystem_acl_driver,
    validate_private_filesystem_acl_entries, validate_private_filesystem_acl_transaction,
};
#[cfg(windows)]
use managed_proxy::ManagedSandboxProxy;
#[cfg(all(test, windows))]
use process::WindowsKillOnCloseJob;
#[cfg(test)]
use process::cleanup_child_after_setup_error;
#[cfg(any(test, windows))]
use process::minimal_environment;
use process::spawn_local_command;
use runtime::{
    RUNTIME_ROOT_MARKER, normalize_lexical, prepare_unique_runtime_root,
    runtime_marker_is_regular_file, validate_runtime_root_ancestors,
    validate_runtime_root_not_symlink, validate_runtime_tree_has_no_symlinks,
};
use serde_json::Map;
use serde_json::{Value, json};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Output;
use std::time::Duration;
#[cfg(windows)]
use {
    codex_protocol::models::PermissionProfile,
    codex_utils_absolute_path::AbsolutePathBuf,
    std::collections::{HashMap, HashSet},
    std::os::windows::process::ExitStatusExt,
};

#[derive(Debug)]
struct BackendUnavailableError {
    reason: String,
}

impl std::fmt::Display for BackendUnavailableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for BackendUnavailableError {}

pub(crate) fn backend_unavailable_reason(err: &io::Error) -> Option<&str> {
    err.get_ref()?
        .downcast_ref::<BackendUnavailableError>()
        .map(|err| err.reason.as_str())
}

#[cfg(windows)]
fn public_windows_setup_unavailable_reason(code: &str) -> String {
    format!("windows sandbox setup unavailable: {code}")
}

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
        stdin: ExecutionStdin,
        env: &ExecutionEnv,
        timeout: Option<Duration>,
    ) -> io::Result<BackendExecutionOutput>;
    fn capabilities_json(&self) -> Value;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionStdin {
    Empty,
    Bytes(Vec<u8>),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExecutionEnv {
    pub entries: Vec<(String, String)>,
}

impl ExecutionEnv {
    pub fn keys(&self) -> Vec<String> {
        self.entries.iter().map(|(key, _)| key.clone()).collect()
    }
}

#[derive(Debug)]
pub struct BackendExecutionOutput {
    pub output: Output,
    pub timed_out: bool,
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
    ) -> io::Result<BackendExecutionOutput> {
        self.as_backend()
            .execute_plan(plan, command, cwd, stdin, env, timeout)
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
    pub filesystem_protected: Vec<&'static str>,
    private_filesystem_deny: Vec<String>,
    private_filesystem_rules: Vec<WindowsFilesystemRule>,
    pub process_boundary: &'static str,
    pub process_identity: &'static str,
    pub process_cleanup: &'static str,
    private_process_sandbox_user_model: &'static str,
    private_process_token: &'static str,
    private_process_job: &'static str,
    private_setup_account_name: &'static str,
    private_setup_group_name: &'static str,
    private_setup_identity_artifacts: &'static str,
    private_setup_payload: Option<String>,
    private_vendor_permission_profile: Option<String>,
    pub network_mode: &'static str,
    pub network_direct_egress: &'static str,
    pub network_managed_proxy: &'static str,
    pub environment_inherit: String,
    pub environment_scrub: Vec<String>,
    pub environment_proxy: bool,
    pub environment_runtime: Vec<(String, String)>,
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
            filesystem_read: policy
                .filesystem
                .read
                .iter()
                .chain(policy.filesystem.read_only.iter())
                .cloned()
                .collect(),
            filesystem_write: policy.filesystem.write.clone(),
            filesystem_deny: policy.filesystem.deny.clone(),
            filesystem_protected: protected_filesystem_labels(policy),
            private_filesystem_deny: Vec::new(),
            private_filesystem_rules: Vec::new(),
            process_boundary: "local-process",
            process_identity: "current-user",
            process_cleanup: "direct-child",
            private_process_sandbox_user_model: "current-user",
            private_process_token: "none",
            private_process_job: "none",
            private_setup_account_name: "current-user",
            private_setup_group_name: "current-user",
            private_setup_identity_artifacts: "current-user",
            private_setup_payload: None,
            private_vendor_permission_profile: None,
            network_mode: policy.network.mode.as_str(),
            network_direct_egress: "unmanaged",
            network_managed_proxy: "none",
            environment_inherit: policy.environment.inherit.clone(),
            environment_scrub: policy.environment.scrub.clone(),
            environment_proxy: policy.environment.proxy,
            environment_runtime: Vec::new(),
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
                "protected": self.filesystem_protected.clone(),
            },
            "process": {
                "boundary": self.process_boundary,
                "identity": self.process_identity,
                "cleanup": self.process_cleanup,
            },
            "network": {
                "mode": self.network_mode,
                "direct_egress": self.network_direct_egress,
                "managed_proxy": self.network_managed_proxy,
            },
            "environment": {
                "inherit": self.environment_inherit.clone(),
                "scrub": self.environment_scrub.clone(),
                "proxy": self.environment_proxy,
                "runtime": environment_runtime_json(&self.environment_runtime),
            },
            "setup": self.setup_json(),
            "required_backend_features": self.required_backend_features.clone(),
        })
    }

    fn setup_json(&self) -> Value {
        json!({
            "requires_runtime_roots": self.runtime_root.is_some(),
            "requires_runtime_environment": !self.environment_runtime.is_empty(),
            "requires_runtime_cleanup": self.runtime_root.is_some(),
            "requires_network_guard": self.network_direct_egress == "deny",
            "requires_managed_proxy": self.network_managed_proxy == "required",
            "requires_process_boundary": self.process_boundary != "local-process",
            "fail_closed_on_setup_error": self.is_sandbox_enforced(),
        })
    }

    pub fn prepare_sandbox_setup(&self) -> io::Result<PreparedSandboxSetup> {
        self.prepare_sandbox_setup_with_driver(new_windows_filesystem_acl_driver())
    }

    fn prepare_sandbox_setup_with_driver(
        &self,
        mut filesystem_driver: Box<dyn WindowsFilesystemAclDriver>,
    ) -> io::Result<PreparedSandboxSetup> {
        self.validate_private_process_setup()?;
        self.validate_private_network_setup()?;
        let mut prepared_roots = self.prepare_runtime_roots()?;
        match self.prepare_filesystem_rules_with_driver(filesystem_driver.as_mut()) {
            Ok(filesystem_roots) => extend_unique(&mut prepared_roots, filesystem_roots),
            Err(setup_err) => {
                self.cleanup_runtime_roots()?;
                return Err(setup_err);
            }
        }
        Ok(PreparedSandboxSetup {
            prepared_roots,
            filesystem_driver,
        })
    }

    fn validate_private_process_setup(&self) -> io::Result<()> {
        if !self.is_sandbox_enforced() {
            return Ok(());
        }
        if self.process_boundary == "restricted-local-process"
            && self.process_identity == "low-privilege"
            && self.process_cleanup == "process-tree"
            && self.private_process_sandbox_user_model == "single-sandbox-user"
            && self.private_process_token == "restricted-token"
            && self.private_process_job == "kill-on-close-job"
            && self.private_setup_account_name == "RunSealSandbox"
            && self.private_setup_group_name == "RunSealSandboxUsers"
            && self.private_setup_identity_artifacts == "single-sandbox-user-artifacts"
            && has_single_user_setup_payload(self.private_setup_payload.as_deref())
        {
            return Ok(());
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sandboxed plan requires a single sandbox user restricted process boundary and setup identity artifacts",
        ))
    }

    fn validate_private_network_setup(&self) -> io::Result<()> {
        if !self.is_sandbox_enforced() {
            return Ok(());
        }
        if matches!(
            (
                self.network_mode,
                self.network_direct_egress,
                self.network_managed_proxy,
            ),
            ("disabled", "deny", "none") | ("proxy", "deny", "required")
        ) {
            return Ok(());
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sandboxed plan requires a valid network guard",
        ))
    }

    pub fn prepare_runtime_roots(&self) -> io::Result<Vec<String>> {
        self.validate_runtime_roots_for_setup()?;
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
            prepare_unique_runtime_root(&mut prepared, root)?;
        }
        for (_, root) in &self.environment_runtime {
            prepare_unique_runtime_root(&mut prepared, root)?;
        }
        if let Some(runtime_root) = &self.runtime_root {
            fs::write(
                Path::new(runtime_root).join(RUNTIME_ROOT_MARKER),
                self.execution_id.as_bytes(),
            )?;
        }
        Ok(prepared)
    }

    #[cfg(test)]
    fn prepare_filesystem_rules(&self) -> io::Result<Vec<String>> {
        let mut driver = new_windows_filesystem_acl_driver();
        self.prepare_filesystem_rules_with_driver(driver.as_mut())
    }

    fn prepare_filesystem_rules_with_driver(
        &self,
        driver: &mut dyn WindowsFilesystemAclDriver,
    ) -> io::Result<Vec<String>> {
        let acl_plan = WindowsFilesystemAclPlan::from_rules(&self.private_filesystem_rules);
        let transaction = WindowsFilesystemAclTransactionPlan::from_acl_plan(&acl_plan);
        validate_private_filesystem_acl_transaction(&transaction)?;
        validate_private_filesystem_acl_entries(&transaction)?;
        let subject = self.private_filesystem_acl_subject(&transaction)?;
        apply_private_filesystem_acl_transaction(&transaction, subject, driver)?;

        Ok(transaction.rollback_roots().to_vec())
    }

    fn private_filesystem_acl_subject(
        &self,
        transaction: &WindowsFilesystemAclTransactionPlan,
    ) -> io::Result<Option<WindowsFilesystemAclSubject>> {
        if transaction.apply_entries().next().is_none() {
            return Ok(None);
        }
        WindowsFilesystemAclSubject::from_plan(
            self.process_identity,
            self.private_process_sandbox_user_model,
            self.private_process_token,
        )
        .map(Some)
    }

    fn cleanup_sandbox_setup_with_driver(
        &self,
        driver: &mut dyn WindowsFilesystemAclDriver,
    ) -> io::Result<Vec<String>> {
        let mut cleaned = self.cleanup_filesystem_rules_with_driver(driver)?;
        extend_unique(&mut cleaned, self.cleanup_runtime_roots()?);
        Ok(cleaned)
    }

    fn cleanup_filesystem_rules_with_driver(
        &self,
        driver: &mut dyn WindowsFilesystemAclDriver,
    ) -> io::Result<Vec<String>> {
        let acl_plan = WindowsFilesystemAclPlan::from_rules(&self.private_filesystem_rules);
        let transaction = WindowsFilesystemAclTransactionPlan::from_acl_plan(&acl_plan);
        validate_private_filesystem_acl_transaction(&transaction)?;
        validate_private_filesystem_acl_entries(&transaction)?;

        let cleaned = transaction.rollback_roots().to_vec();
        if cleaned.is_empty() {
            return Ok(cleaned);
        }

        driver.rollback()?;
        Ok(cleaned)
    }

    pub fn cleanup_runtime_roots(&self) -> io::Result<Vec<String>> {
        let Some(runtime_root) = &self.runtime_root else {
            return Ok(Vec::new());
        };
        let runtime_root = Path::new(runtime_root);
        self.validate_runtime_root_for_cleanup(runtime_root)?;
        if runtime_root.exists() {
            fs::remove_dir_all(runtime_root)?;
            Ok(vec![path_string(runtime_root)])
        } else {
            Ok(Vec::new())
        }
    }

    pub fn is_sandbox_enforced(&self) -> bool {
        self.enforcement != "local-execution"
    }

    #[cfg(windows)]
    fn vendor_permission_profile(&self) -> io::Result<PermissionProfile> {
        let Some(permission_profile) = &self.private_vendor_permission_profile else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sandboxed plan is missing vendor permission profile",
            ));
        };
        serde_json::from_str(permission_profile).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid vendor permission profile: {err}"),
            )
        })
    }

    fn validate_runtime_roots_for_setup(&self) -> io::Result<()> {
        let Some(runtime_root) = &self.runtime_root else {
            return Ok(());
        };
        let expected = normalize_lexical(&self.expected_runtime_root()?);
        let workspace = normalize_lexical(Path::new(&self.cwd));
        validate_runtime_root_ancestors(&expected, &workspace, "prepare")?;
        let runtime_root = Path::new(runtime_root);
        if normalize_lexical(runtime_root) != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to prepare runtime root outside planned workspace runtime directory: {}",
                    runtime_root.display()
                ),
            ));
        }
        self.validate_runtime_root_path_for_setup(runtime_root, &expected)?;
        validate_runtime_tree_has_no_symlinks(runtime_root, "prepare")?;
        self.validate_runtime_marker_for_setup(runtime_root)?;
        for root in [
            self.profile_root.as_ref(),
            self.synthetic_home.as_ref(),
            self.temp_root.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            self.validate_runtime_root_path_for_setup(Path::new(root), &expected)?;
        }
        for (_, root) in &self.environment_runtime {
            self.validate_runtime_root_path_for_setup(Path::new(root), &expected)?;
        }
        Ok(())
    }

    fn validate_runtime_marker_for_setup(&self, runtime_root: &Path) -> io::Result<()> {
        if !runtime_root.exists() {
            return Ok(());
        }
        let marker = runtime_root.join(RUNTIME_ROOT_MARKER);
        if !runtime_marker_is_regular_file(&marker)?
            || fs::read_to_string(&marker)? != self.execution_id
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to prepare runtime root with mismatched marker: {}",
                    runtime_root.display()
                ),
            ));
        }
        Ok(())
    }

    fn validate_runtime_root_path_for_setup(&self, root: &Path, expected: &Path) -> io::Result<()> {
        let root = normalize_lexical(root);
        if !root.starts_with(expected) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to prepare runtime root outside planned workspace runtime directory: {}",
                    root.display()
                ),
            ));
        }
        for ancestor in root.ancestors() {
            if !ancestor.starts_with(expected) {
                break;
            }
            validate_runtime_root_not_symlink(ancestor, "prepare")?;
        }
        Ok(())
    }

    fn validate_runtime_root_for_cleanup(&self, runtime_root: &Path) -> io::Result<()> {
        let expected = normalize_lexical(&self.expected_runtime_root()?);
        if normalize_lexical(runtime_root) != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to clean runtime root outside planned workspace runtime directory: {}",
                    runtime_root.display()
                ),
            ));
        }
        let workspace = normalize_lexical(Path::new(&self.cwd));
        validate_runtime_root_ancestors(&expected, &workspace, "clean")?;
        if !runtime_root.exists() {
            return Ok(());
        }
        let metadata = fs::symlink_metadata(runtime_root)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to clean symlinked runtime root: {}",
                    runtime_root.display()
                ),
            ));
        }
        let marker = runtime_root.join(RUNTIME_ROOT_MARKER);
        if !runtime_marker_is_regular_file(&marker)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to clean unmarked runtime root: {}",
                    runtime_root.display()
                ),
            ));
        }
        if fs::read_to_string(&marker)? != self.execution_id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to clean runtime root with mismatched marker: {}",
                    runtime_root.display()
                ),
            ));
        }
        validate_runtime_tree_has_no_symlinks(runtime_root, "clean")?;
        Ok(())
    }

    fn expected_runtime_root(&self) -> io::Result<PathBuf> {
        let execution_id = Path::new(&self.execution_id);
        if !matches!(execution_id.components().next(), Some(Component::Normal(_)))
            || execution_id.components().count() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid execution id for runtime root: {}",
                    self.execution_id
                ),
            ));
        }
        Ok(Path::new(&self.cwd)
            .join(".runseal")
            .join("runtime")
            .join(&self.execution_id))
    }
}

pub struct PreparedSandboxSetup {
    prepared_roots: Vec<String>,
    filesystem_driver: Box<dyn WindowsFilesystemAclDriver>,
}

impl PreparedSandboxSetup {
    pub fn prepared_roots(&self) -> &[String] {
        &self.prepared_roots
    }

    pub fn cleanup(mut self, plan: &PlatformSandboxPlan) -> io::Result<Vec<String>> {
        plan.cleanup_sandbox_setup_with_driver(self.filesystem_driver.as_mut())
    }
}

fn extend_unique(target: &mut Vec<String>, source: Vec<String>) {
    for item in source {
        if !target.iter().any(|existing| existing == &item) {
            target.push(item);
        }
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

impl WindowsReferenceBackend {
    fn fail_closed_plan(
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

    fn fail_closed_plan_with_host_roots(
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

fn has_single_user_setup_payload(payload: Option<&str>) -> bool {
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

fn environment_runtime_json(entries: &[(String, String)]) -> Value {
    let mut object = Map::new();
    for (key, value) in entries {
        object.insert(key.clone(), json!(value));
    }
    Value::Object(object)
}

fn protected_filesystem_labels(policy: &SandboxPolicy) -> Vec<&'static str> {
    let mut labels = Vec::new();
    if !policy.filesystem.deny.is_empty() {
        labels.push("workspace_metadata");
    }
    if policy.sandbox_level == SandboxLevel::WorkspaceContained {
        labels.push("host_profile");
        labels.push("credential_roots");
    }
    labels
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
];

#[cfg(not(windows))]
const WINDOWS_REFERENCE_SUPPORTED_FEATURES: &[BackendFeature] = &[
    BackendFeature::RuntimeRoots,
    BackendFeature::RuntimeEnvironment,
    BackendFeature::ProcessCleanup,
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
                "Windows reference backend uses a vendored upstream sandbox crate",
                "RunSeal-specific code remains a policy, plan, audit, and conformance adapter",
                "runtime roots are created, marked, and cleaned with containment checks",
                "runtime environment redirects are injected into child process environments",
                "process cleanup is backed by Windows kill-on-close Job Objects",
                "filesystem and network enforcement are delegated to the Windows sandbox boundary",
            ],
        )
    }
}

#[cfg(windows)]
fn execute_windows_sandbox_plan(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
) -> io::Result<BackendExecutionOutput> {
    if !matches!(stdin, ExecutionStdin::Empty) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sandboxed Windows execution does not support stdin bytes yet",
        ));
    }

    let _runtime_root = required_plan_path(plan.runtime_root.as_deref(), "runtime_root")?;
    let vendor_sandbox_home = vendor_sandbox_home(cwd);
    let workspace_root = AbsolutePathBuf::from_absolute_path_checked(cwd).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid workspace root: {err}"),
        )
    })?;
    let workspace_roots = [workspace_root];
    let permission_profile = plan.vendor_permission_profile()?;
    plan.prepare_runtime_roots()?;
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
    let env_map = sandbox_environment(plan, env, managed_proxy.as_ref());
    let workspace_contained = plan.sandbox_level == SandboxLevel::WorkspaceContained.as_str();
    let deny_read_paths = if workspace_contained {
        windows_workspace_contained_deny_read_paths(&workspace_roots, plan, &env_map)?
    } else {
        Vec::new()
    };
    let sandbox_command = windows_sandbox_command(command, &env_map);

    let result =
        codex_windows_sandbox::run_windows_sandbox_capture_for_permission_profile_elevated(
            codex_windows_sandbox::ElevatedSandboxProfileCaptureRequest {
                permission_profile: &permission_profile,
                workspace_roots: workspace_roots.as_slice(),
                codex_home: &vendor_sandbox_home,
                command: sandbox_command,
                cwd,
                env_map,
                timeout_ms: timeout.map(duration_millis_u64),
                cancellation: None,
                use_private_desktop: false,
                proxy_enforced: plan.network_managed_proxy == "required",
                read_roots_override: None,
                read_roots_include_platform_defaults: workspace_contained,
                write_roots_override: None,
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
        });
    let cleanup = plan.cleanup_runtime_roots();

    let capture = match (result, cleanup) {
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
    })
}

#[cfg(windows)]
fn windows_sandbox_command(command: &[String], env_map: &HashMap<String, String>) -> Vec<String> {
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
fn windows_workspace_contained_deny_read_paths(
    workspace_roots: &[AbsolutePathBuf],
    plan: &PlatformSandboxPlan,
    env_map: &HashMap<String, String>,
) -> io::Result<Vec<AbsolutePathBuf>> {
    let Some(user_profile) = std::env::var_os("USERPROFILE").map(PathBuf::from) else {
        return Ok(Vec::new());
    };
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
fn collect_workspace_contained_profile_denies(
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
fn windows_sandbox_path_key(path: &Path) -> String {
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

#[cfg(windows)]
fn vendor_sandbox_home(cwd: &Path) -> PathBuf {
    windows_sandbox_home(cwd)
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

fn capabilities_json_for(backend: &dyn SandboxBackend, notes: &[&'static str]) -> Value {
    let supported_features = backend.supported_features();
    let read_only = capability_status(
        supported_features,
        &[
            BackendFeature::FilesystemPolicy,
            BackendFeature::RuntimeRoots,
            BackendFeature::RuntimeEnvironment,
            BackendFeature::ProcessIsolation,
            BackendFeature::ProcessCleanup,
            BackendFeature::DirectNetworkDeny,
            BackendFeature::NetworkDisabled,
        ],
    );
    let workspace_write = capability_status(
        supported_features,
        &[
            BackendFeature::FilesystemPolicy,
            BackendFeature::RuntimeRoots,
            BackendFeature::RuntimeEnvironment,
            BackendFeature::ProcessIsolation,
            BackendFeature::ProcessCleanup,
            BackendFeature::DirectNetworkDeny,
            BackendFeature::NetworkProxy,
            BackendFeature::ManagedProxy,
        ],
    );
    let network_disabled = capability_status(
        supported_features,
        &[
            BackendFeature::DirectNetworkDeny,
            BackendFeature::NetworkDisabled,
        ],
    );
    let network_proxy = capability_status(
        supported_features,
        &[
            BackendFeature::DirectNetworkDeny,
            BackendFeature::NetworkProxy,
            BackendFeature::ManagedProxy,
        ],
    );
    json!({
        "backend": backend.name(),
        "backend_status": backend.status(),
        "platform": backend.platform(),
        "features": {
            "local_execution": true,
            "filesystem_policy": supported_features.contains(&BackendFeature::FilesystemPolicy),
            "runtime_roots": supported_features.contains(&BackendFeature::RuntimeRoots),
            "runtime_environment": supported_features.contains(&BackendFeature::RuntimeEnvironment),
            "process_isolation": supported_features.contains(&BackendFeature::ProcessIsolation),
            "process_cleanup": supported_features.contains(&BackendFeature::ProcessCleanup),
            "direct_network_deny": supported_features.contains(&BackendFeature::DirectNetworkDeny),
            "network_disabled": supported_features.contains(&BackendFeature::NetworkDisabled),
            "network_proxy": supported_features.contains(&BackendFeature::NetworkProxy),
            "managed_proxy": supported_features.contains(&BackendFeature::ManagedProxy),
            "resource_limits": supported_features.contains(&BackendFeature::ResourceLimits),
            "audit_jsonl": true,
            "otel_export": false,
        },
        "sandbox_levels": {
            "read-only": read_only,
            "workspace-contained": read_only,
            "workspace-write": workspace_write,
            "danger-full-access": CapabilityStatus::Supported.as_str(),
        },
        "network_modes": {
            "disabled": network_disabled,
            "proxy": network_proxy,
        },
        "notes": notes,
    })
}

fn capability_status(
    supported_features: &[BackendFeature],
    required_features: &[BackendFeature],
) -> &'static str {
    if required_features
        .iter()
        .all(|feature| supported_features.contains(feature))
    {
        CapabilityStatus::Supported.as_str()
    } else {
        CapabilityStatus::Unsupported.as_str()
    }
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
    use crate::windows::policy::{
        WindowsFilesystemAccess, WindowsFilesystemAclEntry, WindowsFilesystemAclPlan,
        WindowsFilesystemAclTransactionPlan, WindowsFilesystemRule, WindowsFilesystemRuleSource,
    };
    use serde_json::json;
    use std::ffi::OsString;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::time::Instant;
    use tempfile::TempDir;

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
    fn windows_setup_unavailable_reason_exposes_code_only() {
        assert_eq!(
            public_windows_setup_unavailable_reason("orchestrator_helper_launch_failed"),
            "windows sandbox setup unavailable: orchestrator_helper_launch_failed"
        );
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

    fn effective_environment_value(
        environment: &[(OsString, OsString)],
        key: &str,
    ) -> Option<String> {
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
            ]
        } else {
            &[
                BackendFeature::RuntimeRoots,
                BackendFeature::RuntimeEnvironment,
                BackendFeature::ProcessCleanup,
            ]
        }
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
        let mut plan =
            WindowsReferenceBackend.fail_closed_plan("exec_rollback_roots", &cwd, &policy);
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
        let mut plan =
            WindowsReferenceBackend.fail_closed_plan("exec_cleanup_setup", &cwd, &policy);
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
        let mut plan =
            WindowsReferenceBackend.fail_closed_plan("exec_cleanup_dedupe", &cwd, &policy);
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
    fn sandbox_cleanup_preserves_runtime_tree_after_filesystem_rollback_failure() -> io::Result<()>
    {
        let tmp = TempDir::new()?;
        let cwd = tmp.path().join("workspace");
        fs::create_dir_all(&cwd)?;
        let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
        let mut plan =
            WindowsReferenceBackend.fail_closed_plan("exec_cleanup_failure", &cwd, &policy);
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
        let mut plan =
            WindowsReferenceBackend.fail_closed_plan("exec_inconsistent_acl", &cwd, &policy);
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
    fn sandbox_setup_rejects_incomplete_process_boundary_before_creating_runtime_tree()
    -> io::Result<()> {
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
        let mut plan =
            WindowsReferenceBackend.fail_closed_plan("exec_bad_user_model", &cwd, &policy);
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
    fn sandbox_setup_rejects_non_single_user_setup_artifacts_before_runtime_tree() -> io::Result<()>
    {
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
    fn sandbox_setup_rejects_missing_single_user_setup_payload_before_runtime_tree()
    -> io::Result<()> {
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
        let mut plan =
            WindowsReferenceBackend.fail_closed_plan("exec_outside_setup", &cwd, &policy);
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

    #[cfg(any(unix, windows))]
    #[test]
    fn runtime_setup_refuses_symlinked_runtime_marker() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let cwd = tmp.path().join("workspace");
        fs::create_dir_all(&cwd)?;
        let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
        let plan =
            WindowsReferenceBackend.fail_closed_plan("exec_setup_marker_symlink", &cwd, &policy);
        let runtime_root = PathBuf::from(plan.runtime_root.as_ref().unwrap());
        fs::create_dir_all(&runtime_root)?;
        let marker_target = tmp.path().join("marker-target");
        fs::write(&marker_target, plan.execution_id.as_bytes())?;
        if let Err(err) =
            symlink_file_for_test(&marker_target, &runtime_root.join(RUNTIME_ROOT_MARKER))
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
        let plan =
            WindowsReferenceBackend.fail_closed_plan("exec_setup_tree_symlink", &cwd, &policy);
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
    fn runtime_setup_refuses_runtime_parent_symlink_before_creating_runtime_tree() -> io::Result<()>
    {
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
        if let Err(err) =
            symlink_file_for_test(&marker_target, &runtime_root.join(RUNTIME_ROOT_MARKER))
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
        let plan =
            WindowsReferenceBackend.fail_closed_plan("exec_cleanup_tree_symlink", &cwd, &policy);
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
}
