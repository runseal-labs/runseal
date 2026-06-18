use crate::policy::{BackendFeature, SandboxLevel, SandboxPolicy};
use crate::windows_plan::{
    WindowsFilesystemAclEntry, WindowsFilesystemAclPlan, WindowsFilesystemAclTransactionPlan,
    WindowsFilesystemAclTransactionStep, WindowsFilesystemRule, WindowsHostRoots,
    WindowsPolicyPlan, WindowsRuntimeRoots,
};
use serde_json::Map;
use serde_json::{Value, json};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(windows)]
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};

const RUNTIME_ROOT_MARKER: &str = ".runseal-runtime-root";

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
    private_process_token: &'static str,
    private_process_job: &'static str,
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
            filesystem_read: policy.filesystem.read.clone(),
            filesystem_write: policy.filesystem.write.clone(),
            filesystem_deny: policy.filesystem.deny.clone(),
            filesystem_protected: protected_filesystem_labels(policy),
            private_filesystem_deny: Vec::new(),
            private_filesystem_rules: Vec::new(),
            process_boundary: "local-process",
            process_identity: "current-user",
            process_cleanup: "direct-child",
            private_process_token: "none",
            private_process_job: "none",
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

    pub fn prepare_sandbox_setup(&self) -> io::Result<Vec<String>> {
        let prepared_roots = self.prepare_runtime_roots()?;
        if let Err(setup_err) = self.prepare_filesystem_rules() {
            self.cleanup_runtime_roots()?;
            return Err(setup_err);
        }
        Ok(prepared_roots)
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

    pub fn prepare_filesystem_rules(&self) -> io::Result<Vec<String>> {
        let mut driver = ValidateOnlyWindowsFilesystemAclDriver;
        self.prepare_filesystem_rules_with_driver(&mut driver)
    }

    fn prepare_filesystem_rules_with_driver(
        &self,
        driver: &mut dyn WindowsFilesystemAclDriver,
    ) -> io::Result<Vec<String>> {
        let acl_plan = WindowsFilesystemAclPlan::from_rules(&self.private_filesystem_rules);
        let transaction = WindowsFilesystemAclTransactionPlan::from_acl_plan(&acl_plan);
        validate_private_filesystem_acl_transaction(&transaction)?;
        validate_private_filesystem_acl_entries(&transaction)?;
        apply_private_filesystem_acl_transaction(&transaction, driver)?;

        let mut prepared = Vec::new();
        for entry in transaction.apply_entries() {
            if !prepared.iter().any(|root| root == entry.root()) {
                prepared.push(entry.root().to_string());
            }
        }
        Ok(prepared)
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

    fn validate_runtime_root_for_cleanup(&self, runtime_root: &Path) -> io::Result<()> {
        let expected = self.expected_runtime_root()?;
        if normalize_lexical(runtime_root) != normalize_lexical(&expected) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to clean runtime root outside planned workspace runtime directory: {}",
                    runtime_root.display()
                ),
            ));
        }
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
        if !marker.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to clean unmarked runtime root: {}",
                    runtime_root.display()
                ),
            ));
        }
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
                    "invalid execution id for runtime cleanup: {}",
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

fn prepare_unique_runtime_root(prepared: &mut Vec<String>, root: &str) -> io::Result<()> {
    fs::create_dir_all(root)?;
    if !prepared.iter().any(|item| item == root) {
        prepared.push(root.to_string());
    }
    Ok(())
}

fn validate_private_filesystem_acl_transaction(
    transaction: &WindowsFilesystemAclTransactionPlan,
) -> io::Result<()> {
    if !transaction.captures_before_apply() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private filesystem ACL transaction must capture rollback state before applying entries",
        ));
    }
    for root in transaction.rollback_roots() {
        validate_private_filesystem_rule_root(root)?;
    }
    Ok(())
}

fn validate_private_filesystem_acl_entries(
    transaction: &WindowsFilesystemAclTransactionPlan,
) -> io::Result<()> {
    for entry in transaction.apply_entries() {
        validate_private_filesystem_acl_entry(entry)?;
    }
    Ok(())
}

trait WindowsFilesystemAclDriver {
    fn capture_rollback(&mut self, root: &str) -> io::Result<()>;
    fn apply_entry(&mut self, entry: &WindowsFilesystemAclEntry) -> io::Result<()>;
    fn rollback(&mut self) -> io::Result<()>;
}

#[derive(Default)]
struct ValidateOnlyWindowsFilesystemAclDriver;

impl WindowsFilesystemAclDriver for ValidateOnlyWindowsFilesystemAclDriver {
    fn capture_rollback(&mut self, _root: &str) -> io::Result<()> {
        Ok(())
    }

    fn apply_entry(&mut self, _entry: &WindowsFilesystemAclEntry) -> io::Result<()> {
        Ok(())
    }

    fn rollback(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn apply_private_filesystem_acl_transaction(
    transaction: &WindowsFilesystemAclTransactionPlan,
    driver: &mut dyn WindowsFilesystemAclDriver,
) -> io::Result<()> {
    for step in transaction.steps() {
        match step {
            WindowsFilesystemAclTransactionStep::CaptureRollback { root } => {
                driver.capture_rollback(root)?;
            }
            WindowsFilesystemAclTransactionStep::ApplyEntry { entry } => {
                if let Err(apply_err) = driver.apply_entry(entry) {
                    return rollback_private_filesystem_acl_transaction(driver, apply_err);
                }
            }
        }
    }
    Ok(())
}

fn rollback_private_filesystem_acl_transaction(
    driver: &mut dyn WindowsFilesystemAclDriver,
    apply_err: io::Error,
) -> io::Result<()> {
    if let Err(rollback_err) = driver.rollback() {
        return Err(io::Error::other(format!(
            "private filesystem ACL transaction failed ({apply_err}); rollback failed ({rollback_err})"
        )));
    }
    Err(apply_err)
}

fn validate_private_filesystem_acl_entry(entry: &WindowsFilesystemAclEntry) -> io::Result<()> {
    validate_private_filesystem_rule_root(entry.root())?;
    if !entry.has_consistent_access_source() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "inconsistent private filesystem ACL entry for root: {}",
                entry.root()
            ),
        ));
    }
    if !entry.is_tree_scoped() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "private filesystem ACL entry must be tree scoped: {}",
                entry.root()
            ),
        ));
    }
    if entry.requires_existing_root() {
        validate_existing_filesystem_rule_root(entry)?;
    }
    Ok(())
}

fn validate_private_filesystem_rule_root(root: &str) -> io::Result<()> {
    if root.is_empty() || root == "*" {
        return Err(invalid_filesystem_rule_root(root));
    }
    if contains_parent_traversal(root)
        || is_broad_filesystem_rule_root(root)
        || is_windows_drive_relative(root)
        || !is_concrete_filesystem_rule_root(root)
    {
        return Err(invalid_filesystem_rule_root(root));
    }
    Ok(())
}

fn validate_existing_filesystem_rule_root(entry: &WindowsFilesystemAclEntry) -> io::Result<()> {
    let metadata = fs::symlink_metadata(entry.root()).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "private filesystem rule root must exist before setup: {}",
                    entry.root()
                ),
            )
        } else {
            err
        }
    })?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to prepare symlinked filesystem rule root: {}",
                entry.root()
            ),
        ));
    }
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "private filesystem rule root must be a directory: {}",
                entry.root()
            ),
        ));
    }
    Ok(())
}

fn invalid_filesystem_rule_root(root: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid private filesystem rule root: {root}"),
    )
}

fn contains_parent_traversal(path: &str) -> bool {
    Path::new(path)
        .components()
        .any(|component| component == Component::ParentDir)
        || path.split(['/', '\\']).any(|component| component == "..")
}

fn is_broad_filesystem_rule_root(root: &str) -> bool {
    let trimmed = root.trim_end_matches(['/', '\\']);
    root.trim_matches(['/', '\\']).is_empty()
        || matches!(trimmed.to_ascii_lowercase().as_str(), "~" | "$home")
        || trimmed.ends_with(':')
}

fn is_windows_drive_relative(root: &str) -> bool {
    let bytes = root.as_bytes();
    bytes.len() >= 2 && bytes[1] == b':' && !matches!(bytes.get(2), Some(b'/' | b'\\'))
}

fn is_concrete_filesystem_rule_root(root: &str) -> bool {
    root.starts_with(['/', '\\']) || is_windows_drive_absolute(root)
}

fn is_windows_drive_absolute(root: &str) -> bool {
    let bytes = root.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
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
        let private_process_token = windows_policy.process.token.as_str();
        let private_process_job = windows_policy.process.job.as_str();
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
            private_process_token,
            private_process_job,
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
        "scaffold"
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
                "Windows reference backend scaffold is present",
                "runtime roots are created, marked, and cleaned with containment checks",
                "runtime environment redirects are injected into child process environments",
                "process cleanup is backed by Windows kill-on-close Job Objects",
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

fn spawn_local_command(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
) -> io::Result<BackendExecutionOutput> {
    let mut process = Command::new(&command[0]);
    process
        .args(&command[1..])
        .current_dir(cwd)
        .env_clear()
        .envs(minimal_environment(plan))
        .envs(env.entries.iter().map(|(key, value)| (key, value)));
    match &stdin {
        ExecutionStdin::Empty => {
            process.stdin(Stdio::null());
        }
        ExecutionStdin::Bytes(_) => {
            process.stdin(Stdio::piped());
        }
    }

    let Some(timeout) = timeout else {
        process.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = process.spawn()?;
        #[cfg(windows)]
        let _process_job = match assign_windows_process_job(plan, &child) {
            Ok(process_job) => process_job,
            Err(err) => return Err(cleanup_child_after_setup_error(child, err)),
        };
        if let ExecutionStdin::Bytes(bytes) = stdin
            && let Err(err) = write_child_stdin(&mut child, bytes)
        {
            return Err(cleanup_child_after_setup_error(child, err));
        }
        return child
            .wait_with_output()
            .map(|output| BackendExecutionOutput {
                output,
                timed_out: false,
            });
    };

    if matches!(stdin, ExecutionStdin::Bytes(_)) {
        process.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    let start = Instant::now();
    let mut child = process.spawn()?;
    #[cfg(windows)]
    let _process_job = match assign_windows_process_job(plan, &child) {
        Ok(process_job) => process_job,
        Err(err) => return Err(cleanup_child_after_setup_error(child, err)),
    };
    if let ExecutionStdin::Bytes(bytes) = stdin
        && let Err(err) = write_child_stdin(&mut child, bytes)
    {
        return Err(cleanup_child_after_setup_error(child, err));
    }
    loop {
        if child.try_wait()?.is_some() {
            return child
                .wait_with_output()
                .map(|output| BackendExecutionOutput {
                    output,
                    timed_out: false,
                });
        }

        if start.elapsed() >= timeout {
            if let Err(err) = child.kill()
                && err.kind() != io::ErrorKind::InvalidInput
            {
                return Err(err);
            }
            return child
                .wait_with_output()
                .map(|output| BackendExecutionOutput {
                    output,
                    timed_out: true,
                });
        }

        thread::sleep(
            timeout
                .saturating_sub(start.elapsed())
                .min(Duration::from_millis(10)),
        );
    }
}

fn write_child_stdin(child: &mut std::process::Child, bytes: Vec<u8>) -> io::Result<()> {
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&bytes)?;
    }
    Ok(())
}

fn cleanup_child_after_setup_error(mut child: Child, setup_err: io::Error) -> io::Error {
    let kill_err = match child.kill() {
        Ok(()) => None,
        Err(err) if err.kind() == io::ErrorKind::InvalidInput => None,
        Err(err) => Some(err),
    };
    let wait_err = child.wait().err();

    match (kill_err, wait_err) {
        (None, None) => setup_err,
        (Some(kill_err), None) => io::Error::other(format!(
            "child setup failed ({setup_err}); cleanup kill failed ({kill_err})"
        )),
        (None, Some(wait_err)) => io::Error::other(format!(
            "child setup failed ({setup_err}); cleanup wait failed ({wait_err})"
        )),
        (Some(kill_err), Some(wait_err)) => io::Error::other(format!(
            "child setup failed ({setup_err}); cleanup kill failed ({kill_err}); cleanup wait failed ({wait_err})"
        )),
    }
}

#[cfg(windows)]
fn assign_windows_process_job(
    plan: &PlatformSandboxPlan,
    child: &std::process::Child,
) -> io::Result<Option<WindowsKillOnCloseJob>> {
    if plan.private_process_job != "kill-on-close-job" {
        return Ok(None);
    }
    let job = WindowsKillOnCloseJob::new()?;
    job.assign_child(child)?;
    Ok(Some(job))
}

#[cfg(windows)]
struct WindowsKillOnCloseJob {
    handle: HANDLE,
}

#[cfg(windows)]
impl WindowsKillOnCloseJob {
    fn new() -> io::Result<Self> {
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Self { handle };
        if let Err(err) = job.set_kill_on_close() {
            drop(job);
            return Err(err);
        }
        Ok(job)
    }

    fn set_kill_on_close(&self) -> io::Result<()> {
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let result = unsafe {
            SetInformationJobObject(
                self.handle,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(limits).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn assign_child(&self, child: &std::process::Child) -> io::Result<()> {
        let process_handle = child.as_raw_handle() as HANDLE;
        let result = unsafe { AssignProcessToJobObject(self.handle, process_handle) };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for WindowsKillOnCloseJob {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

fn minimal_environment(plan: &PlatformSandboxPlan) -> Vec<(OsString, OsString)> {
    if plan.environment_inherit != "minimal" {
        return Vec::new();
    }

    let mut environment: Vec<(OsString, OsString)> = minimal_environment_keys()
        .into_iter()
        .filter(|key| {
            !plan
                .environment_scrub
                .iter()
                .any(|pattern| matches_environment_scrub_pattern(key, pattern))
        })
        .filter_map(|key| env::var_os(key).map(|value| (OsString::from(key), value)))
        .collect();
    environment.extend(
        plan.environment_runtime
            .iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value))),
    );
    environment
}

fn minimal_environment_keys() -> Vec<&'static str> {
    if cfg!(windows) {
        vec![
            "PATH",
            "Path",
            "PATHEXT",
            "SYSTEMROOT",
            "SystemRoot",
            "WINDIR",
            "COMSPEC",
            "TEMP",
            "TMP",
        ]
    } else {
        vec!["PATH", "TMPDIR", "LANG", "LC_ALL"]
    }
}

pub(crate) fn matches_environment_scrub_pattern(key: &str, pattern: &str) -> bool {
    let key = key.to_ascii_uppercase();
    let pattern = pattern.to_ascii_uppercase();

    if let Some(prefix) = pattern.strip_suffix('*') {
        return key.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return key.ends_with(suffix);
    }

    key == pattern
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
            "runtime_roots": supported_features.contains(&BackendFeature::RuntimeRoots),
            "runtime_environment": supported_features.contains(&BackendFeature::RuntimeEnvironment),
            "process_isolation": supported_features.contains(&BackendFeature::ProcessIsolation),
            "process_cleanup": supported_features.contains(&BackendFeature::ProcessCleanup),
            "direct_network_deny": supported_features.contains(&BackendFeature::DirectNetworkDeny),
            "network_disabled": supported_features.contains(&BackendFeature::NetworkDisabled),
            "network_proxy": supported_features.contains(&BackendFeature::NetworkProxy),
            "managed_proxy": supported_features.contains(&BackendFeature::ManagedProxy),
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
    use crate::windows_plan::{
        WindowsFilesystemAccess, WindowsFilesystemAclPlan, WindowsFilesystemAclTransactionPlan,
        WindowsFilesystemRule, WindowsFilesystemRuleSource,
    };
    use serde_json::json;
    use std::ffi::OsString;
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[derive(Default)]
    struct RecordingAclDriver {
        events: Vec<String>,
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

        fn apply_entry(&mut self, entry: &WindowsFilesystemAclEntry) -> io::Result<()> {
            self.events.push(format!("apply:{}", entry.root()));
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
            &[
                BackendFeature::RuntimeRoots,
                BackendFeature::RuntimeEnvironment,
                BackendFeature::ProcessCleanup,
            ]
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
        assert_eq!(plan.private_process_token, "restricted-token");
        assert_eq!(plan.private_process_job, "kill-on-close-job");
        assert_eq!(plan.filesystem_protected, vec!["workspace_metadata"]);
        let plan_json = plan.json();
        let public_plan = plan_json.to_string();
        assert!(!public_plan.contains("restricted-token"));
        assert!(!public_plan.contains("kill-on-close-job"));
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
            &[
                BackendFeature::RuntimeRoots,
                BackendFeature::RuntimeEnvironment,
                BackendFeature::ProcessCleanup,
            ]
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

        apply_private_filesystem_acl_transaction(&transaction, &mut driver)?;

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

        let err = apply_private_filesystem_acl_transaction(&transaction, &mut driver)
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

        let err = apply_private_filesystem_acl_transaction(&transaction, &mut driver)
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

        let err = apply_private_filesystem_acl_transaction(&transaction, &mut driver)
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

        let err = plan.prepare_sandbox_setup().unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!runtime_root.exists());
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
}
