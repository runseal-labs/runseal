use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::path::{Component, Path};

pub const POLICY_VERSION: &str = "runseal.policy/v1";
const MAX_ENV_ENTRIES: usize = 64;
const MAX_ENV_KEY_BYTES: usize = 128;
const MAX_ENV_VALUE_BYTES: usize = 4096;
pub const PROTECTED_WORKSPACE_SUBPATHS: [&str; 5] = [
    ".git",
    ".runseal/audit",
    ".runseal/audit.jsonl",
    ".agents",
    ".codex",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxLevel {
    ReadOnly,
    WorkspaceContained,
    WorkspaceWrite,
    DangerFullAccess,
}

impl SandboxLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::WorkspaceContained => "workspace-contained",
            Self::WorkspaceWrite => "workspace-write",
            Self::DangerFullAccess => "danger-full-access",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "read-only" => Some(Self::ReadOnly),
            "workspace-contained" => Some(Self::WorkspaceContained),
            "workspace-write" => Some(Self::WorkspaceWrite),
            "danger-full-access" => Some(Self::DangerFullAccess),
            _ => None,
        }
    }

    fn protects_workspace(self) -> bool {
        matches!(self, Self::WorkspaceContained | Self::WorkspaceWrite)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkMode {
    Unmanaged,
    Disabled,
    Proxy,
}

impl NetworkMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unmanaged => "unmanaged",
            Self::Disabled => "disabled",
            Self::Proxy => "proxy",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "unmanaged" => Some(Self::Unmanaged),
            "disabled" => Some(Self::Disabled),
            "proxy" => Some(Self::Proxy),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendFeature {
    FilesystemPolicy,
    RuntimeRoots,
    RuntimeEnvironment,
    ProcessIsolation,
    ProcessCleanup,
    DirectNetworkDeny,
    NetworkDisabled,
    NetworkProxy,
    ManagedProxy,
    PolicyEpoch,
    ResourceLimits,
}

impl BackendFeature {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FilesystemPolicy => "filesystem_policy",
            Self::RuntimeRoots => "runtime_roots",
            Self::RuntimeEnvironment => "runtime_environment",
            Self::ProcessIsolation => "process_isolation",
            Self::ProcessCleanup => "process_cleanup",
            Self::DirectNetworkDeny => "direct_network_deny",
            Self::NetworkDisabled => "network_disabled",
            Self::NetworkProxy => "network_proxy",
            Self::ManagedProxy => "managed_proxy",
            Self::PolicyEpoch => "policy_epoch",
            Self::ResourceLimits => "resource_limits",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemPolicy {
    pub read: Vec<String>,
    pub read_only: Vec<String>,
    pub write: Vec<String>,
    pub deny: Vec<String>,
    pub protect_vcs: bool,
    pub unrestricted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkPolicy {
    pub mode: NetworkMode,
    pub routes: Vec<String>,
    pub direct_allow_hosts: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentPolicy {
    pub inherit: String,
    pub scrub: Vec<String>,
    pub set: Vec<(String, String)>,
    pub proxy: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourcePolicy {
    pub timeout_ms: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub cpu_percent: Option<u64>,
    pub max_output_bytes: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessPolicy {
    pub allow_child_processes: bool,
    pub kill_on_parent_exit: bool,
    pub max_processes: Option<u64>,
    pub interactive: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalPolicy {
    pub on_violation: String,
    pub on_network_route_missing: String,
    pub on_broad_write: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicySource {
    Named,
    Inline,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxPolicy {
    pub id: String,
    pub sandbox_level: SandboxLevel,
    pub filesystem: FilesystemPolicy,
    pub network: NetworkPolicy,
    pub environment: EnvironmentPolicy,
    pub resources: ResourcePolicy,
    pub process: ProcessPolicy,
    pub approval: ApprovalPolicy,
    pub source: PolicySource,
}

impl SandboxPolicy {
    pub fn canonical_json(&self) -> Value {
        json!({
            "version": POLICY_VERSION,
            "id": self.id.clone(),
            "sandbox_level": self.sandbox_level.as_str(),
            "filesystem": {
                "read": self.filesystem.read.clone(),
                "read_only": self.filesystem.read_only.clone(),
                "write": self.filesystem.write.clone(),
                "deny": self.filesystem.deny.clone(),
                "protect_vcs": self.filesystem.protect_vcs,
                "unrestricted": self.filesystem.unrestricted,
            },
            "network": {
                "mode": self.network.mode.as_str(),
                "routes": self.network.routes.clone(),
                "direct_allow_hosts": self.network.direct_allow_hosts.clone(),
            },
            "environment": {
                "inherit": self.environment.inherit.clone(),
                "scrub": self.environment.scrub.clone(),
                "set": environment_set_json(&self.environment.set),
                "proxy": self.environment.proxy,
            },
            "resources": {
                "timeout_ms": self.resources.timeout_ms,
                "memory_bytes": self.resources.memory_bytes,
                "cpu_percent": self.resources.cpu_percent,
                "max_output_bytes": self.resources.max_output_bytes,
            },
            "process": {
                "allow_child_processes": self.process.allow_child_processes,
                "kill_on_parent_exit": self.process.kill_on_parent_exit,
                "max_processes": self.process.max_processes,
                "interactive": self.process.interactive,
            },
            "runtime": {
                "root_mode": self.runtime_root_mode(),
            },
            "required_backend_features": self.required_backend_feature_names(),
            "approval": {
                "on_violation": self.approval.on_violation.clone(),
                "on_network_route_missing": self.approval.on_network_route_missing.clone(),
                "on_broad_write": self.approval.on_broad_write.clone(),
            }
        })
    }

    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_json().to_string().as_bytes());
        format!("sha256:{:x}", hasher.finalize())
    }

    pub fn explain_json(&self) -> Value {
        let canonical_policy = self.canonical_json();
        json!({
            "policy_id": self.id.clone(),
            "policy_hash": self.hash(),
            "version": POLICY_VERSION,
            "sandbox_level": self.sandbox_level.as_str(),
            "filesystem": {
                "read": self.filesystem.read.clone(),
                "read_only": self.filesystem.read_only.clone(),
                "write": self.filesystem.write.clone(),
                "deny": self.filesystem.deny.clone(),
                "protect_vcs": self.filesystem.protect_vcs,
                "unrestricted": self.filesystem.unrestricted,
            },
            "network": {
                "mode": self.network.mode.as_str(),
                "routes": self.network.routes.clone(),
                "direct_allow_hosts": self.network.direct_allow_hosts.clone(),
            },
            "environment": {
                "inherit": self.environment.inherit.clone(),
                "scrub": self.environment.scrub.clone(),
                "set": environment_set_json(&self.environment.set),
                "proxy": self.environment.proxy,
            },
            "resources": {
                "timeout_ms": self.resources.timeout_ms,
                "memory_bytes": self.resources.memory_bytes,
                "cpu_percent": self.resources.cpu_percent,
                "max_output_bytes": self.resources.max_output_bytes,
            },
            "process": {
                "allow_child_processes": self.process.allow_child_processes,
                "kill_on_parent_exit": self.process.kill_on_parent_exit,
                "max_processes": self.process.max_processes,
                "interactive": self.process.interactive,
            },
            "approval": {
                "on_violation": self.approval.on_violation.clone(),
                "on_network_route_missing": self.approval.on_network_route_missing.clone(),
                "on_broad_write": self.approval.on_broad_write.clone(),
            },
            "backend_requirement": if self.allows_local_execution() {
                "local-execution"
            } else {
                "sandbox-backend"
            },
            "required_backend_features": self.required_backend_feature_names(),
            "support": if self.allows_local_execution() {
                "supported"
            } else {
                "unsupported"
            },
            "canonical_policy": canonical_policy,
        })
    }

    pub fn allows_local_execution(&self) -> bool {
        self.sandbox_level == SandboxLevel::DangerFullAccess
    }

    pub fn denies_execution_without_backend(&self) -> bool {
        self.source == PolicySource::Inline
            && !self.filesystem.unrestricted
            && self.filesystem.write.is_empty()
    }

    pub fn requires_broad_write_approval(&self) -> bool {
        self.sandbox_level != SandboxLevel::DangerFullAccess
            && self.approval.on_broad_write == "request"
            && self
                .filesystem
                .write
                .iter()
                .any(|entry| is_broad_write_root(entry))
    }

    pub fn required_backend_features(&self) -> Vec<BackendFeature> {
        if self.allows_local_execution() {
            return Vec::new();
        }

        let mut features = vec![
            BackendFeature::FilesystemPolicy,
            BackendFeature::RuntimeRoots,
            BackendFeature::RuntimeEnvironment,
            BackendFeature::ProcessIsolation,
            BackendFeature::ProcessCleanup,
        ];
        if self.resources.memory_bytes.is_some() || self.resources.cpu_percent.is_some() {
            features.push(BackendFeature::ResourceLimits);
        }
        match self.network.mode {
            NetworkMode::Unmanaged => {}
            NetworkMode::Disabled => {
                features.push(BackendFeature::DirectNetworkDeny);
                features.push(BackendFeature::NetworkDisabled);
            }
            NetworkMode::Proxy => {
                features.push(BackendFeature::DirectNetworkDeny);
                features.push(BackendFeature::NetworkProxy);
                features.push(BackendFeature::ManagedProxy);
            }
        }
        features
    }

    pub fn required_backend_feature_names(&self) -> Vec<&'static str> {
        self.required_backend_features()
            .into_iter()
            .map(BackendFeature::as_str)
            .collect()
    }

    fn runtime_root_mode(&self) -> &'static str {
        if self.allows_local_execution() {
            "none"
        } else {
            "per-execution"
        }
    }
}

#[derive(Debug)]
pub struct PolicyError {
    pub code: &'static str,
    pub reason: String,
}

impl PolicyError {
    fn invalid(reason: impl Into<String>) -> Self {
        Self {
            code: "POLICY_INVALID",
            reason: reason.into(),
        }
    }
}

pub fn normalize_policy(
    input: &Value,
    cwd: &Path,
    network_override: Option<NetworkMode>,
) -> Result<SandboxPolicy, PolicyError> {
    if let Some(profile) = input.as_str() {
        return named_profile(profile, cwd, network_override);
    }

    let object = input
        .as_object()
        .ok_or_else(|| PolicyError::invalid("policy must be a profile name or object"))?;
    validate_keys(
        object,
        "policy",
        &[
            "version",
            "id",
            "description",
            "sandbox_level",
            "filesystem",
            "network",
            "environment",
            "process",
            "resources",
            "audit",
            "approval",
            "backend",
        ],
    )?;

    let version = optional_string(object, "version")?.unwrap_or(POLICY_VERSION);
    if version != POLICY_VERSION {
        return Err(PolicyError::invalid(format!(
            "unsupported policy version: {version}"
        )));
    }
    optional_string(object, "description")?;
    reject_non_empty_section(object, "audit")?;
    reject_non_empty_section(object, "backend")?;

    let id = optional_string(object, "id")?
        .unwrap_or("inline")
        .to_string();
    let filesystem = optional_object(object, "filesystem")?;
    let sandbox_level = if let Some(level) = optional_string(object, "sandbox_level")? {
        SandboxLevel::from_str(level).ok_or_else(|| {
            PolicyError::invalid(format!(
                "sandbox_level must be read-only, workspace-contained, workspace-write, or danger-full-access, got {level}"
            ))
        })?
    } else {
        infer_level(filesystem)
    };
    let inline_network = match inline_network_mode(object.get("network")) {
        Some(network) => Some(network?),
        None => None,
    };
    let network = if let Some(network) = network_override {
        network
    } else if let Some(network) = inline_network {
        network
    } else {
        default_network_mode(sandbox_level)
    };
    let approval = inline_approval(optional_object(object, "approval")?)?;
    let network = inline_network_policy(object.get("network"), network)?;
    let environment = inline_environment(optional_object(object, "environment")?, network.mode)?;
    let resources = inline_resources(optional_object(object, "resources")?, sandbox_level)?;
    let process = inline_process(optional_object(object, "process")?, sandbox_level)?;
    let filesystem = inline_filesystem(filesystem, cwd, sandbox_level, &approval)?;

    Ok(SandboxPolicy {
        id,
        sandbox_level,
        filesystem,
        network,
        environment,
        resources,
        process,
        approval,
        source: PolicySource::Inline,
    })
}

fn named_profile(
    profile: &str,
    cwd: &Path,
    network_override: Option<NetworkMode>,
) -> Result<SandboxPolicy, PolicyError> {
    let sandbox_level = SandboxLevel::from_str(profile)
        .ok_or_else(|| PolicyError::invalid(format!("unknown policy profile: {profile}")))?;
    let network = network_override.unwrap_or_else(|| default_network_mode(sandbox_level));

    Ok(SandboxPolicy {
        id: profile.to_string(),
        sandbox_level,
        filesystem: profile_filesystem(cwd, sandbox_level),
        network: default_network(network),
        environment: default_environment(network),
        resources: default_resources(),
        process: default_process(sandbox_level),
        approval: default_approval(),
        source: PolicySource::Named,
    })
}

fn profile_filesystem(cwd: &Path, sandbox_level: SandboxLevel) -> FilesystemPolicy {
    match sandbox_level {
        SandboxLevel::DangerFullAccess => FilesystemPolicy {
            read: vec!["*".to_string()],
            read_only: Vec::new(),
            write: vec!["*".to_string()],
            deny: Vec::new(),
            protect_vcs: false,
            unrestricted: true,
        },
        SandboxLevel::ReadOnly => FilesystemPolicy {
            read: vec![path_string(cwd)],
            read_only: Vec::new(),
            write: Vec::new(),
            deny: Vec::new(),
            protect_vcs: false,
            unrestricted: false,
        },
        SandboxLevel::WorkspaceContained | SandboxLevel::WorkspaceWrite => FilesystemPolicy {
            read: vec![path_string(cwd)],
            read_only: Vec::new(),
            write: vec![path_string(cwd)],
            deny: protected_subpaths(cwd),
            protect_vcs: true,
            unrestricted: false,
        },
    }
}

fn inline_filesystem(
    filesystem: Option<&Map<String, Value>>,
    cwd: &Path,
    sandbox_level: SandboxLevel,
    approval: &ApprovalPolicy,
) -> Result<FilesystemPolicy, PolicyError> {
    if let Some(filesystem) = filesystem {
        validate_keys(
            filesystem,
            "filesystem",
            &["read", "read_only", "write", "deny", "protect_vcs"],
        )?;
    }
    let read = string_array(filesystem, "read")?.unwrap_or_else(|| match sandbox_level {
        SandboxLevel::DangerFullAccess => vec!["*".to_string()],
        _ => vec![path_string(cwd)],
    });
    let read_only = string_array(filesystem, "read_only")?.unwrap_or_default();
    let write = string_array(filesystem, "write")?.unwrap_or_else(|| match sandbox_level {
        SandboxLevel::DangerFullAccess => vec!["*".to_string()],
        SandboxLevel::ReadOnly => Vec::new(),
        SandboxLevel::WorkspaceContained | SandboxLevel::WorkspaceWrite => vec![path_string(cwd)],
    });
    let protect_vcs = optional_bool(filesystem, "protect_vcs")?
        .unwrap_or_else(|| sandbox_level.protects_workspace());
    let deny = string_array(filesystem, "deny")?.unwrap_or_else(|| {
        if protect_vcs {
            protected_subpaths(cwd)
        } else {
            Vec::new()
        }
    });
    validate_path_entries(&read, "filesystem.read", false)?;
    validate_path_entries(&read_only, "filesystem.read_only", false)?;
    let reject_broad_write =
        sandbox_level != SandboxLevel::DangerFullAccess && approval.on_broad_write != "request";
    validate_path_entries(&write, "filesystem.write", reject_broad_write)?;
    validate_path_entries(&deny, "filesystem.deny", false)?;

    Ok(FilesystemPolicy {
        read,
        read_only,
        write,
        deny,
        protect_vcs,
        unrestricted: sandbox_level == SandboxLevel::DangerFullAccess,
    })
}

fn string_array(
    object: Option<&Map<String, Value>>,
    field: &'static str,
) -> Result<Option<Vec<String>>, PolicyError> {
    string_array_for(object, "filesystem", field)
}

fn string_array_for(
    object: Option<&Map<String, Value>>,
    context: &'static str,
    field: &'static str,
) -> Result<Option<Vec<String>>, PolicyError> {
    let Some(value) = object.and_then(|object| object.get(field)) else {
        return Ok(None);
    };
    let items = value
        .as_array()
        .ok_or_else(|| PolicyError::invalid(format!("{context}.{field} must be an array")))?;

    items
        .iter()
        .map(|item| {
            item.as_str().map(str::to_string).ok_or_else(|| {
                PolicyError::invalid(format!("{context}.{field} entries must be strings"))
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn inline_network_mode(network: Option<&Value>) -> Option<Result<NetworkMode, PolicyError>> {
    let value = network?;
    let mode = if let Some(mode) = value.as_str() {
        mode
    } else {
        let object = match value.as_object() {
            Some(object) => object,
            None => {
                return Some(Err(PolicyError::invalid(
                    "network must be a string or object",
                )));
            }
        };
        if let Err(err) =
            validate_keys(object, "network", &["mode", "routes", "direct_allow_hosts"])
        {
            return Some(Err(err));
        }
        match optional_string(object, "mode") {
            Ok(Some(mode)) => mode,
            Ok(None) => "unmanaged",
            Err(err) => return Some(Err(err)),
        }
    };

    Some(NetworkMode::from_str(mode).ok_or_else(|| {
        PolicyError::invalid(format!(
            "network.mode must be unmanaged, disabled, or proxy, got {mode}"
        ))
    }))
}

fn inline_network_policy(
    network: Option<&Value>,
    mode: NetworkMode,
) -> Result<NetworkPolicy, PolicyError> {
    let mut policy = default_network(mode);
    let Some(network) = network else {
        return Ok(policy);
    };
    let Some(object) = network.as_object() else {
        return Ok(policy);
    };

    if let Some(routes) = string_array_for(Some(object), "network", "routes")? {
        validate_non_empty_strings(&routes, "network.routes")?;
        if mode != NetworkMode::Proxy && !routes.is_empty() {
            return Err(PolicyError::invalid("network.routes require proxy mode"));
        }
        policy.routes = routes;
    }
    if let Some(direct_allow_hosts) =
        string_array_for(Some(object), "network", "direct_allow_hosts")?
    {
        validate_non_empty_strings(&direct_allow_hosts, "network.direct_allow_hosts")?;
        if !direct_allow_hosts.is_empty() {
            return Err(PolicyError::invalid(
                "network.direct_allow_hosts is not supported in this build",
            ));
        }
        policy.direct_allow_hosts = direct_allow_hosts;
    }

    Ok(policy)
}

fn inline_environment(
    environment: Option<&Map<String, Value>>,
    network: NetworkMode,
) -> Result<EnvironmentPolicy, PolicyError> {
    let mut policy = default_environment(network);
    let Some(environment) = environment else {
        return Ok(policy);
    };

    validate_keys(
        environment,
        "environment",
        &["inherit", "scrub", "proxy", "set"],
    )?;

    if let Some(inherit) = optional_string(environment, "inherit")? {
        if inherit != "minimal" {
            return Err(PolicyError::invalid(format!(
                "environment.inherit must be minimal, got {inherit}"
            )));
        }
        policy.inherit = inherit.to_string();
    }
    if let Some(scrub) = string_array_for(Some(environment), "environment", "scrub")? {
        validate_environment_patterns(&scrub)?;
        policy.scrub = scrub;
    }
    if let Some(proxy) = optional_bool_for(Some(environment), "environment", "proxy")? {
        policy.proxy = proxy;
    }
    if network == NetworkMode::Proxy && !policy.proxy {
        return Err(PolicyError::invalid(
            "network.proxy requires environment.proxy=true",
        ));
    }
    policy.set = environment_set(environment.get("set"), &policy.scrub)?;

    Ok(policy)
}

fn inline_resources(
    resources: Option<&Map<String, Value>>,
    sandbox_level: SandboxLevel,
) -> Result<ResourcePolicy, PolicyError> {
    let Some(resources) = resources else {
        return Ok(default_resources());
    };
    validate_keys(
        resources,
        "resources",
        &[
            "timeout_ms",
            "memory_bytes",
            "cpu_percent",
            "max_output_bytes",
        ],
    )?;
    if sandbox_level == SandboxLevel::DangerFullAccess {
        reject_backend_resource_requirement(resources, "memory_bytes")?;
        reject_backend_resource_requirement(resources, "cpu_percent")?;
    }

    Ok(ResourcePolicy {
        timeout_ms: optional_u64(resources, "resources", "timeout_ms")?,
        memory_bytes: optional_positive_u64(resources, "resources", "memory_bytes")?,
        cpu_percent: optional_positive_u64(resources, "resources", "cpu_percent")?,
        max_output_bytes: optional_u64(resources, "resources", "max_output_bytes")?,
    })
}

fn inline_process(
    process: Option<&Map<String, Value>>,
    sandbox_level: SandboxLevel,
) -> Result<ProcessPolicy, PolicyError> {
    let mut policy = default_process(sandbox_level);
    let Some(process) = process else {
        return Ok(policy);
    };
    validate_keys(
        process,
        "process",
        &[
            "allow_child_processes",
            "kill_on_parent_exit",
            "max_processes",
            "interactive",
        ],
    )?;

    if let Some(allow_child_processes) =
        optional_bool_for(Some(process), "process", "allow_child_processes")?
    {
        if !allow_child_processes {
            return Err(PolicyError::invalid(
                "process.allow_child_processes=false is not supported in this build",
            ));
        }
        policy.allow_child_processes = allow_child_processes;
    }
    if let Some(kill_on_parent_exit) =
        optional_bool_for(Some(process), "process", "kill_on_parent_exit")?
    {
        if sandbox_level == SandboxLevel::DangerFullAccess && kill_on_parent_exit {
            return Err(PolicyError::invalid(
                "process.kill_on_parent_exit requires a sandbox backend",
            ));
        }
        if sandbox_level != SandboxLevel::DangerFullAccess && !kill_on_parent_exit {
            return Err(PolicyError::invalid(
                "sandboxed process.kill_on_parent_exit must be true",
            ));
        }
        policy.kill_on_parent_exit = kill_on_parent_exit;
    }
    if process.contains_key("max_processes") {
        return Err(PolicyError::invalid(
            "process.max_processes is not supported in this build",
        ));
    }
    if let Some(interactive) = optional_bool_for(Some(process), "process", "interactive")? {
        if interactive {
            return Err(PolicyError::invalid(
                "process.interactive is not supported in this build",
            ));
        }
        policy.interactive = interactive;
    }

    Ok(policy)
}

fn inline_approval(approval: Option<&Map<String, Value>>) -> Result<ApprovalPolicy, PolicyError> {
    let mut policy = default_approval();
    let Some(approval) = approval else {
        return Ok(policy);
    };
    validate_keys(
        approval,
        "approval",
        &["on_violation", "on_network_route_missing", "on_broad_write"],
    )?;

    if let Some(action) = optional_string(approval, "on_violation")? {
        policy.on_violation = approval_action("approval.on_violation", action)?;
    }
    if let Some(action) = optional_string(approval, "on_network_route_missing")? {
        policy.on_network_route_missing =
            approval_action("approval.on_network_route_missing", action)?;
    }
    if let Some(action) = optional_string(approval, "on_broad_write")? {
        policy.on_broad_write = approval_action("approval.on_broad_write", action)?;
    }

    Ok(policy)
}

fn approval_action(field: &'static str, action: &str) -> Result<String, PolicyError> {
    if action == "deny" || action == "request" {
        Ok(action.to_string())
    } else {
        Err(PolicyError::invalid(format!(
            "{field} must be deny or request, got {action}"
        )))
    }
}

fn environment_set(
    value: Option<&Value>,
    scrub: &[String],
) -> Result<Vec<(String, String)>, PolicyError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| PolicyError::invalid("environment.set must be an object"))?;
    if object.len() > MAX_ENV_ENTRIES {
        return Err(PolicyError::invalid(format!(
            "environment.set must include at most {MAX_ENV_ENTRIES} entries"
        )));
    }

    let mut entries = Vec::with_capacity(object.len());
    for (key, value) in object {
        validate_environment_key(key)?;
        if scrub
            .iter()
            .any(|pattern| matches_environment_scrub_pattern(key, pattern))
        {
            return Err(PolicyError::invalid(format!(
                "environment.set.{key} is denied by environment scrub"
            )));
        }
        let value = value.as_str().ok_or_else(|| {
            PolicyError::invalid(format!("environment.set.{key} must be a string"))
        })?;
        if value.len() > MAX_ENV_VALUE_BYTES {
            return Err(PolicyError::invalid(format!(
                "environment.set.{key} must be at most {MAX_ENV_VALUE_BYTES} bytes"
            )));
        }
        entries.push((key.clone(), value.to_string()));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

fn default_network_mode(_sandbox_level: SandboxLevel) -> NetworkMode {
    NetworkMode::Unmanaged
}

fn default_network(mode: NetworkMode) -> NetworkPolicy {
    NetworkPolicy {
        mode,
        routes: Vec::new(),
        direct_allow_hosts: Vec::new(),
    }
}

fn default_environment(network: NetworkMode) -> EnvironmentPolicy {
    EnvironmentPolicy {
        inherit: "minimal".to_string(),
        scrub: vec![
            "*_TOKEN".to_string(),
            "*_KEY".to_string(),
            "*_SECRET".to_string(),
            "*_PASSWORD".to_string(),
            "*_AUTHORIZATION".to_string(),
            "*_COOKIE".to_string(),
            "AWS_*".to_string(),
            "OPENAI_API_KEY".to_string(),
            "ANTHROPIC_API_KEY".to_string(),
            "AUTHORIZATION".to_string(),
            "COOKIE".to_string(),
            "PASSWORD".to_string(),
            "PYTHONPATH".to_string(),
        ],
        set: Vec::new(),
        proxy: network == NetworkMode::Proxy,
    }
}

fn default_resources() -> ResourcePolicy {
    ResourcePolicy {
        timeout_ms: None,
        memory_bytes: None,
        cpu_percent: None,
        max_output_bytes: None,
    }
}

fn default_process(sandbox_level: SandboxLevel) -> ProcessPolicy {
    ProcessPolicy {
        allow_child_processes: true,
        kill_on_parent_exit: sandbox_level != SandboxLevel::DangerFullAccess,
        max_processes: None,
        interactive: false,
    }
}

fn default_approval() -> ApprovalPolicy {
    ApprovalPolicy {
        on_violation: "deny".to_string(),
        on_network_route_missing: "deny".to_string(),
        on_broad_write: "deny".to_string(),
    }
}

fn infer_level(filesystem: Option<&Map<String, Value>>) -> SandboxLevel {
    if filesystem
        .and_then(|object| object.get("write"))
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        return SandboxLevel::ReadOnly;
    }

    SandboxLevel::WorkspaceWrite
}

fn protected_subpaths(cwd: &Path) -> Vec<String> {
    PROTECTED_WORKSPACE_SUBPATHS
        .into_iter()
        .map(|name| path_string(&cwd.join(name)))
        .collect()
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn validate_path_entries(
    entries: &[String],
    field: &'static str,
    reject_broad_write: bool,
) -> Result<(), PolicyError> {
    for entry in entries {
        if entry.is_empty() {
            return Err(PolicyError::invalid(format!(
                "{field} entries must not be empty"
            )));
        }
        if contains_parent_traversal(entry) {
            return Err(PolicyError::invalid(format!(
                "{field} entries must not contain traversal components"
            )));
        }
        if reject_broad_write && is_broad_write_root(entry) {
            return Err(PolicyError::invalid(format!(
                "{field} broad roots require danger-full-access"
            )));
        }
    }
    Ok(())
}

fn validate_environment_patterns(entries: &[String]) -> Result<(), PolicyError> {
    for entry in entries {
        if entry.is_empty() {
            return Err(PolicyError::invalid(
                "environment.scrub entries must not be empty",
            ));
        }
    }
    Ok(())
}

fn validate_non_empty_strings(entries: &[String], field: &'static str) -> Result<(), PolicyError> {
    for entry in entries {
        if entry.is_empty() {
            return Err(PolicyError::invalid(format!(
                "{field} entries must not be empty"
            )));
        }
    }
    Ok(())
}

fn validate_environment_key(key: &str) -> Result<(), PolicyError> {
    if key.is_empty() || key.len() > MAX_ENV_KEY_BYTES {
        return Err(PolicyError::invalid(format!(
            "environment.set.{key} is not a valid environment variable name"
        )));
    }

    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return Err(PolicyError::invalid(
            "environment.set key is not a valid environment variable name",
        ));
    };
    if !(first == '_' || first.is_ascii_alphabetic())
        || chars.any(|item| !(item == '_' || item.is_ascii_alphanumeric()))
    {
        return Err(PolicyError::invalid(format!(
            "environment.set.{key} is not a valid environment variable name"
        )));
    }

    Ok(())
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

fn environment_set_json(entries: &[(String, String)]) -> Value {
    let mut object = Map::new();
    for (key, value) in entries {
        object.insert(key.clone(), json!(value));
    }
    Value::Object(object)
}

fn contains_parent_traversal(entry: &str) -> bool {
    Path::new(entry)
        .components()
        .any(|component| component == Component::ParentDir)
        || entry.split(['/', '\\']).any(|component| component == "..")
}

fn is_broad_write_root(entry: &str) -> bool {
    if entry == "*" {
        return true;
    }

    let normalized = entry.trim_end_matches(['/', '\\']).to_ascii_lowercase();
    matches!(entry, "/" | "\\")
        || matches!(normalized.as_str(), "~" | "$home")
        || normalized.ends_with(':')
}

fn validate_keys(
    object: &Map<String, Value>,
    context: &'static str,
    allowed_keys: &[&'static str],
) -> Result<(), PolicyError> {
    for key in object.keys() {
        if !allowed_keys.contains(&key.as_str()) {
            return Err(PolicyError::invalid(format!(
                "{context}.{key} is not supported by {POLICY_VERSION}"
            )));
        }
    }
    Ok(())
}

fn optional_string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<Option<&'a str>, PolicyError> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| PolicyError::invalid(format!("{field} must be a string")))
}

fn optional_object<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<Option<&'a Map<String, Value>>, PolicyError> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    value
        .as_object()
        .map(Some)
        .ok_or_else(|| PolicyError::invalid(format!("{field} must be an object")))
}

fn optional_bool(
    object: Option<&Map<String, Value>>,
    field: &'static str,
) -> Result<Option<bool>, PolicyError> {
    optional_bool_for(object, "filesystem", field)
}

fn optional_bool_for(
    object: Option<&Map<String, Value>>,
    context: &'static str,
    field: &'static str,
) -> Result<Option<bool>, PolicyError> {
    let Some(value) = object.and_then(|object| object.get(field)) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| PolicyError::invalid(format!("{context}.{field} must be a boolean")))
}

fn optional_u64(
    object: &Map<String, Value>,
    context: &'static str,
    field: &'static str,
) -> Result<Option<u64>, PolicyError> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| PolicyError::invalid(format!("{context}.{field} must be an integer")))
}

fn optional_positive_u64(
    object: &Map<String, Value>,
    context: &'static str,
    field: &'static str,
) -> Result<Option<u64>, PolicyError> {
    let value = optional_u64(object, context, field)?;
    if value == Some(0) {
        return Err(PolicyError::invalid(format!(
            "{context}.{field} must be greater than zero"
        )));
    }
    Ok(value)
}

fn reject_backend_resource_requirement(
    resources: &Map<String, Value>,
    field: &'static str,
) -> Result<(), PolicyError> {
    if resources.contains_key(field) {
        return Err(PolicyError::invalid(format!(
            "resources.{field} requires a sandbox backend"
        )));
    }
    Ok(())
}

fn reject_non_empty_section(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<(), PolicyError> {
    let Some(section) = optional_object(object, field)? else {
        return Ok(());
    };
    if section.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::invalid(format!(
            "{field} requirements are not supported in this build"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn assert_policy_invalid(input: Value, expected_reason: &str) {
        let cwd = PathBuf::from("/workspace");
        let err = normalize_policy(&input, &cwd, None).unwrap_err();

        assert_eq!(err.code, "POLICY_INVALID");
        assert!(
            err.reason.contains(expected_reason),
            "expected reason to contain {expected_reason:?}, got {:?}",
            err.reason
        );
    }

    #[test]
    fn named_profile_materializes_canonical_policy() {
        let cwd = PathBuf::from("/workspace");
        let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();

        assert_eq!(policy.id, "workspace-write");
        assert_eq!(policy.sandbox_level, SandboxLevel::WorkspaceWrite);
        assert_eq!(policy.network.mode, NetworkMode::Unmanaged);
        assert!(policy.filesystem.protect_vcs);
        assert_eq!(
            policy.required_backend_feature_names(),
            vec![
                "filesystem_policy",
                "runtime_roots",
                "runtime_environment",
                "process_isolation",
                "process_cleanup"
            ]
        );
        assert_eq!(
            policy.canonical_json()["runtime"]["root_mode"],
            "per-execution"
        );
        assert_eq!(
            policy.canonical_json()["required_backend_features"],
            json!(policy.required_backend_feature_names())
        );
        assert!(policy.hash().starts_with("sha256:"));
    }

    #[test]
    fn danger_full_access_hash_records_no_runtime_or_backend_requirements() {
        let cwd = PathBuf::from("/workspace");
        let policy = normalize_policy(&json!("danger-full-access"), &cwd, None).unwrap();

        assert_eq!(policy.canonical_json()["runtime"]["root_mode"], "none");
        assert_eq!(
            policy.canonical_json()["required_backend_features"],
            json!([])
        );
    }

    #[test]
    fn network_override_changes_canonical_hash() {
        let cwd = PathBuf::from("/workspace");
        let unmanaged = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
        let disabled =
            normalize_policy(&json!("workspace-write"), &cwd, Some(NetworkMode::Disabled)).unwrap();

        assert_eq!(disabled.network.mode, NetworkMode::Disabled);
        assert_ne!(unmanaged.hash(), disabled.hash());
    }

    #[test]
    fn workspace_path_changes_canonical_hash() {
        let first =
            normalize_policy(&json!("workspace-write"), Path::new("/workspace-a"), None).unwrap();
        let second =
            normalize_policy(&json!("workspace-write"), Path::new("/workspace-b"), None).unwrap();

        assert_ne!(
            first.canonical_json()["filesystem"],
            second.canonical_json()["filesystem"]
        );
        assert_ne!(first.hash(), second.hash());
    }

    #[test]
    fn inline_policy_rejects_unknown_top_level_fields() {
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "filesystem": {},
                "unknown_requirement": true
            }),
            "policy.unknown_requirement",
        );
    }

    #[test]
    fn inline_policy_rejects_unknown_filesystem_fields() {
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "filesystem": {
                    "read": ["/workspace"],
                    "execute": ["/tools"]
                }
            }),
            "filesystem.execute",
        );
    }

    #[test]
    fn inline_policy_materializes_read_only_roots() {
        let cwd = PathBuf::from("/workspace");
        let policy = normalize_policy(
            &json!({
                "version": POLICY_VERSION,
                "filesystem": {
                    "read": ["/workspace"],
                    "read_only": ["/cache"],
                    "write": ["/workspace"]
                },
                "network": {"mode": "disabled"}
            }),
            &cwd,
            None,
        )
        .unwrap();

        assert_eq!(policy.filesystem.read_only, vec!["/cache"]);
        assert_eq!(
            policy.canonical_json()["filesystem"]["read_only"],
            json!(["/cache"])
        );
    }

    #[test]
    fn inline_policy_materializes_environment_controls() {
        let cwd = PathBuf::from("/workspace");
        let policy = normalize_policy(
            &json!({
                "version": POLICY_VERSION,
                "environment": {
                    "inherit": "minimal",
                    "scrub": ["*_SECRET"],
                    "set": {
                        "CI": "1"
                    },
                    "proxy": false
                },
                "network": {"mode": "disabled"}
            }),
            &cwd,
            None,
        )
        .unwrap();

        assert_eq!(policy.environment.inherit, "minimal");
        assert_eq!(policy.environment.scrub, vec!["*_SECRET"]);
        assert_eq!(
            policy.environment.set,
            vec![("CI".to_string(), "1".to_string())]
        );
        assert!(!policy.environment.proxy);
        assert_eq!(policy.canonical_json()["environment"]["set"]["CI"], "1");
        assert_eq!(policy.canonical_json()["environment"]["proxy"], false);
    }

    #[test]
    fn inline_policy_rejects_proxy_network_without_proxy_environment() {
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "network": {"mode": "proxy"},
                "environment": {"proxy": false}
            }),
            "network.proxy requires environment.proxy=true",
        );
    }

    #[test]
    fn inline_policy_materializes_resource_timeout() {
        let cwd = PathBuf::from("/workspace");
        let policy = normalize_policy(
            &json!({
                "version": POLICY_VERSION,
                "resources": {
                    "timeout_ms": 1000,
                    "memory_bytes": 2147483648u64,
                    "cpu_percent": 200,
                    "max_output_bytes": 2048
                }
            }),
            &cwd,
            None,
        )
        .unwrap();

        assert_eq!(policy.resources.timeout_ms, Some(1000));
        assert_eq!(policy.resources.memory_bytes, Some(2147483648));
        assert_eq!(policy.resources.cpu_percent, Some(200));
        assert_eq!(policy.resources.max_output_bytes, Some(2048));
        assert_eq!(policy.canonical_json()["resources"]["timeout_ms"], 1000);
        assert_eq!(
            policy.canonical_json()["resources"]["memory_bytes"],
            2147483648u64
        );
        assert_eq!(policy.canonical_json()["resources"]["cpu_percent"], 200);
        assert_eq!(
            policy.canonical_json()["resources"]["max_output_bytes"],
            2048
        );
    }

    #[test]
    fn inline_policy_materializes_network_routes() {
        let cwd = PathBuf::from("/workspace");
        let policy = normalize_policy(
            &json!({
                "version": POLICY_VERSION,
                "network": {
                    "mode": "proxy",
                    "routes": ["github-api"],
                    "direct_allow_hosts": []
                }
            }),
            &cwd,
            None,
        )
        .unwrap();

        assert_eq!(policy.network.mode, NetworkMode::Proxy);
        assert_eq!(policy.network.routes, vec!["github-api"]);
        assert!(policy.network.direct_allow_hosts.is_empty());
        assert_eq!(
            policy.canonical_json()["network"]["routes"],
            json!(["github-api"])
        );
    }

    #[test]
    fn inline_policy_materializes_approval_actions() {
        let cwd = PathBuf::from("/workspace");
        let policy = normalize_policy(
            &json!({
                "version": POLICY_VERSION,
                "approval": {
                    "on_violation": "deny",
                    "on_network_route_missing": "request",
                    "on_broad_write": "request"
                }
            }),
            &cwd,
            None,
        )
        .unwrap();

        assert_eq!(policy.approval.on_violation, "deny");
        assert_eq!(
            policy.canonical_json()["approval"]["on_network_route_missing"],
            "request"
        );
    }

    #[test]
    fn inline_policy_materializes_sandbox_process_controls() {
        let cwd = PathBuf::from("/workspace");
        let policy = normalize_policy(
            &json!({
                "version": POLICY_VERSION,
                "sandbox_level": "read-only",
                "process": {
                    "allow_child_processes": true,
                    "kill_on_parent_exit": true,
                    "interactive": false
                }
            }),
            &cwd,
            None,
        )
        .unwrap();

        assert!(policy.process.allow_child_processes);
        assert!(policy.process.kill_on_parent_exit);
        assert_eq!(policy.process.max_processes, None);
        assert!(!policy.process.interactive);
        assert_eq!(
            policy.canonical_json()["process"]["kill_on_parent_exit"],
            true
        );
    }

    #[test]
    fn network_override_does_not_skip_inline_network_validation() {
        let cwd = PathBuf::from("/workspace");
        let err = normalize_policy(
            &json!({
                "version": POLICY_VERSION,
                "network": {
                    "mode": "proxy",
                    "unknown": true
                }
            }),
            &cwd,
            Some(NetworkMode::Disabled),
        )
        .unwrap_err();

        assert_eq!(err.code, "POLICY_INVALID");
        assert!(err.reason.contains("network.unknown"));
    }

    #[test]
    fn inline_policy_rejects_non_empty_unsupported_sections() {
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "environment": {
                    "scrub": ["*_SECRET"],
                    "set": {
                        "RUNSEAL_SECRET": "1"
                    }
                }
            }),
            "environment.set.RUNSEAL_SECRET is denied by environment scrub",
        );
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "environment": {
                    "set": []
                }
            }),
            "environment.set must be an object",
        );
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "sandbox_level": "danger-full-access",
                "resources": {
                    "memory_bytes": 1000
                }
            }),
            "resources.memory_bytes requires a sandbox backend",
        );
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "resources": {
                    "cpu_percent": 0
                }
            }),
            "resources.cpu_percent must be greater than zero",
        );
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "network": {
                    "mode": "disabled",
                    "routes": ["github-api"]
                }
            }),
            "network.routes require proxy mode",
        );
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "network": {
                    "mode": "proxy",
                    "direct_allow_hosts": ["example.com"]
                }
            }),
            "network.direct_allow_hosts is not supported",
        );
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "approval": {
                    "on_broad_write": "allow"
                }
            }),
            "approval.on_broad_write must be deny or request",
        );
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "sandbox_level": "danger-full-access",
                "process": {
                    "kill_on_parent_exit": true
                }
            }),
            "process.kill_on_parent_exit requires a sandbox backend",
        );
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "process": {
                    "allow_child_processes": false
                }
            }),
            "process.allow_child_processes=false is not supported",
        );
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "process": {
                    "kill_on_parent_exit": false
                }
            }),
            "sandboxed process.kill_on_parent_exit must be true",
        );
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "process": {
                    "max_processes": 2
                }
            }),
            "process.max_processes is not supported",
        );
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "process": {
                    "interactive": true
                }
            }),
            "process.interactive is not supported",
        );
    }

    #[test]
    fn invalid_sandbox_level_is_not_inferred() {
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "sandbox_level": "workspace-proxy",
                "filesystem": {
                    "write": ["/workspace"]
                }
            }),
            "sandbox_level must be",
        );
    }

    #[test]
    fn legacy_network_alias_is_rejected() {
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "network": {
                    "mode": "none"
                }
            }),
            "network.mode must be unmanaged, disabled, or proxy",
        );
    }

    #[test]
    fn filesystem_paths_reject_parent_traversal() {
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "filesystem": {
                    "read": ["../secret"]
                }
            }),
            "filesystem.read entries must not contain traversal components",
        );
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "filesystem": {
                    "write": ["workspace/../outside"]
                }
            }),
            "filesystem.write entries must not contain traversal components",
        );
    }

    #[test]
    fn sandboxed_filesystem_write_rejects_broad_roots() {
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "sandbox_level": "workspace-write",
                "filesystem": {
                    "write": ["*"]
                }
            }),
            "filesystem.write broad roots require danger-full-access",
        );
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "sandbox_level": "workspace-write",
                "filesystem": {
                    "write": ["/"]
                }
            }),
            "filesystem.write broad roots require danger-full-access",
        );
    }

    #[test]
    fn broad_write_request_materializes_approval_requirement() {
        let cwd = PathBuf::from("/workspace");
        let policy = normalize_policy(
            &json!({
                "version": POLICY_VERSION,
                "sandbox_level": "workspace-write",
                "filesystem": {
                    "write": ["*"]
                },
                "approval": {
                    "on_broad_write": "request"
                }
            }),
            &cwd,
            None,
        )
        .unwrap();

        assert!(policy.requires_broad_write_approval());
        assert_eq!(policy.canonical_json()["filesystem"]["write"], json!(["*"]));
        assert_eq!(
            policy.canonical_json()["approval"]["on_broad_write"],
            "request"
        );
    }

    #[test]
    fn danger_full_access_allows_explicit_wildcard_filesystem() {
        let cwd = PathBuf::from("/workspace");
        let policy = normalize_policy(
            &json!({
                "version": POLICY_VERSION,
                "sandbox_level": "danger-full-access",
                "filesystem": {
                    "read": ["*"],
                    "write": ["*"]
                }
            }),
            &cwd,
            None,
        )
        .unwrap();

        assert!(policy.allows_local_execution());
        assert_eq!(policy.filesystem.write, vec!["*"]);
    }
}
