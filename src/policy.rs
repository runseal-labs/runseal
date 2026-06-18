use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::path::{Component, Path};

pub const POLICY_VERSION: &str = "runseal.policy/v1";

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
    Disabled,
    Proxy,
}

impl NetworkMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Proxy => "proxy",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "disabled" => Some(Self::Disabled),
            "proxy" => Some(Self::Proxy),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendFeature {
    FilesystemPolicy,
    NetworkDisabled,
    NetworkProxy,
}

impl BackendFeature {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FilesystemPolicy => "filesystem_policy",
            Self::NetworkDisabled => "network_disabled",
            Self::NetworkProxy => "network_proxy",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemPolicy {
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub deny: Vec<String>,
    pub protect_vcs: bool,
    pub unrestricted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkPolicy {
    pub mode: NetworkMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentPolicy {
    pub inherit: String,
    pub scrub: Vec<String>,
    pub proxy: bool,
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
                "write": self.filesystem.write.clone(),
                "deny": self.filesystem.deny.clone(),
                "protect_vcs": self.filesystem.protect_vcs,
                "unrestricted": self.filesystem.unrestricted,
            },
            "network": {
                "mode": self.network.mode.as_str(),
            },
            "environment": {
                "inherit": self.environment.inherit.clone(),
                "scrub": self.environment.scrub.clone(),
                "proxy": self.environment.proxy,
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
                "write": self.filesystem.write.clone(),
                "deny": self.filesystem.deny.clone(),
                "protect_vcs": self.filesystem.protect_vcs,
                "unrestricted": self.filesystem.unrestricted,
            },
            "network": {
                "mode": self.network.mode.as_str(),
            },
            "environment": {
                "inherit": self.environment.inherit.clone(),
                "scrub": self.environment.scrub.clone(),
                "proxy": self.environment.proxy,
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

    pub fn required_backend_features(&self) -> Vec<BackendFeature> {
        if self.allows_local_execution() {
            return Vec::new();
        }

        let mut features = vec![BackendFeature::FilesystemPolicy];
        features.push(match self.network.mode {
            NetworkMode::Disabled => BackendFeature::NetworkDisabled,
            NetworkMode::Proxy => BackendFeature::NetworkProxy,
        });
        features
    }

    pub fn required_backend_feature_names(&self) -> Vec<&'static str> {
        self.required_backend_features()
            .into_iter()
            .map(BackendFeature::as_str)
            .collect()
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
    reject_non_empty_section(object, "environment")?;
    reject_non_empty_section(object, "process")?;
    reject_non_empty_section(object, "resources")?;
    reject_non_empty_section(object, "audit")?;
    reject_non_empty_section(object, "approval")?;
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

    Ok(SandboxPolicy {
        id,
        sandbox_level,
        filesystem: inline_filesystem(filesystem, cwd, sandbox_level)?,
        network: NetworkPolicy { mode: network },
        environment: default_environment(network),
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
        network: NetworkPolicy { mode: network },
        environment: default_environment(network),
        source: PolicySource::Named,
    })
}

fn profile_filesystem(cwd: &Path, sandbox_level: SandboxLevel) -> FilesystemPolicy {
    match sandbox_level {
        SandboxLevel::DangerFullAccess => FilesystemPolicy {
            read: vec!["*".to_string()],
            write: vec!["*".to_string()],
            deny: Vec::new(),
            protect_vcs: false,
            unrestricted: true,
        },
        SandboxLevel::ReadOnly => FilesystemPolicy {
            read: vec![path_string(cwd)],
            write: Vec::new(),
            deny: Vec::new(),
            protect_vcs: false,
            unrestricted: false,
        },
        SandboxLevel::WorkspaceContained | SandboxLevel::WorkspaceWrite => FilesystemPolicy {
            read: vec![path_string(cwd)],
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
) -> Result<FilesystemPolicy, PolicyError> {
    if let Some(filesystem) = filesystem {
        validate_keys(
            filesystem,
            "filesystem",
            &["read", "write", "deny", "protect_vcs"],
        )?;
    }
    let read = string_array(filesystem, "read")?.unwrap_or_else(|| match sandbox_level {
        SandboxLevel::DangerFullAccess => vec!["*".to_string()],
        _ => vec![path_string(cwd)],
    });
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
    validate_path_entries(
        &write,
        "filesystem.write",
        sandbox_level != SandboxLevel::DangerFullAccess,
    )?;
    validate_path_entries(&deny, "filesystem.deny", false)?;

    Ok(FilesystemPolicy {
        read,
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
    let Some(value) = object.and_then(|object| object.get(field)) else {
        return Ok(None);
    };
    let items = value
        .as_array()
        .ok_or_else(|| PolicyError::invalid(format!("filesystem.{field} must be an array")))?;

    items
        .iter()
        .map(|item| {
            item.as_str().map(str::to_string).ok_or_else(|| {
                PolicyError::invalid(format!("filesystem.{field} entries must be strings"))
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
        if let Err(err) = validate_keys(object, "network", &["mode"]) {
            return Some(Err(err));
        }
        match optional_string(object, "mode") {
            Ok(Some(mode)) => mode,
            Ok(None) => "disabled",
            Err(err) => return Some(Err(err)),
        }
    };

    Some(NetworkMode::from_str(mode).ok_or_else(|| {
        PolicyError::invalid(format!(
            "network.mode must be disabled or proxy, got {mode}"
        ))
    }))
}

fn default_network_mode(sandbox_level: SandboxLevel) -> NetworkMode {
    match sandbox_level {
        SandboxLevel::WorkspaceWrite => NetworkMode::Proxy,
        _ => NetworkMode::Disabled,
    }
}

fn default_environment(network: NetworkMode) -> EnvironmentPolicy {
    EnvironmentPolicy {
        inherit: "minimal".to_string(),
        scrub: vec![
            "*_TOKEN".to_string(),
            "*_KEY".to_string(),
            "AWS_*".to_string(),
            "OPENAI_API_KEY".to_string(),
            "ANTHROPIC_API_KEY".to_string(),
        ],
        proxy: network == NetworkMode::Proxy,
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
    [".git", ".agents", ".codex"]
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
    let Some(value) = object.and_then(|object| object.get(field)) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| PolicyError::invalid(format!("filesystem.{field} must be a boolean")))
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
        assert_eq!(policy.network.mode, NetworkMode::Proxy);
        assert!(policy.filesystem.protect_vcs);
        assert_eq!(
            policy.required_backend_feature_names(),
            vec!["filesystem_policy", "network_proxy"]
        );
        assert!(policy.hash().starts_with("sha256:"));
    }

    #[test]
    fn network_override_changes_canonical_hash() {
        let cwd = PathBuf::from("/workspace");
        let proxy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
        let disabled =
            normalize_policy(&json!("workspace-write"), &cwd, Some(NetworkMode::Disabled)).unwrap();

        assert_eq!(disabled.network.mode, NetworkMode::Disabled);
        assert_ne!(proxy.hash(), disabled.hash());
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
                    "read_only": ["/cache"]
                }
            }),
            "filesystem.read_only",
        );
    }

    #[test]
    fn inline_policy_rejects_unsupported_network_routes() {
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "network": {
                    "mode": "proxy",
                    "routes": ["github-api"]
                }
            }),
            "network.routes",
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
                    "routes": ["github-api"]
                }
            }),
            &cwd,
            Some(NetworkMode::Disabled),
        )
        .unwrap_err();

        assert_eq!(err.code, "POLICY_INVALID");
        assert!(err.reason.contains("network.routes"));
    }

    #[test]
    fn inline_policy_rejects_non_empty_unsupported_sections() {
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "environment": {
                    "set": {
                        "CI": "1"
                    }
                }
            }),
            "environment requirements are not supported",
        );
        assert_policy_invalid(
            json!({
                "version": POLICY_VERSION,
                "resources": {
                    "timeout_ms": 1000
                }
            }),
            "resources requirements are not supported",
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
            "network.mode must be disabled or proxy",
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
