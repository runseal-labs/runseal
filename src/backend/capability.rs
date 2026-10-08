use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityStatus {
    Supported,
    Experimental,
    Unsupported,
    Unavailable,
    RequiresSetup,
}

impl CapabilityStatus {
    pub const ALL: [Self; 5] = [
        Self::Supported,
        Self::Experimental,
        Self::Unsupported,
        Self::Unavailable,
        Self::RequiresSetup,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Experimental => "experimental",
            Self::Unsupported => "unsupported",
            Self::Unavailable => "unavailable",
            Self::RequiresSetup => "requires_setup",
        }
    }
}

pub const EXECUTION_CAPABILITY_NAMES: [&str; 13] = [
    "streaming_output",
    "active_execution_query",
    "execution_cancel",
    "stdin_bytes",
    "stdin_file",
    "stdin_stream",
    "transparent_exec",
    "pty",
    "pty_resize",
    "pty_interrupt",
    "control_channel",
    "same_policy_concurrency",
    "mixed_policy_concurrency",
];

/// Per-execution capability statuses ordered like EXECUTION_CAPABILITY_NAMES.
pub type ExecutionCapabilityStatuses = [CapabilityStatus; EXECUTION_CAPABILITY_NAMES.len()];

/// Engine-level baseline: the shared lifecycle and byte I/O work, but no
/// interactive terminal or explicit control channel.
pub fn baseline_execution_capabilities() -> ExecutionCapabilityStatuses {
    use CapabilityStatus::{Supported, Unsupported};
    [
        Supported,
        Supported,
        Supported,
        Supported,
        Supported,
        Supported,
        Supported,
        Unsupported,
        Unsupported,
        Unsupported,
        Unsupported,
        Supported,
        Unsupported,
    ]
}

/// Baseline plus real terminal and control-channel support.
pub fn interactive_execution_capabilities() -> ExecutionCapabilityStatuses {
    let mut statuses = baseline_execution_capabilities();
    statuses[7] = CapabilityStatus::Supported;
    statuses[8] = CapabilityStatus::Supported;
    statuses[9] = CapabilityStatus::Supported;
    statuses[10] = CapabilityStatus::Supported;
    statuses
}

fn execution_capabilities_object(statuses: &ExecutionCapabilityStatuses) -> Value {
    let mut map = serde_json::Map::new();
    for (name, status) in EXECUTION_CAPABILITY_NAMES.iter().zip(statuses.iter()) {
        map.insert((*name).to_string(), json!(status.as_str()));
    }
    Value::Object(map)
}

fn strongest(statuses: &[&'static str]) -> &'static str {
    if statuses.contains(&CapabilityStatus::Unsupported.as_str()) {
        CapabilityStatus::Unsupported.as_str()
    } else if statuses.contains(&CapabilityStatus::Unavailable.as_str()) {
        CapabilityStatus::Unavailable.as_str()
    } else if statuses.contains(&CapabilityStatus::RequiresSetup.as_str()) {
        CapabilityStatus::RequiresSetup.as_str()
    } else if statuses.contains(&CapabilityStatus::Experimental.as_str()) {
        CapabilityStatus::Experimental.as_str()
    } else {
        CapabilityStatus::Supported.as_str()
    }
}

fn io_mode_supported(statuses: &ExecutionCapabilityStatuses, io_mode: &str) -> bool {
    match io_mode {
        "pty" => matches!(
            statuses[7],
            CapabilityStatus::Supported | CapabilityStatus::Experimental
        ),
        _ => true,
    }
}

fn profile_feature_statuses(
    statuses: &ExecutionCapabilityStatuses,
    io_mode: &str,
    requestable: bool,
) -> Value {
    let mut map = serde_json::Map::new();
    for (index, name) in EXECUTION_CAPABILITY_NAMES.iter().enumerate() {
        let applicable = match io_mode {
            "pty" => !matches!(*name, "stdin_bytes" | "stdin_file" | "control_channel"),
            _ => !matches!(*name, "pty" | "pty_resize" | "pty_interrupt"),
        };
        let status = if requestable && applicable {
            statuses[index]
        } else {
            CapabilityStatus::Unsupported
        };
        map.insert((*name).to_string(), json!(status.as_str()));
    }
    Value::Object(map)
}

fn execution_profiles_json(
    statuses: &ExecutionCapabilityStatuses,
    sandbox_levels: &[(&'static str, &'static str)],
    network_modes: &[(&'static str, &'static str)],
) -> Value {
    let mut profiles = Vec::new();
    for (sandbox_level, sandbox_status) in sandbox_levels {
        for (network_mode, network_status) in network_modes {
            for io_mode in ["pipe", "pty"] {
                let base = strongest(&[*sandbox_status, *network_status]);
                let io_supported = io_mode_supported(statuses, io_mode);
                let requestable = base != CapabilityStatus::Unsupported.as_str() && io_supported;
                let status = if requestable {
                    base
                } else {
                    CapabilityStatus::Unsupported.as_str()
                };
                profiles.push(json!({
                    "sandbox_level": sandbox_level,
                    "network_mode": network_mode,
                    "io_mode": io_mode,
                    "status": status,
                    "feature_statuses": profile_feature_statuses(statuses, io_mode, requestable),
                }));
            }
        }
    }
    Value::Array(profiles)
}

/// Platform execution boundary for RunSeal sandbox policies.
///
pub(super) fn capabilities_json_for(backend: &dyn SandboxBackend, notes: &[&'static str]) -> Value {
    let supported_features = backend.supported_features();
    let read_only = capability_status(
        supported_features,
        &[
            BackendFeature::FilesystemPolicy,
            BackendFeature::RuntimeRoots,
            BackendFeature::RuntimeEnvironment,
            BackendFeature::ProcessIsolation,
            BackendFeature::ProcessCleanup,
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
    let execution_statuses = backend.execution_capabilities();
    let sandbox_level_rows = [
        ("read-only", read_only),
        ("workspace-write", workspace_write),
        ("workspace-contained", read_only),
        ("danger-full-access", CapabilityStatus::Supported.as_str()),
    ];
    let network_mode_rows = [
        ("unmanaged", CapabilityStatus::Supported.as_str()),
        ("disabled", network_disabled),
        ("proxy", network_proxy),
    ];
    json!({
        "backend": backend.name(),
        "backend_status": backend.status(),
        "platform": backend.platform(),
        "capability_statuses": CapabilityStatus::ALL.map(CapabilityStatus::as_str),
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
            "policy_epoch": supported_features.contains(&BackendFeature::PolicyEpoch),
            "setup_readiness": true,
            "stdin_bytes": true,
            "stdin_file": true,
            "resource_limits": supported_features.contains(&BackendFeature::ResourceLimits),
            "audit_jsonl": true,
            "otel_export": false,
        },
        "feature_statuses": {
            "local_execution": CapabilityStatus::Supported.as_str(),
            "filesystem_policy": feature_status(supported_features, BackendFeature::FilesystemPolicy),
            "runtime_roots": feature_status(supported_features, BackendFeature::RuntimeRoots),
            "runtime_environment": feature_status(supported_features, BackendFeature::RuntimeEnvironment),
            "process_isolation": feature_status(supported_features, BackendFeature::ProcessIsolation),
            "process_cleanup": feature_status(supported_features, BackendFeature::ProcessCleanup),
            "direct_network_deny": feature_status(supported_features, BackendFeature::DirectNetworkDeny),
            "network_disabled": feature_status(supported_features, BackendFeature::NetworkDisabled),
            "network_proxy": feature_status(supported_features, BackendFeature::NetworkProxy),
            "managed_proxy": feature_status(supported_features, BackendFeature::ManagedProxy),
            "policy_epoch": feature_status(supported_features, BackendFeature::PolicyEpoch),
            "setup_readiness": CapabilityStatus::Supported.as_str(),
            "stdin_bytes": CapabilityStatus::Supported.as_str(),
            "stdin_file": CapabilityStatus::Supported.as_str(),
            "resource_limits": feature_status(supported_features, BackendFeature::ResourceLimits),
            "audit_jsonl": CapabilityStatus::Supported.as_str(),
            "otel_export": CapabilityStatus::Unsupported.as_str(),
        },
        "execution_capabilities": execution_capabilities_object(&execution_statuses),
        "execution_profiles": execution_profiles_json(
            &execution_statuses,
            &sandbox_level_rows,
            &network_mode_rows,
        ),
        "sandbox_levels": {
            "read-only": read_only,
            "workspace-contained": read_only,
            "workspace-write": workspace_write,
            "danger-full-access": CapabilityStatus::Supported.as_str(),
        },
        "network_modes": {
            "unmanaged": CapabilityStatus::Supported.as_str(),
            "disabled": network_disabled,
            "proxy": network_proxy,
        },
        "notes": notes,
    })
}

fn feature_status(supported_features: &[BackendFeature], feature: BackendFeature) -> &'static str {
    if supported_features.contains(&feature) {
        CapabilityStatus::Supported.as_str()
    } else {
        CapabilityStatus::Unsupported.as_str()
    }
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

pub(super) fn missing_backend_features(
    policy: &SandboxPolicy,
    supported_features: &[BackendFeature],
) -> Vec<BackendFeature> {
    policy
        .required_backend_features()
        .into_iter()
        .filter(|feature| !supported_features.contains(feature))
        .collect()
}
