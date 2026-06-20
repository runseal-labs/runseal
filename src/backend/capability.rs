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
            "setup_readiness": supported_features.contains(&BackendFeature::SetupReadiness),
            "stdin_bytes": supported_features.contains(&BackendFeature::StdinBytes),
            "stdin_file": supported_features.contains(&BackendFeature::StdinFile),
            "resource_limits": supported_features.contains(&BackendFeature::ResourceLimits),
            "audit_jsonl": supported_features.contains(&BackendFeature::AuditJsonl),
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
