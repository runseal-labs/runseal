use crate::policy::{SandboxLevel, SandboxPolicy};
use serde_json::{json, Value};

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

pub trait SandboxBackend {
    fn name(&self) -> &'static str;
    fn platform(&self) -> &'static str;
    fn supports_policy(&self, policy: &SandboxPolicy) -> CapabilityStatus;
    fn capabilities_json(&self) -> Value;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LocalBackend;

impl SandboxBackend for LocalBackend {
    fn name(&self) -> &'static str {
        "runseal-local"
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

    fn capabilities_json(&self) -> Value {
        json!({
            "backend": self.name(),
            "platform": self.platform(),
            "features": {
                "local_execution": true,
                "filesystem_policy": false,
                "network_disabled": false,
                "network_proxy": false,
                "resource_limits": false,
                "audit_jsonl": false,
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

pub fn active_backend() -> LocalBackend {
    LocalBackend
}

fn host_platform() -> &'static str {
    match std::env::consts::OS {
        "windows" => "windows",
        "macos" => "macos",
        "linux" => "linux",
        _ => "unknown",
    }
}
