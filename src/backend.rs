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
    fn status(&self) -> &'static str;
    fn platform(&self) -> &'static str;
    fn supports_policy(&self, policy: &SandboxPolicy) -> CapabilityStatus;
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

    fn capabilities_json(&self) -> Value {
        match self {
            Self::Local(backend) => backend.capabilities_json(),
            Self::WindowsReference(backend) => backend.capabilities_json(),
        }
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
