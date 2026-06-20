use super::capability::CapabilityStatus;
use super::core::SandboxBackend;
use super::plan::PlatformSandboxPlan;
use crate::policy::SandboxPolicy;
use serde_json::{Value, json};
use std::io;

#[derive(Debug)]
pub(super) struct BackendUnavailableError {
    pub(super) reason: String,
}

impl std::fmt::Display for BackendUnavailableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for BackendUnavailableError {}

#[cfg(windows)]
pub(super) const POLICY_TRANSITION_BUSY_REASON: &str =
    "policy transition busy: active sandboxed executions use a different policy epoch";

#[cfg(windows)]
#[derive(Debug)]
pub(super) struct PolicyTransitionBusyError {
    pub(super) reason: &'static str,
}

#[cfg(windows)]
impl std::fmt::Display for PolicyTransitionBusyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason)
    }
}

#[cfg(windows)]
impl std::error::Error for PolicyTransitionBusyError {}

pub(crate) fn backend_unavailable_reason(err: &io::Error) -> Option<&str> {
    err.get_ref()?
        .downcast_ref::<BackendUnavailableError>()
        .map(|err| err.reason.as_str())
}

pub(crate) fn policy_transition_busy_reason(err: &io::Error) -> Option<&str> {
    #[cfg(windows)]
    {
        err.get_ref()?
            .downcast_ref::<PolicyTransitionBusyError>()
            .map(|err| err.reason)
    }

    #[cfg(not(windows))]
    {
        let _ = err;
        None
    }
}

#[cfg(all(test, windows))]
pub(crate) fn policy_transition_busy_error_for_test() -> io::Error {
    io::Error::other(PolicyTransitionBusyError {
        reason: POLICY_TRANSITION_BUSY_REASON,
    })
}

#[cfg(windows)]
pub(super) fn public_windows_setup_unavailable_reason(_code: &str) -> String {
    "windows sandbox setup unavailable; run `runseal setup windows-sandbox` to install or repair"
        .to_string()
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
    pub(super) fn unsupported(backend: &dyn SandboxBackend, policy: &SandboxPolicy) -> Self {
        Self::unsupported_with_plan(backend, policy, None)
    }

    pub(super) fn unsupported_with_plan(
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
