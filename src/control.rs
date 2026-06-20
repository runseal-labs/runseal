use crate::PROTOCOL_VERSION;
use crate::backend::{SandboxBackend, active_backend};
use crate::execution::current_dir;
use crate::policy::{POLICY_VERSION, SandboxPolicy};
use crate::setup::windows_sandbox_setup_status_for_cwd;
use serde_json::{Value, json};
use std::path::Path;

pub(crate) fn version_payload() -> Value {
    json!({
        "runseal_version": env!("CARGO_PKG_VERSION"),
        "protocol_version": PROTOCOL_VERSION,
        "policy_versions": [POLICY_VERSION],
    })
}

pub(crate) fn capabilities_payload() -> Value {
    let mut payload = active_backend().capabilities_json();
    if let (Some(payload), Ok(setup_status)) = (
        payload.as_object_mut(),
        windows_sandbox_setup_status_for_cwd(&current_dir()),
    ) {
        payload.insert("setup_status".to_string(), setup_status);
    }
    payload
}

pub(crate) fn explain_policy_json(policy: &SandboxPolicy, cwd: &Path) -> Value {
    let backend = active_backend();
    let missing_features = backend.missing_feature_names(policy);
    let mut result = policy.explain_json();
    if let Some(result) = result.as_object_mut() {
        result.insert(
            "support".to_string(),
            json!(if missing_features.is_empty() {
                "supported"
            } else {
                "unsupported"
            }),
        );
        result.insert("missing_features".to_string(), json!(missing_features));
        if let Ok(setup_status) = windows_sandbox_setup_status_for_cwd(cwd) {
            result.insert("setup_status".to_string(), setup_status);
        }
    }
    result
}
