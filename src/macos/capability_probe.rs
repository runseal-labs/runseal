use serde_json::{Value, json};

pub(crate) fn capability_probes() -> Value {
    json!([
        {
            "capability": "filesystem_policy",
            "mechanism": "sandbox_exec",
            "status": "unsupported",
            "diagnostic_only": true
        },
        {
            "capability": "filesystem_policy",
            "mechanism": "sandbox_exec_executable",
            "status": "unsupported",
            "diagnostic_only": true
        },
        {
            "capability": "platform_version",
            "mechanism": "macos_version",
            "status": "unsupported",
            "diagnostic_only": true
        },
        {
            "capability": "filesystem_policy",
            "mechanism": "temporary_profile",
            "status": "unsupported",
            "diagnostic_only": true
        },
        {
            "capability": "filesystem_policy",
            "mechanism": "canonical_paths",
            "status": "unsupported",
            "diagnostic_only": true
        },
        {
            "capability": "filesystem_policy",
            "mechanism": "symlink_path_model",
            "status": "unsupported",
            "diagnostic_only": true
        }
    ])
}
