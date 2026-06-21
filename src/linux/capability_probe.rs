use serde_json::{Value, json};

pub(crate) fn capability_probes() -> Value {
    json!([
        {
            "capability": "filesystem_policy",
            "mechanism": "landlock",
            "status": "unsupported",
            "diagnostic_only": true
        },
        {
            "capability": "filesystem_policy",
            "mechanism": "landlock_abi_version",
            "status": "unsupported",
            "diagnostic_only": true
        },
        {
            "capability": "process_isolation",
            "mechanism": "user_namespaces",
            "status": "unsupported",
            "diagnostic_only": true
        },
        {
            "capability": "process_isolation",
            "mechanism": "user_namespace_quota",
            "status": "unsupported",
            "diagnostic_only": true
        },
        {
            "capability": "process_isolation",
            "mechanism": "mount_namespaces",
            "status": "unsupported",
            "diagnostic_only": true
        },
        {
            "capability": "process_isolation",
            "mechanism": "pid_namespaces",
            "status": "unsupported",
            "diagnostic_only": true
        },
        {
            "capability": "network_disabled",
            "mechanism": "network_namespaces",
            "status": "unsupported",
            "diagnostic_only": true
        },
        {
            "capability": "process_isolation",
            "mechanism": "seccomp",
            "status": "unsupported",
            "diagnostic_only": true
        },
        {
            "capability": "process_isolation",
            "mechanism": "bubblewrap",
            "status": "unsupported",
            "diagnostic_only": true
        },
        {
            "capability": "process_isolation",
            "mechanism": "unprivileged_user_namespaces",
            "status": "unsupported",
            "diagnostic_only": true
        }
    ])
}
