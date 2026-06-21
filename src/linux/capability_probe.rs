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
            "capability": "process_isolation",
            "mechanism": "user_namespaces",
            "status": "unsupported",
            "diagnostic_only": true
        },
        {
            "capability": "process_isolation",
            "mechanism": "bubblewrap",
            "status": "unsupported",
            "diagnostic_only": true
        }
    ])
}
