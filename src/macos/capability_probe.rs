use serde_json::{Value, json};

pub(crate) fn capability_probes() -> Value {
    json!([
        {
            "capability": "filesystem_policy",
            "mechanism": "seatbelt",
            "status": "unsupported",
            "diagnostic_only": true
        }
    ])
}
