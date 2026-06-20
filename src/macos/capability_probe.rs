use serde_json::{Value, json};
use std::path::Path;

pub(crate) fn payload() -> Value {
    json!({
        "sandboxed_execution": "unsupported",
        "filesystem_enforcement": "unsupported",
        "network_enforcement": "unsupported",
        "runtime": {
            "sandbox_exec": file_status("/usr/bin/sandbox-exec"),
        },
    })
}

fn file_status(path: &str) -> &'static str {
    if Path::new(path).exists() {
        "available"
    } else {
        "unavailable"
    }
}
