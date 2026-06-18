use crate::error::RunSealError;
use serde_json::{Value, json};

pub(crate) fn result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

pub(crate) fn error(id: Value, err: RunSealError) -> Value {
    let mut data = json!({
        "code": err.code,
        "reason": err.reason,
    });
    if let (Some(data), Some(details)) = (data.as_object_mut(), err.details) {
        data.extend(details.as_object().cloned().unwrap_or_default());
    }

    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32000,
            "message": err.message,
            "data": data
        }
    })
}
