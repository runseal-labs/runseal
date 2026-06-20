use crate::error::RunSealError;
use serde_json::{Value, json};

pub(crate) fn cli_error_payload(err: RunSealError) -> Value {
    let mut data = json!({
        "code": err.code,
        "reason": err.reason,
    });
    if let (Some(data), Some(details)) = (data.as_object_mut(), err.details) {
        data.extend(details.as_object().cloned().unwrap_or_default());
    }

    json!({
        "error": {
            "message": err.message,
            "data": data,
        }
    })
}
