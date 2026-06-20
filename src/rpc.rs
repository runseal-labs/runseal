use crate::error::RunSealError;
use serde_json::{Value, json};

pub(crate) fn result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

pub(crate) fn error(id: Value, err: RunSealError) -> Value {
    let code = match err.code.as_str() {
        "INVALID_REQUEST" => -32602,
        "INTERNAL_ERROR" => -32603,
        _ => -32000,
    };
    error_with_code(id, code, err)
}

pub(crate) fn parse_error(reason: impl Into<String>) -> Value {
    error_with_code(
        Value::Null,
        -32700,
        RunSealError::new("INVALID_REQUEST", reason),
    )
}

pub(crate) fn invalid_request(id: Value, err: RunSealError) -> Value {
    error_with_code(id, -32600, err)
}

pub(crate) fn method_not_found(id: Value, method: &str) -> Value {
    error_with_code(
        id,
        -32601,
        RunSealError::new("METHOD_NOT_FOUND", format!("method not found: {method}")),
    )
}

fn error_with_code(id: Value, code: i64, err: RunSealError) -> Value {
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
            "code": code,
            "message": err.message,
            "data": data
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_error_uses_json_rpc_internal_error_code() {
        let response = error(
            json!(1),
            RunSealError::new("INTERNAL_ERROR", "unexpected implementation failure"),
        );

        assert_eq!(response["error"]["code"], -32603);
        assert_eq!(response["error"]["data"]["code"], "INTERNAL_ERROR");
    }
}
