use super::*;

pub(crate) fn run_rpc_stdio() -> Result<(), String> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.map_err(|err| format!("failed to read stdin: {err}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = serde_json::from_str(&line)
            .map_err(|err| format!("invalid JSON-RPC request: {err}"))?;
        for message in handle_rpc_request(&request) {
            writeln!(stdout, "{message}")
                .map_err(|err| format!("failed to write stdout: {err}"))?;
            stdout
                .flush()
                .map_err(|err| format!("failed to flush stdout: {err}"))?;
        }
    }
    Ok(())
}

fn handle_rpc_request(request: &Value) -> Vec<Value> {
    let (id, method, params) = match rpc_request_parts(request) {
        Ok(parts) => parts,
        Err(err) => {
            return vec![rpc::error(
                request.get("id").cloned().unwrap_or(Value::Null),
                err,
            )];
        }
    };

    match method {
        "getVersion" => match validate_empty_params(&params, "getVersion") {
            Ok(()) => vec![rpc::result(id, commands::version::payload())],
            Err(err) => vec![rpc::error(id, err)],
        },
        "getCapabilities" => match validate_empty_params(&params, "getCapabilities") {
            Ok(()) => vec![rpc::result(id, commands::capabilities::payload())],
            Err(err) => vec![rpc::error(id, err)],
        },
        "explainPolicy" => match explain_policy_from_params(&params) {
            Ok(result) => vec![rpc::result(id, result)],
            Err(err) => vec![rpc::error(id, err)],
        },
        "execute" => match execute_from_params(&params) {
            Ok((events, result)) => {
                let mut messages: Vec<Value> = events
                    .into_iter()
                    .map(|event| json!({"jsonrpc": "2.0", "method": "event", "params": event}))
                    .collect();
                messages.push(rpc::result(id, result));
                messages
            }
            Err(err) => vec![rpc::error(id, err)],
        },
        "getExecution" => match execution_not_found_from_params(&params, "getExecution", &[]) {
            Ok(result) => vec![rpc::result(id, result)],
            Err(err) => vec![rpc::error(id, err)],
        },
        "cancelExecution" => {
            match execution_not_found_from_params(&params, "cancelExecution", &["reason"]) {
                Ok(result) => vec![rpc::result(id, result)],
                Err(err) => vec![rpc::error(id, err)],
            }
        }
        "subscribeEvents" => {
            match execution_not_found_from_params(&params, "subscribeEvents", &["types"]) {
                Ok(result) => vec![rpc::result(id, result)],
                Err(err) => vec![rpc::error(id, err)],
            }
        }
        "disposeSession" => match dispose_session_from_params(&params) {
            Ok(result) => vec![rpc::result(id, result)],
            Err(err) => vec![rpc::error(id, err)],
        },
        _ => vec![rpc::error(
            id,
            RunSealError::new("INVALID_REQUEST", format!("unknown method: {method}")),
        )],
    }
}

fn rpc_request_parts(request: &Value) -> Result<(Value, &str, Value), RunSealError> {
    let request = request.as_object().ok_or_else(|| {
        RunSealError::new("INVALID_REQUEST", "JSON-RPC request must be an object")
    })?;
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let version = request.get("jsonrpc").and_then(Value::as_str);
    if version != Some("2.0") {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            "request.jsonrpc must be 2.0",
        ));
    }
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RunSealError::new("INVALID_REQUEST", "request.method is required"))?;
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
    Ok((id, method, params))
}
