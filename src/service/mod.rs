use crate::control;
use crate::error::RunSealError;
use crate::events::new_execution_ids;
use crate::execution::{audit_stream_event_metadata, execute_command_with_ids};
use crate::rpc;
use crate::setup::windows_sandbox_setup_status_for_cwd;
use request_validation::{
    audit_events_params, cancel_execution_id_from_params, execute_request_from_params,
    explain_policy_request_from_params, get_execution_id_from_params, session_id_from_params,
    setup_status_cwd_from_params, subscribe_events_params, tail_audit_params,
    validate_empty_params,
};
use serde_json::{Value, json};
use state::ServiceState;

mod event_bus;
mod executions;
mod request_validation;
mod sessions;
mod state;

#[derive(Default)]
pub(crate) struct Service {
    state: ServiceState,
    mode: ServiceMode,
}

#[derive(Clone, Copy, Default)]
enum ServiceMode {
    Direct,
    #[default]
    Service,
}

impl Service {
    pub(crate) fn direct() -> Self {
        Self {
            state: ServiceState::default(),
            mode: ServiceMode::Direct,
        }
    }

    pub(crate) fn stateful() -> Self {
        Self::default()
    }

    pub(crate) fn handle_rpc_request(&mut self, request: &Value) -> Vec<Value> {
        if request
            .as_object()
            .is_some_and(|object| !object.contains_key("id"))
        {
            return Vec::new();
        }
        let (id, method, params) = match rpc_request_parts(request) {
            Ok(parts) => parts,
            Err(err) => {
                return vec![rpc::invalid_request(request_id_for_error(request), err)];
            }
        };
        let Some(id) = id else {
            return Vec::new();
        };

        match method {
            "getVersion" => match validate_empty_params(&params, "getVersion") {
                Ok(()) => vec![rpc::result(id, control::version_payload())],
                Err(err) => vec![rpc::error(id, err)],
            },
            "getCapabilities" => match validate_empty_params(&params, "getCapabilities") {
                Ok(()) => vec![rpc::result(id, control::capabilities_payload())],
                Err(err) => vec![rpc::error(id, err)],
            },
            "getServiceStatus" => match validate_empty_params(&params, "getServiceStatus") {
                Ok(()) => vec![rpc::result(id, self.service_status())],
                Err(err) => vec![rpc::error(id, err)],
            },
            "explainPolicy" => match explain_policy_request_from_params(&params) {
                Ok((policy, cwd)) => {
                    vec![rpc::result(id, control::explain_policy_json(&policy, &cwd))]
                }
                Err(err) => vec![rpc::error(id, err)],
            },
            "getSetupStatus" => {
                let cwd = match setup_status_cwd_from_params(&params) {
                    Ok(cwd) => cwd,
                    Err(err) => return vec![rpc::error(id, err)],
                };
                match windows_sandbox_setup_status_for_cwd(&cwd) {
                    Ok(result) => vec![rpc::result(id, result)],
                    Err(err) => vec![rpc::error(id, RunSealError::new("INTERNAL_ERROR", err))],
                }
            }
            "execute" => self.execute(id, &params),
            "getExecution" => self.get_execution(id, &params),
            "listExecutions" => match validate_empty_params(&params, "listExecutions") {
                Ok(()) => vec![rpc::result(id, self.list_executions())],
                Err(err) => vec![rpc::error(id, err)],
            },
            "cancelExecution" => self.cancel_execution(id, &params),
            "subscribeEvents" => self.subscribe_events(id, &params),
            "getAuditEvents" => self.get_audit_events(id, &params),
            "tailAudit" => self.tail_audit(id, &params),
            "disposeSession" => self.dispose_session(id, &params),
            _ => vec![rpc::method_not_found(id, method)],
        }
    }

    fn service_status(&self) -> Value {
        let stateful = matches!(self.mode, ServiceMode::Service);
        json!({
            "status": "running",
            "mode": if stateful { "service" } else { "direct" },
            "transport": "stdio",
            "stateful": stateful,
            "local_only": true,
            "remote_listener": false,
        })
    }

    fn execute(&mut self, id: Value, params: &Value) -> Vec<Value> {
        let result = execute_request_from_params(params).and_then(|request| {
            let ids = new_execution_ids();
            execute_command_with_ids(
                ids,
                &request.command,
                &request.cwd,
                &request.policy,
                request.stdin,
                request.env,
                request.metadata,
                request.timeout,
            )
        });
        match result {
            Ok((events, result)) => {
                self.state.record_finished_execution(&result, &events);
                let mut messages: Vec<Value> = events
                    .into_iter()
                    .map(|event| json!({"jsonrpc": "2.0", "method": "event", "params": event}))
                    .collect();
                messages.push(rpc::result(id, result));
                messages
            }
            Err(err) => {
                let events = err.events.clone();
                self.state.record_failed_execution(&err);
                let mut messages: Vec<Value> = events
                    .into_iter()
                    .map(|event| json!({"jsonrpc": "2.0", "method": "event", "params": event}))
                    .collect();
                messages.push(rpc::error(id, err));
                messages
            }
        }
    }

    fn get_execution(&self, id: Value, params: &Value) -> Vec<Value> {
        let execution_id = match get_execution_id_from_params(params) {
            Ok(execution_id) => execution_id,
            Err(err) => return vec![rpc::error(id, err)],
        };
        match self.state.execution_result(&execution_id) {
            Some(result) => vec![rpc::result(id, result)],
            None => vec![rpc::error(id, execution_not_found(&execution_id))],
        }
    }

    fn list_executions(&self) -> Value {
        let executions = self.state.execution_summaries();
        json!({
            "count": executions.len(),
            "executions": executions,
        })
    }

    fn cancel_execution(&self, id: Value, params: &Value) -> Vec<Value> {
        let execution_id = match cancel_execution_id_from_params(params) {
            Ok(execution_id) => execution_id,
            Err(err) => return vec![rpc::error(id, err)],
        };
        match self.state.execution_result(&execution_id) {
            Some(result) => vec![rpc::error(id, execution_not_cancellable(&result))],
            None => vec![rpc::error(id, execution_not_found(&execution_id))],
        }
    }

    fn subscribe_events(&self, id: Value, params: &Value) -> Vec<Value> {
        let (execution_id, types) = match subscribe_events_params(params) {
            Ok(params) => params,
            Err(err) => return vec![rpc::error(id, err)],
        };
        let Some(events) = self.state.execution_events(&execution_id, &types) else {
            return vec![rpc::error(id, execution_not_found(&execution_id))];
        };
        let event_count = events.len();
        let mut messages = events
            .into_iter()
            .map(|event| json!({"jsonrpc": "2.0", "method": "event", "params": event}))
            .collect::<Vec<_>>();
        messages.push(rpc::result(
            id,
            json!({
                "execution_id": execution_id,
                "status": "subscribed",
                "event_count": event_count,
            }),
        ));
        messages
    }

    fn get_audit_events(&self, id: Value, params: &Value) -> Vec<Value> {
        let (execution_id, types) = match audit_events_params(params) {
            Ok(params) => params,
            Err(err) => return vec![rpc::error(id, err)],
        };
        let Some(events) = self.state.execution_events(&execution_id, &types) else {
            return vec![rpc::error(id, execution_not_found(&execution_id))];
        };
        let events = audit_event_metadata(events);
        vec![rpc::result(
            id,
            json!({
                "execution_id": execution_id,
                "count": events.len(),
                "events": events,
            }),
        )]
    }

    fn tail_audit(&self, id: Value, params: &Value) -> Vec<Value> {
        let types = match tail_audit_params(params) {
            Ok(types) => types,
            Err(err) => return vec![rpc::error(id, err)],
        };
        let events = audit_event_metadata(self.state.audit_tail(&types));
        vec![rpc::result(
            id,
            json!({
                "count": events.len(),
                "events": events,
            }),
        )]
    }

    fn dispose_session(&mut self, id: Value, params: &Value) -> Vec<Value> {
        let session_id = match session_id_from_params(params) {
            Ok(session_id) => session_id,
            Err(err) => return vec![rpc::error(id, err)],
        };
        let released_sessions = usize::from(self.state.dispose_session(&session_id));
        vec![rpc::result(
            id,
            json!({
                "session_id": session_id,
                "status": "disposed",
                "released_sessions": released_sessions,
                "released_executions": 0,
            }),
        )]
    }
}

fn execution_not_found(execution_id: &str) -> RunSealError {
    RunSealError::with_details(
        "EXECUTION_NOT_FOUND",
        format!("execution not found: {execution_id}"),
        json!({ "execution_id": execution_id }),
    )
}

fn audit_event_metadata(events: Vec<Value>) -> Vec<Value> {
    events
        .into_iter()
        .map(|event| {
            let mut event = audit_stream_event_metadata(&event);
            if let Some(object) = event.as_object_mut() {
                object.remove("metadata");
            }
            event
        })
        .collect()
}

fn execution_not_cancellable(result: &Value) -> RunSealError {
    let execution_id = result
        .get("execution_id")
        .and_then(Value::as_str)
        .unwrap_or("exec_unknown");
    let status = result
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let mut details = json!({
        "execution_id": execution_id,
        "status": status,
    });
    if let Some(details) = details.as_object_mut() {
        for key in [
            "session_id",
            "seal_id",
            "policy_id",
            "policy_hash",
            "policy_epoch",
            "backend",
            "audit_path",
        ] {
            if let Some(value) = result.get(key) {
                details.insert(key.to_string(), value.clone());
            }
        }
    }
    RunSealError::with_details(
        "EXECUTION_NOT_CANCELLABLE",
        format!("execution is not cancellable: {execution_id}"),
        details,
    )
}

fn rpc_request_parts(request: &Value) -> Result<(Option<Value>, &str, Value), RunSealError> {
    if request.is_array() {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            "batch requests are not supported",
        ));
    }
    let request = request.as_object().ok_or_else(|| {
        RunSealError::new("INVALID_REQUEST", "JSON-RPC request must be an object")
    })?;
    let id = request.get("id").map(validated_request_id).transpose()?;
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

fn request_id_for_error(request: &Value) -> Value {
    request
        .get("id")
        .filter(|value| is_valid_request_id(value))
        .cloned()
        .unwrap_or(Value::Null)
}

fn validated_request_id(value: &Value) -> Result<Value, RunSealError> {
    if is_valid_request_id(value) {
        Ok(value.clone())
    } else {
        Err(RunSealError::new(
            "INVALID_REQUEST",
            "request.id must be a string, number, or null",
        ))
    }
}

fn is_valid_request_id(value: &Value) -> bool {
    value.is_string() || value.is_number() || value.is_null()
}

#[cfg(test)]
mod tests {
    use super::audit_event_metadata;
    use serde_json::json;

    #[test]
    fn audit_lookup_metadata_is_public_safe() {
        let events = audit_event_metadata(vec![json!({
            "type": "execution.stdout",
            "metadata": {"Authorization": "secret"},
            "data": "base64:c2VjcmV0",
            "text": "secret",
            "bytes": 6
        })]);

        assert_eq!(events[0]["type"], "execution.stdout");
        assert_eq!(events[0]["bytes"], 6);
        assert!(events[0].get("metadata").is_none());
        assert!(events[0].get("data").is_none());
        assert!(events[0].get("text").is_none());
    }
}
