use crate::commands;
use crate::error::RunSealError;
use crate::protocol::request_validation::{
    cancel_execution_id_from_params, execute_from_params, explain_policy_from_params,
    get_execution_id_from_params, session_id_from_params, subscribe_events_params,
    validate_empty_params,
};
use crate::rpc;
use serde_json::{Value, json};
use state::ServiceState;

mod event_bus;
mod executions;
mod sessions;
mod state;

#[derive(Default)]
pub(crate) struct Service {
    state: ServiceState,
}

impl Service {
    pub(crate) fn handle_rpc_request(&mut self, request: &Value) -> Vec<Value> {
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
            "execute" => self.execute(id, &params),
            "getExecution" => self.get_execution(id, &params),
            "cancelExecution" => self.cancel_execution(id, &params),
            "subscribeEvents" => self.subscribe_events(id, &params),
            "disposeSession" => self.dispose_session(id, &params),
            _ => vec![rpc::error(
                id,
                RunSealError::new("INVALID_REQUEST", format!("unknown method: {method}")),
            )],
        }
    }

    fn execute(&mut self, id: Value, params: &Value) -> Vec<Value> {
        match execute_from_params(params) {
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
                self.state.record_failed_execution(&err);
                vec![rpc::error(id, err)]
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

    fn cancel_execution(&self, id: Value, params: &Value) -> Vec<Value> {
        let execution_id = match cancel_execution_id_from_params(params) {
            Ok(execution_id) => execution_id,
            Err(err) => return vec![rpc::error(id, err)],
        };
        vec![rpc::error(id, execution_not_found(&execution_id))]
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

    fn dispose_session(&mut self, id: Value, params: &Value) -> Vec<Value> {
        let session_id = match session_id_from_params(params) {
            Ok(session_id) => session_id,
            Err(err) => return vec![rpc::error(id, err)],
        };
        let released_executions = self.state.dispose_session(&session_id);
        vec![rpc::result(
            id,
            json!({
                "session_id": session_id,
                "status": "disposed",
                "released_executions": released_executions,
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
