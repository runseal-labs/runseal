use crate::error::RunSealError;
use crate::events::timestamp_now;
use serde_json::{Value, json};
use std::collections::BTreeMap;

use super::event_bus::filter_events;

#[derive(Default)]
pub(super) struct ExecutionStore {
    records: BTreeMap<String, ExecutionRecord>,
}

struct ExecutionRecord {
    session_id: String,
    result: Value,
    events: Vec<Value>,
}

impl ExecutionStore {
    pub(super) fn record_finished(&mut self, result: &Value, events: &[Value]) -> Option<String> {
        let (Some(execution_id), Some(session_id)) = (
            result.get("execution_id").and_then(Value::as_str),
            result.get("session_id").and_then(Value::as_str),
        ) else {
            return None;
        };
        self.records.insert(
            execution_id.to_string(),
            ExecutionRecord {
                session_id: session_id.to_string(),
                result: result.clone(),
                events: events.to_vec(),
            },
        );
        Some(session_id.to_string())
    }

    pub(super) fn record_failed(&mut self, err: &RunSealError) -> Option<String> {
        let details = err.details.as_ref()?;
        let (Some(execution_id), Some(session_id)) = (
            details.get("execution_id").and_then(Value::as_str),
            details.get("session_id").and_then(Value::as_str),
        ) else {
            return None;
        };
        let mut result = json!({
            "execution_id": execution_id,
            "session_id": session_id,
            "status": error_status(err),
            "error": {
                "code": err.code,
                "reason": err.reason,
            },
        });
        let events = if err.events.is_empty() {
            vec![error_event(execution_id, session_id, err, details)]
        } else {
            err.events.clone()
        };
        if let (Some(result), Some(details)) = (result.as_object_mut(), details.as_object()) {
            for key in [
                "seal_id",
                "policy_id",
                "policy_hash",
                "policy_epoch",
                "audit_path",
                "backend",
                "platform_plan",
            ] {
                if let Some(value) = details.get(key) {
                    result.insert(key.to_string(), value.clone());
                }
            }
            if let Some(started_at) = event_time(&events, "execution.started") {
                result.insert("started_at".to_string(), started_at);
            }
            if let Some(finished_at) = terminal_time(&events) {
                result.insert("finished_at".to_string(), finished_at);
            }
        }
        self.records.insert(
            execution_id.to_string(),
            ExecutionRecord {
                session_id: session_id.to_string(),
                result,
                events,
            },
        );
        Some(session_id.to_string())
    }

    pub(super) fn result(&self, execution_id: &str) -> Option<Value> {
        self.records
            .get(execution_id)
            .map(|record| record.result.clone())
    }

    pub(super) fn summaries(&self) -> Vec<Value> {
        self.records
            .values()
            .map(|record| execution_summary(&record.result))
            .collect()
    }

    pub(super) fn events(&self, execution_id: &str, types: &[String]) -> Option<Vec<Value>> {
        self.records
            .get(execution_id)
            .map(|record| filter_events(&record.events, types))
    }

    pub(super) fn all_events(&self, types: &[String]) -> Vec<Value> {
        self.records
            .values()
            .flat_map(|record| filter_events(&record.events, types))
            .collect()
    }

    pub(super) fn remove_session(&mut self, session_id: &str) -> usize {
        let before = self.records.len();
        self.records
            .retain(|_, record| record.session_id != session_id);
        before - self.records.len()
    }
}

fn execution_summary(result: &Value) -> Value {
    let mut summary = serde_json::Map::new();
    for key in [
        "execution_id",
        "session_id",
        "seal_id",
        "status",
        "policy_id",
        "policy_hash",
        "policy_epoch",
        "backend",
        "audit_path",
        "started_at",
        "finished_at",
        "exit_code",
        "signal",
        "stdout_bytes",
        "stderr_bytes",
        "output_truncated",
        "error",
    ] {
        if let Some(value) = result.get(key) {
            summary.insert(key.to_string(), value.clone());
        }
    }
    Value::Object(summary)
}

fn event_time(events: &[Value], event_type: &str) -> Option<Value> {
    events
        .iter()
        .find(|event| event.get("type").and_then(Value::as_str) == Some(event_type))
        .and_then(|event| event.get("time"))
        .cloned()
}

fn terminal_time(events: &[Value]) -> Option<Value> {
    events
        .iter()
        .rev()
        .find(|event| {
            matches!(
                event.get("type").and_then(Value::as_str),
                Some(
                    "execution.finished"
                        | "execution.failed"
                        | "policy.denied"
                        | "policy.requires_approval"
                        | "sandbox.backend_capability"
                        | "sandbox.setup_failed"
                )
            ) || event.get("type").and_then(Value::as_str) == Some("sandbox.cleanup")
                && event.get("decision").and_then(Value::as_str) == Some("failed")
        })
        .and_then(|event| event.get("time"))
        .cloned()
}

fn error_status(err: &RunSealError) -> &'static str {
    match err.code.as_str() {
        "APPROVAL_REQUIRED" | "POLICY_DENIED" => "denied",
        _ => "failed",
    }
}

fn error_event(execution_id: &str, session_id: &str, err: &RunSealError, details: &Value) -> Value {
    let (event_type, decision, reason) = match err.code.as_str() {
        "APPROVAL_REQUIRED" => (
            "policy.requires_approval",
            "requires_approval",
            err.reason.as_str(),
        ),
        "POLICY_DENIED" => ("policy.denied", "denied", err.reason.as_str()),
        "EXECUTION_FAILED_TO_START" => ("execution.failed", "failed", "execution failed to start"),
        _ => ("execution.failed", "failed", err.reason.as_str()),
    };
    let mut event = json!({
        "type": event_type,
        "time": timestamp_now(),
        "runseal_version": env!("CARGO_PKG_VERSION"),
        "execution_id": execution_id,
        "session_id": session_id,
        "status": error_status(err),
        "decision": decision,
        "reason": reason,
        "error": err.reason,
    });
    if let (Some(event), Some(details)) = (event.as_object_mut(), details.as_object()) {
        for key in [
            "seal_id",
            "policy_id",
            "policy_hash",
            "policy_epoch",
            "audit_path",
            "backend",
            "setup_status",
        ] {
            if let Some(value) = details.get(key) {
                event.insert(key.to_string(), value.clone());
            }
        }
    }
    event
}
