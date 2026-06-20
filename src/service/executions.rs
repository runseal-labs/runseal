use crate::error::RunSealError;
use crate::events::timestamp_now;
use crate::execution::audit_stream_event_metadata;
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
            "status": "failed",
            "error": {
                "code": err.code,
                "reason": err.reason,
            },
        });
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
        }
        self.records.insert(
            execution_id.to_string(),
            ExecutionRecord {
                session_id: session_id.to_string(),
                result,
                events: vec![failed_event(execution_id, session_id, err, details)],
            },
        );
        Some(session_id.to_string())
    }

    pub(super) fn result(&self, execution_id: &str) -> Option<Value> {
        self.records
            .get(execution_id)
            .map(|record| record.result.clone())
    }

    pub(super) fn status(&self, execution_id: &str) -> Option<&str> {
        self.records.get(execution_id).map(|record| {
            record
                .result
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        })
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

    pub(super) fn audit_events(&self, execution_id: &str, types: &[String]) -> Option<Vec<Value>> {
        self.events(execution_id, types).map(|events| {
            events
                .into_iter()
                .map(|event| audit_stream_event_metadata(&event))
                .collect()
        })
    }

    pub(super) fn all_events(&self, types: &[String]) -> Vec<Value> {
        self.records
            .values()
            .flat_map(|record| filter_events(&record.events, types))
            .map(|event| audit_stream_event_metadata(&event))
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

fn failed_event(
    execution_id: &str,
    session_id: &str,
    err: &RunSealError,
    details: &Value,
) -> Value {
    let reason = if err.code == "EXECUTION_FAILED_TO_START" {
        "execution failed to start"
    } else {
        err.reason.as_str()
    };
    let mut event = json!({
        "type": "execution.failed",
        "time": timestamp_now(),
        "runseal_version": env!("CARGO_PKG_VERSION"),
        "execution_id": execution_id,
        "session_id": session_id,
        "status": "failed",
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
