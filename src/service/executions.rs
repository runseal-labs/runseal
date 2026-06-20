use crate::error::RunSealError;
use crate::events::timestamp_now;
use crate::execution::ExecutionCancellation;
use serde_json::{Value, json};
use std::collections::BTreeMap;

use super::event_bus::filter_events;

#[derive(Default)]
pub(super) struct ExecutionStore {
    records: BTreeMap<String, ExecutionRecord>,
    active: BTreeMap<String, ActiveExecution>,
    record_order: Vec<String>,
}

struct ExecutionRecord {
    result: Value,
    events: Vec<Value>,
}

struct ActiveExecution {
    result: Value,
    events: Vec<Value>,
    cancellation: ExecutionCancellation,
}

impl ExecutionStore {
    pub(super) fn record_running(
        &mut self,
        result: Value,
        cancellation: ExecutionCancellation,
    ) -> Option<String> {
        let (Some(execution_id), Some(session_id)) = (
            result.get("execution_id").and_then(Value::as_str),
            result.get("session_id").and_then(Value::as_str),
        ) else {
            return None;
        };
        let execution_id = execution_id.to_string();
        let session_id = session_id.to_string();
        if !self.records.contains_key(&execution_id) && !self.active.contains_key(&execution_id) {
            self.record_order.push(execution_id.clone());
        }
        self.active.insert(
            execution_id,
            ActiveExecution {
                result,
                events: Vec::new(),
                cancellation,
            },
        );
        Some(session_id)
    }

    pub(super) fn record_finished(&mut self, result: &Value, events: &[Value]) -> Option<String> {
        let (Some(execution_id), Some(session_id)) = (
            result.get("execution_id").and_then(Value::as_str),
            result.get("session_id").and_then(Value::as_str),
        ) else {
            return None;
        };
        let mut result = result.clone();
        if let Some(result) = result.as_object_mut() {
            result.remove("stdout");
            result.remove("stderr");
            result.remove("metadata");
        }
        self.insert_record(
            execution_id,
            ExecutionRecord {
                result,
                events: events.to_vec(),
            },
        );
        self.active.remove(execution_id);
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
                "support",
                "missing_features",
                "setup_status",
                "setup_error",
                "cleanup_error",
                "timeout_ms",
                "max_output_bytes",
                "stdout_bytes",
                "stderr_bytes",
                "output_truncated",
                "retained_stdout_bytes",
                "retained_stderr_bytes",
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
        self.insert_record(execution_id, ExecutionRecord { result, events });
        self.active.remove(execution_id);
        Some(session_id.to_string())
    }

    pub(super) fn result(&self, execution_id: &str) -> Option<Value> {
        self.active
            .get(execution_id)
            .map(|record| record.result.clone())
            .or_else(|| {
                self.records
                    .get(execution_id)
                    .map(|record| record.result.clone())
            })
    }

    pub(super) fn summaries(&self) -> Vec<Value> {
        self.record_order
            .iter()
            .filter_map(|execution_id| {
                self.active
                    .get(execution_id)
                    .map(|record| &record.result)
                    .or_else(|| self.records.get(execution_id).map(|record| &record.result))
            })
            .map(execution_summary)
            .collect()
    }

    pub(super) fn events(&self, execution_id: &str, types: &[String]) -> Option<Vec<Value>> {
        self.active
            .get(execution_id)
            .map(|record| filter_events(&record.events, types))
            .or_else(|| {
                self.records
                    .get(execution_id)
                    .map(|record| filter_events(&record.events, types))
            })
    }

    pub(super) fn all_events(&self, types: &[String]) -> Vec<Value> {
        self.record_order
            .iter()
            .filter_map(|execution_id| {
                self.active
                    .get(execution_id)
                    .map(|record| &record.events)
                    .or_else(|| self.records.get(execution_id).map(|record| &record.events))
            })
            .flat_map(|events| filter_events(events, types))
            .collect()
    }

    pub(super) fn cancel_active(&mut self, execution_id: &str) -> Option<Value> {
        let active = self.active.get_mut(execution_id)?;
        active.cancellation.cancel();
        if let Some(result) = active.result.as_object_mut() {
            result.insert("status".to_string(), json!("cancelling"));
        }
        Some(active.result.clone())
    }

    fn insert_record(&mut self, execution_id: &str, record: ExecutionRecord) {
        if !self.records.contains_key(execution_id) && !self.active.contains_key(execution_id) {
            self.record_order.push(execution_id.to_string());
        }
        self.records.insert(execution_id.to_string(), record);
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
        "support",
        "missing_features",
        "setup_status",
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
                        | "execution.cancelled"
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
        "EXECUTION_CANCELLED" => "cancelled",
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
        "EXECUTION_CANCELLED" => ("execution.cancelled", "cancelled", "execution cancelled"),
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

#[cfg(test)]
mod tests {
    use super::ExecutionStore;
    use crate::error::RunSealError;
    use serde_json::{Value, json};

    fn finished_result(execution_id: &str, session_id: &str) -> Value {
        json!({
            "execution_id": execution_id,
            "session_id": session_id,
            "status": "finished",
        })
    }

    fn marked_event(execution_id: &str, marker: &str) -> Value {
        json!({
            "type": "policy.resolved",
            "execution_id": execution_id,
            "marker": marker,
        })
    }

    #[test]
    fn summaries_preserve_service_record_order() {
        let mut store = ExecutionStore::default();
        store.record_finished(&finished_result("exec_b", "sess_b"), &[]);
        store.record_finished(&finished_result("exec_a", "sess_a"), &[]);

        let execution_ids = store
            .summaries()
            .into_iter()
            .map(|summary| summary["execution_id"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();

        assert_eq!(execution_ids, ["exec_b", "exec_a"]);
    }

    #[test]
    fn audit_tail_preserves_record_and_event_order() {
        let mut store = ExecutionStore::default();
        store.record_finished(
            &finished_result("exec_b", "sess_b"),
            &[marked_event("exec_b", "b1"), marked_event("exec_b", "b2")],
        );
        store.record_finished(
            &finished_result("exec_a", "sess_a"),
            &[marked_event("exec_a", "a1")],
        );

        let markers = store
            .all_events(&[])
            .into_iter()
            .map(|event| event["marker"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();

        assert_eq!(markers, ["b1", "b2", "a1"]);
    }

    #[test]
    fn finished_records_omit_raw_output() {
        let mut store = ExecutionStore::default();
        store.record_finished(
            &json!({
                "execution_id": "exec_a",
                "session_id": "sess_a",
                "status": "finished",
                "stdout": "secret-output",
                "stderr": "secret-error",
                "stdout_bytes": 13,
                "stderr_bytes": 12,
                "metadata": {"Authorization": "secret"}
            }),
            &[],
        );

        let result = store.result("exec_a").expect("finished record must exist");
        assert!(result.get("stdout").is_none());
        assert!(result.get("stderr").is_none());
        assert!(result.get("metadata").is_none());
        assert_eq!(result["stdout_bytes"], 13);
        assert_eq!(result["stderr_bytes"], 12);
    }

    #[test]
    fn failed_records_preserve_setup_status() {
        let mut store = ExecutionStore::default();
        let err = RunSealError::with_details(
            "BACKEND_UNAVAILABLE",
            "windows sandbox setup unavailable",
            json!({
                "execution_id": "exec_a",
                "session_id": "sess_a",
                "setup_status": {
                    "setup": "windows-sandbox",
                    "next_action": "run_setup"
                }
            }),
        );

        store.record_failed(&err);

        let result = store.result("exec_a").expect("failed record must exist");
        assert_eq!(result["setup_status"]["setup"], "windows-sandbox");
        assert_eq!(result["setup_status"]["next_action"], "run_setup");

        let summary = store.summaries().pop().expect("summary must exist");
        assert_eq!(summary["setup_status"]["setup"], "windows-sandbox");
        assert_eq!(summary["setup_status"]["next_action"], "run_setup");
    }
}
