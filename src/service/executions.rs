use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct ExecutionStore {
    records: BTreeMap<String, ExecutionRecord>,
    order: Vec<String>,
    retained_bytes: usize,
    truncated: bool,
}

struct ExecutionRecord {
    result: Value,
}

impl ExecutionStore {
    pub(super) fn record_finished(&mut self, result: &Value) -> Option<String> {
        let (Some(execution_id), Some(session_id)) = (
            result.get("execution_id").and_then(Value::as_str),
            result.get("session_id").and_then(Value::as_str),
        ) else {
            return None;
        };
        self.insert_record(
            execution_id,
            ExecutionRecord {
                result: result.clone(),
            },
        );
        Some(session_id.to_string())
    }

    pub(super) fn ids_for_session(&self, session_id: &str) -> Vec<String> {
        self.records
            .iter()
            .filter(|(_, record)| record.result["session_id"] == session_id)
            .map(|(id, _)| id.clone())
            .collect()
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
        self.ordered_records()
            .map(|record| execution_summary(&record.result))
            .collect()
    }

    fn insert_record(&mut self, execution_id: &str, record: ExecutionRecord) {
        if !self.records.contains_key(execution_id) {
            self.order.push(execution_id.to_string());
        }
        if let Some(previous) = self.records.remove(execution_id) {
            self.retained_bytes = self.retained_bytes.saturating_sub(record_bytes(&previous));
        }
        self.retained_bytes += record_bytes(&record);
        self.records.insert(execution_id.to_string(), record);
        while self.records.len() > crate::limits::deployment().completed_executions
            || self.retained_bytes > crate::limits::deployment().completed_execution_bytes
        {
            let Some(oldest) = self.order.first().cloned() else {
                break;
            };
            self.order.remove(0);
            if let Some(record) = self.records.remove(&oldest) {
                self.retained_bytes = self.retained_bytes.saturating_sub(record_bytes(&record));
            }
            self.truncated = true;
        }
    }

    pub(super) fn truncated(&self) -> bool {
        self.truncated
    }

    fn ordered_records(&self) -> impl Iterator<Item = &ExecutionRecord> {
        self.order
            .iter()
            .filter_map(|execution_id| self.records.get(execution_id))
    }
}

fn record_bytes(record: &ExecutionRecord) -> usize {
    super::retention::retained_bytes(&record.result) + 512
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
        "terminal_bytes",
        "control_bytes",
        "stderr_merged",
        "output_truncated",
        "termination_reason",
        "cleanup_complete",
        "latest_seq",
        "earliest_available_seq",
        "error",
    ] {
        if let Some(value) = result.get(key) {
            summary.insert(key.to_string(), value.clone());
        }
    }
    Value::Object(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completion_store_enforces_count_and_resident_byte_budgets() {
        let mut store = ExecutionStore::default();
        for index in 0..1025 {
            store.record_finished(&json!({"execution_id":format!("exec_{index}"),"session_id":"sess_one","status":"finished"}));
        }
        assert_eq!(store.records.len(), 1024);
        assert!(store.result("exec_0").is_none());
        assert!(store.truncated());
        for index in 0..12 {
            store.record_finished(&json!({"execution_id":format!("exec_large_{index}"),"session_id":"sess_one","status":"finished","details":"x".repeat(1024 * 1024)}));
        }
        assert!(store.retained_bytes <= 8 * 1024 * 1024);
        assert!(store.result("exec_large_0").is_none());
        assert!(store.result("exec_large_11").is_some());
        assert_eq!(store.records.len(), store.order.len());
    }
    #[test]
    fn summaries_preserve_record_order() {
        let mut store = ExecutionStore::default();
        store.record_finished(
            &json!({"execution_id":"exec_z","session_id":"sess_1","status":"finished"}),
        );
        store.record_finished(
            &json!({"execution_id":"exec_a","session_id":"sess_1","status":"finished"}),
        );
        assert_eq!(store.summaries()[0]["execution_id"], "exec_z");
        assert_eq!(store.summaries()[1]["execution_id"], "exec_a");
    }
    #[test]
    fn failed_result_preserves_setup_status() {
        let mut store = ExecutionStore::default();
        store.record_finished(&json!({"execution_id":"exec_setup","session_id":"sess_1","status":"failed","error":{"code":"BACKEND_UNAVAILABLE"},"setup_status":{"setup":"windows-sandbox","requires_setup":true}}));
        let result = store.result("exec_setup").unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["setup_status"]["requires_setup"], true);
    }
}
