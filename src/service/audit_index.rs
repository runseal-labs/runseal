use serde_json::Value;
use std::collections::VecDeque;

#[derive(Default)]
pub(super) struct AuditIndex {
    events: VecDeque<Value>,
    bytes: usize,
    truncated: bool,
}

impl AuditIndex {
    pub fn record(&mut self, event: &Value) {
        let event = crate::execution::audit_stream_event_metadata(event);
        self.bytes += super::retention::retained_bytes(&event) + 64;
        self.events.push_back(event);
        while self.bytes > crate::limits::deployment().audit_cache_bytes {
            let Some(oldest) = self.events.pop_front() else {
                break;
            };
            self.bytes = self
                .bytes
                .saturating_sub(super::retention::retained_bytes(&oldest) + 64);
            self.truncated = true;
        }
    }
    pub fn for_execution(&self, id: &str, types: &[String], latest_seq: u64) -> (Vec<Value>, bool) {
        let retained: Vec<_> = self
            .events
            .iter()
            .filter(|event| event["execution_id"] == id)
            .collect();
        let truncated = retained
            .first()
            .and_then(|event| event["event_seq"].as_u64())
            .map_or(latest_seq > 0, |seq| seq > 1);
        (
            retained
                .into_iter()
                .filter(|event| super::event_bus::event_matches_types(event, types))
                .cloned()
                .collect(),
            truncated,
        )
    }
    pub fn tail(&self, types: &[String]) -> (Vec<Value>, bool) {
        (
            self.events
                .iter()
                .filter(|event| super::event_bus::event_matches_types(event, types))
                .cloned()
                .collect(),
            self.truncated,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fully_evicted_known_execution_reports_missing_audit_history() {
        let index = AuditIndex::default();
        assert!(index.for_execution("exec_evicted", &[], 3).1);
        assert!(!index.for_execution("exec_preparing", &[], 0).1);
    }
    #[test]
    fn audit_tail_preserves_interleaved_execution_order_without_payloads() {
        let mut index = AuditIndex::default();
        for (id, seq) in [("exec_z", 1), ("exec_a", 1), ("exec_z", 2)] {
            index.record(&serde_json::json!({"execution_id":id,"event_seq":seq,"type":"execution.stdout","data":"base64:c2VjcmV0"}));
        }
        let (events, truncated) = index.tail(&[]);
        assert!(!truncated);
        assert_eq!(
            events
                .iter()
                .map(|event| event["execution_id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["exec_z", "exec_a", "exec_z"]
        );
        assert!(events.iter().all(|event| event.get("data").is_none()));
    }
}
