use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};

struct CachedEvent {
    order: u64,
    bytes: usize,
    value: Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn insertion_snapshot_matches_actual_per_execution_and_connection_eviction() {
        let mut cache = ReplayCache::default();
        for index in 0..40 {
            let id = format!("exec_{}", index % 12);
            let event = json!({"execution_id":id,"event_seq":index+1,"data":"x".repeat(512*1024),"result":{"earliest_available_seq":0}});
            let before = cache.bytes;
            let earliest = cache.earliest_after(&event);
            assert_eq!(
                cache.bytes, before,
                "preview must not publish or evict an event"
            );
            cache.record(event);
            assert_eq!(cache.earliest(&id, index + 1), earliest);
        }
        let oversized =
            json!({"execution_id":"exec_large","event_seq":99,"data":"x".repeat(1024*1024)});
        assert_eq!(cache.earliest_after(&oversized), 100);
        cache.record(oversized);
        assert_eq!(cache.earliest("exec_large", 99), 100);
    }

    #[test]
    fn per_execution_eviction_reclaims_global_index_entries() {
        let mut cache = ReplayCache::default();
        for seq in 1..=20 {
            cache.record(
                json!({"execution_id":"exec_one","event_seq":seq,"data":"x".repeat(128 * 1024)}),
            );
        }
        assert!(cache.histories["exec_one"].bytes <= 1024 * 1024);
        assert!(cache.earliest("exec_one", 20) > 1);
        assert_eq!(cache.order.len(), cache.events("exec_one").len());
        assert_eq!(cache.bytes, cache.histories["exec_one"].bytes);
    }

    #[test]
    fn connection_budget_evicts_in_global_order_across_executions() {
        let mut cache = ReplayCache::default();
        for index in 0..20 {
            cache.record(json!({"execution_id":format!("exec_{index}"),"event_seq":1,"data":"x".repeat(512 * 1024)}));
        }
        assert!(cache.bytes <= 8 * 1024 * 1024);
        assert_eq!(cache.earliest("exec_0", 1), 2);
        assert!(cache.events("exec_0").is_empty());
        assert_eq!(cache.earliest("exec_19", 1), 1);
        assert_eq!(cache.order.len(), cache.histories.len());
        assert_eq!(
            cache.bytes,
            cache
                .histories
                .values()
                .map(|history| history.bytes)
                .sum::<usize>()
        );
    }
}
#[derive(Default)]
struct History {
    events: VecDeque<CachedEvent>,
    bytes: usize,
}

#[derive(Default)]
pub(super) struct ReplayCache {
    histories: BTreeMap<String, History>,
    order: BTreeMap<u64, String>,
    next_order: u64,
    bytes: usize,
}

impl ReplayCache {
    /// Preview insertion without publishing a terminal that has not been audited yet.
    pub fn earliest_after(&self, event: &Value) -> u64 {
        let Some(id) = event["execution_id"].as_str() else {
            return 0;
        };
        let latest = event["event_seq"].as_u64().unwrap_or(0);
        let incoming = super::retention::retained_bytes(event) + 512;
        if incoming > crate::limits::deployment().replay_execution_bytes {
            return latest + 1;
        }
        let mut removed = std::collections::BTreeSet::new();
        let mut total = self.bytes + incoming;
        if let Some(history) = self.histories.get(id) {
            let mut retained = history.bytes + incoming;
            for old in &history.events {
                if retained <= crate::limits::deployment().replay_execution_bytes {
                    break;
                }
                retained -= old.bytes;
                total -= old.bytes;
                removed.insert(old.order);
            }
        }
        // Walk only small references, never clone retained output to calculate the range.
        let mut candidates = self
            .histories
            .values()
            .flat_map(|history| history.events.iter())
            .collect::<Vec<_>>();
        candidates.sort_unstable_by_key(|old| old.order);
        for old in candidates {
            if total <= crate::limits::deployment().replay_connection_bytes {
                break;
            }
            if removed.insert(old.order) {
                total -= old.bytes;
            }
        }
        self.histories
            .get(id)
            .and_then(|history| {
                history
                    .events
                    .iter()
                    .find(|old| !removed.contains(&old.order))
            })
            .and_then(|old| old.value["event_seq"].as_u64())
            .unwrap_or(latest)
    }

    pub fn record(&mut self, event: Value) {
        let Some(id) = event["execution_id"].as_str().map(str::to_owned) else {
            return;
        };
        self.next_order += 1;
        let order = self.next_order;
        let bytes = super::retention::retained_bytes(&event) + 512;
        let history = self.histories.entry(id.clone()).or_default();
        history.bytes += bytes;
        history.events.push_back(CachedEvent {
            order,
            bytes,
            value: event,
        });
        self.order.insert(order, id.clone());
        self.bytes += bytes;
        while self.histories.get(&id).is_some_and(|history| {
            history.bytes > crate::limits::deployment().replay_execution_bytes
        }) {
            self.remove_first(&id);
        }
        while self.bytes > crate::limits::deployment().replay_connection_bytes {
            let Some((_, id)) = self.order.first_key_value() else {
                break;
            };
            let id = id.clone();
            self.remove_first(&id);
        }
    }
    pub fn remove_execution(&mut self, id: &str) {
        while self.histories.contains_key(id) {
            self.remove_first(id);
        }
    }

    fn remove_first(&mut self, id: &str) {
        let Some(history) = self.histories.get_mut(id) else {
            return;
        };
        if let Some(event) = history.events.pop_front() {
            history.bytes = history.bytes.saturating_sub(event.bytes);
            self.bytes = self.bytes.saturating_sub(event.bytes);
            self.order.remove(&event.order);
        }
        if history.events.is_empty() {
            self.histories.remove(id);
        }
    }
    pub fn events(&self, id: &str) -> Vec<Value> {
        self.histories
            .get(id)
            .map(|history| {
                history
                    .events
                    .iter()
                    .map(|event| event.value.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn earliest(&self, id: &str, latest: u64) -> u64 {
        self.histories
            .get(id)
            .and_then(|history| history.events.front())
            .and_then(|event| event.value["event_seq"].as_u64())
            .unwrap_or(latest + 1)
    }
}
