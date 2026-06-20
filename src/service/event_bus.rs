use serde_json::{Value, json};
use std::sync::mpsc::Sender;

#[derive(Default)]
pub(super) struct EventBus {
    subscriptions: Vec<Subscription>,
}

struct Subscription {
    execution_id: String,
    types: Vec<String>,
    sender: Sender<Vec<Value>>,
}

impl EventBus {
    pub(super) fn subscribe(
        &mut self,
        execution_id: String,
        types: Vec<String>,
        sender: Sender<Vec<Value>>,
    ) {
        self.subscriptions.push(Subscription {
            execution_id,
            types,
            sender,
        });
    }

    pub(super) fn publish(&mut self, event: &Value) {
        let Some(execution_id) = event.get("execution_id").and_then(Value::as_str) else {
            return;
        };
        self.subscriptions.retain(|subscription| {
            if subscription.execution_id != execution_id
                || !event_matches_types(event, &subscription.types)
            {
                return true;
            }
            subscription
                .sender
                .send(vec![notification(event.clone())])
                .is_ok()
        });
    }

    pub(super) fn clear_execution(&mut self, execution_id: &str) {
        self.subscriptions
            .retain(|subscription| subscription.execution_id != execution_id);
    }

    pub(super) fn clear(&mut self) {
        self.subscriptions.clear();
    }
}

pub(super) fn notifications(events: Vec<Value>, emit_events: bool) -> Vec<Value> {
    if emit_events {
        events.into_iter().map(notification).collect()
    } else {
        Vec::new()
    }
}

pub(super) fn notification(event: Value) -> Value {
    json!({"jsonrpc": "2.0", "method": "event", "params": event})
}

pub(super) fn filter_events(events: &[Value], types: &[String]) -> Vec<Value> {
    events
        .iter()
        .filter(|event| event_matches_types(event, types))
        .cloned()
        .collect()
}

fn event_matches_types(event: &Value, types: &[String]) -> bool {
    if types.is_empty() {
        return true;
    }
    let Some(event_type) = event.get("type").and_then(Value::as_str) else {
        return false;
    };
    types.iter().any(|filter| {
        filter == event_type
            || filter == "*"
            || filter
                .strip_suffix(".*")
                .is_some_and(|prefix| event_type.starts_with(prefix))
    })
}
