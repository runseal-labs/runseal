use serde_json::Value;

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
                .strip_suffix('*')
                .is_some_and(|prefix| event_type.starts_with(prefix))
    })
}
