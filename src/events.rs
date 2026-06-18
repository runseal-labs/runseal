use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

static EXECUTION_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub(crate) struct ExecutionIds {
    pub(crate) execution_id: String,
    pub(crate) session_id: String,
    pub(crate) seal_id: String,
}

#[derive(Debug)]
pub(crate) struct ExecutionEventContext<'a> {
    pub(crate) ids: &'a ExecutionIds,
    pub(crate) policy_id: &'a str,
    pub(crate) policy_hash: &'a str,
    pub(crate) audit_path: &'a str,
    pub(crate) backend: Value,
}

pub(crate) fn new_execution_ids() -> ExecutionIds {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    let pid = std::process::id();
    let counter = EXECUTION_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let suffix = format!("{millis:x}_{pid:x}_{counter:x}");
    ExecutionIds {
        execution_id: format!("exec_{suffix}"),
        session_id: format!("sess_{suffix}"),
        seal_id: format!("seal_{suffix}"),
    }
}

pub(crate) fn stream_event(
    event_type: &'static str,
    context: &ExecutionEventContext<'_>,
    bytes: &[u8],
    offset: u64,
) -> Value {
    let encoded = STANDARD.encode(bytes);
    execution_event_now(
        json!({
            "type": event_type,
            "execution_id": context.ids.execution_id,
            "data": format!("base64:{encoded}"),
            "encoding": "base64",
            "stream_offset": offset,
            "bytes": bytes.len(),
        }),
        context,
    )
}

pub(crate) fn execution_event_now(event: Value, context: &ExecutionEventContext<'_>) -> Value {
    let time = timestamp_now();
    execution_event_at(event, &time, context)
}

pub(crate) fn execution_event_at(
    event: Value,
    time: &str,
    context: &ExecutionEventContext<'_>,
) -> Value {
    let mut event = event_at(event, time);
    if let Some(object) = event.as_object_mut() {
        object
            .entry("execution_id")
            .or_insert_with(|| json!(context.ids.execution_id));
        object
            .entry("session_id")
            .or_insert_with(|| json!(context.ids.session_id));
        object
            .entry("seal_id")
            .or_insert_with(|| json!(context.ids.seal_id));
        object
            .entry("policy_id")
            .or_insert_with(|| json!(context.policy_id));
        object
            .entry("policy_hash")
            .or_insert_with(|| json!(context.policy_hash));
        object
            .entry("audit_path")
            .or_insert_with(|| json!(context.audit_path));
        object
            .entry("backend")
            .or_insert_with(|| context.backend.clone());
    }
    event
}

pub(crate) fn backend_event_json(name: &str, status: &str, platform: &str) -> Value {
    json!({
        "name": name,
        "status": status,
        "platform": platform,
    })
}

fn event_at(mut event: Value, time: &str) -> Value {
    if let Some(object) = event.as_object_mut() {
        object.insert("time".to_string(), json!(time));
    }
    event
}

pub(crate) fn timestamp_now() -> String {
    match OffsetDateTime::now_utc().format(&Rfc3339) {
        Ok(timestamp) => timestamp,
        Err(_) => "1970-01-01T00:00:00Z".to_string(),
    }
}
