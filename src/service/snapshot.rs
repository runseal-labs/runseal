use serde_json::{Value, json};

#[cfg(test)]
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

pub(super) fn response(
    id: Value,
    field: &str,
    items: Vec<Value>,
    mut result: Value,
    mut truncated: bool,
) -> Value {
    let max_response_bytes = crate::limits::deployment().query_response_bytes();
    result[field] = json!([]);
    result["count"] = json!(0);
    result["truncated"] = json!(true);
    let overhead = crate::rpc::result(id.clone(), result.clone())
        .to_string()
        .len()
        + 32;
    let mut remaining = max_response_bytes.saturating_sub(overhead);
    let mut tail = Vec::new();
    for mut item in items.into_iter().rev() {
        let mut size = item.to_string().len() + 1;
        if size > max_response_bytes.saturating_sub(overhead) {
            item = json!({"omitted":true,"execution_id":item["execution_id"],"event_seq":item["event_seq"]});
            size = item.to_string().len() + 1;
            truncated = true;
        }
        if size > remaining {
            truncated = true;
            break;
        }
        remaining -= size;
        tail.push(item);
    }
    tail.reverse();
    result["count"] = json!(tail.len());
    result[field] = json!(tail);
    result["truncated"] = json!(truncated);
    crate::rpc::result(id, result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keeps_newest_complete_records_inside_the_envelope_limit() {
        let records = (0..80)
            .map(|index| json!({"execution_id":format!("exec_{index}"),"payload":"x".repeat(8192)}))
            .collect();
        let message = response(json!("id".repeat(64)), "events", records, json!({}), false);
        assert!(message.to_string().len() <= MAX_RESPONSE_BYTES);
        assert_eq!(message["result"]["truncated"], true);
        let events = message["result"]["events"].as_array().unwrap();
        assert_eq!(events.last().unwrap()["execution_id"], "exec_79");
        assert_eq!(
            events.first().unwrap()["payload"].as_str().unwrap().len(),
            8192
        );
    }
    #[test]
    fn oversized_record_is_an_identified_omission() {
        let message = response(
            json!(1),
            "events",
            vec![
                json!({"execution_id":"exec_large","event_seq":3,"payload":"x".repeat(MAX_RESPONSE_BYTES)}),
            ],
            json!({}),
            false,
        );
        assert!(message.to_string().len() <= MAX_RESPONSE_BYTES);
        assert_eq!(message["result"]["events"][0]["omitted"], true);
        assert_eq!(message["result"]["events"][0]["execution_id"], "exec_large");
        assert_eq!(message["result"]["truncated"], true);
    }
}
