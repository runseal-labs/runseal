use serde_json::Value;
use std::process::Output;

pub(crate) fn truncate_output(output: &mut Output, max_output_bytes: Option<u64>) -> bool {
    let Some(max_output_bytes) = max_output_bytes.and_then(|value| usize::try_from(value).ok())
    else {
        return false;
    };
    let original_stdout_len = output.stdout.len();
    let original_stderr_len = output.stderr.len();

    let stdout_len = output.stdout.len().min(max_output_bytes);
    output.stdout.truncate(stdout_len);
    let stderr_budget = max_output_bytes.saturating_sub(stdout_len);
    output
        .stderr
        .truncate(output.stderr.len().min(stderr_budget));

    output.stdout.len() != original_stdout_len || output.stderr.len() != original_stderr_len
}

pub(crate) fn audit_stream_event_metadata(event: &Value) -> Value {
    let mut event = event.clone();
    if let Some(object) = event.as_object_mut() {
        object.remove("data");
        object.remove("text");
    }
    event
}
