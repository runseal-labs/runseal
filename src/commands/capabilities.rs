use super::*;

pub(crate) fn payload() -> Value {
    let mut payload = attach_windows_setup_status(active_backend().capabilities_json());
    payload["limits"] = serde_json::json!({
        "max_active_executions": crate::limits::deployment().max_active_executions,
        "replay_execution_bytes": crate::limits::deployment().replay_execution_bytes,
        "replay_connection_bytes": crate::limits::deployment().replay_connection_bytes,
        "completed_executions": crate::limits::deployment().completed_executions,
        "completed_execution_bytes": crate::limits::deployment().completed_execution_bytes,
        "audit_cache_bytes": crate::limits::deployment().audit_cache_bytes,
        "stream_chunk_bytes": crate::limits::deployment().stream_chunk_bytes,
        "input_pending_bytes": crate::limits::deployment().input_pending_bytes,
        "rpc_frame_bytes": crate::limits::deployment().rpc_frame_bytes,
        "max_output_bytes": crate::limits::deployment().max_output_bytes,
        "sender_bytes": crate::limits::deployment().sender_bytes,
        "backpressure_ms": crate::limits::deployment().backpressure_ms,
        "cleanup_timeout_ms": crate::limits::deployment().cleanup_timeout_ms,
        "query_response_bytes": crate::limits::deployment().query_response_bytes(),
    });
    payload
}

#[cfg(windows)]
fn attach_windows_setup_status(mut payload: Value) -> Value {
    if let (Some(payload), Ok(setup_status)) = (
        payload.as_object_mut(),
        windows_sandbox_setup_status_for_cwd(&current_dir()),
    ) {
        payload.insert("setup_status".to_string(), setup_status);
    }
    payload
}

#[cfg(not(windows))]
fn attach_windows_setup_status(payload: Value) -> Value {
    payload
}

pub(crate) fn run() -> Result<(), String> {
    println!("{}", payload());
    Ok(())
}
