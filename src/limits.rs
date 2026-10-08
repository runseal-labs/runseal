use crate::error::RunSealError;
use std::sync::OnceLock;

#[derive(Clone, Copy)]
pub(crate) struct DeploymentLimits {
    pub(crate) max_active_executions: usize,
    pub(crate) replay_execution_bytes: usize,
    pub(crate) replay_connection_bytes: usize,
    pub(crate) completed_executions: usize,
    pub(crate) completed_execution_bytes: usize,
    pub(crate) audit_cache_bytes: usize,
    pub(crate) stream_chunk_bytes: usize,
    pub(crate) input_pending_bytes: usize,
    pub(crate) rpc_frame_bytes: usize,
    pub(crate) max_output_bytes: usize,
    pub(crate) sender_bytes: usize,
    pub(crate) backpressure_ms: usize,
    pub(crate) cleanup_timeout_ms: usize,
}

impl Default for DeploymentLimits {
    fn default() -> Self {
        Self {
            max_active_executions: 8,
            replay_execution_bytes: 1024 * 1024,
            replay_connection_bytes: 8 * 1024 * 1024,
            completed_executions: 1024,
            completed_execution_bytes: 8 * 1024 * 1024,
            audit_cache_bytes: 8 * 1024 * 1024,
            stream_chunk_bytes: 64 * 1024,
            input_pending_bytes: 256 * 1024,
            rpc_frame_bytes: 1024 * 1024,
            max_output_bytes: 16 * 1024 * 1024,
            sender_bytes: 8 * 1024 * 1024,
            backpressure_ms: 5000,
            cleanup_timeout_ms: 10000,
        }
    }
}

impl DeploymentLimits {
    pub(crate) fn backpressure_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.backpressure_ms as u64)
    }

    pub(crate) fn cleanup_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.cleanup_timeout_ms as u64)
    }

    pub(crate) fn queued_protocol_bytes(&self) -> usize {
        self.sender_bytes - 2 * 1024 * 1024
    }

    pub(crate) fn protocol_data_bytes(&self) -> usize {
        self.queued_protocol_bytes() - 1024 * 1024
    }

    pub(crate) fn query_response_bytes(&self) -> usize {
        self.rpc_frame_bytes.min(256 * 1024)
    }
}

static LIMITS: OnceLock<DeploymentLimits> = OnceLock::new();

pub(crate) fn initialize() -> Result<(), RunSealError> {
    let defaults = DeploymentLimits::default();
    let max_active_executions = configured_integer(
        "RUNSEAL_MAX_ACTIVE_EXECUTIONS",
        defaults.max_active_executions,
        1,
        64,
    )?;
    let replay_execution_bytes = configured_integer(
        "RUNSEAL_REPLAY_EXECUTION_BYTES",
        defaults.replay_execution_bytes,
        64 * 1024,
        64 * 1024 * 1024,
    )?;
    let replay_connection_bytes = configured_integer(
        "RUNSEAL_REPLAY_CONNECTION_BYTES",
        defaults.replay_connection_bytes,
        64 * 1024,
        256 * 1024 * 1024,
    )?;
    if replay_connection_bytes < replay_execution_bytes {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            "deployment replay connection budget must cover the per-execution budget",
        ));
    }
    let completed_executions = configured_integer(
        "RUNSEAL_COMPLETED_EXECUTIONS",
        defaults.completed_executions,
        1,
        65536,
    )?;
    let completed_execution_bytes = configured_integer(
        "RUNSEAL_COMPLETED_EXECUTION_BYTES",
        defaults.completed_execution_bytes,
        64 * 1024,
        256 * 1024 * 1024,
    )?;
    let audit_cache_bytes = configured_integer(
        "RUNSEAL_AUDIT_CACHE_BYTES",
        defaults.audit_cache_bytes,
        64 * 1024,
        256 * 1024 * 1024,
    )?;
    let stream_chunk_bytes = configured_integer(
        "RUNSEAL_STREAM_CHUNK_BYTES",
        defaults.stream_chunk_bytes,
        8 * 1024,
        64 * 1024,
    )?;
    let input_pending_bytes = configured_integer(
        "RUNSEAL_INPUT_PENDING_BYTES",
        defaults.input_pending_bytes,
        8 * 1024,
        16 * 1024 * 1024,
    )?;
    if input_pending_bytes < stream_chunk_bytes {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            "deployment input pending budget must cover the chunk limit",
        ));
    }
    let rpc_frame_bytes = configured_integer(
        "RUNSEAL_RPC_FRAME_BYTES",
        defaults.rpc_frame_bytes,
        128 * 1024,
        1024 * 1024,
    )?;
    let max_output_bytes = configured_integer(
        "RUNSEAL_MAX_OUTPUT_BYTES",
        defaults.max_output_bytes,
        1,
        16 * 1024 * 1024,
    )?;
    let _ = LIMITS.set(DeploymentLimits {
        max_active_executions,
        replay_execution_bytes,
        replay_connection_bytes,
        completed_executions,
        completed_execution_bytes,
        audit_cache_bytes,
        stream_chunk_bytes,
        input_pending_bytes,
        rpc_frame_bytes,
        max_output_bytes,
        sender_bytes: configured_integer(
            "RUNSEAL_SENDER_BYTES",
            defaults.sender_bytes,
            5 * 1024 * 1024,
            64 * 1024 * 1024,
        )?,
        cleanup_timeout_ms: configured_integer(
            "RUNSEAL_CLEANUP_TIMEOUT_MS",
            defaults.cleanup_timeout_ms,
            100,
            60000,
        )?,
        backpressure_ms: configured_integer(
            "RUNSEAL_BACKPRESSURE_MS",
            defaults.backpressure_ms,
            100,
            60000,
        )?,
    });
    Ok(())
}

pub(crate) fn deployment() -> &'static DeploymentLimits {
    LIMITS.get_or_init(DeploymentLimits::default)
}

fn configured_integer(
    name: &str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, RunSealError> {
    match std::env::var_os(name) {
        None => Ok(default),
        Some(value) => value
            .to_str()
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| (minimum..=maximum).contains(value))
            .ok_or_else(|| {
                RunSealError::new(
                    "INVALID_REQUEST",
                    format!(
                        "deployment limit {name} must be an integer from {minimum} to {maximum}"
                    ),
                )
            }),
    }
}
