mod control;
mod engine;
mod errors;
mod journal;
mod output;
mod paths;
mod preparation;
pub(crate) mod retained;
#[cfg(windows)]
pub(crate) use control::TerminalCommand;
pub(crate) use control::{ExecutionControl, TerminationCause};
#[cfg(windows)]
pub(crate) use errors::windows_setup_status_for_backend_error;

use crate::backend::{ExecutionEnv, ExecutionStdin};
use crate::policy::SandboxPolicy;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;

/// Owned request shared by all entry points; it can move to the lifecycle worker.
pub(crate) struct ExecutionRequest {
    pub ids: crate::events::ExecutionIds,
    pub control: ExecutionControl,
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub policy: SandboxPolicy,
    pub stdin: ExecutionStdin,
    pub control_input: Option<crate::backend::ExecutionInput>,
    pub io: crate::backend::ExecutionIo,
    pub env: ExecutionEnv,
    pub metadata: Option<Value>,
    pub timeout: Option<Duration>,
}

pub(crate) use engine::execute_command;
pub(crate) use engine::{ExecutionObserver, execute_command_with_observer};
pub(crate) use output::audit_stream_event_metadata;
#[cfg(not(windows))]
pub(crate) use paths::validate_execution_cwd;
pub(crate) use paths::{current_dir, normalize_execution_cwd};

pub(crate) use engine::execute_prepared_after_admission_with_observer;
#[cfg(all(test, windows))]
pub(crate) use engine::execute_prepared_with_events;
pub(crate) use journal::ExecutionJournal;
