mod engine;
mod errors;
mod output;
mod paths;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionStdin {
    Empty,
    Bytes(Vec<u8>),
    File(Vec<u8>),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExecutionEnv {
    pub entries: Vec<(String, String)>,
}

impl ExecutionEnv {
    pub fn keys(&self) -> Vec<String> {
        self.entries.iter().map(|(key, _)| key.clone()).collect()
    }
}

pub(crate) use engine::{execute_command, execute_command_with_ids};
pub(crate) use output::audit_stream_event_metadata;
#[cfg(not(windows))]
pub(crate) use paths::validate_execution_cwd;
pub(crate) use paths::{current_dir, normalize_execution_cwd};
