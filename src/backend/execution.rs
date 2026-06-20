use super::*;

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

#[derive(Debug)]
pub struct BackendExecutionOutput {
    pub output: Output,
    pub timed_out: bool,
    pub events: Vec<Value>,
}
