use serde_json::Value;
use std::process::Output;

#[derive(Debug)]
pub struct BackendExecutionOutput {
    pub output: Output,
    pub timed_out: bool,
    pub cancelled: bool,
    pub events: Vec<Value>,
}
