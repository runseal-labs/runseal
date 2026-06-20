use crate::control;
use serde_json::Value;

pub(crate) fn payload() -> Value {
    control::capabilities_payload()
}

pub(crate) fn run() -> Result<(), String> {
    println!("{}", payload());
    Ok(())
}
