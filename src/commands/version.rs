use crate::control;
use serde_json::Value;

pub(crate) fn payload() -> Value {
    control::version_payload()
}

pub(crate) fn print_plain() -> Result<(), String> {
    println!("{}", env!("CARGO_PKG_VERSION"));
    Ok(())
}

pub(crate) fn print_json() -> Result<(), String> {
    println!("{}", payload());
    Ok(())
}
