use crate::backend::{SandboxBackend, active_backend};
use crate::execution::current_dir;
use crate::setup::windows_sandbox_setup_status_for_cwd;
use serde_json::Value;

pub(crate) fn payload() -> Value {
    let mut payload = active_backend().capabilities_json();
    if let (Some(payload), Ok(setup_status)) = (
        payload.as_object_mut(),
        windows_sandbox_setup_status_for_cwd(&current_dir()),
    ) {
        payload.insert("setup_status".to_string(), setup_status);
    }
    payload
}

pub(crate) fn run() -> Result<(), String> {
    println!("{}", payload());
    Ok(())
}
