use super::*;

pub(crate) fn payload() -> Value {
    attach_windows_setup_status(active_backend().capabilities_json())
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
