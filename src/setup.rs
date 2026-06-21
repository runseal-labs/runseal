#[cfg(windows)]
use crate::backend;
#[cfg(not(windows))]
use crate::execution::validate_execution_cwd;
use serde_json::{Value, json};
use std::path::Path;

#[cfg(windows)]
pub(crate) fn windows_sandbox_setup_status_for_cwd(cwd: &Path) -> Result<Value, String> {
    let sandbox_home = backend::windows_sandbox_home(cwd);
    let broker_available =
        codex_windows_sandbox::provisioning_setup_broker_is_available(&sandbox_home);
    let setup_complete = codex_windows_sandbox::sandbox_setup_is_complete(&sandbox_home);
    let elevated = codex_windows_sandbox::current_process_is_elevated()
        .map_err(|err| format!("windows sandbox setup status failed: {err}"))?;
    Ok(windows_sandbox_setup_status_payload(
        true,
        setup_complete,
        broker_available,
        Some(elevated),
    ))
}

#[cfg(not(windows))]
pub(crate) fn windows_sandbox_setup_status_for_cwd(cwd: &Path) -> Result<Value, String> {
    validate_execution_cwd(cwd).map_err(|err| err.message)?;
    Ok(windows_sandbox_setup_status_payload(
        false, false, false, None,
    ))
}

pub(crate) fn windows_sandbox_setup_status_payload(
    platform_supported: bool,
    setup_complete: bool,
    broker_available: bool,
    elevated: Option<bool>,
) -> Value {
    let requires_setup = platform_supported && !setup_complete;
    let can_run_setup_now = requires_setup && (elevated.unwrap_or(false) || broker_available);
    let next_action = if !platform_supported {
        "unsupported"
    } else if setup_complete {
        "none"
    } else if can_run_setup_now {
        "run_setup"
    } else {
        "open_elevated_shell"
    };
    let next_command = match next_action {
        "run_setup" | "open_elevated_shell" => {
            Some("runseal setup windows-sandbox --cwd <absolute-workspace-path> --json")
        }
        _ => None,
    };
    json!({
        "setup": "windows-sandbox",
        "platform_supported": platform_supported,
        "broker": if broker_available { "available" } else { "unavailable" },
        "elevated": elevated,
        "can_repair": can_run_setup_now,
        "can_run_setup_now": can_run_setup_now,
        "requires_setup": requires_setup,
        "next_action": next_action,
        "next_command": next_command,
    })
}
