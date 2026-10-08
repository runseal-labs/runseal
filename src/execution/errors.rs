use crate::backend::{backend_unavailable_reason, policy_transition_busy_reason};
use serde_json::Value;
use std::io;
use std::path::Path;

pub(crate) fn backend_execution_error(
    err: &io::Error,
    sandbox_enforced: bool,
    cwd: &Path,
) -> Option<(&'static str, String, Option<Value>)> {
    if let Some(reason) = policy_transition_busy_reason(err) {
        return Some(("POLICY_TRANSITION_BUSY", reason.to_string(), None));
    }
    if sandbox_enforced && let Some(reason) = backend_unavailable_reason(err) {
        return Some((
            "BACKEND_UNAVAILABLE",
            reason.to_string(),
            backend_unavailable_setup_status(reason, cwd),
        ));
    }
    None
}

fn backend_unavailable_setup_status(reason: &str, cwd: &Path) -> Option<Value> {
    #[cfg(windows)]
    {
        if reason.starts_with("windows sandbox") {
            return Some(windows_setup_status_or_fallback(
                crate::commands::setup::windows_sandbox_setup_status_for_cwd(cwd),
            ));
        }
    }

    #[cfg(not(windows))]
    {
        let _ = (reason, cwd);
    }

    None
}

#[cfg(windows)]
fn windows_setup_status_or_fallback(status: Result<Value, String>) -> Value {
    status.unwrap_or_else(|_| {
        crate::commands::setup::windows_sandbox_setup_status_payload(true, false, false, None)
    })
}

#[cfg(windows)]
pub(crate) fn windows_setup_status_for_backend_error(cwd: &Path) -> Value {
    windows_setup_status_or_fallback(
        crate::commands::setup::windows_sandbox_setup_status_for_cwd(cwd),
    )
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn sandboxed_spawn_error_is_not_backend_unavailable() {
        let err = io::Error::other("runner failed");

        assert_eq!(backend_execution_error(&err, true, Path::new(".")), None);
    }

    #[test]
    fn windows_sandbox_binding_unavailability_includes_setup_status() {
        let setup_status = backend_unavailable_setup_status(
            "windows sandbox process binding unavailable",
            Path::new("."),
        )
        .expect("Windows sandbox availability errors include setup status");

        assert_eq!(setup_status["setup"], "windows-sandbox");
    }

    #[cfg(windows)]
    #[test]
    fn unavailable_setup_status_probe_keeps_structured_fail_closed_status() {
        let setup_status = windows_setup_status_or_fallback(Err("probe unavailable".into()));

        assert_eq!(setup_status["setup"], "windows-sandbox");
        assert_eq!(setup_status["platform_supported"], true);
        assert_eq!(setup_status["elevated"], Value::Null);
        assert_eq!(setup_status["can_repair"], false);
        assert_eq!(setup_status["can_run_setup_now"], false);
        assert_eq!(setup_status["next_action"], "open_elevated_shell");
    }

    #[cfg(windows)]
    #[test]
    fn policy_transition_busy_maps_to_public_error_code() {
        let err = crate::backend::policy_transition_busy_error_for_test();
        let (code, reason, setup_status) = backend_execution_error(&err, true, Path::new("."))
            .expect("busy error must map to public code");

        assert_eq!(code, "POLICY_TRANSITION_BUSY");
        assert!(reason.contains("policy transition busy"));
        assert_eq!(setup_status, None);
    }
}
