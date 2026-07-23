mod audit;
mod backend;
mod cli;
mod commands;
mod error;
mod events;
mod execution;
mod linux;
mod macos;
mod policy;
mod process_output;
mod protocol;
mod rpc;
mod service;
mod stdin;
mod windows;

#[cfg(windows)]
use crate::windows::vendor_adapter::WindowsVendorSandboxProfile;
use backend::{ExecutionEnv, ExecutionStdin, SandboxBackend, active_backend};
use cli::{parse_exec_args, parse_policy_args};
#[cfg(all(test, not(windows)))]
use commands::setup::{windows_sandbox_setup_failed_error, windows_sandbox_setup_status_payload};
#[cfg(all(test, windows))]
use commands::setup::{
    windows_sandbox_setup_failed_error, windows_sandbox_setup_status_payload,
    windows_sandbox_setup_success_payload,
};
use error::RunSealError;
use policy::{POLICY_VERSION, SandboxPolicy, normalize_policy};
use serde_json::{Value, json};
use std::env;
use std::path::{Path, PathBuf};

const PROTOCOL_VERSION: &str = "runseal.protocol/v1";
const MAX_METADATA_BYTES: usize = 4096;
const MAX_PROTOCOL_ID_BYTES: usize = 128;
const MAX_ENV_ENTRIES: usize = 64;
const MAX_ENV_KEY_BYTES: usize = 128;
const MAX_ENV_VALUE_BYTES: usize = 4096;
const WINDOWS_SANDBOX_SETUP_FAILED: &str = "windows sandbox setup failed; first install requires an elevated shell; later repairs can reuse the setup broker";
const WINDOWS_SANDBOX_UNSUPPORTED: &str = "windows sandbox setup is only supported on Windows";

pub fn run_cli() {
    if let Err(err) = run() {
        if !err.is_empty() {
            eprintln!("{err}");
        }
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [flag] if flag == "--help" || flag == "-h" => commands::print_help(),
        [command] if command == "help" => commands::print_help(),
        [flag] if flag == "--version" => commands::version::print_plain(),
        [json_flag, command] if json_flag == "--json" && command == "version" => {
            commands::version::print_json()
        }
        [command, json_flag] if command == "version" && json_flag == "--json" => {
            commands::version::print_json()
        }
        [command] if command == "version" => commands::version::print_plain(),
        [command] if command == "capabilities" => commands::capabilities::run(),
        #[cfg(target_os = "linux")]
        [command, rest @ ..] if command == "__linux-proxy-relay" => {
            backend::run_linux_proxy_relay(rest).map(|code| std::process::exit(code))
        }
        [command, flag] if command == "rpc" && flag == "--stdio" => {
            protocol::rpc_handler::run_rpc_stdio()
        }
        [command, rest @ ..] if command == "mcp" => commands::mcp::run(rest),
        [command, flag] if command == "service" && flag == "--stdio" => {
            protocol::rpc_handler::run_service_stdio()
        }
        [command, flag, ..] if command == "service" && (flag == "--pipe" || flag == "--socket") => {
            Err(format!(
                "service {flag} requires a local service transport RFC and is not implemented"
            ))
        }
        [command, flag, ..] if command == "service" && (flag == "--tcp" || flag == "--http") => {
            Err(format!(
                "service {flag} requires a remote transport RFC and is not implemented"
            ))
        }
        [command, flag] if command == "service" && (flag == "--tcp" || flag == "--http") => Err(
            format!("service {flag} requires a remote transport RFC and is not implemented"),
        ),
        [command, rest @ ..] if command == "setup" => commands::setup::run(rest),
        [command, rest @ ..] if command == "explain-policy" => commands::explain_policy::run(rest),
        [command, rest @ ..] if command == "exec" => commands::exec::run(rest),
        [] => Err("missing command".to_string()),
        _ => Err(format!("unknown command: {}", args.join(" "))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::new_execution_ids;
    use crate::protocol::request_validation::duration_millis_u64;
    use std::collections::HashSet;
    use std::time::Duration;

    #[test]
    fn execution_ids_are_unique_for_fast_local_requests() {
        let mut execution_ids = HashSet::new();
        let mut session_ids = HashSet::new();
        let mut seal_ids = HashSet::new();

        for _ in 0..4096 {
            let ids = new_execution_ids();
            assert!(execution_ids.insert(ids.execution_id));
            assert!(session_ids.insert(ids.session_id));
            assert!(seal_ids.insert(ids.seal_id));
        }
    }

    #[test]
    fn windows_setup_failure_message_hides_vendor_codes() {
        assert!(!WINDOWS_SANDBOX_SETUP_FAILED.contains("orchestrator_"));
        assert!(!WINDOWS_SANDBOX_SETUP_FAILED.contains("helper_"));
        assert!(WINDOWS_SANDBOX_SETUP_FAILED.contains("first install requires an elevated shell"));
        assert!(WINDOWS_SANDBOX_SETUP_FAILED.contains("repairs can reuse the setup broker"));
        assert!(!WINDOWS_SANDBOX_SETUP_FAILED.contains("install or repair requires"));
    }

    #[test]
    fn windows_setup_failed_json_includes_setup_status() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = windows_sandbox_setup_failed_error(tmp.path());
        let expected_code = if cfg!(windows) {
            "WINDOWS_SANDBOX_SETUP_FAILED"
        } else {
            "WINDOWS_SANDBOX_UNSUPPORTED"
        };
        let expected_reason = if cfg!(windows) {
            WINDOWS_SANDBOX_SETUP_FAILED
        } else {
            WINDOWS_SANDBOX_UNSUPPORTED
        };

        assert_eq!(err.code, expected_code);
        assert_eq!(err.reason, expected_reason);
        let details = err.details.expect("details");
        assert_eq!(details["setup_status"]["setup"], "windows-sandbox");
        assert!(details["setup_status"]["next_action"].as_str().is_some());
    }

    #[cfg(windows)]
    #[test]
    fn windows_setup_success_payload_hides_internal_paths() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let payload = windows_sandbox_setup_success_payload(tmp.path());

        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["setup"], "windows-sandbox");
        assert_eq!(payload["setup_status"]["setup"], "windows-sandbox");
        assert!(payload.get("sandbox_home").is_none());
        assert!(payload.get("profile_root").is_none());
        assert!(payload.get("runtime_root").is_none());
    }

    #[test]
    fn windows_setup_status_can_repair_via_elevation_or_broker() {
        let elevated = windows_sandbox_setup_status_payload(true, false, false, Some(true));
        let broker = windows_sandbox_setup_status_payload(true, false, true, Some(false));
        let ready = windows_sandbox_setup_status_payload(true, true, false, Some(false));
        let missing = windows_sandbox_setup_status_payload(true, false, false, Some(false));
        let unsupported = windows_sandbox_setup_status_payload(false, false, true, Some(true));

        assert_eq!(elevated["can_repair"], true);
        assert_eq!(elevated["can_run_setup_now"], true);
        assert_eq!(elevated["requires_setup"], true);
        assert_eq!(elevated["next_action"], "run_setup");
        assert_eq!(
            elevated["next_command"],
            "runseal setup windows-sandbox --cwd <absolute-workspace-path> --json"
        );
        assert_eq!(broker["can_repair"], true);
        assert_eq!(broker["can_run_setup_now"], true);
        assert_eq!(broker["requires_setup"], true);
        assert_eq!(broker["next_action"], "run_setup");
        assert_eq!(
            broker["next_command"],
            "runseal setup windows-sandbox --cwd <absolute-workspace-path> --json"
        );
        assert_eq!(ready["can_repair"], false);
        assert_eq!(ready["can_run_setup_now"], false);
        assert_eq!(ready["requires_setup"], false);
        assert_eq!(ready["next_action"], "none");
        assert!(ready["next_command"].is_null());
        assert_eq!(missing["can_repair"], false);
        assert_eq!(missing["can_run_setup_now"], false);
        assert_eq!(missing["requires_setup"], true);
        assert_eq!(missing["next_action"], "open_elevated_shell");
        assert_eq!(
            missing["next_command"],
            "runseal setup windows-sandbox --cwd <absolute-workspace-path> --json --elevate"
        );
        assert_eq!(unsupported["can_repair"], false);
        assert_eq!(unsupported["can_run_setup_now"], false);
        assert_eq!(unsupported["requires_setup"], false);
        assert_eq!(unsupported["next_action"], "unsupported");
        assert!(unsupported["next_command"].is_null());
    }

    #[test]
    fn duration_millis_conversion_saturates_to_u64() {
        assert_eq!(duration_millis_u64(Duration::from_millis(42)), 42);
        assert_eq!(duration_millis_u64(Duration::MAX), u64::MAX);
    }
}
