#[cfg(windows)]
use crate::backend;
use crate::error::RunSealError;
use crate::execution::{current_dir, normalize_execution_cwd};
#[cfg(windows)]
use crate::policy::{NetworkMode, normalize_policy};
use crate::protocol::error_payload::cli_error_payload;
use crate::setup::{windows_sandbox_setup_status_for_cwd, windows_sandbox_setup_status_payload};
#[cfg(windows)]
use crate::windows::vendor_adapter::WindowsVendorSandboxProfile;
use crate::{WINDOWS_SANDBOX_SETUP_FAILED, WINDOWS_SANDBOX_UNSUPPORTED};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const SETUP_HELP_TEXT: &str = "\
Usage: runseal setup windows-sandbox [--cwd <path>] [--status] [--json]

Windows sandbox setup:
  First install requires an elevated PowerShell; later repairs reuse the sandbox broker when available.
  Sandboxed exec fails closed when setup is missing or stale.
  --status reports setup readiness without changing setup state.
  --json reports setup failures as structured JSON.
";

pub(crate) fn run(args: &[String]) -> Result<(), String> {
    match args {
        [flag] if flag == "--help" || flag == "-h" => {
            print!("{SETUP_HELP_TEXT}");
            Ok(())
        }
        [target, flag] if target == "windows-sandbox" && (flag == "--help" || flag == "-h") => {
            print!("{SETUP_HELP_TEXT}");
            Ok(())
        }
        [target, rest @ ..] if target == "windows-sandbox" => {
            let json_output = rest.iter().any(|arg| arg == "--json");
            let request = match parse_windows_setup_args(rest) {
                Ok(request) => request,
                Err(err) if json_output => {
                    println!(
                        "{}",
                        cli_error_payload(RunSealError::new("INVALID_REQUEST", err))
                    );
                    return Err(String::new());
                }
                Err(err) => return Err(err),
            };
            if request.status {
                return run_windows_sandbox_setup_status(&request.cwd, request.json);
            }
            run_windows_sandbox_setup(&request.cwd, request.json)
        }
        _ if args.iter().any(|arg| arg == "--json") => {
            println!(
                "{}",
                cli_error_payload(RunSealError::new(
                    "INVALID_REQUEST",
                    "usage: runseal setup windows-sandbox [--cwd <path>] [--status] [--json]",
                ))
            );
            Err(String::new())
        }
        _ => Err(
            "usage: runseal setup windows-sandbox [--cwd <path>] [--status] [--json]".to_string(),
        ),
    }
}

struct WindowsSetupArgs {
    cwd: PathBuf,
    status: bool,
    json: bool,
}

fn parse_windows_setup_args(args: &[String]) -> Result<WindowsSetupArgs, String> {
    let mut cwd = current_dir();
    let mut status = false;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--cwd" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    "usage: runseal setup windows-sandbox [--cwd <path>] [--status] [--json]"
                        .to_string()
                })?;
                cwd = PathBuf::from(value);
            }
            "--status" => status = true,
            "--json" => json = true,
            _ => {
                return Err(
                    "usage: runseal setup windows-sandbox [--cwd <path>] [--status] [--json]"
                        .to_string(),
                );
            }
        }
        index += 1;
    }

    Ok(WindowsSetupArgs { cwd, status, json })
}

#[cfg(windows)]
fn run_windows_sandbox_setup(cwd: &Path, json_output: bool) -> Result<(), String> {
    let cwd = match normalize_execution_cwd(cwd) {
        Ok(cwd) => cwd,
        Err(err) => {
            if json_output {
                println!("{}", cli_error_payload(err));
                return Err(String::new());
            }
            return Err(err.message);
        }
    };
    let cwd = cwd.as_path();
    let setup_status = match windows_sandbox_setup_status_for_cwd(cwd) {
        Ok(status) => status,
        Err(err) if json_output => {
            println!(
                "{}",
                cli_error_payload(RunSealError::new("INTERNAL_ERROR", err))
            );
            return Err(String::new());
        }
        Err(err) => return Err(err),
    };
    if !windows_sandbox_setup_requires_setup(&setup_status) {
        println!("{}", windows_sandbox_setup_success_payload(cwd));
        return Ok(());
    }
    if !windows_sandbox_setup_can_run_now(&setup_status) {
        if json_output {
            println!(
                "{}",
                cli_error_payload(windows_sandbox_setup_failed_error(cwd))
            );
            return Err(String::new());
        }
        return Err(WINDOWS_SANDBOX_SETUP_FAILED.to_string());
    }
    let sandbox_home = backend::windows_sandbox_home(cwd);
    if let Err(err) = run_windows_sandbox_full_setup(cwd, &sandbox_home) {
        if json_output {
            println!(
                "{}",
                cli_error_payload(windows_sandbox_setup_failed_error_with_detail(cwd, &err))
            );
            return Err(String::new());
        }
        return Err(format!("{WINDOWS_SANDBOX_SETUP_FAILED}: {err}"));
    }
    println!("{}", windows_sandbox_setup_success_payload(cwd));
    Ok(())
}

#[cfg(windows)]
fn run_windows_sandbox_full_setup(cwd: &Path, sandbox_home: &Path) -> Result<(), String> {
    let policy = normalize_policy(&json!("workspace-write"), cwd, Some(NetworkMode::Disabled))
        .map_err(|err| err.reason)?;
    let vendor_profile = WindowsVendorSandboxProfile::from_policy(&policy);
    let permission_profile = vendor_profile.permission_profile()?;
    let workspace_roots = vec![
        codex_utils_absolute_path::AbsolutePathBuf::try_from(cwd)
            .map_err(|err| format!("invalid setup cwd {}: {err}", cwd.display()))?,
    ];
    let env_map = std::collections::HashMap::new();
    let permissions =
        codex_windows_sandbox::ResolvedWindowsSandboxPermissions::try_from_permission_profile_for_workspace_roots(
            &permission_profile,
            workspace_roots.as_slice(),
        )
        .map_err(|err| err.to_string())?;

    codex_windows_sandbox::run_elevated_setup(
        codex_windows_sandbox::SandboxSetupRequest {
            permissions: &permissions,
            command_cwd: cwd,
            env_map: &env_map,
            codex_home: sandbox_home,
            proxy_enforced: true,
        },
        codex_windows_sandbox::SetupRootOverrides {
            write_roots: Some(vec![cwd.to_path_buf()]),
            ..Default::default()
        },
    )
    .map_err(|err| err.to_string())
}

#[cfg(windows)]
fn run_windows_sandbox_setup_status(cwd: &Path, json_output: bool) -> Result<(), String> {
    let cwd = match normalize_execution_cwd(cwd) {
        Ok(cwd) => cwd,
        Err(err) => {
            if json_output {
                println!("{}", cli_error_payload(err));
                return Err(String::new());
            }
            return Err(err.message);
        }
    };
    println!("{}", windows_sandbox_setup_status_for_cwd(&cwd)?);
    Ok(())
}

#[cfg(not(windows))]
fn run_windows_sandbox_setup_status(cwd: &Path, json_output: bool) -> Result<(), String> {
    let cwd = match normalize_execution_cwd(cwd) {
        Ok(cwd) => cwd,
        Err(err) => {
            if json_output {
                println!("{}", cli_error_payload(err));
                return Err(String::new());
            }
            return Err(err.message);
        }
    };
    println!("{}", windows_sandbox_setup_status_for_cwd(&cwd)?);
    Ok(())
}

pub(crate) fn windows_sandbox_setup_failed_error(cwd: &Path) -> RunSealError {
    windows_sandbox_setup_failed_error_with_detail(cwd, "")
}

fn windows_sandbox_setup_failed_error_with_detail(cwd: &Path, detail: &str) -> RunSealError {
    let setup_status = windows_sandbox_setup_status_for_cwd(cwd).unwrap_or_else(|_| {
        windows_sandbox_setup_status_payload(cfg!(windows), false, false, None)
    });
    let (code, reason) = if cfg!(windows) {
        ("WINDOWS_SANDBOX_SETUP_FAILED", WINDOWS_SANDBOX_SETUP_FAILED)
    } else {
        ("WINDOWS_SANDBOX_UNSUPPORTED", WINDOWS_SANDBOX_UNSUPPORTED)
    };
    let mut details = json!({ "setup_status": setup_status });
    if !detail.is_empty() {
        details["detail"] = json!(detail);
    }
    RunSealError::with_details(code, reason, details)
}

#[cfg(windows)]
fn windows_sandbox_setup_can_run_now(setup_status: &Value) -> bool {
    setup_status["can_run_setup_now"].as_bool().unwrap_or(false)
}

#[cfg(windows)]
fn windows_sandbox_setup_requires_setup(setup_status: &Value) -> bool {
    setup_status["requires_setup"].as_bool().unwrap_or(true)
}

#[cfg(windows)]
pub(crate) fn windows_sandbox_setup_success_payload(cwd: &Path) -> Value {
    let mut payload = json!({
        "status": "ok",
        "setup": "windows-sandbox",
    });
    if let (Some(payload), Ok(setup_status)) = (
        payload.as_object_mut(),
        windows_sandbox_setup_status_for_cwd(cwd),
    ) {
        payload.insert("setup_status".to_string(), setup_status);
    }
    payload
}

#[cfg(not(windows))]
fn run_windows_sandbox_setup(cwd: &Path, json_output: bool) -> Result<(), String> {
    let cwd = match normalize_execution_cwd(cwd) {
        Ok(cwd) => cwd,
        Err(err) => {
            if json_output {
                println!("{}", cli_error_payload(err));
                return Err(String::new());
            }
            return Err(err.message);
        }
    };
    if json_output {
        println!(
            "{}",
            cli_error_payload(windows_sandbox_setup_failed_error(&cwd))
        );
        return Err(String::new());
    }
    Err(WINDOWS_SANDBOX_UNSUPPORTED.to_string())
}
