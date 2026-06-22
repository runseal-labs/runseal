use super::*;
#[cfg(not(windows))]
use crate::execution::validate_execution_cwd;
#[cfg(windows)]
use crate::policy::NetworkMode;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

const SETUP_HELP_TEXT: &str = "\
Usage: runseal setup windows-sandbox [--cwd <path>] [--status] [--json] [--elevate]

Windows sandbox setup:
  Use --elevate to request UAC when first install cannot run in the current shell.
  Later repairs reuse the sandbox broker when available.
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
            run_windows_sandbox_setup(&request.cwd, request.json, request.elevate)
        }
        _ if args.iter().any(|arg| arg == "--json") => {
            println!(
                "{}",
                cli_error_payload(RunSealError::new(
                    "INVALID_REQUEST",
                    "usage: runseal setup windows-sandbox [--cwd <path>] [--status] [--json] [--elevate]",
                ))
            );
            Err(String::new())
        }
        _ => Err(
            "usage: runseal setup windows-sandbox [--cwd <path>] [--status] [--json] [--elevate]"
                .to_string(),
        ),
    }
}

struct WindowsSetupArgs {
    cwd: PathBuf,
    status: bool,
    json: bool,
    elevate: bool,
}

fn parse_windows_setup_args(args: &[String]) -> Result<WindowsSetupArgs, String> {
    let mut cwd = current_dir();
    let mut status = false;
    let mut json = false;
    let mut elevate = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--cwd" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    "usage: runseal setup windows-sandbox [--cwd <path>] [--status] [--json] [--elevate]"
                        .to_string()
                })?;
                cwd = PathBuf::from(value);
            }
            "--status" => status = true,
            "--json" => json = true,
            "--elevate" => elevate = true,
            _ => {
                return Err(
                    "usage: runseal setup windows-sandbox [--cwd <path>] [--status] [--json] [--elevate]"
                        .to_string(),
                );
            }
        }
        index += 1;
    }

    Ok(WindowsSetupArgs {
        cwd,
        status,
        json,
        elevate,
    })
}

#[cfg(windows)]
fn run_windows_sandbox_setup(cwd: &Path, json_output: bool, elevate: bool) -> Result<(), String> {
    run_windows_sandbox_setup_inner(cwd, json_output, elevate)
}

#[cfg(windows)]
fn run_windows_sandbox_setup_inner(
    cwd: &Path,
    json_output: bool,
    elevate: bool,
) -> Result<(), String> {
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
                cli_error_payload(RunSealError::new(
                    "WINDOWS_SANDBOX_SETUP_STATUS_FAILED",
                    err,
                ))
            );
            return Err(String::new());
        }
        Err(err) => return Err(err),
    };
    if !windows_sandbox_setup_requires_setup(&setup_status) {
        println!("{}", windows_sandbox_setup_success_payload(cwd));
        return Ok(());
    }
    if elevate && setup_status["elevated"].as_bool() == Some(false) {
        return request_elevated_windows_sandbox_setup(cwd, json_output, setup_status);
    }
    if !windows_sandbox_setup_can_run_now(&setup_status) {
        if elevate {
            return request_elevated_windows_sandbox_setup(cwd, json_output, setup_status);
        }
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
fn request_elevated_windows_sandbox_setup(
    cwd: &Path,
    json_output: bool,
    setup_status: Value,
) -> Result<(), String> {
    request_elevated_windows_sandbox_setup_launch(cwd, json_output)?;
    if json_output {
        println!(
            "{}",
            json!({
                "status": "elevation_requested",
                "setup": "windows-sandbox",
                "setup_status": setup_status,
            })
        );
    } else {
        println!("windows sandbox setup elevation requested");
    }
    Ok(())
}

#[cfg(windows)]
fn request_elevated_windows_sandbox_setup_launch(
    cwd: &Path,
    json_output: bool,
) -> Result<(), String> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let exe = std::env::current_exe().map_err(|err| format!("locate current executable: {err}"))?;
    let mut args = vec![
        "setup".to_string(),
        "windows-sandbox".to_string(),
        "--cwd".to_string(),
        cwd.as_os_str().to_string_lossy().into_owned(),
    ];
    if json_output {
        args.push("--json".to_string());
    }
    let params = args
        .iter()
        .map(|arg| quote_windows_arg(arg))
        .collect::<Vec<_>>()
        .join(" ");
    let verb = wide_null("runas");
    let exe = wide_os_null(exe.as_os_str());
    let params = wide_null(&params);

    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            exe.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            SW_HIDE,
        )
    } as isize;
    if result <= 32 {
        return Err(format!(
            "request UAC elevation failed with ShellExecuteW code {result}"
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn quote_windows_arg(arg: &str) -> String {
    if arg.is_empty()
        || arg
            .bytes()
            .any(|byte| byte == b' ' || byte == b'\t' || byte == b'"')
    {
        let mut quoted = String::from("\"");
        let mut backslashes = 0;
        for ch in arg.chars() {
            match ch {
                '\\' => backslashes += 1,
                '"' => {
                    quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                    quoted.push('"');
                    backslashes = 0;
                }
                _ => {
                    quoted.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                    quoted.push(ch);
                }
            }
        }
        quoted.push_str(&"\\".repeat(backslashes * 2));
        quoted.push('"');
        quoted
    } else {
        arg.to_string()
    }
}

#[cfg(windows)]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn wide_os_null(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(all(test, windows))]
mod tests {
    use super::quote_windows_arg;

    #[test]
    fn windows_elevation_args_are_quoted_for_shell_execute() {
        assert_eq!(quote_windows_arg("setup"), "setup");
        assert_eq!(
            quote_windows_arg("C:\\Program Files\\RunSeal"),
            "\"C:\\Program Files\\RunSeal\""
        );
        assert_eq!(quote_windows_arg("quoted\"arg"), "\"quoted\\\"arg\"");
        assert_eq!(quote_windows_arg("trailing\\"), "trailing\\");
        assert_eq!(quote_windows_arg("needs space\\"), "\"needs space\\\\\"");
    }
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
    let setup_status = match windows_sandbox_setup_status_for_cwd(&cwd) {
        Ok(status) => status,
        Err(err) if json_output => {
            println!(
                "{}",
                cli_error_payload(RunSealError::new(
                    "WINDOWS_SANDBOX_SETUP_STATUS_FAILED",
                    err,
                ))
            );
            return Err(String::new());
        }
        Err(err) => return Err(err),
    };
    println!("{setup_status}");
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
    let setup_status = match windows_sandbox_setup_status_for_cwd(&cwd) {
        Ok(status) => status,
        Err(err) if json_output => {
            println!(
                "{}",
                cli_error_payload(RunSealError::new(
                    "WINDOWS_SANDBOX_SETUP_STATUS_FAILED",
                    err,
                ))
            );
            return Err(String::new());
        }
        Err(err) => return Err(err),
    };
    println!("{setup_status}");
    Ok(())
}

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

pub(crate) fn windows_sandbox_setup_status_payload(
    platform_supported: bool,
    setup_complete: bool,
    broker_available: bool,
    elevated: Option<bool>,
) -> Value {
    let can_run_setup_now = platform_supported && (elevated.unwrap_or(false) || broker_available);
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
        "run_setup" => Some("runseal setup windows-sandbox --cwd <absolute-workspace-path> --json"),
        "open_elevated_shell" => {
            Some("runseal setup windows-sandbox --cwd <absolute-workspace-path> --json --elevate")
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
        "requires_setup": platform_supported && !setup_complete,
        "next_action": next_action,
        "next_command": next_command,
    })
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
fn run_windows_sandbox_setup(cwd: &Path, json_output: bool, _elevate: bool) -> Result<(), String> {
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
