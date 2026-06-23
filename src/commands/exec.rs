use super::*;

const EXEC_HELP_TEXT: &str = "\
Usage: runseal exec [--json|--events] [--policy <policy>] [--network <mode>] [--cwd <path>] [--timeout-ms <ms>] -- <command> [args...]

Options:
  --policy       danger-full-access, read-only, workspace-contained, or workspace-write
  --network      unmanaged, disabled, or proxy
  --cwd          existing workspace directory
  --timeout-ms   execution timeout in milliseconds
";

pub(crate) fn run(args: &[String]) -> Result<(), String> {
    if matches!(args, [flag] if flag == "--help" || flag == "-h") {
        print!("{EXEC_HELP_TEXT}");
        return Ok(());
    }
    let machine_readable = args
        .iter()
        .take_while(|arg| arg.as_str() != "--")
        .any(|arg| arg == "--json" || arg == "--events");
    let request = match parse_exec_args(args) {
        Ok(request) => request,
        Err(err) if machine_readable => {
            println!(
                "{}",
                cli_error_payload(RunSealError::new("INVALID_REQUEST", err))
            );
            return Err(String::new());
        }
        Err(err) => return Err(err),
    };
    let cwd = match normalize_execution_cwd(&request.cwd) {
        Ok(cwd) => cwd,
        Err(err) if request.json || request.events => {
            println!("{}", cli_error_payload(err));
            return Err(String::new());
        }
        Err(err) => return Err(err.message),
    };
    let policy = match normalize_policy(
        &Value::String(request.policy.clone()),
        &cwd,
        request.network,
    ) {
        Ok(policy) => policy,
        Err(err) if request.json || request.events => {
            println!("{}", cli_error_payload(err.into()));
            return Err(String::new());
        }
        Err(err) => return Err(err.reason),
    };
    let (events, result) = match execute_command(
        &request.command,
        &cwd,
        &policy,
        ExecutionStdin::Empty,
        ExecutionEnv::default(),
        None,
        request.timeout,
    ) {
        Ok(result) => result,
        Err(err) if request.json || request.events => {
            println!("{}", cli_error_payload(err));
            return Err(String::new());
        }
        Err(err) => return Err(err.message),
    };

    if request.events {
        for event in events {
            println!("{event}");
        }
        return Ok(());
    }

    if request.json {
        println!("{result}");
        return Ok(());
    }

    if let Some(text) = result.get("stdout").and_then(Value::as_str) {
        print!("{text}");
    }
    Ok(())
}
