use super::*;

const REPAIR_HELP_TEXT: &str = "\
Usage: runseal repair execution-gates [--json] [--accept-unverified-release]

Explicitly repair the Windows sandbox execution binding left by a host that died
without acknowledging cleanup. The repair refuses unless every recorded
reservation owner is gone, no process runs under the sandbox identity, and every
recorded runtime root is absent or safely removable. Only this explicit repair
restores such a binding: normal admission, setup status reads, and restarts do
not.

--accept-unverified-release proceeds when a token cannot be inspected or a
reservation predates runtime-root recording. The JSON report marks exactly what
remained unverified; without the flag the repair fails closed.
";

const REPAIR_USAGE: &str =
    "usage: runseal repair execution-gates [--json] [--accept-unverified-release]";

pub(crate) fn run(args: &[String]) -> Result<(), String> {
    match args {
        [flag] if flag == "--help" || flag == "-h" => {
            print!("{REPAIR_HELP_TEXT}");
            Ok(())
        }
        [target, rest @ ..] if target == "execution-gates" => run_execution_gates(rest),
        _ if args.iter().any(|arg| arg == "--json") => {
            println!(
                "{}",
                cli_error_payload(RunSealError::new("INVALID_REQUEST", REPAIR_USAGE))
            );
            Err(String::new())
        }
        _ => Err(REPAIR_USAGE.to_string()),
    }
}

fn run_execution_gates(args: &[String]) -> Result<(), String> {
    if matches!(args, [flag] if flag == "--help" || flag == "-h") {
        print!("{REPAIR_HELP_TEXT}");
        return Ok(());
    }
    let json_output = args.iter().any(|arg| arg == "--json");
    let mut accept_unverified_release = false;
    for arg in args {
        match arg.as_str() {
            "--json" => {}
            "--accept-unverified-release" => accept_unverified_release = true,
            _ => {
                if json_output {
                    println!(
                        "{}",
                        cli_error_payload(RunSealError::new("INVALID_REQUEST", REPAIR_USAGE))
                    );
                    return Err(String::new());
                }
                return Err(REPAIR_USAGE.to_string());
            }
        }
    }
    repair_execution_gates(accept_unverified_release, json_output)
}

#[cfg(not(windows))]
fn repair_execution_gates(
    _accept_unverified_release: bool,
    json_output: bool,
) -> Result<(), String> {
    const MESSAGE: &str = "execution gate repair is only supported on Windows";
    if json_output {
        println!(
            "{}",
            cli_error_payload(RunSealError::new("BACKEND_CAPABILITY_MISSING", MESSAGE))
        );
        return Err(String::new());
    }
    Err(MESSAGE.to_string())
}

#[cfg(windows)]
fn repair_execution_gates(
    accept_unverified_release: bool,
    json_output: bool,
) -> Result<(), String> {
    use std::time::Instant;

    let deadline = Instant::now() + crate::limits::deployment().cleanup_timeout();
    match crate::backend::repair_execution_gate(accept_unverified_release, deadline) {
        Ok(report) => {
            print_repair_report(&report, json_output);
            Ok(())
        }
        Err(error) if crate::backend::cleanup_failed(&error) => {
            const MESSAGE: &str =
                "execution gate repair refused: the recorded range is not proven released";
            if json_output {
                println!(
                    "{}",
                    cli_error_payload(RunSealError::new("EXECUTION_CLEANUP_FAILED", MESSAGE))
                );
                return Err(String::new());
            }
            Err(format!("[runseal:EXECUTION_CLEANUP_FAILED] {MESSAGE}"))
        }
        Err(error) => {
            let unavailable = crate::backend::backend_unavailable_reason(&error).is_some();
            let (code, message) = if unavailable {
                (
                    "BACKEND_UNAVAILABLE",
                    "execution gate repair cannot inspect the sandbox process boundary",
                )
            } else {
                (
                    "EXECUTION_CLEANUP_FAILED",
                    "execution gate repair could not verify or update the binding",
                )
            };
            if json_output {
                println!("{}", cli_error_payload(RunSealError::new(code, message)));
                Err(String::new())
            } else {
                Err(format!("[runseal:{code}] {message}"))
            }
        }
    }
}

#[cfg(windows)]
fn print_repair_report(report: &crate::backend::ExecutionGateRepair, json_output: bool) {
    if json_output {
        println!(
            "{}",
            json!({
                "repaired": report.repaired,
                "cleared_executions": report.cleared_executions,
                "removed_runtime_roots": report.removed_runtime_roots,
                "cleared_cleanup_failed_marker": report.cleared_cleanup_failed_marker,
                "cleared_quarantine": report.cleared_quarantine,
                "unverified_runtime_roots": report.unverified_runtime_roots,
                "uninspectable_processes": report.uninspectable_processes,
            })
        );
        return;
    }
    if report.repaired {
        println!(
            "repaired execution gate: cleared {} reservation(s), removed {} runtime root(s)",
            report.cleared_executions, report.removed_runtime_roots
        );
    } else {
        println!("no execution gate repair needed");
    }
}
