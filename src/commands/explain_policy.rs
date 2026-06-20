use crate::cli::parse_policy_args;
use crate::control;
use crate::execution::normalize_execution_cwd;
use crate::policy::{SandboxPolicy, normalize_policy};
use serde_json::Value;
use std::path::Path;

const EXPLAIN_POLICY_HELP_TEXT: &str = "\
Usage: runseal explain-policy [--policy <policy>] [--network <mode>] [--cwd <path>]

Options:
  --policy   danger-full-access, read-only, workspace-contained, or workspace-write
  --network  disabled or proxy
  --cwd      existing workspace directory
";

pub(crate) fn run(args: &[String]) -> Result<(), String> {
    if matches!(args, [flag] if flag == "--help" || flag == "-h") {
        print!("{EXPLAIN_POLICY_HELP_TEXT}");
        return Ok(());
    }
    let request = parse_policy_args(args)?;
    let cwd = normalize_execution_cwd(&request.cwd).map_err(|err| err.reason)?;
    let policy = normalize_policy(
        &Value::String(request.policy.clone()),
        &cwd,
        request.network,
    )
    .map_err(|err| err.reason)?;

    println!("{}", explain_policy_json(&policy, &cwd));
    Ok(())
}

pub(crate) fn explain_policy_json(policy: &SandboxPolicy, cwd: &Path) -> Value {
    control::explain_policy_json(policy, cwd)
}
