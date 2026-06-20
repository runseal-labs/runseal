use crate::backend::{SandboxBackend, active_backend};
use crate::cli::parse_policy_args;
use crate::execution::normalize_execution_cwd;
use crate::policy::{SandboxPolicy, normalize_policy};
use crate::setup::windows_sandbox_setup_status_for_cwd;
use serde_json::{Value, json};
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
    let backend = active_backend();
    let missing_features = backend.missing_feature_names(policy);
    let mut result = policy.explain_json();
    if let Some(result) = result.as_object_mut() {
        result.insert(
            "support".to_string(),
            json!(if missing_features.is_empty() {
                "supported"
            } else {
                "unsupported"
            }),
        );
        result.insert("missing_features".to_string(), json!(missing_features));
        if let Ok(setup_status) = windows_sandbox_setup_status_for_cwd(cwd) {
            result.insert("setup_status".to_string(), setup_status);
        }
    }
    result
}
