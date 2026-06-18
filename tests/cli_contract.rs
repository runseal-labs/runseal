use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::env;
use std::path::PathBuf;
use std::process::{Command, Output};
use tempfile::TempDir;

fn runseal_bin() -> PathBuf {
    env::var_os("RUNSEAL_BIN")
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO_BIN_EXE_runseal").map(PathBuf::from))
        .unwrap_or_else(|| {
            let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/debug/runseal");
            if cfg!(windows) {
                path.set_extension("exe");
            }
            path
        })
}

fn require_runseal_bin() -> Result<PathBuf> {
    let bin = runseal_bin();
    if !bin.exists() {
        bail!(
            "RunSeal binary not found at {}. Set RUNSEAL_BIN to a candidate implementation to run conformance tests.",
            bin.display()
        );
    }
    Ok(bin)
}

fn run_cli(args: &[&str]) -> Result<Output> {
    let bin = require_runseal_bin()?;
    Command::new(bin)
        .args(args)
        .output()
        .context("failed to spawn runseal")
}

fn stdout_json(output: &Output) -> Result<Value> {
    serde_json::from_slice(&output.stdout).context("stdout was not valid JSON")
}

fn stdout_json_lines(output: &Output) -> Result<Vec<Value>> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).context("stdout line was not valid JSON"))
        .collect()
}

#[test]
fn missing_binary_is_explicit_red_state() {
    if runseal_bin().exists() {
        return;
    }
    let error = run_cli(&["--version"]).expect_err("missing implementation should be RED");
    let message = error.to_string();
    assert!(message.contains("RunSeal binary not found"), "{message}");
    assert!(message.contains("RUNSEAL_BIN"), "{message}");
}

#[test]
fn version_reports_protocol_and_runtime_versions() -> Result<()> {
    let output = run_cli(&["--json", "version"])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output)?;
    assert!(payload["runseal_version"].as_str().is_some());
    assert_eq!(payload["protocol_version"], "runseal.protocol/v1");
    assert!(payload["policy_versions"]
        .as_array()
        .expect("policy_versions must be an array")
        .iter()
        .any(|version| version == "runseal.policy/v1"));
    Ok(())
}

#[test]
fn capabilities_cli_reports_local_baseline() -> Result<()> {
    let output = run_cli(&["capabilities"])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output)?;
    assert_eq!(payload["backend"], "runseal-local");
    assert!(payload["platform"].as_str().is_some());
    assert_eq!(payload["features"]["local_execution"], true);
    assert_eq!(payload["features"]["filesystem_policy"], false);
    assert_eq!(payload["sandbox_levels"]["danger-full-access"], "supported");
    assert_eq!(payload["sandbox_levels"]["read-only"], "unsupported");
    assert_eq!(payload["network_modes"]["proxy"], "unsupported");
    Ok(())
}

#[test]
fn explain_policy_cli_materializes_standard_profile() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let output = run_cli(&[
        "explain-policy",
        "--policy",
        "workspace-write",
        "--network",
        "disabled",
        "--cwd",
        &cwd,
    ])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output)?;
    assert_eq!(payload["policy_id"], "workspace-write");
    assert_eq!(payload["sandbox_level"], "workspace-write");
    assert_eq!(payload["network"]["mode"], "disabled");
    assert_eq!(payload["environment"]["inherit"], "minimal");
    assert_eq!(payload["backend_requirement"], "sandbox-backend");
    assert_eq!(
        payload["canonical_policy"]["filesystem"]["protect_vcs"],
        true
    );
    assert!(payload["policy_hash"]
        .as_str()
        .unwrap_or_default()
        .starts_with("sha256:"));
    Ok(())
}

#[test]
fn exec_events_stream_uses_execution_vocabulary() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let output = run_cli(&[
        "exec",
        "--events",
        "--policy",
        "danger-full-access",
        "--cwd",
        &cwd,
        "--",
        "python3",
        "-c",
        "print('hello from runseal')",
    ])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events = stdout_json_lines(&output)?;
    let event_types: Vec<_> = events
        .iter()
        .filter_map(|event| event["type"].as_str())
        .collect();

    assert!(event_types.contains(&"execution.started"));
    assert!(event_types.contains(&"execution.stdout"));
    assert!(event_types.contains(&"execution.finished"));
    assert!(events
        .iter()
        .filter(|event| event["type"]
            .as_str()
            .unwrap_or_default()
            .starts_with("execution."))
        .all(|event| event.get("execution_id").is_some()));
    assert!(events.iter().all(|event| event.get("process_id").is_none()));
    Ok(())
}

#[test]
fn exec_json_returns_execution_result() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let output = run_cli(&[
        "exec",
        "--json",
        "--policy",
        "danger-full-access",
        "--cwd",
        &cwd,
        "--",
        "python3",
        "-c",
        "print(42)",
    ])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output)?;
    assert_eq!(payload["status"], "finished");
    assert_eq!(payload["exit_code"], 0);
    assert!(payload["execution_id"]
        .as_str()
        .unwrap_or_default()
        .starts_with("exec_"));
    assert_eq!(payload["policy_id"], "danger-full-access");
    assert_eq!(payload["sandbox"]["enforced"], false);
    assert!(payload["policy_hash"]
        .as_str()
        .unwrap_or_default()
        .starts_with("sha256:"));
    assert!(payload["stdout_bytes"].as_u64().unwrap_or_default() > 0);
    assert!(payload["resource_usage"]["duration_ms"].as_u64().is_some());
    Ok(())
}
