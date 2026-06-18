use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use tempfile::TempDir;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

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

fn decode_stream_event(event: &Value) -> Result<String> {
    assert_rfc3339_timestamp(&event["time"])?;
    assert_eq!(event["encoding"], "base64");
    assert_eq!(event["stream_offset"], 0);
    assert!(event.get("text").is_none());
    let encoded = event["data"]
        .as_str()
        .and_then(|data| data.strip_prefix("base64:"))
        .context("stream event must include base64-prefixed data")?;
    let bytes = STANDARD
        .decode(encoded)
        .context("stream data must decode")?;
    String::from_utf8(bytes).context("stream data must be UTF-8 for this test")
}

fn assert_rfc3339_timestamp(value: &Value) -> Result<()> {
    let timestamp = value.as_str().context("timestamp must be a string")?;
    OffsetDateTime::parse(timestamp, &Rfc3339)
        .with_context(|| format!("timestamp must be RFC3339 UTC: {timestamp}"))?;
    Ok(())
}

fn expected_backend_name() -> &'static str {
    if cfg!(windows) {
        "runseal-windows-reference"
    } else if cfg!(target_os = "macos") {
        "runseal-macos-experimental"
    } else if cfg!(target_os = "linux") {
        "runseal-linux-community"
    } else {
        "runseal-local"
    }
}

fn expected_backend_status() -> &'static str {
    if cfg!(windows) {
        "scaffold"
    } else if cfg!(target_os = "macos") {
        "experimental"
    } else if cfg!(target_os = "linux") {
        "future-community"
    } else {
        "local-baseline"
    }
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
    assert!(
        payload["policy_versions"]
            .as_array()
            .expect("policy_versions must be an array")
            .iter()
            .any(|version| version == "runseal.policy/v1")
    );
    Ok(())
}

#[test]
fn capabilities_cli_reports_active_backend_baseline() -> Result<()> {
    let output = run_cli(&["capabilities"])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output)?;
    assert_eq!(payload["backend"], expected_backend_name());
    assert_eq!(payload["backend_status"], expected_backend_status());
    assert!(payload["platform"].as_str().is_some());
    assert_eq!(payload["features"]["local_execution"], true);
    assert_eq!(payload["features"]["filesystem_policy"], false);
    assert_eq!(payload["features"]["audit_jsonl"], true);
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
        payload["required_backend_features"],
        serde_json::json!(["filesystem_policy", "network_disabled"])
    );
    assert_eq!(
        payload["canonical_policy"]["filesystem"]["protect_vcs"],
        true
    );
    assert!(
        payload["policy_hash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sha256:")
    );
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
    for event in &events {
        assert_rfc3339_timestamp(&event["time"])?;
    }
    let stdout_event = events
        .iter()
        .find(|event| event["type"] == "execution.stdout")
        .context("execution.stdout event must exist")?;
    assert!(decode_stream_event(stdout_event)?.contains("hello from runseal"));
    assert!(
        events
            .iter()
            .filter(|event| event["type"]
                .as_str()
                .unwrap_or_default()
                .starts_with("execution."))
            .all(|event| event.get("execution_id").is_some())
    );
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
    assert_eq!(payload["signal"], Value::Null);
    assert_rfc3339_timestamp(&payload["started_at"])?;
    assert_rfc3339_timestamp(&payload["finished_at"])?;
    assert!(
        payload["execution_id"]
            .as_str()
            .unwrap_or_default()
            .starts_with("exec_")
    );
    let session_id = payload["session_id"]
        .as_str()
        .expect("ExecutionResult must include session_id");
    let seal_id = payload["seal_id"]
        .as_str()
        .expect("ExecutionResult must include seal_id");
    assert!(session_id.starts_with("sess_"));
    assert!(seal_id.starts_with("seal_"));
    assert_eq!(payload["policy_id"], "danger-full-access");
    assert_eq!(payload["sandbox"]["enforced"], false);
    assert_eq!(payload["platform_plan"]["enforcement"], "local-execution");
    assert_eq!(
        payload["platform_plan"]["backend"]["name"],
        expected_backend_name()
    );
    assert_eq!(payload["platform_plan"]["filesystem"]["write"][0], "*");
    assert!(
        payload["policy_hash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sha256:")
    );
    let audit_path = payload["audit_path"]
        .as_str()
        .expect("ExecutionResult must include audit_path");
    assert_eq!(audit_path, format!(".runseal/audit/{session_id}.jsonl"));
    let audit_file = tmp.path().join(audit_path);
    let audit_jsonl = fs::read_to_string(&audit_file)
        .with_context(|| format!("audit file must exist at {}", audit_file.display()))?;
    let audit_events: Vec<Value> = audit_jsonl
        .lines()
        .map(|line| serde_json::from_str(line).context("audit line must be JSON"))
        .collect::<Result<_>>()?;
    let audit_event_types: Vec<_> = audit_events
        .iter()
        .filter_map(|event| event["type"].as_str())
        .collect();
    assert!(audit_event_types.contains(&"execution.started"));
    assert!(audit_event_types.contains(&"execution.stdout"));
    assert!(audit_event_types.contains(&"execution.finished"));
    for event in &audit_events {
        assert_rfc3339_timestamp(&event["time"])?;
        assert_eq!(event["session_id"], session_id);
        assert_eq!(event["seal_id"], seal_id);
    }
    let audit_stdout = audit_events
        .iter()
        .find(|event| event["type"] == "execution.stdout")
        .context("execution.stdout audit event must exist")?;
    assert!(decode_stream_event(audit_stdout)?.contains("42"));
    assert!(payload["stdout_bytes"].as_u64().unwrap_or_default() > 0);
    assert_eq!(payload["output_truncated"], false);
    assert!(payload["resource_usage"]["duration_ms"].as_u64().is_some());
    Ok(())
}

#[test]
fn exec_cli_enforces_timeout_ms() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let output = run_cli(&[
        "exec",
        "--json",
        "--policy",
        "danger-full-access",
        "--timeout-ms",
        "10",
        "--cwd",
        &cwd,
        "--",
        "python3",
        "-c",
        "import time; time.sleep(1)",
    ])?;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("execution timed out"), "{stderr}");
    Ok(())
}

#[test]
fn exec_cli_rejects_invalid_timeout_ms() -> Result<()> {
    let output = run_cli(&[
        "exec",
        "--policy",
        "danger-full-access",
        "--timeout-ms",
        "soon",
        "--",
        "python3",
        "-c",
        "print('must not run')",
    ])?;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("timeout must be an integer in milliseconds"),
        "{stderr}"
    );
    Ok(())
}
