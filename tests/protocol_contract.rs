use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
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

fn rpc_request(method: &str, params: Value) -> String {
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string() + "\n"
}

fn run_rpc(message: &str) -> Result<Output> {
    run_rpc_with_env(message, &[])
}

fn run_rpc_with_env(message: &str, envs: &[(&str, &str)]) -> Result<Output> {
    let bin = require_runseal_bin()?;
    let mut child = Command::new(bin)
        .args(["rpc", "--stdio"])
        .envs(envs.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn runseal rpc")?;

    child
        .stdin
        .as_mut()
        .context("stdin unavailable")?
        .write_all(message.as_bytes())?;

    child
        .wait_with_output()
        .context("failed to wait for runseal rpc")
}

fn python_bin() -> &'static str {
    if cfg!(windows) { "python" } else { "python3" }
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

fn assert_event_envelope(event: &Value) -> Result<()> {
    assert_rfc3339_timestamp(&event["time"])?;
    assert!(
        event["execution_id"]
            .as_str()
            .unwrap_or_default()
            .starts_with("exec_")
    );
    assert!(
        event["session_id"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sess_")
    );
    assert!(
        event["seal_id"]
            .as_str()
            .unwrap_or_default()
            .starts_with("seal_")
    );
    assert!(event["policy_id"].as_str().is_some());
    assert!(
        event["policy_hash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sha256:")
    );
    assert!(
        event["audit_path"]
            .as_str()
            .unwrap_or_default()
            .starts_with(".runseal/audit/sess_")
    );
    assert!(event["backend"]["name"].as_str().is_some());
    assert!(event["backend"]["status"].as_str().is_some());
    assert!(event["backend"]["platform"].as_str().is_some());
    Ok(())
}

fn read_audit_events(root: &std::path::Path, audit_path: &str) -> Result<Vec<Value>> {
    let audit_file = root.join(audit_path);
    let audit_jsonl = fs::read_to_string(&audit_file)
        .with_context(|| format!("audit file must exist at {}", audit_file.display()))?;
    audit_jsonl
        .lines()
        .map(|line| serde_json::from_str(line).context("audit line must be JSON"))
        .collect()
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

fn expected_process_cleanup_supported() -> bool {
    cfg!(windows)
}

fn expected_runtime_roots_supported() -> bool {
    cfg!(windows)
}

fn expected_runtime_environment_supported() -> bool {
    cfg!(windows)
}

fn expected_missing_features(additional: &[&'static str]) -> Vec<&'static str> {
    let mut features = vec!["filesystem_policy"];
    if !expected_runtime_roots_supported() {
        features.push("runtime_roots");
    }
    if !expected_runtime_environment_supported() {
        features.push("runtime_environment");
    }
    features.push("process_isolation");
    if !expected_process_cleanup_supported() {
        features.push("process_cleanup");
    }
    features.push("direct_network_deny");
    features.extend_from_slice(additional);
    features
}

fn assert_no_private_windows_setup_terms(value: &Value) {
    let public_payload = value.to_string();
    for private_term in [
        "single-sandbox-user",
        "RunSealSandbox",
        "RunSealSandboxUsers",
        "restricted-token",
        "kill-on-close-job",
        "offline",
        "online",
    ] {
        assert!(
            !public_payload.contains(private_term),
            "public protocol must not expose private Windows setup term {private_term}"
        );
    }
}

#[test]
fn rpc_missing_binary_is_explicit_red_state() {
    if runseal_bin().exists() {
        return;
    }
    let error = run_rpc(&rpc_request("getVersion", json!({})))
        .expect_err("missing implementation should be RED");
    assert!(error.to_string().contains("RunSeal binary not found"));
}

#[test]
fn get_version_rpc_contract() -> Result<()> {
    let output = run_rpc(&rpc_request("getVersion", json!({})))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = &messages[0];
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert_eq!(
        response["result"]["protocol_version"],
        "runseal.protocol/v1"
    );
    assert!(
        response["result"]["policy_versions"]
            .as_array()
            .expect("policy_versions must be an array")
            .iter()
            .any(|version| version == "runseal.policy/v1")
    );
    Ok(())
}

#[test]
fn get_capabilities_rpc_contract() -> Result<()> {
    let output = run_rpc(&rpc_request("getCapabilities", json!({})))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let payload = &messages[0]["result"];
    assert_eq!(payload["backend"], expected_backend_name());
    assert_eq!(payload["backend_status"], expected_backend_status());
    assert!(payload["platform"].as_str().is_some());
    assert_eq!(payload["sandbox_levels"]["danger-full-access"], "supported");
    assert_eq!(payload["sandbox_levels"]["workspace-write"], "unsupported");
    assert_eq!(payload["network_modes"]["disabled"], "unsupported");
    assert_eq!(
        payload["features"]["runtime_roots"],
        expected_runtime_roots_supported()
    );
    assert_eq!(
        payload["features"]["runtime_environment"],
        expected_runtime_environment_supported()
    );
    assert_eq!(payload["features"]["process_isolation"], false);
    assert_eq!(
        payload["features"]["process_cleanup"],
        expected_process_cleanup_supported()
    );
    assert_eq!(payload["features"]["direct_network_deny"], false);
    assert_eq!(payload["features"]["managed_proxy"], false);
    assert_eq!(payload["features"]["audit_jsonl"], true);
    assert_no_private_windows_setup_terms(payload);
    Ok(())
}

#[test]
fn execution_lookup_methods_return_stable_not_found() -> Result<()> {
    for method in ["getExecution", "cancelExecution", "subscribeEvents"] {
        let output = run_rpc(&rpc_request(
            method,
            json!({"execution_id": "exec_missing"}),
        ))?;

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let messages = stdout_json_lines(&output)?;
        let response = &messages[0];

        assert_eq!(response["error"]["data"]["code"], "EXECUTION_NOT_FOUND");
        assert_eq!(response["error"]["data"]["execution_id"], "exec_missing");
    }
    Ok(())
}

#[test]
fn dispose_session_is_noop_for_stdio_mvp() -> Result<()> {
    let output = run_rpc(&rpc_request(
        "disposeSession",
        json!({"session_id": "sess_missing"}),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = &messages[0];

    assert_eq!(response["result"]["session_id"], "sess_missing");
    assert_eq!(response["result"]["status"], "disposed");
    Ok(())
}

#[test]
fn execute_rejects_unsupported_request_fields() -> Result<()> {
    let tmp = TempDir::new()?;
    let unsupported_cases = [("trace_id", json!("trace_test"))];

    for (field, value) in unsupported_cases {
        let mut request = json!({
            "command": [python_bin(), "-c", "print('must not run')"],
            "cwd": tmp.path(),
            "policy": "danger-full-access"
        });
        request
            .as_object_mut()
            .expect("request must be an object")
            .insert(field.to_string(), value);

        let output = run_rpc(&rpc_request("execute", request))?;

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let messages = stdout_json_lines(&output)?;
        let response = &messages[0];

        assert_eq!(response["error"]["data"]["code"], "INVALID_REQUEST");
        assert!(
            response["error"]["data"]["reason"]
                .as_str()
                .unwrap_or_default()
                .contains(&format!("params.{field} is not supported"))
        );
    }
    Ok(())
}

#[test]
fn execute_accepts_non_secret_env_and_audits_keys_only() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [
                python_bin(),
                "-c",
                "import os; print('flag=' + os.environ.get('RUNSEAL_PUBLIC_FLAG', 'missing'))"
            ],
            "cwd": tmp.path(),
            "policy": "danger-full-access",
            "env": {"RUNSEAL_PUBLIC_FLAG": "visible"}
        }),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .unwrap();

    assert_eq!(response["result"]["status"], "finished");
    assert_eq!(response["result"]["exit_code"], 0);
    assert!(
        response["result"]["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("flag=visible")
    );

    let audit_path = response["result"]["audit_path"]
        .as_str()
        .expect("execution result must include audit_path");
    let audit_events = read_audit_events(tmp.path(), audit_path)?;
    let started = audit_events
        .iter()
        .find(|event| event["type"] == "execution.started")
        .context("execution.started audit event must exist")?;
    assert_eq!(
        started["environment"]["requested_keys"],
        json!(["RUNSEAL_PUBLIC_FLAG"])
    );
    let audit_jsonl = fs::read_to_string(tmp.path().join(audit_path))?;
    assert!(audit_jsonl.contains("RUNSEAL_PUBLIC_FLAG"));
    assert!(!audit_jsonl.contains("visible"));
    Ok(())
}

#[test]
fn execute_applies_policy_environment_set() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [
                python_bin(),
                "-c",
                "import os; print(os.environ.get('RUNSEAL_POLICY_FLAG', 'missing') + ':' + os.environ.get('RUNSEAL_OVERRIDE', 'missing'))"
            ],
            "cwd": tmp.path(),
            "policy": {
                "version": "runseal.policy/v1",
                "sandbox_level": "danger-full-access",
                "environment": {
                    "set": {
                        "RUNSEAL_POLICY_FLAG": "policy",
                        "RUNSEAL_OVERRIDE": "policy"
                    }
                }
            },
            "env": {"RUNSEAL_OVERRIDE": "request"}
        }),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .unwrap();

    assert_eq!(response["result"]["status"], "finished");
    assert!(
        response["result"]["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("policy:request")
    );

    let audit_path = response["result"]["audit_path"]
        .as_str()
        .expect("execution result must include audit_path");
    let audit_events = read_audit_events(tmp.path(), audit_path)?;
    let started = audit_events
        .iter()
        .find(|event| event["type"] == "execution.started")
        .context("execution.started audit event must exist")?;
    assert_eq!(
        started["environment"]["requested_keys"],
        json!(["RUNSEAL_OVERRIDE", "RUNSEAL_POLICY_FLAG"])
    );
    let audit_jsonl = fs::read_to_string(tmp.path().join(audit_path))?;
    assert!(!audit_jsonl.contains("policy:request"));
    Ok(())
}

#[test]
fn execute_rejects_secret_env_keys() -> Result<()> {
    let tmp = TempDir::new()?;
    for key in ["OPENAI_API_KEY", "RUNSEAL_TOKEN", "AWS_REGION"] {
        let output = run_rpc(&rpc_request(
            "execute",
            json!({
                "command": [python_bin(), "-c", "print('must not run')"],
                "cwd": tmp.path(),
                "policy": "danger-full-access",
                "env": {key: "blocked"}
            }),
        ))?;

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let messages = stdout_json_lines(&output)?;
        let response = &messages[0];

        assert_eq!(response["error"]["data"]["code"], "INVALID_REQUEST");
        assert!(
            response["error"]["data"]["reason"]
                .as_str()
                .unwrap_or_default()
                .contains("is denied by policy environment scrub")
        );
    }
    Ok(())
}

#[test]
fn execute_copies_metadata_to_audit_events() -> Result<()> {
    let tmp = TempDir::new()?;
    let metadata = json!({
        "agent_id": "agent_test",
        "skill_id": "skill_test_runner"
    });
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "print('metadata ok')"],
            "cwd": tmp.path(),
            "policy": "danger-full-access",
            "metadata": metadata
        }),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .unwrap();

    assert_eq!(response["result"]["status"], "finished");
    assert!(response["result"].get("metadata").is_none());
    assert!(
        messages
            .iter()
            .filter(|message| message.get("method") == Some(&json!("event")))
            .all(|message| message
                .get("params")
                .and_then(|params| params.get("metadata"))
                .is_none())
    );

    let audit_path = response["result"]["audit_path"]
        .as_str()
        .expect("execution result must include audit_path");
    let audit_events = read_audit_events(tmp.path(), audit_path)?;
    for event_type in ["execution.started", "execution.finished"] {
        let event = audit_events
            .iter()
            .find(|event| event["type"] == event_type)
            .with_context(|| format!("audit event {event_type} must exist"))?;
        assert_event_envelope(event)?;
        assert_eq!(event["metadata"], metadata);
    }
    Ok(())
}

#[test]
fn execute_rejects_invalid_metadata() -> Result<()> {
    let tmp = TempDir::new()?;
    let cases = vec![
        (json!("agent_test"), "params.metadata must be an object"),
        (
            json!({"payload": "x".repeat(5000)}),
            "params.metadata must be at most",
        ),
    ];

    for (metadata, expected_reason) in cases {
        let output = run_rpc(&rpc_request(
            "execute",
            json!({
                "command": [python_bin(), "-c", "print('must not run')"],
                "cwd": tmp.path(),
                "policy": "danger-full-access",
                "metadata": metadata
            }),
        ))?;

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let messages = stdout_json_lines(&output)?;
        let response = &messages[0];

        assert_eq!(response["error"]["data"]["code"], "INVALID_REQUEST");
        assert!(
            response["error"]["data"]["reason"]
                .as_str()
                .unwrap_or_default()
                .contains(expected_reason)
        );
    }
    Ok(())
}

#[test]
fn execute_accepts_empty_stdin() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [
                python_bin(),
                "-c",
                "import sys; data = sys.stdin.buffer.read(); print(f'stdin_bytes={len(data)}')"
            ],
            "cwd": tmp.path(),
            "policy": "danger-full-access",
            "stdin": {"mode": "empty"}
        }),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .unwrap();

    assert_eq!(response["result"]["status"], "finished");
    assert_eq!(response["result"]["exit_code"], 0);
    assert!(
        response["result"]["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("stdin_bytes=0")
    );
    Ok(())
}

#[test]
fn execute_accepts_bytes_stdin_and_audits_metadata_only() -> Result<()> {
    let tmp = TempDir::new()?;
    let stdin_bytes = b"stdin-secret payload";
    let encoded = STANDARD.encode(stdin_bytes);
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [
                python_bin(),
                "-c",
                "import sys; data = sys.stdin.buffer.read(); print(f'stdin_bytes={len(data)}')"
            ],
            "cwd": tmp.path(),
            "policy": "danger-full-access",
            "stdin": {
                "mode": "bytes",
                "data": format!("base64:{encoded}"),
                "encoding": "base64"
            }
        }),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .unwrap();

    assert_eq!(response["result"]["status"], "finished");
    assert_eq!(response["result"]["exit_code"], 0);
    assert!(
        response["result"]["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains(&format!("stdin_bytes={}", stdin_bytes.len()))
    );

    let audit_path = response["result"]["audit_path"]
        .as_str()
        .expect("execution result must include audit_path");
    let audit_events = read_audit_events(tmp.path(), audit_path)?;
    let started = audit_events
        .iter()
        .find(|event| event["type"] == "execution.started")
        .context("execution.started audit event must exist")?;
    assert_eq!(started["stdin"]["mode"], "bytes");
    assert_eq!(started["stdin"]["byte_count"], stdin_bytes.len());

    let audit_jsonl = fs::read_to_string(tmp.path().join(audit_path))?;
    assert!(!audit_jsonl.contains("stdin-secret"));
    assert!(!audit_jsonl.contains(&encoded));
    Ok(())
}

#[test]
fn execute_rejects_invalid_bytes_stdin() -> Result<()> {
    let tmp = TempDir::new()?;
    let cases = [
        (
            json!({
                "mode": "bytes",
                "data": "base64:aGVsbG8=",
                "encoding": "utf8"
            }),
            "params.stdin.encoding must be base64",
        ),
        (
            json!({
                "mode": "bytes",
                "data": "aGVsbG8=",
                "encoding": "base64"
            }),
            "params.stdin.data must use base64: prefix",
        ),
        (
            json!({
                "mode": "bytes",
                "data": "base64:not-valid-base64",
                "encoding": "base64"
            }),
            "params.stdin.data must be valid base64",
        ),
        (
            json!({
                "mode": "bytes",
                "data": "base64:aGVsbG8=",
                "encoding": "base64",
                "extra": true
            }),
            "params.extra is not supported by execute stdin",
        ),
    ];

    for (stdin, expected_reason) in cases {
        let output = run_rpc(&rpc_request(
            "execute",
            json!({
                "command": [python_bin(), "-c", "print('must not run')"],
                "cwd": tmp.path(),
                "policy": "danger-full-access",
                "stdin": stdin
            }),
        ))?;

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let messages = stdout_json_lines(&output)?;
        let response = &messages[0];

        assert_eq!(response["error"]["data"]["code"], "INVALID_REQUEST");
        assert!(
            response["error"]["data"]["reason"]
                .as_str()
                .unwrap_or_default()
                .contains(expected_reason)
        );
    }
    Ok(())
}

#[test]
fn execute_rejects_unimplemented_stdin_modes() -> Result<()> {
    let tmp = TempDir::new()?;
    for mode in ["inherit", "stream"] {
        let output = run_rpc(&rpc_request(
            "execute",
            json!({
                "command": [python_bin(), "-c", "print('must not run')"],
                "cwd": tmp.path(),
                "policy": "danger-full-access",
                "stdin": {"mode": mode}
            }),
        ))?;

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let messages = stdout_json_lines(&output)?;
        let response = &messages[0];

        assert_eq!(response["error"]["data"]["code"], "INVALID_REQUEST");
        assert!(
            response["error"]["data"]["reason"]
                .as_str()
                .unwrap_or_default()
                .contains(&format!("params.stdin.mode={mode} is not supported"))
        );
    }
    Ok(())
}

#[test]
fn execute_timeout_returns_stable_error_and_audit_event() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "import time; time.sleep(1)"],
            "cwd": tmp.path(),
            "policy": "danger-full-access",
            "timeout_ms": 10
        }),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = &messages[0];

    assert_eq!(response["error"]["data"]["code"], "EXECUTION_TIMEOUT");
    assert_eq!(response["error"]["data"]["timeout_ms"], 10);
    let audit_path = response["error"]["data"]["audit_path"]
        .as_str()
        .expect("timeout error must return audit_path");
    let audit_events = read_audit_events(tmp.path(), audit_path)?;
    assert!(audit_events.iter().any(
        |event| event["type"] == "execution.failed" && event["reason"] == "execution timed out"
    ));
    let failed_event = audit_events
        .iter()
        .find(|event| event["type"] == "execution.failed")
        .context("execution.failed audit event must exist")?;
    assert_event_envelope(failed_event)?;
    Ok(())
}

#[test]
fn execute_uses_policy_resource_timeout() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "import time; time.sleep(1)"],
            "cwd": tmp.path(),
            "policy": {
                "version": "runseal.policy/v1",
                "sandbox_level": "danger-full-access",
                "resources": {"timeout_ms": 10}
            }
        }),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = &messages[0];

    assert_eq!(response["error"]["data"]["code"], "EXECUTION_TIMEOUT");
    assert_eq!(response["error"]["data"]["timeout_ms"], 10);
    Ok(())
}

#[test]
fn execute_rejects_timeout_above_policy_limit() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "print('must not run')"],
            "cwd": tmp.path(),
            "policy": {
                "version": "runseal.policy/v1",
                "sandbox_level": "danger-full-access",
                "resources": {"timeout_ms": 10}
            },
            "timeout_ms": 20
        }),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = &messages[0];

    assert_eq!(response["error"]["data"]["code"], "INVALID_REQUEST");
    assert!(
        response["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("params.timeout_ms exceeds policy resources.timeout_ms")
    );
    Ok(())
}

#[test]
fn explain_policy_rejects_unsupported_request_fields() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "explainPolicy",
        json!({
            "cwd": tmp.path(),
            "policy": "workspace-write",
            "metadata": {"agent_id": "agent_test"}
        }),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = &messages[0];

    assert_eq!(response["error"]["data"]["code"], "INVALID_REQUEST");
    assert!(
        response["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("params.metadata is not supported")
    );
    Ok(())
}

#[test]
fn explain_policy_returns_effective_hash_and_network_mode() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let output = run_rpc(&rpc_request(
        "explainPolicy",
        json!({"policy": "workspace-write", "cwd": cwd}),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let payload = &messages[0]["result"];
    assert_eq!(payload["policy_id"], "workspace-write");
    assert_eq!(payload["sandbox_level"], "workspace-write");
    assert!(
        payload["policy_hash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sha256:")
    );
    assert_eq!(payload["network"]["mode"], "proxy");
    assert_eq!(payload["environment"]["inherit"], "minimal");
    assert_eq!(payload["backend_requirement"], "sandbox-backend");
    assert_eq!(payload["support"], "unsupported");
    assert_eq!(
        payload["required_backend_features"],
        json!([
            "filesystem_policy",
            "runtime_roots",
            "runtime_environment",
            "process_isolation",
            "process_cleanup",
            "direct_network_deny",
            "network_proxy",
            "managed_proxy"
        ])
    );
    assert!(
        payload["filesystem"]["write"]
            .as_array()
            .expect("filesystem.write must be an array")
            .iter()
            .any(|path| path == tmp.path().to_string_lossy().as_ref())
    );
    assert_no_private_windows_setup_terms(payload);
    assert!(
        payload["canonical_policy"]["filesystem"]["deny"]
            .as_array()
            .expect("canonical filesystem.deny must be an array")
            .iter()
            .any(|path| path.as_str().unwrap_or_default().ends_with(".git"))
    );
    Ok(())
}

#[test]
fn explain_policy_hash_tracks_network_override() -> Result<()> {
    let tmp = TempDir::new()?;
    let proxy = run_rpc(&rpc_request(
        "explainPolicy",
        json!({"policy": "workspace-write", "cwd": tmp.path(), "network": {"mode": "proxy"}}),
    ))?;
    let disabled = run_rpc(&rpc_request(
        "explainPolicy",
        json!({"policy": "workspace-write", "cwd": tmp.path(), "network": {"mode": "disabled"}}),
    ))?;

    assert!(proxy.status.success());
    assert!(disabled.status.success());
    let proxy_messages = stdout_json_lines(&proxy)?;
    let disabled_messages = stdout_json_lines(&disabled)?;
    let proxy_payload = &proxy_messages[0]["result"];
    let disabled_payload = &disabled_messages[0]["result"];

    assert_eq!(proxy_payload["network"]["mode"], "proxy");
    assert_eq!(disabled_payload["network"]["mode"], "disabled");
    assert_ne!(
        proxy_payload["policy_hash"],
        disabled_payload["policy_hash"]
    );
    assert_ne!(
        proxy_payload["canonical_policy"],
        disabled_payload["canonical_policy"]
    );
    Ok(())
}

#[test]
fn policy_denial_uses_stable_error_code() -> Result<()> {
    let tmp = TempDir::new()?;
    let forbidden_path = tmp.path().join("outside");
    let code = format!("open({forbidden_path:?}, 'w').write('x')");
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", code],
            "cwd": tmp.path(),
            "policy": {
                "version": "runseal.policy/v1",
                "filesystem": {"read": [tmp.path()], "write": []},
                "network": {"mode": "disabled"}
            }
        }),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .unwrap();
    assert_eq!(response["error"]["data"]["code"], "POLICY_DENIED");
    assert!(response["error"]["data"]["reason"].as_str().is_some());
    let audit_path = response["error"]["data"]["audit_path"]
        .as_str()
        .expect("policy denial must return audit_path");
    let audit_events = read_audit_events(tmp.path(), audit_path)?;
    assert!(
        audit_events
            .iter()
            .any(|event| event["type"] == "policy.denied" && event["decision"] == "denied")
    );
    Ok(())
}

#[test]
fn execute_rejects_missing_cwd_without_creating_it() -> Result<()> {
    let tmp = TempDir::new()?;
    let missing_cwd = tmp.path().join("missing-workspace");
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "print('must not run')"],
            "cwd": missing_cwd,
            "policy": "danger-full-access"
        }),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .unwrap();

    assert_eq!(response["error"]["data"]["code"], "INVALID_REQUEST");
    assert!(
        response["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("params.cwd must be an existing directory")
    );
    assert!(!missing_cwd.exists());
    Ok(())
}

#[test]
fn inline_policy_accepts_read_only_filesystem_roots() -> Result<()> {
    let tmp = TempDir::new()?;
    let cache = tmp.path().join("cache");
    let cache = cache.to_string_lossy().to_string();
    let output = run_rpc(&rpc_request(
        "explainPolicy",
        json!({
            "cwd": tmp.path(),
            "policy": {
                "version": "runseal.policy/v1",
                "filesystem": {
                    "read": [tmp.path()],
                    "read_only": [cache],
                    "write": [tmp.path()]
                },
                "network": {"mode": "disabled"}
            }
        }),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let payload = &messages[0]["result"];

    assert_eq!(payload["filesystem"]["read_only"], json!([cache]));
    assert_eq!(
        payload["canonical_policy"]["filesystem"]["read_only"],
        json!([cache])
    );
    Ok(())
}

#[test]
fn inline_policy_accepts_environment_controls() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "explainPolicy",
        json!({
            "cwd": tmp.path(),
            "policy": {
                "version": "runseal.policy/v1",
                "environment": {
                    "inherit": "minimal",
                    "scrub": ["RUNSEAL_SECRET_*"],
                    "set": {
                        "CI": "1"
                    },
                    "proxy": false
                },
                "resources": {
                    "timeout_ms": 1000
                },
                "network": {"mode": "proxy"}
            }
        }),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let payload = &messages[0]["result"];

    assert_eq!(payload["environment"]["inherit"], "minimal");
    assert_eq!(payload["environment"]["scrub"], json!(["RUNSEAL_SECRET_*"]));
    assert_eq!(payload["environment"]["set"]["CI"], "1");
    assert_eq!(payload["environment"]["proxy"], false);
    assert_eq!(payload["resources"]["timeout_ms"], 1000);
    assert_eq!(
        payload["canonical_policy"]["environment"]["scrub"],
        json!(["RUNSEAL_SECRET_*"])
    );
    assert_eq!(payload["canonical_policy"]["environment"]["set"]["CI"], "1");
    assert_eq!(payload["canonical_policy"]["resources"]["timeout_ms"], 1000);
    Ok(())
}

#[test]
fn inline_policy_rejects_unsafe_filesystem_paths() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "explainPolicy",
        json!({
            "cwd": tmp.path(),
            "policy": {
                "version": "runseal.policy/v1",
                "sandbox_level": "workspace-write",
                "filesystem": {
                    "write": ["../outside"]
                }
            }
        }),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = &messages[0];

    assert_eq!(response["error"]["data"]["code"], "POLICY_INVALID");
    assert!(
        response["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("filesystem.write entries must not contain traversal components")
    );
    Ok(())
}

#[test]
fn sandboxed_policy_without_backend_fails_closed() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "print('must not run')"],
            "cwd": tmp.path(),
            "policy": "read-only"
        }),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .unwrap();
    assert_eq!(
        response["error"]["data"]["code"],
        "BACKEND_CAPABILITY_MISSING"
    );
    assert_eq!(
        response["error"]["data"]["backend"]["name"],
        expected_backend_name()
    );
    assert_eq!(response["error"]["data"]["support"], "unsupported");
    assert_eq!(
        response["error"]["data"]["missing_features"],
        json!(expected_missing_features(&["network_disabled"]))
    );
    let audit_path = response["error"]["data"]["audit_path"]
        .as_str()
        .expect("backend failure must return audit_path");
    let audit_events = read_audit_events(tmp.path(), audit_path)?;
    assert_no_private_windows_setup_terms(&json!(audit_events));
    assert!(
        audit_events
            .iter()
            .any(|event| event["type"] == "sandbox.backend_capability"
                && event["decision"] == "unsupported")
    );
    if cfg!(windows) {
        let plan = &response["error"]["data"]["platform_plan"];
        assert_eq!(plan["enforcement"], "fail-closed-preview");
        assert_eq!(plan["sandbox_level"], "read-only");
        assert_eq!(plan["network"]["mode"], "disabled");
        assert_eq!(plan["network"]["direct_egress"], "deny");
        assert_eq!(plan["network"]["managed_proxy"], "none");
        assert_eq!(plan["process"]["boundary"], "restricted-local-process");
        assert_eq!(plan["process"]["identity"], "low-privilege");
        assert_eq!(plan["process"]["cleanup"], "process-tree");
        assert_eq!(plan["filesystem"]["protected"], json!([]));
        assert_eq!(plan["setup"]["requires_runtime_roots"], true);
        assert_eq!(plan["setup"]["requires_runtime_environment"], true);
        assert_eq!(plan["setup"]["requires_runtime_cleanup"], true);
        assert_eq!(plan["setup"]["requires_network_guard"], true);
        assert_eq!(plan["setup"]["requires_managed_proxy"], false);
        assert_eq!(plan["setup"]["requires_process_boundary"], true);
        assert_eq!(plan["setup"]["fail_closed_on_setup_error"], true);
        assert_no_private_windows_setup_terms(plan);
        assert_eq!(
            plan["required_backend_features"],
            json!([
                "filesystem_policy",
                "runtime_roots",
                "runtime_environment",
                "process_isolation",
                "process_cleanup",
                "direct_network_deny",
                "network_disabled"
            ])
        );
        assert!(
            plan["runtime_root"]
                .as_str()
                .unwrap_or_default()
                .contains(".runseal")
        );
        assert!(plan["profile_root"].as_str().is_some());
        assert!(plan["synthetic_home"].as_str().is_some());
        assert!(plan["temp_root"].as_str().is_some());
        let runtime_env = &plan["environment"]["runtime"];
        assert_eq!(runtime_env["RUNSEAL_HOME"], plan["synthetic_home"]);
        assert_eq!(runtime_env["RUNSEAL_TMP"], plan["temp_root"]);
        assert_eq!(runtime_env["HOME"], plan["synthetic_home"]);
        assert_eq!(runtime_env["USERPROFILE"], plan["profile_root"]);
        assert_eq!(runtime_env["TEMP"], plan["temp_root"]);
        assert_eq!(runtime_env["TMP"], plan["temp_root"]);
        assert!(
            runtime_env["APPDATA"]
                .as_str()
                .unwrap_or_default()
                .contains("AppData")
        );
        assert!(
            runtime_env["LOCALAPPDATA"]
                .as_str()
                .unwrap_or_default()
                .contains("AppData")
        );
        let write_roots = plan["filesystem"]["write"]
            .as_array()
            .expect("read-only write roots must be an array");
        assert!(!write_roots.iter().any(|root| root == &plan["cwd"]));
        for root in [
            &plan["runtime_root"],
            &plan["profile_root"],
            &plan["synthetic_home"],
            &plan["temp_root"],
        ] {
            assert!(
                write_roots.iter().any(|write_root| write_root == root),
                "read-only preview write roots must include runtime root {root}"
            );
        }
        assert!(
            plan["filesystem"]["write"]
                .as_array()
                .expect("read-only write roots must be an array")
                .iter()
                .all(Value::is_string)
        );
        let runtime_root = PathBuf::from(
            plan["runtime_root"]
                .as_str()
                .expect("runtime root must be a string"),
        );
        assert!(
            !runtime_root.exists(),
            "runtime root must be cleaned after fail-closed setup: {}",
            runtime_root.display()
        );
        assert!(audit_events
            .iter()
            .any(|event| event["type"] == "sandbox.prepared" && event["decision"] == "prepared"));
        assert!(
            audit_events
                .iter()
                .any(|event| event["type"] == "sandbox.cleanup" && event["decision"] == "cleaned")
        );
    }
    assert!(
        messages
            .iter()
            .all(|message| message.get("method") != Some(&json!("event")))
    );
    Ok(())
}

#[test]
fn workspace_contained_plan_reports_profile_protection_without_private_paths() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "print('must not run')"],
            "cwd": tmp.path(),
            "policy": "workspace-contained"
        }),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .unwrap();
    assert_eq!(
        response["error"]["data"]["code"],
        "BACKEND_CAPABILITY_MISSING"
    );

    if cfg!(windows) {
        let protected = &response["error"]["data"]["platform_plan"]["filesystem"]["protected"];
        assert_eq!(
            protected,
            &json!(["workspace_metadata", "host_profile", "credential_roots"])
        );
        assert!(
            protected
                .as_array()
                .expect("protected labels must be an array")
                .iter()
                .all(Value::is_string)
        );
    }
    Ok(())
}

#[test]
fn execute_rpc_streams_events_and_final_result() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "print('protocol ok')"],
            "cwd": tmp.path(),
            "policy": "danger-full-access"
        }),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let notifications: Vec<_> = messages
        .iter()
        .filter(|message| message.get("method") == Some(&json!("event")))
        .collect();
    let response = messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .unwrap();
    let event_types: Vec<_> = notifications
        .iter()
        .filter_map(|event| event["params"]["type"].as_str())
        .collect();

    assert!(event_types.contains(&"execution.started"));
    assert!(event_types.contains(&"execution.stdout"));
    assert!(event_types.contains(&"execution.finished"));
    let session_id = response["result"]["session_id"]
        .as_str()
        .expect("ExecutionResult must include session_id");
    let seal_id = response["result"]["seal_id"]
        .as_str()
        .expect("ExecutionResult must include seal_id");
    assert!(session_id.starts_with("sess_"));
    assert!(seal_id.starts_with("seal_"));
    for notification in &notifications {
        assert_event_envelope(&notification["params"])?;
        assert_eq!(notification["params"]["session_id"], session_id);
        assert_eq!(notification["params"]["seal_id"], seal_id);
    }
    let stdout_event = notifications
        .iter()
        .map(|message| &message["params"])
        .find(|event| event["type"] == "execution.stdout")
        .context("execution.stdout notification must exist")?;
    assert!(decode_stream_event(stdout_event)?.contains("protocol ok"));
    assert_eq!(response["result"]["status"], "finished");
    assert_eq!(response["result"]["exit_code"], 0);
    assert_eq!(response["result"]["signal"], Value::Null);
    assert_rfc3339_timestamp(&response["result"]["started_at"])?;
    assert_rfc3339_timestamp(&response["result"]["finished_at"])?;
    assert_eq!(
        response["result"]["platform_plan"]["enforcement"],
        "local-execution"
    );
    assert_eq!(
        response["result"]["platform_plan"]["backend"]["name"],
        expected_backend_name()
    );
    assert_eq!(
        response["result"]["platform_plan"]["environment"]["inherit"],
        "minimal"
    );
    assert_eq!(
        response["result"]["platform_plan"]["process"]["boundary"],
        "local-process"
    );
    assert_eq!(
        response["result"]["platform_plan"]["process"]["identity"],
        "current-user"
    );
    assert_eq!(
        response["result"]["platform_plan"]["process"]["cleanup"],
        "direct-child"
    );
    assert_eq!(
        response["result"]["platform_plan"]["setup"]["requires_runtime_roots"],
        false
    );
    assert_eq!(
        response["result"]["platform_plan"]["setup"]["requires_network_guard"],
        false
    );
    assert_eq!(
        response["result"]["platform_plan"]["setup"]["requires_process_boundary"],
        false
    );
    assert_eq!(
        response["result"]["platform_plan"]["setup"]["fail_closed_on_setup_error"],
        false
    );
    assert!(
        response["result"]["audit_path"]
            .as_str()
            .unwrap_or_default()
            .starts_with(".runseal/audit/sess_")
    );
    assert_eq!(
        response["result"]["audit_path"],
        format!(".runseal/audit/{session_id}.jsonl")
    );
    assert_eq!(response["result"]["sandbox"]["enforced"], false);
    assert_eq!(
        response["result"]["backend"]["name"],
        expected_backend_name()
    );
    assert_eq!(
        response["result"]["backend"]["status"],
        expected_backend_status()
    );
    assert_eq!(response["result"]["output_truncated"], false);
    Ok(())
}

#[test]
fn execute_uses_minimal_environment() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc_with_env(
        &rpc_request(
            "execute",
            json!({
                "command": [
                    python_bin(),
                    "-c",
                    "import os; print('sentinel=' + os.environ.get('RUNSEAL_SECRET_SENTINEL', 'missing'))"
                ],
                "cwd": tmp.path(),
                "policy": "danger-full-access"
            }),
        ),
        &[("RUNSEAL_SECRET_SENTINEL", "blocked")],
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .unwrap();

    assert_eq!(response["result"]["status"], "finished");
    assert_eq!(response["result"]["exit_code"], 0);
    assert!(
        response["result"]["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("sentinel=missing")
    );
    assert!(
        response["result"]["platform_plan"]["environment"]["scrub"]
            .as_array()
            .expect("environment.scrub must be an array")
            .iter()
            .any(|pattern| pattern == "*_TOKEN")
    );
    Ok(())
}
