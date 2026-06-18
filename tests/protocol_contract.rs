use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
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

fn rpc_request(method: &str, params: Value) -> String {
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string() + "\n"
}

fn run_rpc(message: &str) -> Result<Output> {
    let bin = require_runseal_bin()?;
    let mut child = Command::new(bin)
        .args(["rpc", "--stdio"])
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

fn stdout_json_lines(output: &Output) -> Result<Vec<Value>> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).context("stdout line was not valid JSON"))
        .collect()
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
    assert_eq!(payload["features"]["audit_jsonl"], true);
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
        json!(["filesystem_policy", "network_proxy"])
    );
    assert!(
        payload["filesystem"]["write"]
            .as_array()
            .expect("filesystem.write must be an array")
            .iter()
            .any(|path| path == tmp.path().to_string_lossy().as_ref())
    );
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
            "command": ["python3", "-c", code],
            "cwd": tmp.path(),
            "policy": {
                "version": "runseal.policy/v1",
                "filesystem": {"read": [tmp.path()], "write": []},
                "network": {"mode": "none"}
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
fn sandboxed_policy_without_backend_fails_closed() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": ["python3", "-c", "print('must not run')"],
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
        json!(["filesystem_policy", "network_disabled"])
    );
    let audit_path = response["error"]["data"]["audit_path"]
        .as_str()
        .expect("backend failure must return audit_path");
    let audit_events = read_audit_events(tmp.path(), audit_path)?;
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
        assert_eq!(
            plan["required_backend_features"],
            json!(["filesystem_policy", "network_disabled"])
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
        assert!(
            plan["filesystem"]["write"]
                .as_array()
                .expect("read-only write roots must be an array")
                .is_empty()
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
                .any(|event| event["type"] == "sandbox.cleaned" && event["decision"] == "cleaned")
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
fn execute_rpc_streams_events_and_final_result() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": ["python3", "-c", "print('protocol ok')"],
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
    assert_eq!(response["result"]["status"], "finished");
    assert_eq!(response["result"]["exit_code"], 0);
    assert_eq!(
        response["result"]["platform_plan"]["enforcement"],
        "local-execution"
    );
    assert_eq!(
        response["result"]["platform_plan"]["backend"]["name"],
        expected_backend_name()
    );
    assert!(
        response["result"]["audit_path"]
            .as_str()
            .unwrap_or_default()
            .starts_with(".runseal/audit/exec_")
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
    Ok(())
}
