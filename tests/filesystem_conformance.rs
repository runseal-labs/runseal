use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
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

fn execute(policy: &str, cwd: &Path, code: String) -> Result<Value> {
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": ["python3", "-c", code],
            "cwd": cwd,
            "policy": policy
        }),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    stdout_json_lines(&output)?
        .into_iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .context("execute response with id 1 must exist")
}

fn assert_backend_missing(response: &Value, root: &Path) -> Result<()> {
    assert_eq!(
        response["error"]["data"]["code"],
        "BACKEND_CAPABILITY_MISSING"
    );
    assert_eq!(response["error"]["data"]["support"], "unsupported");
    assert!(
        response["error"]["data"]["missing_features"]
            .as_array()
            .context("unsupported response must include missing_features")?
            .iter()
            .any(|feature| feature == "filesystem_policy")
    );

    let audit_path = response["error"]["data"]["audit_path"]
        .as_str()
        .context("unsupported response must include audit_path")?;
    let audit_jsonl = fs::read_to_string(root.join(audit_path))?;
    assert!(audit_jsonl.contains("\"type\":\"sandbox.backend_capability\""));
    Ok(())
}

fn is_backend_missing(response: &Value) -> bool {
    response["error"]["data"]["code"] == "BACKEND_CAPABILITY_MISSING"
}

#[test]
fn workspace_write_allows_workspace_write_when_supported_or_fails_closed() -> Result<()> {
    let tmp = TempDir::new()?;
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(&workspace)?;
    let target = workspace.join("inside.txt");
    let code = format!("from pathlib import Path; Path({target:?}).write_text('inside')");
    let response = execute("workspace-write", &workspace, code)?;

    if is_backend_missing(&response) {
        assert_backend_missing(&response, &workspace)?;
        assert!(!target.exists());
        return Ok(());
    }

    assert_eq!(response["result"]["status"], "finished");
    assert_eq!(response["result"]["exit_code"], 0);
    assert_eq!(fs::read_to_string(target)?, "inside");
    Ok(())
}

#[test]
fn workspace_write_denies_external_write_when_supported_or_fails_closed() -> Result<()> {
    let tmp = TempDir::new()?;
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(&workspace)?;
    let outside = tmp.path().join("outside.txt");
    let code = format!("from pathlib import Path; Path({outside:?}).write_text('outside')");
    let response = execute("workspace-write", &workspace, code)?;

    if is_backend_missing(&response) {
        assert_backend_missing(&response, &workspace)?;
        assert!(!outside.exists());
        return Ok(());
    }

    assert_eq!(response["result"]["status"], "finished");
    assert_ne!(response["result"]["exit_code"], 0);
    assert!(!outside.exists());
    Ok(())
}

#[test]
fn read_only_denies_workspace_write_when_supported_or_fails_closed() -> Result<()> {
    let tmp = TempDir::new()?;
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(&workspace)?;
    let target = workspace.join("read-only-write.txt");
    let code = format!("from pathlib import Path; Path({target:?}).write_text('blocked')");
    let response = execute("read-only", &workspace, code)?;

    if is_backend_missing(&response) {
        assert_backend_missing(&response, &workspace)?;
        assert!(!target.exists());
        return Ok(());
    }

    assert_eq!(response["result"]["status"], "finished");
    assert_ne!(response["result"]["exit_code"], 0);
    assert!(!target.exists());
    Ok(())
}

#[test]
fn workspace_contained_denies_external_read_when_supported_or_fails_closed() -> Result<()> {
    let tmp = TempDir::new()?;
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(&workspace)?;
    let outside = tmp.path().join("host-profile-secret.txt");
    fs::write(&outside, "outside-secret")?;
    let code = format!("from pathlib import Path; print(Path({outside:?}).read_text())");
    let response = execute("workspace-contained", &workspace, code)?;

    if is_backend_missing(&response) {
        assert_backend_missing(&response, &workspace)?;
        return Ok(());
    }

    assert_eq!(response["result"]["status"], "finished");
    assert_ne!(response["result"]["exit_code"], 0);
    assert!(
        !response["result"]["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("outside-secret")
    );
    Ok(())
}
