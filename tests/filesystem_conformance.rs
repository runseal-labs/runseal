use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
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

fn execute(policy: &str, cwd: &Path, code: String) -> Result<Value> {
    execute_with_network(policy, cwd, None, code)
}

fn execute_with_network(
    policy: &str,
    cwd: &Path,
    network: Option<&str>,
    code: String,
) -> Result<Value> {
    let params = if let Some(network) = network {
        json!({
            "command": [python_bin(), "-c", code],
            "cwd": cwd,
            "policy": policy,
            "network": {"mode": network}
        })
    } else {
        json!({
            "command": [python_bin(), "-c", code],
            "cwd": cwd,
            "policy": policy
        })
    };
    let output = run_rpc(&rpc_request("execute", params))?;

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
    let expected_features = expected_missing_features(&[]);
    assert_backend_missing_features(response, root, &expected_features)
}

fn assert_backend_unavailable(response: &Value, root: &Path) -> Result<()> {
    assert_eq!(response["error"]["data"]["code"], "BACKEND_UNAVAILABLE");
    assert_no_private_windows_setup_terms(response);
    let audit_path = response["error"]["data"]["audit_path"]
        .as_str()
        .context("unavailable response must include audit_path")?;
    let audit_jsonl = fs::read_to_string(root.join(audit_path))?;
    let audit_events = audit_jsonl
        .lines()
        .map(|line| serde_json::from_str(line).context("audit line must be JSON"))
        .collect::<Result<Vec<Value>>>()?;
    assert_no_private_windows_setup_terms(&json!(&audit_events));
    assert!(audit_events.iter().any(|event| {
        event["type"] == "execution.failed"
            && event["reason"]
                .as_str()
                .unwrap_or_default()
                .starts_with("windows sandbox setup unavailable")
    }));
    Ok(())
}

fn expected_missing_features(additional: &[&'static str]) -> Vec<&'static str> {
    let mut features = vec!["filesystem_policy"];
    if !cfg!(windows) {
        features.push("runtime_roots");
    }
    if !cfg!(windows) {
        features.push("runtime_environment");
    }
    features.push("process_isolation");
    if !cfg!(windows) {
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
        "orchestrator_",
        "helper_",
        "vendored",
        "upstream",
        "Job Object",
        "Codex",
        "OpenAI",
        "WindowsApps",
        "offline",
        "online",
    ] {
        assert!(
            !public_payload.contains(private_term),
            "conformance output must not expose private Windows setup term {private_term}"
        );
    }
}

fn assert_backend_missing_features(
    response: &Value,
    root: &Path,
    expected_features: &[&str],
) -> Result<()> {
    assert_eq!(
        response["error"]["data"]["code"],
        "BACKEND_CAPABILITY_MISSING"
    );
    assert_eq!(response["error"]["data"]["support"], "unsupported");
    assert_no_private_windows_setup_terms(response);
    let missing_features = response["error"]["data"]["missing_features"]
        .as_array()
        .context("unsupported response must include missing_features")?;
    for expected_feature in expected_features {
        assert!(
            missing_features
                .iter()
                .any(|feature| feature == expected_feature),
            "missing_features must include {expected_feature}"
        );
    }

    let audit_path = response["error"]["data"]["audit_path"]
        .as_str()
        .context("unsupported response must include audit_path")?;
    let audit_jsonl = fs::read_to_string(root.join(audit_path))?;
    let audit_events = audit_jsonl
        .lines()
        .map(|line| serde_json::from_str(line).context("audit line must be JSON"))
        .collect::<Result<Vec<Value>>>()?;
    assert_no_private_windows_setup_terms(&json!(&audit_events));
    let backend_event = audit_events
        .iter()
        .find(|event| event["type"] == "sandbox.backend_capability")
        .context("audit must include sandbox.backend_capability event")?;
    for expected_feature in expected_features {
        assert!(
            backend_event["missing_features"]
                .as_array()
                .context("backend audit event must include missing_features")?
                .iter()
                .any(|feature| feature == expected_feature),
            "backend audit event missing_features must include {expected_feature}"
        );
    }
    Ok(())
}

fn is_backend_missing(response: &Value) -> bool {
    response["error"]["data"]["code"] == "BACKEND_CAPABILITY_MISSING"
}

fn is_backend_unavailable(response: &Value) -> bool {
    response["error"]["data"]["code"] == "BACKEND_UNAVAILABLE"
}

fn start_loopback_http_server() -> Result<(u16, thread::JoinHandle<Result<bool>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buffer = [0_u8; 512];
                    let read = stream.read(&mut buffer)?;
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    assert!(request.starts_with("GET /proxy-ok HTTP/1.1"));
                    let body = "proxy-ok";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream.write_all(response.as_bytes())?;
                    return Ok(true);
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => return Ok(false),
                Err(err) => return Err(err.into()),
            }
        }
    });
    Ok((port, handle))
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
    if is_backend_unavailable(&response) {
        assert_backend_unavailable(&response, &workspace)?;
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
    if is_backend_unavailable(&response) {
        assert_backend_unavailable(&response, &workspace)?;
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
    if is_backend_unavailable(&response) {
        assert_backend_unavailable(&response, &workspace)?;
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
    if is_backend_unavailable(&response) {
        assert_backend_unavailable(&response, &workspace)?;
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

#[test]
fn workspace_write_protects_workspace_metadata_when_supported_or_fails_closed() -> Result<()> {
    for protected_subpath in [".git", ".agents", ".codex"] {
        let tmp = TempDir::new()?;
        let workspace = tmp.path().join("workspace");
        let protected_root = workspace.join(protected_subpath);
        fs::create_dir_all(&protected_root)?;
        let target = protected_root.join("blocked.txt");
        let code = format!("from pathlib import Path; Path({target:?}).write_text('blocked')");
        let response = execute("workspace-write", &workspace, code)?;

        if is_backend_missing(&response) {
            assert_backend_missing(&response, &workspace)?;
            assert!(!target.exists());
            continue;
        }
        if is_backend_unavailable(&response) {
            assert_backend_unavailable(&response, &workspace)?;
            assert!(!target.exists());
            continue;
        }

        assert_eq!(response["result"]["status"], "finished");
        assert_ne!(response["result"]["exit_code"], 0);
        assert!(!target.exists());
    }
    Ok(())
}

#[test]
fn runtime_environment_roots_are_per_execution_when_supported_or_fails_closed() -> Result<()> {
    let tmp = TempDir::new()?;
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(&workspace)?;
    let marker = "runseal-runtime-isolation-marker.txt";
    let env_keys = [
        "USERPROFILE",
        "HOME",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
    ];
    let writer_code = format!(
        "import os, pathlib\n\
         keys = {env_keys:?}\n\
         for key in keys:\n\
             root = os.environ[key]\n\
             path = pathlib.Path(root) / {marker:?}\n\
             path.parent.mkdir(parents=True, exist_ok=True)\n\
             path.write_text(key, encoding='utf-8')"
    );
    let first = execute("workspace-write", &workspace, writer_code)?;

    if is_backend_missing(&first) {
        assert_backend_missing(&first, &workspace)?;
        return Ok(());
    }
    if is_backend_unavailable(&first) {
        assert_backend_unavailable(&first, &workspace)?;
        return Ok(());
    }

    assert_eq!(first["result"]["status"], "finished");
    assert_eq!(first["result"]["exit_code"], 0);

    let reader_code = format!(
        "import json, os, pathlib\n\
         keys = {env_keys:?}\n\
         leaked = [key for key in keys if (pathlib.Path(os.environ[key]) / {marker:?}).exists()]\n\
         print(json.dumps(leaked))"
    );
    let second = execute("workspace-write", &workspace, reader_code)?;

    assert_eq!(second["result"]["status"], "finished");
    assert_eq!(second["result"]["exit_code"], 0);
    let leaked = serde_json::from_str::<Value>(
        second["result"]["stdout"]
            .as_str()
            .context("second execution must return stdout")?
            .trim(),
    )?;
    assert_eq!(leaked, json!([]));
    Ok(())
}

#[test]
fn network_disabled_blocks_direct_egress_when_supported_or_fails_closed() -> Result<()> {
    let tmp = TempDir::new()?;
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(&workspace)?;
    let code = "import socket; socket.create_connection(('1.1.1.1', 53), timeout=0.5); print('direct-network-ok')".to_string();
    let response = execute_with_network("workspace-write", &workspace, Some("disabled"), code)?;

    if is_backend_missing(&response) {
        let expected_features = expected_missing_features(&["network_disabled"]);
        assert_backend_missing_features(&response, &workspace, &expected_features)?;
        return Ok(());
    }
    if is_backend_unavailable(&response) {
        assert_backend_unavailable(&response, &workspace)?;
        return Ok(());
    }

    assert_eq!(response["result"]["status"], "finished");
    assert_ne!(response["result"]["exit_code"], 0);
    assert!(
        !response["result"]["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("direct-network-ok")
    );
    Ok(())
}

#[test]
fn network_proxy_blocks_direct_egress_when_supported_or_fails_closed() -> Result<()> {
    let tmp = TempDir::new()?;
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(&workspace)?;
    let code = "import socket; socket.create_connection(('1.1.1.1', 53), timeout=0.5); print('direct-network-ok')".to_string();
    let response = execute_with_network("workspace-write", &workspace, Some("proxy"), code)?;

    if is_backend_missing(&response) {
        let expected_features = expected_missing_features(&["network_proxy", "managed_proxy"]);
        assert_backend_missing_features(&response, &workspace, &expected_features)?;
        return Ok(());
    }
    if is_backend_unavailable(&response) {
        assert_backend_unavailable(&response, &workspace)?;
        return Ok(());
    }

    assert_eq!(response["result"]["status"], "finished");
    assert_ne!(response["result"]["exit_code"], 0);
    assert!(
        !response["result"]["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("direct-network-ok")
    );
    Ok(())
}

#[test]
fn network_proxy_allows_http_through_managed_proxy_when_supported_or_fails_closed() -> Result<()> {
    let tmp = TempDir::new()?;
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(&workspace)?;
    let (port, upstream) = start_loopback_http_server()?;
    let code = format!(
        "import os, socket, urllib.parse\n\
         proxy = urllib.parse.urlparse(os.environ['HTTP_PROXY'])\n\
         with socket.create_connection((proxy.hostname, proxy.port), timeout=2) as s:\n\
             s.sendall(b'GET http://127.0.0.1:{port}/proxy-ok HTTP/1.1\\r\\nHost: 127.0.0.1:{port}\\r\\nConnection: close\\r\\n\\r\\n')\n\
             data = b''\n\
             while True:\n\
                 chunk = s.recv(4096)\n\
                 if not chunk:\n\
                     break\n\
                 data += chunk\n\
         print(data.decode('utf-8', 'replace'))"
    );
    let response = execute_with_network("workspace-write", &workspace, Some("proxy"), code)?;

    if is_backend_missing(&response) {
        let upstream_hit = upstream.join().expect("upstream server thread")?;
        assert!(!upstream_hit);
        let expected_features = expected_missing_features(&["network_proxy", "managed_proxy"]);
        assert_backend_missing_features(&response, &workspace, &expected_features)?;
        return Ok(());
    }
    if is_backend_unavailable(&response) {
        let upstream_hit = upstream.join().expect("upstream server thread")?;
        assert!(!upstream_hit);
        assert_backend_unavailable(&response, &workspace)?;
        return Ok(());
    }

    let upstream_hit = upstream.join().expect("upstream server thread")?;
    assert!(upstream_hit);
    assert_eq!(response["result"]["status"], "finished");
    assert_eq!(response["result"]["exit_code"], 0);
    assert!(
        response["result"]["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("proxy-ok")
    );
    Ok(())
}
