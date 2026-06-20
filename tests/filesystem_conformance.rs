use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
#[cfg(windows)]
use std::sync::{Mutex, MutexGuard};
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

fn platform_script_command(python_code: String, powershell_script: String) -> Vec<String> {
    if cfg!(windows) {
        vec![
            "powershell".to_string(),
            "-NoProfile".to_string(),
            "-Command".to_string(),
            powershell_script,
        ]
    } else {
        vec![python_bin().to_string(), "-c".to_string(), python_code]
    }
}

fn stdin_echo_command() -> Vec<String> {
    if cfg!(windows) {
        vec![
            "powershell".to_string(),
            "-NoProfile".to_string(),
            "-Command".to_string(),
            "$text = [Console]::In.ReadToEnd(); [Console]::Out.Write($text)".to_string(),
        ]
    } else {
        vec![
            python_bin().to_string(),
            "-c".to_string(),
            "import sys; print(sys.stdin.buffer.read().decode('utf-8'), end='')".to_string(),
        ]
    }
}

fn execute_platform_script(
    policy: &str,
    cwd: &Path,
    network: Option<&str>,
    python_code: String,
    powershell_script: String,
) -> Result<Value> {
    execute_params(platform_script_params(
        policy,
        cwd,
        network,
        python_code,
        powershell_script,
    ))
}

fn platform_script_params(
    policy: &str,
    cwd: &Path,
    network: Option<&str>,
    python_code: String,
    powershell_script: String,
) -> Value {
    let mut params = json!({
        "command": platform_script_command(python_code, powershell_script),
        "cwd": cwd,
        "policy": policy
    });
    if let Some(network) = network {
        params["network"] = json!({"mode": network});
    }
    params
}

fn ps_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn ps_path(path: &Path) -> String {
    ps_literal(path.to_string_lossy().as_ref())
}

fn ps_write_text(path: &Path, text: &str) -> String {
    format!(
        "Set-Content -LiteralPath {} -Value {} -NoNewline",
        ps_path(path),
        ps_literal(text)
    )
}

fn stdout_json_lines(output: &Output) -> Result<Vec<Value>> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).context("stdout line was not valid JSON"))
        .collect()
}

fn execute_params(params: Value) -> Result<Value> {
    #[cfg(windows)]
    let _guard = windows_conformance_lock()?;

    execute_params_unlocked(params)
}

fn execute_params_unlocked(params: Value) -> Result<Value> {
    execute_messages_unlocked(params)?
        .into_iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .context("execute response with id 1 must exist")
}

fn execute_messages_unlocked(params: Value) -> Result<Vec<Value>> {
    let output = run_rpc(&rpc_request("execute", params))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    stdout_json_lines(&output)
}

#[cfg(windows)]
fn windows_conformance_lock() -> Result<MutexGuard<'static, ()>> {
    static LOCK: Mutex<()> = Mutex::new(());
    // RunSeal tests share global Windows sandbox state; use narrower locks if test throughput matters.
    LOCK.lock()
        .map_err(|_| anyhow::anyhow!("windows conformance lock poisoned"))
}

fn assert_backend_missing(response: &Value, root: &Path) -> Result<()> {
    let expected_features = expected_missing_features(&[]);
    assert_backend_missing_features(response, root, &expected_features)
}

fn assert_backend_unavailable(response: &Value, root: &Path) -> Result<()> {
    assert_eq!(response["error"]["data"]["code"], "BACKEND_UNAVAILABLE");
    if cfg!(windows) {
        let setup_status = &response["error"]["data"]["setup_status"];
        assert_eq!(setup_status["setup"], "windows-sandbox");
        assert_eq!(setup_status["platform_supported"], true);
        assert!(
            matches!(
                setup_status["broker"].as_str(),
                Some("available" | "unavailable")
            ),
            "{setup_status}"
        );
        assert!(setup_status["elevated"].is_boolean(), "{setup_status}");
        let elevated = setup_status["elevated"].as_bool().unwrap_or(false);
        let broker_available = setup_status["broker"] == "available";
        assert_eq!(
            setup_status["can_repair"].as_bool(),
            Some(elevated || broker_available),
            "{setup_status}"
        );
        assert_eq!(
            setup_status["can_run_setup_now"].as_bool(),
            Some(elevated || broker_available),
            "{setup_status}"
        );
        assert!(
            matches!(
                setup_status["next_action"].as_str(),
                Some("none" | "run_setup" | "open_elevated_shell" | "unsupported")
            ),
            "{setup_status}"
        );
    }
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
    for event in &audit_events {
        assert_audit_event_envelope(event);
    }
    let failed_event = audit_events
        .iter()
        .find(|event| {
            event["type"] == "execution.failed"
                && event["reason"]
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("windows sandbox setup unavailable")
        })
        .context("backend unavailable audit must include execution.failed")?;
    if cfg!(windows) {
        assert_eq!(
            failed_event["setup_status"],
            response["error"]["data"]["setup_status"]
        );
    }
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
        "WindowsSandboxSetup",
        "scheduled task",
        "sandbox account",
        "local user",
        "profile account",
        "SID",
        "ACL",
        "WFP",
        "firewall",
        "Job Object",
        "Codex",
        "OpenAI",
        "WindowsApps",
        "offline",
        "online",
        "dual",
        "two users",
    ] {
        assert!(
            !public_payload.contains(private_term),
            "conformance output must not expose private Windows setup term {private_term}"
        );
    }
}

fn assert_audit_event_envelope(event: &Value) {
    assert!(event["type"].as_str().is_some());
    assert!(event["time"].as_str().is_some());
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
    assert_eq!(event["policy_epoch"], event["policy_hash"]);
    assert!(event["runseal_version"].as_str().is_some());
    assert!(
        event["audit_path"]
            .as_str()
            .unwrap_or_default()
            .starts_with(".runseal/audit/sess_")
    );
    assert!(event["backend"]["name"].as_str().is_some());
    assert!(event["backend"]["status"].as_str().is_some());
    assert!(event["backend"]["platform"].as_str().is_some());
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
    assert_eq!(missing_features, expected_features);

    let audit_path = response["error"]["data"]["audit_path"]
        .as_str()
        .context("unsupported response must include audit_path")?;
    let audit_jsonl = fs::read_to_string(root.join(audit_path))?;
    let audit_events = audit_jsonl
        .lines()
        .map(|line| serde_json::from_str(line).context("audit line must be JSON"))
        .collect::<Result<Vec<Value>>>()?;
    assert_no_private_windows_setup_terms(&json!(&audit_events));
    for event in &audit_events {
        assert_audit_event_envelope(event);
    }
    let backend_event = audit_events
        .iter()
        .find(|event| event["type"] == "sandbox.backend_capability")
        .context("audit must include sandbox.backend_capability event")?;
    assert_eq!(
        backend_event["missing_features"]
            .as_array()
            .context("backend audit event must include missing_features")?,
        expected_features
    );
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
        let deadline = Instant::now() + Duration::from_secs(10);
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
    let response = execute_platform_script(
        "workspace-write",
        &workspace,
        None,
        code,
        ps_write_text(&target, "inside"),
    )?;

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
    let response = execute_platform_script(
        "workspace-write",
        &workspace,
        None,
        code,
        ps_write_text(&outside, "outside"),
    )?;

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
fn read_only_allows_workspace_read_when_supported_or_fails_closed() -> Result<()> {
    let tmp = TempDir::new()?;
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(&workspace)?;
    let target = workspace.join("readable.txt");
    fs::write(&target, "workspace-readable")?;
    let code = format!("from pathlib import Path; print(Path({target:?}).read_text())");
    let response = execute_platform_script(
        "read-only",
        &workspace,
        None,
        code,
        format!("Get-Content -Raw -LiteralPath {}", ps_path(&target)),
    )?;

    if is_backend_missing(&response) {
        assert_backend_missing(&response, &workspace)?;
        assert_eq!(fs::read_to_string(target)?, "workspace-readable");
        return Ok(());
    }
    if is_backend_unavailable(&response) {
        assert_backend_unavailable(&response, &workspace)?;
        assert_eq!(fs::read_to_string(target)?, "workspace-readable");
        return Ok(());
    }

    assert_eq!(response["result"]["status"], "finished");
    assert_eq!(response["result"]["exit_code"], 0);
    assert!(
        response["result"]["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("workspace-readable")
    );
    Ok(())
}

#[test]
fn read_only_denies_workspace_write_when_supported_or_fails_closed() -> Result<()> {
    let tmp = TempDir::new()?;
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(&workspace)?;
    let target = workspace.join("read-only-write.txt");
    let code = format!("from pathlib import Path; Path({target:?}).write_text('blocked')");
    let response = execute_platform_script(
        "read-only",
        &workspace,
        None,
        code,
        ps_write_text(&target, "blocked"),
    )?;

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
fn read_only_proxy_network_requires_supported_backend_or_fails_closed() -> Result<()> {
    let tmp = TempDir::new()?;
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(&workspace)?;
    let response = execute_platform_script(
        "read-only",
        &workspace,
        Some("proxy"),
        "print('read-only-proxy-ok')".to_string(),
        "'read-only-proxy-ok'".to_string(),
    )?;

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
    assert_eq!(response["result"]["exit_code"], 0);
    assert!(
        response["result"]["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("read-only-proxy-ok")
    );
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
    let response = execute_platform_script(
        "workspace-contained",
        &workspace,
        None,
        code,
        format!("Get-Content -Raw -LiteralPath {}", ps_path(&outside)),
    )?;

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
        let response = execute_platform_script(
            "workspace-write",
            &workspace,
            None,
            code,
            ps_write_text(&target, "blocked"),
        )?;

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
         roots = [os.environ[key] for key in keys]\n\
         roots.append(os.environ['HOMEDRIVE'] + os.environ['HOMEPATH'])\n\
         for root in roots:\n\
             path = pathlib.Path(root) / {marker:?}\n\
             path.parent.mkdir(parents=True, exist_ok=True)\n\
             path.write_text(root, encoding='utf-8')"
    );
    let ps_writer = format!(
        "$keys = @({}); \
         $roots = @(); \
         foreach ($key in $keys) {{ $roots += [Environment]::GetEnvironmentVariable($key) }}; \
         $roots += \"$env:HOMEDRIVE$env:HOMEPATH\"; \
         foreach ($root in $roots) {{ \
             $path = Join-Path $root {}; \
             New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null; \
             Set-Content -LiteralPath $path -Value $root -NoNewline \
         }}",
        env_keys
            .iter()
            .map(|key| ps_literal(key))
            .collect::<Vec<_>>()
            .join(","),
        ps_literal(marker)
    );
    let first =
        execute_platform_script("workspace-write", &workspace, None, writer_code, ps_writer)?;

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
         roots = [(key, os.environ[key]) for key in keys]\n\
         roots.append(('HOMEDRIVE+HOMEPATH', os.environ['HOMEDRIVE'] + os.environ['HOMEPATH']))\n\
         leaked = [key for key, root in roots if (pathlib.Path(root) / {marker:?}).exists()]\n\
         print(json.dumps(leaked))"
    );
    let ps_reader = format!(
        "$keys = @({}); \
         $roots = @(); \
         foreach ($key in $keys) {{ $roots += @($key, [Environment]::GetEnvironmentVariable($key)) }}; \
         $roots += @('HOMEDRIVE+HOMEPATH', \"$env:HOMEDRIVE$env:HOMEPATH\"); \
         $leaked = @(); \
         for ($i = 0; $i -lt $roots.Count; $i += 2) {{ \
             if (Test-Path -LiteralPath (Join-Path $roots[$i + 1] {})) {{ $leaked += $roots[$i] }} \
         }}; \
         if ($leaked.Count -eq 0) {{ '[]' }} else {{ $leaked | ConvertTo-Json -Compress }}",
        env_keys
            .iter()
            .map(|key| ps_literal(key))
            .collect::<Vec<_>>()
            .join(","),
        ps_literal(marker)
    );
    let second =
        execute_platform_script("workspace-write", &workspace, None, reader_code, ps_reader)?;

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
fn workspace_write_accepts_bytes_stdin_when_supported_or_fails_closed() -> Result<()> {
    let tmp = TempDir::new()?;
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(&workspace)?;
    let stdin_text = "runseal sandbox stdin bytes";
    let encoded = STANDARD.encode(stdin_text.as_bytes());
    let response = execute_params(json!({
        "command": stdin_echo_command(),
        "cwd": workspace,
        "policy": "workspace-write",
        "network": {"mode": "disabled"},
        "stdin": {
            "mode": "bytes",
            "data": format!("base64:{encoded}"),
            "encoding": "base64"
        }
    }))?;

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
    assert_eq!(response["result"]["exit_code"], 0);
    assert_eq!(
        response["result"]["stdout"].as_str().unwrap_or_default(),
        stdin_text
    );
    Ok(())
}

#[test]
fn workspace_write_accepts_file_stdin_when_supported_or_fails_closed() -> Result<()> {
    let tmp = TempDir::new()?;
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(&workspace)?;
    let stdin_path = workspace.join("stdin-payload.txt");
    let stdin_text = "runseal sandbox stdin file";
    fs::write(&stdin_path, stdin_text)?;
    let response = execute_params(json!({
        "command": stdin_echo_command(),
        "cwd": workspace,
        "policy": "workspace-write",
        "network": {"mode": "disabled"},
        "stdin": {
            "mode": "file",
            "path": stdin_path
        }
    }))?;

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
    assert_eq!(response["result"]["exit_code"], 0);
    assert_eq!(
        response["result"]["stdout"].as_str().unwrap_or_default(),
        stdin_text
    );
    Ok(())
}

#[test]
fn network_disabled_blocks_direct_egress_when_supported_or_fails_closed() -> Result<()> {
    let tmp = TempDir::new()?;
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(&workspace)?;
    let code = "import socket; socket.create_connection(('1.1.1.1', 53), timeout=0.5); print('direct-network-ok')".to_string();
    let ps_code = "$ErrorActionPreference = 'Stop'; \
                   $client = [Net.Sockets.TcpClient]::new(); \
                   $async = $client.BeginConnect('1.1.1.1', 53, $null, $null); \
                   if ($async.AsyncWaitHandle.WaitOne(500)) { \
                       $client.EndConnect($async); \
                       'direct-network-ok' \
                   } else { throw 'direct network timeout' }"
        .to_string();
    let response = execute_platform_script(
        "workspace-write",
        &workspace,
        Some("disabled"),
        code,
        ps_code,
    )?;

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
    let ps_code = "$ErrorActionPreference = 'Stop'; \
                   $client = [Net.Sockets.TcpClient]::new(); \
                   $async = $client.BeginConnect('1.1.1.1', 53, $null, $null); \
                   if ($async.AsyncWaitHandle.WaitOne(500)) { \
                       $client.EndConnect($async); \
                       'direct-network-ok' \
                   } else { throw 'direct network timeout' }"
        .to_string();
    let response =
        execute_platform_script("workspace-write", &workspace, Some("proxy"), code, ps_code)?;

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
    #[cfg(windows)]
    let _guard = windows_conformance_lock()?;
    let warmup = execute_params_unlocked(platform_script_params(
        "workspace-write",
        &workspace,
        Some("proxy"),
        "print('proxy-warmup')".to_string(),
        "Write-Output proxy-warmup".to_string(),
    ))?;
    if is_backend_missing(&warmup) {
        let expected_features = expected_missing_features(&["network_proxy", "managed_proxy"]);
        assert_backend_missing_features(&warmup, &workspace, &expected_features)?;
        return Ok(());
    }
    if is_backend_unavailable(&warmup) {
        assert_backend_unavailable(&warmup, &workspace)?;
        return Ok(());
    }
    assert_eq!(warmup["result"]["status"], "finished");
    assert_eq!(warmup["result"]["exit_code"], 0);

    let (port, upstream) = start_loopback_http_server()?;
    let code = format!(
        "import os, socket, time, urllib.parse\n\
         proxy = urllib.parse.urlparse(os.environ['HTTP_PROXY'])\n\
         proxy_auth = 'Proxy-Authorization: ' + os.environ['RUNSEAL_NETWORK_PROXY_AUTHORIZATION'] + '\\r\\n'\n\
         request = f'GET http://127.0.0.1:{port}/proxy-ok HTTP/1.1\\r\\nHost: 127.0.0.1:{port}\\r\\n{{proxy_auth}}Connection: close\\r\\n\\r\\n'.encode('ascii')\n\
         deadline = time.monotonic() + 8\n\
         last = None\n\
         while time.monotonic() < deadline:\n\
             try:\n\
                 with socket.create_connection((proxy.hostname, proxy.port), timeout=2) as s:\n\
                     s.settimeout(2)\n\
                     s.sendall(request)\n\
                     data = b''\n\
                     while True:\n\
                         chunk = s.recv(4096)\n\
                         if not chunk:\n\
                             break\n\
                         data += chunk\n\
                 text = data.decode('utf-8', 'replace')\n\
                 if 'proxy-ok' in text:\n\
                     print(text)\n\
                     break\n\
                 last = 'unexpected proxy response: ' + text\n\
             except Exception as exc:\n\
                 last = str(exc)\n\
             time.sleep(0.25)\n\
         else:\n\
             raise RuntimeError('proxy request did not reach upstream: ' + str(last))"
    );
    let proxy_request = format!(
        "\"GET http://127.0.0.1:{port}/proxy-ok HTTP/1.1`r`nHost: 127.0.0.1:{port}`r`nConnection: close`r`n`r`n\""
    );
    let ps_code = r#"
$ErrorActionPreference = 'Stop'
$proxy = [Uri]$env:HTTP_PROXY
$request = __REQUEST__
$request = $request.Replace("Connection: close`r`n", "Proxy-Authorization: $env:RUNSEAL_NETWORK_PROXY_AUTHORIZATION`r`nConnection: close`r`n")
$deadline = [DateTime]::UtcNow.AddSeconds(8)
$last = $null
$successText = $null
while ([DateTime]::UtcNow -lt $deadline) {
    $client = $null
    try {
        $client = [Net.Sockets.TcpClient]::new()
        $client.ReceiveTimeout = 2000
        $client.SendTimeout = 2000
        $client.Connect($proxy.Host, $proxy.Port)
        $stream = $client.GetStream()
        $bytes = [Text.Encoding]::ASCII.GetBytes($request)
        $stream.Write($bytes, 0, $bytes.Length)
        $buffer = New-Object byte[] 4096
        $text = ''
        while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $text += [Text.Encoding]::UTF8.GetString($buffer, 0, $count)
        }
        if ($text.Contains('proxy-ok')) {
            $successText = $text
            break
        }
        $last = "unexpected proxy response: $text"
    } catch {
        $last = $_.Exception.Message
    } finally {
        if ($null -ne $client) {
            $client.Dispose()
        }
    }
    Start-Sleep -Milliseconds 250
}
if ($null -eq $successText) {
    throw "proxy request did not reach upstream: $last"
}
$successText
"#
    .replace("__REQUEST__", &proxy_request);
    let messages = execute_messages_unlocked(platform_script_params(
        "workspace-write",
        &workspace,
        Some("proxy"),
        code,
        ps_code,
    ))?;
    let response = messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .context("execute response with id 1 must exist")?;

    if is_backend_missing(response) {
        let upstream_hit = upstream.join().expect("upstream server thread")?;
        assert!(!upstream_hit);
        let expected_features = expected_missing_features(&["network_proxy", "managed_proxy"]);
        assert_backend_missing_features(response, &workspace, &expected_features)?;
        return Ok(());
    }
    if is_backend_unavailable(response) {
        let upstream_hit = upstream.join().expect("upstream server thread")?;
        assert!(!upstream_hit);
        assert_backend_unavailable(response, &workspace)?;
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
    let audit_path = response["result"]["audit_path"]
        .as_str()
        .context("successful response must include audit_path")?;
    let audit_jsonl = fs::read_to_string(workspace.join(audit_path))?;
    assert_no_proxy_credential_terms_in_str(&audit_jsonl);
    let audit_events = audit_jsonl
        .lines()
        .map(|line| serde_json::from_str(line).context("audit line must be JSON"))
        .collect::<Result<Vec<Value>>>()?;
    assert!(
        audit_events
            .iter()
            .any(|event| event["type"] == "execution.network.proxy_ready"),
        "managed proxy executions must audit proxy readiness"
    );
    assert!(
        audit_events
            .iter()
            .any(|event| event["type"] == "execution.network.request"),
        "managed proxy executions must audit proxy requests"
    );
    assert!(
        messages.iter().any(|message| {
            message.get("method") == Some(&json!("event"))
                && message["params"]["type"] == "execution.network.request"
        }),
        "managed proxy executions must stream proxy request events"
    );
    Ok(())
}

#[test]
fn network_proxy_credentials_are_redacted_when_supported_or_fails_closed() -> Result<()> {
    let tmp = TempDir::new()?;
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(&workspace)?;
    let response = execute_platform_script(
        "workspace-write",
        &workspace,
        Some("proxy"),
        "print('proxy-redaction-ok')".to_string(),
        "Write-Output proxy-redaction-ok".to_string(),
    )?;

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
    assert_eq!(response["result"]["exit_code"], 0);
    assert!(
        response["result"]["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("proxy-redaction-ok")
    );
    assert_no_proxy_credential_terms(&response);

    let audit_path = response["result"]["audit_path"]
        .as_str()
        .context("successful response must include audit_path")?;
    let audit_jsonl = fs::read_to_string(workspace.join(audit_path))?;
    assert_no_proxy_credential_terms_in_str(&audit_jsonl);
    Ok(())
}

fn assert_no_proxy_credential_terms(value: &Value) {
    assert_no_proxy_credential_terms_in_str(&value.to_string());
}

fn assert_no_proxy_credential_terms_in_str(payload: &str) {
    for private_term in [
        "http://runseal:",
        "https://runseal:",
        "Proxy-Authorization",
        "proxy-authorization",
        "Basic runseal",
    ] {
        assert!(
            !payload.contains(private_term),
            "structured output must not expose proxy credential term {private_term}"
        );
    }
}
