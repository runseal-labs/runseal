use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
#[cfg(windows)]
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;
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

fn rpc_request_with_id(id: u64, method: &str, params: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string() + "\n"
}

fn run_rpc(message: &str) -> Result<Output> {
    run_rpc_with_env(message, &[])
}

fn run_rpc_with_env(message: &str, envs: &[(&str, &str)]) -> Result<Output> {
    #[cfg(windows)]
    let _guard = windows_protocol_lock()?;

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

#[cfg(windows)]
fn windows_protocol_lock() -> Result<MutexGuard<'static, ()>> {
    static LOCK: Mutex<()> = Mutex::new(());
    // ponytail: global Windows sandbox state; split by policy if protocol test time matters.
    LOCK.lock()
        .map_err(|_| anyhow::anyhow!("windows protocol lock poisoned"))
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

fn response_with_id(messages: &[Value], id: u64) -> Result<&Value> {
    messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(id)))
        .with_context(|| format!("response id {id} must exist"))
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
    assert!(event["type"].as_str().is_some());
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
    assert!(event["policy_epoch"].as_str().is_some());
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
    Ok(())
}

fn assert_error_execution_binding(error: &Value) {
    assert!(
        error["execution_id"]
            .as_str()
            .unwrap_or_default()
            .starts_with("exec_")
    );
    assert!(
        error["session_id"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sess_")
    );
    assert!(error["policy_id"].as_str().is_some());
    assert!(
        error["policy_hash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sha256:")
    );
    assert_eq!(error["policy_epoch"], error["policy_hash"]);
    assert_eq!(error["backend"]["name"], expected_backend_name());
    assert_eq!(error["backend"]["status"], expected_backend_status());
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
        "reference"
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

fn expected_windows_sandbox_supported() -> bool {
    cfg!(windows)
}

fn expected_resource_limits_supported() -> bool {
    false
}

fn expected_status(supported: bool) -> &'static str {
    if supported {
        "supported"
    } else {
        "unsupported"
    }
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
            "public protocol must not expose private Windows setup term {private_term}"
        );
    }
}

fn path_equals_existing(left: &str, right: &std::path::Path) -> bool {
    let Ok(left) = PathBuf::from(left).canonicalize() else {
        return false;
    };
    let Ok(right) = right.canonicalize() else {
        return false;
    };
    left == right
}

fn assert_backend_unavailable(response: &Value, root: &std::path::Path) -> Result<()> {
    assert_eq!(response["error"]["data"]["code"], "BACKEND_UNAVAILABLE");
    assert_eq!(
        response["error"]["data"]["backend"]["name"],
        expected_backend_name()
    );
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
        .context("unavailable response must return audit_path")?;
    let audit_events = read_audit_events(root, audit_path)?;
    assert_no_private_windows_setup_terms(&json!(audit_events));
    Ok(())
}

fn assert_portable_capability_probe_contract(payload: &Value) {
    if cfg!(windows) {
        assert!(payload.get("capability_probes").is_none());
        return;
    }

    let probes = &payload["capability_probes"];
    assert_eq!(probes["sandboxed_execution"], "unsupported");
    assert_eq!(probes["filesystem_enforcement"], "unsupported");
    assert_eq!(probes["network_enforcement"], "unsupported");
    let serialized = payload.to_string();
    assert!(!serialized.contains("/proc/"));
    assert!(!serialized.contains("/sys/"));
    assert!(!serialized.contains("/usr/bin"));

    if cfg!(target_os = "linux") {
        for key in [
            "user_namespace",
            "mount_namespace",
            "pid_namespace",
            "network_namespace",
            "seccomp",
            "landlock",
            "bubblewrap",
            "max_user_namespaces",
            "unprivileged_user_namespace",
        ] {
            assert!(probes["runtime"][key].as_str().is_some(), "{key}");
        }
        assert!(
            probes["runtime"]["landlock_abi"]["status"]
                .as_str()
                .is_some()
        );
    }

    if cfg!(target_os = "macos") {
        assert!(probes["runtime"]["sandbox_exec"].as_str().is_some());
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
fn rpc_stdio_replies_before_stdin_eof() -> Result<()> {
    let bin = require_runseal_bin()?;
    let mut child = Command::new(bin)
        .args(["rpc", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn runseal rpc")?;
    let mut stdin = child.stdin.take().context("stdin unavailable")?;
    let stdout = child.stdout.take().context("stdout unavailable")?;

    stdin.write_all(rpc_request("getVersion", json!({})).as_bytes())?;
    stdin.flush()?;

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = tx.send(result);
    });
    let line = rx
        .recv_timeout(Duration::from_secs(2))
        .context("rpc response timed out before stdin eof")??;
    let response: Value = serde_json::from_str(&line)?;
    assert_eq!(response["id"], 1);
    assert_eq!(
        response["result"]["protocol_version"],
        "runseal.protocol/v1"
    );

    drop(stdin);
    let status = child.wait().context("failed to wait for runseal rpc")?;
    assert!(status.success());
    Ok(())
}

#[test]
fn rpc_stdio_reports_parse_error_and_continues() -> Result<()> {
    let mut child = Command::new(require_runseal_bin()?)
        .args(["rpc", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn runseal rpc")?;
    let mut stdin = child.stdin.take().context("stdin unavailable")?;
    let stdout = child.stdout.take().context("stdout unavailable")?;
    let mut stdout = BufReader::new(stdout);

    stdin.write_all(b"{not-json\n")?;
    stdin.write_all(rpc_request_with_id(1, "getVersion", json!({})).as_bytes())?;
    stdin.flush()?;

    let mut parse_line = String::new();
    stdout
        .read_line(&mut parse_line)
        .context("failed to read parse error response")?;
    let parse_response: Value =
        serde_json::from_str(&parse_line).context("parse error response must be JSON")?;
    assert_eq!(parse_response["id"], Value::Null);
    assert_eq!(parse_response["error"]["code"], -32700);
    assert_eq!(parse_response["error"]["data"]["code"], "INVALID_REQUEST");
    assert!(
        parse_response["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("invalid JSON-RPC request")
    );

    let (_, ok_response) = read_rpc_response(&mut stdout, 1)?;
    assert_eq!(
        ok_response["result"]["protocol_version"],
        "runseal.protocol/v1"
    );

    drop(stdin);
    let status = child.wait().context("failed to wait for runseal rpc")?;
    assert!(status.success());
    Ok(())
}

#[test]
fn rpc_stdio_ignores_client_notification_and_continues() -> Result<()> {
    let mut child = Command::new(require_runseal_bin()?)
        .args(["rpc", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn runseal rpc")?;
    let mut stdin = child.stdin.take().context("stdin unavailable")?;
    let stdout = child.stdout.take().context("stdout unavailable")?;
    let mut stdout = BufReader::new(stdout);

    let notification = json!({
        "jsonrpc": "2.0",
        "method": "getVersion",
        "params": {}
    })
    .to_string()
        + "\n";
    stdin.write_all(notification.as_bytes())?;
    stdin.write_all(br#"{"jsonrpc":"2.0","params":{}}"#)?;
    stdin.write_all(b"\n")?;
    stdin.write_all(rpc_request_with_id(1, "getVersion", json!({})).as_bytes())?;
    stdin.flush()?;

    let (notifications, ok_response) = read_rpc_response(&mut stdout, 1)?;
    assert!(
        notifications.is_empty(),
        "client notification produced messages: {notifications:?}"
    );
    assert_eq!(
        ok_response["result"]["protocol_version"],
        "runseal.protocol/v1"
    );

    drop(stdin);
    let status = child.wait().context("failed to wait for runseal rpc")?;
    assert!(status.success());
    Ok(())
}

#[test]
fn rpc_stdio_does_not_keep_completed_execution_state() -> Result<()> {
    #[cfg(windows)]
    let _guard = windows_protocol_lock()?;

    let tmp = TempDir::new()?;
    let mut child = Command::new(require_runseal_bin()?)
        .args(["rpc", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn runseal rpc")?;
    let mut stdin = child.stdin.take().context("stdin unavailable")?;
    let stdout = child.stdout.take().context("stdout unavailable")?;
    let mut stdout = BufReader::new(stdout);

    stdin.write_all(
        rpc_request_with_id(
            1,
            "execute",
            json!({
                "command": [python_bin(), "-c", "print('direct-rpc')"],
                "cwd": tmp.path(),
                "policy": "danger-full-access",
            }),
        )
        .as_bytes(),
    )?;
    let (_, execute_response) = read_rpc_response(&mut stdout, 1)?;
    let execution_id = execute_response["result"]["execution_id"]
        .as_str()
        .context("execute result must include execution_id")?
        .to_string();

    stdin.write_all(
        rpc_request_with_id(2, "getExecution", json!({ "execution_id": execution_id })).as_bytes(),
    )?;
    let (_, get_response) = read_rpc_response(&mut stdout, 2)?;
    assert_eq!(get_response["error"]["data"]["code"], "EXECUTION_NOT_FOUND");

    drop(stdin);
    let status = child.wait().context("failed to wait for runseal rpc")?;
    assert!(status.success());
    Ok(())
}

#[test]
fn service_stdio_lists_execution_summaries() -> Result<()> {
    #[cfg(windows)]
    let _guard = windows_protocol_lock()?;

    let tmp = TempDir::new()?;
    let mut child = Command::new(require_runseal_bin()?)
        .args(["service", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn runseal service")?;
    let mut stdin = child.stdin.take().context("stdin unavailable")?;
    let stdout = child.stdout.take().context("stdout unavailable")?;
    let mut stdout = BufReader::new(stdout);

    stdin.write_all(
        rpc_request_with_id(
            1,
            "execute",
            json!({
                "command": [python_bin(), "-c", "print('secret-output')"],
                "cwd": tmp.path(),
                "policy": "danger-full-access",
            }),
        )
        .as_bytes(),
    )?;
    let (_, execute_response) = read_rpc_response(&mut stdout, 1)?;
    let execution_id = execute_response["result"]["execution_id"]
        .as_str()
        .context("execute result must include execution_id")?
        .to_string();

    stdin.write_all(rpc_request_with_id(2, "listExecutions", json!({})).as_bytes())?;
    let (_, list_response) = read_rpc_response(&mut stdout, 2)?;
    assert_eq!(list_response["result"]["count"], 1);
    let executions = list_response["result"]["executions"]
        .as_array()
        .context("executions must be an array")?;
    let summary = &executions[0];
    assert_eq!(summary["execution_id"], execution_id);
    assert_eq!(summary["status"], "finished");
    assert_eq!(summary["policy_id"], "danger-full-access");
    assert!(summary["stdout_bytes"].as_u64().is_some());
    assert_rfc3339_timestamp(&summary["started_at"])?;
    assert_rfc3339_timestamp(&summary["finished_at"])?;
    assert!(summary.get("stdout").is_none());
    assert!(summary.get("stderr").is_none());
    assert!(summary.get("platform_plan").is_none());
    assert!(!summary.to_string().contains("secret-output"));

    drop(stdin);
    let status = child.wait().context("failed to wait for runseal service")?;
    assert!(status.success());
    Ok(())
}

#[test]
fn service_stdio_returns_audit_events_by_execution() -> Result<()> {
    #[cfg(windows)]
    let _guard = windows_protocol_lock()?;

    let tmp = TempDir::new()?;
    let mut child = Command::new(require_runseal_bin()?)
        .args(["service", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn runseal service")?;
    let mut stdin = child.stdin.take().context("stdin unavailable")?;
    let stdout = child.stdout.take().context("stdout unavailable")?;
    let mut stdout = BufReader::new(stdout);

    stdin.write_all(
        rpc_request_with_id(
            1,
            "execute",
            json!({
                "command": [python_bin(), "-c", "print('audit-query')"],
                "cwd": tmp.path(),
                "policy": "danger-full-access",
            }),
        )
        .as_bytes(),
    )?;
    let (_, execute_response) = read_rpc_response(&mut stdout, 1)?;
    let execution_id = execute_response["result"]["execution_id"]
        .as_str()
        .context("execute result must include execution_id")?
        .to_string();

    stdin.write_all(
        rpc_request_with_id(
            2,
            "getAuditEvents",
            json!({ "execution_id": execution_id, "types": ["policy.*"] }),
        )
        .as_bytes(),
    )?;
    let (_, audit_response) = read_rpc_response(&mut stdout, 2)?;
    assert_eq!(audit_response["result"]["execution_id"], execution_id);
    assert_eq!(audit_response["result"]["count"], 2);
    let events = audit_response["result"]["events"]
        .as_array()
        .context("events must be an array")?;
    assert!(events.iter().all(|event| {
        event["type"]
            .as_str()
            .unwrap_or_default()
            .starts_with("policy.")
    }));
    assert!(
        events
            .iter()
            .any(|event| event["type"] == "policy.resolved")
    );
    assert!(events.iter().any(|event| event["type"] == "policy.allowed"));
    assert!(!audit_response["result"].to_string().contains("audit-query"));

    drop(stdin);
    let status = child.wait().context("failed to wait for runseal service")?;
    assert!(status.success());
    Ok(())
}

#[test]
fn service_stdio_tails_retained_audit_events() -> Result<()> {
    #[cfg(windows)]
    let _guard = windows_protocol_lock()?;

    let tmp = TempDir::new()?;
    let mut child = Command::new(require_runseal_bin()?)
        .args(["service", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn runseal service")?;
    let mut stdin = child.stdin.take().context("stdin unavailable")?;
    let stdout = child.stdout.take().context("stdout unavailable")?;
    let mut stdout = BufReader::new(stdout);

    stdin.write_all(
        rpc_request_with_id(
            1,
            "execute",
            json!({
                "command": [python_bin(), "-c", "print('audit-tail')"],
                "cwd": tmp.path(),
                "policy": "danger-full-access",
            }),
        )
        .as_bytes(),
    )?;
    read_rpc_response(&mut stdout, 1)?;

    stdin.write_all(
        rpc_request_with_id(2, "tailAudit", json!({ "types": ["policy.*"] })).as_bytes(),
    )?;
    let (_, tail_response) = read_rpc_response(&mut stdout, 2)?;
    assert_eq!(tail_response["result"]["count"], 2);
    let events = tail_response["result"]["events"]
        .as_array()
        .context("events must be an array")?;
    assert!(events.iter().all(|event| {
        event["type"]
            .as_str()
            .unwrap_or_default()
            .starts_with("policy.")
    }));
    assert!(
        events
            .iter()
            .any(|event| event["type"] == "policy.resolved")
    );
    assert!(events.iter().any(|event| event["type"] == "policy.allowed"));
    assert!(!tail_response["result"].to_string().contains("audit-tail"));

    drop(stdin);
    let status = child.wait().context("failed to wait for runseal service")?;
    assert!(status.success());
    Ok(())
}

#[test]
fn service_stdio_orders_retained_execution_snapshots_by_record_order() -> Result<()> {
    #[cfg(windows)]
    let _guard = windows_protocol_lock()?;

    let tmp = TempDir::new()?;
    let mut child = Command::new(require_runseal_bin()?)
        .args(["service", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn runseal service")?;
    let mut stdin = child.stdin.take().context("stdin unavailable")?;
    let stdout = child.stdout.take().context("stdout unavailable")?;
    let mut stdout = BufReader::new(stdout);

    let mut execution_ids = Vec::new();
    for (id, marker) in [(1, "first"), (2, "second")] {
        stdin.write_all(
            rpc_request_with_id(
                id,
                "execute",
                json!({
                    "command": [python_bin(), "-c", format!("print('{marker}')")],
                    "cwd": tmp.path(),
                    "policy": "danger-full-access",
                }),
            )
            .as_bytes(),
        )?;
        let (_, execute_response) = read_rpc_response(&mut stdout, id)?;
        execution_ids.push(
            execute_response["result"]["execution_id"]
                .as_str()
                .context("execute result must include execution_id")?
                .to_string(),
        );
    }

    stdin.write_all(rpc_request_with_id(3, "listExecutions", json!({})).as_bytes())?;
    let (_, list_response) = read_rpc_response(&mut stdout, 3)?;
    let listed_ids = list_response["result"]["executions"]
        .as_array()
        .context("executions must be an array")?
        .iter()
        .map(|execution| {
            execution["execution_id"]
                .as_str()
                .context("summary must include execution_id")
                .map(str::to_string)
        })
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(listed_ids, execution_ids);

    stdin.write_all(
        rpc_request_with_id(4, "tailAudit", json!({ "types": ["execution.finished"] })).as_bytes(),
    )?;
    let (_, tail_response) = read_rpc_response(&mut stdout, 4)?;
    let tailed_ids = tail_response["result"]["events"]
        .as_array()
        .context("events must be an array")?
        .iter()
        .map(|event| {
            event["execution_id"]
                .as_str()
                .context("event must include execution_id")
                .map(str::to_string)
        })
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(tailed_ids, execution_ids);

    drop(stdin);
    let status = child.wait().context("failed to wait for runseal service")?;
    assert!(status.success());
    Ok(())
}

#[test]
fn get_audit_events_rejects_path_lookup() -> Result<()> {
    let output = run_rpc(&rpc_request(
        "getAuditEvents",
        json!({ "audit_path": ".runseal/audit/fake.jsonl" }),
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
            .contains("params.audit_path is not supported")
    );
    Ok(())
}

#[test]
fn tail_audit_rejects_path_lookup() -> Result<()> {
    let output = run_rpc(&rpc_request(
        "tailAudit",
        json!({ "audit_path": ".runseal/audit/fake.jsonl" }),
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
            .contains("params.audit_path is not supported")
    );
    Ok(())
}

#[test]
fn rpc_stdio_returns_no_cross_request_audit_events() -> Result<()> {
    let tmp = TempDir::new()?;
    let mut child = Command::new(require_runseal_bin()?)
        .args(["rpc", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn runseal rpc")?;
    let mut stdin = child.stdin.take().context("stdin unavailable")?;
    let stdout = child.stdout.take().context("stdout unavailable")?;
    let mut stdout = BufReader::new(stdout);

    stdin.write_all(
        rpc_request_with_id(
            1,
            "execute",
            json!({
                "command": [python_bin(), "-c", "print('direct-audit')"],
                "cwd": tmp.path(),
                "policy": "danger-full-access",
            }),
        )
        .as_bytes(),
    )?;
    let (_, execute_response) = read_rpc_response(&mut stdout, 1)?;
    let execution_id = execute_response["result"]["execution_id"]
        .as_str()
        .context("execute result must include execution_id")?
        .to_string();

    stdin.write_all(
        rpc_request_with_id(2, "getAuditEvents", json!({ "execution_id": execution_id }))
            .as_bytes(),
    )?;
    let (_, response) = read_rpc_response(&mut stdout, 2)?;
    assert_eq!(response["error"]["data"]["code"], "EXECUTION_NOT_FOUND");

    drop(stdin);
    let status = child.wait().context("failed to wait for runseal rpc")?;
    assert!(status.success());
    Ok(())
}

#[test]
fn rpc_stdio_tails_no_cross_request_audit_events() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&format!(
        "{}{}",
        rpc_request_with_id(
            1,
            "execute",
            json!({
                "command": [python_bin(), "-c", "print('direct-tail')"],
                "cwd": tmp.path(),
                "policy": "danger-full-access",
            }),
        ),
        rpc_request_with_id(2, "tailAudit", json!({}))
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = response_with_id(&messages, 2)?;
    assert_eq!(response["result"]["count"], 0);
    assert_eq!(response["result"]["events"], json!([]));
    Ok(())
}

#[test]
fn rpc_stdio_lists_no_cross_request_executions() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&format!(
        "{}{}",
        rpc_request_with_id(
            1,
            "execute",
            json!({
                "command": [python_bin(), "-c", "print('direct-output')"],
                "cwd": tmp.path(),
                "policy": "danger-full-access",
            }),
        ),
        rpc_request_with_id(2, "listExecutions", json!({}))
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = response_with_id(&messages, 2)?;
    assert_eq!(response["result"]["count"], 0);
    assert_eq!(response["result"]["executions"], json!([]));
    Ok(())
}

#[test]
fn rpc_and_service_report_current_control_plane_mode() -> Result<()> {
    for (command, expected_mode, expected_stateful) in
        [("rpc", "direct", false), ("service", "service", true)]
    {
        let mut child = Command::new(require_runseal_bin()?)
            .args([command, "--stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to spawn runseal {command}"))?;
        let mut stdin = child.stdin.take().context("stdin unavailable")?;
        let stdout = child.stdout.take().context("stdout unavailable")?;
        let mut stdout = BufReader::new(stdout);

        stdin.write_all(rpc_request_with_id(1, "getServiceStatus", json!({})).as_bytes())?;
        let (_, response) = read_rpc_response(&mut stdout, 1)?;
        assert_eq!(response["result"]["status"], "running");
        assert_eq!(response["result"]["mode"], expected_mode);
        assert_eq!(response["result"]["transport"], "stdio");
        assert_eq!(response["result"]["stateful"], expected_stateful);
        assert_eq!(response["result"]["local_only"], true);
        assert_eq!(response["result"]["remote_listener"], false);
        assert_no_private_windows_setup_terms(&response["result"]);

        drop(stdin);
        let status = child.wait().context("failed to wait for runseal")?;
        assert!(status.success());
    }
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
    assert_eq!(
        payload["capability_statuses"],
        json!([
            "supported",
            "experimental",
            "unsupported",
            "unavailable",
            "requires_setup"
        ])
    );
    assert_eq!(payload["sandbox_levels"]["danger-full-access"], "supported");
    assert_eq!(
        payload["sandbox_levels"]["workspace-write"],
        expected_status(expected_windows_sandbox_supported())
    );
    assert_eq!(
        payload["network_modes"]["disabled"],
        expected_status(expected_windows_sandbox_supported())
    );
    assert_eq!(
        payload["features"]["runtime_roots"],
        expected_runtime_roots_supported()
    );
    assert_eq!(
        payload["features"]["runtime_environment"],
        expected_runtime_environment_supported()
    );
    assert_eq!(
        payload["features"]["process_isolation"],
        expected_windows_sandbox_supported()
    );
    assert_eq!(
        payload["features"]["process_cleanup"],
        expected_process_cleanup_supported()
    );
    assert_eq!(
        payload["features"]["direct_network_deny"],
        expected_windows_sandbox_supported()
    );
    assert_eq!(
        payload["features"]["managed_proxy"],
        expected_windows_sandbox_supported()
    );
    assert_eq!(
        payload["features"]["network_proxy"],
        expected_windows_sandbox_supported()
    );
    assert_eq!(
        payload["features"]["network_disabled"],
        expected_windows_sandbox_supported()
    );
    assert_eq!(
        payload["features"]["policy_epoch"],
        expected_windows_sandbox_supported()
    );
    assert_eq!(payload["features"]["setup_readiness"], true);
    assert_eq!(payload["features"]["stdin_bytes"], true);
    assert_eq!(payload["features"]["stdin_file"], true);
    assert_eq!(
        payload["features"]["resource_limits"],
        expected_resource_limits_supported()
    );
    assert_eq!(payload["features"]["audit_jsonl"], true);
    assert_eq!(payload["features"]["otel_export"], false);
    assert_eq!(payload["setup_status"]["setup"], "windows-sandbox");
    assert!(payload["setup_status"]["next_action"].as_str().is_some());
    assert_portable_capability_probe_contract(payload);
    assert_no_private_windows_setup_terms(payload);
    Ok(())
}

#[test]
fn get_setup_status_rpc_contract() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request("getSetupStatus", json!({ "cwd": tmp.path() })))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let payload = &messages[0]["result"];
    assert_eq!(payload["setup"], "windows-sandbox");
    assert!(payload["platform_supported"].is_boolean());
    assert!(payload["next_action"].as_str().is_some());
    assert_no_private_windows_setup_terms(payload);
    Ok(())
}

#[test]
fn rpc_rejects_malformed_envelope() -> Result<()> {
    let cases = [
        (json!([]), "batch requests are not supported"),
        (
            json!({"jsonrpc": "1.0", "id": 1, "method": "getVersion", "params": {}}),
            "request.jsonrpc must be 2.0",
        ),
        (
            json!({"jsonrpc": "2.0", "id": 1, "params": {}}),
            "request.method is required",
        ),
    ];

    for (request, expected_reason) in cases {
        let output = run_rpc(&(request.to_string() + "\n"))?;

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let messages = stdout_json_lines(&output)?;
        let response = &messages[0];

        assert_eq!(response["error"]["code"], -32600);
        assert_eq!(response["error"]["data"]["code"], "INVALID_REQUEST");
        assert_eq!(response["error"]["data"]["reason"], expected_reason);
    }
    Ok(())
}

#[test]
fn rpc_rejects_invalid_request_id_with_null_response_id() -> Result<()> {
    let output = run_rpc(
        &(json!({
            "jsonrpc": "2.0",
            "id": {"not": "valid"},
            "method": "getVersion",
            "params": {}
        })
        .to_string()
            + "\n"),
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = &messages[0];

    assert_eq!(response["id"], Value::Null);
    assert_eq!(response["error"]["code"], -32600);
    assert_eq!(response["error"]["data"]["code"], "INVALID_REQUEST");
    assert_eq!(
        response["error"]["data"]["reason"],
        "request.id must be a string, number, or null"
    );
    Ok(())
}

#[test]
fn rpc_rejects_unknown_method_as_method_not_found() -> Result<()> {
    let output = run_rpc(&rpc_request("missingMethod", json!({})))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = &messages[0];

    assert_eq!(response["error"]["code"], -32601);
    assert_eq!(response["error"]["data"]["code"], "METHOD_NOT_FOUND");
    assert_eq!(
        response["error"]["data"]["reason"],
        "method not found: missingMethod"
    );
    Ok(())
}

#[test]
fn no_param_methods_reject_unsupported_params() -> Result<()> {
    for method in ["getVersion", "getCapabilities"] {
        let output = run_rpc(&rpc_request(method, json!({"extra": true})))?;

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let messages = stdout_json_lines(&output)?;
        let response = &messages[0];

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(response["error"]["data"]["code"], "INVALID_REQUEST");
        assert_eq!(
            response["error"]["data"]["reason"],
            format!("params.extra is not supported by {method}")
        );
    }
    Ok(())
}

#[test]
fn no_param_methods_require_object_params() -> Result<()> {
    for method in ["getVersion", "getCapabilities"] {
        let output = run_rpc(&rpc_request(method, json!(null)))?;

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let messages = stdout_json_lines(&output)?;
        let response = &messages[0];

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(response["error"]["data"]["code"], "INVALID_REQUEST");
        assert_eq!(
            response["error"]["data"]["reason"],
            format!("{method} params must be an object")
        );
    }
    Ok(())
}

#[test]
fn execution_lookup_methods_return_stable_not_found() -> Result<()> {
    let cases = [
        ("getExecution", json!({"execution_id": "exec_missing"})),
        (
            "cancelExecution",
            json!({"execution_id": "exec_missing", "reason": "user_requested"}),
        ),
        (
            "subscribeEvents",
            json!({"execution_id": "exec_missing", "types": ["execution.*", "policy.*"]}),
        ),
    ];
    for (method, params) in cases {
        let output = run_rpc(&rpc_request(method, params))?;

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
fn service_stdio_keeps_completed_execution_state() -> Result<()> {
    #[cfg(windows)]
    let _guard = windows_protocol_lock()?;

    let tmp = TempDir::new()?;
    let mut child = Command::new(require_runseal_bin()?)
        .args(["service", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn runseal service")?;
    let mut stdin = child.stdin.take().context("stdin unavailable")?;
    let stdout = child.stdout.take().context("stdout unavailable")?;
    let mut stdout = BufReader::new(stdout);

    stdin.write_all(
        rpc_request_with_id(
            1,
            "execute",
            json!({
                "command": [python_bin(), "-c", "print('service-ok')"],
                "cwd": tmp.path(),
                "policy": "danger-full-access",
            }),
        )
        .as_bytes(),
    )?;
    let (execute_events, execute_response) = read_rpc_response(&mut stdout, 1)?;
    let execution_id = execute_response["result"]["execution_id"]
        .as_str()
        .context("execute result must include execution_id")?
        .to_string();
    let session_id = execute_response["result"]["session_id"]
        .as_str()
        .context("execute result must include session_id")?
        .to_string();
    assert!(
        execute_events
            .iter()
            .any(|event| event["params"]["type"] == "execution.requested")
    );
    assert!(
        execute_events
            .iter()
            .any(|event| event["params"]["type"] == "policy.resolved")
    );
    assert!(
        execute_events
            .iter()
            .any(|event| event["params"]["type"] == "policy.allowed")
    );
    assert!(
        execute_events
            .iter()
            .any(|event| event["params"]["type"] == "execution.resource.sample")
    );
    assert!(
        execute_events
            .iter()
            .any(|event| event["params"]["type"] == "execution.finished")
    );

    stdin.write_all(
        rpc_request_with_id(2, "getExecution", json!({ "execution_id": execution_id })).as_bytes(),
    )?;
    let (_, get_response) = read_rpc_response(&mut stdout, 2)?;
    assert_eq!(get_response["result"]["execution_id"], execution_id);
    assert_eq!(get_response["result"]["status"], "finished");

    stdin.write_all(
        rpc_request_with_id(
            3,
            "subscribeEvents",
            json!({ "execution_id": execution_id, "types": ["execution.*"] }),
        )
        .as_bytes(),
    )?;
    let (subscription_events, subscribe_response) = read_rpc_response(&mut stdout, 3)?;
    assert_eq!(subscribe_response["result"]["execution_id"], execution_id);
    assert!(subscription_events.iter().all(|event| {
        event["params"]["type"]
            .as_str()
            .unwrap_or_default()
            .starts_with("execution.")
    }));
    assert!(
        subscription_events
            .iter()
            .any(|event| event["params"]["type"] == "execution.finished")
    );

    stdin.write_all(
        rpc_request_with_id(
            4,
            "cancelExecution",
            json!({ "execution_id": execution_id, "reason": "test" }),
        )
        .as_bytes(),
    )?;
    let (_, cancel_response) = read_rpc_response(&mut stdout, 4)?;
    assert_eq!(
        cancel_response["error"]["data"]["code"],
        "EXECUTION_NOT_CANCELLABLE"
    );
    assert_eq!(
        cancel_response["error"]["data"]["execution_id"],
        execution_id
    );
    assert_eq!(cancel_response["error"]["data"]["status"], "finished");

    stdin.write_all(
        rpc_request_with_id(5, "disposeSession", json!({ "session_id": session_id })).as_bytes(),
    )?;
    let (_, dispose_response) = read_rpc_response(&mut stdout, 5)?;
    assert_eq!(dispose_response["result"]["status"], "disposed");
    assert_eq!(dispose_response["result"]["released_executions"], 0);

    stdin.write_all(
        rpc_request_with_id(6, "getExecution", json!({ "execution_id": execution_id })).as_bytes(),
    )?;
    let (_, retained_response) = read_rpc_response(&mut stdout, 6)?;
    assert_eq!(retained_response["result"]["execution_id"], execution_id);
    assert_eq!(retained_response["result"]["status"], "finished");

    stdin.write_all(
        rpc_request_with_id(
            7,
            "getAuditEvents",
            json!({ "execution_id": execution_id, "types": ["execution.finished"] }),
        )
        .as_bytes(),
    )?;
    let (_, audit_response) = read_rpc_response(&mut stdout, 7)?;
    assert_eq!(audit_response["result"]["count"], 1);

    drop(stdin);
    let status = child.wait().context("failed to wait for runseal service")?;
    assert!(status.success());
    Ok(())
}

#[test]
fn service_stdio_keeps_failed_execution_state() -> Result<()> {
    #[cfg(windows)]
    let _guard = windows_protocol_lock()?;

    let tmp = TempDir::new()?;
    let mut child = Command::new(require_runseal_bin()?)
        .args(["service", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn runseal service")?;
    let mut stdin = child.stdin.take().context("stdin unavailable")?;
    let stdout = child.stdout.take().context("stdout unavailable")?;
    let mut stdout = BufReader::new(stdout);

    stdin.write_all(
        rpc_request_with_id(
            1,
            "execute",
            json!({
                "command": ["runseal-command-that-does-not-exist"],
                "cwd": tmp.path(),
                "policy": "danger-full-access",
            }),
        )
        .as_bytes(),
    )?;
    let (execute_events, execute_response) = read_rpc_response(&mut stdout, 1)?;
    assert_eq!(
        execute_response["error"]["data"]["code"],
        "EXECUTION_FAILED_TO_START"
    );
    assert!(execute_response["error"]["data"].get("events").is_none());
    let execution_id = execute_response["error"]["data"]["execution_id"]
        .as_str()
        .context("failed execute response must include execution_id")?
        .to_string();
    for event_type in [
        "execution.requested",
        "policy.resolved",
        "policy.allowed",
        "execution.started",
        "execution.failed",
    ] {
        assert!(
            execute_events
                .iter()
                .any(|event| event["params"]["type"] == event_type),
            "execute response must emit {event_type}"
        );
    }
    assert!(
        execute_response["error"]["data"]["policy_hash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sha256:")
    );
    assert_eq!(
        execute_response["error"]["data"]["policy_epoch"],
        execute_response["error"]["data"]["policy_hash"]
    );

    stdin.write_all(
        rpc_request_with_id(2, "getExecution", json!({ "execution_id": execution_id })).as_bytes(),
    )?;
    let (_, get_response) = read_rpc_response(&mut stdout, 2)?;
    assert_eq!(get_response["result"]["execution_id"], execution_id);
    assert_eq!(get_response["result"]["status"], "failed");
    assert_rfc3339_timestamp(&get_response["result"]["started_at"])?;
    assert_rfc3339_timestamp(&get_response["result"]["finished_at"])?;
    assert_eq!(
        get_response["result"]["error"]["code"],
        "EXECUTION_FAILED_TO_START"
    );
    assert_eq!(get_response["result"]["policy_id"], "danger-full-access");
    assert_eq!(
        get_response["result"]["policy_hash"],
        execute_response["error"]["data"]["policy_hash"]
    );
    assert_eq!(
        get_response["result"]["policy_epoch"],
        execute_response["error"]["data"]["policy_epoch"]
    );

    stdin.write_all(
        rpc_request_with_id(
            3,
            "cancelExecution",
            json!({ "execution_id": execution_id }),
        )
        .as_bytes(),
    )?;
    let (_, cancel_response) = read_rpc_response(&mut stdout, 3)?;
    assert_eq!(
        cancel_response["error"]["data"]["code"],
        "EXECUTION_NOT_CANCELLABLE"
    );
    assert_eq!(
        cancel_response["error"]["data"]["execution_id"],
        execution_id
    );
    assert_eq!(cancel_response["error"]["data"]["status"], "failed");

    stdin.write_all(
        rpc_request_with_id(
            4,
            "subscribeEvents",
            json!({ "execution_id": execution_id, "types": ["execution.*"] }),
        )
        .as_bytes(),
    )?;
    let (subscription_events, subscribe_response) = read_rpc_response(&mut stdout, 4)?;
    assert_eq!(subscribe_response["result"]["execution_id"], execution_id);
    assert_eq!(subscribe_response["result"]["event_count"], 3);
    let failed_event = subscription_events
        .iter()
        .find(|event| event["params"]["type"] == "execution.failed")
        .context("failed execution subscription must replay execution.failed")?;
    assert_eq!(failed_event["params"]["execution_id"], execution_id);
    assert_eq!(
        failed_event["params"]["reason"],
        "execution failed to start"
    );
    assert!(
        !failed_event["params"]["error"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    );
    assert_eq!(
        failed_event["params"]["policy_hash"],
        execute_response["error"]["data"]["policy_hash"]
    );

    drop(stdin);
    let status = child.wait().context("failed to wait for runseal service")?;
    assert!(status.success());
    Ok(())
}

#[test]
fn service_stdio_records_policy_denial_state() -> Result<()> {
    #[cfg(windows)]
    let _guard = windows_protocol_lock()?;

    let tmp = TempDir::new()?;
    let mut child = Command::new(require_runseal_bin()?)
        .args(["service", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn runseal service")?;
    let mut stdin = child.stdin.take().context("stdin unavailable")?;
    let stdout = child.stdout.take().context("stdout unavailable")?;
    let mut stdout = BufReader::new(stdout);

    stdin.write_all(
        rpc_request_with_id(
            1,
            "execute",
            json!({
                "command": [python_bin(), "-c", "print('must not run')"],
                "cwd": tmp.path(),
                "policy": {
                    "version": "runseal.policy/v1",
                    "filesystem": {"read": [tmp.path()], "write": []},
                    "network": {"mode": "disabled"}
                }
            }),
        )
        .as_bytes(),
    )?;
    let (execute_events, execute_response) = read_rpc_response(&mut stdout, 1)?;
    assert_eq!(execute_response["error"]["data"]["code"], "POLICY_DENIED");
    assert!(execute_response["error"]["data"].get("events").is_none());
    let execution_id = execute_response["error"]["data"]["execution_id"]
        .as_str()
        .context("policy denial response must include execution_id")?
        .to_string();
    for event_type in ["execution.requested", "policy.resolved", "policy.denied"] {
        assert!(
            execute_events
                .iter()
                .any(|event| event["params"]["type"] == event_type),
            "execute response must emit {event_type}"
        );
    }

    stdin.write_all(
        rpc_request_with_id(2, "getExecution", json!({ "execution_id": execution_id })).as_bytes(),
    )?;
    let (_, get_response) = read_rpc_response(&mut stdout, 2)?;
    assert_eq!(get_response["result"]["execution_id"], execution_id);
    assert_eq!(get_response["result"]["status"], "denied");
    assert!(get_response["result"].get("started_at").is_none());
    assert_rfc3339_timestamp(&get_response["result"]["finished_at"])?;
    assert_eq!(get_response["result"]["error"]["code"], "POLICY_DENIED");

    stdin.write_all(
        rpc_request_with_id(
            3,
            "subscribeEvents",
            json!({ "execution_id": execution_id, "types": ["policy.*"] }),
        )
        .as_bytes(),
    )?;
    let (subscription_events, subscribe_response) = read_rpc_response(&mut stdout, 3)?;
    assert_eq!(subscribe_response["result"]["event_count"], 2);
    assert!(
        subscription_events
            .iter()
            .any(|event| event["params"]["type"] == "policy.denied")
    );

    drop(stdin);
    let status = child.wait().context("failed to wait for runseal service")?;
    assert!(status.success());
    Ok(())
}

fn read_rpc_response(
    stdout: &mut BufReader<impl std::io::Read>,
    id: u64,
) -> Result<(Vec<Value>, Value)> {
    let mut notifications = Vec::new();
    loop {
        let mut line = String::new();
        stdout
            .read_line(&mut line)
            .context("failed to read service stdout")?;
        if line.is_empty() {
            bail!("service stdout closed before response id {id}");
        }
        let message: Value = serde_json::from_str(&line).context("stdout line was not JSON")?;
        if message.get("id").and_then(Value::as_u64) == Some(id) {
            return Ok((notifications, message));
        }
        notifications.push(message);
    }
}

#[test]
fn lookup_and_session_methods_reject_malformed_ids() -> Result<()> {
    let cases = [
        ("getExecution", json!({"execution_id": "missing"}), "exec_"),
        (
            "cancelExecution",
            json!({"execution_id": "missing", "reason": "user_requested"}),
            "exec_",
        ),
        (
            "subscribeEvents",
            json!({"execution_id": "missing", "types": ["execution.*"]}),
            "exec_",
        ),
        ("disposeSession", json!({"session_id": "missing"}), "sess_"),
    ];

    for (method, params, prefix) in cases {
        let output = run_rpc(&rpc_request(method, params))?;

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
                .contains(&format!("must start with {prefix}"))
        );
    }
    Ok(())
}

#[test]
fn lookup_and_session_methods_reject_path_like_ids() -> Result<()> {
    let cases = [
        ("getExecution", json!({"execution_id": "exec_../escape"})),
        (
            "cancelExecution",
            json!({"execution_id": "exec_escape/path", "reason": "user_requested"}),
        ),
        (
            "subscribeEvents",
            json!({"execution_id": "exec_escape\\path", "types": ["execution.*"]}),
        ),
        ("disposeSession", json!({"session_id": "sess_../escape"})),
    ];

    for (method, params) in cases {
        let output = run_rpc(&rpc_request(method, params))?;

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
                .contains("must contain only ASCII letters, digits, or _")
        );
    }
    Ok(())
}

#[test]
fn lookup_and_session_methods_reject_empty_id_suffixes() -> Result<()> {
    let cases = [
        ("getExecution", json!({"execution_id": "exec_"})),
        ("disposeSession", json!({"session_id": "sess_"})),
    ];

    for (method, params) in cases {
        let output = run_rpc(&rpc_request(method, params))?;

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
                .contains("must include an id suffix")
        );
    }
    Ok(())
}

#[test]
fn lookup_and_session_methods_reject_overlong_ids() -> Result<()> {
    let long_exec_id = format!("exec_{}", "a".repeat(128));
    let long_session_id = format!("sess_{}", "a".repeat(128));
    let cases = [
        ("getExecution", json!({"execution_id": long_exec_id})),
        ("disposeSession", json!({"session_id": long_session_id})),
    ];

    for (method, params) in cases {
        let output = run_rpc(&rpc_request(method, params))?;

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
                .contains("must be at most 128 bytes")
        );
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
    let unsupported_cases = [
        ("trace_id", json!("trace_test")),
        ("network_mode", json!("proxy")),
    ];

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
fn execute_output_limit_returns_stable_error_and_audit_event() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "import sys; sys.stdout.write('abcdef')"],
            "cwd": tmp.path(),
            "policy": {
                "version": "runseal.policy/v1",
                "sandbox_level": "danger-full-access",
                "resources": {"max_output_bytes": 3}
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

    assert_eq!(response["error"]["data"]["code"], "OUTPUT_LIMIT_EXCEEDED");
    assert_error_execution_binding(&response["error"]["data"]);
    assert_eq!(response["error"]["data"]["stdout_bytes"], 6);
    assert_eq!(response["error"]["data"]["retained_stdout_bytes"], 3);
    let audit_path = response["error"]["data"]["audit_path"]
        .as_str()
        .context("output limit error must include audit_path")?;
    let audit_events = read_audit_events(tmp.path(), audit_path)?;
    assert!(audit_events.iter().any(|event| {
        event["type"] == "execution.output.truncated" && event["decision"] == "truncated"
    }));
    assert!(audit_events.iter().any(|event| {
        event["type"] == "execution.resource.limit_exceeded"
            && event["resource"] == "max_output_bytes"
    }));
    assert!(audit_events.iter().any(|event| {
        event["type"] == "execution.failed" && event["reason"] == "output limit exceeded"
    }));
    Ok(())
}

#[test]
fn execute_rejects_secret_env_keys() -> Result<()> {
    let tmp = TempDir::new()?;
    for key in [
        "OPENAI_API_KEY",
        "RUNSEAL_TOKEN",
        "RUNSEAL_SECRET",
        "DATABASE_PASSWORD",
        "HTTP_AUTHORIZATION",
        "SESSION_COOKIE",
        "AUTHORIZATION",
        "COOKIE",
        "PASSWORD",
        "AWS_REGION",
    ] {
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
    for event_type in [
        "execution.requested",
        "policy.resolved",
        "policy.allowed",
        "execution.started",
        "execution.resource.sample",
        "execution.finished",
    ] {
        let event = audit_events
            .iter()
            .find(|event| event["type"] == event_type)
            .with_context(|| format!("audit event {event_type} must exist"))?;
        assert_event_envelope(event)?;
        assert_eq!(event["metadata"], metadata);
    }
    let requested = audit_events
        .iter()
        .find(|event| event["type"] == "execution.requested")
        .unwrap();
    assert_eq!(requested["decision"], "requested");
    assert_eq!(requested["command_args"], 3);
    let resolved = audit_events
        .iter()
        .find(|event| event["type"] == "policy.resolved")
        .unwrap();
    assert_eq!(resolved["decision"], "resolved");
    assert_eq!(resolved["sandbox_level"], "danger-full-access");
    assert_eq!(resolved["backend_requirement"], "local-execution");
    let allowed = audit_events
        .iter()
        .find(|event| event["type"] == "policy.allowed")
        .unwrap();
    assert_eq!(allowed["decision"], "allowed");
    assert_eq!(allowed["sandbox"]["level"], "danger-full-access");
    assert_eq!(allowed["sandbox"]["enforced"], false);
    let sample = audit_events
        .iter()
        .find(|event| event["type"] == "execution.resource.sample")
        .unwrap();
    assert!(sample["duration_ms"].as_u64().is_some());
    assert!(sample["stdout_bytes"].as_u64().is_some());
    assert!(sample["stderr_bytes"].as_u64().is_some());
    assert_eq!(sample["output_truncated"], false);
    Ok(())
}

#[test]
fn execute_audits_effective_network_routes() -> Result<()> {
    let tmp = TempDir::new()?;
    let routes = json!(["github-api", "crm-readonly"]);
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "print('routes ok')"],
            "cwd": tmp.path(),
            "policy": {
                "version": "runseal.policy/v1",
                "sandbox_level": "danger-full-access",
                "network": {
                    "mode": "proxy",
                    "routes": routes
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
    let response = messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .unwrap();

    assert_eq!(response["result"]["status"], "finished");
    assert_eq!(response["result"]["network"]["mode"], "proxy");
    assert_eq!(response["result"]["network"]["routes"], routes);
    assert_eq!(
        response["result"]["network"]["direct_allow_hosts"],
        json!([])
    );

    let audit_path = response["result"]["audit_path"]
        .as_str()
        .expect("execution result must include audit_path");
    let audit_events = read_audit_events(tmp.path(), audit_path)?;
    for event_type in ["policy.resolved", "policy.allowed", "execution.started"] {
        let event = audit_events
            .iter()
            .find(|event| event["type"] == event_type)
            .with_context(|| format!("audit event {event_type} must exist"))?;
        assert_eq!(event["network"]["mode"], "proxy");
        assert_eq!(event["network"]["routes"], routes);
        assert_eq!(event["network"]["direct_allow_hosts"], json!([]));
    }
    Ok(())
}

#[test]
fn execute_redacts_sensitive_metadata_in_audit_events() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "print('metadata redaction ok')"],
            "cwd": tmp.path(),
            "policy": "danger-full-access",
            "metadata": {
                "Authorization": "Bearer audit-secret",
                "nested": {
                    "Cookie": "session=audit-secret",
                    "safe": "visible"
                },
                "items": [
                    {"proxy-authorization": "Basic audit-secret"},
                    {"token": "audit-secret"}
                ]
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
    let audit_path = response["result"]["audit_path"]
        .as_str()
        .expect("execution result must include audit_path");
    let audit_jsonl = fs::read_to_string(tmp.path().join(audit_path))?;
    assert!(!audit_jsonl.contains("audit-secret"));

    let audit_events = read_audit_events(tmp.path(), audit_path)?;
    let requested = audit_events
        .iter()
        .find(|event| event["type"] == "execution.requested")
        .context("execution.requested audit event must exist")?;
    assert_eq!(requested["metadata"]["Authorization"], "[REDACTED]");
    assert_eq!(requested["metadata"]["nested"]["Cookie"], "[REDACTED]");
    assert_eq!(requested["metadata"]["nested"]["safe"], "visible");
    assert_eq!(
        requested["metadata"]["items"][0]["proxy-authorization"],
        "[REDACTED]"
    );
    assert_eq!(requested["metadata"]["items"][1]["token"], "[REDACTED]");
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
fn execute_accepts_file_stdin_and_audits_metadata_only() -> Result<()> {
    let tmp = TempDir::new()?;
    let stdin_path = tmp.path().join("stdin-payload.bin");
    let stdin_bytes = vec![b'x'; 128 * 1024];
    fs::write(&stdin_path, &stdin_bytes)?;
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
                "mode": "file",
                "path": stdin_path
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
    assert_eq!(started["stdin"]["mode"], "file");
    assert_eq!(started["stdin"]["byte_count"], stdin_bytes.len());

    let audit_jsonl = fs::read_to_string(tmp.path().join(audit_path))?;
    assert!(!audit_jsonl.contains("stdin-payload.bin"));
    Ok(())
}

#[test]
fn execute_rejects_file_stdin_outside_cwd() -> Result<()> {
    let tmp = TempDir::new()?;
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(&workspace)?;
    let outside = tmp.path().join("outside.txt");
    fs::write(&outside, b"outside-secret")?;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "print('must not run')"],
            "cwd": workspace,
            "policy": "danger-full-access",
            "stdin": {
                "mode": "file",
                "path": outside
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

    assert_eq!(response["error"]["data"]["code"], "INVALID_REQUEST");
    assert!(
        response["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("params.stdin.path must be under params.cwd")
    );
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
    let oversized = STANDARD.encode(vec![b'x'; 64 * 1024 + 1]);
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "print('must not run')"],
            "cwd": tmp.path(),
            "policy": "danger-full-access",
            "stdin": {
                "mode": "bytes",
                "data": format!("base64:{oversized}"),
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
    let response = &messages[0];

    assert_eq!(response["error"]["data"]["code"], "INVALID_REQUEST");
    assert!(
        response["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("params.stdin.data must decode to at most 65536 bytes")
    );
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
fn execute_with_timeout_captures_stdout_when_command_finishes() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "print('timeout stdout ok')"],
            "cwd": tmp.path(),
            "policy": "danger-full-access",
            "timeout_ms": 5000
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
            .contains("timeout stdout ok")
    );
    assert!(
        response["result"]["stdout_bytes"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    Ok(())
}

#[test]
fn execute_with_timeout_drains_large_stdout_while_waiting() -> Result<()> {
    let tmp = TempDir::new()?;
    let stdout_bytes = 256 * 1024;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [
                python_bin(),
                "-c",
                format!("import sys; sys.stdout.buffer.write(b'x' * {stdout_bytes})")
            ],
            "cwd": tmp.path(),
            "policy": {
                "version": "runseal.policy/v1",
                "sandbox_level": "danger-full-access",
                "resources": {"max_output_bytes": stdout_bytes + 1024}
            },
            "timeout_ms": 5000
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
    assert_eq!(response["result"]["stdout_bytes"], stdout_bytes);
    assert_eq!(response["result"]["output_truncated"], false);
    Ok(())
}

#[test]
fn execute_timeout_survives_unread_file_stdin() -> Result<()> {
    let tmp = TempDir::new()?;
    let stdin_path = tmp.path().join("large-stdin.bin");
    fs::write(&stdin_path, vec![b'x'; 2 * 1024 * 1024])?;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "import time; time.sleep(1)"],
            "cwd": tmp.path(),
            "policy": "danger-full-access",
            "stdin": {
                "mode": "file",
                "path": stdin_path
            },
            "timeout_ms": 50
        }),
    ))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let response = response_with_id(&messages, 1)?;

    assert_eq!(response["error"]["data"]["code"], "EXECUTION_TIMEOUT");
    assert_eq!(response["error"]["data"]["timeout_ms"], 50);
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
    let response = response_with_id(&messages, 1)?;

    assert_eq!(response["error"]["data"]["code"], "EXECUTION_TIMEOUT");
    assert_error_execution_binding(&response["error"]["data"]);
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
    let limit_event = audit_events
        .iter()
        .find(|event| event["type"] == "execution.resource.limit_exceeded")
        .context("execution.resource.limit_exceeded audit event must exist")?;
    assert_event_envelope(limit_event)?;
    assert_eq!(limit_event["decision"], "limit_exceeded");
    assert_eq!(limit_event["resource"], "timeout_ms");
    assert_eq!(limit_event["limit"], 10);
    Ok(())
}

#[test]
fn execute_start_failure_returns_audit_path_and_failed_event() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": ["runseal-command-that-does-not-exist-for-test"],
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
    let response = response_with_id(&messages, 1)?;

    assert_eq!(
        response["error"]["data"]["code"],
        "EXECUTION_FAILED_TO_START"
    );
    assert_eq!(response["error"]["data"]["policy_id"], "danger-full-access");
    assert!(
        response["error"]["data"]["policy_hash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sha256:")
    );
    assert_eq!(
        response["error"]["data"]["policy_epoch"],
        response["error"]["data"]["policy_hash"]
    );
    let audit_path = response["error"]["data"]["audit_path"]
        .as_str()
        .expect("start failure must return audit_path");
    let audit_events = read_audit_events(tmp.path(), audit_path)?;
    let failed_event = audit_events
        .iter()
        .find(|event| event["type"] == "execution.failed")
        .context("execution.failed audit event must exist")?;
    assert_event_envelope(failed_event)?;
    assert_eq!(failed_event["reason"], "execution failed to start");
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
    let response = response_with_id(&messages, 1)?;

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
    let unsupported_cases = [
        ("metadata", json!({"agent_id": "agent_test"})),
        ("network_mode", json!("proxy")),
    ];

    for (field, value) in unsupported_cases {
        let mut request = json!({
            "cwd": tmp.path(),
            "policy": "workspace-write"
        });
        request
            .as_object_mut()
            .expect("request must be an object")
            .insert(field.to_string(), value);

        let output = run_rpc(&rpc_request("explainPolicy", request))?;

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
    assert_eq!(
        payload["support"],
        expected_status(expected_windows_sandbox_supported())
    );
    assert_eq!(payload["setup_status"]["setup"], "windows-sandbox");
    assert!(payload["setup_status"]["can_run_setup_now"].is_boolean());
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
    assert_eq!(
        payload["missing_features"],
        if expected_windows_sandbox_supported() {
            json!([])
        } else {
            payload["required_backend_features"].clone()
        }
    );
    assert!(
        payload["filesystem"]["write"]
            .as_array()
            .expect("filesystem.write must be an array")
            .iter()
            .filter_map(Value::as_str)
            .any(|path| path_equals_existing(path, tmp.path()))
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
    assert_eq!(response["error"]["code"], -32000);
    assert_eq!(response["error"]["data"]["code"], "POLICY_DENIED");
    assert_error_execution_binding(&response["error"]["data"]);
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
fn policy_request_uses_approval_required_error_code() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "print('must not run')"],
            "cwd": tmp.path(),
            "policy": {
                "version": "runseal.policy/v1",
                "filesystem": {"read": [tmp.path()], "write": []},
                "network": {"mode": "disabled"},
                "approval": {
                    "on_violation": "request"
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
    let response = messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .unwrap();
    assert_eq!(response["error"]["data"]["code"], "APPROVAL_REQUIRED");
    assert_error_execution_binding(&response["error"]["data"]);
    let audit_path = response["error"]["data"]["audit_path"]
        .as_str()
        .expect("approval required error must return audit_path");
    let audit_events = read_audit_events(tmp.path(), audit_path)?;
    assert!(audit_events.iter().any(|event| {
        event["type"] == "policy.requires_approval" && event["decision"] == "requires_approval"
    }));
    Ok(())
}

#[test]
fn broad_write_request_uses_approval_required_error_code() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "print('must not run')"],
            "cwd": tmp.path(),
            "policy": {
                "version": "runseal.policy/v1",
                "sandbox_level": "workspace-write",
                "filesystem": {"write": ["*"]},
                "network": {"mode": "disabled"},
                "approval": {
                    "on_broad_write": "request"
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
    let response = messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .unwrap();
    assert_eq!(response["error"]["data"]["code"], "APPROVAL_REQUIRED");
    assert_error_execution_binding(&response["error"]["data"]);
    assert!(
        response["error"]["data"]["reason"]
            .as_str()
            .unwrap()
            .contains("broad write")
    );
    let audit_path = response["error"]["data"]["audit_path"]
        .as_str()
        .expect("approval required error must return audit_path");
    let audit_events = read_audit_events(tmp.path(), audit_path)?;
    assert!(audit_events.iter().any(|event| {
        event["type"] == "policy.requires_approval"
            && event["decision"] == "requires_approval"
            && event["reason"].as_str().unwrap().contains("broad write")
    }));
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
                    "timeout_ms": 1000,
                    "memory_bytes": 2147483648u64,
                    "cpu_percent": 200,
                    "max_output_bytes": 2048
                },
                "process": {
                    "allow_child_processes": true,
                    "kill_on_parent_exit": true,
                    "interactive": false
                },
                "network": {
                    "mode": "disabled",
                    "direct_allow_hosts": []
                },
                "approval": {
                    "on_violation": "deny",
                    "on_network_route_missing": "deny",
                    "on_broad_write": "deny"
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
    let payload = &messages[0]["result"];

    assert_eq!(payload["environment"]["inherit"], "minimal");
    assert_eq!(payload["environment"]["scrub"], json!(["RUNSEAL_SECRET_*"]));
    assert_eq!(payload["environment"]["set"]["CI"], "1");
    assert_eq!(payload["environment"]["proxy"], false);
    assert_eq!(payload["network"]["routes"], json!([]));
    assert_eq!(payload["network"]["direct_allow_hosts"], json!([]));
    assert_eq!(payload["resources"]["timeout_ms"], 1000);
    assert_eq!(payload["resources"]["memory_bytes"], 2147483648u64);
    assert_eq!(payload["resources"]["cpu_percent"], 200);
    assert_eq!(payload["resources"]["max_output_bytes"], 2048);
    assert_eq!(payload["process"]["allow_child_processes"], true);
    assert_eq!(payload["process"]["kill_on_parent_exit"], true);
    assert_eq!(payload["process"]["max_processes"], Value::Null);
    assert_eq!(payload["process"]["interactive"], false);
    assert_eq!(payload["approval"]["on_violation"], "deny");
    assert_eq!(payload["approval"]["on_network_route_missing"], "deny");
    assert_eq!(payload["approval"]["on_broad_write"], "deny");
    assert_eq!(
        payload["canonical_policy"]["environment"]["scrub"],
        json!(["RUNSEAL_SECRET_*"])
    );
    assert_eq!(payload["canonical_policy"]["environment"]["set"]["CI"], "1");
    assert_eq!(payload["canonical_policy"]["network"]["routes"], json!([]));
    assert_eq!(payload["canonical_policy"]["resources"]["timeout_ms"], 1000);
    assert_eq!(
        payload["canonical_policy"]["resources"]["memory_bytes"],
        2147483648u64
    );
    assert_eq!(payload["canonical_policy"]["resources"]["cpu_percent"], 200);
    assert_eq!(
        payload["canonical_policy"]["resources"]["max_output_bytes"],
        2048
    );
    assert_eq!(
        payload["canonical_policy"]["process"]["kill_on_parent_exit"],
        true
    );
    assert_eq!(
        payload["canonical_policy"]["approval"]["on_broad_write"],
        "deny"
    );
    Ok(())
}

#[test]
fn inline_policy_rejects_proxy_network_without_proxy_environment() -> Result<()> {
    let tmp = TempDir::new()?;
    let output = run_rpc(&rpc_request(
        "explainPolicy",
        json!({
            "cwd": tmp.path(),
            "policy": {
                "version": "runseal.policy/v1",
                "network": {"mode": "proxy"},
                "environment": {"proxy": false}
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
            .contains("network.proxy requires environment.proxy=true")
    );
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
fn sandboxed_policy_uses_platform_backend_or_reports_unavailable() -> Result<()> {
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

    if cfg!(windows) {
        if response.get("error").is_some() {
            assert_backend_unavailable(response, tmp.path())?;
        } else {
            assert_eq!(response["result"]["status"], "finished");
            assert_eq!(response["result"]["exit_code"], 0);
            assert_eq!(response["result"]["sandbox"]["enforced"], true);
            assert_eq!(
                response["result"]["platform_plan"]["enforcement"],
                "windows-sandbox"
            );
            assert_no_private_windows_setup_terms(response);
        }
        return Ok(());
    }

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

    if cfg!(windows) {
        let plan = if response.get("error").is_some() {
            assert_backend_unavailable(response, tmp.path())?;
            &response["error"]["data"]["platform_plan"]
        } else {
            assert_eq!(response["result"]["sandbox"]["enforced"], true);
            &response["result"]["platform_plan"]
        };
        let protected = &plan["filesystem"]["protected"];
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
        return Ok(());
    }

    assert_eq!(
        response["error"]["data"]["code"],
        "BACKEND_CAPABILITY_MISSING"
    );
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
    let execution_id = response["result"]["execution_id"]
        .as_str()
        .expect("ExecutionResult must include execution_id");
    let session_id = response["result"]["session_id"]
        .as_str()
        .expect("ExecutionResult must include session_id");
    let seal_id = response["result"]["seal_id"]
        .as_str()
        .expect("ExecutionResult must include seal_id");
    assert!(execution_id.starts_with("exec_"));
    assert!(session_id.starts_with("sess_"));
    assert!(seal_id.starts_with("seal_"));
    for notification in &notifications {
        assert_eq!(notification["jsonrpc"], "2.0");
        assert!(notification.get("id").is_none());
        assert_event_envelope(&notification["params"])?;
        assert_eq!(notification["params"]["execution_id"], execution_id);
        assert_eq!(notification["params"]["session_id"], session_id);
        assert_eq!(notification["params"]["seal_id"], seal_id);
        assert_eq!(
            notification["params"]["policy_epoch"],
            response["result"]["policy_epoch"]
        );
    }
    let stdout_event = notifications
        .iter()
        .map(|message| &message["params"])
        .find(|event| event["type"] == "execution.stdout")
        .context("execution.stdout notification must exist")?;
    let finished_event = notifications
        .iter()
        .map(|message| &message["params"])
        .find(|event| event["type"] == "execution.finished")
        .context("execution.finished notification must exist")?;
    assert!(decode_stream_event(stdout_event)?.contains("protocol ok"));
    assert_eq!(response["result"]["status"], "finished");
    assert_eq!(response["result"]["exit_code"], 0);
    assert_eq!(finished_event["status"], response["result"]["status"]);
    assert_eq!(finished_event["exit_code"], response["result"]["exit_code"]);
    assert_eq!(response["result"]["signal"], Value::Null);
    assert_eq!(
        response["result"]["policy_epoch"],
        response["result"]["policy_hash"]
    );
    assert_eq!(stdout_event["bytes"], response["result"]["stdout_bytes"]);
    assert!(
        response["result"]["stdout_bytes"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert_eq!(response["result"]["stderr_bytes"], 0);
    assert!(
        response["result"]["resource_usage"]["duration_ms"]
            .as_u64()
            .is_some()
    );
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
    let audit_path = response["result"]["audit_path"]
        .as_str()
        .expect("ExecutionResult must include audit_path");
    let audit_jsonl = fs::read_to_string(tmp.path().join(audit_path))?;
    assert!(!audit_jsonl.contains("protocol ok"));
    let audit_events = read_audit_events(tmp.path(), audit_path)?;
    let audit_stdout = audit_events
        .iter()
        .find(|event| event["type"] == "execution.stdout")
        .context("execution.stdout audit event must exist")?;
    assert_eq!(audit_stdout["encoding"], "base64");
    assert_eq!(audit_stdout["stream_offset"], 0);
    assert_eq!(audit_stdout["bytes"], stdout_event["bytes"]);
    assert!(audit_stdout.get("data").is_none());
    assert!(audit_stdout.get("text").is_none());
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
fn policy_epoch_tracks_effective_policy() -> Result<()> {
    let tmp = TempDir::new()?;
    let first = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "print('first')"],
            "cwd": tmp.path(),
            "policy": "danger-full-access",
            "network": {"mode": "disabled"}
        }),
    ))?;
    let same = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "print('same')"],
            "cwd": tmp.path(),
            "policy": "danger-full-access",
            "network": {"mode": "disabled"}
        }),
    ))?;
    let second = run_rpc(&rpc_request(
        "execute",
        json!({
            "command": [python_bin(), "-c", "print('second')"],
            "cwd": tmp.path(),
            "policy": "danger-full-access",
            "network": {"mode": "proxy"}
        }),
    ))?;

    assert!(first.status.success());
    assert!(same.status.success());
    assert!(second.status.success());
    let first_messages = stdout_json_lines(&first)?;
    let same_messages = stdout_json_lines(&same)?;
    let second_messages = stdout_json_lines(&second)?;
    let first_result = &first_messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .context("first response with id 1 must exist")?["result"];
    let same_result = &same_messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .context("same-policy response with id 1 must exist")?["result"];
    let second_result = &second_messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .context("second response with id 1 must exist")?["result"];

    assert_eq!(first_result["status"], "finished");
    assert_eq!(same_result["status"], "finished");
    assert_eq!(second_result["status"], "finished");
    assert_eq!(first_result["policy_epoch"], first_result["policy_hash"]);
    assert_eq!(same_result["policy_epoch"], same_result["policy_hash"]);
    assert_eq!(second_result["policy_epoch"], second_result["policy_hash"]);
    assert_eq!(first_result["policy_hash"], same_result["policy_hash"]);
    assert_eq!(first_result["policy_epoch"], same_result["policy_epoch"]);
    assert_ne!(first_result["policy_hash"], second_result["policy_hash"]);
    assert_ne!(first_result["policy_epoch"], second_result["policy_epoch"]);
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
    let scrub = response["result"]["platform_plan"]["environment"]["scrub"]
        .as_array()
        .expect("environment.scrub must be an array");
    for expected in ["*_TOKEN", "*_SECRET", "*_PASSWORD", "*_AUTHORIZATION"] {
        assert!(scrub.iter().any(|pattern| pattern == expected));
    }
    Ok(())
}
