use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;
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

fn python_bin() -> &'static str {
    static PYTHON: OnceLock<String> = OnceLock::new();
    PYTHON.get_or_init(resolve_python_bin)
}

fn resolve_python_bin() -> String {
    if let Some(path) = env::var_os("RUNSEAL_TEST_PYTHON") {
        return PathBuf::from(path).to_string_lossy().into_owned();
    }
    let output = match if cfg!(windows) {
        Command::new("where.exe").arg("python").output()
    } else {
        Command::new("sh")
            .args(["-c", "command -v python3"])
            .output()
    } {
        Ok(output) => output,
        Err(err) => panic!("failed to locate python: {err}"),
    };
    let stdout = match String::from_utf8(output.stdout) {
        Ok(stdout) => stdout,
        Err(err) => panic!("python path must be utf-8: {err}"),
    };
    match stdout.lines().next() {
        Some(path) => path.to_string(),
        None => panic!("python must exist"),
    }
}

fn run_mcp(args: &[&str], message: &str) -> Result<Output> {
    let bin = require_runseal_bin()?;
    let mut command = Command::new(bin);
    command.args(["mcp", "--stdio"]).args(args);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn runseal mcp")?;

    child
        .stdin
        .as_mut()
        .context("stdin unavailable")?
        .write_all(message.as_bytes())?;

    child
        .wait_with_output()
        .context("failed to wait for runseal mcp")
}

fn mcp_request(id: u64, method: &str, params: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string() + "\n"
}

fn stdout_json_lines(output: &Output) -> Result<Vec<Value>> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).context("stdout line was not valid JSON"))
        .collect()
}

fn output_reports_cwd(output: &str, expected: &Path) -> bool {
    let Ok(expected) = expected.canonicalize() else {
        return false;
    };

    output.lines().any(|line| {
        PathBuf::from(line)
            .canonicalize()
            .is_ok_and(|actual| actual == expected)
    })
}

#[test]
fn mcp_initialize_negotiates_supported_protocol_and_declares_static_tools() -> Result<()> {
    let output = run_mcp(
        &[],
        &mcp_request(
            1,
            "initialize",
            json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0.0.0"}
            }),
        ),
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let messages = stdout_json_lines(&output)?;
    assert_eq!(messages.len(), 1);
    let response = &messages[0];
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert_eq!(response["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(
        response["result"]["capabilities"]["tools"]["listChanged"],
        false
    );
    assert_eq!(response["result"]["serverInfo"]["name"], "runseal");
    Ok(())
}

#[test]
fn mcp_tools_list_exposes_only_exec() -> Result<()> {
    let output = run_mcp(&[], &mcp_request(1, "tools/list", json!({})))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let messages = stdout_json_lines(&output)?;
    let tools = messages[0]["result"]["tools"]
        .as_array()
        .context("tools/list must return tools")?;
    assert_eq!(tools.len(), 1);
    let tool = &tools[0];
    assert_eq!(tool["name"], "exec");
    assert_eq!(tool["title"], "Exec");
    assert!(
        tool["description"]
            .as_str()
            .unwrap_or_default()
            .contains("fixed sandbox policy"),
        "{tool}"
    );
    assert_eq!(
        tool["inputSchema"]["required"],
        json!(["command", "cwd"]),
        "{tool}"
    );
    assert!(tool["inputSchema"]["properties"].get("command").is_some());
    assert!(tool["inputSchema"]["properties"].get("cwd").is_some());
    assert!(
        tool["inputSchema"]["properties"]
            .get("timeout_ms")
            .is_some()
    );
    assert_eq!(
        tool["inputSchema"]["properties"]["timeout_ms"]["minimum"],
        1
    );
    assert!(tool["inputSchema"]["properties"].get("policy").is_none());
    assert!(tool["inputSchema"]["properties"].get("network").is_none());
    assert!(tool["inputSchema"]["properties"].get("env").is_some());
    assert_eq!(tool["inputSchema"]["additionalProperties"], false);
    Ok(())
}

#[test]
fn mcp_tools_list_mentions_fixed_proxy_network_access() -> Result<()> {
    let output = run_mcp(
        &["--network", "proxy"],
        &mcp_request(1, "tools/list", json!({})),
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let tool = &messages[0]["result"]["tools"][0];
    let description = tool["description"].as_str().unwrap_or_default();
    assert!(description.contains("fixed to proxy"), "{description}");
    assert!(description.contains("managed proxy"), "{description}");
    assert!(description.contains("HTTP_PROXY"), "{description}");
    assert!(description.contains("do not hardcode"), "{description}");
    assert!(description.contains("per-execution"), "{description}");
    assert!(
        description.contains("RUNSEAL_NETWORK_PROXY_AUTHORIZATION"),
        "{description}"
    );
    assert!(tool["inputSchema"]["properties"].get("network").is_none());
    Ok(())
}

#[test]
fn mcp_exec_runs_with_per_call_cwd() -> Result<()> {
    let call_cwd = TempDir::new()?;
    let cwd = call_cwd.path().to_string_lossy().to_string();
    let output = run_mcp(
        &["--policy", "danger-full-access"],
        &mcp_request(
            1,
            "tools/call",
            json!({
                "name": "exec",
                "arguments": {
                    "command": [python_bin(), "-c", "import os; print(os.getcwd())"],
                    "cwd": cwd
                }
            }),
        ),
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let result = &messages[0]["result"];
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(result["structuredContent"]["exit_code"], 0);
    assert!(
        output_reports_cwd(
            result["structuredContent"]["stdout"]
                .as_str()
                .unwrap_or_default(),
            call_cwd.path(),
        ),
        "{result}"
    );
    assert!(
        output_reports_cwd(
            result["content"][0]["text"].as_str().unwrap_or_default(),
            call_cwd.path(),
        ),
        "{result}"
    );
    assert!(result["structuredContent"].get("platform_plan").is_none());
    assert_eq!(result["structuredContent"]["network"]["mode"], "unmanaged");
    Ok(())
}

#[test]
fn mcp_exec_accepts_client_meta() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let output = run_mcp(
        &["--policy", "danger-full-access"],
        &mcp_request(
            1,
            "tools/call",
            json!({
                "name": "exec",
                "arguments": {
                    "command": [python_bin(), "-c", "print('meta-ok')"],
                    "cwd": cwd
                },
                "_meta": {"progressToken": "client-token"}
            }),
        ),
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let result = &messages[0]["result"];
    assert_eq!(result["isError"], false, "{result}");
    assert!(
        result["structuredContent"]["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("meta-ok"),
        "{result}"
    );
    Ok(())
}

#[test]
fn mcp_stdio_handles_ping_while_exec_is_running() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let message = mcp_request(
        1,
        "tools/call",
        json!({
            "name": "exec",
            "arguments": {
                "command": [
                    python_bin(),
                    "-c",
                    "import time; time.sleep(1); print('done')"
                ],
                "cwd": cwd,
                "timeout_ms": 5000
            }
        }),
    ) + &mcp_request(2, "ping", json!({}));

    let output = run_mcp(&["--policy", "danger-full-access"], &message)?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["id"], 2);
    assert_eq!(messages[0]["result"], json!({}));
    assert_eq!(messages[1]["id"], 1);
    assert!(
        messages[1]["result"]["structuredContent"]["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("done"),
        "{messages:?}"
    );
    Ok(())
}

#[test]
fn mcp_exec_reports_command_failures_as_tool_errors() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let output = run_mcp(
        &["--policy", "danger-full-access"],
        &mcp_request(
            1,
            "tools/call",
            json!({
                "name": "exec",
                "arguments": {
                    "command": [python_bin(), "-c", "import sys; sys.exit(7)"],
                    "cwd": cwd
                }
            }),
        ),
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let result = &messages[0]["result"];
    assert_eq!(result["isError"], true, "{result}");
    assert_eq!(result["structuredContent"]["exit_code"], 7);
    assert!(result.get("error").is_none());
    Ok(())
}

#[test]
fn mcp_exec_accepts_non_secret_environment_overrides() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let output = run_mcp(
        &["--policy", "danger-full-access"],
        &mcp_request(
            1,
            "tools/call",
            json!({
                "name": "exec",
                "arguments": {
                    "command": [
                        python_bin(),
                        "-c",
                        "import os; print(os.environ.get('RUNSEAL_TEST_VALUE', 'missing'))"
                    ],
                    "cwd": cwd,
                    "env": {"RUNSEAL_TEST_VALUE": "from-mcp"}
                }
            }),
        ),
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let result = &messages[0]["result"];
    assert_eq!(result["isError"], false, "{result}");
    assert!(
        result["structuredContent"]["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("from-mcp"),
        "{result}"
    );
    Ok(())
}

#[test]
fn mcp_exec_rejects_secret_environment_overrides_as_tool_errors() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let output = run_mcp(
        &["--policy", "danger-full-access"],
        &mcp_request(
            1,
            "tools/call",
            json!({
                "name": "exec",
                "arguments": {
                    "command": [python_bin(), "-c", "print('must not run')"],
                    "cwd": cwd,
                    "env": {"OPENAI_API_KEY": "blocked"}
                }
            }),
        ),
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let result = &messages[0]["result"];
    assert_eq!(result["isError"], true, "{result}");
    assert_eq!(
        result["structuredContent"]["error"]["data"]["code"], "INVALID_REQUEST",
        "{result}"
    );
    assert!(
        result["structuredContent"]["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("environment scrub"),
        "{result}"
    );
    Ok(())
}

#[test]
fn mcp_exec_rejects_policy_and_network_overrides_as_tool_errors() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    for forbidden in ["policy", "network", "stdin"] {
        let output = run_mcp(
            &["--policy", "danger-full-access"],
            &mcp_request(
                1,
                "tools/call",
                json!({
                    "name": "exec",
                    "arguments": {
                        "command": [python_bin(), "-c", "print('must not run')"],
                        "cwd": cwd,
                        forbidden: "blocked"
                    }
                }),
            ),
        )?;

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let messages = stdout_json_lines(&output)?;
        let result = &messages[0]["result"];
        assert_eq!(result["isError"], true, "{result}");
        assert_eq!(
            result["structuredContent"]["error"]["data"]["code"], "INVALID_REQUEST",
            "{result}"
        );
        assert!(
            result["structuredContent"]["error"]["data"]["reason"]
                .as_str()
                .unwrap_or_default()
                .contains(forbidden),
            "{result}"
        );
    }
    Ok(())
}

#[test]
fn mcp_exec_rejects_unqualified_program_as_tool_error() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let output = run_mcp(
        &["--policy", "danger-full-access"],
        &mcp_request(
            1,
            "tools/call",
            json!({
                "name": "exec",
                "arguments": {
                    "command": ["python", "-c", "print('must not run')"],
                    "cwd": cwd
                }
            }),
        ),
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let result = &messages[0]["result"];
    assert_eq!(result["isError"], true, "{result}");
    assert!(
        result["structuredContent"]["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("path-qualified"),
        "{result}"
    );
    Ok(())
}

#[test]
fn mcp_exec_requires_per_call_cwd() -> Result<()> {
    let output = run_mcp(
        &["--policy", "danger-full-access"],
        &mcp_request(
            1,
            "tools/call",
            json!({
                "name": "exec",
                "arguments": {
                    "command": [python_bin(), "-c", "print('must not run')"]
                }
            }),
        ),
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let result = &messages[0]["result"];
    assert_eq!(result["isError"], true, "{result}");
    assert!(
        result["structuredContent"]["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("arguments.cwd is required"),
        "{result}"
    );
    Ok(())
}

#[test]
fn mcp_exec_rejects_zero_timeout_as_tool_error() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let output = run_mcp(
        &["--policy", "danger-full-access"],
        &mcp_request(
            1,
            "tools/call",
            json!({
                "name": "exec",
                "arguments": {
                    "command": [python_bin(), "-c", "print('must not run')"],
                    "cwd": cwd,
                    "timeout_ms": 0
                }
            }),
        ),
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = stdout_json_lines(&output)?;
    let result = &messages[0]["result"];
    assert_eq!(result["isError"], true, "{result}");
    assert!(
        result["structuredContent"]["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("at least 1"),
        "{result}"
    );
    Ok(())
}
