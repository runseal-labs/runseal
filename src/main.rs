use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const PROTOCOL_VERSION: &str = "runseal.protocol/v1";
const POLICY_VERSION: &str = "runseal.policy/v1";

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [flag] if flag == "--version" => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        [json_flag, command] if json_flag == "--json" && command == "version" => {
            println!("{}", version_payload());
            Ok(())
        }
        [command, json_flag] if command == "version" && json_flag == "--json" => {
            println!("{}", version_payload());
            Ok(())
        }
        [command] if command == "version" => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        [command, flag] if command == "rpc" && flag == "--stdio" => run_rpc_stdio(),
        [command, rest @ ..] if command == "exec" => run_exec(rest),
        [] => Err("missing command".to_string()),
        _ => Err(format!("unknown command: {}", args.join(" "))),
    }
}

fn version_payload() -> Value {
    json!({
        "runseal_version": env!("CARGO_PKG_VERSION"),
        "protocol_version": PROTOCOL_VERSION,
        "policy_versions": [POLICY_VERSION],
    })
}

fn run_rpc_stdio() -> Result<(), String> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|err| format!("failed to read stdin: {err}"))?;

    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let request: Value =
            serde_json::from_str(line).map_err(|err| format!("invalid JSON-RPC request: {err}"))?;
        for message in handle_rpc_request(&request) {
            println!("{message}");
        }
    }
    Ok(())
}

fn handle_rpc_request(request: &Value) -> Vec<Value> {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));

    match method {
        "getVersion" => vec![rpc_result(id, version_payload())],
        "explainPolicy" => {
            let cwd = params
                .get("cwd")
                .and_then(Value::as_str)
                .map(PathBuf::from)
                .unwrap_or_else(current_dir);
            let policy = params
                .get("policy")
                .cloned()
                .unwrap_or_else(|| json!("read-only"));
            vec![rpc_result(id, explain_policy(&policy, &cwd))]
        }
        "execute" => match execute_from_params(&params) {
            Ok((events, result)) => {
                let mut messages: Vec<Value> = events
                    .into_iter()
                    .map(|event| json!({"jsonrpc": "2.0", "method": "event", "params": event}))
                    .collect();
                messages.push(rpc_result(id, result));
                messages
            }
            Err(err) => vec![rpc_error(id, err)],
        },
        _ => vec![rpc_error(
            id,
            RunSealError::new("INVALID_REQUEST", format!("unknown method: {method}")),
        )],
    }
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn rpc_error(id: Value, err: RunSealError) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32000,
            "message": err.message,
            "data": {
                "code": err.code,
                "reason": err.reason,
            }
        }
    })
}

fn run_exec(args: &[String]) -> Result<(), String> {
    let request = parse_exec_args(args)?;
    let policy = Value::String(request.policy.clone());
    let (events, result) =
        execute_command(&request.command, &request.cwd, &policy).map_err(|err| err.message)?;

    if request.events {
        for event in events {
            println!("{event}");
        }
        return Ok(());
    }

    if request.json {
        println!("{result}");
        return Ok(());
    }

    if let Some(text) = result.get("stdout").and_then(Value::as_str) {
        print!("{text}");
    }
    Ok(())
}

fn parse_exec_args(args: &[String]) -> Result<CliExecRequest, String> {
    let mut json = false;
    let mut events = false;
    let mut policy = "read-only".to_string();
    let mut cwd = current_dir();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => {
                json = true;
                index += 1;
            }
            "--events" => {
                events = true;
                index += 1;
            }
            "--policy" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--policy requires a value".to_string())?;
                policy = value.clone();
                index += 2;
            }
            "--cwd" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--cwd requires a value".to_string())?;
                cwd = PathBuf::from(value);
                index += 2;
            }
            "--" => {
                let command = args[index + 1..].to_vec();
                if command.is_empty() {
                    return Err("exec requires a command after --".to_string());
                }
                return Ok(CliExecRequest {
                    json,
                    events,
                    policy,
                    cwd,
                    command,
                });
            }
            other => return Err(format!("unknown exec argument: {other}")),
        }
    }

    Err("exec requires -- followed by a command".to_string())
}

fn execute_from_params(params: &Value) -> Result<(Vec<Value>, Value), RunSealError> {
    let command = params
        .get("command")
        .and_then(Value::as_array)
        .ok_or_else(|| RunSealError::new("INVALID_REQUEST", "params.command must be an array"))?
        .iter()
        .map(|item| {
            item.as_str().map(str::to_string).ok_or_else(|| {
                RunSealError::new("INVALID_REQUEST", "params.command entries must be strings")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let cwd = params
        .get("cwd")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(current_dir);
    let policy = params
        .get("policy")
        .cloned()
        .unwrap_or_else(|| json!("read-only"));

    execute_command(&command, &cwd, &policy)
}

fn execute_command(
    command: &[String],
    cwd: &PathBuf,
    policy: &Value,
) -> Result<(Vec<Value>, Value), RunSealError> {
    if command.is_empty() {
        return Err(RunSealError::new("INVALID_REQUEST", "command is empty"));
    }

    if denies_execution(policy) {
        return Err(RunSealError::new(
            "POLICY_DENIED",
            "filesystem write denied by policy",
        ));
    }

    if !allows_local_execution(policy) {
        return Err(RunSealError::new(
            "BACKEND_CAPABILITY_MISSING",
            format!(
                "no sandbox backend can enforce policy {} in this build",
                policy_id(policy)
            ),
        ));
    }

    let execution_id = new_execution_id();
    let policy_id = policy_id(policy);
    let policy_hash = policy_hash(policy, cwd);
    let started = json!({
        "type": "execution.started",
        "execution_id": execution_id,
        "policy_id": policy_id,
        "policy_hash": policy_hash,
        "sandbox": {
            "level": policy_id,
            "enforced": false,
        }
    });

    let timer = Instant::now();
    let output = spawn_command(command, cwd)?;
    let duration_ms = timer.elapsed().as_millis() as u64;
    let exit_code = output.status.code().unwrap_or(1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let mut events = vec![started];
    if !stdout.is_empty() {
        events.push(json!({
            "type": "execution.stdout",
            "execution_id": execution_id,
            "text": stdout,
            "bytes": output.stdout.len(),
        }));
    }
    if !stderr.is_empty() {
        events.push(json!({
            "type": "execution.stderr",
            "execution_id": execution_id,
            "text": stderr,
            "bytes": output.stderr.len(),
        }));
    }
    events.push(json!({
        "type": "execution.finished",
        "execution_id": execution_id,
        "exit_code": exit_code,
        "status": "finished",
    }));

    let result = json!({
        "execution_id": execution_id,
        "status": "finished",
        "exit_code": exit_code,
        "policy_id": policy_id,
        "policy_hash": policy_hash,
        "sandbox": {
            "level": policy_id,
            "enforced": false,
        },
        "stdout_bytes": output.stdout.len(),
        "stderr_bytes": output.stderr.len(),
        "stdout": stdout,
        "stderr": stderr,
        "resource_usage": {
            "duration_ms": duration_ms,
        }
    });

    Ok((events, result))
}

fn spawn_command(command: &[String], cwd: &PathBuf) -> Result<Output, RunSealError> {
    Command::new(&command[0])
        .args(&command[1..])
        .current_dir(cwd)
        .output()
        .map_err(|err| {
            RunSealError::new(
                "EXECUTION_FAILED_TO_START",
                format!("failed to spawn command {}: {err}", command[0]),
            )
        })
}

fn explain_policy(policy: &Value, cwd: &PathBuf) -> Value {
    let policy_id = policy_id(policy);
    let network_mode = network_mode(policy);
    let write_roots = write_roots(policy, cwd);
    json!({
        "policy_id": policy_id,
        "policy_hash": policy_hash(policy, cwd),
        "network": {
            "mode": network_mode,
        },
        "filesystem": {
            "read": [cwd.to_string_lossy()],
            "write": write_roots,
        }
    })
}

fn policy_id(policy: &Value) -> String {
    policy
        .as_str()
        .map(str::to_string)
        .or_else(|| policy.get("id").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_else(|| "inline".to_string())
}

fn network_mode(policy: &Value) -> &'static str {
    if let Some(policy) = policy.as_str() {
        return if policy.contains("proxy") {
            "proxy"
        } else {
            "disabled"
        };
    }

    policy
        .get("network")
        .and_then(|network| network.get("mode"))
        .and_then(Value::as_str)
        .map(|mode| if mode == "proxy" { "proxy" } else { "disabled" })
        .unwrap_or("disabled")
}

fn write_roots(policy: &Value, cwd: &PathBuf) -> Vec<String> {
    if let Some(policy) = policy.as_str() {
        return match policy {
            "workspace-proxy" | "workspace-write" | "workspace-contained" => {
                vec![cwd.to_string_lossy().to_string()]
            }
            _ => Vec::new(),
        };
    }

    policy
        .get("filesystem")
        .and_then(|filesystem| filesystem.get("write"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn denies_execution(policy: &Value) -> bool {
    policy
        .get("filesystem")
        .and_then(|filesystem| filesystem.get("write"))
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
}

fn allows_local_execution(policy: &Value) -> bool {
    policy.as_str() == Some("danger-full-access")
        || policy.get("id").and_then(Value::as_str) == Some("danger-full-access")
        || policy.get("level").and_then(Value::as_str) == Some("danger-full-access")
        || policy.get("sandbox_level").and_then(Value::as_str) == Some("danger-full-access")
}

fn policy_hash(policy: &Value, cwd: &PathBuf) -> String {
    let mut hasher = Sha256::new();
    hasher.update(policy.to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(cwd.to_string_lossy().as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

fn new_execution_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    format!("exec_{millis:x}")
}

fn current_dir() -> PathBuf {
    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

#[derive(Debug)]
struct CliExecRequest {
    json: bool,
    events: bool,
    policy: String,
    cwd: PathBuf,
    command: Vec<String>,
}

#[derive(Debug)]
struct RunSealError {
    code: String,
    message: String,
    reason: String,
}

impl RunSealError {
    fn new(code: impl Into<String>, reason: impl Into<String>) -> Self {
        let code = code.into();
        let reason = reason.into();
        Self {
            message: reason.clone(),
            code,
            reason,
        }
    }
}
