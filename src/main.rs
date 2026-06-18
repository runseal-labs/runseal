mod policy;

use policy::{normalize_policy, NetworkMode, PolicyError, SandboxPolicy, POLICY_VERSION};
use serde_json::{json, Value};
use std::env;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const PROTOCOL_VERSION: &str = "runseal.protocol/v1";

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
        [command, rest @ ..] if command == "explain-policy" => run_explain_policy(rest),
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
        "explainPolicy" => match explain_policy_from_params(&params) {
            Ok(result) => vec![rpc_result(id, result)],
            Err(err) => vec![rpc_error(id, err)],
        },
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
    let policy = normalize_policy(
        &Value::String(request.policy.clone()),
        &request.cwd,
        request.network,
    )
    .map_err(|err| err.reason)?;
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

fn run_explain_policy(args: &[String]) -> Result<(), String> {
    let request = parse_policy_args(args)?;
    let policy = normalize_policy(
        &Value::String(request.policy.clone()),
        &request.cwd,
        request.network,
    )
    .map_err(|err| err.reason)?;

    println!("{}", policy.explain_json());
    Ok(())
}

fn parse_exec_args(args: &[String]) -> Result<CliExecRequest, String> {
    let mut json = false;
    let mut events = false;
    let mut policy = "read-only".to_string();
    let mut network = None;
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
            "--network" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--network requires a value".to_string())?;
                network = Some(parse_network_mode(value)?);
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
                    network,
                    cwd,
                    command,
                });
            }
            other => return Err(format!("unknown exec argument: {other}")),
        }
    }

    Err("exec requires -- followed by a command".to_string())
}

fn parse_policy_args(args: &[String]) -> Result<CliPolicyRequest, String> {
    let mut policy = "read-only".to_string();
    let mut network = None;
    let mut cwd = current_dir();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--policy" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--policy requires a value".to_string())?;
                policy = value.clone();
                index += 2;
            }
            "--network" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--network requires a value".to_string())?;
                network = Some(parse_network_mode(value)?);
                index += 2;
            }
            "--cwd" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--cwd requires a value".to_string())?;
                cwd = PathBuf::from(value);
                index += 2;
            }
            other => return Err(format!("unknown explain-policy argument: {other}")),
        }
    }

    Ok(CliPolicyRequest {
        policy,
        network,
        cwd,
    })
}

fn parse_network_mode(value: &str) -> Result<NetworkMode, String> {
    NetworkMode::from_str(value)
        .ok_or_else(|| format!("network mode must be disabled or proxy, got {value}"))
}

fn explain_policy_from_params(params: &Value) -> Result<Value, RunSealError> {
    let cwd = params
        .get("cwd")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(current_dir);
    let policy = params
        .get("policy")
        .cloned()
        .unwrap_or_else(|| json!("read-only"));
    let network = network_override_from_params(params)?;
    let policy = normalize_policy(&policy, &cwd, network)?;

    Ok(policy.explain_json())
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
    let network = network_override_from_params(params)?;
    let policy = normalize_policy(&policy, &cwd, network)?;

    execute_command(&command, &cwd, &policy)
}

fn network_override_from_params(params: &Value) -> Result<Option<NetworkMode>, RunSealError> {
    let Some(value) = params.get("network").or_else(|| params.get("network_mode")) else {
        return Ok(None);
    };
    let mode = if let Some(mode) = value.as_str() {
        mode
    } else {
        value.get("mode").and_then(Value::as_str).ok_or_else(|| {
            RunSealError::new("INVALID_REQUEST", "params.network.mode is required")
        })?
    };

    NetworkMode::from_str(mode).map(Some).ok_or_else(|| {
        RunSealError::new("POLICY_INVALID", "network.mode must be disabled or proxy")
    })
}

fn execute_command(
    command: &[String],
    cwd: &PathBuf,
    policy: &SandboxPolicy,
) -> Result<(Vec<Value>, Value), RunSealError> {
    if command.is_empty() {
        return Err(RunSealError::new("INVALID_REQUEST", "command is empty"));
    }

    if policy.denies_execution_without_backend() {
        return Err(RunSealError::new(
            "POLICY_DENIED",
            "filesystem write denied by policy",
        ));
    }

    if !policy.allows_local_execution() {
        return Err(RunSealError::new(
            "BACKEND_CAPABILITY_MISSING",
            format!(
                "no sandbox backend can enforce policy {} in this build",
                policy.id
            ),
        ));
    }

    let execution_id = new_execution_id();
    let policy_id = policy.id.clone();
    let policy_hash = policy.hash();
    let started = json!({
        "type": "execution.started",
        "execution_id": execution_id,
        "policy_id": policy_id,
        "policy_hash": policy_hash,
        "sandbox": {
            "level": policy.sandbox_level.as_str(),
            "enforced": false,
        },
        "network": {
            "mode": policy.network.mode.as_str(),
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
            "level": policy.sandbox_level.as_str(),
            "enforced": false,
        },
        "network": {
            "mode": policy.network.mode.as_str(),
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
    network: Option<NetworkMode>,
    cwd: PathBuf,
    command: Vec<String>,
}

#[derive(Debug)]
struct CliPolicyRequest {
    policy: String,
    network: Option<NetworkMode>,
    cwd: PathBuf,
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

impl From<PolicyError> for RunSealError {
    fn from(err: PolicyError) -> Self {
        Self::new(err.code, err.reason)
    }
}
