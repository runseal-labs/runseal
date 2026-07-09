use super::*;
use crate::policy::NetworkMode;
use crate::protocol::request_validation::env_from_params;
use serde_json::{Map, Value, json};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MCP_HELP_TEXT: &str = "\
Usage: runseal mcp --stdio [--policy <policy>] [--network <mode>]

Options:
  --policy   fixed sandbox policy for all MCP executions (default: workspace-write)
  --network  fixed network mode for all MCP executions (default: unmanaged)
MCP exposes exactly one tool: exec. Tool calls may set command, cwd, timeout_ms, and env.
";

const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
const MCP_PROTOCOL_FALLBACK_VERSION: &str = "2025-06-18";

#[derive(Clone, Debug)]
struct McpConfig {
    policy: String,
    network: Option<NetworkMode>,
}

#[derive(Debug)]
struct McpExecRequest {
    command: Vec<String>,
    cwd: PathBuf,
    timeout: Option<Duration>,
}

pub(crate) fn run(args: &[String]) -> Result<(), String> {
    if matches!(args, [flag] if flag == "--help" || flag == "-h") {
        print!("{MCP_HELP_TEXT}");
        return Ok(());
    }
    let config = parse_mcp_args(args)?;
    run_mcp_stdio(&config).map_err(|err| err.to_string())
}

fn parse_mcp_args(args: &[String]) -> Result<McpConfig, String> {
    let mut stdio = false;
    let mut policy = "workspace-write".to_string();
    let mut network = Some(NetworkMode::Unmanaged);
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--stdio" => {
                stdio = true;
                index += 1;
            }
            "--policy" => {
                policy = args
                    .get(index + 1)
                    .ok_or_else(|| "--policy requires a value".to_string())?
                    .clone();
                index += 2;
            }
            "--network" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--network requires a value".to_string())?;
                network = Some(NetworkMode::from_str(value).ok_or_else(|| {
                    format!("network mode must be unmanaged, disabled, or proxy, got {value}")
                })?);
                index += 2;
            }
            "--http" | "--sse" | "--tcp" => {
                return Err(format!(
                    "mcp {} requires a transport RFC and is not implemented",
                    args[index]
                ));
            }
            other => return Err(format!("unknown mcp argument: {other}")),
        }
    }

    if !stdio {
        return Err("mcp requires --stdio".to_string());
    }

    Ok(McpConfig { policy, network })
}

fn run_mcp_stdio(config: &McpConfig) -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = Arc::new(Mutex::new(io::stdout()));
    let config = Arc::new(config.clone());
    let mut workers = Vec::new();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(&line) {
            Ok(request) => {
                if request.get("method").and_then(Value::as_str) == Some("tools/call") {
                    workers.push(spawn_tools_call_worker(
                        Arc::clone(&config),
                        Arc::clone(&stdout),
                        request,
                    ));
                } else if let Some(response) = handle_mcp_request(&config, &request) {
                    write_mcp_response(&stdout, response)?;
                }
            }
            Err(err) => {
                write_mcp_response(&stdout, rpc::parse_error(err.to_string()))?;
            }
        }
    }
    for worker in workers {
        worker
            .join()
            .map_err(|_| io::Error::other("mcp worker thread panicked"))??;
    }
    Ok(())
}

fn spawn_tools_call_worker(
    config: Arc<McpConfig>,
    stdout: Arc<Mutex<io::Stdout>>,
    request: Value,
) -> JoinHandle<io::Result<()>> {
    thread::spawn(move || {
        if let Some(response) = handle_mcp_request(&config, &request) {
            write_mcp_response(&stdout, response)?;
        }
        Ok(())
    })
}

fn write_mcp_response(stdout: &Mutex<io::Stdout>, response: Value) -> io::Result<()> {
    let mut stdout = stdout
        .lock()
        .map_err(|_| io::Error::other("mcp stdout lock poisoned"))?;
    writeln!(stdout, "{response}")?;
    stdout.flush()
}

fn handle_mcp_request(config: &McpConfig, request: &Value) -> Option<Value> {
    let id = request.get("id").cloned();
    let method = request.get("method").and_then(Value::as_str);

    let id = id?;
    let Some(method) = method else {
        return Some(rpc::invalid_request(
            id,
            RunSealError::new("INVALID_REQUEST", "request.method is required"),
        ));
    };

    match method {
        "initialize" => Some(rpc::result(
            id,
            initialize_result(request.get("params").unwrap_or(&json!({}))),
        )),
        "ping" => Some(rpc::result(id, json!({}))),
        "tools/list" => Some(rpc::result(id, tools_list_result(config))),
        "tools/call" => Some(handle_tools_call(
            config,
            id,
            request.get("params").unwrap_or(&json!({})),
        )),
        _ => Some(rpc::method_not_found(id, method)),
    }
}

fn initialize_result(params: &Value) -> Value {
    let protocol_version = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .filter(|version| {
            *version == MCP_PROTOCOL_VERSION || *version == MCP_PROTOCOL_FALLBACK_VERSION
        })
        .unwrap_or(MCP_PROTOCOL_VERSION);
    json!({
        "protocolVersion": protocol_version,
        "capabilities": {
            "tools": {
                "listChanged": false
            }
        },
        "serverInfo": {
            "name": "runseal",
            "version": env!("CARGO_PKG_VERSION")
        }
    })
}

fn tools_list_result(config: &McpConfig) -> Value {
    let network_note = match config.network.unwrap_or(NetworkMode::Unmanaged) {
        NetworkMode::Unmanaged => {
            "Network mode is fixed to unmanaged: commands may use direct network access."
        }
        NetworkMode::Disabled => {
            "Network mode is fixed to disabled: commands should not expect network access."
        }
        NetworkMode::Proxy => {
            "Network mode is fixed to proxy: commands may access the network through RunSeal's managed proxy. Inside this exec call, use the injected HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, GIT_HTTP_PROXY, and GIT_HTTPS_PROXY environment variables directly; do not hardcode proxy host, port, or credentials. Proxy credentials are per-execution and available in RUNSEAL_NETWORK_PROXY_AUTHORIZATION only when a tool needs an explicit Proxy-Authorization header."
        }
    };
    let description = format!(
        "Run a path-qualified command in a caller-supplied workspace under this server's fixed sandbox policy and network mode. {network_note}"
    );
    json!({
        "tools": [
            {
                "name": "exec",
                "title": "Exec",
                "description": description,
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "command": {
                            "type": "array",
                            "items": {"type": "string"},
                            "minItems": 1,
                            "description": "Command argv. The program path must be absolute or path-qualified."
                        },
                        "cwd": {
                            "type": "string",
                            "description": "Existing workspace directory for this execution."
                        },
                        "timeout_ms": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Optional timeout for this execution in milliseconds."
                        },
                        "env": {
                            "type": "object",
                            "additionalProperties": {"type": "string"},
                            "description": "Optional environment overrides subject to the fixed RunSeal policy scrub rules."
                        }
                    },
                    "required": ["command", "cwd"]
                },
                "annotations": {
                    "readOnlyHint": false,
                    "destructiveHint": true,
                    "idempotentHint": false,
                    "openWorldHint": true
                }
            }
        ]
    })
}

fn handle_tools_call(config: &McpConfig, id: Value, params: &Value) -> Value {
    match tools_call_result(config, params) {
        Ok(result) => rpc::result(id, result),
        Err(err) => rpc::error(id, err),
    }
}

fn tools_call_result(config: &McpConfig, params: &Value) -> Result<Value, RunSealError> {
    let params = params.as_object().ok_or_else(|| {
        RunSealError::new("INVALID_REQUEST", "tools/call params must be an object")
    })?;
    validate_keys(params, "tools/call", &["name", "arguments", "_meta"])?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| RunSealError::new("INVALID_REQUEST", "params.name must be a string"))?;
    if name != "exec" {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            format!("unknown MCP tool: {name}"),
        ));
    }
    let default_arguments = json!({});
    let arguments = params
        .get("arguments")
        .unwrap_or(&default_arguments)
        .as_object()
        .ok_or_else(|| {
            RunSealError::new("INVALID_REQUEST", "params.arguments must be an object")
        })?;
    let request = match exec_request_from_arguments(arguments) {
        Ok(request) => request,
        Err(err) => return Ok(tool_runseal_error(err)),
    };
    let cwd = match normalize_execution_cwd(&request.cwd) {
        Ok(cwd) => cwd,
        Err(err) => return Ok(tool_runseal_error(err)),
    };
    let policy = match normalize_policy(&Value::String(config.policy.clone()), &cwd, config.network)
    {
        Ok(policy) => policy,
        Err(err) => return Ok(tool_runseal_error(err.into())),
    };
    let env = match env_from_params(arguments, &policy) {
        Ok(env) => env,
        Err(err) => return Ok(tool_runseal_error(err)),
    };
    match execute_command(
        &request.command,
        &cwd,
        &policy,
        ExecutionStdin::Empty,
        env,
        None,
        request.timeout,
    ) {
        Ok((_events, result)) => {
            let exit_code = result.get("exit_code").and_then(Value::as_i64).unwrap_or(1);
            Ok(tool_result(mcp_execution_payload(&result), exit_code != 0))
        }
        Err(err) => Ok(tool_runseal_error(err)),
    }
}

fn exec_request_from_arguments(
    arguments: &Map<String, Value>,
) -> Result<McpExecRequest, RunSealError> {
    validate_keys(arguments, "exec", &["command", "cwd", "timeout_ms", "env"])?;
    let command = arguments
        .get("command")
        .and_then(Value::as_array)
        .ok_or_else(|| RunSealError::new("INVALID_REQUEST", "arguments.command must be an array"))?
        .iter()
        .map(|item| {
            item.as_str().map(str::to_string).ok_or_else(|| {
                RunSealError::new(
                    "INVALID_REQUEST",
                    "arguments.command entries must be strings",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_command(&command)?;
    let cwd = arguments
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| RunSealError::new("INVALID_REQUEST", "arguments.cwd is required"))?;
    let timeout = match arguments.get("timeout_ms") {
        Some(value) => {
            let timeout_ms = value.as_u64().ok_or_else(|| {
                RunSealError::new("INVALID_REQUEST", "arguments.timeout_ms must be an integer")
            })?;
            if timeout_ms == 0 {
                return Err(RunSealError::new(
                    "INVALID_REQUEST",
                    "arguments.timeout_ms must be at least 1",
                ));
            }
            Some(Duration::from_millis(timeout_ms))
        }
        None => None,
    };

    Ok(McpExecRequest {
        command,
        cwd,
        timeout,
    })
}

fn validate_command(command: &[String]) -> Result<(), RunSealError> {
    let Some(program) = command.first().filter(|program| !program.is_empty()) else {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            "arguments.command is empty",
        ));
    };
    if !(Path::new(program).is_absolute() || program.contains('/') || program.contains('\\')) {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            "arguments.command[0] must be path-qualified",
        ));
    }
    Ok(())
}

fn validate_keys(
    object: &Map<String, Value>,
    context: &'static str,
    allowed_keys: &[&'static str],
) -> Result<(), RunSealError> {
    for key in object.keys() {
        if !allowed_keys.contains(&key.as_str()) {
            return Err(RunSealError::new(
                "INVALID_REQUEST",
                format!("{context} does not support {key}"),
            ));
        }
    }
    Ok(())
}

fn mcp_execution_payload(result: &Value) -> Value {
    let mut payload = Map::new();
    insert_if_present(&mut payload, result, "status");
    insert_if_present(&mut payload, result, "exit_code");
    insert_if_present(&mut payload, result, "stdout");
    insert_if_present(&mut payload, result, "stderr");
    insert_if_present(&mut payload, result, "stdout_bytes");
    insert_if_present(&mut payload, result, "stderr_bytes");
    insert_if_present(&mut payload, result, "output_truncated");
    insert_if_present(&mut payload, result, "resource_usage");
    insert_if_present(&mut payload, result, "audit_path");
    insert_if_present(&mut payload, result, "execution_id");
    insert_if_present(&mut payload, result, "session_id");
    insert_if_present(&mut payload, result, "policy_id");
    insert_if_present(&mut payload, result, "policy_hash");
    insert_if_present(&mut payload, result, "sandbox");
    insert_if_present(&mut payload, result, "network");
    Value::Object(payload)
}

fn mcp_error_payload(payload: &Value) -> Value {
    let Some(error) = payload.get("error") else {
        return payload.clone();
    };
    let Some(data) = error.get("data") else {
        return payload.clone();
    };
    let mut compact_data = Map::new();
    insert_if_present(&mut compact_data, data, "code");
    insert_if_present(&mut compact_data, data, "reason");
    insert_if_present(&mut compact_data, data, "audit_path");
    insert_if_present(&mut compact_data, data, "execution_id");
    insert_if_present(&mut compact_data, data, "session_id");
    insert_if_present(&mut compact_data, data, "policy_id");
    insert_if_present(&mut compact_data, data, "policy_hash");
    insert_if_present(&mut compact_data, data, "setup_status");

    json!({
        "error": {
            "message": error.get("message").cloned().unwrap_or(Value::Null),
            "data": compact_data,
        }
    })
}

fn insert_if_present(target: &mut Map<String, Value>, source: &Value, key: &'static str) {
    if let Some(value) = source.get(key) {
        target.insert(key.to_string(), value.clone());
    }
}

fn tool_result(payload: Value, is_error: bool) -> Value {
    let text = tool_content_text(&payload, is_error);
    json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ],
        "structuredContent": payload,
        "isError": is_error
    })
}

fn tool_content_text(payload: &Value, is_error: bool) -> String {
    if is_error {
        return payload
            .pointer("/error/data/reason")
            .or_else(|| payload.pointer("/error/message"))
            .and_then(Value::as_str)
            .unwrap_or("RunSeal execution failed")
            .to_string();
    }
    let stdout = payload.get("stdout").and_then(Value::as_str).unwrap_or("");
    let stderr = payload.get("stderr").and_then(Value::as_str).unwrap_or("");
    if !stdout.is_empty() {
        return stdout.to_string();
    }
    if !stderr.is_empty() {
        return stderr.to_string();
    }
    format!(
        "RunSeal execution finished with exit_code={}",
        payload
            .get("exit_code")
            .map(Value::to_string)
            .unwrap_or_else(|| "unknown".to_string())
    )
}

fn tool_runseal_error(err: RunSealError) -> Value {
    tool_result(mcp_error_payload(&cli_error_payload(err)), true)
}
