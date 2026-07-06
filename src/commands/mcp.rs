use super::*;
use crate::policy::NetworkMode;
use crate::protocol::request_validation::env_from_params;
use serde_json::{Map, Value, json};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

const MCP_HELP_TEXT: &str = "\
Usage: runseal mcp --stdio [--policy <policy>] [--network <mode>] [--cwd <path>]

Options:
  --policy   fixed sandbox policy for all MCP executions (default: workspace-write)
  --network  fixed network mode for all MCP executions (default: unmanaged)
  --cwd      default workspace directory; tools/call may override cwd per execution

MCP exposes exactly one tool: runseal_exec. Tool calls may set command, cwd, timeout_ms, and env.
";

const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
const MCP_PROTOCOL_FALLBACK_VERSION: &str = "2025-06-18";

#[derive(Debug)]
struct McpConfig {
    policy: String,
    network: Option<NetworkMode>,
    default_cwd: PathBuf,
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
    let mut default_cwd = current_dir();
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
            "--cwd" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--cwd requires a value".to_string())?;
                default_cwd = PathBuf::from(value);
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

    Ok(McpConfig {
        policy,
        network,
        default_cwd,
    })
}

fn run_mcp_stdio(config: &McpConfig) -> io::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(&line) {
            Ok(request) => {
                if let Some(response) = handle_mcp_request(config, &request) {
                    writeln!(stdout, "{response}")?;
                    stdout.flush()?;
                }
            }
            Err(err) => {
                let response = rpc::parse_error(err.to_string());
                writeln!(stdout, "{response}")?;
                stdout.flush()?;
            }
        }
    }
    Ok(())
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
        "tools/list" => Some(rpc::result(id, tools_list_result())),
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

fn tools_list_result() -> Value {
    json!({
        "tools": [
            {
                "name": "runseal_exec",
                "title": "RunSeal Exec",
                "description": "Run a path-qualified command through RunSeal under the MCP server's fixed startup policy and network mode.",
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
                            "description": "Optional working directory for this execution. Defaults to the server startup cwd."
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
                    "required": ["command"]
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
    validate_keys(params, "tools/call", &["name", "arguments"])?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| RunSealError::new("INVALID_REQUEST", "params.name must be a string"))?;
    if name != "runseal_exec" {
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
    let request = match exec_request_from_arguments(config, arguments) {
        Ok(request) => request,
        Err(err) => return Ok(tool_error(cli_error_payload(err))),
    };
    let cwd = match normalize_execution_cwd(&request.cwd) {
        Ok(cwd) => cwd,
        Err(err) => return Ok(tool_error(cli_error_payload(err))),
    };
    let policy = match normalize_policy(&Value::String(config.policy.clone()), &cwd, config.network)
    {
        Ok(policy) => policy,
        Err(err) => return Ok(tool_error(cli_error_payload(err.into()))),
    };
    let env = match env_from_params(arguments, &policy) {
        Ok(env) => env,
        Err(err) => return Ok(tool_error(cli_error_payload(err))),
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
            Ok(tool_result(result, exit_code != 0))
        }
        Err(err) => Ok(tool_error(cli_error_payload(err))),
    }
}

fn exec_request_from_arguments(
    config: &McpConfig,
    arguments: &Map<String, Value>,
) -> Result<McpExecRequest, RunSealError> {
    validate_keys(
        arguments,
        "runseal_exec",
        &["command", "cwd", "timeout_ms", "env"],
    )?;
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
        .map(PathBuf::from)
        .unwrap_or_else(|| config.default_cwd.clone());
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

fn tool_result(payload: Value, is_error: bool) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": payload.to_string()
            }
        ],
        "structuredContent": payload,
        "isError": is_error
    })
}

fn tool_error(payload: Value) -> Value {
    tool_result(payload, true)
}
