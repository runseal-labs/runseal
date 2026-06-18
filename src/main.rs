mod audit;
mod backend;
mod policy;
mod windows_plan;

use audit::AuditWriter;
use backend::{
    BackendError, ExecutionEnv, ExecutionStdin, SandboxBackend, active_backend,
    matches_environment_scrub_pattern,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use policy::{NetworkMode, POLICY_VERSION, PolicyError, SandboxPolicy, normalize_policy};
use serde_json::{Map, Value, json};
use std::env;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const PROTOCOL_VERSION: &str = "runseal.protocol/v1";
const MAX_METADATA_BYTES: usize = 4096;
const STDIN_BASE64_PREFIX: &str = "base64:";
const MAX_STDIN_BYTES: usize = 64 * 1024;
const MAX_STDIN_DATA_BYTES: usize = STDIN_BASE64_PREFIX.len() + 4 * MAX_STDIN_BYTES.div_ceil(3);
const MAX_ENV_ENTRIES: usize = 64;
const MAX_ENV_KEY_BYTES: usize = 128;
const MAX_ENV_VALUE_BYTES: usize = 4096;

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
        [command] if command == "capabilities" => {
            println!("{}", active_backend().capabilities_json());
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
        "getCapabilities" => vec![rpc_result(id, active_backend().capabilities_json())],
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
        "getExecution" | "cancelExecution" | "subscribeEvents" => {
            match execution_not_found_from_params(&params) {
                Ok(result) => vec![rpc_result(id, result)],
                Err(err) => vec![rpc_error(id, err)],
            }
        }
        "disposeSession" => match dispose_session_from_params(&params) {
            Ok(result) => vec![rpc_result(id, result)],
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
    let mut data = json!({
        "code": err.code,
        "reason": err.reason,
    });
    if let (Some(data), Some(details)) = (data.as_object_mut(), err.details) {
        data.extend(details.as_object().cloned().unwrap_or_default());
    }

    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32000,
            "message": err.message,
            "data": data
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
    let (events, result) = execute_command(
        &request.command,
        &request.cwd,
        &policy,
        ExecutionStdin::Empty,
        ExecutionEnv::default(),
        None,
        request.timeout,
    )
    .map_err(|err| err.message)?;

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
    let mut timeout = None;
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
            "--timeout-ms" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--timeout-ms requires a value".to_string())?;
                timeout = Some(parse_timeout_ms(value)?);
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
                    timeout,
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

fn parse_timeout_ms(value: &str) -> Result<Duration, String> {
    let timeout_ms = value
        .parse::<u64>()
        .map_err(|_| format!("timeout must be an integer in milliseconds, got {value}"))?;
    Ok(Duration::from_millis(timeout_ms))
}

fn explain_policy_from_params(params: &Value) -> Result<Value, RunSealError> {
    let params = params_object(params, "explainPolicy")?;
    validate_param_keys(
        params,
        "explainPolicy",
        &["policy", "cwd", "network", "network_mode"],
    )?;
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
    let params = params_object(params, "execute")?;
    validate_param_keys(
        params,
        "execute",
        &[
            "command",
            "cwd",
            "policy",
            "network",
            "network_mode",
            "stdin",
            "timeout_ms",
            "metadata",
            "env",
        ],
    )?;
    let stdin = stdin_from_params(params)?;
    let timeout = timeout_from_params(params)?;
    let metadata = metadata_from_params(params)?;
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
    let env = env_from_params(params, &policy)?;

    execute_command(&command, &cwd, &policy, stdin, env, metadata, timeout)
}

fn execution_not_found_from_params(params: &Value) -> Result<Value, RunSealError> {
    let params = params_object(params, "execution lookup")?;
    validate_param_keys(params, "execution lookup", &["execution_id"])?;
    let execution_id = required_string_param(params, "execution_id")?;

    Err(RunSealError::with_details(
        "EXECUTION_NOT_FOUND",
        format!("execution not found: {execution_id}"),
        json!({
            "execution_id": execution_id,
        }),
    ))
}

fn dispose_session_from_params(params: &Value) -> Result<Value, RunSealError> {
    let params = params_object(params, "disposeSession")?;
    validate_param_keys(params, "disposeSession", &["session_id"])?;
    let session_id = required_string_param(params, "session_id")?;

    Ok(json!({
        "session_id": session_id,
        "status": "disposed",
    }))
}

fn params_object<'a>(
    params: &'a Value,
    method: &'static str,
) -> Result<&'a Map<String, Value>, RunSealError> {
    params.as_object().ok_or_else(|| {
        RunSealError::new(
            "INVALID_REQUEST",
            format!("{method} params must be an object"),
        )
    })
}

fn validate_param_keys(
    params: &Map<String, Value>,
    method: &'static str,
    allowed_keys: &[&'static str],
) -> Result<(), RunSealError> {
    for key in params.keys() {
        if !allowed_keys.contains(&key.as_str()) {
            return Err(RunSealError::new(
                "INVALID_REQUEST",
                format!("params.{key} is not supported by {method}"),
            ));
        }
    }
    Ok(())
}

fn required_string_param(
    params: &Map<String, Value>,
    field: &'static str,
) -> Result<String, RunSealError> {
    params
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| RunSealError::new("INVALID_REQUEST", format!("params.{field} is required")))
}

fn network_override_from_params(
    params: &Map<String, Value>,
) -> Result<Option<NetworkMode>, RunSealError> {
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

fn timeout_from_params(params: &Map<String, Value>) -> Result<Option<Duration>, RunSealError> {
    let Some(value) = params.get("timeout_ms") else {
        return Ok(None);
    };
    let timeout_ms = value.as_u64().ok_or_else(|| {
        RunSealError::new("INVALID_REQUEST", "params.timeout_ms must be an integer")
    })?;

    Ok(Some(Duration::from_millis(timeout_ms)))
}

fn stdin_from_params(params: &Map<String, Value>) -> Result<ExecutionStdin, RunSealError> {
    let Some(value) = params.get("stdin") else {
        return Ok(ExecutionStdin::Empty);
    };
    let stdin = value
        .as_object()
        .ok_or_else(|| RunSealError::new("INVALID_REQUEST", "params.stdin must be an object"))?;
    let mode = stdin
        .get("mode")
        .and_then(Value::as_str)
        .ok_or_else(|| RunSealError::new("INVALID_REQUEST", "params.stdin.mode is required"))?;

    match mode {
        "empty" => {
            validate_param_keys(stdin, "execute stdin", &["mode"])?;
            Ok(ExecutionStdin::Empty)
        }
        "bytes" => stdin_bytes_from_params(stdin),
        "inherit" | "stream" => Err(RunSealError::new(
            "INVALID_REQUEST",
            format!("params.stdin.mode={mode} is not supported by execute"),
        )),
        _ => Err(RunSealError::new(
            "INVALID_REQUEST",
            format!("params.stdin.mode must be empty, got {mode}"),
        )),
    }
}

fn stdin_bytes_from_params(stdin: &Map<String, Value>) -> Result<ExecutionStdin, RunSealError> {
    validate_param_keys(stdin, "execute stdin", &["mode", "data", "encoding"])?;
    let encoding = stdin
        .get("encoding")
        .and_then(Value::as_str)
        .ok_or_else(|| RunSealError::new("INVALID_REQUEST", "params.stdin.encoding is required"))?;
    if encoding != "base64" {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            "params.stdin.encoding must be base64",
        ));
    }
    let data = stdin
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| RunSealError::new("INVALID_REQUEST", "params.stdin.data is required"))?;
    if data.len() > MAX_STDIN_DATA_BYTES {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            format!("params.stdin.data must decode to at most {MAX_STDIN_BYTES} bytes"),
        ));
    }
    let encoded = data.strip_prefix(STDIN_BASE64_PREFIX).ok_or_else(|| {
        RunSealError::new(
            "INVALID_REQUEST",
            "params.stdin.data must use base64: prefix",
        )
    })?;
    let bytes = STANDARD.decode(encoded).map_err(|err| {
        RunSealError::new(
            "INVALID_REQUEST",
            format!("params.stdin.data must be valid base64: {err}"),
        )
    })?;
    if bytes.len() > MAX_STDIN_BYTES {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            format!("params.stdin.data must decode to at most {MAX_STDIN_BYTES} bytes"),
        ));
    }

    Ok(ExecutionStdin::Bytes(bytes))
}

fn stdin_audit_json(stdin: &ExecutionStdin) -> Value {
    match stdin {
        ExecutionStdin::Empty => json!({
            "mode": "empty",
            "byte_count": 0,
        }),
        ExecutionStdin::Bytes(bytes) => json!({
            "mode": "bytes",
            "byte_count": bytes.len(),
        }),
    }
}

fn metadata_from_params(params: &Map<String, Value>) -> Result<Option<Value>, RunSealError> {
    let Some(metadata) = params.get("metadata") else {
        return Ok(None);
    };
    let Some(object) = metadata.as_object() else {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            "params.metadata must be an object",
        ));
    };
    let metadata = Value::Object(object.clone());
    let metadata_len = serde_json::to_vec(&metadata)
        .map_err(|err| {
            RunSealError::new(
                "INVALID_REQUEST",
                format!("params.metadata could not be serialized: {err}"),
            )
        })?
        .len();
    if metadata_len > MAX_METADATA_BYTES {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            format!("params.metadata must be at most {MAX_METADATA_BYTES} bytes"),
        ));
    }

    Ok(Some(metadata))
}

fn env_from_params(
    params: &Map<String, Value>,
    policy: &SandboxPolicy,
) -> Result<ExecutionEnv, RunSealError> {
    let Some(value) = params.get("env") else {
        return Ok(ExecutionEnv::default());
    };
    let env = value
        .as_object()
        .ok_or_else(|| RunSealError::new("INVALID_REQUEST", "params.env must be an object"))?;
    if env.len() > MAX_ENV_ENTRIES {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            format!("params.env must include at most {MAX_ENV_ENTRIES} entries"),
        ));
    }

    let mut entries = Vec::with_capacity(env.len());
    for (key, value) in env {
        validate_env_key(key)?;
        if policy
            .environment
            .scrub
            .iter()
            .any(|pattern| matches_environment_scrub_pattern(key, pattern))
        {
            return Err(RunSealError::new(
                "INVALID_REQUEST",
                format!("params.env.{key} is denied by policy environment scrub"),
            ));
        }
        let value = value.as_str().ok_or_else(|| {
            RunSealError::new(
                "INVALID_REQUEST",
                format!("params.env.{key} must be a string"),
            )
        })?;
        if value.len() > MAX_ENV_VALUE_BYTES {
            return Err(RunSealError::new(
                "INVALID_REQUEST",
                format!("params.env.{key} must be at most {MAX_ENV_VALUE_BYTES} bytes"),
            ));
        }
        entries.push((key.clone(), value.to_string()));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    Ok(ExecutionEnv { entries })
}

fn validate_env_key(key: &str) -> Result<(), RunSealError> {
    if key.is_empty() || key.len() > MAX_ENV_KEY_BYTES {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            format!("params.env.{key} is not a valid environment variable name"),
        ));
    }

    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            "params.env key is not a valid environment variable name",
        ));
    };
    if !(first == '_' || first.is_ascii_alphabetic())
        || chars.any(|item| !(item == '_' || item.is_ascii_alphanumeric()))
    {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            format!("params.env.{key} is not a valid environment variable name"),
        ));
    }

    Ok(())
}

fn execute_command(
    command: &[String],
    cwd: &Path,
    policy: &SandboxPolicy,
    stdin: ExecutionStdin,
    env: ExecutionEnv,
    metadata: Option<Value>,
    timeout: Option<Duration>,
) -> Result<(Vec<Value>, Value), RunSealError> {
    if command.is_empty() {
        return Err(RunSealError::new("INVALID_REQUEST", "command is empty"));
    }

    let ids = new_execution_ids();
    let policy_id = policy.id.clone();
    let policy_hash = policy.hash();
    let stdin_audit = stdin_audit_json(&stdin);
    let env_keys = env.keys();
    let mut audit = create_audit_writer(cwd, &ids.session_id)?;
    let audit_path = audit.relative_path().to_string();
    let backend = active_backend();
    let event_context = ExecutionEventContext {
        ids: &ids,
        policy_id: &policy_id,
        policy_hash: &policy_hash,
        audit_path: &audit_path,
        backend: backend_event_json(backend.name(), backend.status(), backend.platform()),
    };

    if policy.denies_execution_without_backend() {
        let reason = "filesystem write denied by policy";
        let event = execution_event_now(
            json!({
                "type": "policy.denied",
                "execution_id": ids.execution_id,
                "policy_id": policy_id,
                "policy_hash": policy_hash,
                "audit_path": audit_path,
                "decision": "denied",
                "reason": reason,
            }),
            &event_context,
        );
        write_audit_event_with_metadata(&mut audit, &event, &metadata)?;

        return Err(RunSealError::with_details(
            "POLICY_DENIED",
            reason,
            json!({
                "execution_id": ids.execution_id,
                "session_id": ids.session_id,
                "seal_id": ids.seal_id,
                "audit_path": audit_path,
            }),
        ));
    }

    let plan = match backend.compile_plan(&ids.execution_id, cwd, policy) {
        Ok(plan) => plan,
        Err(err) => {
            let details = err.details_json();
            let mut prepared_setup = None;
            if let Some(plan) = err.plan.as_deref() {
                match plan.prepare_sandbox_setup() {
                    Ok(setup) => {
                        let event = execution_event_now(
                            json!({
                                "type": "sandbox.prepared",
                                "execution_id": ids.execution_id,
                                "policy_id": policy_id,
                                "policy_hash": policy_hash,
                                "audit_path": audit_path,
                                "decision": "prepared",
                                "prepared_roots": setup.prepared_roots(),
                                "platform_plan": plan.json(),
                            }),
                            &event_context,
                        );
                        write_audit_event_with_metadata(&mut audit, &event, &metadata)?;
                        prepared_setup = Some(setup);
                    }
                    Err(setup_err) => {
                        let event = execution_event_now(
                            json!({
                                "type": "sandbox.setup_failed",
                                "execution_id": ids.execution_id,
                                "policy_id": policy_id,
                                "policy_hash": policy_hash,
                                "audit_path": audit_path,
                                "decision": "failed",
                                "reason": setup_err.to_string(),
                                "platform_plan": plan.json(),
                            }),
                            &event_context,
                        );
                        write_audit_event_with_metadata(&mut audit, &event, &metadata)?;

                        let mut details = details;
                        if let Some(details) = details.as_object_mut() {
                            details.insert("execution_id".to_string(), json!(ids.execution_id));
                            details.insert("session_id".to_string(), json!(ids.session_id));
                            details.insert("seal_id".to_string(), json!(ids.seal_id));
                            details.insert("audit_path".to_string(), json!(audit_path));
                            details.insert("setup_error".to_string(), json!(setup_err.to_string()));
                        }

                        return Err(RunSealError::with_details(
                            "INTERNAL_ERROR",
                            "failed to prepare sandbox setup",
                            details,
                        ));
                    }
                }
            }

            let event = execution_event_now(
                json!({
                    "type": "sandbox.backend_capability",
                    "execution_id": ids.execution_id,
                    "policy_id": policy_id,
                    "policy_hash": policy_hash,
                    "audit_path": audit_path,
                    "decision": "unsupported",
                    "reason": err.reason,
                    "backend": details.get("backend").cloned().unwrap_or_else(|| json!({})),
                    "support": details.get("support").cloned().unwrap_or_else(|| json!("unsupported")),
                    "missing_features": details.get("missing_features").cloned().unwrap_or_else(|| json!([])),
                    "platform_plan": details.get("platform_plan").cloned().unwrap_or(Value::Null),
                }),
                &event_context,
            );
            write_audit_event_with_metadata(&mut audit, &event, &metadata)?;

            if let (Some(plan), Some(setup)) = (err.plan.as_deref(), prepared_setup) {
                match setup.cleanup(plan) {
                    Ok(cleaned_roots) => {
                        let event = execution_event_now(
                            json!({
                                "type": "sandbox.cleaned",
                                "execution_id": ids.execution_id,
                                "policy_id": policy_id,
                                "policy_hash": policy_hash,
                                "audit_path": audit_path,
                                "decision": "cleaned",
                                "cleaned_roots": cleaned_roots,
                                "platform_plan": plan.json(),
                            }),
                            &event_context,
                        );
                        write_audit_event_with_metadata(&mut audit, &event, &metadata)?;
                    }
                    Err(cleanup_err) => {
                        let event = execution_event_now(
                            json!({
                                "type": "sandbox.cleanup_failed",
                                "execution_id": ids.execution_id,
                                "policy_id": policy_id,
                                "policy_hash": policy_hash,
                                "audit_path": audit_path,
                                "decision": "failed",
                                "reason": cleanup_err.to_string(),
                                "platform_plan": plan.json(),
                            }),
                            &event_context,
                        );
                        write_audit_event_with_metadata(&mut audit, &event, &metadata)?;

                        let mut details = details;
                        if let Some(details) = details.as_object_mut() {
                            details.insert("execution_id".to_string(), json!(ids.execution_id));
                            details.insert("session_id".to_string(), json!(ids.session_id));
                            details.insert("seal_id".to_string(), json!(ids.seal_id));
                            details.insert("audit_path".to_string(), json!(audit_path));
                            details.insert(
                                "cleanup_error".to_string(),
                                json!(cleanup_err.to_string()),
                            );
                        }

                        return Err(RunSealError::with_details(
                            "INTERNAL_ERROR",
                            "failed to clean sandbox runtime roots",
                            details,
                        ));
                    }
                }
            }

            let mut details = details;
            if let Some(details) = details.as_object_mut() {
                details.insert("execution_id".to_string(), json!(ids.execution_id));
                details.insert("session_id".to_string(), json!(ids.session_id));
                details.insert("seal_id".to_string(), json!(ids.seal_id));
                details.insert("audit_path".to_string(), json!(audit_path));
            }

            return Err(RunSealError::with_details(err.code, err.reason, details));
        }
    };

    let sandbox_enforced = plan.is_sandbox_enforced();
    let started_at = timestamp_now();
    let started = execution_event_at(
        json!({
            "type": "execution.started",
            "execution_id": ids.execution_id,
            "policy_id": policy_id,
            "policy_hash": policy_hash,
            "audit_path": audit_path,
            "sandbox": {
                "level": policy.sandbox_level.as_str(),
                "enforced": sandbox_enforced,
            },
            "network": {
                "mode": policy.network.mode.as_str(),
            },
            "backend": {
                "name": plan.backend,
                "status": plan.backend_status,
                "platform": plan.platform,
            },
            "platform_plan": plan.json(),
            "stdin": stdin_audit,
            "environment": {
                "requested_keys": env_keys,
            },
        }),
        &started_at,
        &event_context,
    );
    write_audit_event_with_metadata(&mut audit, &started, &metadata)?;

    let timer = Instant::now();
    let execution_output = backend
        .execute_plan(&plan, command, cwd, stdin, &env, timeout)
        .map_err(|err| {
            RunSealError::new(
                "EXECUTION_FAILED_TO_START",
                format!("failed to spawn command {}: {err}", command[0]),
            )
        })?;
    let output = execution_output.output;
    let duration_ms = timer.elapsed().as_millis() as u64;
    if execution_output.timed_out {
        let timeout_ms = timeout.map(|duration| duration.as_millis() as u64);
        let failed = execution_event_now(
            json!({
                "type": "execution.failed",
                "execution_id": ids.execution_id,
                "policy_id": policy_id,
                "policy_hash": policy_hash,
                "audit_path": audit_path,
                "status": "failed",
                "reason": "execution timed out",
                "timeout_ms": timeout_ms,
                "duration_ms": duration_ms,
            }),
            &event_context,
        );
        write_audit_event_with_metadata(&mut audit, &failed, &metadata)?;

        return Err(RunSealError::with_details(
            "EXECUTION_TIMEOUT",
            "execution timed out",
            json!({
                "execution_id": ids.execution_id,
                "session_id": ids.session_id,
                "seal_id": ids.seal_id,
                "audit_path": audit_path,
                "timeout_ms": timeout_ms,
                "stdout_bytes": output.stdout.len(),
                "stderr_bytes": output.stderr.len(),
            }),
        ));
    }
    let mut events = vec![started];
    if !output.stdout.is_empty() {
        let event = stream_event("execution.stdout", &event_context, &output.stdout, 0);
        write_audit_event_with_metadata(&mut audit, &event, &metadata)?;
        events.push(event);
    }
    if !output.stderr.is_empty() {
        let event = stream_event("execution.stderr", &event_context, &output.stderr, 0);
        write_audit_event_with_metadata(&mut audit, &event, &metadata)?;
        events.push(event);
    }
    let exit_code = output.status.code().unwrap_or(1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let finished_at = timestamp_now();
    let finished = execution_event_at(
        json!({
            "type": "execution.finished",
            "execution_id": ids.execution_id,
            "exit_code": exit_code,
            "status": "finished",
        }),
        &finished_at,
        &event_context,
    );
    write_audit_event_with_metadata(&mut audit, &finished, &metadata)?;
    events.push(finished);

    let result = json!({
        "execution_id": ids.execution_id,
        "session_id": ids.session_id,
        "seal_id": ids.seal_id,
        "status": "finished",
        "exit_code": exit_code,
        "signal": null,
        "started_at": started_at,
        "finished_at": finished_at,
        "policy_id": policy_id,
        "policy_hash": policy_hash,
        "audit_path": audit_path,
        "sandbox": {
            "level": policy.sandbox_level.as_str(),
            "enforced": sandbox_enforced,
        },
        "network": {
            "mode": policy.network.mode.as_str(),
        },
        "backend": {
            "name": plan.backend,
            "status": plan.backend_status,
            "platform": plan.platform,
        },
        "platform_plan": plan.json(),
        "stdout_bytes": output.stdout.len(),
        "stderr_bytes": output.stderr.len(),
        "output_truncated": false,
        "stdout": stdout,
        "stderr": stderr,
        "resource_usage": {
            "duration_ms": duration_ms,
        }
    });

    Ok((events, result))
}

fn stream_event(
    event_type: &'static str,
    context: &ExecutionEventContext<'_>,
    bytes: &[u8],
    offset: u64,
) -> Value {
    let encoded = STANDARD.encode(bytes);
    execution_event_now(
        json!({
            "type": event_type,
            "execution_id": context.ids.execution_id,
            "data": format!("base64:{encoded}"),
            "encoding": "base64",
            "stream_offset": offset,
            "bytes": bytes.len(),
        }),
        context,
    )
}

fn execution_event_now(event: Value, context: &ExecutionEventContext<'_>) -> Value {
    let time = timestamp_now();
    execution_event_at(event, &time, context)
}

fn execution_event_at(event: Value, time: &str, context: &ExecutionEventContext<'_>) -> Value {
    let mut event = event_at(event, time);
    if let Some(object) = event.as_object_mut() {
        object
            .entry("execution_id")
            .or_insert_with(|| json!(context.ids.execution_id));
        object
            .entry("session_id")
            .or_insert_with(|| json!(context.ids.session_id));
        object
            .entry("seal_id")
            .or_insert_with(|| json!(context.ids.seal_id));
        object
            .entry("policy_id")
            .or_insert_with(|| json!(context.policy_id));
        object
            .entry("policy_hash")
            .or_insert_with(|| json!(context.policy_hash));
        object
            .entry("audit_path")
            .or_insert_with(|| json!(context.audit_path));
        object
            .entry("backend")
            .or_insert_with(|| context.backend.clone());
    }
    event
}

fn backend_event_json(name: &str, status: &str, platform: &str) -> Value {
    json!({
        "name": name,
        "status": status,
        "platform": platform,
    })
}

fn event_at(mut event: Value, time: &str) -> Value {
    if let Some(object) = event.as_object_mut() {
        object.insert("time".to_string(), json!(time));
    }
    event
}

fn timestamp_now() -> String {
    match OffsetDateTime::now_utc().format(&Rfc3339) {
        Ok(timestamp) => timestamp,
        Err(_) => "1970-01-01T00:00:00Z".to_string(),
    }
}

fn create_audit_writer(cwd: &Path, session_id: &str) -> Result<AuditWriter, RunSealError> {
    AuditWriter::create(cwd, session_id).map_err(|err| {
        RunSealError::new(
            "INTERNAL_ERROR",
            format!("failed to create audit writer: {err}"),
        )
    })
}

fn write_audit_event(audit: &mut AuditWriter, event: &Value) -> Result<(), RunSealError> {
    audit.write_event(event).map_err(|err| {
        RunSealError::new(
            "INTERNAL_ERROR",
            format!("failed to write audit event: {err}"),
        )
    })
}

fn write_audit_event_with_metadata(
    audit: &mut AuditWriter,
    event: &Value,
    metadata: &Option<Value>,
) -> Result<(), RunSealError> {
    let Some(metadata) = metadata else {
        return write_audit_event(audit, event);
    };

    let mut audit_event = event.clone();
    if let Some(object) = audit_event.as_object_mut() {
        object.insert("metadata".to_string(), metadata.clone());
    }
    write_audit_event(audit, &audit_event)
}

#[derive(Debug)]
struct ExecutionIds {
    execution_id: String,
    session_id: String,
    seal_id: String,
}

#[derive(Debug)]
struct ExecutionEventContext<'a> {
    ids: &'a ExecutionIds,
    policy_id: &'a str,
    policy_hash: &'a str,
    audit_path: &'a str,
    backend: Value,
}

fn new_execution_ids() -> ExecutionIds {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    ExecutionIds {
        execution_id: format!("exec_{millis:x}"),
        session_id: format!("sess_{millis:x}"),
        seal_id: format!("seal_{millis:x}"),
    }
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
    timeout: Option<Duration>,
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
    details: Option<Value>,
}

impl RunSealError {
    fn new(code: impl Into<String>, reason: impl Into<String>) -> Self {
        let code = code.into();
        let reason = reason.into();
        Self {
            message: reason.clone(),
            code,
            reason,
            details: None,
        }
    }

    fn with_details(code: impl Into<String>, reason: impl Into<String>, details: Value) -> Self {
        let code = code.into();
        let reason = reason.into();
        Self {
            message: reason.clone(),
            code,
            reason,
            details: Some(details),
        }
    }
}

impl From<PolicyError> for RunSealError {
    fn from(err: PolicyError) -> Self {
        Self::new(err.code, err.reason)
    }
}

impl From<BackendError> for RunSealError {
    fn from(err: BackendError) -> Self {
        let details = err.details_json();
        Self::with_details(err.code, err.reason, details)
    }
}
