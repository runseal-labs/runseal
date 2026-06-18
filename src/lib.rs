mod audit;
mod backend;
mod cli;
mod error;
mod events;
mod policy;
mod rpc;
mod stdin;
mod windows;

use audit::{create_audit_writer, write_audit_event_with_metadata};
use backend::{
    ExecutionEnv, ExecutionStdin, SandboxBackend, active_backend, backend_unavailable_reason,
};
use cli::{parse_exec_args, parse_policy_args};
use error::RunSealError;
use events::{
    ExecutionEventContext, backend_event_json, execution_event_at, execution_event_now,
    new_execution_ids, stream_event, timestamp_now,
};
use policy::{
    NetworkMode, POLICY_VERSION, SandboxPolicy, matches_environment_scrub_pattern, normalize_policy,
};
use serde_json::{Map, Value, json};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, Instant};
use stdin::{stdin_audit_json, stdin_from_params};

const PROTOCOL_VERSION: &str = "runseal.protocol/v1";
const MAX_METADATA_BYTES: usize = 4096;
const MAX_ENV_ENTRIES: usize = 64;
const MAX_ENV_KEY_BYTES: usize = 128;
const MAX_ENV_VALUE_BYTES: usize = 4096;
const WINDOWS_SANDBOX_SETUP_FAILED: &str =
    "windows sandbox setup failed; run from an elevated shell";
const HELP_TEXT: &str = "\
Usage: runseal <command> [options]

Commands:
  exec --policy <policy> [--network <mode>] [--cwd <path>] -- <command> [args...]
  explain-policy --policy <policy> [--network <mode>] [--cwd <path>]
  capabilities
  setup windows-sandbox [--cwd <path>]
  rpc --stdio
  version
";
const SETUP_HELP_TEXT: &str = "\
Usage: runseal setup windows-sandbox [--cwd <path>]

Windows sandbox setup:
  Run from an elevated PowerShell to install or repair the sandbox broker.
  Sandboxed exec fails closed when setup is missing or stale.
";

pub fn run_cli() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [flag] if flag == "--help" || flag == "-h" => {
            print!("{HELP_TEXT}");
            Ok(())
        }
        [command] if command == "help" => {
            print!("{HELP_TEXT}");
            Ok(())
        }
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
        [command, rest @ ..] if command == "setup" => run_setup(rest),
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
        "getVersion" => vec![rpc::result(id, version_payload())],
        "getCapabilities" => vec![rpc::result(id, active_backend().capabilities_json())],
        "explainPolicy" => match explain_policy_from_params(&params) {
            Ok(result) => vec![rpc::result(id, result)],
            Err(err) => vec![rpc::error(id, err)],
        },
        "execute" => match execute_from_params(&params) {
            Ok((events, result)) => {
                let mut messages: Vec<Value> = events
                    .into_iter()
                    .map(|event| json!({"jsonrpc": "2.0", "method": "event", "params": event}))
                    .collect();
                messages.push(rpc::result(id, result));
                messages
            }
            Err(err) => vec![rpc::error(id, err)],
        },
        "getExecution" | "cancelExecution" | "subscribeEvents" => {
            match execution_not_found_from_params(&params) {
                Ok(result) => vec![rpc::result(id, result)],
                Err(err) => vec![rpc::error(id, err)],
            }
        }
        "disposeSession" => match dispose_session_from_params(&params) {
            Ok(result) => vec![rpc::result(id, result)],
            Err(err) => vec![rpc::error(id, err)],
        },
        _ => vec![rpc::error(
            id,
            RunSealError::new("INVALID_REQUEST", format!("unknown method: {method}")),
        )],
    }
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

fn run_setup(args: &[String]) -> Result<(), String> {
    match args {
        [flag] if flag == "--help" || flag == "-h" => {
            print!("{SETUP_HELP_TEXT}");
            Ok(())
        }
        [target] if target == "windows-sandbox" => run_windows_sandbox_setup(&current_dir()),
        [target, flag] if target == "windows-sandbox" && (flag == "--help" || flag == "-h") => {
            print!("{SETUP_HELP_TEXT}");
            Ok(())
        }
        [target, flag, cwd] if target == "windows-sandbox" && flag == "--cwd" => {
            run_windows_sandbox_setup(&PathBuf::from(cwd))
        }
        _ => Err("usage: runseal setup windows-sandbox [--cwd <path>]".to_string()),
    }
}

#[cfg(windows)]
fn run_windows_sandbox_setup(cwd: &Path) -> Result<(), String> {
    validate_execution_cwd(cwd).map_err(|err| err.message)?;
    let sandbox_home = backend::windows_sandbox_home(cwd);
    let real_user = env::var("USERNAME").unwrap_or_else(|_| "Administrators".to_string());
    codex_windows_sandbox::run_elevated_provisioning_setup(&sandbox_home, &real_user)
        .map_err(|_| WINDOWS_SANDBOX_SETUP_FAILED.to_string())?;
    println!(
        "{}",
        json!({
            "status": "ok",
            "setup": "windows-sandbox",
            "sandbox_home": sandbox_home.to_string_lossy(),
        })
    );
    Ok(())
}

#[cfg(not(windows))]
fn run_windows_sandbox_setup(_cwd: &Path) -> Result<(), String> {
    Err("windows sandbox setup is only supported on Windows".to_string())
}

fn run_explain_policy(args: &[String]) -> Result<(), String> {
    let request = parse_policy_args(args)?;
    let policy = normalize_policy(
        &Value::String(request.policy.clone()),
        &request.cwd,
        request.network,
    )
    .map_err(|err| err.reason)?;

    println!("{}", explain_policy_json(&policy));
    Ok(())
}

fn explain_policy_json(policy: &SandboxPolicy) -> Value {
    let backend = active_backend();
    let missing_features = backend.missing_feature_names(policy);
    let mut result = policy.explain_json();
    if let Some(result) = result.as_object_mut() {
        result.insert(
            "support".to_string(),
            json!(if missing_features.is_empty() {
                "supported"
            } else {
                "unsupported"
            }),
        );
        result.insert("missing_features".to_string(), json!(missing_features));
    }
    result
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

    Ok(explain_policy_json(&policy))
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
    let timeout = timeout_from_params(params, &policy)?;
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

fn timeout_from_params(
    params: &Map<String, Value>,
    policy: &SandboxPolicy,
) -> Result<Option<Duration>, RunSealError> {
    let requested_timeout = match params.get("timeout_ms") {
        Some(value) => Some(value.as_u64().ok_or_else(|| {
            RunSealError::new("INVALID_REQUEST", "params.timeout_ms must be an integer")
        })?),
        None => None,
    };
    let timeout_ms = match (requested_timeout, policy.resources.timeout_ms) {
        (Some(requested), Some(limit)) if requested > limit => {
            return Err(RunSealError::new(
                "INVALID_REQUEST",
                "params.timeout_ms exceeds policy resources.timeout_ms",
            ));
        }
        (Some(requested), _) => Some(requested),
        (None, policy_timeout) => policy_timeout,
    };

    Ok(timeout_ms.map(Duration::from_millis))
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
    let mut entries = policy.environment.set.clone();
    let Some(value) = params.get("env") else {
        return Ok(ExecutionEnv { entries });
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
        upsert_env_entry(&mut entries, key.clone(), value.to_string());
    }
    if entries.len() > MAX_ENV_ENTRIES {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            format!(
                "environment.set and params.env must include at most {MAX_ENV_ENTRIES} combined entries"
            ),
        ));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    Ok(ExecutionEnv { entries })
}

fn upsert_env_entry(entries: &mut Vec<(String, String)>, key: String, value: String) {
    if let Some((_, existing_value)) = entries
        .iter_mut()
        .find(|(existing_key, _)| existing_key == &key)
    {
        *existing_value = value;
    } else {
        entries.push((key, value));
    }
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
    validate_execution_cwd(cwd)?;

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

    let requested = execution_event_now(
        json!({
            "type": "execution.requested",
            "decision": "requested",
            "command_args": command.len(),
        }),
        &event_context,
    );
    write_audit_event_with_metadata(&mut audit, &requested, &metadata)?;
    let resolved = execution_event_now(
        json!({
            "type": "policy.resolved",
            "decision": "resolved",
            "sandbox_level": policy.sandbox_level.as_str(),
            "network": {
                "mode": policy.network.mode.as_str(),
            },
            "backend_requirement": if policy.allows_local_execution() {
                "local-execution"
            } else {
                "sandbox-backend"
            },
            "required_backend_features": policy.required_backend_feature_names(),
        }),
        &event_context,
    );
    write_audit_event_with_metadata(&mut audit, &resolved, &metadata)?;

    if policy.requires_broad_write_approval() {
        let reason = "filesystem broad write requires approval";
        let event = execution_event_now(
            json!({
                "type": "policy.requires_approval",
                "execution_id": ids.execution_id,
                "policy_id": policy_id,
                "policy_hash": policy_hash,
                "audit_path": audit_path,
                "decision": "requires_approval",
                "reason": reason,
            }),
            &event_context,
        );
        write_audit_event_with_metadata(&mut audit, &event, &metadata)?;

        return Err(RunSealError::with_details(
            "APPROVAL_REQUIRED",
            reason,
            json!({
                "execution_id": ids.execution_id,
                "session_id": ids.session_id,
                "seal_id": ids.seal_id,
                "audit_path": audit_path,
            }),
        ));
    }

    if policy.denies_execution_without_backend() {
        let reason = "filesystem write denied by policy";
        let requires_approval = policy.approval.on_violation == "request";
        let event_type = if requires_approval {
            "policy.requires_approval"
        } else {
            "policy.denied"
        };
        let decision = if requires_approval {
            "requires_approval"
        } else {
            "denied"
        };
        let event = execution_event_now(
            json!({
                "type": event_type,
                "execution_id": ids.execution_id,
                "policy_id": policy_id,
                "policy_hash": policy_hash,
                "audit_path": audit_path,
                "decision": decision,
                "reason": reason,
            }),
            &event_context,
        );
        write_audit_event_with_metadata(&mut audit, &event, &metadata)?;

        return Err(RunSealError::with_details(
            if requires_approval {
                "APPROVAL_REQUIRED"
            } else {
                "POLICY_DENIED"
            },
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
                                "type": "sandbox.cleanup",
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
                                "type": "sandbox.cleanup",
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
    let allowed = execution_event_now(
        json!({
            "type": "policy.allowed",
            "decision": "allowed",
            "sandbox": {
                "level": policy.sandbox_level.as_str(),
                "enforced": sandbox_enforced,
            },
            "network": {
                "mode": policy.network.mode.as_str(),
            },
        }),
        &event_context,
    );
    write_audit_event_with_metadata(&mut audit, &allowed, &metadata)?;
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
    let execution_output = match backend.execute_plan(&plan, command, cwd, stdin, &env, timeout) {
        Ok(output) => output,
        Err(err) => {
            let unavailable_reason = if sandbox_enforced {
                backend_unavailable_reason(&err).map(str::to_string)
            } else {
                None
            };
            let failure_reason = unavailable_reason
                .as_deref()
                .unwrap_or("execution failed to start");
            let failed = execution_event_now(
                json!({
                    "type": "execution.failed",
                    "execution_id": ids.execution_id,
                    "policy_id": policy_id,
                    "policy_hash": policy_hash,
                    "audit_path": audit_path,
                    "status": "failed",
                    "reason": failure_reason,
                    "error": err.to_string(),
                }),
                &event_context,
            );
            write_audit_event_with_metadata(&mut audit, &failed, &metadata)?;

            if let Some(reason) = unavailable_reason {
                return Err(RunSealError::with_details(
                    "BACKEND_UNAVAILABLE",
                    reason,
                    json!({
                        "execution_id": ids.execution_id,
                        "session_id": ids.session_id,
                        "seal_id": ids.seal_id,
                        "audit_path": audit_path,
                        "backend": {
                            "name": plan.backend,
                            "status": plan.backend_status,
                            "platform": plan.platform,
                        },
                        "platform_plan": plan.json(),
                    }),
                ));
            }

            return Err(RunSealError::with_details(
                "EXECUTION_FAILED_TO_START",
                format!("failed to spawn command {}: {err}", command[0]),
                json!({
                    "execution_id": ids.execution_id,
                    "session_id": ids.session_id,
                    "seal_id": ids.seal_id,
                    "audit_path": audit_path,
                }),
            ));
        }
    };
    let mut output = execution_output.output;
    let output_truncated = truncate_output(&mut output, policy.resources.max_output_bytes);
    let duration_ms = timer.elapsed().as_millis() as u64;
    if execution_output.timed_out {
        let timeout_ms = timeout.map(|duration| duration.as_millis() as u64);
        let limit_exceeded = execution_event_now(
            json!({
                "type": "execution.resource.limit_exceeded",
                "decision": "limit_exceeded",
                "resource": "timeout_ms",
                "limit": timeout_ms,
                "duration_ms": duration_ms,
            }),
            &event_context,
        );
        write_audit_event_with_metadata(&mut audit, &limit_exceeded, &metadata)?;
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
    if output_truncated {
        let event = execution_event_now(
            json!({
                "type": "execution.output.truncated",
                "execution_id": ids.execution_id,
                "policy_id": policy_id,
                "policy_hash": policy_hash,
                "audit_path": audit_path,
                "decision": "truncated",
                "max_output_bytes": policy.resources.max_output_bytes,
                "stdout_bytes": output.stdout.len(),
                "stderr_bytes": output.stderr.len(),
            }),
            &event_context,
        );
        write_audit_event_with_metadata(&mut audit, &event, &metadata)?;
        events.push(event);
    }
    let exit_code = output.status.code().unwrap_or(1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let finished_at = timestamp_now();
    let resource_sample = execution_event_at(
        json!({
            "type": "execution.resource.sample",
            "duration_ms": duration_ms,
            "stdout_bytes": output.stdout.len(),
            "stderr_bytes": output.stderr.len(),
            "output_truncated": output_truncated,
        }),
        &finished_at,
        &event_context,
    );
    write_audit_event_with_metadata(&mut audit, &resource_sample, &metadata)?;
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
        "output_truncated": output_truncated,
        "stdout": stdout,
        "stderr": stderr,
        "resource_usage": {
            "duration_ms": duration_ms,
        }
    });

    Ok((events, result))
}

fn truncate_output(output: &mut Output, max_output_bytes: Option<u64>) -> bool {
    let Some(max_output_bytes) = max_output_bytes.and_then(|value| usize::try_from(value).ok())
    else {
        return false;
    };
    let original_stdout_len = output.stdout.len();
    let original_stderr_len = output.stderr.len();

    let stdout_len = output.stdout.len().min(max_output_bytes);
    output.stdout.truncate(stdout_len);
    let stderr_budget = max_output_bytes.saturating_sub(stdout_len);
    output
        .stderr
        .truncate(output.stderr.len().min(stderr_budget));

    output.stdout.len() != original_stdout_len || output.stderr.len() != original_stderr_len
}

fn validate_execution_cwd(cwd: &Path) -> Result<(), RunSealError> {
    let metadata = fs::symlink_metadata(cwd).map_err(|err| {
        RunSealError::new(
            "INVALID_REQUEST",
            format!("params.cwd must be an existing directory: {err}"),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            format!(
                "params.cwd must be an existing directory: {}",
                cwd.display()
            ),
        ));
    }

    Ok(())
}

fn current_dir() -> PathBuf {
    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn execution_ids_are_unique_for_fast_local_requests() {
        let mut execution_ids = HashSet::new();
        let mut session_ids = HashSet::new();
        let mut seal_ids = HashSet::new();

        for _ in 0..4096 {
            let ids = new_execution_ids();
            assert!(execution_ids.insert(ids.execution_id));
            assert!(session_ids.insert(ids.session_id));
            assert!(seal_ids.insert(ids.seal_id));
        }
    }

    #[test]
    fn windows_setup_failure_message_hides_vendor_codes() {
        assert!(!WINDOWS_SANDBOX_SETUP_FAILED.contains("orchestrator_"));
        assert!(!WINDOWS_SANDBOX_SETUP_FAILED.contains("helper_"));
    }
}
