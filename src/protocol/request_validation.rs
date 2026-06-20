use crate::backend::ExecutionEnv;
use crate::commands;
use crate::error::RunSealError;
use crate::execution::{current_dir, execute_command, normalize_execution_cwd};
use crate::policy::{
    NetworkMode, SandboxPolicy, matches_environment_scrub_pattern, normalize_policy,
};
use crate::stdin::stdin_from_params;
use crate::{
    MAX_ENV_ENTRIES, MAX_ENV_KEY_BYTES, MAX_ENV_VALUE_BYTES, MAX_METADATA_BYTES,
    MAX_PROTOCOL_ID_BYTES,
};
use serde_json::{Map, Value, json};
use std::path::PathBuf;
use std::time::Duration;

pub(crate) fn explain_policy_from_params(params: &Value) -> Result<Value, RunSealError> {
    let params = params_object(params, "explainPolicy")?;
    validate_param_keys(params, "explainPolicy", &["policy", "cwd", "network"])?;
    let cwd = params
        .get("cwd")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(current_dir);
    let cwd = normalize_execution_cwd(&cwd)?;
    let policy = params
        .get("policy")
        .cloned()
        .unwrap_or_else(|| json!("read-only"));
    let network = network_override_from_params(params)?;
    let policy = normalize_policy(&policy, &cwd, network)?;

    Ok(commands::explain_policy::explain_policy_json(&policy, &cwd))
}

pub(crate) fn setup_status_cwd_from_params(params: &Value) -> Result<PathBuf, RunSealError> {
    let params = params_object(params, "getSetupStatus")?;
    validate_param_keys(params, "getSetupStatus", &["cwd"])?;
    let cwd = params
        .get("cwd")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(current_dir);
    normalize_execution_cwd(&cwd)
}

pub(crate) fn execute_from_params(params: &Value) -> Result<(Vec<Value>, Value), RunSealError> {
    let params = params_object(params, "execute")?;
    validate_param_keys(
        params,
        "execute",
        &[
            "command",
            "cwd",
            "policy",
            "network",
            "stdin",
            "timeout_ms",
            "metadata",
            "env",
        ],
    )?;
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
    let cwd = normalize_execution_cwd(&cwd)?;
    let stdin = stdin_from_params(params, &cwd)?;
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

pub(crate) fn get_execution_id_from_params(params: &Value) -> Result<String, RunSealError> {
    let params = params_object(params, "getExecution")?;
    validate_param_keys(params, "getExecution", &["execution_id"])?;
    required_prefixed_string_param(params, "execution_id", "exec_")
}

pub(crate) fn cancel_execution_id_from_params(params: &Value) -> Result<String, RunSealError> {
    let params = params_object(params, "cancelExecution")?;
    validate_param_keys(params, "cancelExecution", &["execution_id", "reason"])?;
    validate_optional_lookup_params(params)?;
    required_prefixed_string_param(params, "execution_id", "exec_")
}

pub(crate) fn subscribe_events_params(
    params: &Value,
) -> Result<(String, Vec<String>), RunSealError> {
    let params = params_object(params, "subscribeEvents")?;
    validate_param_keys(params, "subscribeEvents", &["execution_id", "types"])?;
    validate_optional_lookup_params(params)?;
    let execution_id = required_prefixed_string_param(params, "execution_id", "exec_")?;
    let types = params
        .get("types")
        .and_then(Value::as_array)
        .map(|types| {
            types
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Ok((execution_id, types))
}

fn validate_optional_lookup_params(params: &Map<String, Value>) -> Result<(), RunSealError> {
    if let Some(reason) = params.get("reason") {
        reason
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                RunSealError::new(
                    "INVALID_REQUEST",
                    "params.reason must be a non-empty string",
                )
            })?;
    }
    if let Some(types) = params.get("types") {
        let types = types
            .as_array()
            .ok_or_else(|| RunSealError::new("INVALID_REQUEST", "params.types must be an array"))?;
        for event_type in types {
            event_type
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    RunSealError::new(
                        "INVALID_REQUEST",
                        "params.types entries must be non-empty strings",
                    )
                })?;
        }
    }
    Ok(())
}

pub(crate) fn session_id_from_params(params: &Value) -> Result<String, RunSealError> {
    let params = params_object(params, "disposeSession")?;
    validate_param_keys(params, "disposeSession", &["session_id"])?;
    required_prefixed_string_param(params, "session_id", "sess_")
}

pub(crate) fn validate_empty_params(
    params: &Value,
    method: &'static str,
) -> Result<(), RunSealError> {
    let params = params_object(params, method)?;
    validate_param_keys(params, method, &[])
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

fn required_prefixed_string_param(
    params: &Map<String, Value>,
    field: &'static str,
    prefix: &'static str,
) -> Result<String, RunSealError> {
    let value = required_string_param(params, field)?;
    if !value.starts_with(prefix) {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            format!("params.{field} must start with {prefix}"),
        ));
    }
    if value.len() == prefix.len() {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            format!("params.{field} must include an id suffix"),
        ));
    }
    if value.len() > MAX_PROTOCOL_ID_BYTES {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            format!("params.{field} must be at most {MAX_PROTOCOL_ID_BYTES} bytes"),
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            format!("params.{field} must contain only ASCII letters, digits, or _"),
        ));
    }
    Ok(value)
}

fn network_override_from_params(
    params: &Map<String, Value>,
) -> Result<Option<NetworkMode>, RunSealError> {
    let Some(value) = params.get("network") else {
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

pub(crate) fn duration_millis_u64(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
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
