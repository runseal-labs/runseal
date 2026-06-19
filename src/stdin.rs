use crate::backend::ExecutionStdin;
use crate::error::RunSealError;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Map, Value, json};
use std::fs;
use std::path::{Path, PathBuf};

const STDIN_BASE64_PREFIX: &str = "base64:";
const MAX_STDIN_BYTES: usize = 64 * 1024;
const MAX_STDIN_DATA_BYTES: usize = STDIN_BASE64_PREFIX.len() + 4 * MAX_STDIN_BYTES.div_ceil(3);
const MAX_STDIN_FILE_BYTES: u64 = 16 * 1024 * 1024;

pub(crate) fn stdin_from_params(
    params: &Map<String, Value>,
    cwd: &Path,
) -> Result<ExecutionStdin, RunSealError> {
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
            validate_stdin_keys(stdin, &["mode"])?;
            Ok(ExecutionStdin::Empty)
        }
        "bytes" => stdin_bytes_from_params(stdin),
        "file" => stdin_file_from_params(stdin, cwd),
        "inherit" | "stream" => Err(RunSealError::new(
            "INVALID_REQUEST",
            format!("params.stdin.mode={mode} is not supported by execute"),
        )),
        _ => Err(RunSealError::new(
            "INVALID_REQUEST",
            format!("params.stdin.mode must be empty, bytes, or file, got {mode}"),
        )),
    }
}

fn stdin_bytes_from_params(stdin: &Map<String, Value>) -> Result<ExecutionStdin, RunSealError> {
    validate_stdin_keys(stdin, &["mode", "data", "encoding"])?;
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

fn stdin_file_from_params(
    stdin: &Map<String, Value>,
    cwd: &Path,
) -> Result<ExecutionStdin, RunSealError> {
    validate_stdin_keys(stdin, &["mode", "path"])?;
    let raw_path = stdin
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| RunSealError::new("INVALID_REQUEST", "params.stdin.path is required"))?;
    if raw_path.is_empty() {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            "params.stdin.path must not be empty",
        ));
    }

    let requested = PathBuf::from(raw_path);
    let path = if requested.is_absolute() {
        requested
    } else {
        cwd.join(requested)
    };
    let cwd = fs::canonicalize(cwd).map_err(|err| {
        RunSealError::new(
            "INVALID_REQUEST",
            format!("params.cwd must be an existing directory: {err}"),
        )
    })?;
    let path = fs::canonicalize(&path).map_err(|err| {
        RunSealError::new(
            "INVALID_REQUEST",
            format!("params.stdin.path must be an existing file under params.cwd: {err}"),
        )
    })?;
    if !path.starts_with(&cwd) {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            "params.stdin.path must be under params.cwd",
        ));
    }

    let metadata = fs::metadata(&path).map_err(|err| {
        RunSealError::new(
            "INVALID_REQUEST",
            format!("params.stdin.path must be readable: {err}"),
        )
    })?;
    if !metadata.is_file() {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            "params.stdin.path must be a regular file",
        ));
    }
    if metadata.len() > MAX_STDIN_FILE_BYTES {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            format!("params.stdin.path must be at most {MAX_STDIN_FILE_BYTES} bytes"),
        ));
    }
    let bytes = fs::read(&path).map_err(|err| {
        RunSealError::new(
            "INVALID_REQUEST",
            format!("params.stdin.path must be readable: {err}"),
        )
    })?;
    if bytes.len() as u64 > MAX_STDIN_FILE_BYTES {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            format!("params.stdin.path must be at most {MAX_STDIN_FILE_BYTES} bytes"),
        ));
    }
    Ok(ExecutionStdin::File(bytes))
}

fn validate_stdin_keys(stdin: &Map<String, Value>, allowed: &[&str]) -> Result<(), RunSealError> {
    for key in stdin.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(RunSealError::new(
                "INVALID_REQUEST",
                format!("params.{key} is not supported by execute stdin"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn stdin_audit_json(stdin: &ExecutionStdin) -> Value {
    match stdin {
        ExecutionStdin::Empty => json!({
            "mode": "empty",
            "byte_count": 0,
        }),
        ExecutionStdin::Bytes(bytes) => json!({
            "mode": "bytes",
            "byte_count": bytes.len(),
        }),
        ExecutionStdin::File(bytes) => json!({
            "mode": "file",
            "byte_count": bytes.len(),
        }),
    }
}
