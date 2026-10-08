use crate::policy::NetworkMode;
use std::env;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug)]
pub(crate) struct CliExecRequest {
    pub(crate) json: bool,
    pub(crate) events: bool,
    pub(crate) policy: String,
    pub(crate) network: Option<NetworkMode>,
    pub(crate) cwd: PathBuf,
    pub(crate) timeout: Option<Duration>,
    pub(crate) stdin_inherit: bool,
    pub(crate) pty: bool,
    pub(crate) control_fd3: bool,
    pub(crate) command: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct CliPolicyRequest {
    pub(crate) policy: String,
    pub(crate) network: Option<NetworkMode>,
    pub(crate) cwd: PathBuf,
}

pub(crate) fn parse_exec_args(args: &[String]) -> Result<CliExecRequest, String> {
    let mut json = false;
    let mut events = false;
    let mut policy = "read-only".to_string();
    let mut network = None;
    let mut cwd = current_dir();
    let mut timeout = None;
    let mut stdin_inherit = false;
    let mut pty = false;
    let mut control_fd3 = false;
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
            "--control-fd" => {
                if args.get(index + 1).map(String::as_str) != Some("3") {
                    return Err("--control-fd requires 3".to_string());
                }
                control_fd3 = true;
                index += 2;
            }
            "--pty" => {
                pty = true;
                index += 1;
            }
            "--stdin" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--stdin requires a value".to_string())?;
                stdin_inherit = match value.as_str() {
                    "empty" => false,
                    "inherit" => true,
                    _ => return Err("--stdin must be empty or inherit".to_string()),
                };
                index += 2;
            }
            "--" => {
                let command = args[index + 1..].to_vec();
                if command.is_empty() {
                    return Err("exec requires a command after --".to_string());
                }
                if json && events {
                    return Err("--json and --events are mutually exclusive".to_string());
                }
                if control_fd3 && (pty || json || events) {
                    return Err("--control-fd requires plain pipe output".to_string());
                }
                if pty && (!stdin_inherit || json || events) {
                    return Err("--pty requires --stdin inherit and plain output".to_string());
                }
                if stdin_inherit && (json || events) {
                    return Err("--stdin inherit requires plain output".to_string());
                }
                return Ok(CliExecRequest {
                    json,
                    events,
                    policy,
                    network,
                    cwd,
                    timeout,
                    stdin_inherit,
                    pty,
                    control_fd3,
                    command,
                });
            }
            _ => return Err("unknown exec argument".to_string()),
        }
    }

    Err("exec requires -- followed by a command".to_string())
}

pub(crate) fn parse_policy_args(args: &[String]) -> Result<CliPolicyRequest, String> {
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
        .ok_or_else(|| "network mode must be unmanaged, disabled, or proxy".to_string())
}

fn parse_timeout_ms(value: &str) -> Result<Duration, String> {
    let timeout_ms = value
        .parse::<u64>()
        .map_err(|_| "timeout must be an integer in milliseconds".to_string())?;
    Ok(Duration::from_millis(timeout_ms))
}

fn current_dir() -> PathBuf {
    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}
