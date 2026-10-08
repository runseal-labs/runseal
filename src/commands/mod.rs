use super::*;
use crate::execution::{ExecutionRequest, current_dir, execute_command, normalize_execution_cwd};
use crate::protocol::error_payload::cli_error_payload;
#[cfg(windows)]
use setup::windows_sandbox_setup_status_for_cwd;

pub(crate) mod capabilities;
pub(crate) mod exec;
pub(crate) mod explain_policy;
pub(crate) mod mcp;
pub(crate) mod repair;
pub(crate) mod setup;
pub(crate) mod version;

const HELP_TEXT: &str = "\
Usage: runseal <command> [options]

Commands:
  exec --policy <policy> [--network <mode>] [--cwd <path>] -- <command> [args...]
  explain-policy --policy <policy> [--network <mode>] [--cwd <path>]
  capabilities
  mcp --stdio [--policy <policy>] [--network <mode>] [--cwd <path>]
  setup windows-sandbox [--cwd <path>] [--status] [--json] [--elevate]
  repair execution-gates [--json] [--accept-unverified-release]
  rpc --stdio
  service --stdio
  version

Deployment:
  RUNSEAL_MAX_ACTIVE_EXECUTIONS  per-connection admission limit, 1..64 (default 8)
  RUNSEAL_REPLAY_EXECUTION_BYTES  replay bytes per execution (default 1048576)
  RUNSEAL_REPLAY_CONNECTION_BYTES  replay bytes per connection (default 8388608)
  RUNSEAL_COMPLETED_EXECUTIONS  retained terminal count (default 1024)
  RUNSEAL_COMPLETED_EXECUTION_BYTES  retained terminal bytes (default 8388608)
  RUNSEAL_AUDIT_CACHE_BYTES  redacted audit query bytes (default 8388608)
  RUNSEAL_STREAM_CHUNK_BYTES  decoded stream/input/control chunk bytes (default 65536)
  RUNSEAL_INPUT_PENDING_BYTES  pending stdin/control bytes per stream (default 262144)
  RUNSEAL_RPC_FRAME_BYTES  JSON-RPC line bytes including newline (default 1048576)
  RUNSEAL_MAX_OUTPUT_BYTES  aggregate output bytes per execution (default 16777216)
  RUNSEAL_SENDER_BYTES  protocol send bytes per connection (default 8388608)
  RUNSEAL_BACKPRESSURE_MS  no-output-progress grace in milliseconds (default 5000)
  RUNSEAL_CLEANUP_TIMEOUT_MS  total host cleanup wait in milliseconds (default 10000)
";

pub(crate) fn print_help() -> Result<(), String> {
    print!("{HELP_TEXT}");
    Ok(())
}
