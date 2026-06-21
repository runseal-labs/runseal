use super::*;
use crate::execution::{current_dir, execute_command, normalize_execution_cwd};
use crate::protocol::error_payload::cli_error_payload;
#[cfg(windows)]
use setup::windows_sandbox_setup_status_for_cwd;

pub(crate) mod capabilities;
pub(crate) mod exec;
pub(crate) mod explain_policy;
pub(crate) mod setup;
pub(crate) mod version;

const HELP_TEXT: &str = "\
Usage: runseal <command> [options]

Commands:
  exec --policy <policy> [--network <mode>] [--cwd <path>] -- <command> [args...]
  explain-policy --policy <policy> [--network <mode>] [--cwd <path>]
  capabilities
  setup windows-sandbox [--cwd <path>] [--status] [--json]
  rpc --stdio
  service --stdio
  version
";

pub(crate) fn print_help() -> Result<(), String> {
    print!("{HELP_TEXT}");
    Ok(())
}
