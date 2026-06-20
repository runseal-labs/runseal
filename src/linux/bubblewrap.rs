use crate::backend::process::{minimal_environment, spawn_prepared_command};
use crate::backend::{BackendExecutionOutput, PlatformSandboxPlan};
use crate::execution::{ExecutionCancellation, ExecutionEnv, ExecutionStdin};
use std::io;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

pub(crate) fn execute_read_only(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
    cancellation: Option<ExecutionCancellation>,
) -> io::Result<BackendExecutionOutput> {
    let mut process = Command::new("bwrap");
    process
        .arg("--unshare-user")
        .arg("--unshare-pid")
        .arg("--unshare-net")
        .arg("--die-with-parent")
        .arg("--ro-bind")
        .arg("/")
        .arg("/")
        .arg("--ro-bind")
        .arg(cwd)
        .arg(cwd)
        .arg("--chdir")
        .arg(cwd)
        .arg("--")
        .arg(&command[0])
        .args(&command[1..])
        .env_clear()
        .envs(minimal_environment(plan))
        .envs(env.entries.iter().map(|(key, value)| (key, value)));

    spawn_prepared_command(plan, process, stdin, timeout, cancellation)
}
