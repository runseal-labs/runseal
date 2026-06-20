mod capability;
mod core;
mod error;
mod execution;
mod filesystem;
#[cfg(windows)]
mod managed_proxy;
mod plan;
#[cfg(windows)]
mod policy_epoch;
mod process;
mod registry;
mod runtime;
mod skeleton;
mod windows;
use std::path::{Path, PathBuf};

pub use core::SandboxBackend;
pub use error::BackendError;
#[cfg(all(test, windows))]
pub(crate) use error::policy_transition_busy_error_for_test;
pub(crate) use error::{backend_unavailable_reason, policy_transition_busy_reason};
pub use execution::BackendExecutionOutput;
pub use plan::PlatformSandboxPlan;
pub use registry::active_backend;
#[cfg(windows)]
pub(crate) use windows::windows_sandbox_home;
fn host_platform() -> &'static str {
    match std::env::consts::OS {
        "windows" => "windows",
        "macos" => "macos",
        "linux" => "linux",
        _ => "unknown",
    }
}

fn path_string(path: &Path) -> String {
    PathBuf::from(path).to_string_lossy().to_string()
}

fn runtime_environment_value_is_path(key: &str) -> bool {
    !matches!(key, "HOMEDRIVE" | "HOMEPATH")
}

#[cfg(test)]
mod tests;
