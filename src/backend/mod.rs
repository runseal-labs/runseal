use crate::policy::{
    BackendFeature, SandboxLevel, SandboxPolicy, matches_environment_scrub_pattern,
};
use crate::windows::policy::{
    WindowsFilesystemAclPlan, WindowsFilesystemAclTransactionPlan, WindowsFilesystemRule,
    WindowsHostRoots, WindowsPolicyPlan, WindowsRuntimeRoots,
};
use crate::windows::vendor_adapter::WindowsVendorSandboxProfile;
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
#[cfg(windows)]
use crate::events::timestamp_now;
use filesystem::{
    WindowsFilesystemAclDriver, WindowsFilesystemAclSubject,
    apply_private_filesystem_acl_transaction, new_windows_filesystem_acl_driver,
    validate_private_filesystem_acl_entries, validate_private_filesystem_acl_transaction,
};
#[cfg(windows)]
use managed_proxy::ManagedSandboxProxy;
#[cfg(all(test, windows))]
use process::WindowsKillOnCloseJob;
#[cfg(test)]
use process::cleanup_child_after_setup_error;
#[cfg(any(test, windows))]
use process::minimal_environment;
use process::spawn_local_command;
use runtime::{
    RUNTIME_ROOT_MARKER, normalize_lexical, prepare_unique_runtime_root,
    runtime_marker_is_regular_file, validate_runtime_root_ancestors,
    validate_runtime_root_not_symlink, validate_runtime_tree_has_no_symlinks,
};
use serde_json::Map;
use serde_json::{Value, json};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Output;
#[cfg(windows)]
use {
    codex_protocol::models::PermissionProfile,
    codex_utils_absolute_path::AbsolutePathBuf,
    std::collections::{HashMap, HashSet},
    std::os::windows::process::ExitStatusExt,
    std::sync::{Mutex, OnceLock},
};

pub use capability::CapabilityStatus;
use capability::capabilities_json_for;
#[cfg(test)]
use capability::missing_backend_features;
pub use core::SandboxBackend;
pub use error::BackendError;
#[cfg(all(test, windows))]
pub(crate) use error::policy_transition_busy_error_for_test;
#[cfg(windows)]
use error::{
    BackendUnavailableError, POLICY_TRANSITION_BUSY_REASON, PolicyTransitionBusyError,
    public_windows_setup_unavailable_reason,
};
pub(crate) use error::{backend_unavailable_reason, policy_transition_busy_reason};
pub use execution::{BackendExecutionOutput, ExecutionEnv, ExecutionStdin};
pub use plan::PlatformSandboxPlan;
#[cfg(test)]
use plan::environment_runtime_json;
use plan::protected_filesystem_labels;
#[cfg(windows)]
use policy_epoch::windows_sandbox_execution_gate;
#[cfg(all(test, windows))]
use policy_epoch::{WindowsSandboxPolicyCohortKey, windows_sandbox_execution_gate_for_key};
pub use registry::active_backend;
#[cfg(test)]
use skeleton::{LinuxCommunityBackend, MacosExperimentalBackend};
#[cfg(test)]
use windows::WindowsReferenceBackend;
use windows::has_single_user_setup_payload;
#[cfg(windows)]
pub(crate) use windows::windows_sandbox_home;
#[cfg(all(test, windows))]
use windows::*;
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
