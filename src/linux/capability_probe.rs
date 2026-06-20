use serde_json::{Value, json};
use std::env;
use std::fs;
use std::path::Path;

pub(crate) fn payload() -> Value {
    json!({
        "sandboxed_execution": "unsupported",
        "filesystem_enforcement": "unsupported",
        "network_enforcement": "unsupported",
        "runtime": {
            "user_namespace": file_status("/proc/self/ns/user"),
            "mount_namespace": file_status("/proc/self/ns/mnt"),
            "pid_namespace": file_status("/proc/self/ns/pid"),
            "network_namespace": file_status("/proc/self/ns/net"),
            "seccomp": seccomp_status(),
            "landlock": file_status("/sys/kernel/security/landlock"),
            "landlock_abi": landlock_abi(),
            "bubblewrap": path_status("bwrap"),
            "unprivileged_user_namespace": unprivileged_user_namespace_status(),
        },
    })
}

fn file_status(path: &str) -> &'static str {
    if Path::new(path).exists() {
        "available"
    } else {
        "unavailable"
    }
}

fn path_status(binary: &str) -> &'static str {
    let Some(paths) = env::var_os("PATH") else {
        return "unavailable";
    };

    if env::split_paths(&paths).any(|dir| dir.join(binary).is_file()) {
        "available"
    } else {
        "unavailable"
    }
}

fn seccomp_status() -> &'static str {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("Seccomp:"))
                .and_then(|line| line.split_once(':'))
                .and_then(|(_, value)| value.trim().parse::<u64>().ok())
                .map(|mode| if mode > 0 { "available" } else { "unavailable" })
        })
        .unwrap_or("unavailable")
}

fn landlock_abi() -> Value {
    let version = fs::read_to_string("/sys/kernel/security/landlock/abi")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|version| *version > 0);

    json!({
        "status": version.map(|_| "available").unwrap_or("unavailable"),
        "version": version,
    })
}

fn unprivileged_user_namespace_status() -> &'static str {
    fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .ok()
        .map(|raw| {
            if raw.trim() == "1" {
                "available"
            } else {
                "unavailable"
            }
        })
        .unwrap_or("unavailable")
}
