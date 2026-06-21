use serde_json::{Value, json};
use std::path::Path;

pub(crate) fn capability_probes() -> Value {
    let landlock_abi_version = landlock_abi_version();
    json!([
        probe(
            "filesystem_policy",
            "landlock",
            landlock_abi_version.is_some(),
            false,
        ),
        probe_with_details(
            "filesystem_policy",
            "landlock_abi_version",
            landlock_abi_version.is_some(),
            landlock_abi_version.map(|version| json!({"abi_version": version})),
        ),
        probe(
            "process_isolation",
            "user_namespaces",
            Path::new("/proc/self/ns/user").exists(),
            true,
        ),
        probe(
            "process_isolation",
            "user_namespace_quota",
            user_namespace_quota_available(),
            true,
        ),
        probe(
            "process_isolation",
            "mount_namespaces",
            Path::new("/proc/self/ns/mnt").exists(),
            true,
        ),
        probe(
            "process_isolation",
            "pid_namespaces",
            Path::new("/proc/self/ns/pid").exists(),
            true,
        ),
        probe(
            "network_disabled",
            "network_namespaces",
            Path::new("/proc/self/ns/net").exists(),
            true,
        ),
        probe(
            "process_isolation",
            "seccomp",
            Path::new("/proc/self/status").exists(),
            false,
        ),
        probe(
            "process_isolation",
            "bubblewrap",
            command_exists("bwrap"),
            true
        ),
        probe(
            "process_isolation",
            "unprivileged_user_namespaces",
            unprivileged_user_namespaces_available(),
            true,
        )
    ])
}

fn probe(capability: &str, mechanism: &str, available: bool, active: bool) -> Value {
    json!({
        "capability": capability,
        "mechanism": mechanism,
        "status": probe_status(available, active),
        "diagnostic_only": true,
        "available": available
    })
}

fn probe_with_details(
    capability: &str,
    mechanism: &str,
    available: bool,
    details: Option<Value>,
) -> Value {
    let mut probe = probe(capability, mechanism, available, false);
    if let Some(details) = details {
        probe["details"] = details;
    }
    probe
}

fn probe_status(available: bool, active: bool) -> &'static str {
    if active && available {
        "experimental"
    } else if active {
        "unavailable"
    } else {
        "unsupported"
    }
}

fn user_namespace_quota_available() -> bool {
    read_usize("/proc/sys/user/max_user_namespaces").is_some_and(|value| value > 0)
}

fn unprivileged_user_namespaces_available() -> bool {
    if let Some(value) = read_usize("/proc/sys/kernel/unprivileged_userns_clone") {
        return value > 0;
    }
    user_namespace_quota_available()
}

fn read_usize(path: &str) -> Option<usize> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn command_exists(command: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|path| path.join(command).is_file()))
}

#[cfg(target_os = "linux")]
fn landlock_abi_version() -> Option<usize> {
    const SYS_LANDLOCK_CREATE_RULESET: isize = 444;
    const LANDLOCK_CREATE_RULESET_VERSION: usize = 1;

    unsafe extern "C" {
        fn syscall(number: isize, ...) -> isize;
    }

    let version = unsafe {
        syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<u8>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    usize::try_from(version).ok().filter(|version| *version > 0)
}

#[cfg(not(target_os = "linux"))]
fn landlock_abi_version() -> Option<usize> {
    None
}
