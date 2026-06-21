use serde_json::{Value, json};

pub(crate) fn capability_probes() -> Value {
    json!([
        probe(
            "filesystem_policy",
            "sandbox_exec",
            command_exists("sandbox-exec"),
            true,
        ),
        probe(
            "filesystem_policy",
            "sandbox_exec_executable",
            command_exists("sandbox-exec"),
            true,
        ),
        probe(
            "platform_version",
            "macos_version",
            cfg!(target_os = "macos"),
            true,
        ),
        probe(
            "filesystem_policy",
            "temporary_profile",
            cfg!(target_os = "macos"),
            false,
        ),
        probe(
            "filesystem_policy",
            "canonical_paths",
            cfg!(target_os = "macos"),
            true,
        ),
        probe(
            "filesystem_policy",
            "symlink_path_model",
            cfg!(target_os = "macos"),
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

fn probe_status(available: bool, active: bool) -> &'static str {
    if active && available {
        "experimental"
    } else if active {
        "unavailable"
    } else {
        "unsupported"
    }
}

fn command_exists(command: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|path| path.join(command).is_file()))
}
