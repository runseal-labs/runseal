use serde_json::{Value, json};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

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
            "max_user_namespaces": positive_sysctl_status("/proc/sys/user/max_user_namespaces"),
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

    if binary_status_in_paths(binary, env::split_paths(&paths)) {
        "available"
    } else {
        "unavailable"
    }
}

fn binary_status_in_paths(binary: &str, paths: impl IntoIterator<Item = PathBuf>) -> bool {
    paths
        .into_iter()
        .any(|dir| is_executable_file(&dir.join(binary)))
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
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
    let quota_allows = positive_sysctl("/proc/sys/user/max_user_namespaces");
    let clone_allows = fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|value| value > 0);

    unprivileged_user_namespace_status_for(quota_allows, clone_allows)
}

fn unprivileged_user_namespace_status_for(
    quota_allows: Option<bool>,
    clone_allows: Option<bool>,
) -> &'static str {
    match (quota_allows, clone_allows) {
        (Some(false), _) | (_, Some(false)) => "unavailable",
        (Some(true), _) | (_, Some(true)) => "available",
        _ => "unavailable",
    }
}

fn positive_sysctl_status(path: &str) -> &'static str {
    positive_sysctl(path)
        .map(|enabled| if enabled { "available" } else { "unavailable" })
        .unwrap_or("unavailable")
}

fn positive_sysctl(path: &str) -> Option<bool> {
    fs::read_to_string(path)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|value| value > 0)
}

#[cfg(test)]
mod tests {
    use super::{binary_status_in_paths, unprivileged_user_namespace_status_for};
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn user_namespace_probe_combines_quota_and_distro_toggle() {
        assert_eq!(
            unprivileged_user_namespace_status_for(Some(true), None),
            "available"
        );
        assert_eq!(
            unprivileged_user_namespace_status_for(Some(true), Some(false)),
            "unavailable"
        );
        assert_eq!(
            unprivileged_user_namespace_status_for(Some(false), Some(true)),
            "unavailable"
        );
        assert_eq!(
            unprivileged_user_namespace_status_for(None, None),
            "unavailable"
        );
    }

    #[test]
    fn path_probe_finds_binary_only_in_candidate_dirs() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("bwrap"), b"test").unwrap();
        make_executable(&dir.path().join("bwrap"));

        assert!(binary_status_in_paths("bwrap", [dir.path().to_path_buf()]));
        assert!(!binary_status_in_paths(
            "missing",
            [dir.path().to_path_buf()]
        ));
    }

    #[cfg(unix)]
    #[test]
    fn path_probe_rejects_non_executable_files() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("bwrap"), b"test").unwrap();

        assert!(!binary_status_in_paths("bwrap", [dir.path().to_path_buf()]));
    }

    #[cfg(unix)]
    fn make_executable(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &std::path::Path) {}
}
