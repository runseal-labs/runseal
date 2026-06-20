use serde_json::{Value, json};
use std::path::Path;

pub(crate) fn payload() -> Value {
    json!({
        "sandboxed_execution": "unsupported",
        "filesystem_enforcement": "unsupported",
        "network_enforcement": "unsupported",
        "runtime": {
            "sandbox_exec": executable_file_status("/usr/bin/sandbox-exec"),
        },
    })
}

fn executable_file_status(path: &str) -> &'static str {
    if is_executable_file(Path::new(path)) {
        "available"
    } else {
        "unavailable"
    }
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::executable_file_status;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn sandbox_exec_probe_requires_candidate_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("sandbox-exec");
        fs::write(&path, b"test").unwrap();
        make_executable(&path);

        assert_eq!(executable_file_status(path.to_str().unwrap()), "available");
        assert_eq!(
            executable_file_status(dir.path().join("missing").to_str().unwrap()),
            "unavailable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_exec_probe_rejects_non_executable_files() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("sandbox-exec");
        fs::write(&path, b"test").unwrap();

        assert_eq!(
            executable_file_status(path.to_str().unwrap()),
            "unavailable"
        );
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
