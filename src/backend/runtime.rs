use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

pub(super) const RUNTIME_ROOT_MARKER: &str = ".runseal-runtime-root";

pub(super) fn prepare_unique_runtime_root(
    prepared: &mut Vec<String>,
    root: &str,
) -> io::Result<()> {
    fs::create_dir_all(root)?;
    if !prepared.iter().any(|item| item == root) {
        prepared.push(root.to_string());
    }
    Ok(())
}

pub(super) fn validate_runtime_root_ancestors(
    expected: &Path,
    workspace: &Path,
    operation: &str,
) -> io::Result<()> {
    for ancestor in expected.ancestors() {
        if !ancestor.starts_with(workspace) {
            break;
        }
        validate_runtime_root_not_symlink(ancestor, operation)?;
    }
    Ok(())
}

pub(super) fn validate_runtime_root_not_symlink(root: &Path, operation: &str) -> io::Result<()> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to {operation} symlinked runtime root: {}",
                root.display()
            ),
        )),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

pub(super) fn runtime_marker_is_regular_file(marker: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(marker) {
        Ok(metadata) => Ok(metadata.is_file() && !metadata.file_type().is_symlink()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

pub(super) fn validate_runtime_tree_has_no_symlinks(
    root: &Path,
    operation: &str,
) -> io::Result<()> {
    if !root.exists() {
        return Ok(());
    }

    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "refusing to {operation} runtime tree with symlink entry: {}",
                        path.display()
                    ),
                ));
            }
            if metadata.is_dir() {
                stack.push(path);
            }
        }
    }
    Ok(())
}

pub(super) fn normalize_lexical(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}
