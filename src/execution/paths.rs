use crate::error::RunSealError;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn validate_execution_cwd(cwd: &Path) -> Result<(), RunSealError> {
    let metadata = fs::symlink_metadata(cwd).map_err(|err| {
        RunSealError::new(
            "INVALID_REQUEST",
            format!("params.cwd must be an existing directory: {err}"),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            format!(
                "params.cwd must be an existing directory: {}",
                cwd.display()
            ),
        ));
    }

    Ok(())
}

pub(crate) fn normalize_execution_cwd(cwd: &Path) -> Result<PathBuf, RunSealError> {
    validate_execution_cwd(cwd)?;
    fs::canonicalize(cwd)
        .map(simplify_windows_extended_path)
        .map_err(|err| {
            RunSealError::new(
                "INVALID_REQUEST",
                format!("params.cwd must be an existing directory: {err}"),
            )
        })
}

fn simplify_windows_extended_path(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let value = path.to_string_lossy();
        if let Some(stripped) = value.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{stripped}"));
        }
        if let Some(stripped) = value.strip_prefix(r"\\?\") {
            return PathBuf::from(stripped);
        }
    }
    path
}

pub(crate) fn current_dir() -> PathBuf {
    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}
