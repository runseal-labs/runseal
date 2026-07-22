use std::ffi::OsStr;
use std::ffi::c_void;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Result;
use codex_windows_sandbox::ensure_allow_mask_aces_with_inheritance;
use codex_windows_sandbox::path_mask_allows;
use windows_sys::Win32::Security::CONTAINER_INHERIT_ACE;
use windows_sys::Win32::Security::OBJECT_INHERIT_ACE;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_EXECUTE;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;

const READ_EXECUTE_MASK: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;

pub(super) fn ensure_codex_app_runtime_bin_readable(
    sandbox_group_psid: *mut c_void,
    refresh_errors: &mut Vec<String>,
    log: &mut dyn Write,
) -> Result<()> {
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .map(PathBuf::from)
                .map(|profile| profile.join("AppData").join("Local"))
        });
    let Some(local_app_data) = local_app_data else {
        return Ok(());
    };

    // Codex desktop copies bundled Windows binaries out of WindowsApps to this
    // fixed LocalAppData cache before launching codex.exe.
    let runtime_bin_dir = local_app_data.join("OpenAI").join("Codex").join("bin");
    if !runtime_bin_dir.is_dir() {
        return Ok(());
    }

    let _ = ensure_read_execute_acl(
        &runtime_bin_dir,
        sandbox_group_psid,
        refresh_errors,
        log,
        "runtime bin",
        /*log_grant*/ true,
    )?;
    Ok(())
}

pub(super) fn ensure_runseal_packaged_resources_readable(
    sandbox_group_psid: *mut c_void,
    refresh_errors: &mut Vec<String>,
    log: &mut dyn Write,
) -> Result<()> {
    let Ok(current_exe) = std::env::current_exe() else {
        return Ok(());
    };

    for root in packaged_resource_roots_for_setup_exe(&current_exe) {
        ensure_read_execute_acl_recursive(
            &root,
            sandbox_group_psid,
            refresh_errors,
            log,
            "packaged resource",
        )?;
    }
    Ok(())
}

fn packaged_resource_roots_for_setup_exe(exe: &Path) -> Vec<PathBuf> {
    let Some(bin_dir) = exe.parent() else {
        return Vec::new();
    };
    if !file_name_eq(bin_dir, "bin") {
        return Vec::new();
    }
    let Some(resources_dir) = bin_dir.parent() else {
        return Vec::new();
    };
    if !file_name_eq(resources_dir, "resources") {
        return Vec::new();
    }

    vec![bin_dir.to_path_buf(), resources_dir.join("runtime")]
}

fn file_name_eq(path: &Path, expected: &str) -> bool {
    path.file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name.eq_ignore_ascii_case(expected))
}

fn ensure_read_execute_acl_recursive(
    root: &Path,
    sandbox_group_psid: *mut c_void,
    refresh_errors: &mut Vec<String>,
    log: &mut dyn Write,
    label: &str,
) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }

    let mut granted_count = 0usize;
    if ensure_read_execute_acl(
        root,
        sandbox_group_psid,
        refresh_errors,
        log,
        label,
        /*log_grant*/ false,
    )? {
        granted_count += 1;
    }
    if !root.is_dir() {
        if granted_count > 0 {
            super::log_line(
                log,
                &format!(
                    "granted read/execute ACE to {granted_count} {label} path under {}",
                    root.display()
                ),
            )?;
        }
        return Ok(());
    }

    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) => {
                refresh_errors.push(format!(
                    "{label} read/execute scan failed on {}: {err}",
                    dir.display()
                ));
                super::log_line(
                    log,
                    &format!(
                        "{label} read/execute scan failed on {}: {err}; continuing",
                        dir.display()
                    ),
                )?;
                continue;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if ensure_read_execute_acl(
                &path,
                sandbox_group_psid,
                refresh_errors,
                log,
                label,
                /*log_grant*/ false,
            )? {
                granted_count += 1;
            }
            if file_type.is_dir() {
                stack.push(path);
            }
        }
    }
    if granted_count > 0 {
        super::log_line(
            log,
            &format!(
                "granted read/execute ACE to {granted_count} {label} paths under {}",
                root.display()
            ),
        )?;
    }
    Ok(())
}

fn ensure_read_execute_acl(
    path: &Path,
    sandbox_group_psid: *mut c_void,
    refresh_errors: &mut Vec<String>,
    log: &mut dyn Write,
    label: &str,
    log_grant: bool,
) -> Result<bool> {
    let has_access = match path_mask_allows(
        path,
        &[sandbox_group_psid],
        READ_EXECUTE_MASK,
        /*require_all_bits*/ true,
    ) {
        Ok(has_access) => has_access,
        Err(err) => {
            refresh_errors.push(format!(
                "{label} read/execute mask check failed on {} for sandbox_group: {err}",
                path.display()
            ));
            super::log_line(
                log,
                &format!(
                    "{label} read/execute mask check failed on {} for sandbox_group: {err}; continuing",
                    path.display()
                ),
            )?;
            false
        }
    };
    if has_access {
        return Ok(false);
    }

    let inheritance = if path.is_dir() {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    };

    if log_grant {
        super::log_line(
            log,
            &format!(
                "granting read/execute ACE to {} for sandbox users",
                path.display()
            ),
        )?;
    }
    let result = unsafe {
        ensure_allow_mask_aces_with_inheritance(
            path,
            &[sandbox_group_psid],
            READ_EXECUTE_MASK,
            inheritance,
        )
    };
    match result {
        Ok(added) => Ok(added),
        Err(err) => {
            refresh_errors.push(format!(
                "grant read/execute ACE failed on {} for sandbox_group: {err}",
                path.display()
            ));
            super::log_line(
                log,
                &format!(
                    "grant read/execute ACE failed on {} for sandbox_group: {err}",
                    path.display()
                ),
            )?;
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::packaged_resource_roots_for_setup_exe;
    use std::path::Path;
    use std::path::PathBuf;

    #[test]
    fn packaged_resource_roots_detects_electron_resources_bin() {
        let exe = Path::new(
            r"C:\Users\example\AppData\Local\Programs\RunSeal-Dev\resources\bin\runseal-windows-sandbox-setup.exe",
        );

        let roots = packaged_resource_roots_for_setup_exe(exe);

        assert_eq!(
            roots,
            vec![
                PathBuf::from(r"C:\Users\example\AppData\Local\Programs\RunSeal-Dev\resources\bin"),
                PathBuf::from(
                    r"C:\Users\example\AppData\Local\Programs\RunSeal-Dev\resources\runtime"
                ),
            ]
        );
    }

    #[test]
    fn packaged_resource_roots_ignores_dev_target_exe() {
        let exe = Path::new(r"C:\build\runseal\target\release\runseal-windows-sandbox-setup.exe");

        assert!(packaged_resource_roots_for_setup_exe(exe).is_empty());
    }
}
