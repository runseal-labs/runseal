use crate::acl::revoke_deny_read_ace;
use crate::setup::sandbox_dir;
use crate::token::convert_string_sid_to_sid;
use anyhow::Context;
use anyhow::Result;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;

const DENY_READ_ACL_STATE_FILE: &str = "deny_read_acl_state.json";

#[derive(Default, Deserialize)]
struct PersistentDenyReadAclState {
    principals: BTreeMap<String, Vec<PathBuf>>,
}

/// Removes every deny-read ACE tracked by the retired finite-deny backend.
///
/// # Safety
/// Tracked principal SIDs must be SDDL strings that can be converted to valid SID pointers.
pub unsafe fn clear_legacy_persistent_deny_read_acls(codex_home: &Path) -> Result<usize> {
    let state_path = sandbox_dir(codex_home).join(DENY_READ_ACL_STATE_FILE);
    let state = load_state(&state_path)?;
    let mut removed = 0usize;

    for (principal_sid, paths) in state.principals {
        let Some(psid) = (unsafe { convert_string_sid_to_sid(&principal_sid) }) else {
            continue;
        };
        for path in paths {
            if unsafe { revoke_deny_read_ace(&path, psid) }.unwrap_or(false) {
                removed += 1;
            }
        }
        unsafe {
            LocalFree(psid as HLOCAL);
        }
    }

    match std::fs::remove_file(&state_path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err)
                .with_context(|| format!("remove deny-read ACL state {}", state_path.display()));
        }
    }
    Ok(removed)
}
fn load_state(path: &Path) -> Result<PersistentDenyReadAclState> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("parse deny-read ACL state {}", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Ok(PersistentDenyReadAclState::default())
        }
        Err(err) => {
            Err(err).with_context(|| format!("read deny-read ACL state {}", path.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn empty_legacy_state_is_consumed_once() {
        let codex_home = TempDir::new().expect("create temporary codex home");
        let sandbox_dir = sandbox_dir(codex_home.path());
        std::fs::create_dir_all(&sandbox_dir).expect("create sandbox state directory");
        let state_path = sandbox_dir.join(DENY_READ_ACL_STATE_FILE);
        std::fs::write(&state_path, r#"{"principals":{}}"#).expect("write legacy deny-read state");

        let removed = unsafe { clear_legacy_persistent_deny_read_acls(codex_home.path()) }
            .expect("consume legacy deny-read state");

        assert_eq!(removed, 0);
        assert!(!state_path.exists(), "legacy state file should be deleted");
    }
}
