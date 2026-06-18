use crate::windows::policy::{
    WindowsFilesystemAclEffect, WindowsFilesystemAclEntry, WindowsFilesystemAclRights,
    WindowsFilesystemAclTransactionPlan, WindowsFilesystemAclTransactionStep,
};
use std::fs;
use std::io;
use std::path::{Component, Path};

pub(super) trait WindowsFilesystemAclDriver {
    fn capture_rollback(&mut self, root: &str) -> io::Result<()>;
    fn apply_entry(
        &mut self,
        subject: WindowsFilesystemAclSubject,
        entry: &WindowsFilesystemAclEntry,
    ) -> io::Result<()>;
    fn rollback(&mut self) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WindowsFilesystemAclSubject {
    SingleSandboxUserRestrictedToken,
}

impl WindowsFilesystemAclSubject {
    pub(super) fn from_plan(
        process_identity: &str,
        private_process_sandbox_user_model: &str,
        private_process_token: &str,
    ) -> io::Result<Self> {
        if process_identity == "low-privilege"
            && private_process_sandbox_user_model == "single-sandbox-user"
            && private_process_token == "restricted-token"
        {
            return Ok(Self::SingleSandboxUserRestrictedToken);
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private filesystem ACL rules require a single sandbox user restricted process identity",
        ))
    }

    #[cfg(test)]
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::SingleSandboxUserRestrictedToken => "single-sandbox-user-restricted-token",
        }
    }
}

pub(super) fn new_windows_filesystem_acl_driver() -> Box<dyn WindowsFilesystemAclDriver> {
    Box::new(ValidateOnlyWindowsFilesystemAclDriver)
}

#[derive(Default)]
struct ValidateOnlyWindowsFilesystemAclDriver;

impl WindowsFilesystemAclDriver for ValidateOnlyWindowsFilesystemAclDriver {
    fn capture_rollback(&mut self, _root: &str) -> io::Result<()> {
        Ok(())
    }

    fn apply_entry(
        &mut self,
        _subject: WindowsFilesystemAclSubject,
        _entry: &WindowsFilesystemAclEntry,
    ) -> io::Result<()> {
        Ok(())
    }

    fn rollback(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn validate_private_filesystem_acl_transaction(
    transaction: &WindowsFilesystemAclTransactionPlan,
) -> io::Result<()> {
    if !transaction.captures_before_apply() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private filesystem ACL transaction must capture rollback state before applying entries",
        ));
    }
    for root in transaction.rollback_roots() {
        validate_private_filesystem_rule_root(root)?;
    }
    Ok(())
}

pub(super) fn validate_private_filesystem_acl_entries(
    transaction: &WindowsFilesystemAclTransactionPlan,
) -> io::Result<()> {
    for entry in transaction.apply_entries() {
        validate_private_filesystem_acl_entry(entry)?;
    }
    Ok(())
}

pub(super) fn apply_private_filesystem_acl_transaction(
    transaction: &WindowsFilesystemAclTransactionPlan,
    subject: Option<WindowsFilesystemAclSubject>,
    driver: &mut dyn WindowsFilesystemAclDriver,
) -> io::Result<()> {
    for step in transaction.steps() {
        match step {
            WindowsFilesystemAclTransactionStep::CaptureRollback { root } => {
                driver.capture_rollback(root)?;
            }
            WindowsFilesystemAclTransactionStep::ApplyEntry { entry } => {
                let Some(subject) = subject else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "private filesystem ACL entry requires a single sandbox user restricted process identity",
                    ));
                };
                if let Err(apply_err) = driver.apply_entry(subject, entry) {
                    return rollback_private_filesystem_acl_transaction(driver, apply_err);
                }
            }
        }
    }
    Ok(())
}

fn rollback_private_filesystem_acl_transaction(
    driver: &mut dyn WindowsFilesystemAclDriver,
    apply_err: io::Error,
) -> io::Result<()> {
    if let Err(rollback_err) = driver.rollback() {
        return Err(io::Error::other(format!(
            "private filesystem ACL transaction failed ({apply_err}); rollback failed ({rollback_err})"
        )));
    }
    Err(apply_err)
}

fn validate_private_filesystem_acl_entry(entry: &WindowsFilesystemAclEntry) -> io::Result<()> {
    validate_private_filesystem_rule_root(entry.root())?;
    validate_private_filesystem_acl_operation(entry)?;
    if !entry.has_consistent_access_source() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "inconsistent private filesystem ACL entry for root: {}",
                entry.root()
            ),
        ));
    }
    if !entry.is_tree_scoped() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "private filesystem ACL entry must be tree scoped: {}",
                entry.root()
            ),
        ));
    }
    if entry.requires_existing_root() {
        validate_existing_filesystem_rule_root(entry)?;
    }
    Ok(())
}

fn validate_private_filesystem_acl_operation(entry: &WindowsFilesystemAclEntry) -> io::Result<()> {
    match (entry.effect(), entry.rights()) {
        (WindowsFilesystemAclEffect::Deny, WindowsFilesystemAclRights::FullControl)
        | (WindowsFilesystemAclEffect::Allow, WindowsFilesystemAclRights::Modify)
        | (WindowsFilesystemAclEffect::Allow, WindowsFilesystemAclRights::ReadExecute) => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "private filesystem ACL entry has unsupported operation for root: {}",
                entry.root()
            ),
        )),
    }
}

fn validate_private_filesystem_rule_root(root: &str) -> io::Result<()> {
    if root.is_empty() || root == "*" {
        return Err(invalid_filesystem_rule_root(root));
    }
    if contains_parent_traversal(root)
        || is_broad_filesystem_rule_root(root)
        || is_windows_drive_relative(root)
        || !is_concrete_filesystem_rule_root(root)
    {
        return Err(invalid_filesystem_rule_root(root));
    }
    Ok(())
}

fn validate_existing_filesystem_rule_root(entry: &WindowsFilesystemAclEntry) -> io::Result<()> {
    let metadata = fs::symlink_metadata(entry.root()).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "private filesystem rule root must exist before setup: {}",
                    entry.root()
                ),
            )
        } else {
            err
        }
    })?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to prepare symlinked filesystem rule root: {}",
                entry.root()
            ),
        ));
    }
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "private filesystem rule root must be a directory: {}",
                entry.root()
            ),
        ));
    }
    Ok(())
}

fn invalid_filesystem_rule_root(root: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid private filesystem rule root: {root}"),
    )
}

fn contains_parent_traversal(path: &str) -> bool {
    Path::new(path)
        .components()
        .any(|component| component == Component::ParentDir)
        || path.split(['/', '\\']).any(|component| component == "..")
}

fn is_broad_filesystem_rule_root(root: &str) -> bool {
    let trimmed = root.trim_end_matches(['/', '\\']);
    root.trim_matches(['/', '\\']).is_empty()
        || matches!(trimmed.to_ascii_lowercase().as_str(), "~" | "$home")
        || trimmed.ends_with(':')
}

fn is_windows_drive_relative(root: &str) -> bool {
    let bytes = root.as_bytes();
    bytes.len() >= 2 && bytes[1] == b':' && !matches!(bytes.get(2), Some(b'/' | b'\\'))
}

fn is_concrete_filesystem_rule_root(root: &str) -> bool {
    root.starts_with(['/', '\\']) || is_windows_drive_absolute(root)
}

fn is_windows_drive_absolute(root: &str) -> bool {
    let bytes = root.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}
