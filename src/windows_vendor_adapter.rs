use crate::policy::{NetworkMode, SandboxPolicy};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WindowsVendorSandboxProfile {
    Disabled,
    Managed {
        filesystem: WindowsVendorFilesystemPolicy,
        network: WindowsVendorNetworkPolicy,
        managed_proxy_required: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowsVendorFilesystemPolicy {
    pub(crate) entries: Vec<WindowsVendorFilesystemEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowsVendorFilesystemEntry {
    pub(crate) path: String,
    pub(crate) access: WindowsVendorFilesystemAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsVendorFilesystemAccess {
    Read,
    Write,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsVendorNetworkPolicy {
    Restricted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsVendorTokenMode {
    ReadOnlyCapability,
    WritableRootsCapability,
}

impl WindowsVendorSandboxProfile {
    pub(crate) fn from_policy(policy: &SandboxPolicy) -> Self {
        if policy.allows_local_execution() {
            return Self::Disabled;
        }

        Self::Managed {
            filesystem: WindowsVendorFilesystemPolicy {
                entries: filesystem_entries(policy),
            },
            network: WindowsVendorNetworkPolicy::Restricted,
            managed_proxy_required: policy.network.mode == NetworkMode::Proxy,
        }
    }

    pub(crate) fn token_mode(&self) -> Option<WindowsVendorTokenMode> {
        let Self::Managed { filesystem, .. } = self else {
            return None;
        };
        if filesystem
            .entries
            .iter()
            .any(|entry| entry.access == WindowsVendorFilesystemAccess::Write)
        {
            Some(WindowsVendorTokenMode::WritableRootsCapability)
        } else {
            Some(WindowsVendorTokenMode::ReadOnlyCapability)
        }
    }
}

fn filesystem_entries(policy: &SandboxPolicy) -> Vec<WindowsVendorFilesystemEntry> {
    let mut entries = Vec::new();
    extend_entries(
        &mut entries,
        &policy.filesystem.read,
        WindowsVendorFilesystemAccess::Read,
    );
    extend_entries(
        &mut entries,
        &policy.filesystem.write,
        WindowsVendorFilesystemAccess::Write,
    );
    extend_entries(
        &mut entries,
        &policy.filesystem.deny,
        WindowsVendorFilesystemAccess::Deny,
    );
    entries
}

fn extend_entries(
    entries: &mut Vec<WindowsVendorFilesystemEntry>,
    paths: &[String],
    access: WindowsVendorFilesystemAccess,
) {
    entries.extend(
        paths
            .iter()
            .cloned()
            .map(|path| WindowsVendorFilesystemEntry { path, access }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::normalize_policy;
    use serde_json::json;
    use std::path::PathBuf;

    #[test]
    fn workspace_write_policy_maps_to_managed_vendor_profile() {
        let cwd = PathBuf::from("C:/workspace");
        let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
        let profile = WindowsVendorSandboxProfile::from_policy(&policy);

        assert_eq!(
            profile,
            WindowsVendorSandboxProfile::Managed {
                filesystem: WindowsVendorFilesystemPolicy {
                    entries: vec![
                        WindowsVendorFilesystemEntry {
                            path: cwd.to_string_lossy().to_string(),
                            access: WindowsVendorFilesystemAccess::Read,
                        },
                        WindowsVendorFilesystemEntry {
                            path: cwd.to_string_lossy().to_string(),
                            access: WindowsVendorFilesystemAccess::Write,
                        },
                        WindowsVendorFilesystemEntry {
                            path: cwd.join(".git").to_string_lossy().to_string(),
                            access: WindowsVendorFilesystemAccess::Deny,
                        },
                        WindowsVendorFilesystemEntry {
                            path: cwd.join(".agents").to_string_lossy().to_string(),
                            access: WindowsVendorFilesystemAccess::Deny,
                        },
                        WindowsVendorFilesystemEntry {
                            path: cwd.join(".codex").to_string_lossy().to_string(),
                            access: WindowsVendorFilesystemAccess::Deny,
                        },
                    ],
                },
                network: WindowsVendorNetworkPolicy::Restricted,
                managed_proxy_required: true,
            }
        );
        assert_eq!(
            profile.token_mode(),
            Some(WindowsVendorTokenMode::WritableRootsCapability)
        );
    }

    #[test]
    fn danger_full_access_maps_to_disabled_vendor_profile() {
        let cwd = PathBuf::from("C:/workspace");
        let policy = normalize_policy(&json!("danger-full-access"), &cwd, None).unwrap();
        let profile = WindowsVendorSandboxProfile::from_policy(&policy);

        assert_eq!(profile, WindowsVendorSandboxProfile::Disabled);
        assert_eq!(profile.token_mode(), None);
    }
}
