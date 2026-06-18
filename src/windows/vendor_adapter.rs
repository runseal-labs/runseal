use crate::policy::{NetworkMode, SandboxPolicy};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WindowsVendorSandboxProfile {
    Disabled,
    Managed {
        filesystem: WindowsVendorFilesystemPolicy,
        network: WindowsVendorNetworkPolicy,
        sandbox_user_model: WindowsVendorSandboxUserModel,
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
    Disabled,
    Proxy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsVendorSandboxUserModel {
    SingleSandboxUser,
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
            network: match policy.network.mode {
                NetworkMode::Disabled => WindowsVendorNetworkPolicy::Disabled,
                NetworkMode::Proxy => WindowsVendorNetworkPolicy::Proxy,
            },
            sandbox_user_model: WindowsVendorSandboxUserModel::SingleSandboxUser,
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

    pub(crate) fn read_roots(&self) -> Vec<String> {
        self.entries_with_access(WindowsVendorFilesystemAccess::Read)
    }

    pub(crate) fn write_roots(&self) -> Vec<String> {
        self.entries_with_access(WindowsVendorFilesystemAccess::Write)
    }

    pub(crate) fn deny_roots(&self) -> Vec<String> {
        self.entries_with_access(WindowsVendorFilesystemAccess::Deny)
    }

    pub(crate) fn network_policy(&self) -> Option<WindowsVendorNetworkPolicy> {
        match self {
            Self::Disabled => None,
            Self::Managed { network, .. } => Some(*network),
        }
    }

    pub(crate) fn sandbox_user_model(&self) -> Option<WindowsVendorSandboxUserModel> {
        match self {
            Self::Disabled => None,
            Self::Managed {
                sandbox_user_model, ..
            } => Some(*sandbox_user_model),
        }
    }

    fn entries_with_access(&self, access: WindowsVendorFilesystemAccess) -> Vec<String> {
        match self {
            Self::Disabled => Vec::new(),
            Self::Managed { filesystem, .. } => filesystem
                .entries
                .iter()
                .filter(|entry| entry.access == access)
                .map(|entry| entry.path.clone())
                .collect(),
        }
    }
}

impl WindowsVendorSandboxUserModel {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SingleSandboxUser => "single-sandbox-user",
        }
    }

    pub(crate) fn setup_identity_artifacts(self) -> &'static str {
        match self {
            Self::SingleSandboxUser => "single-sandbox-user-artifacts",
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
        &policy.filesystem.read_only,
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
                network: WindowsVendorNetworkPolicy::Proxy,
                sandbox_user_model: WindowsVendorSandboxUserModel::SingleSandboxUser,
            }
        );
        assert_eq!(
            profile.token_mode(),
            Some(WindowsVendorTokenMode::WritableRootsCapability)
        );
        assert_eq!(
            profile.sandbox_user_model(),
            Some(WindowsVendorSandboxUserModel::SingleSandboxUser)
        );
        assert_eq!(
            profile.network_policy(),
            Some(WindowsVendorNetworkPolicy::Proxy)
        );
        assert_eq!(
            profile.read_roots(),
            vec![cwd.to_string_lossy().to_string()]
        );
        assert_eq!(
            profile.write_roots(),
            vec![cwd.to_string_lossy().to_string()]
        );
        assert_eq!(
            profile.deny_roots(),
            [".git", ".agents", ".codex"]
                .into_iter()
                .map(|path| cwd.join(path).to_string_lossy().to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn danger_full_access_maps_to_disabled_vendor_profile() {
        let cwd = PathBuf::from("C:/workspace");
        let policy = normalize_policy(&json!("danger-full-access"), &cwd, None).unwrap();
        let profile = WindowsVendorSandboxProfile::from_policy(&policy);

        assert_eq!(profile, WindowsVendorSandboxProfile::Disabled);
        assert_eq!(profile.token_mode(), None);
        assert_eq!(profile.sandbox_user_model(), None);
        assert_eq!(profile.network_policy(), None);
        assert!(profile.read_roots().is_empty());
        assert!(profile.write_roots().is_empty());
        assert!(profile.deny_roots().is_empty());
    }
}
