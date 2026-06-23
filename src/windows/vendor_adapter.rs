use crate::policy::{NetworkMode, SandboxPolicy};
#[cfg(windows)]
use codex_protocol::models::{ManagedFileSystemPermissions, PermissionProfile};
#[cfg(windows)]
use codex_protocol::permissions::{
    FileSystemAccessMode, FileSystemPath, FileSystemSandboxEntry, FileSystemSandboxPolicy,
    NetworkSandboxPolicy,
};
#[cfg(windows)]
use codex_utils_absolute_path::AbsolutePathBuf;
use serde_json::{Value, json};
use std::path::Path;

const SETUP_PAYLOAD_VERSION: u32 = 6;

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
    Unmanaged,
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
                NetworkMode::Unmanaged => WindowsVendorNetworkPolicy::Unmanaged,
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

    #[cfg(windows)]
    pub(crate) fn permission_profile(&self) -> Result<PermissionProfile, String> {
        let Self::Managed {
            filesystem,
            network,
            ..
        } = self
        else {
            return Ok(PermissionProfile::Disabled);
        };

        let entries = filesystem
            .entries
            .iter()
            .map(codex_filesystem_entry)
            .collect::<Result<Vec<_>, _>>()?;
        let file_system = FileSystemSandboxPolicy::restricted(entries);

        Ok(PermissionProfile::Managed {
            file_system: ManagedFileSystemPermissions::from_sandbox_policy(&file_system),
            network: match network {
                WindowsVendorNetworkPolicy::Unmanaged => NetworkSandboxPolicy::Enabled,
                WindowsVendorNetworkPolicy::Disabled | WindowsVendorNetworkPolicy::Proxy => {
                    NetworkSandboxPolicy::Restricted
                }
            },
        })
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

    pub(crate) fn single_user_setup_payload(
        &self,
        codex_home: &Path,
        command_cwd: &Path,
        real_user: &str,
    ) -> Option<Value> {
        let Self::Managed {
            sandbox_user_model, ..
        } = self
        else {
            return None;
        };
        #[cfg(windows)]
        if self.permission_profile().is_err() {
            return None;
        }

        Some(json!({
            "version": SETUP_PAYLOAD_VERSION,
            "sandbox_username": sandbox_user_model.local_account_name(),
            "codex_home": path_string(codex_home),
            "command_cwd": path_string(command_cwd),
            "read_roots": self.read_roots(),
            "write_roots": self.write_roots(),
            "deny_read_paths": self.deny_roots(),
            "deny_write_paths": Vec::<String>::new(),
            "proxy_ports": Vec::<u16>::new(),
            "allow_local_binding": false,
            "real_user": real_user,
            "mode": "full",
            "refresh_only": false,
        }))
    }
}

#[cfg(windows)]
fn codex_filesystem_entry(
    entry: &WindowsVendorFilesystemEntry,
) -> Result<FileSystemSandboxEntry, String> {
    let path = AbsolutePathBuf::from_absolute_path_checked(Path::new(&entry.path))
        .map_err(|err| format!("invalid filesystem path {}: {err}", entry.path))?;
    Ok(FileSystemSandboxEntry {
        path: FileSystemPath::Path { path },
        access: codex_access_mode(entry.access),
    })
}

#[cfg(windows)]
fn codex_access_mode(access: WindowsVendorFilesystemAccess) -> FileSystemAccessMode {
    match access {
        WindowsVendorFilesystemAccess::Read => FileSystemAccessMode::Read,
        WindowsVendorFilesystemAccess::Write => FileSystemAccessMode::Write,
        WindowsVendorFilesystemAccess::Deny => FileSystemAccessMode::Deny,
    }
}

impl WindowsVendorSandboxUserModel {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SingleSandboxUser => "single-sandbox-user",
        }
    }

    pub(crate) fn local_account_name(self) -> &'static str {
        match self {
            Self::SingleSandboxUser => "RunSealSandbox",
        }
    }

    pub(crate) fn local_group_name(self) -> &'static str {
        match self {
            Self::SingleSandboxUser => "RunSealSandboxUsers",
        }
    }

    pub(crate) fn setup_identity_artifacts(self) -> &'static str {
        match self {
            Self::SingleSandboxUser => "single-sandbox-user-artifacts",
        }
    }
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn filesystem_entries(policy: &SandboxPolicy) -> Vec<WindowsVendorFilesystemEntry> {
    let mut entries = Vec::new();
    let write_roots = policy.filesystem.write.clone();
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
        &write_roots,
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
                network: WindowsVendorNetworkPolicy::Unmanaged,
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
            Some(WindowsVendorNetworkPolicy::Unmanaged)
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
        assert_eq!(profile.single_user_setup_payload(&cwd, &cwd, "User"), None);
    }

    #[cfg(windows)]
    #[test]
    fn managed_profile_builds_codex_windows_permissions() {
        let cwd = PathBuf::from("C:/workspace");
        let policy = match normalize_policy(&json!("workspace-write"), &cwd, None) {
            Ok(policy) => policy,
            Err(err) => panic!("workspace-write policy must normalize: {}", err.reason),
        };
        let profile = WindowsVendorSandboxProfile::from_policy(&policy);
        let permission_profile = match profile.permission_profile() {
            Ok(permission_profile) => permission_profile,
            Err(err) => panic!("vendor permission profile must build: {err}"),
        };
        let workspace_root = match AbsolutePathBuf::from_absolute_path_checked(&cwd) {
            Ok(path) => path,
            Err(err) => panic!("workspace root must be absolute: {err}"),
        };
        if let Err(err) =
            codex_windows_sandbox::ResolvedWindowsSandboxPermissions::try_from_permission_profile_for_workspace_roots(
                &permission_profile,
                &[workspace_root],
            )
        {
            panic!("codex windows sandbox permissions must resolve: {err}");
        }
        let (file_system, network) = permission_profile.to_runtime_permissions();

        assert_eq!(network, NetworkSandboxPolicy::Enabled);
        assert_eq!(file_system.entries.len(), 5);
        assert_eq!(
            file_system
                .entries
                .iter()
                .filter(|entry| entry.access == FileSystemAccessMode::Write)
                .count(),
            1
        );
    }

    #[cfg(windows)]
    #[test]
    fn disabled_profile_builds_disabled_codex_permission_profile() {
        let cwd = PathBuf::from("C:/workspace");
        let policy = match normalize_policy(&json!("danger-full-access"), &cwd, None) {
            Ok(policy) => policy,
            Err(err) => panic!("danger-full-access policy must normalize: {}", err.reason),
        };
        let profile = WindowsVendorSandboxProfile::from_policy(&policy);
        let permission_profile = match profile.permission_profile() {
            Ok(permission_profile) => permission_profile,
            Err(err) => panic!("vendor permission profile must build: {err}"),
        };

        assert_eq!(permission_profile, PermissionProfile::Disabled);
    }

    #[test]
    fn setup_payload_uses_one_sandbox_identity() {
        let cwd = PathBuf::from("C:/workspace");
        let codex_home = PathBuf::from("C:/runseal/sandbox");
        let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
        let profile = WindowsVendorSandboxProfile::from_policy(&policy);
        let payload = profile
            .single_user_setup_payload(&codex_home, &cwd, "User")
            .unwrap();

        assert_eq!(payload["version"], SETUP_PAYLOAD_VERSION);
        assert_eq!(payload["sandbox_username"], "RunSealSandbox");
        assert_eq!(payload["codex_home"], "C:/runseal/sandbox");
        assert_eq!(payload["command_cwd"], "C:/workspace");
        assert_eq!(payload["deny_write_paths"], json!([]));
        assert_eq!(payload["proxy_ports"], json!([]));
        assert_eq!(payload["allow_local_binding"], false);
        assert_eq!(payload["real_user"], "User");
        assert_eq!(payload["mode"], "full");
        assert_eq!(payload["refresh_only"], false);
        assert_eq!(payload.get("sandbox_home"), None);
        assert_eq!(payload.get("network"), None);
        let serialized = payload.to_string();
        assert!(!serialized.contains("offline"));
        assert!(!serialized.contains("online"));
    }
}
