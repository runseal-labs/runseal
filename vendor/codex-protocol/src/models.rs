use crate::permissions::FileSystemSandboxPolicy;
use crate::permissions::NetworkSandboxPolicy;
use codex_utils_absolute_path::AbsolutePathBuf;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ManagedFileSystemPermissions {
    Restricted {
        entries: Vec<crate::permissions::FileSystemSandboxEntry>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        glob_scan_max_depth: Option<usize>,
    },
    Unrestricted,
}

impl ManagedFileSystemPermissions {
    pub fn from_sandbox_policy(policy: &FileSystemSandboxPolicy) -> Self {
        match policy.kind {
            crate::permissions::FileSystemSandboxKind::Restricted => Self::Restricted {
                entries: policy.entries.clone(),
                glob_scan_max_depth: policy.glob_scan_max_depth,
            },
            crate::permissions::FileSystemSandboxKind::Unrestricted
            | crate::permissions::FileSystemSandboxKind::ExternalSandbox => Self::Unrestricted,
        }
    }

    pub fn to_sandbox_policy(&self) -> FileSystemSandboxPolicy {
        match self {
            Self::Restricted {
                entries,
                glob_scan_max_depth,
            } => FileSystemSandboxPolicy {
                kind: crate::permissions::FileSystemSandboxKind::Restricted,
                entries: entries.clone(),
                glob_scan_max_depth: *glob_scan_max_depth,
            },
            Self::Unrestricted => FileSystemSandboxPolicy::unrestricted(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PermissionProfile {
    Managed {
        file_system: ManagedFileSystemPermissions,
        network: NetworkSandboxPolicy,
    },
    Disabled,
    External {
        network: NetworkSandboxPolicy,
    },
}

impl Default for PermissionProfile {
    fn default() -> Self {
        Self::read_only()
    }
}

impl PermissionProfile {
    pub fn read_only() -> Self {
        let file_system = FileSystemSandboxPolicy::read_only();
        Self::Managed {
            file_system: ManagedFileSystemPermissions::from_sandbox_policy(&file_system),
            network: NetworkSandboxPolicy::Restricted,
        }
    }

    pub fn workspace_write() -> Self {
        Self::workspace_write_with(&[], NetworkSandboxPolicy::Restricted, false, false)
    }

    pub fn workspace_write_with(
        writable_roots: &[AbsolutePathBuf],
        network: NetworkSandboxPolicy,
        exclude_tmpdir_env_var: bool,
        exclude_slash_tmp: bool,
    ) -> Self {
        let file_system = FileSystemSandboxPolicy::workspace_write(
            writable_roots,
            exclude_tmpdir_env_var,
            exclude_slash_tmp,
        );
        Self::Managed {
            file_system: ManagedFileSystemPermissions::from_sandbox_policy(&file_system),
            network,
        }
    }

    pub fn materialize_project_roots_with_workspace_roots(
        self,
        workspace_roots: &[AbsolutePathBuf],
    ) -> Self {
        match self {
            Self::Managed {
                file_system,
                network,
            } => {
                let file_system = file_system
                    .to_sandbox_policy()
                    .materialize_project_roots_with_workspace_roots(workspace_roots);
                Self::Managed {
                    file_system: ManagedFileSystemPermissions::from_sandbox_policy(&file_system),
                    network,
                }
            }
            Self::Disabled => Self::Disabled,
            Self::External { network } => Self::External { network },
        }
    }

    pub fn to_runtime_permissions(&self) -> (FileSystemSandboxPolicy, NetworkSandboxPolicy) {
        match self {
            Self::Managed {
                file_system,
                network,
            } => (file_system.to_sandbox_policy(), *network),
            Self::Disabled => (
                FileSystemSandboxPolicy::unrestricted(),
                NetworkSandboxPolicy::Enabled,
            ),
            Self::External { network } => (FileSystemSandboxPolicy::external_sandbox(), *network),
        }
    }
}
