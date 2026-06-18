use crate::policy::{NetworkMode, SandboxPolicy};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowsPolicyPlan {
    pub(crate) filesystem: WindowsFilesystemPlan,
    pub(crate) network: WindowsNetworkPlan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowsFilesystemPlan {
    pub(crate) mode: WindowsFilesystemMode,
    pub(crate) read_roots: Vec<String>,
    pub(crate) write_roots: Vec<String>,
    pub(crate) runtime_write_roots: Vec<String>,
    pub(crate) protected_roots: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsFilesystemMode {
    ReadOnlyCapability,
    WritableRootsCapability,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WindowsNetworkPlan {
    pub(crate) guard: WindowsNetworkGuard,
    pub(crate) inject_proxy_environment: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsNetworkGuard {
    Disabled,
    Proxy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowsRuntimeRoots {
    pub(crate) runtime_root: String,
    pub(crate) profile_root: String,
    pub(crate) synthetic_home: String,
    pub(crate) temp_root: String,
}

impl WindowsNetworkGuard {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Proxy => "proxy",
        }
    }
}

impl WindowsPolicyPlan {
    pub(crate) fn from_policy_and_runtime_roots(
        policy: &SandboxPolicy,
        runtime_roots: Option<WindowsRuntimeRoots>,
    ) -> Self {
        let mode = if policy.filesystem.write.is_empty() {
            WindowsFilesystemMode::ReadOnlyCapability
        } else {
            WindowsFilesystemMode::WritableRootsCapability
        };
        let guard = match policy.network.mode {
            NetworkMode::Disabled => WindowsNetworkGuard::Disabled,
            NetworkMode::Proxy => WindowsNetworkGuard::Proxy,
        };

        Self {
            filesystem: WindowsFilesystemPlan {
                mode,
                read_roots: policy.filesystem.read.clone(),
                write_roots: policy.filesystem.write.clone(),
                runtime_write_roots: runtime_roots
                    .map(WindowsRuntimeRoots::write_roots)
                    .unwrap_or_default(),
                protected_roots: policy.filesystem.deny.clone(),
            },
            network: WindowsNetworkPlan {
                guard,
                inject_proxy_environment: guard == WindowsNetworkGuard::Proxy
                    && policy.environment.proxy,
            },
        }
    }
}

impl WindowsFilesystemPlan {
    pub(crate) fn effective_write_roots(&self) -> Vec<String> {
        let mut roots = Vec::new();
        for root in self
            .write_roots
            .iter()
            .chain(self.runtime_write_roots.iter())
        {
            push_unique(&mut roots, root.clone());
        }
        roots
    }
}

impl WindowsRuntimeRoots {
    pub(crate) fn new(
        runtime_root: String,
        profile_root: String,
        synthetic_home: String,
        temp_root: String,
    ) -> Self {
        Self {
            runtime_root,
            profile_root,
            synthetic_home,
            temp_root,
        }
    }

    fn write_roots(self) -> Vec<String> {
        let mut roots = Vec::new();
        for root in [
            self.runtime_root,
            self.profile_root,
            self.synthetic_home,
            self.temp_root,
        ] {
            push_unique(&mut roots, root);
        }
        roots
    }
}

fn push_unique(roots: &mut Vec<String>, root: String) {
    if !roots.contains(&root) {
        roots.push(root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{NetworkMode, normalize_policy};
    use serde_json::json;
    use std::path::PathBuf;

    #[test]
    fn read_only_policy_uses_read_only_capability_plan() {
        let cwd = PathBuf::from("/workspace");
        let policy = normalize_policy(&json!("read-only"), &cwd, None).unwrap();

        let plan = WindowsPolicyPlan::from_policy_and_runtime_roots(&policy, None);

        assert_eq!(
            plan.filesystem.mode,
            WindowsFilesystemMode::ReadOnlyCapability
        );
        assert_eq!(plan.filesystem.read_roots, vec!["/workspace"]);
        assert!(plan.filesystem.write_roots.is_empty());
        assert!(plan.filesystem.runtime_write_roots.is_empty());
        assert!(plan.filesystem.effective_write_roots().is_empty());
        assert!(plan.filesystem.protected_roots.is_empty());
        assert_eq!(plan.network.guard, WindowsNetworkGuard::Disabled);
        assert!(!plan.network.inject_proxy_environment);
    }

    #[test]
    fn workspace_write_policy_uses_writable_roots_plan() {
        let cwd = PathBuf::from("/workspace");
        let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
        let protected_roots = [".git", ".agents", ".codex"]
            .into_iter()
            .map(|path| cwd.join(path).to_string_lossy().to_string())
            .collect::<Vec<_>>();

        let plan = WindowsPolicyPlan::from_policy_and_runtime_roots(&policy, None);

        assert_eq!(
            plan.filesystem.mode,
            WindowsFilesystemMode::WritableRootsCapability
        );
        assert_eq!(plan.filesystem.read_roots, vec!["/workspace"]);
        assert_eq!(plan.filesystem.write_roots, vec!["/workspace"]);
        assert!(plan.filesystem.runtime_write_roots.is_empty());
        assert_eq!(plan.filesystem.effective_write_roots(), vec!["/workspace"]);
        assert_eq!(plan.filesystem.protected_roots, protected_roots);
        assert_eq!(plan.network.guard, WindowsNetworkGuard::Proxy);
        assert!(plan.network.inject_proxy_environment);
    }

    #[test]
    fn runtime_roots_are_effective_writable_roots_without_changing_policy_roots() {
        let cwd = PathBuf::from("/workspace");
        let policy = normalize_policy(&json!("read-only"), &cwd, None).unwrap();
        let runtime_roots = WindowsRuntimeRoots::new(
            "/workspace/.runseal/runtime/exec_1".to_string(),
            "/workspace/.runseal/runtime/exec_1/profile".to_string(),
            "/workspace/.runseal/runtime/exec_1/home".to_string(),
            "/workspace/.runseal/runtime/exec_1/temp".to_string(),
        );

        let plan = WindowsPolicyPlan::from_policy_and_runtime_roots(&policy, Some(runtime_roots));

        assert!(plan.filesystem.write_roots.is_empty());
        assert_eq!(
            plan.filesystem.runtime_write_roots,
            vec![
                "/workspace/.runseal/runtime/exec_1",
                "/workspace/.runseal/runtime/exec_1/profile",
                "/workspace/.runseal/runtime/exec_1/home",
                "/workspace/.runseal/runtime/exec_1/temp",
            ]
        );
        assert_eq!(
            plan.filesystem.effective_write_roots(),
            plan.filesystem.runtime_write_roots
        );
    }

    #[test]
    fn runtime_write_roots_are_deduplicated_with_policy_write_roots() {
        let cwd = PathBuf::from("/workspace");
        let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();
        let runtime_roots = WindowsRuntimeRoots::new(
            "/workspace".to_string(),
            "/workspace/.runseal/runtime/exec_1/profile".to_string(),
            "/workspace/.runseal/runtime/exec_1/home".to_string(),
            "/workspace/.runseal/runtime/exec_1/temp".to_string(),
        );

        let plan = WindowsPolicyPlan::from_policy_and_runtime_roots(&policy, Some(runtime_roots));

        assert_eq!(
            plan.filesystem.effective_write_roots(),
            vec![
                "/workspace",
                "/workspace/.runseal/runtime/exec_1/profile",
                "/workspace/.runseal/runtime/exec_1/home",
                "/workspace/.runseal/runtime/exec_1/temp",
            ]
        );
    }

    #[test]
    fn workspace_contained_network_override_uses_disabled_guard() {
        let cwd = PathBuf::from("/workspace");
        let policy = normalize_policy(
            &json!("workspace-contained"),
            &cwd,
            Some(NetworkMode::Disabled),
        )
        .unwrap();

        let plan = WindowsPolicyPlan::from_policy_and_runtime_roots(&policy, None);

        assert_eq!(
            plan.filesystem.mode,
            WindowsFilesystemMode::WritableRootsCapability
        );
        assert_eq!(plan.network.guard, WindowsNetworkGuard::Disabled);
        assert!(!plan.network.inject_proxy_environment);
    }
}
