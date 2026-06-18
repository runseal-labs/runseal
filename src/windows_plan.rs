use crate::policy::{NetworkMode, SandboxLevel, SandboxPolicy};
use std::env;
use std::path::Path;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowsPolicyPlan {
    pub(crate) filesystem: WindowsFilesystemPlan,
    pub(crate) network: WindowsNetworkPlan,
    pub(crate) environment: WindowsEnvironmentPlan,
    pub(crate) process: WindowsProcessPlan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowsFilesystemPlan {
    pub(crate) mode: WindowsFilesystemMode,
    pub(crate) read_roots: Vec<String>,
    pub(crate) write_roots: Vec<String>,
    pub(crate) runtime_write_roots: Vec<String>,
    pub(crate) protected_roots: Vec<String>,
    pub(crate) private_protected_roots: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsFilesystemMode {
    ReadOnlyCapability,
    WritableRootsCapability,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowsFilesystemRule {
    pub(crate) access: WindowsFilesystemAccess,
    pub(crate) root: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsFilesystemAccess {
    Deny,
    ReadWrite,
    ReadOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WindowsNetworkPlan {
    pub(crate) guard: WindowsNetworkGuard,
    pub(crate) direct_egress: WindowsDirectEgress,
    pub(crate) managed_proxy: WindowsManagedProxy,
    pub(crate) inject_proxy_environment: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsNetworkGuard {
    Disabled,
    Proxy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsDirectEgress {
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsManagedProxy {
    None,
    Required,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowsEnvironmentPlan {
    pub(crate) runtime: Vec<(String, String)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WindowsProcessPlan {
    pub(crate) boundary: WindowsProcessBoundary,
    pub(crate) identity: WindowsProcessIdentity,
    pub(crate) cleanup: WindowsProcessCleanup,
    pub(crate) token: WindowsProcessToken,
    pub(crate) job: WindowsProcessJob,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsProcessBoundary {
    RestrictedLocalProcess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsProcessIdentity {
    LowPrivilegeSandbox,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsProcessCleanup {
    ProcessTree,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsProcessToken {
    Restricted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsProcessJob {
    KillOnClose,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowsRuntimeRoots {
    pub(crate) runtime_root: String,
    pub(crate) profile_root: String,
    pub(crate) synthetic_home: String,
    pub(crate) temp_root: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct WindowsHostRoots {
    profile_root: Option<String>,
    appdata_root: Option<String>,
    local_appdata_root: Option<String>,
}

impl WindowsNetworkGuard {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Proxy => "proxy",
        }
    }
}

impl WindowsDirectEgress {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
        }
    }
}

impl WindowsManagedProxy {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Required => "required",
        }
    }
}

impl WindowsProcessPlan {
    fn sandboxed() -> Self {
        Self {
            boundary: WindowsProcessBoundary::RestrictedLocalProcess,
            identity: WindowsProcessIdentity::LowPrivilegeSandbox,
            cleanup: WindowsProcessCleanup::ProcessTree,
            token: WindowsProcessToken::Restricted,
            job: WindowsProcessJob::KillOnClose,
        }
    }
}

impl WindowsProcessBoundary {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::RestrictedLocalProcess => "restricted-local-process",
        }
    }
}

impl WindowsProcessIdentity {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::LowPrivilegeSandbox => "low-privilege",
        }
    }
}

impl WindowsProcessCleanup {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ProcessTree => "process-tree",
        }
    }
}

impl WindowsProcessToken {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Restricted => "restricted-token",
        }
    }
}

impl WindowsProcessJob {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::KillOnClose => "kill-on-close-job",
        }
    }
}

impl WindowsPolicyPlan {
    #[cfg(test)]
    pub(crate) fn from_policy_and_runtime_roots(
        policy: &SandboxPolicy,
        runtime_roots: Option<WindowsRuntimeRoots>,
    ) -> Self {
        Self::from_policy_runtime_and_host_roots(policy, runtime_roots, WindowsHostRoots::default())
    }

    pub(crate) fn from_policy_runtime_and_host_roots(
        policy: &SandboxPolicy,
        runtime_roots: Option<WindowsRuntimeRoots>,
        host_roots: WindowsHostRoots,
    ) -> Self {
        let runtime_write_roots = runtime_roots
            .as_ref()
            .map(WindowsRuntimeRoots::write_roots)
            .unwrap_or_default();
        let runtime_environment = runtime_roots
            .as_ref()
            .map(WindowsRuntimeRoots::environment)
            .unwrap_or_default();
        let mode = if policy.filesystem.write.is_empty() {
            WindowsFilesystemMode::ReadOnlyCapability
        } else {
            WindowsFilesystemMode::WritableRootsCapability
        };
        let guard = match policy.network.mode {
            NetworkMode::Disabled => WindowsNetworkGuard::Disabled,
            NetworkMode::Proxy => WindowsNetworkGuard::Proxy,
        };
        let managed_proxy = match guard {
            WindowsNetworkGuard::Disabled => WindowsManagedProxy::None,
            WindowsNetworkGuard::Proxy => WindowsManagedProxy::Required,
        };

        Self {
            filesystem: WindowsFilesystemPlan {
                mode,
                read_roots: policy.filesystem.read.clone(),
                write_roots: policy.filesystem.write.clone(),
                runtime_write_roots,
                protected_roots: policy.filesystem.deny.clone(),
                private_protected_roots: host_roots.protected_roots(policy),
            },
            network: WindowsNetworkPlan {
                guard,
                direct_egress: WindowsDirectEgress::Deny,
                managed_proxy,
                inject_proxy_environment: guard == WindowsNetworkGuard::Proxy
                    && policy.environment.proxy,
            },
            environment: WindowsEnvironmentPlan {
                runtime: runtime_environment,
            },
            process: WindowsProcessPlan::sandboxed(),
        }
    }
}

impl WindowsHostRoots {
    pub(crate) fn new(
        profile_root: Option<String>,
        appdata_root: Option<String>,
        local_appdata_root: Option<String>,
    ) -> Self {
        Self {
            profile_root,
            appdata_root,
            local_appdata_root,
        }
    }

    pub(crate) fn from_current_environment() -> Self {
        Self::new(
            env_path("USERPROFILE").or_else(|| env_path("HOME")),
            env_path("APPDATA"),
            env_path("LOCALAPPDATA"),
        )
    }

    fn protected_roots(&self, policy: &SandboxPolicy) -> Vec<String> {
        if policy.sandbox_level != SandboxLevel::WorkspaceContained {
            return Vec::new();
        }

        let mut roots = Vec::new();
        if let Some(root) = &self.profile_root {
            push_unique(&mut roots, root.clone());
            for child in [
                ".ssh",
                ".aws",
                ".azure",
                ".config/gcloud",
                ".docker",
                ".kube",
            ] {
                push_unique(&mut roots, join_runtime_path(root, child));
            }
        }
        if let Some(root) = &self.appdata_root {
            push_unique(&mut roots, root.clone());
            for child in ["gh", "GitHub CLI"] {
                push_unique(&mut roots, join_runtime_path(root, child));
            }
        }
        if let Some(root) = &self.local_appdata_root {
            push_unique(&mut roots, root.clone());
            push_unique(&mut roots, join_runtime_path(root, "Google/Cloud SDK"));
        }
        roots
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

    pub(crate) fn enforcement_rules(&self) -> Vec<WindowsFilesystemRule> {
        let mut rules = Vec::new();
        let mut deny_roots = Vec::new();
        for root in self
            .protected_roots
            .iter()
            .chain(self.private_protected_roots.iter())
        {
            push_unique_root(&mut deny_roots, root.clone());
            push_filesystem_rule(&mut rules, WindowsFilesystemAccess::Deny, root.clone());
        }

        let mut writable_roots = Vec::new();
        for root in self.effective_write_roots() {
            if contains_windows_root(&deny_roots, &root) {
                continue;
            }
            push_unique_root(&mut writable_roots, root.clone());
            push_filesystem_rule(&mut rules, WindowsFilesystemAccess::ReadWrite, root);
        }

        for root in &self.read_roots {
            if contains_windows_root(&deny_roots, root)
                || contains_windows_root(&writable_roots, root)
            {
                continue;
            }
            push_filesystem_rule(&mut rules, WindowsFilesystemAccess::ReadOnly, root.clone());
        }

        rules
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

    fn write_roots(&self) -> Vec<String> {
        let mut roots = Vec::new();
        for root in [
            self.runtime_root.clone(),
            self.profile_root.clone(),
            self.synthetic_home.clone(),
            self.temp_root.clone(),
        ] {
            push_unique(&mut roots, root);
        }
        roots
    }

    fn environment(&self) -> Vec<(String, String)> {
        vec![
            ("RUNSEAL_HOME".to_string(), self.synthetic_home.clone()),
            ("RUNSEAL_TMP".to_string(), self.temp_root.clone()),
            ("HOME".to_string(), self.synthetic_home.clone()),
            ("USERPROFILE".to_string(), self.profile_root.clone()),
            (
                "APPDATA".to_string(),
                join_runtime_path(&self.profile_root, "AppData/Roaming"),
            ),
            (
                "LOCALAPPDATA".to_string(),
                join_runtime_path(&self.profile_root, "AppData/Local"),
            ),
            ("TEMP".to_string(), self.temp_root.clone()),
            ("TMP".to_string(), self.temp_root.clone()),
        ]
    }
}

fn push_unique(roots: &mut Vec<String>, root: String) {
    if !roots.contains(&root) {
        roots.push(root);
    }
}

fn push_unique_root(roots: &mut Vec<String>, root: String) {
    if !contains_windows_root(roots, &root) {
        roots.push(root);
    }
}

fn push_filesystem_rule(
    rules: &mut Vec<WindowsFilesystemRule>,
    access: WindowsFilesystemAccess,
    root: String,
) {
    if rules
        .iter()
        .any(|rule| rule.access == access && same_windows_root(&rule.root, &root))
    {
        return;
    }

    rules.push(WindowsFilesystemRule { access, root });
}

fn contains_windows_root(roots: &[String], candidate: &str) -> bool {
    roots.iter().any(|root| same_windows_root(root, candidate))
}

fn same_windows_root(left: &str, right: &str) -> bool {
    windows_root_key(left) == windows_root_key(right)
}

fn windows_root_key(root: &str) -> String {
    let mut normalized = root.replace('/', "\\");
    while normalized.len() > 3 && normalized.ends_with('\\') {
        normalized.pop();
    }
    normalized.to_ascii_lowercase()
}

fn join_runtime_path(root: &str, child: &str) -> String {
    Path::new(root).join(child).to_string_lossy().to_string()
}

fn env_path(key: &str) -> Option<String> {
    env::var_os(key)
        .filter(|value| !value.is_empty())
        .map(|value| Path::new(&value).to_string_lossy().to_string())
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
        assert!(plan.filesystem.private_protected_roots.is_empty());
        assert_eq!(plan.network.guard, WindowsNetworkGuard::Disabled);
        assert_eq!(plan.network.direct_egress, WindowsDirectEgress::Deny);
        assert_eq!(plan.network.managed_proxy, WindowsManagedProxy::None);
        assert!(!plan.network.inject_proxy_environment);
        assert!(plan.environment.runtime.is_empty());
        assert_eq!(
            plan.process.boundary,
            WindowsProcessBoundary::RestrictedLocalProcess
        );
        assert_eq!(
            plan.process.identity,
            WindowsProcessIdentity::LowPrivilegeSandbox
        );
        assert_eq!(plan.process.cleanup, WindowsProcessCleanup::ProcessTree);
        assert_eq!(plan.process.token, WindowsProcessToken::Restricted);
        assert_eq!(plan.process.job, WindowsProcessJob::KillOnClose);
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
        assert!(plan.filesystem.private_protected_roots.is_empty());
        assert_eq!(plan.network.guard, WindowsNetworkGuard::Proxy);
        assert_eq!(plan.network.direct_egress, WindowsDirectEgress::Deny);
        assert_eq!(plan.network.managed_proxy, WindowsManagedProxy::Required);
        assert!(plan.network.inject_proxy_environment);
        assert!(plan.environment.runtime.is_empty());
    }

    #[test]
    fn filesystem_rules_prioritize_denies_over_workspace_writes() {
        let cwd = PathBuf::from("/workspace");
        let policy = normalize_policy(&json!("workspace-write"), &cwd, None).unwrap();

        let plan = WindowsPolicyPlan::from_policy_and_runtime_roots(&policy, None);
        let rules = plan.filesystem.enforcement_rules();

        assert_eq!(
            rules[0],
            WindowsFilesystemRule {
                access: WindowsFilesystemAccess::Deny,
                root: cwd.join(".git").to_string_lossy().to_string(),
            }
        );
        assert_eq!(
            rules[3],
            WindowsFilesystemRule {
                access: WindowsFilesystemAccess::ReadWrite,
                root: "/workspace".to_string(),
            }
        );
        assert!(
            rules.iter().all(|rule| rule.root != "/workspace"
                || rule.access != WindowsFilesystemAccess::ReadOnly)
        );
    }

    #[test]
    fn filesystem_rules_deduplicate_windows_root_spellings() {
        let filesystem = WindowsFilesystemPlan {
            mode: WindowsFilesystemMode::WritableRootsCapability,
            read_roots: vec!["C:/Workspace".to_string(), "c:\\workspace\\".to_string()],
            write_roots: vec!["C:/Workspace".to_string(), "c:\\workspace\\".to_string()],
            runtime_write_roots: Vec::new(),
            protected_roots: vec![
                "C:/Workspace/.Git/".to_string(),
                "c:\\workspace\\.git".to_string(),
            ],
            private_protected_roots: Vec::new(),
        };

        let rules = filesystem.enforcement_rules();

        assert_eq!(
            rules
                .iter()
                .filter(|rule| rule.access == WindowsFilesystemAccess::Deny
                    && same_windows_root(&rule.root, "c:\\workspace\\.git"))
                .count(),
            1
        );
        assert_eq!(
            rules
                .iter()
                .filter(|rule| rule.access == WindowsFilesystemAccess::ReadWrite
                    && same_windows_root(&rule.root, "c:\\workspace"))
                .count(),
            1
        );
        assert_eq!(
            rules
                .iter()
                .filter(|rule| rule.access == WindowsFilesystemAccess::ReadOnly
                    && same_windows_root(&rule.root, "c:\\workspace"))
                .count(),
            0
        );
    }

    #[test]
    fn workspace_contained_uses_private_host_protection_roots() {
        let cwd = PathBuf::from("/workspace");
        let policy = normalize_policy(&json!("workspace-contained"), &cwd, None).unwrap();
        let profile_root = "C:/Users/RunSealUser";
        let appdata_root = "C:/Users/RunSealUser/AppData/Roaming";
        let local_appdata_root = "C:/Users/RunSealUser/AppData/Local";
        let host_roots = WindowsHostRoots::new(
            Some(profile_root.to_string()),
            Some(appdata_root.to_string()),
            Some(local_appdata_root.to_string()),
        );

        let plan = WindowsPolicyPlan::from_policy_runtime_and_host_roots(&policy, None, host_roots);

        assert_eq!(
            plan.filesystem.private_protected_roots,
            vec![
                profile_root.to_string(),
                join_runtime_path(profile_root, ".ssh"),
                join_runtime_path(profile_root, ".aws"),
                join_runtime_path(profile_root, ".azure"),
                join_runtime_path(profile_root, ".config/gcloud"),
                join_runtime_path(profile_root, ".docker"),
                join_runtime_path(profile_root, ".kube"),
                appdata_root.to_string(),
                join_runtime_path(appdata_root, "gh"),
                join_runtime_path(appdata_root, "GitHub CLI"),
                local_appdata_root.to_string(),
                join_runtime_path(local_appdata_root, "Google/Cloud SDK"),
            ]
        );
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
        assert_eq!(
            plan.environment.runtime,
            vec![
                (
                    "RUNSEAL_HOME".to_string(),
                    "/workspace/.runseal/runtime/exec_1/home".to_string()
                ),
                (
                    "RUNSEAL_TMP".to_string(),
                    "/workspace/.runseal/runtime/exec_1/temp".to_string()
                ),
                (
                    "HOME".to_string(),
                    "/workspace/.runseal/runtime/exec_1/home".to_string()
                ),
                (
                    "USERPROFILE".to_string(),
                    "/workspace/.runseal/runtime/exec_1/profile".to_string()
                ),
                (
                    "APPDATA".to_string(),
                    join_runtime_path(
                        "/workspace/.runseal/runtime/exec_1/profile",
                        "AppData/Roaming"
                    )
                ),
                (
                    "LOCALAPPDATA".to_string(),
                    join_runtime_path(
                        "/workspace/.runseal/runtime/exec_1/profile",
                        "AppData/Local"
                    )
                ),
                (
                    "TEMP".to_string(),
                    "/workspace/.runseal/runtime/exec_1/temp".to_string()
                ),
                (
                    "TMP".to_string(),
                    "/workspace/.runseal/runtime/exec_1/temp".to_string()
                ),
            ]
        );

        let rules = plan.filesystem.enforcement_rules();
        assert!(rules.iter().any(|rule| {
            rule.access == WindowsFilesystemAccess::ReadOnly && rule.root == "/workspace"
        }));
        assert!(
            rules.iter().all(|rule| rule.root != "/workspace"
                || rule.access != WindowsFilesystemAccess::ReadWrite)
        );
        assert!(
            rules
                .iter()
                .any(|rule| rule.access == WindowsFilesystemAccess::ReadWrite
                    && rule.root == "/workspace/.runseal/runtime/exec_1/temp")
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
        assert_eq!(plan.network.direct_egress, WindowsDirectEgress::Deny);
        assert_eq!(plan.network.managed_proxy, WindowsManagedProxy::None);
        assert!(!plan.network.inject_proxy_environment);
        assert!(plan.environment.runtime.is_empty());
    }
}
