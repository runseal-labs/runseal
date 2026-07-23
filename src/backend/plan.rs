use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformSandboxPlan {
    pub backend: &'static str,
    pub backend_status: &'static str,
    pub platform: &'static str,
    pub execution_id: String,
    pub policy_id: String,
    pub policy_hash: String,
    pub sandbox_level: &'static str,
    pub enforcement: &'static str,
    pub cwd: String,
    pub runtime_root: Option<String>,
    pub profile_root: Option<String>,
    pub synthetic_home: Option<String>,
    pub temp_root: Option<String>,
    pub filesystem_read: Vec<String>,
    pub filesystem_write: Vec<String>,
    pub filesystem_deny: Vec<String>,
    pub filesystem_protected: Vec<&'static str>,
    pub(super) private_filesystem_deny: Vec<String>,
    pub(super) private_filesystem_rules: Vec<WindowsFilesystemRule>,
    pub(super) private_portable_read_roots: Vec<String>,
    pub(super) private_portable_write_roots: Vec<String>,
    pub(super) private_portable_deny_roots: Vec<String>,
    pub process_boundary: &'static str,
    pub process_identity: &'static str,
    pub process_cleanup: &'static str,
    pub(super) private_process_sandbox_user_model: &'static str,
    pub(super) private_process_token: &'static str,
    pub(super) private_process_job: &'static str,
    pub(super) private_setup_account_name: &'static str,
    pub(super) private_setup_group_name: &'static str,
    pub(super) private_setup_identity_artifacts: &'static str,
    pub(super) private_setup_payload: Option<String>,
    pub(super) private_vendor_permission_profile: Option<String>,
    pub network_mode: &'static str,
    pub network_direct_egress: &'static str,
    pub network_managed_proxy: &'static str,
    pub environment_inherit: String,
    pub environment_scrub: Vec<String>,
    pub environment_proxy: bool,
    pub environment_runtime: Vec<(String, String)>,
    pub required_backend_features: Vec<&'static str>,
}

impl PlatformSandboxPlan {
    pub(super) fn local_execution(
        backend: &dyn SandboxBackend,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Self {
        Self {
            backend: backend.name(),
            backend_status: backend.status(),
            platform: backend.platform(),
            execution_id: execution_id.to_string(),
            policy_id: policy.id.clone(),
            policy_hash: policy.hash(),
            sandbox_level: policy.sandbox_level.as_str(),
            enforcement: "local-execution",
            cwd: path_string(cwd),
            runtime_root: None,
            profile_root: None,
            synthetic_home: None,
            temp_root: None,
            filesystem_read: policy
                .filesystem
                .read
                .iter()
                .chain(policy.filesystem.read_only.iter())
                .cloned()
                .collect(),
            filesystem_write: policy.filesystem.write.clone(),
            filesystem_deny: policy.filesystem.deny.clone(),
            filesystem_protected: protected_filesystem_labels(policy),
            private_filesystem_deny: Vec::new(),
            private_filesystem_rules: Vec::new(),
            private_portable_read_roots: Vec::new(),
            private_portable_write_roots: Vec::new(),
            private_portable_deny_roots: Vec::new(),
            process_boundary: "local-process",
            process_identity: "current-user",
            process_cleanup: "direct-child",
            private_process_sandbox_user_model: "current-user",
            private_process_token: "none",
            private_process_job: "none",
            private_setup_account_name: "current-user",
            private_setup_group_name: "current-user",
            private_setup_identity_artifacts: "current-user",
            private_setup_payload: None,
            private_vendor_permission_profile: None,
            network_mode: policy.network.mode.as_str(),
            network_direct_egress: "unmanaged",
            network_managed_proxy: "none",
            environment_inherit: policy.environment.inherit.clone(),
            environment_scrub: policy.environment.scrub.clone(),
            environment_proxy: policy.environment.proxy,
            environment_runtime: Vec::new(),
            required_backend_features: policy.required_backend_feature_names(),
        }
    }

    pub(super) fn portable_fail_closed_preview(
        backend: &dyn SandboxBackend,
        execution_id: &str,
        _cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Self {
        let runtime_roots = [
            "runtime_root".to_string(),
            "profile_root".to_string(),
            "synthetic_home".to_string(),
            "temp_root".to_string(),
        ];
        Self {
            backend: backend.name(),
            backend_status: backend.status(),
            platform: backend.platform(),
            execution_id: execution_id.to_string(),
            policy_id: policy.id.clone(),
            policy_hash: policy.hash(),
            sandbox_level: policy.sandbox_level.as_str(),
            enforcement: "fail-closed-preview",
            cwd: "workspace".to_string(),
            runtime_root: Some(runtime_roots[0].clone()),
            profile_root: Some(runtime_roots[1].clone()),
            synthetic_home: Some(runtime_roots[2].clone()),
            temp_root: Some(runtime_roots[3].clone()),
            filesystem_read: vec!["workspace".to_string()],
            filesystem_write: runtime_roots.to_vec(),
            filesystem_deny: if policy.filesystem.deny.is_empty() {
                Vec::new()
            } else {
                vec!["policy_denied_roots".to_string()]
            },
            filesystem_protected: protected_filesystem_labels(policy),
            private_filesystem_deny: Vec::new(),
            private_filesystem_rules: Vec::new(),
            private_portable_read_roots: Vec::new(),
            private_portable_write_roots: Vec::new(),
            private_portable_deny_roots: Vec::new(),
            process_boundary: "platform-sandbox",
            process_identity: "current-user",
            process_cleanup: "process-tree",
            private_process_sandbox_user_model: "none",
            private_process_token: "none",
            private_process_job: "none",
            private_setup_account_name: "none",
            private_setup_group_name: "none",
            private_setup_identity_artifacts: "none",
            private_setup_payload: None,
            private_vendor_permission_profile: None,
            network_mode: policy.network.mode.as_str(),
            network_direct_egress: network_direct_egress(policy),
            network_managed_proxy: "none",
            environment_inherit: policy.environment.inherit.clone(),
            environment_scrub: policy.environment.scrub.clone(),
            environment_proxy: policy.environment.proxy,
            environment_runtime: Vec::new(),
            required_backend_features: policy.required_backend_feature_names(),
        }
    }

    pub(super) fn linux_experimental(
        backend: &dyn SandboxBackend,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Self {
        let runtime_root = cwd.join(".runseal").join("runtime").join(execution_id);
        let profile_root = runtime_root.join("profile");
        let synthetic_home = runtime_root.join("home");
        let temp_root = runtime_root.join("tmp");
        Self {
            backend: backend.name(),
            backend_status: backend.status(),
            platform: backend.platform(),
            execution_id: execution_id.to_string(),
            policy_id: policy.id.clone(),
            policy_hash: policy.hash(),
            sandbox_level: policy.sandbox_level.as_str(),
            enforcement: "linux-experimental",
            cwd: path_string(cwd),
            runtime_root: Some(path_string(&runtime_root)),
            profile_root: Some(path_string(&profile_root)),
            synthetic_home: Some(path_string(&synthetic_home)),
            temp_root: Some(path_string(&temp_root)),
            filesystem_read: vec!["workspace".to_string()],
            filesystem_write: portable_experimental_write_labels(policy),
            filesystem_deny: if policy.filesystem.deny.is_empty() {
                Vec::new()
            } else {
                vec!["policy_denied_roots".to_string()]
            },
            filesystem_protected: protected_filesystem_labels(policy),
            private_filesystem_deny: Vec::new(),
            private_filesystem_rules: Vec::new(),
            private_portable_read_roots: policy
                .filesystem
                .read
                .iter()
                .chain(policy.filesystem.read_only.iter())
                .cloned()
                .collect(),
            private_portable_write_roots: policy.filesystem.write.clone(),
            private_portable_deny_roots: policy.filesystem.deny.clone(),
            process_boundary: "platform-sandbox",
            process_identity: "current-user",
            process_cleanup: "process-tree",
            private_process_sandbox_user_model: "none",
            private_process_token: "none",
            private_process_job: "none",
            private_setup_account_name: "none",
            private_setup_group_name: "none",
            private_setup_identity_artifacts: "none",
            private_setup_payload: None,
            private_vendor_permission_profile: None,
            network_mode: policy.network.mode.as_str(),
            network_direct_egress: network_direct_egress(policy),
            network_managed_proxy: "none",
            environment_inherit: policy.environment.inherit.clone(),
            environment_scrub: policy.environment.scrub.clone(),
            environment_proxy: policy.environment.proxy,
            environment_runtime: vec![
                (
                    "RUNSEAL_HOME".to_string(),
                    path_string(synthetic_home.as_path()),
                ),
                ("RUNSEAL_TMP".to_string(), path_string(temp_root.as_path())),
                ("HOME".to_string(), path_string(synthetic_home.as_path())),
                ("TMPDIR".to_string(), path_string(temp_root.as_path())),
            ],
            required_backend_features: policy.required_backend_feature_names(),
        }
    }

    pub(super) fn linux_read_only_experimental(
        backend: &dyn SandboxBackend,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Self {
        Self::linux_experimental(backend, execution_id, cwd, policy)
    }

    pub(super) fn linux_workspace_write_experimental(
        backend: &dyn SandboxBackend,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Self {
        Self::linux_experimental(backend, execution_id, cwd, policy)
    }

    pub(super) fn linux_workspace_contained_experimental(
        backend: &dyn SandboxBackend,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Self {
        Self::linux_experimental(backend, execution_id, cwd, policy)
    }

    pub(super) fn macos_read_only_experimental(
        backend: &dyn SandboxBackend,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Self {
        let mut plan = Self::linux_experimental(backend, execution_id, cwd, policy);
        plan.enforcement = "macos-experimental";
        plan
    }

    pub(super) fn macos_workspace_write_experimental(
        backend: &dyn SandboxBackend,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Self {
        let mut plan = Self::linux_experimental(backend, execution_id, cwd, policy);
        plan.enforcement = "macos-experimental";
        plan
    }

    pub(super) fn macos_workspace_contained_experimental(
        backend: &dyn SandboxBackend,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Self {
        let mut plan = Self::linux_experimental(backend, execution_id, cwd, policy);
        plan.enforcement = "macos-experimental";
        plan
    }

    pub fn json(&self) -> Value {
        json!({
            "backend": {
                "name": self.backend,
                "status": self.backend_status,
                "platform": self.platform,
            },
            "execution_id": self.execution_id,
            "policy_id": self.policy_id,
            "policy_hash": self.policy_hash,
            "sandbox_level": self.sandbox_level,
            "enforcement": self.enforcement,
            "cwd": self.cwd.clone(),
            "runtime_root": self.runtime_root.clone(),
            "profile_root": self.profile_root.clone(),
            "synthetic_home": self.synthetic_home.clone(),
            "temp_root": self.temp_root.clone(),
            "filesystem": {
                "read": self.filesystem_read.clone(),
                "write": self.filesystem_write.clone(),
                "deny": self.filesystem_deny.clone(),
                "protected": self.filesystem_protected.clone(),
            },
            "process": {
                "boundary": self.process_boundary,
                "identity": self.process_identity,
                "cleanup": self.process_cleanup,
            },
            "network": {
                "mode": self.network_mode,
                "direct_egress": self.network_direct_egress,
                "managed_proxy": self.network_managed_proxy,
            },
            "environment": {
                "inherit": self.environment_inherit.clone(),
                "scrub": self.environment_scrub.clone(),
                "proxy": self.environment_proxy,
                "runtime": environment_runtime_json(&self.environment_runtime),
            },
            "setup": self.setup_json(),
            "required_backend_features": self.required_backend_features.clone(),
        })
    }
    fn setup_json(&self) -> Value {
        json!({
            "requires_runtime_roots": self.runtime_root.is_some(),
            "requires_runtime_environment": !self.environment_runtime.is_empty(),
            "requires_runtime_cleanup": self.runtime_root.is_some(),
            "requires_network_guard": self.network_direct_egress == "deny",
            "requires_managed_proxy": self.network_managed_proxy == "required",
            "requires_process_boundary": self.process_boundary != "local-process",
            "fail_closed_on_setup_error": self.is_sandbox_enforced(),
        })
    }

    pub fn prepare_sandbox_setup(&self) -> io::Result<PreparedSandboxSetup> {
        self.prepare_sandbox_setup_with_driver(new_windows_filesystem_acl_driver())
    }

    pub(super) fn prepare_sandbox_setup_with_driver(
        &self,
        mut filesystem_driver: Box<dyn WindowsFilesystemAclDriver>,
    ) -> io::Result<PreparedSandboxSetup> {
        self.validate_private_process_setup()?;
        self.validate_private_network_setup()?;
        let mut prepared_roots = self.prepare_runtime_roots()?;
        match self.prepare_filesystem_rules_with_driver(filesystem_driver.as_mut()) {
            Ok(filesystem_roots) => extend_unique(&mut prepared_roots, filesystem_roots),
            Err(setup_err) => {
                self.cleanup_runtime_roots()?;
                return Err(setup_err);
            }
        }
        Ok(PreparedSandboxSetup {
            prepared_roots,
            filesystem_driver,
        })
    }

    fn validate_private_process_setup(&self) -> io::Result<()> {
        if !self.is_sandbox_enforced() {
            return Ok(());
        }
        if self.process_boundary == "restricted-local-process"
            && self.process_identity == "low-privilege"
            && self.process_cleanup == "process-tree"
            && self.private_process_sandbox_user_model == "single-sandbox-user"
            && self.private_process_token == "restricted-token"
            && self.private_process_job == "kill-on-close-job"
            && self.private_setup_account_name == "RunSealSandbox"
            && self.private_setup_group_name == "RunSealSandboxUsers"
            && self.private_setup_identity_artifacts == "single-sandbox-user-artifacts"
            && has_single_user_setup_payload(self.private_setup_payload.as_deref())
        {
            return Ok(());
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sandboxed plan requires a single sandbox user restricted process boundary and setup identity artifacts",
        ))
    }

    fn validate_private_network_setup(&self) -> io::Result<()> {
        if !self.is_sandbox_enforced() {
            return Ok(());
        }
        if matches!(
            (
                self.network_mode,
                self.network_direct_egress,
                self.network_managed_proxy,
            ),
            ("unmanaged", "unmanaged", "none")
                | ("disabled", "deny", "none")
                | ("proxy", "deny", "required")
        ) {
            return Ok(());
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sandboxed plan requires a valid network guard",
        ))
    }

    pub fn prepare_runtime_roots(&self) -> io::Result<Vec<String>> {
        self.validate_runtime_roots_for_setup()?;
        let runtime_root_existed = self
            .runtime_root
            .as_ref()
            .is_some_and(|root| Path::new(root).exists());
        let result = (|| {
            let mut prepared = Vec::new();
            for root in [
                self.runtime_root.as_ref(),
                self.profile_root.as_ref(),
                self.synthetic_home.as_ref(),
                self.temp_root.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                prepare_unique_runtime_root(&mut prepared, root)?;
            }
            for (key, root) in &self.environment_runtime {
                if !runtime_environment_value_is_path(key) {
                    continue;
                }
                prepare_unique_runtime_root(&mut prepared, root)?;
            }
            if let Some(runtime_root) = &self.runtime_root {
                fs::write(
                    Path::new(runtime_root).join(RUNTIME_ROOT_MARKER),
                    self.execution_id.as_bytes(),
                )?;
            }
            Ok(prepared)
        })();

        match result {
            Ok(prepared) => Ok(prepared),
            Err(setup_err) => {
                if !runtime_root_existed
                    && let Some(runtime_root) = &self.runtime_root
                    && Path::new(runtime_root).exists()
                    && let Err(cleanup_err) = fs::remove_dir_all(runtime_root)
                {
                    return Err(io::Error::other(format!(
                        "runtime setup failed ({setup_err}); runtime cleanup failed ({cleanup_err})"
                    )));
                }
                Err(setup_err)
            }
        }
    }

    #[cfg(test)]
    pub(super) fn prepare_filesystem_rules(&self) -> io::Result<Vec<String>> {
        let mut driver = new_windows_filesystem_acl_driver();
        self.prepare_filesystem_rules_with_driver(driver.as_mut())
    }

    pub(super) fn prepare_filesystem_rules_with_driver(
        &self,
        driver: &mut dyn WindowsFilesystemAclDriver,
    ) -> io::Result<Vec<String>> {
        let acl_plan = WindowsFilesystemAclPlan::from_rules(&self.private_filesystem_rules);
        let transaction = WindowsFilesystemAclTransactionPlan::from_acl_plan(&acl_plan);
        validate_private_filesystem_acl_transaction(&transaction)?;
        validate_private_filesystem_acl_entries(&transaction)?;
        let subject = self.private_filesystem_acl_subject(&transaction)?;
        apply_private_filesystem_acl_transaction(&transaction, subject, driver)?;

        Ok(transaction.rollback_roots().to_vec())
    }

    fn private_filesystem_acl_subject(
        &self,
        transaction: &WindowsFilesystemAclTransactionPlan,
    ) -> io::Result<Option<WindowsFilesystemAclSubject>> {
        if transaction.apply_entries().next().is_none() {
            return Ok(None);
        }
        WindowsFilesystemAclSubject::from_plan(
            self.process_identity,
            self.private_process_sandbox_user_model,
            self.private_process_token,
        )
        .map(Some)
    }

    pub(super) fn cleanup_sandbox_setup_with_driver(
        &self,
        driver: &mut dyn WindowsFilesystemAclDriver,
    ) -> io::Result<Vec<String>> {
        let mut cleaned = self.cleanup_filesystem_rules_with_driver(driver)?;
        extend_unique(&mut cleaned, self.cleanup_runtime_roots()?);
        Ok(cleaned)
    }

    fn cleanup_filesystem_rules_with_driver(
        &self,
        driver: &mut dyn WindowsFilesystemAclDriver,
    ) -> io::Result<Vec<String>> {
        let acl_plan = WindowsFilesystemAclPlan::from_rules(&self.private_filesystem_rules);
        let transaction = WindowsFilesystemAclTransactionPlan::from_acl_plan(&acl_plan);
        validate_private_filesystem_acl_transaction(&transaction)?;
        validate_private_filesystem_acl_entries(&transaction)?;

        let cleaned = transaction.rollback_roots().to_vec();
        if cleaned.is_empty() {
            return Ok(cleaned);
        }

        driver.rollback()?;
        Ok(cleaned)
    }

    pub fn cleanup_runtime_roots(&self) -> io::Result<Vec<String>> {
        let Some(runtime_root) = &self.runtime_root else {
            return Ok(Vec::new());
        };
        let runtime_root = Path::new(runtime_root);
        self.validate_runtime_root_for_cleanup(runtime_root)?;
        if runtime_root.exists() {
            fs::remove_dir_all(runtime_root)?;
            Ok(vec![path_string(runtime_root)])
        } else {
            Ok(Vec::new())
        }
    }

    pub fn is_sandbox_enforced(&self) -> bool {
        self.enforcement != "local-execution"
    }

    #[cfg(windows)]
    pub(super) fn vendor_permission_profile(&self) -> io::Result<PermissionProfile> {
        let Some(permission_profile) = &self.private_vendor_permission_profile else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sandboxed plan is missing vendor permission profile",
            ));
        };
        serde_json::from_str(permission_profile).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid vendor permission profile: {err}"),
            )
        })
    }

    fn validate_runtime_roots_for_setup(&self) -> io::Result<()> {
        let Some(runtime_root) = &self.runtime_root else {
            return Ok(());
        };
        let expected = normalize_lexical(&self.expected_runtime_root()?);
        let workspace = normalize_lexical(Path::new(&self.cwd));
        validate_runtime_root_ancestors(&expected, &workspace, "prepare")?;
        let runtime_root = Path::new(runtime_root);
        if normalize_lexical(runtime_root) != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to prepare runtime root outside planned workspace runtime directory: {}",
                    runtime_root.display()
                ),
            ));
        }
        self.validate_runtime_root_path_for_setup(runtime_root, &expected)?;
        validate_runtime_tree_has_no_symlinks(runtime_root, "prepare")?;
        self.validate_runtime_marker_for_setup(runtime_root)?;
        for root in [
            self.profile_root.as_ref(),
            self.synthetic_home.as_ref(),
            self.temp_root.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            self.validate_runtime_root_path_for_setup(Path::new(root), &expected)?;
        }
        for (key, root) in &self.environment_runtime {
            if !runtime_environment_value_is_path(key) {
                continue;
            }
            self.validate_runtime_root_path_for_setup(Path::new(root), &expected)?;
        }
        Ok(())
    }

    fn validate_runtime_marker_for_setup(&self, runtime_root: &Path) -> io::Result<()> {
        if !runtime_root.exists() {
            return Ok(());
        }
        let marker = runtime_root.join(RUNTIME_ROOT_MARKER);
        if !runtime_marker_is_regular_file(&marker)?
            || fs::read_to_string(&marker)? != self.execution_id
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to prepare runtime root with mismatched marker: {}",
                    runtime_root.display()
                ),
            ));
        }
        Ok(())
    }

    fn validate_runtime_root_path_for_setup(&self, root: &Path, expected: &Path) -> io::Result<()> {
        let root = normalize_lexical(root);
        if !root.starts_with(expected) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to prepare runtime root outside planned workspace runtime directory: {}",
                    root.display()
                ),
            ));
        }
        for ancestor in root.ancestors() {
            if !ancestor.starts_with(expected) {
                break;
            }
            validate_runtime_root_not_symlink(ancestor, "prepare")?;
        }
        Ok(())
    }

    fn validate_runtime_root_for_cleanup(&self, runtime_root: &Path) -> io::Result<()> {
        let expected = normalize_lexical(&self.expected_runtime_root()?);
        if normalize_lexical(runtime_root) != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to clean runtime root outside planned workspace runtime directory: {}",
                    runtime_root.display()
                ),
            ));
        }
        let workspace = normalize_lexical(Path::new(&self.cwd));
        validate_runtime_root_ancestors(&expected, &workspace, "clean")?;
        if !runtime_root.exists() {
            return Ok(());
        }
        let metadata = fs::symlink_metadata(runtime_root)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to clean symlinked runtime root: {}",
                    runtime_root.display()
                ),
            ));
        }
        let marker = runtime_root.join(RUNTIME_ROOT_MARKER);
        if !runtime_marker_is_regular_file(&marker)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to clean unmarked runtime root: {}",
                    runtime_root.display()
                ),
            ));
        }
        if fs::read_to_string(&marker)? != self.execution_id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to clean runtime root with mismatched marker: {}",
                    runtime_root.display()
                ),
            ));
        }
        validate_runtime_tree_has_no_symlinks(runtime_root, "clean")?;
        Ok(())
    }

    fn expected_runtime_root(&self) -> io::Result<PathBuf> {
        let execution_id = Path::new(&self.execution_id);
        if !matches!(execution_id.components().next(), Some(Component::Normal(_)))
            || execution_id.components().count() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid execution id for runtime root: {}",
                    self.execution_id
                ),
            ));
        }
        Ok(Path::new(&self.cwd)
            .join(".runseal")
            .join("runtime")
            .join(&self.execution_id))
    }
}

pub struct PreparedSandboxSetup {
    prepared_roots: Vec<String>,
    filesystem_driver: Box<dyn WindowsFilesystemAclDriver>,
}

impl PreparedSandboxSetup {
    pub fn prepared_roots(&self) -> &[String] {
        &self.prepared_roots
    }

    pub fn cleanup(mut self, plan: &PlatformSandboxPlan) -> io::Result<Vec<String>> {
        plan.cleanup_sandbox_setup_with_driver(self.filesystem_driver.as_mut())
    }
}

fn extend_unique(target: &mut Vec<String>, source: Vec<String>) {
    for item in source {
        if !target.iter().any(|existing| existing == &item) {
            target.push(item);
        }
    }
}
pub(super) fn environment_runtime_json(entries: &[(String, String)]) -> Value {
    let mut object = Map::new();
    for (key, value) in entries {
        object.insert(key.clone(), json!(value));
    }
    Value::Object(object)
}

fn network_direct_egress(policy: &SandboxPolicy) -> &'static str {
    match policy.network.mode {
        NetworkMode::Unmanaged => "unmanaged",
        NetworkMode::Disabled | NetworkMode::Proxy => "deny",
    }
}

pub(super) fn protected_filesystem_labels(policy: &SandboxPolicy) -> Vec<&'static str> {
    let mut labels = Vec::new();
    if !policy.filesystem.deny.is_empty() {
        labels.push("workspace_metadata");
    }
    if policy.sandbox_level == SandboxLevel::WorkspaceContained {
        labels.push("host_profile");
        labels.push("credential_roots");
    }
    labels
}

fn portable_experimental_write_labels(policy: &SandboxPolicy) -> Vec<String> {
    let mut labels = Vec::new();
    if matches!(
        policy.sandbox_level,
        SandboxLevel::WorkspaceWrite | SandboxLevel::WorkspaceContained
    ) {
        labels.push("workspace".to_string());
    }
    labels.extend([
        "runtime_root".to_string(),
        "profile_root".to_string(),
        "synthetic_home".to_string(),
        "temp_root".to_string(),
    ]);
    labels
}
