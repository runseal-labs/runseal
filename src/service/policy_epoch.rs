use crate::policy::SandboxPolicy;

#[derive(Default)]
pub(super) struct PolicyEpochRuntime {
    current_epoch: Option<String>,
}

impl PolicyEpochRuntime {
    pub(super) fn bind(&mut self, policy: &SandboxPolicy) -> String {
        let epoch = policy.hash();
        self.current_epoch = Some(epoch.clone());
        epoch
    }

    #[cfg(test)]
    pub(super) fn current(&self) -> Option<&str> {
        self.current_epoch.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::PolicyEpochRuntime;
    use crate::policy::normalize_policy;
    use serde_json::json;
    use std::path::Path;

    #[test]
    fn bind_tracks_current_policy_epoch() {
        let cwd = Path::new(".");
        let policy = normalize_policy(&json!("danger-full-access"), cwd, None).unwrap();
        let mut runtime = PolicyEpochRuntime::default();

        let epoch = runtime.bind(&policy);

        assert_eq!(runtime.current(), Some(epoch.as_str()));
        assert_eq!(epoch, policy.hash());
    }
}
