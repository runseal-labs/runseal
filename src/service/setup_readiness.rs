use crate::setup::windows_sandbox_setup_status_for_cwd;
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Default)]
pub(super) struct SetupReadinessCache {
    last: Option<(PathBuf, Value)>,
}

impl SetupReadinessCache {
    pub(super) fn refresh(&mut self, cwd: &Path) -> Result<Value, String> {
        let status = windows_sandbox_setup_status_for_cwd(cwd)?;
        self.last = Some((cwd.to_path_buf(), status.clone()));
        Ok(status)
    }

    #[cfg(test)]
    pub(super) fn last(&self) -> Option<(&Path, &Value)> {
        self.last
            .as_ref()
            .map(|(cwd, status)| (cwd.as_path(), status))
    }
}

#[cfg(test)]
mod tests {
    use super::SetupReadinessCache;
    use std::path::Path;

    #[test]
    fn refresh_records_last_setup_status_snapshot() {
        let cwd = Path::new(".");
        let mut cache = SetupReadinessCache::default();

        let status = cache.refresh(cwd).unwrap();

        let (cached_cwd, cached_status) = cache.last().unwrap();
        assert_eq!(cached_cwd, cwd);
        assert_eq!(cached_status, &status);
    }
}
