use codex_utils_absolute_path::AbsolutePathBuf;
use serde::Deserialize;
use serde::Serialize;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkSandboxPolicy {
    #[default]
    Restricted,
    Enabled,
}

impl NetworkSandboxPolicy {
    pub fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileSystemAccessMode {
    Read,
    Write,
    #[serde(alias = "none")]
    Deny,
}

impl FileSystemAccessMode {
    pub fn can_read(self) -> bool {
        !matches!(self, Self::Deny)
    }

    pub fn can_write(self) -> bool {
        matches!(self, Self::Write)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FileSystemSpecialPath {
    Root,
    Minimal,
    #[serde(alias = "current_working_directory")]
    ProjectRoots {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subpath: Option<PathBuf>,
    },
    Tmpdir,
    SlashTmp,
    Unknown {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subpath: Option<PathBuf>,
    },
}

impl FileSystemSpecialPath {
    pub fn project_roots(subpath: Option<PathBuf>) -> Self {
        Self::ProjectRoots { subpath }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FileSystemPath {
    Path { path: AbsolutePathBuf },
    GlobPattern { pattern: String },
    Special { value: FileSystemSpecialPath },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileSystemSandboxEntry {
    pub path: FileSystemPath,
    pub access: FileSystemAccessMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum FileSystemSandboxKind {
    #[default]
    Restricted,
    Unrestricted,
    ExternalSandbox,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSystemSandboxPolicy {
    pub kind: FileSystemSandboxKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glob_scan_max_depth: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<FileSystemSandboxEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WritableRoot {
    pub root: AbsolutePathBuf,
    pub read_only_subpaths: Vec<AbsolutePathBuf>,
}

const PROJECT_ROOTS_GLOB_PATTERN_PREFIX: &str = "codex-project-roots://";

pub fn project_roots_glob_pattern(subpath: &Path) -> String {
    format!("{PROJECT_ROOTS_GLOB_PATTERN_PREFIX}{}", subpath.display())
}

impl Default for FileSystemSandboxPolicy {
    fn default() -> Self {
        Self::read_only()
    }
}

impl FileSystemSandboxPolicy {
    pub fn read_only() -> Self {
        Self::restricted(vec![FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            access: FileSystemAccessMode::Read,
        }])
    }

    pub fn unrestricted() -> Self {
        Self {
            kind: FileSystemSandboxKind::Unrestricted,
            glob_scan_max_depth: None,
            entries: Vec::new(),
        }
    }

    pub fn external_sandbox() -> Self {
        Self {
            kind: FileSystemSandboxKind::ExternalSandbox,
            glob_scan_max_depth: None,
            entries: Vec::new(),
        }
    }

    pub fn restricted(entries: Vec<FileSystemSandboxEntry>) -> Self {
        Self {
            kind: FileSystemSandboxKind::Restricted,
            glob_scan_max_depth: None,
            entries,
        }
    }

    pub fn workspace_write(
        writable_roots: &[AbsolutePathBuf],
        exclude_tmpdir_env_var: bool,
        exclude_slash_tmp: bool,
    ) -> Self {
        let mut entries = vec![FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            access: FileSystemAccessMode::Read,
        }];
        entries.push(FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::project_roots(None),
            },
            access: FileSystemAccessMode::Write,
        });
        for protected in [".git", ".agents", ".codex"] {
            entries.push(FileSystemSandboxEntry {
                path: FileSystemPath::Special {
                    value: FileSystemSpecialPath::project_roots(Some(protected.into())),
                },
                access: FileSystemAccessMode::Read,
            });
        }
        if !exclude_slash_tmp {
            entries.push(FileSystemSandboxEntry {
                path: FileSystemPath::Special {
                    value: FileSystemSpecialPath::SlashTmp,
                },
                access: FileSystemAccessMode::Write,
            });
        }
        if !exclude_tmpdir_env_var {
            entries.push(FileSystemSandboxEntry {
                path: FileSystemPath::Special {
                    value: FileSystemSpecialPath::Tmpdir,
                },
                access: FileSystemAccessMode::Write,
            });
        }
        entries.extend(
            writable_roots
                .iter()
                .cloned()
                .map(|path| FileSystemSandboxEntry {
                    path: FileSystemPath::Path { path },
                    access: FileSystemAccessMode::Write,
                }),
        );
        Self::restricted(entries)
    }

    pub fn materialize_project_roots_with_workspace_roots(
        &self,
        workspace_roots: &[AbsolutePathBuf],
    ) -> Self {
        let mut entries = Vec::new();
        for entry in &self.entries {
            match &entry.path {
                FileSystemPath::Special {
                    value: FileSystemSpecialPath::ProjectRoots { subpath },
                } => {
                    for root in workspace_roots {
                        let path = match subpath {
                            Some(subpath) => root.join(subpath),
                            None => root.clone(),
                        };
                        entries.push(FileSystemSandboxEntry {
                            path: FileSystemPath::Path { path },
                            access: entry.access,
                        });
                    }
                }
                FileSystemPath::GlobPattern { pattern }
                    if pattern.starts_with(PROJECT_ROOTS_GLOB_PATTERN_PREFIX) =>
                {
                    let suffix = &pattern[PROJECT_ROOTS_GLOB_PATTERN_PREFIX.len()..];
                    for root in workspace_roots {
                        entries.push(FileSystemSandboxEntry {
                            path: FileSystemPath::GlobPattern {
                                pattern: root.join(suffix).to_string_lossy().into_owned(),
                            },
                            access: entry.access,
                        });
                    }
                }
                _ => entries.push(entry.clone()),
            }
        }
        Self {
            kind: self.kind,
            glob_scan_max_depth: self.glob_scan_max_depth,
            entries,
        }
    }

    pub fn has_full_disk_read_access(&self) -> bool {
        match self.kind {
            FileSystemSandboxKind::Unrestricted => true,
            FileSystemSandboxKind::ExternalSandbox => false,
            FileSystemSandboxKind::Restricted => self.entries.iter().any(|entry| {
                entry.access.can_read()
                    && matches!(
                        &entry.path,
                        FileSystemPath::Special {
                            value: FileSystemSpecialPath::Root
                        }
                    )
            }),
        }
    }

    pub fn has_full_disk_write_access(&self) -> bool {
        match self.kind {
            FileSystemSandboxKind::Unrestricted => true,
            FileSystemSandboxKind::ExternalSandbox => false,
            FileSystemSandboxKind::Restricted => self.entries.iter().any(|entry| {
                entry.access.can_write()
                    && matches!(
                        &entry.path,
                        FileSystemPath::Special {
                            value: FileSystemSpecialPath::Root
                        }
                    )
            }),
        }
    }

    pub fn include_platform_defaults(&self) -> bool {
        !self.has_full_disk_read_access()
    }

    pub fn get_readable_roots_with_cwd(&self, cwd: &Path) -> Vec<AbsolutePathBuf> {
        self.entries
            .iter()
            .filter(|entry| entry.access.can_read())
            .filter_map(|entry| absolute_entry_path(&entry.path, cwd))
            .collect()
    }

    pub fn get_writable_roots_with_cwd(&self, cwd: &Path) -> Vec<WritableRoot> {
        let mut roots = self
            .entries
            .iter()
            .filter(|entry| entry.access.can_write())
            .filter_map(|entry| absolute_entry_path(&entry.path, cwd))
            .map(|root| WritableRoot {
                root,
                read_only_subpaths: Vec::new(),
            })
            .collect::<Vec<_>>();

        for entry in self
            .entries
            .iter()
            .filter(|entry| entry.access.can_read() && !entry.access.can_write())
        {
            let Some(read_only_path) = absolute_entry_path(&entry.path, cwd) else {
                continue;
            };
            for writable_root in &mut roots {
                if read_only_path
                    .as_path()
                    .starts_with(writable_root.root.as_path())
                {
                    writable_root
                        .read_only_subpaths
                        .push(read_only_path.clone());
                }
            }
        }

        roots
    }

    pub fn get_unreadable_roots_with_cwd(&self, cwd: &Path) -> Vec<AbsolutePathBuf> {
        self.entries
            .iter()
            .filter(|entry| entry.access == FileSystemAccessMode::Deny)
            .filter_map(|entry| absolute_entry_path(&entry.path, cwd))
            .collect()
    }

    pub fn get_unreadable_globs_with_cwd(&self, cwd: &Path) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| entry.access == FileSystemAccessMode::Deny)
            .filter_map(|entry| match &entry.path {
                FileSystemPath::GlobPattern { pattern } => Some(
                    AbsolutePathBuf::resolve_path_against_base(pattern, cwd)
                        .to_string_lossy()
                        .into_owned(),
                ),
                _ => None,
            })
            .collect()
    }
}

fn absolute_entry_path(path: &FileSystemPath, cwd: &Path) -> Option<AbsolutePathBuf> {
    match path {
        FileSystemPath::Path { path } => Some(path.clone()),
        FileSystemPath::Special {
            value: FileSystemSpecialPath::Root,
        } => AbsolutePathBuf::from_absolute_path(root_path()).ok(),
        FileSystemPath::Special {
            value: FileSystemSpecialPath::Tmpdir,
        } => std::env::var_os("TMP")
            .or_else(|| std::env::var_os("TEMP"))
            .and_then(|value| AbsolutePathBuf::from_absolute_path(PathBuf::from(value)).ok()),
        FileSystemPath::Special {
            value: FileSystemSpecialPath::SlashTmp,
        } if cfg!(windows) => None,
        FileSystemPath::Special {
            value: FileSystemSpecialPath::SlashTmp,
        } => AbsolutePathBuf::from_absolute_path("/tmp").ok(),
        FileSystemPath::Special {
            value: FileSystemSpecialPath::ProjectRoots { subpath },
        } => Some(match subpath {
            Some(subpath) => AbsolutePathBuf::resolve_path_against_base(subpath, cwd),
            None => AbsolutePathBuf::from_absolute_path(cwd).ok()?,
        }),
        _ => None,
    }
}

fn root_path() -> &'static Path {
    if cfg!(windows) {
        Path::new(r"C:\")
    } else {
        Path::new("/")
    }
}

pub struct ReadDenyMatcher {
    roots: Vec<PathBuf>,
    globs: Vec<glob::Pattern>,
}

impl ReadDenyMatcher {
    pub fn new(file_system_sandbox_policy: &FileSystemSandboxPolicy, cwd: &Path) -> Option<Self> {
        Self::try_new(file_system_sandbox_policy, cwd)
            .ok()
            .flatten()
    }

    pub fn try_new(
        file_system_sandbox_policy: &FileSystemSandboxPolicy,
        cwd: &Path,
    ) -> Result<Option<Self>, String> {
        let roots = file_system_sandbox_policy
            .get_unreadable_roots_with_cwd(cwd)
            .into_iter()
            .map(AbsolutePathBuf::into_path_buf)
            .collect::<Vec<_>>();
        let globs = file_system_sandbox_policy
            .get_unreadable_globs_with_cwd(cwd)
            .into_iter()
            .map(|pattern| glob::Pattern::new(&pattern).map_err(|err| err.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        if roots.is_empty() && globs.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Self { roots, globs }))
        }
    }

    pub fn is_read_denied(&self, path: &Path) -> bool {
        let normalized = dunce::simplified(path).to_path_buf();
        self.roots.iter().any(|root| normalized.starts_with(root))
            || self
                .globs
                .iter()
                .any(|pattern| pattern.matches_path(&normalized))
    }
}
