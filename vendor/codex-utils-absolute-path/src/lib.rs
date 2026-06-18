use serde::Deserialize;
use serde::Serialize;
use std::borrow::Cow;
use std::path::Display;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AbsolutePathBuf(PathBuf);

impl AbsolutePathBuf {
    pub fn resolve_path_against_base<P: AsRef<Path>, B: AsRef<Path>>(
        path: P,
        base_path: B,
    ) -> Self {
        let path = path.as_ref();
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            base_path.as_ref().join(path)
        };
        Self(normalize_path_for_platform(&absolute).into_owned())
    }

    pub fn from_absolute_path<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let path = path.as_ref();
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        Ok(Self(normalize_path_for_platform(&absolute).into_owned()))
    }

    pub fn from_absolute_path_checked<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("path is not absolute: {}", path.display()),
            ));
        }
        Self::from_absolute_path(path)
    }

    pub fn current_dir() -> std::io::Result<Self> {
        Self::from_absolute_path(std::env::current_dir()?)
    }

    pub fn relative_to_current_dir<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        Ok(Self::resolve_path_against_base(
            path,
            std::env::current_dir()?,
        ))
    }

    pub fn join<P: AsRef<Path>>(&self, path: P) -> Self {
        Self::resolve_path_against_base(path, &self.0)
    }

    pub fn canonicalize(&self) -> std::io::Result<Self> {
        dunce::canonicalize(&self.0).map(Self)
    }

    pub fn parent(&self) -> Option<Self> {
        self.0.parent().map(|path| Self(path.to_path_buf()))
    }

    pub fn ancestors(&self) -> impl Iterator<Item = Self> + '_ {
        self.0.ancestors().map(|path| Self(path.to_path_buf()))
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }

    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }

    pub fn to_path_buf(&self) -> PathBuf {
        self.0.clone()
    }

    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        self.0.to_string_lossy()
    }

    pub fn display(&self) -> Display<'_> {
        self.0.display()
    }
}

fn normalize_path_for_platform(path: &Path) -> Cow<'_, Path> {
    if cfg!(windows)
        && let Some(path) = path.to_str()
        && let Some(normalized) = normalize_windows_device_path(path)
    {
        return Cow::Owned(dunce::simplified(Path::new(&normalized)).to_path_buf());
    }
    Cow::Owned(dunce::simplified(path).to_path_buf())
}

fn normalize_windows_device_path(path: &str) -> Option<String> {
    if let Some(unc) = path.strip_prefix(r"\\?\UNC\") {
        return Some(format!(r"\\{unc}"));
    }
    if let Some(unc) = path.strip_prefix(r"\\.\UNC\") {
        return Some(format!(r"\\{unc}"));
    }
    if let Some(path) = path.strip_prefix(r"\\?\") {
        return Some(path.to_string());
    }
    if let Some(path) = path.strip_prefix(r"\\.\") {
        return Some(path.to_string());
    }
    None
}

impl AsRef<Path> for AbsolutePathBuf {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl std::ops::Deref for AbsolutePathBuf {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<AbsolutePathBuf> for PathBuf {
    fn from(path: AbsolutePathBuf) -> Self {
        path.into_path_buf()
    }
}

impl TryFrom<&Path> for AbsolutePathBuf {
    type Error = std::io::Error;

    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        Self::from_absolute_path(value)
    }
}

impl TryFrom<PathBuf> for AbsolutePathBuf {
    type Error = std::io::Error;

    fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
        Self::from_absolute_path(value)
    }
}

impl TryFrom<&str> for AbsolutePathBuf {
    type Error = std::io::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_absolute_path(value)
    }
}

impl TryFrom<String> for AbsolutePathBuf {
    type Error = std::io::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_absolute_path(value)
    }
}
