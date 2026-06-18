pub mod models;
pub mod permissions;

pub mod config_types {
    use serde::Deserialize;
    use serde::Serialize;
    use std::fmt;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum WindowsSandboxLevel {
        Disabled,
        RestrictedToken,
        Elevated,
    }

    impl fmt::Display for WindowsSandboxLevel {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Disabled => f.write_str("disabled"),
                Self::RestrictedToken => f.write_str("restricted-token"),
                Self::Elevated => f.write_str("elevated"),
            }
        }
    }
}
