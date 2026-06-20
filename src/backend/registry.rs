use super::core::ActiveBackend;
use super::skeleton::{LinuxCommunityBackend, LocalBackend, MacosExperimentalBackend};
use super::windows::WindowsReferenceBackend;

pub fn active_backend() -> ActiveBackend {
    if cfg!(windows) {
        ActiveBackend::WindowsReference(WindowsReferenceBackend)
    } else if cfg!(target_os = "macos") {
        ActiveBackend::MacosExperimental(MacosExperimentalBackend)
    } else if cfg!(target_os = "linux") {
        ActiveBackend::LinuxCommunity(LinuxCommunityBackend)
    } else {
        ActiveBackend::Local(LocalBackend)
    }
}
