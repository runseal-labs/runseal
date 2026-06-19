#![windows_subsystem = "windows"]

#[cfg(target_os = "windows")]
mod win;

#[cfg(target_os = "windows")]
fn main() -> anyhow::Result<()> {
    win::main()
}

#[cfg(not(target_os = "windows"))]
fn main() {
    panic!("runseal-windows-sandbox-setup is Windows-only");
}
