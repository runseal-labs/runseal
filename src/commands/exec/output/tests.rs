use super::*;
use std::os::windows::io::{AsHandle, AsRawHandle};
use std::os::windows::process::CommandExt;
use windows_sys::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
use windows_sys::Win32::System::Diagnostics::Debug::{
    CREATE_PROCESS_DEBUG_EVENT, ContinueDebugEvent, DEBUG_EVENT, DebugActiveProcessStop,
    EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, WaitForDebugEvent,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, DEBUG_ONLY_THIS_PROCESS, WaitForSingleObject,
};

#[test]
fn console_cleanup_deadline_includes_pending_native_process_exit() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    let command =
        std::path::PathBuf::from(std::env::var_os("SystemRoot").context("Windows directory")?)
            .join("System32/cmd.exe");
    let child = Command::new(command)
        .args(["/D", "/C", "exit", "0"])
        .creation_flags(DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    struct DebugSession(u32);
    impl Drop for DebugSession {
        fn drop(&mut self) {
            unsafe {
                DebugActiveProcessStop(self.0);
            }
        }
    }
    let process = child.as_handle().try_clone_to_owned()?;
    let mut output = ConsoleOutputWorker::from_child(child)?;
    let _debugger = DebugSession(output.child.as_ref().context("output child")?.id());
    let mut event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
    loop {
        ensure!(
            unsafe { WaitForDebugEvent(&mut event, 5000) } != 0,
            "debug event: {}",
            io::Error::last_os_error()
        );
        match event.dwDebugEventCode {
            EXIT_PROCESS_DEBUG_EVENT => break,
            CREATE_PROCESS_DEBUG_EVENT => unsafe {
                CloseHandle(event.u.CreateProcessInfo.hFile);
            },
            LOAD_DLL_DEBUG_EVENT => unsafe {
                CloseHandle(event.u.LoadDll.hFile);
            },
            _ => {}
        }
        ensure!(
            unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, 0x00010002) } != 0,
            "continue debug event"
        );
    }
    let pending = unsafe {
        WaitForSingleObject(
            output
                .child
                .as_ref()
                .context("output child")?
                .as_raw_handle(),
            0,
        )
    } == WAIT_TIMEOUT;
    let (sender, receiver) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let start = Instant::now();
        let result = output.finish(start + Duration::from_millis(100), true);
        drop(output);
        let _ = sender.send((result, start.elapsed()));
    });
    let bounded = receiver.recv_timeout(Duration::from_millis(500));
    let returned_before_release = bounded.is_ok();
    let continued =
        unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, 0x00010002) } != 0;
    let result = match bounded {
        Ok(result) => result,
        Err(_) => receiver
            .recv_timeout(Duration::from_secs(5))
            .context("cleanup after releasing native exit")?,
    };
    worker
        .join()
        .map_err(|_| anyhow::anyhow!("cleanup worker panicked"))?;
    ensure!(
        unsafe { WaitForSingleObject(process.as_raw_handle(), 2000) } == 0,
        "native process exit after releasing debug event"
    );
    ensure!(
        pending && continued,
        "real native exit must remain pending until released"
    );
    ensure!(
        returned_before_release && result.1 < Duration::from_millis(500),
        "console cleanup exceeded its deadline: {:?}",
        result.1
    );
    ensure!(
        result
            .0
            .is_err_and(|error| error.kind() == io::ErrorKind::TimedOut),
        "unconfirmed native exit must not report cleanup success"
    );
    Ok(())
}
