use crate::desktop::LaunchDesktop;
use crate::desktop::LaunchDesktopMode;
use crate::logging;
use crate::proc_thread_attr::ProcThreadAttributeList;
use crate::winutil::argv_to_command_line;
use crate::winutil::format_last_error;
use crate::winutil::to_wide;
use anyhow::Result;
use anyhow::anyhow;
use std::collections::HashMap;
use std::ffi::c_void;
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Foundation::SetHandleInformation;
use windows_sys::Win32::Security::SECURITY_CAPABILITIES;
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::Console::GetStdHandle;
use windows_sys::Win32::System::Console::STD_ERROR_HANDLE;
use windows_sys::Win32::System::Console::STD_INPUT_HANDLE;
use windows_sys::Win32::System::Console::STD_OUTPUT_HANDLE;
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Pipes::PeekNamedPipe;
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;
use windows_sys::Win32::System::Threading::CREATE_UNICODE_ENVIRONMENT;
use windows_sys::Win32::System::Threading::CreateProcessAsUserW;
use windows_sys::Win32::System::Threading::CreateProcessW;
use windows_sys::Win32::System::Threading::EXTENDED_STARTUPINFO_PRESENT;
use windows_sys::Win32::System::Threading::PROCESS_INFORMATION;
use windows_sys::Win32::System::Threading::STARTF_FORCEOFFFEEDBACK;
use windows_sys::Win32::System::Threading::STARTF_USESTDHANDLES;
use windows_sys::Win32::System::Threading::STARTUPINFOEXW;
use windows_sys::Win32::System::Threading::STARTUPINFOW;

pub struct CreatedProcess {
    pub process_info: PROCESS_INFORMATION,
    pub startup_info: STARTUPINFOW,
    _desktop: LaunchDesktop,
}

#[derive(Clone, Copy)]
pub(crate) enum ProcessIdentity {
    Current,
    PrimaryToken(HANDLE),
}

/// Terminates the owned execution range and verifies that no active processes remain.
///
/// # Safety
/// `raw_job` must be a valid job handle owned by the caller for the entire call.
pub unsafe fn terminate_process_range_and_wait(
    raw_job: usize,
    wait: std::time::Duration,
) -> std::io::Result<()> {
    use windows_sys::Win32::System::JobObjects::{
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
        QueryInformationJobObject, TerminateJobObject,
    };
    let job = raw_job as HANDLE;
    if TerminateJobObject(job, 1) == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let deadline = std::time::Instant::now() + wait;
    loop {
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = std::mem::zeroed();
        if QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            &mut info as *mut _ as *mut _,
            std::mem::size_of_val(&info) as u32,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if info.ActiveProcesses == 0 {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "execution range cleanup deadline exceeded",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

pub fn make_env_block(env: &HashMap<String, String>) -> Vec<u16> {
    let mut items: Vec<(String, String)> =
        env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    items.sort_by(|a, b| {
        a.0.to_uppercase()
            .cmp(&b.0.to_uppercase())
            .then(a.0.cmp(&b.0))
    });
    let mut w: Vec<u16> = Vec::new();
    for (k, v) in items {
        let mut s = to_wide(format!("{k}={v}"));
        s.pop();
        w.extend_from_slice(&s);
        w.push(0);
    }
    w.push(0);
    w
}

unsafe fn ensure_inheritable_stdio(si: &mut STARTUPINFOW) -> Result<()> {
    for kind in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let h = GetStdHandle(kind);
        if h == 0 || h == INVALID_HANDLE_VALUE {
            return Err(anyhow!("GetStdHandle failed: {}", GetLastError()));
        }
        if SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == 0 {
            return Err(anyhow!("SetHandleInformation failed: {}", GetLastError()));
        }
    }
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_FORCEOFFFEEDBACK;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    Ok(())
}

/// # Safety
/// Caller must provide a valid primary token handle (`h_token`) with appropriate access,
/// and the `argv`, `cwd`, and `env_map` must remain valid for the duration of the call.
#[allow(clippy::too_many_arguments)]
pub unsafe fn create_process_as_user(
    h_token: HANDLE,
    argv: &[String],
    cwd: &Path,
    env_map: &HashMap<String, String>,
    logs_base_dir: Option<&Path>,
    stdio: Option<(HANDLE, HANDLE, HANDLE)>,
    desktop_mode: LaunchDesktopMode,
    restricting_sids: &[*mut c_void],
    start_suspended: bool,
    security_capabilities: Option<*mut SECURITY_CAPABILITIES>,
) -> Result<CreatedProcess> {
    create_process_for_identity(
        ProcessIdentity::PrimaryToken(h_token),
        argv,
        cwd,
        env_map,
        logs_base_dir,
        stdio,
        desktop_mode,
        restricting_sids,
        start_suspended,
        security_capabilities,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
unsafe fn create_process_for_identity(
    identity: ProcessIdentity,
    argv: &[String],
    cwd: &Path,
    env_map: &HashMap<String, String>,
    logs_base_dir: Option<&Path>,
    stdio: Option<(HANDLE, HANDLE, HANDLE)>,
    desktop_mode: LaunchDesktopMode,
    restricting_sids: &[*mut c_void],
    start_suspended: bool,
    security_capabilities: Option<*mut SECURITY_CAPABILITIES>,
    control_handle: Option<HANDLE>,
) -> Result<CreatedProcess> {
    let cmdline_str = argv_to_command_line(argv);
    let mut cmdline: Vec<u16> = to_wide(&cmdline_str);
    let env_block = make_env_block(env_map);
    let desktop = LaunchDesktop::prepare(desktop_mode, logs_base_dir, restricting_sids)?;
    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
    let cwd_wide = to_wide(cwd);
    let env_block_len = env_block.len();
    match stdio {
        Some((stdin_h, stdout_h, stderr_h)) => {
            let mut si: STARTUPINFOEXW = std::mem::zeroed();
            si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            // Some processes (e.g., PowerShell) can fail with STATUS_DLL_INIT_FAILED
            // if lpDesktop is not set when launching with a restricted token.
            // Point explicitly at the interactive desktop or a private desktop.
            si.StartupInfo.lpDesktop = desktop.startup_info_desktop();
            si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES | STARTF_FORCEOFFFEEDBACK;
            si.StartupInfo.hStdInput = stdin_h;
            si.StartupInfo.hStdOutput = stdout_h;
            si.StartupInfo.hStdError = stderr_h;
            // The CRT startup table contains only the fixed logical descriptor 3.
            // Standard descriptors are initialized from the explicit stdio handles.
            let mut descriptor_table = Vec::new();
            if let Some(handle) = control_handle {
                descriptor_table.extend_from_slice(&4u32.to_ne_bytes());
                descriptor_table.extend_from_slice(&[0, 0, 0, 0x09]);
                for descriptor in [
                    INVALID_HANDLE_VALUE,
                    INVALID_HANDLE_VALUE,
                    INVALID_HANDLE_VALUE,
                    handle,
                ] {
                    descriptor_table.extend_from_slice(&descriptor.to_ne_bytes());
                }
                si.StartupInfo.cbReserved2 = descriptor_table.len() as u16;
                si.StartupInfo.lpReserved2 = descriptor_table.as_mut_ptr();
            }
            let mut inherited_handles = vec![stdin_h, stdout_h];
            if let Some(handle) = control_handle {
                inherited_handles.push(handle);
            }
            if !inherited_handles.contains(&stderr_h) {
                inherited_handles.push(stderr_h);
            }
            for &handle in &inherited_handles {
                if SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == 0 {
                    return Err(anyhow!(
                        "SetHandleInformation failed for stdio handle: {}",
                        GetLastError()
                    ));
                }
            }
            let mut attrs = ProcThreadAttributeList::new(
                /*attr_count*/ 1 + u32::from(security_capabilities.is_some()),
            )?;
            attrs.set_handle_list(inherited_handles)?;
            if let Some(capabilities) = security_capabilities {
                attrs.set_security_capabilities(capabilities)?;
            }
            si.lpAttributeList = attrs.as_mut_ptr();

            let creation_flags = CREATE_UNICODE_ENVIRONMENT
                | CREATE_NO_WINDOW
                | EXTENDED_STARTUPINFO_PRESENT
                | if start_suspended { CREATE_SUSPENDED } else { 0 };
            let lowbox = security_capabilities.is_some();
            let current_identity = matches!(identity, ProcessIdentity::Current);
            let ok = if lowbox || current_identity {
                CreateProcessW(
                    std::ptr::null(),
                    cmdline.as_mut_ptr(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    1,
                    creation_flags,
                    env_block.as_ptr() as *mut c_void,
                    cwd_wide.as_ptr(),
                    &si.StartupInfo,
                    &mut pi,
                )
            } else {
                let ProcessIdentity::PrimaryToken(token) = identity else {
                    anyhow::bail!("primary token launch expected");
                };
                CreateProcessAsUserW(
                    token,
                    std::ptr::null(),
                    cmdline.as_mut_ptr(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    1,
                    creation_flags,
                    env_block.as_ptr() as *mut c_void,
                    cwd_wide.as_ptr(),
                    &si.StartupInfo,
                    &mut pi,
                )
            };
            let creation_error = (ok == 0).then(|| GetLastError() as i32);
            if let Some(handle) = control_handle
                && SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) == 0
                && ok != 0
            {
                // No retained control endpoint may stay inheritable in this process.
                // Control launches are suspended until their owned range is assigned.
                let cleanup_ok =
                    windows_sys::Win32::System::Threading::TerminateProcess(pi.hProcess, 1) != 0
                        && windows_sys::Win32::System::Threading::WaitForSingleObject(
                            pi.hProcess,
                            10000,
                        ) == 0;
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                if !cleanup_ok {
                    return Err(crate::SandboxCleanupError.into());
                }
                return Err(anyhow!("control endpoint inheritance reset failed"));
            }
            if let Some(err) = creation_error {
                let msg = format!(
                    "{} failed: {} ({}) | env_u16_len={} | si_flags={} | creation_flags={}",
                    if lowbox || current_identity {
                        "CreateProcessW"
                    } else {
                        "CreateProcessAsUserW"
                    },
                    err,
                    format_last_error(err),
                    env_block_len,
                    si.StartupInfo.dwFlags,
                    creation_flags,
                );
                logging::debug_log(&msg, logs_base_dir);
                return Err(anyhow!(msg));
            }
            si.StartupInfo.cbReserved2 = 0;
            si.StartupInfo.lpReserved2 = ptr::null_mut();
            Ok(CreatedProcess {
                process_info: pi,
                startup_info: si.StartupInfo,
                _desktop: desktop,
            })
        }
        None => {
            let ProcessIdentity::PrimaryToken(h_token) = identity else {
                anyhow::bail!("current identity launch requires explicit stdio handles");
            };
            if security_capabilities.is_some() {
                anyhow::bail!("AppContainer process creation requires an explicit handle list");
            }
            let mut si: STARTUPINFOW = std::mem::zeroed();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            si.lpDesktop = desktop.startup_info_desktop();
            ensure_inheritable_stdio(&mut si)?;

            let creation_flags = CREATE_UNICODE_ENVIRONMENT
                | CREATE_NO_WINDOW
                | if start_suspended { CREATE_SUSPENDED } else { 0 };
            let ok = CreateProcessAsUserW(
                h_token,
                std::ptr::null(),
                cmdline.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                1,
                creation_flags,
                env_block.as_ptr() as *mut c_void,
                cwd_wide.as_ptr(),
                &si,
                &mut pi,
            );
            if ok == 0 {
                let err = GetLastError() as i32;
                let msg = format!(
                    "CreateProcessAsUserW failed: {} ({}) | env_u16_len={} | si_flags={} | creation_flags={}",
                    err,
                    format_last_error(err),
                    env_block_len,
                    si.dwFlags,
                    creation_flags,
                );
                logging::debug_log(&msg, logs_base_dir);
                return Err(anyhow!(msg));
            }
            Ok(CreatedProcess {
                process_info: pi,
                startup_info: si,
                _desktop: desktop,
            })
        }
    }
}

/// Controls whether the child's stdin handle is kept open for writing.
#[allow(dead_code)]
pub enum StdinMode {
    Closed,
    Open,
}

/// Controls how stderr is wired for a pipe-spawned process.
#[allow(dead_code)]
pub enum StderrMode {
    MergeStdout,
    Separate,
}

/// Handles returned by `spawn_process_with_pipes`.
#[allow(dead_code)]
pub struct PipeSpawnHandles {
    pub process: PROCESS_INFORMATION,
    pub stdin_write: Option<HANDLE>,
    pub stdout_read: HANDLE,
    pub stderr_read: Option<HANDLE>,
    pub(crate) desktop: LaunchDesktop,
    pub control: Option<crate::DuplexControl>,
}

struct OwnedProcessHandle(HANDLE);
impl Drop for OwnedProcessHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Inspect buffered bytes without waiting for a foreign writer reference to close.
pub fn available_pipe_bytes(pipe: &std::fs::File) -> std::io::Result<Option<usize>> {
    use std::os::windows::io::AsRawHandle;
    let mut available = 0;
    let success = unsafe {
        PeekNamedPipe(
            pipe.as_raw_handle() as HANDLE,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &mut available,
            ptr::null_mut(),
        )
    };
    if success != 0 {
        return Ok(Some(available as usize));
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_BROKEN_PIPE as i32) {
        Ok(None)
    } else {
        Err(error)
    }
}

/// Local execution with current identity and only an owned lifecycle range.
/// No filesystem, token, account, network, or setup policy is applied here.
pub struct LocalExecutionProcess {
    process: OwnedProcessHandle,
    job: OwnedProcessHandle,
    pub stdin: Option<std::fs::File>,
    pub stdout: Option<std::fs::File>,
    pub stderr: Option<std::fs::File>,
    pub control: Option<crate::DuplexControl>,
    control_owner: Option<crate::DuplexControl>,
    _desktop: Option<LaunchDesktop>,
    terminal: Option<std::sync::Arc<crate::ConptyInstance>>,
}

#[derive(Clone)]
pub struct LocalTerminal {
    owner: std::sync::Arc<crate::ConptyInstance>,
}

impl LocalTerminal {
    pub fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        if !(1..=1000).contains(&rows) || !(1..=1000).contains(&cols) {
            anyhow::bail!("invalid terminal dimensions");
        }
        let handle = self
            .owner
            .raw_handle()
            .ok_or_else(|| anyhow!("terminal unavailable"))?;
        crate::resize_conpty_handle(handle, cols as i16, rows as i16)
    }
}

impl LocalExecutionProcess {
    pub fn spawn(
        command: &[String],
        cwd: &Path,
        environment: &HashMap<String, String>,
        stdin_open: bool,
    ) -> Result<Self> {
        Self::spawn_with_terminal(command, cwd, environment, stdin_open, None)
    }

    pub fn spawn_with_terminal(
        command: &[String],
        cwd: &Path,
        environment: &HashMap<String, String>,
        stdin_open: bool,
        terminal_size: Option<(u16, u16)>,
    ) -> Result<Self> {
        Self::spawn_with_io(command, cwd, environment, stdin_open, terminal_size, false)
    }

    pub fn spawn_with_control(
        command: &[String],
        cwd: &Path,
        environment: &HashMap<String, String>,
        stdin_open: bool,
    ) -> Result<Self> {
        Self::spawn_with_io(command, cwd, environment, stdin_open, None, true)
    }

    fn spawn_with_io(
        command: &[String],
        cwd: &Path,
        environment: &HashMap<String, String>,
        stdin_open: bool,
        terminal_size: Option<(u16, u16)>,
        control_pipe: bool,
    ) -> Result<Self> {
        if terminal_size
            .is_some_and(|(rows, cols)| !(1..=1000).contains(&rows) || !(1..=1000).contains(&cols))
            || (terminal_size.is_some() && !stdin_open)
        {
            anyhow::bail!("invalid terminal input or dimensions");
        }
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        use windows_sys::Win32::System::Threading::{
            ResumeThread, TerminateProcess, WaitForSingleObject,
        };
        unsafe {
            let raw_job = CreateJobObjectW(ptr::null(), ptr::null());
            if raw_job == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let job = OwnedProcessHandle(raw_job);
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const _,
                std::mem::size_of_val(&limits) as u32,
            ) == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let (pi, stdin, stdout, stderr, desktop, terminal, control) =
                if let Some((rows, cols)) = terminal_size {
                    let (pi, mut terminal) = crate::conpty::spawn_conpty_process_for_identity(
                        ProcessIdentity::Current,
                        command,
                        cwd,
                        environment,
                        LaunchDesktopMode::Default,
                        &[],
                        None,
                        true,
                        None,
                        (cols as i16, rows as i16),
                    )?;
                    let stdin = Some(std::fs::File::from_raw_handle(
                        terminal.take_input_write() as *mut _
                    ));
                    let stdout = Some(std::fs::File::from_raw_handle(
                        terminal.take_output_read() as *mut _
                    ));
                    (
                        pi,
                        stdin,
                        stdout,
                        None,
                        None,
                        Some(std::sync::Arc::new(terminal)),
                        None,
                    )
                } else {
                    let pipes = spawn_process_with_pipes_for_identity(
                        ProcessIdentity::Current,
                        command,
                        cwd,
                        environment,
                        if stdin_open {
                            StdinMode::Open
                        } else {
                            StdinMode::Closed
                        },
                        StderrMode::Separate,
                        LaunchDesktopMode::Default,
                        &[],
                        None,
                        true,
                        None,
                        control_pipe,
                    )?;

                    (
                        pipes.process,
                        pipes
                            .stdin_write
                            .map(|handle| std::fs::File::from_raw_handle(handle as *mut _)),
                        Some(std::fs::File::from_raw_handle(pipes.stdout_read as *mut _)),
                        pipes
                            .stderr_read
                            .map(|handle| std::fs::File::from_raw_handle(handle as *mut _)),
                        Some(pipes.desktop),
                        None,
                        pipes.control,
                    )
                };
            let thread = OwnedProcessHandle(pi.hThread);
            let result = Self {
                process: OwnedProcessHandle(pi.hProcess),
                job,
                stdin,
                stdout,
                stderr,
                _desktop: desktop,
                terminal,
                control_owner: control.clone(),
                control,
            };
            if AssignProcessToJobObject(result.job.0, result.process.0) == 0
                || ResumeThread(thread.0) == u32::MAX
            {
                let error = std::io::Error::last_os_error();
                if TerminateProcess(result.process.0, 1) == 0
                    || WaitForSingleObject(result.process.0, 10000) != 0
                {
                    return Err(crate::SandboxCleanupError.into());
                }
                result
                    .cleanup(std::time::Duration::from_secs(10))
                    .map_err(|_| crate::SandboxCleanupError)?;
                return Err(error.into());
            }
            Ok(result)
        }
    }

    pub fn close_terminal(&mut self) -> Option<std::thread::JoinHandle<std::io::Result<()>>> {
        self.terminal.take().map(|terminal| {
            std::thread::spawn(move || {
                drop(terminal);
                Ok(())
            })
        })
    }

    pub fn terminal(&self) -> Option<LocalTerminal> {
        self.terminal.as_ref().map(|owner| LocalTerminal {
            owner: owner.clone(),
        })
    }

    pub fn try_wait(&self) -> std::io::Result<Option<u32>> {
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
        unsafe {
            match WaitForSingleObject(self.process.0, 0) {
                0 => {
                    let mut code = 0;
                    if GetExitCodeProcess(self.process.0, &mut code) == 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(Some(code))
                }
                0x102 => Ok(None),
                _ => Err(std::io::Error::last_os_error()),
            }
        }
    }

    pub fn cleanup(&self, timeout: std::time::Duration) -> std::io::Result<()> {
        let deadline = std::time::Instant::now() + timeout;
        unsafe { terminate_process_range_and_wait(self.job.0 as usize, timeout) }?;
        if let Some(control) = &self.control_owner {
            control.finish_output(deadline.saturating_duration_since(std::time::Instant::now()))?;
        }
        Ok(())
    }

    pub fn finish(&self, timeout: std::time::Duration) -> std::io::Result<u32> {
        let deadline = std::time::Instant::now() + timeout;
        self.cleanup(timeout)?;
        // ActiveProcesses can reach zero before the process handle becomes signaled.
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let wait_ms = u32::try_from(remaining.as_millis())
            .unwrap_or(u32::MAX - 1)
            .min(u32::MAX - 1);
        unsafe {
            if windows_sys::Win32::System::Threading::WaitForSingleObject(self.process.0, wait_ms)
                != 0
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "execution exit wait could not be completed",
                ));
            }
        }
        self.try_wait()?
            .ok_or_else(|| std::io::Error::other("execution exit status unavailable"))
    }
}

impl Drop for LocalExecutionProcess {
    fn drop(&mut self) {
        unsafe {
            // Covers partial setup too; this handle still refers only to the owned process.
            windows_sys::Win32::System::Threading::TerminateProcess(self.process.0, 1);
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.job.0, 1);
        }
    }
}

/// Spawns a process with anonymous pipes and returns the relevant handles.
#[allow(clippy::too_many_arguments)]
pub fn spawn_process_with_pipes(
    h_token: HANDLE,
    argv: &[String],
    cwd: &Path,
    env_map: &HashMap<String, String>,
    stdin_mode: StdinMode,
    stderr_mode: StderrMode,
    desktop_mode: LaunchDesktopMode,
    restricting_sids: &[*mut c_void],
    logs_base_dir: Option<&Path>,
    start_suspended: bool,
    security_capabilities: Option<*mut SECURITY_CAPABILITIES>,
) -> Result<PipeSpawnHandles> {
    spawn_process_with_pipes_and_control(
        h_token,
        argv,
        cwd,
        env_map,
        stdin_mode,
        stderr_mode,
        desktop_mode,
        restricting_sids,
        logs_base_dir,
        start_suspended,
        security_capabilities,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_process_with_pipes_and_control(
    h_token: HANDLE,
    argv: &[String],
    cwd: &Path,
    env_map: &HashMap<String, String>,
    stdin_mode: StdinMode,
    stderr_mode: StderrMode,
    desktop_mode: LaunchDesktopMode,
    restricting_sids: &[*mut c_void],
    logs_base_dir: Option<&Path>,
    start_suspended: bool,
    security_capabilities: Option<*mut SECURITY_CAPABILITIES>,
    control_pipe: bool,
) -> Result<PipeSpawnHandles> {
    spawn_process_with_pipes_for_identity(
        ProcessIdentity::PrimaryToken(h_token),
        argv,
        cwd,
        env_map,
        stdin_mode,
        stderr_mode,
        desktop_mode,
        restricting_sids,
        logs_base_dir,
        start_suspended,
        security_capabilities,
        control_pipe,
    )
}

#[allow(clippy::too_many_arguments)]
fn spawn_process_with_pipes_for_identity(
    identity: ProcessIdentity,
    argv: &[String],
    cwd: &Path,
    env_map: &HashMap<String, String>,
    stdin_mode: StdinMode,
    stderr_mode: StderrMode,
    desktop_mode: LaunchDesktopMode,
    restricting_sids: &[*mut c_void],
    logs_base_dir: Option<&Path>,
    start_suspended: bool,
    security_capabilities: Option<*mut SECURITY_CAPABILITIES>,
    control_pipe: bool,
) -> Result<PipeSpawnHandles> {
    let control = control_pipe.then(crate::DuplexControl::pair).transpose()?;

    let mut in_r: HANDLE = 0;
    let mut in_w: HANDLE = 0;
    let mut out_r: HANDLE = 0;
    let mut out_w: HANDLE = 0;
    let mut err_r: HANDLE = 0;
    let mut err_w: HANDLE = 0;
    unsafe {
        if CreatePipe(&mut in_r, &mut in_w, ptr::null_mut(), 0) == 0 {
            return Err(anyhow!("CreatePipe stdin failed: {}", GetLastError()));
        }
        if CreatePipe(&mut out_r, &mut out_w, ptr::null_mut(), 0) == 0 {
            CloseHandle(in_r);
            CloseHandle(in_w);
            return Err(anyhow!("CreatePipe stdout failed: {}", GetLastError()));
        }
        if matches!(stderr_mode, StderrMode::Separate)
            && CreatePipe(&mut err_r, &mut err_w, ptr::null_mut(), 0) == 0
        {
            CloseHandle(in_r);
            CloseHandle(in_w);
            CloseHandle(out_r);
            CloseHandle(out_w);
            return Err(anyhow!("CreatePipe stderr failed: {}", GetLastError()));
        }
    }

    let stderr_handle = match stderr_mode {
        StderrMode::MergeStdout => out_w,
        StderrMode::Separate => err_w,
    };

    let stdio = Some((in_r, out_w, stderr_handle));
    let spawn_result = unsafe {
        create_process_for_identity(
            identity,
            argv,
            cwd,
            env_map,
            logs_base_dir,
            stdio,
            desktop_mode,
            restricting_sids,
            start_suspended,
            security_capabilities,
            control.as_ref().map(|(_, child)| child.handle()),
        )
    };
    let created = match spawn_result {
        Ok(v) => v,
        Err(err) => {
            unsafe {
                CloseHandle(in_r);
                CloseHandle(in_w);
                CloseHandle(out_r);
                CloseHandle(out_w);
                if matches!(stderr_mode, StderrMode::Separate) {
                    CloseHandle(err_r);
                    CloseHandle(err_w);
                }
            }
            return Err(err);
        }
    };
    let CreatedProcess {
        process_info: pi,
        _desktop: desktop,
        ..
    } = created;

    unsafe {
        CloseHandle(in_r);
        CloseHandle(out_w);
        if matches!(stderr_mode, StderrMode::Separate) {
            CloseHandle(err_w);
        }
        if matches!(stdin_mode, StdinMode::Closed) {
            CloseHandle(in_w);
        }
    }

    Ok(PipeSpawnHandles {
        process: pi,
        stdin_write: match stdin_mode {
            StdinMode::Open => Some(in_w),
            StdinMode::Closed => None,
        },
        stdout_read: out_r,
        stderr_read: match stderr_mode {
            StderrMode::Separate => Some(err_r),
            StderrMode::MergeStdout => None,
        },
        desktop,
        control: control.map(|(parent, _child)| parent),
    })
}

/// Reads a HANDLE until EOF and invokes `on_chunk` for each read.
pub fn read_handle_loop<F>(handle: HANDLE, mut on_chunk: F) -> std::thread::JoinHandle<()>
where
    F: FnMut(&[u8]) + Send + 'static,
{
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            let mut read_bytes: u32 = 0;
            let ok = unsafe {
                ReadFile(
                    handle,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut read_bytes,
                    ptr::null_mut(),
                )
            };
            if ok == 0 || read_bytes == 0 {
                break;
            }
            on_chunk(&buf[..read_bytes as usize]);
        }
        unsafe {
            CloseHandle(handle);
        }
    })
}
