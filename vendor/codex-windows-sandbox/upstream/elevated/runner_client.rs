use crate::identity::SandboxCreds;
use crate::ipc_framed::FramedMessage;
use crate::ipc_framed::IPC_PROTOCOL_VERSION;
use crate::ipc_framed::Message;
use crate::ipc_framed::SpawnRequest;
use crate::ipc_framed::write_frame;
use crate::ipc_framed::{FramePoll, PipeFrameReader};
use crate::runner_pipe::PIPE_ACCESS_INBOUND;
use crate::runner_pipe::PIPE_ACCESS_OUTBOUND;
use crate::runner_pipe::connect_pipe;
use crate::runner_pipe::create_named_pipe;
use crate::runner_pipe::find_runner_exe;
use crate::runner_pipe::pipe_pair;
use crate::token::get_current_token_for_restriction;
use crate::token::get_logon_sid_bytes;
use crate::winutil::quote_windows_arg;
use crate::winutil::string_from_sid_bytes;
use crate::winutil::to_wide;
use anyhow::Result;
use std::ffi::c_void;
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS;
use windows_sys::Win32::Foundation::DuplicateHandle;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::Security::SetKernelObjectSecurity;
use windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode;
use windows_sys::Win32::System::IO::CancelSynchronousIo;
use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;
use windows_sys::Win32::System::Threading::CreateProcessWithLogonW;
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Threading::LOGON_WITH_PROFILE;
use windows_sys::Win32::System::Threading::PROCESS_INFORMATION;
use windows_sys::Win32::System::Threading::ResumeThread;
use windows_sys::Win32::System::Threading::STARTF_FORCEOFFFEEDBACK;
use windows_sys::Win32::System::Threading::STARTUPINFOW;
use windows_sys::Win32::System::Threading::TerminateProcess;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

const RUNNER_PREPARATION_TIMEOUT: Duration = Duration::from_secs(15);
const RUNNER_PREPARATION_POLL: Duration = Duration::from_millis(5);
const RUNNER_ERROR_MODE_FLAGS: u32 = 0x0001 | 0x0002;
const WAIT_OBJECT_0: u32 = 0;

unsafe fn restrict_runner_object_access(process: HANDLE, thread: HANDLE) -> Result<()> {
    let token = get_current_token_for_restriction()?;
    let parent_logon_sid = get_logon_sid_bytes(token);
    CloseHandle(token);
    let parent_logon_sid = string_from_sid_bytes(&parent_logon_sid?).map_err(anyhow::Error::msg)?;
    let sddl = to_wide(format!("D:P(A;;GA;;;SY)(A;;GA;;;{parent_logon_sid})"));
    let mut security_descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    if ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl.as_ptr(),
        1,
        &mut security_descriptor,
        ptr::null_mut(),
    ) == 0
    {
        anyhow::bail!(
            "runner process security descriptor failed: {}",
            GetLastError()
        );
    }
    let result = (|| {
        for (label, handle) in [("process", process), ("thread", thread)] {
            if SetKernelObjectSecurity(
                handle,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                security_descriptor,
            ) == 0
            {
                anyhow::bail!("restrict runner {label} access failed: {}", GetLastError());
            }
        }
        Ok(())
    })();
    let _ = LocalFree(security_descriptor as HLOCAL);
    result
}

fn runner_launch_cwd<'a>(runner_exe: &'a Path, fallback_cwd: &'a Path) -> &'a Path {
    runner_exe
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(fallback_cwd)
}

pub(crate) struct RunnerTransport {
    pipe_write: File,
    pipe_read: File,
}

impl RunnerTransport {
    fn read_spawn_ready(&mut self, budget: &mut PreparationBudget) -> Result<()> {
        let mut reader = PipeFrameReader::default();
        loop {
            budget.check()?;
            match reader.poll(&mut self.pipe_read)? {
                FramePoll::Pending => thread::sleep(RUNNER_PREPARATION_POLL),
                FramePoll::Progress => continue,
                FramePoll::Closed => anyhow::bail!("runner closed before startup confirmation"),
                FramePoll::Message(message) => {
                    return match message.message {
                        Message::SpawnReady { .. } => Ok(()),
                        Message::Exit { payload } => {
                            Err(anyhow::anyhow!(crate::SandboxCaptureCleanupError {
                                exit_code: Some(payload.exit_code),
                                timed_out: payload.timed_out
                            }))
                        }
                        _ => Err(anyhow::anyhow!("runner startup confirmation invalid")),
                    };
                }
            }
        }
    }

    pub(crate) fn into_files(self) -> (File, File) {
        (self.pipe_write, self.pipe_read)
    }
}

#[derive(Clone)]
struct PreparationBudget {
    deadline: Instant,
    execution_deadline: Option<Instant>,
    cancellation: Option<crate::WindowsSandboxCancellationToken>,
    cleanup_deadline: std::sync::Arc<std::sync::Mutex<Option<Instant>>>,
}
impl PreparationBudget {
    fn new(
        cancellation: Option<crate::WindowsSandboxCancellationToken>,
        execution_deadline: Option<Instant>,
    ) -> Self {
        Self {
            deadline: Instant::now() + RUNNER_PREPARATION_TIMEOUT,
            execution_deadline,
            cancellation,
            cleanup_deadline: Default::default(),
        }
    }
    fn check(&mut self) -> Result<()> {
        let now = Instant::now();
        if now >= self.deadline
            || self
                .execution_deadline
                .is_some_and(|deadline| now >= deadline)
            || self
                .cancellation
                .as_ref()
                .is_some_and(|token| token.is_cancelled())
        {
            self.cleanup_deadline();
            return Err(anyhow::anyhow!(crate::SandboxCleanupError));
        }
        Ok(())
    }
    fn cleanup_deadline(&mut self) -> Instant {
        *self
            .cleanup_deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(|| {
                self.cancellation
                    .as_ref()
                    .and_then(crate::WindowsSandboxCancellationToken::cleanup_deadline)
                    .unwrap_or_else(|| {
                        Instant::now()
                            + self
                                .cancellation
                                .as_ref()
                                .map_or_else(
                                    crate::CleanupBudget::default,
                                    crate::WindowsSandboxCancellationToken::cleanup_budget,
                                )
                                .duration()
                    })
            })
    }
}

type PreparationWorker = thread::JoinHandle<Result<Option<File>>>;
fn retained_preparation_workers() -> &'static std::sync::Mutex<Vec<PreparationWorker>> {
    static WORKERS: std::sync::OnceLock<std::sync::Mutex<Vec<PreparationWorker>>> =
        std::sync::OnceLock::new();
    WORKERS.get_or_init(std::sync::Mutex::default)
}
fn retain_preparation_worker(worker: PreparationWorker) {
    let mut retained = retained_preparation_workers()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut index = 0;
    while index < retained.len() {
        if unsafe { WaitForSingleObject(retained[index].as_raw_handle() as HANDLE, 0) }
            == WAIT_OBJECT_0
        {
            let _ = retained.swap_remove(index).join();
        } else {
            index += 1;
        }
    }
    retained.push(worker);
}
fn wait_preparation_worker(
    worker: PreparationWorker,
    budget: &mut PreparationBudget,
) -> Result<Option<File>> {
    let mut interrupted = false;
    loop {
        if budget.check().is_err() {
            interrupted = true;
        }
        if unsafe { WaitForSingleObject(worker.as_raw_handle() as HANDLE, 0) } == WAIT_OBJECT_0 {
            let result = worker
                .join()
                .map_err(|_| anyhow::anyhow!(crate::SandboxCleanupError))?;
            return if interrupted {
                Err(anyhow::anyhow!(crate::SandboxCleanupError))
            } else {
                result
            };
        }
        if interrupted {
            unsafe {
                CancelSynchronousIo(worker.as_raw_handle() as HANDLE);
            }
            if Instant::now() >= budget.cleanup_deadline() {
                retain_preparation_worker(worker);
                return Err(anyhow::anyhow!(crate::SandboxCleanupError));
            }
        }
        thread::sleep(RUNNER_PREPARATION_POLL);
    }
}
fn connect_pipe_with_budget(
    pipe: &File,
    expected_runner_pid: u32,
    budget: &mut PreparationBudget,
) -> Result<()> {
    budget.check()?;
    let process = unsafe { GetCurrentProcess() };
    let mut duplicate = 0;
    if unsafe {
        DuplicateHandle(
            process,
            pipe.as_raw_handle() as HANDLE,
            process,
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let pipe = unsafe { File::from_raw_handle(duplicate as _) };
    let worker = thread::Builder::new()
        .name("runseal-runner-connect".into())
        .spawn(move || {
            connect_pipe(pipe.as_raw_handle() as HANDLE, expected_runner_pid)?;
            Ok(None)
        })?;
    wait_preparation_worker(worker, budget)?;
    Ok(())
}
fn send_spawn_request(
    pipe: File,
    request: SpawnRequest,
    budget: &mut PreparationBudget,
) -> Result<File> {
    budget.check()?;
    let cancellation = budget.cancellation.clone();
    let deadline = budget
        .execution_deadline
        .map_or(budget.deadline, |execution| execution.min(budget.deadline));
    let worker = thread::Builder::new()
        .name("runseal-runner-request".into())
        .spawn(move || {
            if Instant::now() >= deadline
                || cancellation
                    .as_ref()
                    .is_some_and(|token| token.is_cancelled())
            {
                return Err(anyhow::anyhow!(crate::SandboxCleanupError));
            }
            let mut pipe = pipe;
            write_frame(
                &mut pipe,
                &FramedMessage {
                    version: IPC_PROTOCOL_VERSION,
                    message: Message::SpawnRequest {
                        payload: Box::new(request),
                    },
                },
            )?;
            Ok(Some(pipe))
        })?;
    wait_preparation_worker(worker, budget)?
        .ok_or_else(|| anyhow::anyhow!(crate::SandboxCleanupError))
}

struct RunnerProcessOwner {
    process: Option<OwnedHandle>,
    deadline: Option<Instant>,
}
fn retained_runner_processes() -> &'static std::sync::Mutex<Vec<OwnedHandle>> {
    static PROCESSES: std::sync::OnceLock<std::sync::Mutex<Vec<OwnedHandle>>> =
        std::sync::OnceLock::new();
    PROCESSES.get_or_init(std::sync::Mutex::default)
}
impl RunnerProcessOwner {
    fn stop(&mut self, deadline: Instant) -> Result<()> {
        self.deadline = Some(
            self.deadline
                .map_or(deadline, |previous| previous.min(deadline)),
        );
        let Some(process) = &self.process else {
            return Ok(());
        };
        unsafe {
            TerminateProcess(process.as_raw_handle() as HANDLE, 1);
        }
        loop {
            if unsafe { WaitForSingleObject(process.as_raw_handle() as HANDLE, 0) } == WAIT_OBJECT_0
            {
                self.process.take();
                return Ok(());
            }
            if Instant::now()
                >= self
                    .deadline
                    .ok_or_else(|| anyhow::anyhow!(crate::SandboxCleanupError))?
            {
                return Err(anyhow::anyhow!(crate::SandboxCleanupError));
            }
            thread::sleep(RUNNER_PREPARATION_POLL);
        }
    }
    fn release(mut self) {
        self.process.take();
    }
}
impl Drop for RunnerProcessOwner {
    fn drop(&mut self) {
        let deadline = self
            .deadline
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(2));
        let _ = self.stop(deadline);
        if let Some(process) = self.process.take() {
            retained_runner_processes()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(process);
        }
    }
}

struct NativeRunner {
    owner: Option<RunnerProcessOwner>,
    thread: Option<OwnedHandle>,
    process_id: u32,
    budget: PreparationBudget,
}

impl NativeRunner {
    fn from_process_info(pi: PROCESS_INFORMATION, budget: PreparationBudget) -> Self {
        Self {
            owner: Some(RunnerProcessOwner {
                process: Some(unsafe { OwnedHandle::from_raw_handle(pi.hProcess as _) }),
                deadline: None,
            }),
            thread: Some(unsafe { OwnedHandle::from_raw_handle(pi.hThread as _) }),
            process_id: pi.dwProcessId,
            budget,
        }
    }

    fn into_parts(mut self) -> Result<(RunnerProcessOwner, OwnedHandle, u32)> {
        let owner = self
            .owner
            .take()
            .ok_or_else(|| anyhow::anyhow!(crate::SandboxCleanupError))?;
        let thread = self
            .thread
            .take()
            .ok_or_else(|| anyhow::anyhow!(crate::SandboxCleanupError))?;
        Ok((owner, thread, self.process_id))
    }
}

impl Drop for NativeRunner {
    fn drop(&mut self) {
        if let Some(owner) = &mut self.owner {
            let _ = owner.stop(self.budget.cleanup_deadline());
        }
    }
}

type LaunchWorker = thread::JoinHandle<Result<NativeRunner>>;
fn retained_launch_workers() -> &'static std::sync::Mutex<Vec<LaunchWorker>> {
    static WORKERS: std::sync::OnceLock<std::sync::Mutex<Vec<LaunchWorker>>> =
        std::sync::OnceLock::new();
    WORKERS.get_or_init(std::sync::Mutex::default)
}

fn launch_runner_with_budget(
    budget: &mut PreparationBudget,
    launch: impl FnOnce() -> Result<PROCESS_INFORMATION> + Send + 'static,
) -> Result<NativeRunner> {
    budget.check()?;
    let mut worker_budget = budget.clone();
    let worker = thread::Builder::new()
        .name("runseal-runner-logon".into())
        .spawn(move || {
            worker_budget.check()?;
            let runner = NativeRunner::from_process_info(launch()?, worker_budget.clone());
            worker_budget.check()?;
            Ok(runner)
        })?;
    let mut interrupted = false;
    loop {
        if budget.check().is_err() {
            interrupted = true;
        }
        if unsafe { WaitForSingleObject(worker.as_raw_handle() as HANDLE, 0) } == WAIT_OBJECT_0 {
            let result = worker
                .join()
                .map_err(|_| anyhow::anyhow!(crate::SandboxCleanupError))?;
            return if interrupted {
                drop(result);
                Err(anyhow::anyhow!(crate::SandboxCleanupError))
            } else {
                result
            };
        }
        if interrupted && Instant::now() >= budget.cleanup_deadline() {
            let mut retained = retained_launch_workers()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut index = 0;
            while index < retained.len() {
                if unsafe { WaitForSingleObject(retained[index].as_raw_handle() as HANDLE, 0) }
                    == WAIT_OBJECT_0
                {
                    let _ = retained.swap_remove(index).join();
                } else {
                    index += 1;
                }
            }
            retained.push(worker);
            return Err(anyhow::anyhow!(crate::SandboxCleanupError));
        }
        thread::sleep(RUNNER_PREPARATION_POLL);
    }
}

fn resume_runner_after_security_check(
    process: HANDLE,
    thread: HANDLE,
    budget: &mut PreparationBudget,
    configure: impl FnOnce(HANDLE, HANDLE) -> Result<()>,
) -> Result<()> {
    budget.check()?;
    configure(process, thread)?;
    budget.check()?;
    if unsafe { ResumeThread(thread) } == u32::MAX {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn finish_runner_startup(
    mut owner: RunnerProcessOwner,
    budget: &mut PreparationBudget,
    startup: Result<RunnerTransport>,
) -> Result<RunnerTransport> {
    match startup {
        Ok(transport) => {
            owner.release();
            Ok(transport)
        }
        Err(error) => {
            let _ = owner.stop(budget.cleanup_deadline());
            // Runner exit alone does not verify descendants or shared resources.
            if error
                .downcast_ref::<crate::SandboxCaptureCleanupError>()
                .is_some()
            {
                Err(error)
            } else {
                Err(anyhow::anyhow!(crate::SandboxCleanupError))
            }
        }
    }
}

pub(crate) fn spawn_runner_transport(
    codex_home: &Path,
    cwd: &Path,
    sandbox_creds: &SandboxCreds,
    log_dir: Option<&Path>,
    spawn_request: SpawnRequest,
    cancellation: Option<crate::WindowsSandboxCancellationToken>,
    execution_deadline: Option<Instant>,
) -> Result<RunnerTransport> {
    let execution_deadline = match execution_deadline {
        Some(deadline) => Some(deadline),
        None => spawn_request
            .timeout_ms
            .map(|milliseconds| {
                Instant::now()
                    .checked_add(Duration::from_millis(milliseconds))
                    .ok_or_else(|| anyhow::anyhow!("preparation deadline unavailable"))
            })
            .transpose()?,
    };
    let mut budget = PreparationBudget::new(cancellation, execution_deadline);
    budget.check()?;
    let (pipe_in_name, pipe_out_name) = pipe_pair();
    let pipe_write = unsafe {
        File::from_raw_handle(create_named_pipe(
            &pipe_in_name,
            PIPE_ACCESS_OUTBOUND,
            &sandbox_creds.username,
        )? as _)
    };
    let pipe_read = unsafe {
        File::from_raw_handle(create_named_pipe(
            &pipe_out_name,
            PIPE_ACCESS_INBOUND,
            &sandbox_creds.username,
        )? as _)
    };
    let runner_exe = find_runner_exe(codex_home, log_dir);
    let runner_cmdline = runner_exe
        .to_str()
        .map(str::to_owned)
        .unwrap_or_else(|| "runseal-command-runner.exe".to_string());
    let runner_full_cmd = format!(
        "{} {} {}",
        quote_windows_arg(&runner_cmdline),
        quote_windows_arg(&format!("--pipe-in={pipe_in_name}")),
        quote_windows_arg(&format!("--pipe-out={pipe_out_name}"))
    );
    let mut cmdline_vec = to_wide(&runner_full_cmd);
    let exe_w = to_wide(&runner_cmdline);
    let runner_cwd = runner_launch_cwd(&runner_exe, cwd);
    let cwd_w = to_wide(runner_cwd);
    let user_w = to_wide(&sandbox_creds.username);
    let domain_w = to_wide(".");
    let password_w = to_wide(&sandbox_creds.password);
    let runner = launch_runner_with_budget(&mut budget, move || {
        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.dwFlags = STARTF_FORCEOFFFEEDBACK;
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let env_block: Option<Vec<u16>> = None;

        let previous_error_mode = unsafe { SetErrorMode(RUNNER_ERROR_MODE_FLAGS) };
        let spawn_res = unsafe {
            CreateProcessWithLogonW(
                user_w.as_ptr(),
                domain_w.as_ptr(),
                password_w.as_ptr(),
                LOGON_WITH_PROFILE,
                exe_w.as_ptr(),
                cmdline_vec.as_mut_ptr(),
                windows_sys::Win32::System::Threading::CREATE_NO_WINDOW
                    | CREATE_SUSPENDED
                    | windows_sys::Win32::System::Threading::CREATE_UNICODE_ENVIRONMENT,
                env_block
                    .as_ref()
                    .map(|block| block.as_ptr() as *const c_void)
                    .unwrap_or(ptr::null()),
                cwd_w.as_ptr(),
                &si,
                &mut pi,
            )
        };
        let spawn_error = (spawn_res == 0).then(|| unsafe { GetLastError() });
        unsafe {
            SetErrorMode(previous_error_mode);
        }
        if let Some(error) = spawn_error {
            return Err(std::io::Error::from_raw_os_error(error as i32).into());
        }
        Ok(pi)
    })?;
    let (owner, runner_thread, expected_runner_pid) = runner.into_parts()?;
    let runner_process = owner
        .process
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!(crate::SandboxCleanupError))?
        .as_raw_handle() as HANDLE;
    let startup = (|| -> Result<RunnerTransport> {
        resume_runner_after_security_check(
            runner_process,
            runner_thread.as_raw_handle() as HANDLE,
            &mut budget,
            |process, thread| unsafe { restrict_runner_object_access(process, thread) },
        )?;
        connect_pipe_with_budget(&pipe_write, expected_runner_pid, &mut budget)?;
        connect_pipe_with_budget(&pipe_read, expected_runner_pid, &mut budget)?;
        let pipe_write = send_spawn_request(pipe_write, spawn_request, &mut budget)?;
        let mut transport = RunnerTransport {
            pipe_write,
            pipe_read,
        };
        transport.read_spawn_ready(&mut budget)?;
        Ok(transport)
    })();
    drop(runner_thread);
    finish_runner_startup(owner, &mut budget, startup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::windows::io::IntoRawHandle;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    };

    struct Peer(Child);
    impl Drop for Peer {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn late_native_launch_stays_owned_after_parent_deadline_without_resuming_target() -> Result<()>
    {
        use windows_sys::Win32::System::Threading::{
            CreateProcessW, GetExitCodeProcess, GetProcessId,
        };
        let tmp = tempfile::tempdir()?;
        let marker = tmp.path().join("target.ran");
        let launch_marker = marker.clone();
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancellation = cancelled.clone();
        let expired = Instant::now();
        let token = crate::WindowsSandboxCancellationToken::new(move || {
            cancellation.load(Ordering::Acquire)
        })
        .with_cleanup_deadline(move || expired);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (process_tx, process_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let caller = thread::spawn(move || -> Result<()> {
            let mut budget = PreparationBudget::new(Some(token), None);
            let result = launch_runner_with_budget(&mut budget, move || {
                entered_tx.send(thread::current().id())?;
                release_rx.recv()?;
                let python =
                    String::from_utf8(Command::new("where.exe").arg("python").output()?.stdout)?;
                let python = python
                    .lines()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("Python required"))?;
                let argv = vec![
                    python.into(),
                    "-c".into(),
                    "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('RAN')".into(),
                    launch_marker.to_string_lossy().into_owned(),
                ];
                let mut command = to_wide(crate::winutil::argv_to_command_line(&argv));
                let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
                si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
                let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
                if unsafe {
                    CreateProcessW(
                        ptr::null(),
                        command.as_mut_ptr(),
                        ptr::null(),
                        ptr::null(),
                        0,
                        CREATE_SUSPENDED | windows_sys::Win32::System::Threading::CREATE_NO_WINDOW,
                        ptr::null(),
                        ptr::null(),
                        &si,
                        &mut pi,
                    )
                } == 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                let mut observer = 0;
                let current = unsafe { GetCurrentProcess() };
                if unsafe {
                    DuplicateHandle(
                        current,
                        pi.hProcess,
                        current,
                        &mut observer,
                        0,
                        0,
                        DUPLICATE_SAME_ACCESS,
                    )
                } == 0
                {
                    unsafe {
                        TerminateProcess(pi.hProcess, 1);
                        CloseHandle(pi.hThread);
                        CloseHandle(pi.hProcess);
                    }
                    return Err(std::io::Error::last_os_error().into());
                }
                if process_tx
                    .send(unsafe { OwnedHandle::from_raw_handle(observer as _) })
                    .is_err()
                {
                    unsafe {
                        TerminateProcess(pi.hProcess, 1);
                        WaitForSingleObject(pi.hProcess, 2000);
                        CloseHandle(pi.hThread);
                        CloseHandle(pi.hProcess);
                    }
                    anyhow::bail!("fixture process observer unavailable");
                }
                Ok(pi)
            });
            let _ = result_tx.send(result.is_err());
            Ok(())
        });
        let id = entered_rx.recv_timeout(Duration::from_secs(2))?;
        cancelled.store(true, Ordering::Release);
        let before_release = result_rx.recv_timeout(Duration::from_millis(500));
        let retained = retained_launch_workers()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|worker| {
                worker.thread().id() == id
                    && unsafe { WaitForSingleObject(worker.as_raw_handle() as HANDLE, 0) }
                        != WAIT_OBJECT_0
            });
        // Allow only this fixture's late native launch, then observe its actual termination.
        release_tx.send(())?;
        let process = process_rx.recv_timeout(Duration::from_secs(2))?;
        let process_id = unsafe { GetProcessId(process.as_raw_handle() as HANDLE) };
        let stopped = unsafe { WaitForSingleObject(process.as_raw_handle() as HANDLE, 2000) }
            == WAIT_OBJECT_0;
        let mut code = 0;
        let queried = unsafe { GetExitCodeProcess(process.as_raw_handle() as HANDLE, &mut code) };
        caller
            .join()
            .map_err(|_| anyhow::anyhow!("launch fixture caller panic"))??;
        let retained_worker = {
            let mut workers = retained_launch_workers()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            workers
                .iter()
                .position(|worker| worker.thread().id() == id)
                .map(|index| workers.swap_remove(index))
        };
        if let Some(worker) = retained_worker {
            let _ = worker.join();
        }
        let ran = marker.exists();
        // Explicit fixture cleanup precedes assertions, including a broken implementation.
        unsafe {
            TerminateProcess(process.as_raw_handle() as HANDLE, 1);
            WaitForSingleObject(process.as_raw_handle() as HANDLE, 2000);
        }
        retained_runner_processes()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|owned| unsafe { GetProcessId(owned.as_raw_handle() as HANDLE) } != process_id);
        assert!(
            before_release?,
            "parent must report unverified cleanup before the late launch returns"
        );
        assert!(
            retained,
            "the unfinished native launch thread must remain owned"
        );
        assert!(stopped);
        assert_ne!(queried, 0);
        assert_eq!(code, 1);
        assert!(!ran, "a late suspended target must never be resumed");
        Ok(())
    }

    #[test]
    fn setup_failure_cannot_bypass_owned_suspended_process_cleanup() -> Result<()> {
        use windows_sys::Win32::System::Threading::{CreateProcessW, GetExitCodeProcess};
        let tmp = tempfile::TempDir::new()?;
        let marker = tmp.path().join("target.ran");
        let argv = vec![
            "python".to_string(),
            "-c".into(),
            "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('RAN')".into(),
            marker.to_string_lossy().into_owned(),
        ];
        let mut command = to_wide(crate::winutil::argv_to_command_line(&argv));
        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe {
            CreateProcessW(
                ptr::null(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                CREATE_SUSPENDED | windows_sys::Win32::System::Threading::CREATE_NO_WINDOW,
                ptr::null(),
                ptr::null(),
                &si,
                &mut pi,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let process = unsafe { OwnedHandle::from_raw_handle(pi.hProcess as _) };
        let thread = unsafe { OwnedHandle::from_raw_handle(pi.hThread as _) };
        let mut observer = 0;
        let current = unsafe { GetCurrentProcess() };
        if unsafe {
            DuplicateHandle(
                current,
                pi.hProcess,
                current,
                &mut observer,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            unsafe {
                TerminateProcess(pi.hProcess, 1);
                WaitForSingleObject(pi.hProcess, 2000);
            }
            return Err(std::io::Error::last_os_error().into());
        }
        struct Fixture(OwnedHandle);
        impl Drop for Fixture {
            fn drop(&mut self) {
                unsafe {
                    TerminateProcess(self.0.as_raw_handle() as HANDLE, 1);
                    WaitForSingleObject(self.0.as_raw_handle() as HANDLE, 2000);
                }
            }
        }
        let fixture = Fixture(unsafe { OwnedHandle::from_raw_handle(observer as _) });
        let owner = RunnerProcessOwner {
            process: Some(process),
            deadline: None,
        };
        let mut budget = PreparationBudget::new(None, None);
        *budget
            .cleanup_deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(Instant::now() + Duration::from_secs(2));
        let startup = resume_runner_after_security_check(
            pi.hProcess,
            thread.as_raw_handle() as HANDLE,
            &mut budget,
            |_, _| Err(anyhow::anyhow!("controlled security setup failure")),
        );
        assert!(startup.is_err());
        let error = finish_runner_startup(
            owner,
            &mut budget,
            startup.map(|_| RunnerTransport {
                pipe_write: tempfile::tempfile().expect("fixture write"),
                pipe_read: tempfile::tempfile().expect("fixture read"),
            }),
        )
        .err()
        .ok_or_else(|| anyhow::anyhow!("setup failure must be observable"))?;
        let wait = unsafe { WaitForSingleObject(fixture.0.as_raw_handle() as HANDLE, 0) };
        let mut code = 0;
        let queried = unsafe { GetExitCodeProcess(fixture.0.as_raw_handle() as HANDLE, &mut code) };
        let ran = marker.exists();
        drop(fixture);
        drop(thread);
        assert_eq!(
            wait, WAIT_OBJECT_0,
            "the owned suspended process must be gone before returning"
        );
        assert_ne!(queried, 0);
        assert_eq!(code, 1);
        assert!(!ran, "failed setup must not resume the target");
        assert!(
            error.downcast_ref::<crate::SandboxCleanupError>().is_some(),
            "runner exit is not proof of the entire sandbox boundary"
        );
        Ok(())
    }

    #[test]
    fn preparing_cancel_and_timeout_refuse_partial_confirmation_before_peer_eof() -> Result<()> {
        for by_timeout in [false, true] {
            for prefix in [vec![], vec![8, 0], vec![8, 0, 0, 0, b'{']] {
                let tmp = tempfile::TempDir::new()?;
                let ready = tmp.path().join("ready");
                let mut peer=Peer(Command::new("python").args(["-u","-c","import base64,os,pathlib,sys; os.write(1,base64.b64decode(sys.argv[1])); pathlib.Path(sys.argv[2]).write_text('READY'); sys.stdin.buffer.read(1)"])
                    .arg(crate::ipc_framed::encode_bytes(&prefix)).arg(&ready).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?);
                let pipe_read = unsafe {
                    File::from_raw_handle(
                        peer.0
                            .stdout
                            .take()
                            .ok_or_else(|| anyhow::anyhow!("peer stdout"))?
                            .into_raw_handle(),
                    )
                };
                let pipe_write = tempfile::tempfile()?;
                let ready_deadline = Instant::now() + Duration::from_secs(2);
                while !ready.exists() {
                    assert!(Instant::now() < ready_deadline);
                    thread::sleep(Duration::from_millis(5));
                }
                let cancelled = Arc::new(AtomicBool::new(false));
                let checks = Arc::new(AtomicUsize::new(0));
                let flag = cancelled.clone();
                let checked = checks.clone();
                let token = crate::WindowsSandboxCancellationToken::new(move || {
                    checked.fetch_add(1, Ordering::Release);
                    flag.load(Ordering::Acquire)
                });
                let (tx, rx) = mpsc::channel();
                let worker = thread::spawn(move || {
                    let mut transport = RunnerTransport {
                        pipe_read,
                        pipe_write,
                    };
                    let mut budget = PreparationBudget::new(
                        Some(token),
                        by_timeout.then(|| Instant::now() + Duration::from_millis(200)),
                    );
                    let result = transport.read_spawn_ready(&mut budget);
                    let _ = tx.send(result.err().is_some_and(|error| {
                        error.downcast_ref::<crate::SandboxCleanupError>().is_some()
                    }));
                });
                let deadline = Instant::now() + Duration::from_secs(2);
                while checks.load(Ordering::Acquire) < 2 {
                    assert!(Instant::now() < deadline, "preparing poll acknowledgement");
                    thread::sleep(Duration::from_millis(5));
                }
                if !by_timeout {
                    cancelled.store(true, Ordering::Release);
                }
                let result = rx.recv_timeout(Duration::from_secs(2));
                let live = peer.0.try_wait()?.is_none();
                peer.0
                    .stdin
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("peer release"))?
                    .write_all(b"G")?;
                worker
                    .join()
                    .map_err(|_| anyhow::anyhow!("preparing reader panic"))?;
                assert_eq!(peer.0.wait()?.code(), Some(0));
                assert!(
                    live,
                    "peer must still hold its actual writer endpoint when preparing returns"
                );
                assert!(
                    matches!(result, Ok(true)),
                    "cancel/timeout must not require peer EOF: timeout={by_timeout}, prefix={prefix:?}, result={result:?}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn expired_preparation_budget_retains_a_real_native_connect_owner() -> Result<()> {
        use windows_sys::Win32::System::Pipes::CreateNamedPipeW;
        let tmp = tempfile::TempDir::new()?;
        let name = to_wide(format!(
            r"\\.\pipe\RunSealPreparationFixture-{}",
            tmp.path()
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("fixture name"))?
                .to_string_lossy()
        ));
        let raw = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_OUTBOUND,
                0,
                1,
                4096,
                4096,
                0,
                ptr::null_mut(),
            )
        };
        if raw == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error().into());
        }
        let pipe = unsafe { File::from_raw_handle(raw as _) };
        let expected_pid = std::process::id();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (returned_tx, returned_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = entered_tx.send(());
            let result = connect_pipe(pipe.as_raw_handle() as HANDLE, expected_pid);
            let _ = returned_tx.send(());
            let _ = release_rx.recv();
            result?;
            Ok(None)
        });
        entered_rx.recv_timeout(Duration::from_secs(2))?;
        let id = worker.thread().id();
        let token = crate::WindowsSandboxCancellationToken::new(|| true)
            .with_cleanup_deadline(Instant::now);
        let mut budget = PreparationBudget::new(Some(token), None);
        let start = Instant::now();
        let error = wait_preparation_worker(worker, &mut budget)
            .expect_err("expired native connect must fail closed");
        let duration = start.elapsed();
        let retained = retained_preparation_workers()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|worker| worker.thread().id() == id);
        // Cancel only this fixture's connect, retrying the startup race until
        // native completion is acknowledged; the gated owner remains alive.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if returned_rx.try_recv().is_ok() {
                break;
            }
            let workers = retained_preparation_workers()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(worker) = workers.iter().find(|worker| worker.thread().id() == id) {
                unsafe {
                    CancelSynchronousIo(worker.as_raw_handle() as HANDLE);
                }
            }
            drop(workers);
            assert!(
                Instant::now() < deadline,
                "native connect cancellation acknowledgement"
            );
            thread::sleep(Duration::from_millis(5));
        }
        release_tx.send(())?;
        loop {
            let mut workers = retained_preparation_workers()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(index) = workers.iter().position(|worker| {
                worker.thread().id() == id
                    && unsafe { WaitForSingleObject(worker.as_raw_handle() as HANDLE, 0) }
                        == WAIT_OBJECT_0
            }) {
                let result = workers
                    .swap_remove(index)
                    .join()
                    .map_err(|_| anyhow::anyhow!("native connect owner panic"))?;
                assert!(result.is_err());
                break;
            }
            drop(workers);
            assert!(Instant::now() < deadline, "native connect owner join");
            thread::sleep(Duration::from_millis(5));
        }
        assert!(error.downcast_ref::<crate::SandboxCleanupError>().is_some());
        assert!(
            retained,
            "unjoined connect must keep its owned pipe and thread"
        );
        assert!(
            duration < Duration::from_millis(500),
            "expired cleanup must not renew: {duration:?}"
        );
        Ok(())
    }

    #[test]
    fn runner_starts_from_helper_directory_not_command_cwd() {
        let runner = Path::new(
            r"C:\Users\me\AppData\Roaming\RunSeal\windows-sandbox\.sandbox-bin\runseal-command-runner.exe",
        );
        let command_cwd = Path::new(r"C:\Users\me\AppData\Roaming\RunSeal\scratch\session");

        assert_eq!(
            runner_launch_cwd(runner, command_cwd),
            Path::new(r"C:\Users\me\AppData\Roaming\RunSeal\windows-sandbox\.sandbox-bin")
        );
    }
}
