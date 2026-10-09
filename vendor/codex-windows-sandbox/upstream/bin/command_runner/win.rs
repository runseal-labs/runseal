//! Windows command runner used by the **elevated** sandbox path.
//!
//! The CLI launches this binary under the sandbox user when Windows sandbox level is
//! Elevated. It connects to the IPC pipes, reads the framed `SpawnRequest`, derives a
//! restricted token from the sandbox user, and spawns the child process via ConPTY
//! (`tty=true`) or pipes (`tty=false`). It then streams output frames back to the parent,
//! accepts stdin/terminate frames, and emits a final exit frame. The legacy restricted‑token
//! path spawns the child directly and does not use this runner.

#![allow(unsafe_op_in_unsafe_fn)]

mod cwd_junction;

use anyhow::Context;
use anyhow::Result;
use codex_windows_sandbox::AppContainerSecurityCapabilities;
use codex_windows_sandbox::ErrorPayload;
use codex_windows_sandbox::ExitPayload;
use codex_windows_sandbox::FramedMessage;
use codex_windows_sandbox::IPC_PROTOCOL_VERSION;
use codex_windows_sandbox::LaunchDesktopMode;
use codex_windows_sandbox::LocalSid;
use codex_windows_sandbox::Message;
use codex_windows_sandbox::OutputPayload;
use codex_windows_sandbox::OutputStream;
use codex_windows_sandbox::PipeSpawnHandles;
use codex_windows_sandbox::ResizePayload;
use codex_windows_sandbox::SpawnReady;
use codex_windows_sandbox::SpawnRequest;
use codex_windows_sandbox::StderrMode;
use codex_windows_sandbox::StdinMode;
use codex_windows_sandbox::WindowsSandboxIsolationMode;
use codex_windows_sandbox::allow_null_device;
use codex_windows_sandbox::create_elevated_readonly_token_with_caps_from;
use codex_windows_sandbox::create_elevated_workspace_write_token_with_caps_from;
use codex_windows_sandbox::decode_bytes;
use codex_windows_sandbox::encode_bytes;
use codex_windows_sandbox::get_current_token_for_restriction;
use codex_windows_sandbox::hide_current_user_profile_dir;
use codex_windows_sandbox::isolation_mode_for_permission_profile;
use codex_windows_sandbox::log_note;
use codex_windows_sandbox::read_frame;
use codex_windows_sandbox::resize_conpty_handle;
use codex_windows_sandbox::restrict_current_token_default_dacl_to_logon_sid;
use codex_windows_sandbox::spawn_process_with_pipes_and_control;
use codex_windows_sandbox::to_wide;
use codex_windows_sandbox::write_frame;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::path::PathBuf;
use std::ptr;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Storage::FileSystem::CreateFileW;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE;
use windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING;
use windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode;
use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
use windows_sys::Win32::System::JobObjects::CreateJobObjectW;
use windows_sys::Win32::System::JobObjects::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
use windows_sys::Win32::System::JobObjects::JOB_OBJECT_UILIMIT_DESKTOP;
use windows_sys::Win32::System::JobObjects::JOB_OBJECT_UILIMIT_DISPLAYSETTINGS;
use windows_sys::Win32::System::JobObjects::JOB_OBJECT_UILIMIT_EXITWINDOWS;
use windows_sys::Win32::System::JobObjects::JOB_OBJECT_UILIMIT_GLOBALATOMS;
use windows_sys::Win32::System::JobObjects::JOB_OBJECT_UILIMIT_HANDLES;
use windows_sys::Win32::System::JobObjects::JOB_OBJECT_UILIMIT_READCLIPBOARD;
use windows_sys::Win32::System::JobObjects::JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
use windows_sys::Win32::System::JobObjects::JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
use windows_sys::Win32::System::JobObjects::JOBOBJECT_BASIC_UI_RESTRICTIONS;
use windows_sys::Win32::System::JobObjects::JOBOBJECT_EXTENDED_LIMIT_INFORMATION;
use windows_sys::Win32::System::JobObjects::JobObjectBasicUIRestrictions;
use windows_sys::Win32::System::JobObjects::JobObjectExtendedLimitInformation;
#[cfg(test)]
use windows_sys::Win32::System::JobObjects::QueryInformationJobObject;
use windows_sys::Win32::System::JobObjects::SetInformationJobObject;
use windows_sys::Win32::System::JobObjects::TerminateJobObject;
use windows_sys::Win32::System::Threading::GetExitCodeProcess;
use windows_sys::Win32::System::Threading::GetProcessId;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::Win32::System::Threading::MUTEX_ALL_ACCESS;
use windows_sys::Win32::System::Threading::OpenMutexW;
use windows_sys::Win32::System::Threading::PROCESS_INFORMATION;
use windows_sys::Win32::System::Threading::ResumeThread;
use windows_sys::Win32::System::Threading::TerminateProcess;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

const READ_ACL_MUTEX_NAME: &str = "Local\\RunSealSandboxReadAcl";
const WAIT_TIMEOUT: u32 = 0x0000_0102;
const NONINTERACTIVE_ERROR_MODE: u32 = 0x0001 | 0x0002 | 0x8000;
const SANDBOX_JOB_UI_RESTRICTIONS: u32 = JOB_OBJECT_UILIMIT_DESKTOP
    | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
    | JOB_OBJECT_UILIMIT_EXITWINDOWS
    | JOB_OBJECT_UILIMIT_GLOBALATOMS
    | JOB_OBJECT_UILIMIT_HANDLES
    | JOB_OBJECT_UILIMIT_READCLIPBOARD
    | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
    | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;

struct IpcSpawnedProcess {
    log_dir: PathBuf,
    pi: PROCESS_INFORMATION,
    stdout_handle: HANDLE,
    stderr_handle: HANDLE,
    stdin_handle: Option<HANDLE>,
    conpty_owner: Option<codex_windows_sandbox::ConptyInstance>,
    hpc_handle: Option<HANDLE>,
    _pipe_handles: Option<PipeSpawnHandles>,
}

/// Small RAII wrapper for raw Win32 handles.
///
/// The elevated runner has a few early-return paths where we acquire a token, job, or pipe
/// handle and then may fail while preparing the child. Keeping those handles in a guard makes
/// the error paths read more directly and closes the gaps that were previously leaking them.
struct OwnedWinHandle(HANDLE);

impl OwnedWinHandle {
    fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    fn raw(&self) -> HANDLE {
        self.0
    }

    fn into_raw(mut self) -> HANDLE {
        // Transfer ownership to the caller. After this point the caller is responsible for
        // eventually closing the returned HANDLE.
        let handle = self.0;
        self.0 = 0;
        handle
    }
}

impl Drop for OwnedWinHandle {
    fn drop(&mut self) {
        if self.0 != 0 && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

unsafe fn create_sandbox_job() -> Result<HANDLE> {
    let h_job = OwnedWinHandle::new(CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()));
    if h_job.raw() == 0 {
        return Err(anyhow::anyhow!("CreateJobObjectW failed"));
    }
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let ok = SetInformationJobObject(
        h_job.raw(),
        JobObjectExtendedLimitInformation,
        &mut limits as *mut _ as *mut _,
        std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
    );
    if ok == 0 {
        return Err(anyhow::anyhow!(
            "SetInformationJobObject extended limits failed: {}",
            GetLastError()
        ));
    }

    let ui_limits = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: SANDBOX_JOB_UI_RESTRICTIONS,
    };
    let ok = SetInformationJobObject(
        h_job.raw(),
        JobObjectBasicUIRestrictions,
        &ui_limits as *const _ as *const _,
        std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
    );
    if ok == 0 {
        return Err(anyhow::anyhow!(
            "SetInformationJobObject UI restrictions failed: {}",
            GetLastError()
        ));
    }
    Ok(h_job.into_raw())
}

/// Open a named pipe created by the parent process.
fn open_pipe(name: &str, access: u32) -> Result<HANDLE> {
    let path = to_wide(name);
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            0,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            0,
        )
    };
    if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        return Err(anyhow::anyhow!("CreateFileW failed for pipe {name}: {err}"));
    }
    Ok(handle)
}

/// Send an error frame back to the parent process.
fn send_error(
    writer: &Arc<StdMutex<File>>,
    code: &str,
    message: String,
    deadline: std::time::Instant,
) -> Result<()> {
    send_cleanup_frame(
        writer,
        Message::Error {
            payload: ErrorPayload {
                message,
                code: code.to_string(),
            },
        },
        deadline,
    )
}

fn send_cleanup_frame(
    writer: &Arc<StdMutex<File>>,
    message: Message,
    deadline: std::time::Instant,
) -> Result<()> {
    let writer = writer.clone();
    let worker = std::thread::Builder::new()
        .name("runseal-cleanup-report".into())
        .spawn(move || {
            loop {
                if std::time::Instant::now() >= deadline {
                    anyhow::bail!("execution result delivery deadline");
                }
                match writer.try_lock() {
                    Ok(mut guard) => {
                        if std::time::Instant::now() >= deadline {
                            anyhow::bail!("execution result delivery deadline");
                        }
                        return write_frame(
                            &mut *guard,
                            &FramedMessage {
                                version: IPC_PROTOCOL_VERSION,
                                message,
                            },
                        );
                    }
                    Err(std::sync::TryLockError::WouldBlock) => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(std::sync::TryLockError::Poisoned(_)) => {
                        anyhow::bail!("execution result writer unavailable");
                    }
                }
            }
        })?;
    let mut owner = WorkerOwner::new(worker);
    let worker = owner
        .0
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("report owner unavailable"))?;
    while !RetainedWorker::completed(worker) {
        if std::time::Instant::now() >= deadline {
            unsafe {
                windows_sys::Win32::System::IO::CancelSynchronousIo(worker.as_raw_handle() as _);
            }
            anyhow::bail!("execution result delivery deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    owner
        .0
        .take()
        .ok_or_else(|| anyhow::anyhow!("report owner unavailable"))?
        .join()
        .map_err(|_| anyhow::anyhow!("execution result delivery failed"))?
}

fn send_cleanup_error(
    writer: &Arc<StdMutex<File>>,
    message: &str,
    deadline: std::time::Instant,
) -> Result<()> {
    send_cleanup_frame(
        writer,
        Message::Error {
            payload: ErrorPayload {
                code: "cleanup_failed".into(),
                message: message.into(),
            },
        },
        deadline,
    )
}

fn send_cleanup_started(
    writer: &Arc<StdMutex<File>>,
    process: HANDLE,
    timed_out: bool,
    deadline: std::time::Instant,
) -> Result<()> {
    send_cleanup_frame(
        writer,
        Message::CleanupStarted {
            payload: codex_windows_sandbox::CleanupStartedPayload {
                deadline: codex_windows_sandbox::CleanupDeadlinePayload::new(deadline)?,
                exit_code: completed_exit_code(process, std::time::Instant::now()).ok(),
                timed_out,
            },
        },
        deadline,
    )
}

fn send_exit(
    writer: &Arc<StdMutex<File>>,
    payload: ExitPayload,
    deadline: std::time::Instant,
) -> Result<()> {
    send_cleanup_frame(writer, Message::Exit { payload }, deadline)
}

fn send_unverified_range_cleanup(
    writer: &Arc<StdMutex<File>>,
    process: HANDLE,
    timed_out: bool,
    deadline: std::time::Instant,
) -> Result<()> {
    match completed_exit_code(process, std::time::Instant::now()) {
        Ok(exit_code) => send_exit(
            writer,
            ExitPayload {
                exit_code,
                timed_out,
                cleanup_complete: false,
            },
            deadline,
        ),
        Err(_) => send_cleanup_error(
            writer,
            "execution range cleanup could not be verified",
            deadline,
        ),
    }
}

/// Read and validate the initial spawn request frame.
fn read_spawn_request(reader: &mut File, deadline: std::time::Instant) -> Result<SpawnRequest> {
    let mut frames = codex_windows_sandbox::PipeFrameReader::default();
    let msg = loop {
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("runner preparation deadline");
        }
        match frames.poll(reader)? {
            codex_windows_sandbox::FramePoll::Pending => {
                std::thread::sleep(std::time::Duration::from_millis(5))
            }
            codex_windows_sandbox::FramePoll::Progress => continue,
            codex_windows_sandbox::FramePoll::Closed => {
                anyhow::bail!("runner: pipe closed before spawn_request")
            }
            codex_windows_sandbox::FramePoll::Message(message) => break message,
        }
    };
    if std::time::Instant::now() >= deadline {
        anyhow::bail!("runner preparation deadline");
    }
    if msg.version != IPC_PROTOCOL_VERSION {
        anyhow::bail!("runner: unsupported protocol version {}", msg.version);
    }
    match msg.message {
        Message::SpawnRequest { payload } => Ok(*payload),
        _ => anyhow::bail!("runner: expected spawn_request"),
    }
}

fn read_acl_mutex_exists() -> Result<bool> {
    let name = to_wide(OsStr::new(READ_ACL_MUTEX_NAME));
    let handle = unsafe { OpenMutexW(MUTEX_ALL_ACCESS, 0, name.as_ptr()) };
    if handle == 0 {
        let err = unsafe { GetLastError() };
        if err == ERROR_FILE_NOT_FOUND {
            return Ok(false);
        }
        return Err(anyhow::anyhow!("OpenMutexW failed: {err}"));
    }
    unsafe {
        CloseHandle(handle);
    }
    Ok(true)
}

/// Pick an effective CWD, using a junction if the ACL helper is active.
fn effective_cwd(req_cwd: &Path, log_dir: Option<&Path>) -> PathBuf {
    let use_junction = match read_acl_mutex_exists() {
        Ok(exists) => exists,
        Err(err) => {
            log_note(
                &format!(
                    "junction: failed to probe ACL mutex state: {err}; defaulting to junction cwd"
                ),
                log_dir,
            );
            true
        }
    };
    if use_junction {
        cwd_junction::create_cwd_junction(req_cwd, log_dir).unwrap_or_else(|| req_cwd.to_path_buf())
    } else {
        req_cwd.to_path_buf()
    }
}

fn restore_appcontainer_profile_environment(
    env: &mut HashMap<String, String>,
    runner_env: &HashMap<String, String>,
) -> Result<()> {
    for key in ["LOCALAPPDATA", "TEMP", "TMP"] {
        let value = runner_env
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.clone())
            .with_context(|| format!("runner environment is missing {key}"))?;
        env.retain(|candidate, _| !candidate.eq_ignore_ascii_case(key));
        env.insert(key.to_string(), value);
    }
    Ok(())
}

fn spawn_ipc_process(req: &SpawnRequest) -> Result<IpcSpawnedProcess> {
    if req.tty && req.control_open {
        anyhow::bail!("control requires pipe mode");
    }
    let log_dir = req.codex_home.clone();
    hide_current_user_profile_dir(req.codex_home.as_path());
    let isolation_mode = isolation_mode_for_permission_profile(
        &req.permission_profile,
        &req.workspace_roots,
        &req.cwd,
        &req.env,
    )
    .context("resolve permission profile isolation mode")?;
    let mut cap_psids: Vec<LocalSid> = Vec::new();
    for sid in &req.cap_sids {
        cap_psids.push(
            LocalSid::from_string(sid)
                .context("ConvertStringSidToSidW failed for capability SID")?,
        );
    }
    if cap_psids.is_empty() {
        anyhow::bail!("runner: empty capability SID list");
    }

    // The token helpers still take raw SID pointers, but we keep ownership in `LocalSid`
    // wrappers for as long as possible. That way any failure after SID parsing but before the
    // child is fully spawned still releases the backing LocalAlloc memory automatically.
    let cap_psid_ptrs: Vec<*mut _> = cap_psids.iter().map(LocalSid::as_ptr).collect();
    let base = OwnedWinHandle::new(unsafe { get_current_token_for_restriction()? });
    let h_token = if isolation_mode == WindowsSandboxIsolationMode::AppContainerCapabilities {
        None
    } else {
        Some(OwnedWinHandle::new(unsafe {
            match isolation_mode {
                WindowsSandboxIsolationMode::ReadOnlyCapability => {
                    create_elevated_readonly_token_with_caps_from(base.raw(), &cap_psid_ptrs)
                }
                WindowsSandboxIsolationMode::WritableRootsCapability => {
                    create_elevated_workspace_write_token_with_caps_from(base.raw(), &cap_psid_ptrs)
                }
                WindowsSandboxIsolationMode::AppContainerCapabilities => {
                    unreachable!("workspace-contained uses the base sandbox-user token plus LowBox")
                }
            }
        }?))
    };
    let child_token = h_token.as_ref().map_or(base.raw(), OwnedWinHandle::raw);
    let mut appcontainer_capabilities =
        if isolation_mode == WindowsSandboxIsolationMode::AppContainerCapabilities {
            Some(AppContainerSecurityCapabilities::new(&req.cap_sids)?)
        } else {
            None
        };
    let security_capabilities = appcontainer_capabilities
        .as_mut()
        .map(AppContainerSecurityCapabilities::as_mut_ptr);
    let mut child_env = req.env.clone();
    if security_capabilities.is_some() {
        restore_appcontainer_profile_environment(
            &mut child_env,
            &std::env::vars().collect::<HashMap<_, _>>(),
        )?;
        log_note(
            &format!("lowbox: active capability SIDs={:?}", req.cap_sids),
            Some(log_dir.as_path()),
        );
    }
    unsafe {
        // These ACL adjustments need the raw SID values, but ownership stays with `cap_psids`.
        // We do not manually `LocalFree` anything here; the wrappers handle every return path.
        allow_null_device(cap_psid_ptrs[0]);
        for psid in &cap_psid_ptrs {
            allow_null_device(*psid);
        }
    }

    let effective_cwd = effective_cwd(&req.cwd, Some(log_dir.as_path()));

    let mut conpty_owner = None;
    let mut hpc_handle: Option<HANDLE> = None;
    let mut pipe_handles = None;
    let (pi, stdout_handle, stderr_handle, stdin_handle) = if req.tty {
        let (pi, mut conpty) = codex_windows_sandbox::spawn_conpty_process_as_user(
            child_token,
            &req.command,
            &effective_cwd,
            &child_env,
            if req.use_private_desktop {
                LaunchDesktopMode::PrivateWindowStation
            } else {
                LaunchDesktopMode::Default
            },
            &cap_psid_ptrs,
            Some(log_dir.as_path()),
            /*start_suspended*/ true,
            security_capabilities,
            req.terminal_size
                .as_ref()
                .map_or((80, 24), |size| (size.cols as i16, size.rows as i16)),
        )?;
        hpc_handle = conpty.raw_handle();
        let input_write = conpty.take_input_write();
        let output_read = conpty.take_output_read();
        conpty_owner = Some(conpty);
        let stdin_handle = if req.stdin_open {
            Some(input_write)
        } else {
            unsafe {
                CloseHandle(input_write);
            }
            None
        };
        (
            pi,
            output_read,
            windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE,
            stdin_handle,
        )
    } else {
        let stdin_mode = if req.stdin_open {
            StdinMode::Open
        } else {
            StdinMode::Closed
        };
        let spawned_pipes: PipeSpawnHandles = spawn_process_with_pipes_and_control(
            child_token,
            &req.command,
            &effective_cwd,
            &child_env,
            stdin_mode,
            StderrMode::Separate,
            if req.use_private_desktop {
                LaunchDesktopMode::PrivateWindowStation
            } else {
                LaunchDesktopMode::Default
            },
            &cap_psid_ptrs,
            Some(log_dir.as_path()),
            /*start_suspended*/ true,
            security_capabilities,
            req.control_open,
        )?;
        let pi = spawned_pipes.process;
        let stdout_handle = spawned_pipes.stdout_read;
        let stderr_handle = spawned_pipes
            .stderr_read
            .unwrap_or(windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE);
        let stdin_handle = spawned_pipes.stdin_write;
        pipe_handles = Some(spawned_pipes);
        (pi, stdout_handle, stderr_handle, stdin_handle)
    };
    Ok(IpcSpawnedProcess {
        log_dir,
        pi,
        stdout_handle,
        stderr_handle,
        stdin_handle,
        conpty_owner,
        hpc_handle,
        _pipe_handles: pipe_handles,
    })
}

trait RetainedWorker: Send {
    fn completed(&self) -> bool;
    fn join(self: Box<Self>);
    #[cfg(test)]
    fn id(&self) -> std::thread::ThreadId;
}

impl<T: Send + 'static> RetainedWorker for std::thread::JoinHandle<T> {
    fn completed(&self) -> bool {
        unsafe { WaitForSingleObject(self.as_raw_handle() as _, 0) == 0 }
    }
    fn join(self: Box<Self>) {
        let _ = (*self).join();
    }
    #[cfg(test)]
    fn id(&self) -> std::thread::ThreadId {
        self.thread().id()
    }
}

fn retained_workers() -> &'static StdMutex<Vec<Box<dyn RetainedWorker>>> {
    static WORKERS: std::sync::OnceLock<StdMutex<Vec<Box<dyn RetainedWorker>>>> =
        std::sync::OnceLock::new();
    WORKERS.get_or_init(StdMutex::default)
}

struct WorkerOwner<T: Send + 'static>(Option<std::thread::JoinHandle<T>>);

impl<T: Send + 'static> WorkerOwner<T> {
    fn new(worker: std::thread::JoinHandle<T>) -> Self {
        Self(Some(worker))
    }
}

impl<T: Send + 'static> Drop for WorkerOwner<T> {
    fn drop(&mut self) {
        let Some(worker) = self.0.take() else {
            return;
        };
        if RetainedWorker::completed(&worker) {
            let _ = worker.join();
            return;
        }
        let mut retained = retained_workers()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut index = 0;
        while index < retained.len() {
            if retained[index].completed() {
                retained.swap_remove(index).join();
            } else {
                index += 1;
            }
        }
        retained.push(Box::new(worker));
    }
}

/// Stream stdout/stderr from the child into Output frames.
fn spawn_output_reader(
    writer: Arc<StdMutex<File>>,
    handle: HANDLE,
    stream: OutputStream,
    done: Arc<AtomicBool>,
) -> WorkerOwner<Result<()>> {
    let worker = std::thread::spawn(move || {
        let mut reader = unsafe { File::from_raw_handle(handle as _) };
        let mut bytes = [0; 64 * 1024];
        loop {
            let available = match codex_windows_sandbox::available_pipe_bytes(&reader)? {
                None => return Ok(()),
                Some(0) if done.load(Ordering::Acquire) => return Ok(()),
                Some(0) => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                }
                Some(available) => available.min(bytes.len()),
            };
            let count = reader.read(&mut bytes[..available])?;
            if count == 0 {
                return Ok(());
            }
            let msg = FramedMessage {
                version: IPC_PROTOCOL_VERSION,
                message: Message::Output {
                    payload: OutputPayload {
                        data_b64: encode_bytes(&bytes[..count]),
                        stream,
                    },
                },
            };
            let mut writer = writer
                .lock()
                .map_err(|_| anyhow::anyhow!("output writer unavailable"))?;
            write_frame(&mut *writer, &msg)?;
        }
    });
    WorkerOwner::new(worker)
}

type ControlInputSender = std::sync::mpsc::SyncSender<Option<Vec<u8>>>;

#[derive(Clone, Default)]
struct RunnerCleanupClock {
    deadline: Arc<StdMutex<Option<std::time::Instant>>>,
    budget: codex_windows_sandbox::CleanupBudget,
}

impl RunnerCleanupClock {
    fn new(budget: codex_windows_sandbox::CleanupBudget) -> Self {
        Self {
            budget,
            ..Self::default()
        }
    }

    fn adopt(&self, deadline: std::time::Instant) {
        let mut clock = self
            .deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let deadline = deadline.min(std::time::Instant::now() + self.budget.duration());
        *clock = Some(clock.map_or(deadline, |previous| previous.min(deadline)));
    }

    fn begin(&self) -> std::time::Instant {
        *self
            .deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(|| std::time::Instant::now() + self.budget.duration())
    }

    fn remaining(&self) -> Option<std::time::Duration> {
        self.deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .map(|deadline| deadline.saturating_duration_since(std::time::Instant::now()))
    }
}

fn request_termination(
    requested: &AtomicBool,
    process: &StdMutex<Option<HANDLE>>,
    clock: &RunnerCleanupClock,
    job: Option<&OwnedWinHandle>,
) {
    clock.begin();
    requested.store(true, Ordering::Release);
    if let Some(job) = job
        && unsafe { TerminateJobObject(job.raw(), 1) } != 0
    {
        return;
    }
    if let Ok(process) = process.lock()
        && let Some(handle) = *process
    {
        unsafe {
            TerminateProcess(handle, 1);
        }
    }
}

fn spawn_control_workers(
    control: codex_windows_sandbox::DuplexControl,
    output: Arc<StdMutex<File>>,
    done: Arc<AtomicBool>,
    process_handle: Arc<StdMutex<Option<HANDLE>>>,
    terminated: Arc<AtomicBool>,
    cleanup_clock: RunnerCleanupClock,
    job: Arc<OwnedWinHandle>,
) -> (
    ControlInputSender,
    WorkerOwner<Result<()>>,
    WorkerOwner<Result<()>>,
) {
    let (sender, receiver) = std::sync::mpsc::sync_channel::<Option<Vec<u8>>>(1);
    let mut input = control.clone();
    let write_output = output.clone();
    let read_process = process_handle.clone();
    let read_terminated = terminated.clone();
    let read_clock = cleanup_clock.clone();
    let read_job = job.clone();
    let write_worker = std::thread::spawn(move || {
        let result = (|| -> Result<()> {
            while !done.load(Ordering::Acquire) {
                let bytes = match receiver.recv_timeout(std::time::Duration::from_millis(10)) {
                    Ok(Some(bytes)) => bytes,
                    Ok(None) => {
                        input.close_input()?;
                        return Ok(());
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                };
                let mut offset = 0;
                while offset < bytes.len() {
                    if done.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    match std::io::Write::write(&mut input, &bytes[offset..]) {
                        Ok(0) => anyhow::bail!("control input write failed"),
                        Ok(count) => offset += count,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                let mut writer = write_output
                    .lock()
                    .map_err(|_| anyhow::anyhow!("control acknowledgement unavailable"))?;
                write_frame(
                    &mut *writer,
                    &FramedMessage {
                        version: IPC_PROTOCOL_VERSION,
                        message: Message::ControlAcknowledged {
                            payload: codex_windows_sandbox::StdinAcknowledgedPayload {
                                bytes: bytes.len(),
                            },
                        },
                    },
                )?;
            }
            Ok(())
        })();
        if result.is_err() {
            request_termination(&terminated, &process_handle, &cleanup_clock, Some(&job));
        }
        result
    });
    let write_worker = WorkerOwner::new(write_worker);
    let read_worker = std::thread::spawn(move || {
        let mut control = control;
        let mut bytes = [0; 64 * 1024];
        let result = (|| {
            loop {
                match std::io::Read::read(&mut control, &mut bytes) {
                    Ok(0) => return Ok(()),
                    Ok(count) => {
                        let mut writer = output
                            .lock()
                            .map_err(|_| anyhow::anyhow!("control output unavailable"))?;
                        write_frame(
                            &mut *writer,
                            &FramedMessage {
                                version: IPC_PROTOCOL_VERSION,
                                message: Message::Output {
                                    payload: OutputPayload {
                                        data_b64: encode_bytes(&bytes[..count]),
                                        stream: OutputStream::Control,
                                    },
                                },
                            },
                        )?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        })();
        if result.is_err() {
            request_termination(
                &read_terminated,
                &read_process,
                &read_clock,
                Some(&read_job),
            );
        }
        result
    });
    (sender, write_worker, WorkerOwner::new(read_worker))
}

fn join_worker<T: Send + 'static>(
    mut owner: WorkerOwner<T>,
    deadline: std::time::Instant,
    cancel: bool,
) -> Result<T> {
    let worker = owner
        .0
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("worker owner unavailable"))?;
    while !RetainedWorker::completed(worker) {
        if cancel {
            unsafe {
                windows_sys::Win32::System::IO::CancelSynchronousIo(worker.as_raw_handle() as _);
            }
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("worker cleanup deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    owner
        .0
        .take()
        .ok_or_else(|| anyhow::anyhow!("worker owner unavailable"))?
        .join()
        .map_err(|_| anyhow::anyhow!("worker cleanup failed"))
}

fn join_control_worker(
    worker: WorkerOwner<Result<()>>,
    deadline: std::time::Instant,
) -> Result<()> {
    join_worker(worker, deadline, false)?
}

/// Read controls independently of a potentially blocked child stdin write.
#[allow(clippy::too_many_arguments)]
fn spawn_input_loop(
    mut reader: File,
    stdin_handle: Option<HANDLE>,
    control_sender: Option<ControlInputSender>,
    output: Arc<StdMutex<File>>,
    hpc_handle: Arc<StdMutex<Option<HANDLE>>>,
    process_handle: Arc<StdMutex<Option<HANDLE>>>,
    terminated_by_request: Arc<AtomicBool>,
    _log_dir: Option<PathBuf>,
    done: Arc<AtomicBool>,
    cleanup_clock: RunnerCleanupClock,
    job: Arc<OwnedWinHandle>,
) -> (WorkerOwner<()>, WorkerOwner<()>) {
    let controls_output = output.clone();
    let (input_sender, input_receiver) =
        std::sync::mpsc::sync_channel::<Option<(Vec<u8>, bool)>>(1);
    let input_done = done.clone();
    let input_worker = std::thread::spawn(move || {
        if let Some(handle) = stdin_handle {
            while !input_done.load(Ordering::Acquire) {
                let (bytes, acknowledge) =
                    match input_receiver.recv_timeout(std::time::Duration::from_millis(5)) {
                        Ok(Some(input)) => input,
                        Ok(None) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                    };
                let mut offset = 0;
                while offset < bytes.len() {
                    let mut written = 0u32;
                    let ok = unsafe {
                        windows_sys::Win32::Storage::FileSystem::WriteFile(
                            handle,
                            bytes[offset..].as_ptr(),
                            (bytes.len() - offset) as u32,
                            &mut written,
                            ptr::null_mut(),
                        )
                    };
                    if ok == 0 || written == 0 {
                        unsafe {
                            CloseHandle(handle);
                        }
                        return;
                    }
                    offset += written as usize;
                }
                if !acknowledge {
                    continue;
                }
                let acknowledgement = FramedMessage {
                    version: IPC_PROTOCOL_VERSION,
                    message: Message::StdinAcknowledged {
                        payload: codex_windows_sandbox::StdinAcknowledgedPayload {
                            bytes: bytes.len(),
                        },
                    },
                };
                if let Ok(mut output) = output.lock() {
                    if write_frame(&mut *output, &acknowledgement).is_err() {
                        break;
                    }
                } else {
                    break;
                }
            }
            unsafe {
                CloseHandle(handle);
            }
        }
    });
    let input_worker = WorkerOwner::new(input_worker);
    let controls_worker = std::thread::spawn(move || {
        while !done.load(Ordering::Acquire) {
            let msg = match read_frame(&mut reader) {
                Ok(Some(message)) => message,
                _ => break,
            };
            match msg.message {
                Message::Stdin { payload } => {
                    if payload.data_b64.len() > 4 * (64 * 1024usize).div_ceil(3) {
                        break;
                    }
                    let Ok(bytes) = decode_bytes(&payload.data_b64) else {
                        break;
                    };
                    if bytes.len() > 64 * 1024 {
                        break;
                    }
                    // The capture path waits for acknowledgement before the next frame.
                    // A sender that exceeds this bounded window fails closed.
                    if input_sender.try_send(Some((bytes, true))).is_err() {
                        break;
                    }
                }
                Message::Control { payload } => {
                    if payload.data_b64.len() > 4 * (64 * 1024usize).div_ceil(3) {
                        break;
                    }
                    let Ok(bytes) = decode_bytes(&payload.data_b64) else {
                        break;
                    };
                    if bytes.is_empty()
                        || bytes.len() > 64 * 1024
                        || control_sender
                            .as_ref()
                            .is_none_or(|sender| sender.try_send(Some(bytes)).is_err())
                    {
                        break;
                    }
                }
                Message::CloseControl { .. }
                    if control_sender
                        .as_ref()
                        .is_none_or(|sender| sender.try_send(None).is_err()) =>
                {
                    break;
                }
                Message::Interrupt { .. }
                    if hpc_handle.lock().ok().and_then(|guard| *guard).is_none()
                        || input_sender.try_send(Some((vec![3], false))).is_err() =>
                {
                    request_termination(
                        &terminated_by_request,
                        &process_handle,
                        &cleanup_clock,
                        Some(&job),
                    );
                    let _ = send_cleanup_frame(
                        &controls_output,
                        Message::Error {
                            payload: ErrorPayload {
                                code: "terminal_control_failed".into(),
                                message: "terminal interrupt unavailable".into(),
                            },
                        },
                        cleanup_clock.begin(),
                    );
                    break;
                }
                Message::CloseStdin { .. } if input_sender.try_send(None).is_err() => {
                    break;
                }
                Message::Resize {
                    payload: ResizePayload { rows, cols },
                } => {
                    if let Ok(guard) = hpc_handle.lock()
                        && let Some(hpc) = guard.as_ref()
                        && (rows == 0
                            || rows > 1000
                            || cols == 0
                            || cols > 1000
                            || resize_conpty_handle(*hpc, cols as i16, rows as i16).is_err())
                    {
                        request_termination(
                            &terminated_by_request,
                            &process_handle,
                            &cleanup_clock,
                            Some(&job),
                        );
                        let _ = send_cleanup_frame(
                            &controls_output,
                            Message::Error {
                                payload: ErrorPayload {
                                    code: "terminal_control_failed".into(),
                                    message: "terminal resize failed".into(),
                                },
                            },
                            cleanup_clock.begin(),
                        );
                        break;
                    }
                }
                Message::Terminate { payload } => {
                    cleanup_clock.adopt(
                        payload
                            .deadline()
                            .unwrap_or_else(|_| std::time::Instant::now()),
                    );
                    break;
                }
                _ => {}
            }
        }
        if done.load(Ordering::Acquire) {
            return;
        }
        request_termination(
            &terminated_by_request,
            &process_handle,
            &cleanup_clock,
            Some(&job),
        );
    });
    (WorkerOwner::new(controls_worker), input_worker)
}
const WAIT_CLEANUP_EXPIRED: u32 = 0xffff_fffe;

fn wait_for_execution_exit(
    process: HANDLE,
    timeout_ms: Option<u64>,
    cleanup_clock: &RunnerCleanupClock,
) -> u32 {
    let execution_start = std::time::Instant::now();
    let timeout = timeout_ms.map(std::time::Duration::from_millis);
    loop {
        let wait_ms = match timeout {
            None => 5,
            Some(timeout) => {
                let remaining = timeout.saturating_sub(execution_start.elapsed());
                if remaining.is_zero() {
                    break WAIT_TIMEOUT;
                }
                remaining.as_millis().min(u128::from(INFINITE - 1)).max(1) as u32
            }
        };
        if cleanup_clock
            .remaining()
            .is_some_and(|remaining| remaining.is_zero())
        {
            return WAIT_CLEANUP_EXPIRED;
        }
        let result = unsafe { WaitForSingleObject(process, wait_ms.min(5)) };
        if result != WAIT_TIMEOUT {
            break result;
        }
    }
}

fn completed_exit_code(process: HANDLE, deadline: std::time::Instant) -> Result<i32> {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    let mut raw_exit = 0;
    if unsafe {
        WaitForSingleObject(
            process,
            remaining.as_millis().min(u128::from(INFINITE - 1)) as u32,
        )
    } != 0
        || unsafe { GetExitCodeProcess(process, &mut raw_exit) } == 0
    {
        anyhow::bail!("execution exit status could not be verified");
    }
    Ok(raw_exit as i32)
}

/// Entry point for the Windows command runner process.
pub fn main() -> Result<()> {
    let preparation_deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    unsafe {
        // CreateProcessWithLogonW does not reliably preserve the broker's transient error mode.
        // Set it in the runner so every sandbox child inherits non-interactive error reporting.
        SetErrorMode(NONINTERACTIVE_ERROR_MODE);
        restrict_current_token_default_dacl_to_logon_sid()
            .context("restrict command-runner object ACLs")?;
    }
    let mut pipe_in = None;
    let mut pipe_out = None;
    for arg in std::env::args().skip(1) {
        if let Some(rest) = arg.strip_prefix("--pipe-in=") {
            pipe_in = Some(rest.to_string());
        } else if let Some(rest) = arg.strip_prefix("--pipe-out=") {
            pipe_out = Some(rest.to_string());
        }
    }

    let Some(pipe_in) = pipe_in else {
        anyhow::bail!("runner: no pipe-in provided");
    };
    let Some(pipe_out) = pipe_out else {
        anyhow::bail!("runner: no pipe-out provided");
    };

    // Open both pipe ends under guards first so a failure on the second open cannot leak the
    // first HANDLE. Only after both opens succeed do we transfer ownership into `File`, which
    // then becomes responsible for closing them.
    let h_pipe_in = OwnedWinHandle::new(open_pipe(&pipe_in, FILE_GENERIC_READ)?);
    let h_pipe_out = OwnedWinHandle::new(open_pipe(&pipe_out, FILE_GENERIC_WRITE)?);
    let mut pipe_read = unsafe { File::from_raw_handle(h_pipe_in.into_raw() as _) };
    let pipe_write = Arc::new(StdMutex::new(unsafe {
        File::from_raw_handle(h_pipe_out.into_raw() as _)
    }));

    let req = match read_spawn_request(&mut pipe_read, preparation_deadline) {
        Ok(v) => v,
        Err(err) => {
            let _ = send_error(
                &pipe_write,
                "spawn_failed",
                err.to_string(),
                preparation_deadline,
            );
            return Err(err);
        }
    };

    let cleanup_clock = RunnerCleanupClock::new(req.cleanup_budget);

    let h_job = match unsafe { create_sandbox_job() } {
        Ok(job) => Arc::new(OwnedWinHandle::new(job)),
        Err(err) => {
            let _ = send_error(
                &pipe_write,
                "spawn_failed",
                err.to_string(),
                preparation_deadline,
            );
            return Err(err);
        }
    };

    if std::time::Instant::now() >= preparation_deadline {
        anyhow::bail!("runner preparation deadline before process creation");
    }
    let ipc_spawn = match spawn_ipc_process(&req) {
        Ok(value) => value,
        Err(err) => {
            let _ = send_error(
                &pipe_write,
                "spawn_failed",
                err.to_string(),
                preparation_deadline,
            );
            return Err(err);
        }
    };

    unsafe {
        if AssignProcessToJobObject(h_job.raw(), ipc_spawn.pi.hProcess) == 0 {
            let error = GetLastError();
            let _ = TerminateProcess(ipc_spawn.pi.hProcess, 1);
            CloseHandle(ipc_spawn.pi.hThread);
            CloseHandle(ipc_spawn.pi.hProcess);
            let err = anyhow::anyhow!(
                "runner failed to assign suspended child process to sandbox job: {error}"
            );
            let _ = send_error(
                &pipe_write,
                "spawn_failed",
                err.to_string(),
                preparation_deadline,
            );
            return Err(err);
        }
        if std::time::Instant::now() >= preparation_deadline {
            let _ = TerminateJobObject(h_job.raw(), 1);
            CloseHandle(ipc_spawn.pi.hThread);
            CloseHandle(ipc_spawn.pi.hProcess);
            anyhow::bail!("runner preparation deadline before process resume");
        }
        if ResumeThread(ipc_spawn.pi.hThread) == u32::MAX {
            let error = GetLastError();
            let _ = TerminateJobObject(h_job.raw(), 1);
            CloseHandle(ipc_spawn.pi.hThread);
            CloseHandle(ipc_spawn.pi.hProcess);
            let err = anyhow::anyhow!("runner failed to resume sandboxed child process: {error}");
            let _ = send_error(
                &pipe_write,
                "spawn_failed",
                err.to_string(),
                preparation_deadline,
            );
            return Err(err);
        }
    }

    let log_dir = Some(ipc_spawn.log_dir.as_path());
    let control = ipc_spawn
        ._pipe_handles
        .as_ref()
        .and_then(|pipes| pipes.control.clone());
    let pi = ipc_spawn.pi;
    let stdout_handle = ipc_spawn.stdout_handle;
    let stderr_handle = ipc_spawn.stderr_handle;
    let mut conpty_owner = ipc_spawn.conpty_owner;
    let stdin_handle = ipc_spawn.stdin_handle;
    let hpc_handle = Arc::new(StdMutex::new(ipc_spawn.hpc_handle));

    let process_handle = Arc::new(StdMutex::new(Some(pi.hProcess)));
    let terminated_by_request = Arc::new(AtomicBool::new(false));

    let msg = FramedMessage {
        version: IPC_PROTOCOL_VERSION,
        message: Message::SpawnReady {
            payload: SpawnReady {
                process_id: unsafe { GetProcessId(pi.hProcess) },
            },
        },
    };
    if let Err(err) = send_cleanup_frame(&pipe_write, msg.message, preparation_deadline) {
        let _ = send_error(
            &pipe_write,
            "spawn_failed",
            err.to_string(),
            preparation_deadline,
        );
        return Err(err);
    }
    let log_dir_owned = log_dir.map(Path::to_path_buf);
    let output_done = Arc::new(AtomicBool::new(false));
    let out_thread = spawn_output_reader(
        Arc::clone(&pipe_write),
        stdout_handle,
        OutputStream::Stdout,
        output_done.clone(),
    );
    let err_thread = if stderr_handle != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        Some(spawn_output_reader(
            Arc::clone(&pipe_write),
            stderr_handle,
            OutputStream::Stderr,
            output_done.clone(),
        ))
    } else {
        None
    };

    let control_done = Arc::new(AtomicBool::new(false));
    let control_workers = control.clone().map(|control| {
        spawn_control_workers(
            control,
            pipe_write.clone(),
            control_done.clone(),
            process_handle.clone(),
            terminated_by_request.clone(),
            cleanup_clock.clone(),
            h_job.clone(),
        )
    });
    let control_sender = control_workers
        .as_ref()
        .map(|(sender, _, _)| sender.clone());
    let (controls_thread, input_thread) = spawn_input_loop(
        pipe_read,
        stdin_handle,
        control_sender,
        Arc::clone(&pipe_write),
        Arc::clone(&hpc_handle),
        Arc::clone(&process_handle),
        Arc::clone(&terminated_by_request),
        log_dir_owned,
        control_done.clone(),
        cleanup_clock.clone(),
        h_job.clone(),
    );

    let wait_res = wait_for_execution_exit(pi.hProcess, req.timeout_ms, &cleanup_clock);
    let timed_out = wait_res == WAIT_TIMEOUT;
    let cleanup_deadline = cleanup_clock.begin();
    if wait_res != 0 && !timed_out {
        let _ = send_cleanup_frame(
            &pipe_write,
            Message::Error {
                payload: ErrorPayload {
                    code: if wait_res == WAIT_CLEANUP_EXPIRED {
                        "cleanup_failed"
                    } else {
                        "execution_failed"
                    }
                    .into(),
                    message: "failed to observe execution exit".into(),
                },
            },
            cleanup_deadline,
        );
        anyhow::bail!("failed to observe execution exit");
    }
    control_done.store(true, Ordering::Release);
    // A blocked cleanup report must not keep descendants running.
    unsafe {
        TerminateJobObject(h_job.raw(), 1);
    }
    let cleanup_announcement =
        send_cleanup_started(&pipe_write, pi.hProcess, timed_out, cleanup_deadline);
    if cleanup_announcement.is_err() {
        log_note(
            "runner cleanup failed at stage: cleanup_announcement",
            log_dir,
        );
    }
    // The top-level exit is insufficient: descendants must leave the entire range.
    if unsafe {
        codex_windows_sandbox::terminate_process_range_and_wait(
            h_job.raw() as usize,
            cleanup_deadline.saturating_duration_since(std::time::Instant::now()),
        )
    }
    .is_err()
    {
        let _ =
            send_unverified_range_cleanup(&pipe_write, pi.hProcess, timed_out, cleanup_deadline);
        anyhow::bail!("execution range cleanup could not be verified");
    }
    let exit_code = match completed_exit_code(pi.hProcess, cleanup_deadline) {
        Ok(code) => code,
        Err(error) => {
            let _ = send_cleanup_error(
                &pipe_write,
                "execution exit status could not be verified",
                cleanup_deadline,
            );
            return Err(error);
        }
    };
    if let Ok(mut process) = process_handle.lock() {
        *process = None;
    }
    unsafe {
        if pi.hThread != 0 {
            CloseHandle(pi.hThread);
        }
        if pi.hProcess != 0 {
            CloseHandle(pi.hProcess);
        }
    }
    if let Some(control) = &control {
        let cleanup_result = control
            .finish_output(cleanup_deadline.saturating_duration_since(std::time::Instant::now()))
            .and_then(|_| {
                if let Some((_sender, writer, reader)) = control_workers {
                    join_control_worker(writer, cleanup_deadline).map_err(std::io::Error::other)?;
                    join_control_worker(reader, cleanup_deadline).map_err(std::io::Error::other)?;
                }
                Ok(())
            });
        if cleanup_result.is_err() {
            log_note("runner cleanup failed at stage: control_workers", log_dir);
            let _ = send_exit(
                &pipe_write,
                ExitPayload {
                    exit_code,
                    timed_out,
                    cleanup_complete: false,
                },
                cleanup_deadline,
            );
            anyhow::bail!("control cleanup could not be verified");
        }
    }
    drop(h_job);

    if let Ok(mut guard) = hpc_handle.lock() {
        let _ = guard.take();
    }
    let close_worker = WorkerOwner::new(std::thread::spawn(move || drop(conpty_owner.take())));
    let io_cleanup = (|| -> std::result::Result<(), &'static str> {
        join_worker(close_worker, cleanup_deadline, false).map_err(|_| "conpty_close")?;
        output_done.store(true, Ordering::Release);
        join_worker(controls_thread, cleanup_deadline, true).map_err(|_| "controls_reader")?;
        join_worker(input_thread, cleanup_deadline, true).map_err(|_| "stdin_writer")?;
        join_control_worker(out_thread, cleanup_deadline).map_err(|_| "stdout_reader")?;
        if let Some(thread) = err_thread {
            join_control_worker(thread, cleanup_deadline).map_err(|_| "stderr_reader")?;
        }
        Ok::<(), &'static str>(())
    })();
    if let Err(stage) = io_cleanup {
        log_note(&format!("runner cleanup failed at stage: {stage}"), log_dir);
        let _ = send_exit(
            &pipe_write,
            ExitPayload {
                exit_code,
                timed_out,
                cleanup_complete: false,
            },
            cleanup_deadline,
        );
        anyhow::bail!("execution I/O cleanup could not be verified");
    }

    if let Err(err) = send_exit(
        &pipe_write,
        ExitPayload {
            exit_code,
            timed_out,
            cleanup_complete: cleanup_announcement.is_ok(),
        },
        cleanup_deadline,
    ) {
        log_note(&format!("runner exit write failed: {err}"), log_dir);
    }

    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unverified_range_cleanup_reports_native_exit_only_after_process_completion() -> Result<()> {
        use std::io::Write;
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use std::process::{Child, Command, Stdio};
        struct Peer(Child);
        impl Drop for Peer {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        for timeout in [false, true] {
            let tmp = tempfile::TempDir::new()?;
            let ready = tmp.path().join("execution-ready");
            let mut peer = Peer(Command::new("python").args(["-u", "-c", "import sys,pathlib; pathlib.Path(sys.argv[1]).write_text('ready'); sys.stdin.buffer.read(1); sys.exit(7)"])
                .arg(&ready).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::inherit()).spawn()?);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !ready.exists() {
                if peer.0.try_wait()?.is_some() || std::time::Instant::now() >= deadline {
                    anyhow::bail!("execution fixture readiness");
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let process = peer.0.as_raw_handle() as HANDLE;
            let mut read = 0;
            let mut write = 0;
            if unsafe {
                windows_sys::Win32::System::Pipes::CreatePipe(
                    &mut read,
                    &mut write,
                    std::ptr::null_mut(),
                    4096,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut response = unsafe { File::from_raw_handle(read as _) };
            let writer = Arc::new(StdMutex::new(unsafe { File::from_raw_handle(write as _) }));
            assert!(completed_exit_code(process, std::time::Instant::now()).is_err());
            let announced_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            send_cleanup_started(&writer, process, false, announced_deadline)?;
            let announcement = read_frame(&mut response)?
                .ok_or_else(|| anyhow::anyhow!("cleanup announcement missing"))?;
            let Message::CleanupStarted { payload } = announcement.message else {
                anyhow::bail!("cleanup announcement invalid");
            };
            assert_eq!(payload.exit_code, None);
            assert!(payload.deadline.deadline()? <= announced_deadline);
            send_unverified_range_cleanup(
                &writer,
                process,
                false,
                std::time::Instant::now() + std::time::Duration::from_secs(2),
            )?;
            let unknown = read_frame(&mut response)?
                .ok_or_else(|| anyhow::anyhow!("unknown cleanup frame missing"))?;
            let Message::Error { payload } = unknown.message else {
                anyhow::bail!("live process cannot have a reported exit status");
            };
            assert_eq!(payload.code, "cleanup_failed");
            assert!(peer.0.try_wait()?.is_none());
            let timed_out = if timeout {
                let wait =
                    wait_for_execution_exit(process, Some(0), &RunnerCleanupClock::default());
                assert_eq!(wait, WAIT_TIMEOUT);
                if unsafe { TerminateProcess(process, 1) } == 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                true
            } else {
                peer.0
                    .stdin
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("fixture stdin"))?
                    .write_all(b"R")?;
                false
            };
            let actual = completed_exit_code(
                process,
                std::time::Instant::now() + std::time::Duration::from_secs(2),
            )?;
            assert_eq!(peer.0.wait()?.code(), Some(actual));
            assert_eq!(actual, if timeout { 1 } else { 7 });
            send_cleanup_started(&writer, process, timed_out, announced_deadline)?;
            let announcement = read_frame(&mut response)?
                .ok_or_else(|| anyhow::anyhow!("known cleanup announcement missing"))?;
            let Message::CleanupStarted { payload } = announcement.message else {
                anyhow::bail!("known cleanup announcement invalid");
            };
            assert_eq!(payload.exit_code, Some(actual));
            assert_eq!(payload.timed_out, timed_out);
            send_unverified_range_cleanup(
                &writer,
                process,
                timed_out,
                std::time::Instant::now() + std::time::Duration::from_secs(2),
            )?;
            let known = read_frame(&mut response)?
                .ok_or_else(|| anyhow::anyhow!("known cleanup frame missing"))?;
            let Message::Exit { payload } = known.message else {
                anyhow::bail!("completed process facts discarded");
            };
            assert_eq!(payload.exit_code, actual);
            assert_eq!(payload.timed_out, timed_out);
            assert!(
                !payload.cleanup_complete,
                "known exit does not prove range cleanup"
            );
        }
        Ok(())
    }

    #[test]
    fn sandbox_job_configures_all_ui_restrictions() {
        unsafe {
            let job = OwnedWinHandle::new(create_sandbox_job().expect("create sandbox job"));
            let mut ui_limits: JOBOBJECT_BASIC_UI_RESTRICTIONS = std::mem::zeroed();
            let ok = QueryInformationJobObject(
                job.raw(),
                JobObjectBasicUIRestrictions,
                &mut ui_limits as *mut _ as *mut _,
                std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
                std::ptr::null_mut(),
            );

            assert_ne!(
                ok,
                0,
                "QueryInformationJobObject failed: {}",
                GetLastError()
            );
            assert_eq!(
                ui_limits.UIRestrictionsClass & SANDBOX_JOB_UI_RESTRICTIONS,
                SANDBOX_JOB_UI_RESTRICTIONS
            );
        }
    }

    #[test]
    fn appcontainer_uses_runner_profile_environment() {
        let mut child_env = HashMap::from([
            ("LocalAppData".to_string(), r"C:\fake\local".to_string()),
            ("TEMP".to_string(), r"C:\fake\temp".to_string()),
            ("TMP".to_string(), r"C:\fake\tmp".to_string()),
        ]);
        let runner_env = HashMap::from([
            (
                "LOCALAPPDATA".to_string(),
                r"C:\Users\RunSealSandbox\AppData\Local".to_string(),
            ),
            (
                "TEMP".to_string(),
                r"C:\Users\RunSealSandbox\AppData\Local\Temp".to_string(),
            ),
            (
                "TMP".to_string(),
                r"C:\Users\RunSealSandbox\AppData\Local\Temp".to_string(),
            ),
        ]);

        restore_appcontainer_profile_environment(&mut child_env, &runner_env)
            .expect("restore AppContainer profile environment");

        assert_eq!(
            child_env.get("LOCALAPPDATA"),
            runner_env.get("LOCALAPPDATA")
        );
        assert_eq!(child_env.get("TEMP"), runner_env.get("TEMP"));
        assert_eq!(child_env.get("TMP"), runner_env.get("TMP"));
        assert_eq!(
            child_env
                .keys()
                .filter(|key| key.eq_ignore_ascii_case("LOCALAPPDATA"))
                .count(),
            1
        );
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    fn budget_request(milliseconds: u64) -> Result<FramedMessage> {
        Ok(FramedMessage {
            version: IPC_PROTOCOL_VERSION,
            message: Message::SpawnRequest {
                payload: Box::new(SpawnRequest {
                    command: vec!["unused-command".into()],
                    cwd: PathBuf::from(r"C:\workspace"),
                    env: HashMap::new(),
                    permission_profile: codex_protocol::models::PermissionProfile::read_only(),
                    workspace_roots: Vec::new(),
                    codex_home: PathBuf::from(r"C:\runtime"),
                    real_codex_home: PathBuf::from(r"C:\runtime"),
                    cap_sids: Vec::new(),
                    timeout_ms: None,
                    cleanup_budget: codex_windows_sandbox::CleanupBudget::try_from(milliseconds)
                        .map_err(|message| anyhow::anyhow!(message))?,
                    tty: false,
                    terminal_size: None,
                    stdin_open: true,
                    control_open: false,
                    use_private_desktop: false,
                }),
            },
        })
    }

    fn framed_budget_request(value: &serde_json::Value) -> Result<SpawnRequest> {
        let mut read = 0;
        let mut write = 0;
        if unsafe {
            windows_sys::Win32::System::Pipes::CreatePipe(
                &mut read,
                &mut write,
                ptr::null_mut(),
                4096,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut reader = unsafe { File::from_raw_handle(read as _) };
        let mut writer = unsafe { File::from_raw_handle(write as _) };
        let bytes = serde_json::to_vec(value)?;
        writer.write_all(&(bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&bytes)?;
        read_spawn_request(
            &mut reader,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        )
    }

    #[test]
    fn framed_cleanup_budget_is_mandatory_bounded_and_versioned() -> Result<()> {
        let valid = serde_json::to_value(budget_request(60000)?)?;
        let request = framed_budget_request(&valid)?;
        let clock = RunnerCleanupClock::new(request.cleanup_budget);
        let started = clock.begin();
        assert!(
            clock
                .remaining()
                .is_some_and(|remaining| remaining > std::time::Duration::from_secs(59))
        );
        clock.adopt(std::time::Instant::now() + std::time::Duration::from_secs(60));
        assert_eq!(
            clock.begin(),
            started,
            "repeated adoption cannot renew the clock"
        );
        let earlier = std::time::Instant::now() + std::time::Duration::from_millis(25);
        clock.adopt(earlier);
        assert_eq!(clock.begin(), earlier);
        for bad in [
            serde_json::json!(0),
            serde_json::json!(99),
            serde_json::json!(60001),
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!("secret-budget-canary"),
            serde_json::Value::Null,
        ] {
            let mut invalid = valid.clone();
            invalid["payload"]["cleanup_budget"] = bad;
            let error = framed_budget_request(&invalid)
                .err()
                .ok_or_else(|| anyhow::anyhow!("invalid budget accepted"))?;
            assert!(!error.to_string().contains("secret-budget-canary"));
        }
        let mut missing = valid.clone();
        missing["payload"]
            .as_object_mut()
            .unwrap()
            .remove("cleanup_budget");
        assert!(framed_budget_request(&missing).is_err());
        let mut previous = valid;
        previous["version"] = serde_json::json!(10);
        assert!(framed_budget_request(&previous).is_err());
        Ok(())
    }

    #[test]
    fn configured_runner_budget_bounds_native_wait_and_preserves_pending_peer() -> Result<()> {
        use std::io::BufRead;
        struct Peer(std::process::Child);
        impl Drop for Peer {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let python = String::from_utf8(
            std::process::Command::new("where.exe")
                .arg("python")
                .output()?
                .stdout,
        )?;
        let python = python
            .lines()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Python required"))?;
        let mut outcomes = Vec::new();
        for milliseconds in [100, 350] {
            for adopt in [false, true] {
                let request =
                    framed_budget_request(&serde_json::to_value(budget_request(milliseconds)?)?)?;
                let clock = RunnerCleanupClock::new(request.cleanup_budget);
                let mut peer = Peer(std::process::Command::new(python).args(["-u", "-c", "import sys; print('READY',flush=True); assert sys.stdin.buffer.read(1)==b'R'; sys.exit(7)"])
                    .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn()?);
                let mut ready = String::new();
                std::io::BufReader::new(
                    peer.0
                        .stdout
                        .take()
                        .ok_or_else(|| anyhow::anyhow!("fixture stdout"))?,
                )
                .read_line(&mut ready)?;
                let current = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
                let mut wait_only = 0;
                if unsafe {
                    windows_sys::Win32::Foundation::DuplicateHandle(
                        current,
                        peer.0.as_raw_handle() as _,
                        current,
                        &mut wait_only,
                        windows_sys::Win32::System::Threading::PROCESS_SYNCHRONIZE,
                        0,
                        0,
                    )
                } == 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                let wait_only = OwnedWinHandle::new(wait_only);
                let started = std::time::Instant::now();
                if adopt {
                    clock.adopt(started + std::time::Duration::from_secs(60));
                }
                let requested = AtomicBool::new(false);
                request_termination(
                    &requested,
                    &StdMutex::new(Some(wait_only.raw())),
                    &clock,
                    None,
                );
                let deadline = clock.begin();
                let waiter_clock = clock.clone();
                let handle = wait_only.raw() as usize;
                let (tx, rx) = std::sync::mpsc::channel();
                let waiter = std::thread::spawn(move || {
                    let result = wait_for_execution_exit(handle as HANDLE, None, &waiter_clock);
                    let _ = tx.send((result, started.elapsed()));
                });
                let before_release =
                    rx.recv_timeout(std::time::Duration::from_millis(milliseconds + 500));
                let still_alive = peer.0.try_wait()?.is_none();
                peer.0
                    .stdin
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("fixture stdin"))?
                    .write_all(b"R")?;
                let status = peer.0.wait()?;
                waiter
                    .join()
                    .map_err(|_| anyhow::anyhow!("fixture waiter panic"))?;
                outcomes.push((
                    milliseconds,
                    before_release,
                    still_alive,
                    requested.load(Ordering::Acquire),
                    status.code(),
                    ready,
                    clock.begin() == deadline,
                ));
            }
        }
        for (milliseconds, outcome, alive, requested, code, ready, stable) in outcomes {
            let (wait, elapsed) = outcome?;
            assert_eq!(wait, WAIT_CLEANUP_EXPIRED);
            assert!(elapsed >= std::time::Duration::from_millis(milliseconds.saturating_sub(30)));
            assert!(elapsed < std::time::Duration::from_millis(milliseconds + 500));
            assert!(alive && requested && stable);
            assert_eq!(code, Some(7));
            assert_eq!(ready.trim(), "READY");
        }
        Ok(())
    }

    #[test]
    fn actual_control_termination_and_disconnect_stop_descendants_without_stopping_peer()
    -> Result<()> {
        use std::io::BufRead;
        struct Peer(std::process::Child);
        impl Drop for Peer {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let python = String::from_utf8(
            std::process::Command::new("where.exe")
                .arg("python")
                .output()?
                .stdout,
        )?;
        let python = python
            .lines()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Python required"))?;
        let workspace = tempfile::tempdir()?;
        let heartbeat = workspace.path().join("peer.beat");
        let mut peer = Peer(std::process::Command::new(python).args(["-u", "-c", "import sys,time; print('READY',flush=True)\nwhile True:\n with open(sys.argv[1],'ab') as f: f.write(b'B')\n time.sleep(.02)"]).arg(&heartbeat)
            .stdout(std::process::Stdio::piped()).spawn()?);
        let mut peer_ready = String::new();
        std::io::BufReader::new(
            peer.0
                .stdout
                .take()
                .ok_or_else(|| anyhow::anyhow!("peer stdout"))?,
        )
        .read_line(&mut peer_ready)?;
        assert_eq!(peer_ready.trim(), "READY");
        let mut outcomes = Vec::new();
        for termination in [0, 1, 2] {
            let job = Arc::new(OwnedWinHandle::new(unsafe { create_sandbox_job()? }));
            let mut root = Peer(std::process::Command::new(python).args(["-u", "-c", "import sys,subprocess; print('READY',flush=True); assert sys.stdin.buffer.read(1)==b'G'; p=subprocess.Popen([sys.executable,'-u','-c',\"import time; print('READY',flush=True); time.sleep(120)\"],stdout=subprocess.PIPE); assert p.stdout.readline().strip()==b'READY'; print(p.pid,flush=True); sys.stdin.buffer.read(1)"])
                .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn()?);
            let mut output = std::io::BufReader::new(
                root.0
                    .stdout
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("root stdout"))?,
            );
            let mut ready = String::new();
            output.read_line(&mut ready)?;
            if unsafe { AssignProcessToJobObject(job.raw(), root.0.as_raw_handle() as _) } == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            root.0
                .stdin
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("root stdin"))?
                .write_all(b"G")?;
            let mut descendant = String::new();
            output.read_line(&mut descendant)?;
            let descendant: u32 = descendant.trim().parse()?;
            let descendant = OwnedWinHandle::new(unsafe {
                windows_sys::Win32::System::Threading::OpenProcess(
                    windows_sys::Win32::System::Threading::PROCESS_SYNCHRONIZE
                        | windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
                    0,
                    descendant,
                )
            });
            if descendant.raw() == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut wait_only = 0;
            let current = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
            if unsafe {
                windows_sys::Win32::Foundation::DuplicateHandle(
                    current,
                    root.0.as_raw_handle() as _,
                    current,
                    &mut wait_only,
                    windows_sys::Win32::System::Threading::PROCESS_SYNCHRONIZE,
                    0,
                    0,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let wait_only = OwnedWinHandle::new(wait_only);
            let mut read = 0;
            let mut write = 0;
            if unsafe {
                windows_sys::Win32::System::Pipes::CreatePipe(
                    &mut read,
                    &mut write,
                    ptr::null_mut(),
                    4096,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let reader = unsafe { File::from_raw_handle(read as _) };
            let mut writer = unsafe { File::from_raw_handle(write as _) };
            let requested = Arc::new(AtomicBool::new(false));
            let clock = RunnerCleanupClock::default();
            let (controls, input) = spawn_input_loop(
                reader,
                None,
                None,
                Arc::new(StdMutex::new(tempfile::tempfile()?)),
                Arc::new(StdMutex::new(None)),
                Arc::new(StdMutex::new(Some(wait_only.raw()))),
                requested.clone(),
                None,
                Arc::new(AtomicBool::new(false)),
                clock.clone(),
                job.clone(),
            );
            let before = std::fs::metadata(&heartbeat)?.len();
            if termination != 2 {
                write_frame(
                    &mut writer,
                    &FramedMessage {
                        version: IPC_PROTOCOL_VERSION,
                        message: Message::Terminate {
                            payload: codex_windows_sandbox::CleanupDeadlinePayload::new(
                                std::time::Instant::now()
                                    + if termination == 1 {
                                        std::time::Duration::ZERO
                                    } else {
                                        std::time::Duration::from_secs(10)
                                    },
                            )?,
                        },
                    },
                )?;
            }
            drop(writer);
            let root_stopped =
                unsafe { WaitForSingleObject(root.0.as_raw_handle() as _, 1000) } == 0;
            let descendant_stopped = unsafe { WaitForSingleObject(descendant.raw(), 1000) } == 0;
            let actual_root_exit = root_stopped
                .then(|| {
                    completed_exit_code(root.0.as_raw_handle() as _, std::time::Instant::now())
                })
                .transpose()?;
            let actual_descendant_exit = descendant_stopped
                .then(|| completed_exit_code(descendant.raw(), std::time::Instant::now()))
                .transpose()?;
            std::thread::sleep(std::time::Duration::from_millis(100));
            let peer_progress =
                peer.0.try_wait()?.is_none() && std::fs::metadata(&heartbeat)?.len() > before;
            // Fixture cleanup follows observation; it cannot make the observed termination pass.
            unsafe {
                TerminateJobObject(job.raw(), 1);
            }
            let _ = root.0.wait()?;
            join_worker(controls, clock.begin(), true)?;
            join_worker(input, clock.begin(), true)?;
            let expired_deadline_preserved = termination != 1
                || clock
                    .remaining()
                    .is_some_and(|remaining| remaining.is_zero());
            outcomes.push((
                expired_deadline_preserved,
                ready,
                requested.load(Ordering::Acquire),
                root_stopped,
                descendant_stopped,
                actual_root_exit,
                actual_descendant_exit,
                peer_progress,
            ));
        }
        let _ = peer.0.kill();
        let _ = peer.0.wait()?;
        for (
            expired_deadline_preserved,
            ready,
            requested,
            root,
            descendant,
            root_exit,
            descendant_exit,
            peer_progress,
        ) in outcomes
        {
            assert_eq!(ready.trim(), "READY");
            assert!(requested);
            assert!(
                expired_deadline_preserved,
                "an expired host deadline cannot be renewed by the runner"
            );
            assert!(
                root && descendant,
                "the actual control path must stop its whole range"
            );
            assert_eq!(root_exit, Some(1));
            assert_eq!(descendant_exit, Some(1));
            assert!(
                peer_progress,
                "an unrelated execution must keep progressing"
            );
        }
        Ok(())
    }

    #[test]
    fn incomplete_spawn_request_expires_with_its_native_writer_still_open() -> Result<()> {
        let mut outcomes = Vec::new();
        for prefix in [vec![], vec![128, 0], vec![128, 0, 0, 0, b'{']] {
            let mut read = 0;
            let mut write = 0;
            if unsafe {
                windows_sys::Win32::System::Pipes::CreatePipe(
                    &mut read,
                    &mut write,
                    ptr::null_mut(),
                    4096,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut reader = unsafe { File::from_raw_handle(read as _) };
            let mut writer = unsafe { File::from_raw_handle(write as _) };
            writer.write_all(&prefix)?;
            let (tx, rx) = std::sync::mpsc::channel();
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(80);
            let worker = std::thread::spawn(move || {
                let _ = tx.send(read_spawn_request(&mut reader, deadline).is_err());
            });
            let before_release = rx.recv_timeout(std::time::Duration::from_millis(500));
            // Keep the real writer open until after observing the bounded result.
            drop(writer);
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("spawn request fixture panic"))?;
            outcomes.push(before_release);
        }
        for outcome in outcomes {
            assert!(outcome?, "an incomplete request cannot be accepted");
        }
        Ok(())
    }

    #[test]
    fn failed_native_termination_cannot_renew_cleanup_or_wait_for_peer_eof() -> Result<()> {
        use std::io::BufRead;
        struct Peer(std::process::Child);
        impl Drop for Peer {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let python = String::from_utf8(
            std::process::Command::new("where.exe")
                .arg("python")
                .output()?
                .stdout,
        )?;
        let python = python
            .lines()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Python required"))?;
        let mut peer = Peer(std::process::Command::new(python).args(["-u", "-c", "import sys; print('READY',flush=True); assert sys.stdin.buffer.read(1)==b'R'; sys.exit(7)"])
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn()?);
        let mut ready = String::new();
        std::io::BufReader::new(
            peer.0
                .stdout
                .take()
                .ok_or_else(|| anyhow::anyhow!("fixture stdout"))?,
        )
        .read_line(&mut ready)?;
        let current = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
        let mut wait_only = 0;
        if unsafe {
            windows_sys::Win32::Foundation::DuplicateHandle(
                current,
                peer.0.as_raw_handle() as _,
                current,
                &mut wait_only,
                windows_sys::Win32::System::Threading::PROCESS_SYNCHRONIZE,
                0,
                0,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let wait_only = OwnedWinHandle::new(wait_only);
        let requested = AtomicBool::new(false);
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(80);
        let clock = RunnerCleanupClock::default();
        clock.adopt(deadline);
        // The native handle can observe the process but cannot terminate it.
        request_termination(
            &requested,
            &StdMutex::new(Some(wait_only.raw())),
            &clock,
            None,
        );
        let accepted_deadline = clock.begin();
        let waiter_clock = clock.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = wait_only.raw() as usize;
        let waiter = std::thread::spawn(move || {
            let result = wait_for_execution_exit(handle as HANDLE, None, &waiter_clock);
            let _ = tx.send(result);
        });
        let before_release = rx.recv_timeout(std::time::Duration::from_millis(500));
        let still_alive = peer.0.try_wait()?.is_none();
        peer.0
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("fixture stdin"))?
            .write_all(b"R")?;
        let native_exit = peer.0.wait()?;
        waiter
            .join()
            .map_err(|_| anyhow::anyhow!("fixture waiter panic"))?;
        assert_eq!(ready.trim(), "READY");
        assert!(requested.load(Ordering::Acquire));
        assert_eq!(accepted_deadline, deadline);
        assert!(
            still_alive,
            "termination must be refused by the real wait-only handle"
        );
        assert_eq!(before_release?, WAIT_CLEANUP_EXPIRED);
        assert_eq!(native_exit.code(), Some(7));
        Ok(())
    }

    #[test]
    fn cleanup_reports_expire_while_the_writer_lock_or_native_pipe_remains_blocked() -> Result<()> {
        let mut outcomes = Vec::new();
        for locked in [true, false] {
            let mut held_reader = None;
            let file = if locked {
                tempfile::tempfile()?
            } else {
                let mut read = 0;
                let mut write = 0;
                if unsafe {
                    windows_sys::Win32::System::Pipes::CreatePipe(
                        &mut read,
                        &mut write,
                        ptr::null_mut(),
                        4096,
                    )
                } == 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                let reader = unsafe { File::from_raw_handle(read as _) };
                let mut writer = unsafe { File::from_raw_handle(write as _) };
                writer.write_all(&[b'X'; 4096])?;
                assert_eq!(
                    codex_windows_sandbox::available_pipe_bytes(&reader)?,
                    Some(4096)
                );
                held_reader = Some(reader);
                writer
            };
            let writer = Arc::new(StdMutex::new(file));
            let held_lock = locked.then(|| writer.lock().expect("fixture writer lock"));
            let previous: Vec<_> = retained_workers()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .map(|worker| worker.id())
                .collect();
            let output = writer.clone();
            let (result_tx, result_rx) = std::sync::mpsc::channel();
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(80);
            let caller = std::thread::spawn(move || {
                let result = if locked {
                    send_cleanup_error(&output, "execution cleanup unverified", deadline)
                } else {
                    send_exit(
                        &output,
                        ExitPayload {
                            exit_code: 7,
                            timed_out: false,
                            cleanup_complete: false,
                        },
                        deadline,
                    )
                };
                let _ = result_tx.send(result);
            });
            let result = result_rx.recv_timeout(std::time::Duration::from_millis(500));
            let before_release = result.is_ok();
            // Both original endpoints/lock remain owned until the bounded call returns.
            drop(held_lock);
            drop(held_reader);
            caller
                .join()
                .map_err(|_| anyhow::anyhow!("report fixture caller panic"))?;
            let result = match result {
                Ok(result) => result,
                Err(_) => result_rx.recv_timeout(std::time::Duration::from_secs(2))?,
            };
            let mut owners = Vec::new();
            {
                let mut retained = retained_workers()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let mut index = 0;
                while index < retained.len() {
                    if !previous.contains(&retained[index].id()) {
                        owners.push(retained.swap_remove(index));
                    } else {
                        index += 1;
                    }
                }
            }
            for owner in owners {
                // The fixture has released its own blockers; join only its retained reports.
                owner.join();
            }
            outcomes.push((before_release, result));
        }
        for (before_release, result) in outcomes {
            assert!(
                before_release,
                "cleanup report must return before the fixture releases its blocker"
            );
            assert!(
                result.is_err(),
                "blocked delivery cannot confirm a cleanup report"
            );
        }
        Ok(())
    }

    #[test]
    fn expired_join_and_abandoned_sibling_keep_native_worker_owners() -> Result<()> {
        let mut fixture_workers = Vec::new();
        let mut retained_ids = Vec::new();
        let mut expired_join_failed = false;
        let started = std::time::Instant::now();
        for expired_join in [true, false] {
            let mut read = 0;
            let mut write = 0;
            if unsafe {
                windows_sys::Win32::System::Pipes::CreatePipe(
                    &mut read,
                    &mut write,
                    ptr::null_mut(),
                    4096,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut reader = unsafe { File::from_raw_handle(read as _) };
            let mut writer = unsafe { File::from_raw_handle(write as _) };
            let (read_done, read_ack) = std::sync::mpsc::channel();
            let (release, released) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || -> Result<()> {
                let mut byte = [0];
                reader.read_exact(&mut byte)?;
                read_done.send(byte)?;
                // Keep the real pipe and native thread alive after the read completes.
                released.recv()?;
                drop(reader);
                Ok(())
            });
            let id = worker.thread().id();
            let mut observed = 0;
            let current = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
            let duplicated = unsafe {
                windows_sys::Win32::Foundation::DuplicateHandle(
                    current,
                    worker.as_raw_handle() as _,
                    current,
                    &mut observed,
                    0,
                    0,
                    windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS,
                )
            };
            if duplicated == 0 {
                drop(release);
                drop(writer);
                let _ = worker.join();
                return Err(std::io::Error::last_os_error().into());
            }
            let observed = OwnedWinHandle::new(observed);
            let owner = WorkerOwner::new(worker);
            writer.write_all(b"R")?;
            let native_read = read_ack.recv_timeout(std::time::Duration::from_secs(2));
            if expired_join {
                expired_join_failed =
                    join_control_worker(owner, std::time::Instant::now()).is_err();
            } else {
                // An earlier cleanup error can drop a sibling without attempting its join.
                drop(owner);
            }
            let retained = retained_workers()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let found = retained
                .iter()
                .any(|worker| worker.id() == id && !worker.completed());
            drop(retained);
            retained_ids.push((found, native_read));
            fixture_workers.push((id, release, writer, observed));
        }
        let elapsed = started.elapsed();
        // Release and join only this fixture's workers before evaluating the assertions.
        let mut native_completion = Vec::new();
        for (id, release, writer, observed) in fixture_workers {
            let _ = release.send(());
            drop(writer);
            native_completion.push(unsafe { WaitForSingleObject(observed.raw(), 2000) });
            let mut retained = retained_workers()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(index) = retained.iter().position(|worker| worker.id() == id) {
                let worker = retained.swap_remove(index);
                drop(retained);
                worker.join();
            }
        }
        assert!(native_completion.iter().all(|result| *result == 0));
        assert!(expired_join_failed);
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "{elapsed:?}"
        );
        for (found, native_read) in retained_ids {
            assert_eq!(native_read?, *b"R");
            assert!(
                found,
                "unfinished native worker ownership must survive cleanup failure"
            );
        }
        Ok(())
    }

    #[test]
    fn large_execution_timeout_waits_for_the_actual_gated_process_exit() -> Result<()> {
        use std::io::BufRead;
        let python = String::from_utf8(
            std::process::Command::new("where.exe")
                .arg("python")
                .output()?
                .stdout,
        )?;
        let python = python
            .lines()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Python required"))?;
        let mut child = std::process::Command::new(python).args(["-u","-c","import sys; print('READY',flush=True); assert sys.stdin.buffer.read(1)==b'R'; sys.exit(7)"])
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn()?;
        let mut input = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("stdin required"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("stdout required"))?;
        let mut ready = String::new();
        std::io::BufReader::new(stdout).read_line(&mut ready)?;
        assert_eq!(ready.trim(), "READY");
        let process = child.as_raw_handle() as usize;
        let (sender, receiver) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let result = wait_for_execution_exit(
                process as HANDLE,
                Some(1u64 << 32),
                &RunnerCleanupClock::default(),
            );
            let _ = sender.send(result);
        });
        let premature = receiver
            .recv_timeout(std::time::Duration::from_millis(50))
            .ok();
        let alive = child.try_wait()?.is_none();
        input.write_all(b"R")?;
        let status = child.wait()?;
        waiter
            .join()
            .map_err(|_| anyhow::anyhow!("wait worker failed"))?;
        assert!(alive, "the process must remain blocked on its input gate");
        assert!(
            premature.is_none(),
            "large timeout was truncated: {premature:?}"
        );
        assert_eq!(receiver.recv_timeout(std::time::Duration::from_secs(2))?, 0);
        assert_eq!(status.code(), Some(7));
        Ok(())
    }

    #[test]
    fn forced_termination_reports_the_actual_process_exit_code() -> Result<()> {
        use std::io::BufRead;
        let python = String::from_utf8(
            std::process::Command::new("where.exe")
                .arg("python")
                .output()?
                .stdout,
        )?;
        let python = python
            .lines()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Python required"))?;
        let mut child = std::process::Command::new(python)
            .args([
                "-u",
                "-c",
                "import sys; print('READY',flush=True); sys.stdin.buffer.read(1)",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("stdout required"))?;
        let mut ready = String::new();
        std::io::BufReader::new(stdout).read_line(&mut ready)?;
        assert_eq!(ready.trim(), "READY");
        assert!(child.try_wait()?.is_none());
        let process = child.as_raw_handle() as HANDLE;
        if unsafe { TerminateProcess(process, 1) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let code = completed_exit_code(
            process,
            std::time::Instant::now() + std::time::Duration::from_secs(2),
        )?;
        assert_eq!(code, 1);
        assert_eq!(child.wait()?.code(), Some(code));
        Ok(())
    }

    #[test]
    fn real_output_reader_drains_binary_bytes_with_a_foreign_writer_reference() -> Result<()> {
        let mut read = 0;
        let mut write = 0;
        if unsafe {
            windows_sys::Win32::System::Pipes::CreatePipe(
                &mut read,
                &mut write,
                ptr::null_mut(),
                4096,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut writer = unsafe { File::from_raw_handle(write as _) };
        let _foreign_writer = writer.try_clone()?;
        let output = Arc::new(StdMutex::new(tempfile::tempfile()?));
        let done = Arc::new(AtomicBool::new(false));
        let worker = spawn_output_reader(output.clone(), read, OutputStream::Stdout, done.clone());
        let payload: Vec<u8> = (0..129 * 1024).map(|index| (index % 256) as u8).collect();
        writer.write_all(&payload)?;
        drop(writer);
        done.store(true, Ordering::Release);
        join_control_worker(
            worker,
            std::time::Instant::now() + std::time::Duration::from_secs(2),
        )?;
        let mut output = output
            .lock()
            .map_err(|_| anyhow::anyhow!("output unavailable"))?;
        output.seek(SeekFrom::Start(0))?;
        let mut captured = Vec::new();
        while let Some(frame) = read_frame(&mut *output)? {
            match frame.message {
                Message::Output { payload } => {
                    assert_eq!(payload.stream, OutputStream::Stdout);
                    let chunk = decode_bytes(&payload.data_b64)?;
                    assert!(chunk.len() <= 64 * 1024);
                    captured.extend(chunk);
                }
                _ => anyhow::bail!("unexpected frame"),
            }
        }
        assert_eq!(captured, payload);
        Ok(())
    }
}
