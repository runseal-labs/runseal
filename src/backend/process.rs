use super::{
    BackendExecutionOutput, ExecutionEnv, ExecutionStdin, PlatformSandboxPlan,
    matches_environment_scrub_pattern,
};
use std::env;
use std::ffi::OsString;
use std::io::{self, Read, Write};
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(windows)]
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};

pub(super) fn spawn_local_command(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
) -> io::Result<BackendExecutionOutput> {
    if plan.is_sandbox_enforced() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "refusing to spawn sandboxed plan through local execution path",
        ));
    }

    let mut process = Command::new(&command[0]);
    process
        .args(&command[1..])
        .current_dir(cwd)
        .env_clear()
        .envs(minimal_environment(plan))
        .envs(env.entries.iter().map(|(key, value)| (key, value)));
    match &stdin {
        ExecutionStdin::Empty => {
            process.stdin(Stdio::null());
        }
        ExecutionStdin::Bytes(_) | ExecutionStdin::File(_) => {
            process.stdin(Stdio::piped());
        }
    }
    process.stdout(Stdio::piped()).stderr(Stdio::piped());

    let Some(timeout) = timeout else {
        let mut child = process.spawn()?;
        #[cfg(windows)]
        let _process_job = match assign_windows_process_job(plan, &child) {
            Ok(process_job) => process_job,
            Err(err) => return Err(cleanup_child_after_setup_error(child, err)),
        };
        if let ExecutionStdin::Bytes(bytes) | ExecutionStdin::File(bytes) = stdin
            && let Err(err) = write_child_stdin(&mut child, bytes)
        {
            return Err(cleanup_child_after_setup_error(child, err));
        }
        return child
            .wait_with_output()
            .map(|output| BackendExecutionOutput {
                output,
                timed_out: false,
            });
    };

    let mut child = process.spawn()?;
    #[cfg(windows)]
    let _process_job = match assign_windows_process_job(plan, &child) {
        Ok(process_job) => process_job,
        Err(err) => return Err(cleanup_child_after_setup_error(child, err)),
    };
    let stdout_reader = child.stdout.take().map(read_pipe_in_thread);
    let stderr_reader = child.stderr.take().map(read_pipe_in_thread);
    if let ExecutionStdin::Bytes(bytes) | ExecutionStdin::File(bytes) = stdin
        && let Err(err) = write_child_stdin(&mut child, bytes)
    {
        return Err(cleanup_child_after_setup_error(child, err));
    }

    let (status, timed_out) = wait_child_with_timeout(&mut child, timeout)?;
    Ok(BackendExecutionOutput {
        output: Output {
            status,
            stdout: join_pipe_reader(stdout_reader)?,
            stderr: join_pipe_reader(stderr_reader)?,
        },
        timed_out,
    })
}

fn wait_child_with_timeout(child: &mut Child, timeout: Duration) -> io::Result<(ExitStatus, bool)> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok((status, false));
        }

        if start.elapsed() >= timeout {
            if let Err(err) = child.kill()
                && err.kind() != io::ErrorKind::InvalidInput
            {
                return Err(err);
            }
            return child.wait().map(|status| (status, true));
        }

        thread::sleep(
            timeout
                .saturating_sub(start.elapsed())
                .min(Duration::from_millis(10)),
        );
    }
}

fn read_pipe_in_thread(mut pipe: impl Read + Send + 'static) -> JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

fn join_pipe_reader(reader: Option<JoinHandle<io::Result<Vec<u8>>>>) -> io::Result<Vec<u8>> {
    let Some(reader) = reader else {
        return Ok(Vec::new());
    };
    reader
        .join()
        .map_err(|_| io::Error::other("output reader thread panicked"))?
}

fn write_child_stdin(child: &mut Child, bytes: Vec<u8>) -> io::Result<()> {
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&bytes)?;
    }
    Ok(())
}

pub(super) fn cleanup_child_after_setup_error(mut child: Child, setup_err: io::Error) -> io::Error {
    let kill_err = match child.kill() {
        Ok(()) => None,
        Err(err) if err.kind() == io::ErrorKind::InvalidInput => None,
        Err(err) => Some(err),
    };
    let wait_err = child.wait().err();

    match (kill_err, wait_err) {
        (None, None) => setup_err,
        (Some(kill_err), None) => io::Error::other(format!(
            "child setup failed ({setup_err}); cleanup kill failed ({kill_err})"
        )),
        (None, Some(wait_err)) => io::Error::other(format!(
            "child setup failed ({setup_err}); cleanup wait failed ({wait_err})"
        )),
        (Some(kill_err), Some(wait_err)) => io::Error::other(format!(
            "child setup failed ({setup_err}); cleanup kill failed ({kill_err}); cleanup wait failed ({wait_err})"
        )),
    }
}

#[cfg(windows)]
fn assign_windows_process_job(
    plan: &PlatformSandboxPlan,
    child: &Child,
) -> io::Result<Option<WindowsKillOnCloseJob>> {
    if plan.private_process_job != "kill-on-close-job" {
        return Ok(None);
    }
    let job = WindowsKillOnCloseJob::new()?;
    job.assign_child(child)?;
    Ok(Some(job))
}

#[cfg(windows)]
pub(super) struct WindowsKillOnCloseJob {
    handle: HANDLE,
}

#[cfg(windows)]
impl WindowsKillOnCloseJob {
    pub(super) fn new() -> io::Result<Self> {
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Self { handle };
        if let Err(err) = job.set_kill_on_close() {
            drop(job);
            return Err(err);
        }
        Ok(job)
    }

    fn set_kill_on_close(&self) -> io::Result<()> {
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let result = unsafe {
            SetInformationJobObject(
                self.handle,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(limits).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn assign_child(&self, child: &Child) -> io::Result<()> {
        let process_handle = child.as_raw_handle() as HANDLE;
        let result = unsafe { AssignProcessToJobObject(self.handle, process_handle) };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for WindowsKillOnCloseJob {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

pub(super) fn minimal_environment(plan: &PlatformSandboxPlan) -> Vec<(OsString, OsString)> {
    if plan.environment_inherit != "minimal" {
        return Vec::new();
    }

    let mut environment: Vec<(OsString, OsString)> = minimal_environment_keys()
        .into_iter()
        .filter(|key| {
            !plan
                .environment_scrub
                .iter()
                .any(|pattern| matches_environment_scrub_pattern(key, pattern))
        })
        .filter_map(|key| env::var_os(key).map(|value| (OsString::from(key), value)))
        .collect();
    environment.extend(
        plan.environment_runtime
            .iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value))),
    );
    environment
}

fn minimal_environment_keys() -> Vec<&'static str> {
    if cfg!(windows) {
        vec![
            "PATH",
            "Path",
            "PATHEXT",
            "SYSTEMROOT",
            "SystemRoot",
            "WINDIR",
            "COMSPEC",
            "TEMP",
            "TMP",
        ]
    } else {
        vec!["PATH", "TMPDIR", "LANG", "LC_ALL"]
    }
}
