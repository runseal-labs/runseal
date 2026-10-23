//! Private setup helpers use the same noninteractive launch boundary as executions.
use crate::desktop::LaunchDesktopMode;
use crate::process::{
    ProcessIdentity, StderrMode, StdinMode, spawn_process_with_pipes_for_identity,
};
use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::ExitStatusExt;
use std::path::Path;
use std::process::ExitStatus;
use std::time::{Duration, Instant};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, ResumeThread, TerminateProcess, WaitForSingleObject,
};

const EXIT_GRACE: Duration = Duration::from_secs(2);
const REAP_TIMEOUT: Duration = Duration::from_secs(5);

pub struct SetupProcess {
    process: OwnedHandle,
    // Only the shared refresh worker is owned here. Fire-and-forget advisory
    // helpers retain their existing lifetime independently of this wrapper.
    job: Option<OwnedHandle>,
    io_worker: Option<std::thread::JoinHandle<anyhow::Result<ExitStatus>>>,
    stderr_worker: Option<std::thread::JoinHandle<()>>,
    cleanup_confirmed: bool,
    #[cfg(test)]
    pub(crate) force_unconfirmed: bool,
    pub input: Option<File>,
    pub output: File,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{BufRead, Read, Write};
    use windows_sys::Win32::System::Console::GetConsoleWindow;

    pub(crate) fn fixture(mode: &str) -> SetupProcess {
        let mut helper = SetupProcess::spawn(
            &std::env::current_exe().unwrap(),
            &[
                "--ignored".into(),
                "--exact".into(),
                "setup_process::tests::helper_probe".into(),
                "--nocapture".into(),
            ],
            true,
        )
        .unwrap();
        writeln!(helper.input.as_mut().unwrap(), "{mode}").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut text = Vec::new();
        while !String::from_utf8_lossy(&text).contains("HELPER_READY\n") {
            assert!(Instant::now() < deadline, "helper did not become ready");
            if crate::process::available_pipe_bytes(&helper.output)
                .unwrap()
                .unwrap_or(0)
                > 0
            {
                let mut byte = [0];
                helper.output.read_exact(&mut byte).unwrap();
                text.push(byte[0]);
            } else {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        helper
    }

    #[test]
    fn cooperative_worker_exits_on_eof() {
        let mut helper = fixture("cooperate");
        assert!(helper.shutdown().unwrap().success());
        assert!(helper.wait_timeout(Duration::ZERO).unwrap().is_some());
    }

    #[test]
    fn blocked_request_write_expires_and_its_native_io_owner_is_reaped() {
        let mut helper = fixture("hang");
        let started = Instant::now();
        let error = helper
            .exchange(vec![b'x'; 65536], Duration::from_millis(50))
            .unwrap_err();
        assert!(error.to_string().contains("write/read timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(helper.io_worker.is_some());
        assert!(helper.shutdown().is_err());
        assert!(helper.cleanup_confirmed());
        assert!(helper.io_worker.is_none());
    }

    #[test]
    fn response_wait_uses_the_same_request_deadline() {
        let mut helper = fixture("hang");
        let error = helper
            .exchange(b"small request\n".to_vec(), Duration::from_millis(50))
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(helper.shutdown().is_err());
        assert!(helper.cleanup_confirmed());
    }

    #[test]
    fn response_timeout_is_bounded_and_the_worker_is_then_reaped() {
        let mut helper = fixture("hang-with-child");
        let started = Instant::now();
        assert!(
            helper
                .read_status(Duration::from_millis(50))
                .unwrap_err()
                .to_string()
                .contains("response timed out")
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(
            helper.shutdown().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(helper.wait_timeout(Duration::ZERO).unwrap().is_some());
    }

    #[test]
    fn one_worker_handles_multiple_requests_without_consuming_eof() {
        let mut helper = fixture("respond");
        for _ in 0..3 {
            assert!(
                helper
                    .exchange(b"request\n".to_vec(), Duration::from_secs(2))
                    .unwrap()
                    .success()
            );
            assert!(helper.wait_timeout(Duration::ZERO).unwrap().is_none());
        }
        assert!(helper.shutdown().unwrap().success());
    }

    #[test]
    fn stuck_worker_and_descendant_are_reaped_without_touching_another_worker() {
        let mut stuck = fixture("hang-with-child");
        let mut independent = fixture("cooperate");
        let started = Instant::now();
        assert_eq!(
            stuck.shutdown().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(started.elapsed() < EXIT_GRACE + REAP_TIMEOUT + Duration::from_secs(2));
        assert!(stuck.wait_timeout(Duration::ZERO).unwrap().is_some());
        assert!(independent.wait_timeout(Duration::ZERO).unwrap().is_none());
        assert!(independent.shutdown().unwrap().success());
        assert!(fixture("cooperate").shutdown().unwrap().success());
    }

    #[test]
    #[ignore = "native child fixture, launched by lifecycle tests"]
    fn helper_probe() {
        assert_eq!(unsafe { GetConsoleWindow() }, 0);
        let stdin = io::stdin();
        let mut input = stdin.lock();
        let mut mode = String::new();
        input.read_line(&mut mode).unwrap();
        let _child = if mode.trim() == "hang-with-child" {
            use std::os::windows::process::CommandExt;
            Some(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--ignored",
                        "--exact",
                        "setup_process::tests::descendant_probe",
                        "--nocapture",
                    ])
                    .creation_flags(0x0800_0000)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap(),
            )
        } else {
            None
        };
        println!("HELPER_READY");
        io::stdout().flush().unwrap();
        if mode.trim() == "respond" {
            for line in input.lines() {
                line.unwrap();
                println!("0");
                io::stdout().flush().unwrap();
            }
        } else if mode.trim() == "cooperate" {
            input.read_to_end(&mut Vec::new()).unwrap();
        } else {
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }

    #[test]
    #[ignore = "native descendant fixture"]
    fn descendant_probe() {
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    #[test]
    fn helper_stays_console_free_under_a_detached_parent() {
        use std::os::windows::process::CommandExt;
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "setup_process::tests::detached_parent_probe",
                "--nocapture",
            ])
            .creation_flags(0x0000_0008)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    #[test]
    #[ignore = "native detached parent fixture"]
    fn detached_parent_probe() {
        assert_eq!(unsafe { GetConsoleWindow() }, 0);
        assert!(fixture("cooperate").shutdown().unwrap().success());
    }
}

impl SetupProcess {
    pub(super) fn process_identity(&self) -> io::Result<(u32, u64)> {
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::System::Threading::{GetProcessId, GetProcessTimes};
        let mut creation = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut exit = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut kernel = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut user = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let handle = self.process.as_raw_handle() as _;
        if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let id = unsafe { GetProcessId(handle) };
        if id == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((
            id,
            (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime),
        ))
    }

    #[cfg(test)]
    pub(super) fn read_status(&mut self, timeout: Duration) -> anyhow::Result<ExitStatus> {
        Self::read_response(&mut self.output, Instant::now() + timeout)
    }

    fn read_response(output: &mut File, deadline: Instant) -> anyhow::Result<ExitStatus> {
        use std::io::Read;
        let mut response = Vec::new();
        loop {
            if Instant::now() >= deadline {
                anyhow::bail!("setup worker response timed out");
            }
            match crate::process::available_pipe_bytes(output)? {
                None => anyhow::bail!("setup worker disconnected before completion"),
                Some(0) => std::thread::sleep(Duration::from_millis(5)),
                Some(_) => {
                    let mut byte = [0];
                    output.read_exact(&mut byte)?;
                    if byte[0] == b'\n' {
                        break;
                    }
                    response.push(byte[0]);
                    if response.len() > 16 {
                        anyhow::bail!("invalid setup worker response");
                    }
                }
            }
        }
        Ok(ExitStatus::from_raw(
            std::str::from_utf8(&response)?.parse::<u32>()?,
        ))
    }

    pub(super) fn exchange(
        &mut self,
        request: Vec<u8>,
        timeout: Duration,
    ) -> anyhow::Result<ExitStatus> {
        use std::io::Write;
        anyhow::ensure!(
            self.io_worker.is_none(),
            "previous setup I/O is still owned"
        );
        self.cleanup_confirmed = false;
        let deadline = Instant::now() + timeout;
        let mut input = self
            .input
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("setup worker input unavailable"))?
            .try_clone()?;
        let mut output = self.output.try_clone()?;
        self.io_worker = Some(
            std::thread::Builder::new()
                .name("setup-request".into())
                .spawn(move || {
                    if Instant::now() >= deadline {
                        anyhow::bail!("setup request timed out before write");
                    }
                    input.write_all(&request)?;
                    input.flush()?;
                    Self::read_response(&mut output, deadline)
                })?,
        );
        loop {
            if self.io_finished()? {
                let worker = self
                    .io_worker
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("setup I/O owner missing"))?;
                return worker
                    .join()
                    .map_err(|_| anyhow::anyhow!("setup I/O thread panicked"))?;
            }
            if Instant::now() >= deadline {
                self.cancel_io();
                anyhow::bail!("setup request write/read timed out");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    pub(super) fn cleanup_confirmed(&self) -> bool {
        self.cleanup_confirmed
    }

    fn io_finished(&self) -> io::Result<bool> {
        let Some(worker) = &self.io_worker else {
            return Ok(true);
        };
        Self::thread_finished(worker)
    }

    fn thread_finished<T>(worker: &std::thread::JoinHandle<T>) -> io::Result<bool> {
        match unsafe { WaitForSingleObject(worker.as_raw_handle() as _, 0) } {
            0 => Ok(true),
            258 => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }

    fn cancel_io(&self) {
        if let Some(worker) = &self.stderr_worker {
            unsafe {
                windows_sys::Win32::System::IO::CancelSynchronousIo(worker.as_raw_handle() as _);
            }
        }
        if let Some(worker) = &self.io_worker {
            unsafe {
                windows_sys::Win32::System::IO::CancelSynchronousIo(worker.as_raw_handle() as _);
            }
        }
    }

    pub fn spawn(executable: &Path, args: &[String], input: bool) -> anyhow::Result<Self> {
        let mut argv = vec![executable.to_string_lossy().into_owned()];
        argv.extend_from_slice(args);
        let pipes = spawn_process_with_pipes_for_identity(
            ProcessIdentity::Current,
            &argv,
            &std::env::current_dir()?,
            &std::env::vars().collect(),
            if input {
                StdinMode::Open
            } else {
                StdinMode::Closed
            },
            StderrMode::Separate,
            LaunchDesktopMode::Default,
            &[],
            None,
            input,
            None,
            None,
        )?;
        unsafe {
            let _thread = OwnedHandle::from_raw_handle(pipes.process.hThread as *mut _);
            let process = OwnedHandle::from_raw_handle(pipes.process.hProcess as *mut _);
            let job = if input {
                let initialized = (|| -> io::Result<OwnedHandle> {
                    let raw = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                    if raw == 0 {
                        return Err(io::Error::last_os_error());
                    }
                    let job = OwnedHandle::from_raw_handle(raw as *mut _);
                    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                    if SetInformationJobObject(
                        raw,
                        JobObjectExtendedLimitInformation,
                        &limits as *const _ as _,
                        std::mem::size_of_val(&limits) as u32,
                    ) == 0
                        || AssignProcessToJobObject(raw, pipes.process.hProcess) == 0
                        || ResumeThread(pipes.process.hThread) == u32::MAX
                    {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(job)
                })();
                match initialized {
                    Ok(job) => Some(job),
                    Err(error) => {
                        TerminateProcess(pipes.process.hProcess, 1);
                        WaitForSingleObject(
                            pipes.process.hProcess,
                            REAP_TIMEOUT.as_millis() as u32,
                        );
                        // Close pipes even when the suspended launch cannot be installed.
                        if let Some(handle) = pipes.stdin_write {
                            drop(File::from_raw_handle(handle as *mut _));
                        }
                        drop(File::from_raw_handle(pipes.stdout_read as *mut _));
                        if let Some(handle) = pipes.stderr_read {
                            drop(File::from_raw_handle(handle as *mut _));
                        }
                        return Err(error.into());
                    }
                }
            } else {
                None
            };
            let stderr_worker = pipes.stderr_read.map(|stderr| {
                let mut stderr = File::from_raw_handle(stderr as *mut _);
                std::thread::spawn(move || {
                    let _ = io::copy(&mut stderr, &mut io::sink());
                })
            });
            Ok(Self {
                process,
                job,
                io_worker: None,
                stderr_worker,
                cleanup_confirmed: false,
                #[cfg(test)]
                force_unconfirmed: false,
                input: pipes
                    .stdin_write
                    .map(|handle| File::from_raw_handle(handle as *mut _)),
                output: File::from_raw_handle(pipes.stdout_read as *mut _),
            })
        }
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        match self.wait_timeout(Duration::from_secs(120))? {
            Some(status) => Ok(status),
            None => {
                self.terminate_and_reap()?;
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "setup helper exit timed out",
                ))
            }
        }
    }

    pub fn shutdown(&mut self) -> io::Result<ExitStatus> {
        self.input.take();
        if let Some(status) = self.wait_timeout(EXIT_GRACE)? {
            // A worker may exit while a descendant still owns a pipe.
            self.terminate_and_reap()?;
            return Ok(status);
        }
        self.terminate_and_reap()?;
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "setup helper shutdown timed out; owned processes reaped",
        ))
    }

    fn terminate_and_reap(&mut self) -> io::Result<()> {
        self.cleanup_confirmed = false;
        #[cfg(test)]
        if self.force_unconfirmed {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "injected unconfirmed cleanup",
            ));
        }
        self.cancel_io();
        unsafe {
            if let Some(job) = &self.job {
                if TerminateJobObject(job.as_raw_handle() as _, 1) == 0 {
                    return Err(io::Error::last_os_error());
                }
            } else if self.wait_timeout(Duration::ZERO)?.is_none()
                && TerminateProcess(self.process.as_raw_handle() as _, 1) == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        let deadline = Instant::now() + REAP_TIMEOUT;
        loop {
            let exited = self.wait_timeout(Duration::ZERO)?.is_some();
            let empty = if let Some(job) = &self.job {
                let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION =
                    unsafe { std::mem::zeroed() };
                if unsafe {
                    QueryInformationJobObject(
                        job.as_raw_handle() as _,
                        JobObjectBasicAccountingInformation,
                        &mut info as *mut _ as _,
                        std::mem::size_of_val(&info) as u32,
                        std::ptr::null_mut(),
                    )
                } == 0
                {
                    return Err(io::Error::last_os_error());
                }
                info.ActiveProcesses == 0
            } else {
                true
            };
            self.cancel_io();
            let stderr_finished = match &self.stderr_worker {
                Some(worker) => Self::thread_finished(worker)?,
                None => true,
            };
            if exited && empty && self.io_finished()? && stderr_finished {
                if let Some(worker) = self.io_worker.take() {
                    let _ = worker.join();
                }
                if let Some(worker) = self.stderr_worker.take() {
                    let _ = worker.join();
                }
                self.cleanup_confirmed = true;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "setup helper cleanup could not be confirmed",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn wait_timeout(&self, timeout: Duration) -> io::Result<Option<ExitStatus>> {
        unsafe {
            let result = WaitForSingleObject(
                self.process.as_raw_handle() as _,
                timeout.as_millis().min((u32::MAX - 1) as u128) as u32,
            );
            if result == 258 {
                return Ok(None);
            }
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut code = 0;
            if GetExitCodeProcess(self.process.as_raw_handle() as _, &mut code) == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Some(ExitStatus::from_raw(code)))
        }
    }
}
