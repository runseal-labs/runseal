use crate::error::RunSealError;
use crate::execution::ExecutionControl;
use std::io::{self, Write};
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::process::{Child, Command, Stdio};
#[cfg(windows)]
use std::sync::Arc;
#[cfg(windows)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(windows)]
use std::sync::mpsc::{self, SyncSender, TrySendError};
#[cfg(windows)]
use std::thread::JoinHandle;

pub(super) struct Output {
    stderr: bool,
    control: ExecutionControl,
    failure: Option<(&'static str, &'static str)>,
    #[cfg(windows)]
    pipe: Option<codex_windows_sandbox::NonblockingOutputPipe>,
    #[cfg(windows)]
    console: Option<ConsoleOutputWorker>,
}

impl Output {
    pub(super) fn new(stderr: bool, control: ExecutionControl) -> Result<Self, RunSealError> {
        #[cfg(windows)]
        let pipe = if stderr {
            codex_windows_sandbox::NonblockingOutputPipe::stderr()
        } else {
            codex_windows_sandbox::NonblockingOutputPipe::stdout()
        }
        .map_err(|_| RunSealError::new("CLIENT_DISCONNECTED", "output pipe unavailable"))?;
        #[cfg(windows)]
        let console = if pipe.is_none() {
            Some(
                ConsoleOutputWorker::spawn(stderr)
                    .map_err(|_| RunSealError::new("CLIENT_DISCONNECTED", "output unavailable"))?,
            )
        } else {
            None
        };
        Ok(Self {
            stderr,
            control,
            failure: None,
            #[cfg(windows)]
            pipe,
            #[cfg(windows)]
            console,
        })
    }

    pub(super) fn write(&mut self, mut bytes: &[u8]) -> Result<(), RunSealError> {
        if let Some((code, reason)) = self.failure {
            return Err(RunSealError::new(code, reason));
        }
        let mut progress = Instant::now();
        #[cfg(windows)]
        let mut console_progress = self.console.as_ref().map(ConsoleOutputWorker::progress);
        while !bytes.is_empty() {
            match self.write_some(bytes) {
                Ok(0) => return self.fail("CLIENT_DISCONNECTED", "output disconnected"),
                Ok(count) => {
                    bytes = &bytes[count..];
                    progress = Instant::now();
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if self.control.cleanup_deadline_expired() {
                        return self.fail(
                            "EXECUTION_CLEANUP_FAILED",
                            "output cleanup deadline exceeded",
                        );
                    }
                    #[cfg(windows)]
                    if let Some(console) = &self.console {
                        let current = Some(console.progress());
                        if current != console_progress {
                            console_progress = current;
                            progress = Instant::now();
                        }
                    }
                    if let Some(cause) = self.control.cause()
                        && let Some(code) = cause.error_code()
                    {
                        return self.fail(code, "output interrupted");
                    }
                    if progress.elapsed() >= crate::limits::deployment().backpressure_timeout() {
                        return self.fail("CLIENT_BACKPRESSURE", "output stalled");
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return self.fail("CLIENT_DISCONNECTED", "output disconnected"),
            }
        }
        Ok(())
    }

    pub(super) fn write_final(
        &mut self,
        mut bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), RunSealError> {
        if let Some((code, reason)) = self.failure {
            return Err(RunSealError::new(code, reason));
        }
        let mut progress = Instant::now();
        #[cfg(windows)]
        let mut console_progress = self.console.as_ref().map(ConsoleOutputWorker::progress);
        while !bytes.is_empty() {
            match self.write_some(bytes) {
                Ok(0) => return self.fail("CLIENT_DISCONNECTED", "output disconnected"),
                Ok(count) => {
                    bytes = &bytes[count..];
                    progress = Instant::now();
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return self.fail(
                            "EXECUTION_CLEANUP_FAILED",
                            "final output cleanup deadline exceeded",
                        );
                    }
                    #[cfg(windows)]
                    if let Some(console) = &self.console {
                        let current = Some(console.progress());
                        if current != console_progress {
                            console_progress = current;
                            progress = Instant::now();
                        }
                    }
                    if progress.elapsed() >= crate::limits::deployment().backpressure_timeout() {
                        return self.fail("CLIENT_BACKPRESSURE", "final output stalled");
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return self.fail("CLIENT_DISCONNECTED", "output disconnected"),
            }
        }
        Ok(())
    }

    fn fail(&mut self, code: &'static str, reason: &'static str) -> Result<(), RunSealError> {
        self.failure = Some((code, reason));
        #[cfg(windows)]
        if let Some(console) = &mut self.console {
            // A blocked WriteConsoleW worker lives in this helper process. Stop
            // it as soon as output can no longer be delivered so backend range
            // cleanup does not wait for an unrelated console write to finish.
            console.abort();
        }
        Err(RunSealError::new(code, reason))
    }

    fn write_some(&mut self, bytes: &[u8]) -> io::Result<usize> {
        #[cfg(windows)]
        if let Some(pipe) = &mut self.pipe {
            return pipe.write(bytes);
        }
        #[cfg(windows)]
        if let Some(console) = &mut self.console {
            return console.write(bytes);
        }
        let output: &mut dyn Write = if self.stderr {
            &mut std::io::stderr().lock()
        } else {
            &mut std::io::stdout().lock()
        };
        let count = output.write(bytes)?;
        output.flush()?;
        Ok(count)
    }

    pub(super) fn finish(&mut self, deadline: Instant) -> Result<(), String> {
        #[cfg(windows)]
        if let Some(console) = &mut self.console {
            console
                .finish(deadline, self.failure.is_some())
                .map_err(|_| "output cleanup could not be verified".to_string())?;
        }
        #[cfg(not(windows))]
        let _ = deadline;
        Ok(())
    }
}

#[cfg(windows)]
struct ConsoleOutputWorker {
    child: Child,
    sender: Option<SyncSender<Vec<u8>>>,
    writer: Option<JoinHandle<io::Result<()>>>,
    progress: Arc<AtomicU64>,
}

#[cfg(windows)]
impl ConsoleOutputWorker {
    fn spawn(stderr: bool) -> io::Result<Self> {
        let executable = std::env::current_exe()?;
        let mut child = Command::new(executable)
            .args(["__console-output", if stderr { "stderr" } else { "stdout" }])
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;
        let mut stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::other("console output worker input unavailable"));
            }
        };
        let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(4);
        let progress = Arc::new(AtomicU64::new(0));
        let writer_progress = progress.clone();
        let writer = match std::thread::Builder::new()
            .name("runseal-console-output-feed".into())
            .spawn(move || {
                while let Ok(bytes) = receiver.recv() {
                    stdin.write_all(&bytes)?;
                    writer_progress.fetch_add(bytes.len() as u64, Ordering::Release);
                }
                Ok(())
            }) {
            Ok(writer) => writer,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        Ok(Self {
            child,
            sender: Some(sender),
            writer: Some(writer),
            progress,
        })
    }

    fn progress(&self) -> u64 {
        self.progress.load(Ordering::Acquire)
    }

    fn abort(&mut self) {
        self.sender.take();
        let _ = self.kill_child();
    }

    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(sender) = &self.sender else {
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        let count = bytes.len().min(64 * 1024);
        match sender.try_send(bytes[..count].to_vec()) {
            Ok(()) => Ok(count),
            Err(TrySendError::Full(_)) => Err(io::ErrorKind::WouldBlock.into()),
            Err(TrySendError::Disconnected(_)) => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }

    fn finish(&mut self, deadline: Instant, abort: bool) -> io::Result<()> {
        self.sender.take();
        let mut forced = abort;
        if forced {
            self.kill_child()?;
        }
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                forced = true;
                self.kill_child()?;
                break self.child.wait()?;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let writer = self
            .writer
            .take()
            .ok_or_else(|| io::Error::other("console output writer unavailable"))?;
        let write_result = writer
            .join()
            .map_err(|_| io::Error::other("console output writer panicked"))?;
        if !forced && !status.success() {
            return Err(io::Error::other("console output worker failed"));
        }
        if let Err(error) = write_result
            && !(forced
                && matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                ))
        {
            return Err(error);
        }
        Ok(())
    }

    fn kill_child(&mut self) -> io::Result<()> {
        match self.child.kill() {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[cfg(windows)]
impl Drop for ConsoleOutputWorker {
    fn drop(&mut self) {
        self.sender.take();
        let _ = self.kill_child();
        let _ = self.child.wait();
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

#[cfg(windows)]
pub(crate) fn run_console_output_worker(args: &[String]) -> Result<(), String> {
    use std::io::Read;
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler,
    };

    // The execution process owns console cancellation. Its output helper must
    // keep the delivery channel alive when the same console event is broadcast
    // to all attached processes.
    unsafe extern "system" fn ignore_console_control(event: u32) -> windows_sys::core::BOOL {
        if matches!(event, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
            1
        } else {
            0
        }
    }

    if unsafe { SetConsoleCtrlHandler(Some(ignore_console_control), 1) } == 0 {
        return Err("console output control handler unavailable".to_string());
    }

    let mut output = match args {
        [stream] if stream == "stdout" => codex_windows_sandbox::CancellableOutput::stdout(),
        [stream] if stream == "stderr" => codex_windows_sandbox::CancellableOutput::stderr(),
        _ => return Err("invalid internal console output stream".to_string()),
    }
    .map_err(|_| "console output unavailable".to_string())?;
    let mut input = io::stdin().lock();
    let mut buffer = [0; 16 * 1024];
    loop {
        let count = input
            .read(&mut buffer)
            .map_err(|_| "console output input failed".to_string())?;
        if count == 0 {
            break;
        }
        let mut offset = 0;
        while offset < count {
            match output.write(&buffer[offset..count]) {
                Ok(0) => return Err("console output disconnected".to_string()),
                Ok(written) => offset += written,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return Err("console output failed".to_string()),
            }
        }
    }
    output
        .flush(Instant::now() + Duration::from_secs(60))
        .map_err(|_| "console output flush failed".to_string())
}
