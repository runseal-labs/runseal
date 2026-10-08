use crate::error::RunSealError;
use crate::execution::ExecutionControl;
use std::io::{self, Write};
use std::time::{Duration, Instant};

pub(super) struct Output {
    stderr: bool,
    control: ExecutionControl,
    failure: Option<(&'static str, &'static str)>,
    #[cfg(windows)]
    pipe: Option<codex_windows_sandbox::NonblockingOutputPipe>,
    #[cfg(windows)]
    native: Option<codex_windows_sandbox::CancellableOutput>,
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
        let native = if pipe.is_none() {
            Some(
                if stderr {
                    codex_windows_sandbox::CancellableOutput::stderr()
                } else {
                    codex_windows_sandbox::CancellableOutput::stdout()
                }
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
            native,
        })
    }

    pub(super) fn write(&mut self, mut bytes: &[u8]) -> Result<(), RunSealError> {
        if let Some((code, reason)) = self.failure {
            return Err(RunSealError::new(code, reason));
        }
        let mut progress = Instant::now();
        #[cfg(windows)]
        let mut native_progress = self
            .native
            .as_ref()
            .map(codex_windows_sandbox::CancellableOutput::write_progress);
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
                    if let Some(native) = &self.native {
                        let current = Some(native.write_progress());
                        if current != native_progress {
                            native_progress = current;
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

    fn fail(&mut self, code: &'static str, reason: &'static str) -> Result<(), RunSealError> {
        self.failure = Some((code, reason));
        Err(RunSealError::new(code, reason))
    }

    fn write_some(&mut self, bytes: &[u8]) -> io::Result<usize> {
        #[cfg(windows)]
        if let Some(pipe) = &mut self.pipe {
            return pipe.write(bytes);
        }
        #[cfg(windows)]
        if let Some(native) = &mut self.native {
            return native.write(bytes);
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
        if let Some(native) = &mut self.native {
            let result = if self.failure.is_some() {
                native.finish(deadline)
            } else {
                native.flush(deadline)
            };
            result.map_err(|_| "output cleanup could not be verified".to_string())?;
        }
        #[cfg(not(windows))]
        let _ = deadline;
        Ok(())
    }
}
