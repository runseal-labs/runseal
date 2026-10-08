use crate::backend::ExecutionInput;
use crate::error::RunSealError;
use crate::execution::ExecutionControl;

#[cfg(windows)]
mod windows {
    use super::*;
    use std::io::{self, Read, Write};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::{Duration, Instant};

    pub(crate) struct Frontend {
        endpoint: Option<codex_windows_sandbox::InheritedControlEndpoint>,
        queue: Option<ExecutionInput>,
        stop: Arc<AtomicBool>,
        worker: Option<std::thread::JoinHandle<Result<(), String>>>,
        control: ExecutionControl,
    }

    impl Frontend {
        pub(crate) fn new(control: ExecutionControl) -> Result<Self, RunSealError> {
            let endpoint =
                codex_windows_sandbox::InheritedControlEndpoint::from_fd3().map_err(|error| {
                    if error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
                    {
                        RunSealError::new("INVALID_REQUEST", "control fd 3 is not provided")
                    } else if error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|error| error.kind() == io::ErrorKind::InvalidInput)
                    {
                        RunSealError::new(
                            "INVALID_REQUEST",
                            "control fd 3 must be independent of stdio",
                        )
                    } else {
                        RunSealError::new(
                            "BACKEND_CAPABILITY_MISSING",
                            "control fd 3 requires a connected local duplex stream",
                        )
                    }
                })?;
            let queue = ExecutionInput::default();
            let stop = Arc::new(AtomicBool::new(false));
            let mut input = endpoint.clone();
            let input_queue = queue.clone();
            let input_stop = stop.clone();
            let frontend_control = control.clone();
            let worker = std::thread::spawn(move || {
                let result = (|| {
                    let mut bytes = [0; 64 * 1024];
                    while !input_stop.load(Ordering::Acquire) && !control.is_cancelled() {
                        let capacity = input_queue
                            .remaining_capacity()
                            .map_err(|_| "control input queue unavailable")?;
                        if capacity == 0 {
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        let count = capacity
                            .min(bytes.len())
                            .min(crate::limits::deployment().stream_chunk_bytes);
                        match input.read(&mut bytes[..count]) {
                            Ok(0) => {
                                input_queue.close().map_err(|_| "control EOF unavailable")?;
                                return Ok(());
                            }
                            Ok(count) => {
                                input_queue
                                    .write(bytes[..count].to_vec())
                                    .map_err(|_| "control input queue rejected bytes")?;
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(5))
                            }
                            Err(_) => return Err("control input disconnected".to_string()),
                        }
                    }
                    Ok(())
                })();
                if result.is_err() {
                    control.request(crate::execution::TerminationCause::ClientDisconnected);
                }
                result
            });
            Ok(Self {
                endpoint: Some(endpoint),
                queue: Some(queue),
                stop,
                worker: Some(worker),
                control: frontend_control,
            })
        }

        pub(crate) fn input(&self) -> Option<ExecutionInput> {
            self.queue.clone()
        }

        pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<(), RunSealError> {
            let mut offset = 0;
            let mut progress = Instant::now();
            while offset < bytes.len() {
                match self
                    .endpoint
                    .as_mut()
                    .ok_or_else(|| RunSealError::new("INTERNAL_ERROR", "control output closed"))?
                    .write(&bytes[offset..])
                {
                    Ok(0) => {
                        return Err(RunSealError::new(
                            "CLIENT_DISCONNECTED",
                            "control output disconnected",
                        ));
                    }
                    Ok(count) => {
                        offset += count;
                        progress = Instant::now();
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if self.control.cleanup_deadline_expired() {
                            return Err(RunSealError::new(
                                "EXECUTION_CLEANUP_FAILED",
                                "control output cleanup deadline exceeded",
                            ));
                        }
                        if let Some(code) = self
                            .control
                            .cause()
                            .and_then(crate::execution::TerminationCause::error_code)
                        {
                            return Err(RunSealError::new(code, "control output interrupted"));
                        }
                        if progress.elapsed() >= crate::limits::deployment().backpressure_timeout()
                        {
                            return Err(RunSealError::new(
                                "CLIENT_BACKPRESSURE",
                                "control output stalled",
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => {
                        return Err(RunSealError::new(
                            "CLIENT_DISCONNECTED",
                            "control output disconnected",
                        ));
                    }
                }
            }
            Ok(())
        }

        pub(crate) fn finish(&mut self, deadline: Instant) -> Result<(), String> {
            self.stop.store(true, Ordering::Release);
            if let Some(worker) = &self.worker {
                while !crate::execution::retained::thread_finished(worker) {
                    if Instant::now() >= deadline {
                        return Err("control input shutdown deadline".to_string());
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            if let Some(worker) = self.worker.take() {
                // A transport failure already requested its lifecycle cause.
                // Joining proves that the reader no longer owns the endpoint.
                let _ = worker
                    .join()
                    .map_err(|_| "control input worker failed".to_string())?;
            }
            self.queue.take();
            self.endpoint.take().map_or(Ok(()), |endpoint| {
                endpoint
                    .close_output()
                    .map_err(|_| "control output close failed".to_string())
            })
        }
    }

    impl Drop for Frontend {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(worker) = self.worker.take() {
                crate::execution::retained::retain(worker);
            }
        }
    }
}

#[cfg(windows)]
pub(super) use windows::Frontend as ControlFrontend;

#[cfg(not(windows))]
pub(super) struct ControlFrontend;
#[cfg(not(windows))]
impl ControlFrontend {
    pub(super) fn new(_: ExecutionControl) -> Result<Self, RunSealError> {
        Err(RunSealError::new(
            "BACKEND_CAPABILITY_MISSING",
            "CLI control unavailable",
        ))
    }
    pub(super) fn input(&self) -> Option<ExecutionInput> {
        None
    }
    pub(super) fn write(&mut self, _: &[u8]) -> Result<(), RunSealError> {
        Err(RunSealError::new(
            "BACKEND_CAPABILITY_MISSING",
            "CLI control unavailable",
        ))
    }
    pub(super) fn finish(&mut self, _: std::time::Instant) -> Result<(), String> {
        Ok(())
    }
}
