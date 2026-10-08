use crate::error::RunSealError;
use crate::execution::ExecutionControl;
use std::time::Instant;

#[cfg(windows)]
mod windows {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use std::sync::{
        Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender},
    };
    use std::thread::JoinHandle;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler,
    };
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    use windows_sys::core::BOOL;

    static EXCLUSIVE: Mutex<()> = Mutex::new(());
    static INTERRUPTED: AtomicBool = AtomicBool::new(false);

    // The OS callback touches only static atomic storage: no locks, allocation,
    // output, borrowed execution pointers, or backend operations on this thread.
    unsafe extern "system" fn console_control(event: u32) -> BOOL {
        if matches!(event, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
            INTERRUPTED.store(true, Ordering::Release);
            1
        } else {
            0
        }
    }

    pub(crate) struct SignalFrontend {
        exclusive: Option<MutexGuard<'static, ()>>,
        registered: bool,
        stop: Option<Sender<()>>,
        worker: Option<JoinHandle<()>>,
        cleanup_deadline: Option<Instant>,
    }

    impl SignalFrontend {
        pub(crate) fn new(control: ExecutionControl) -> Result<Self, RunSealError> {
            let exclusive = EXCLUSIVE.try_lock().map_err(|_| {
                RunSealError::new("INTERNAL_ERROR", "console cancellation owner unavailable")
            })?;
            INTERRUPTED.store(false, Ordering::Release);
            if unsafe { SetConsoleCtrlHandler(Some(console_control), 1) } == 0 {
                return Err(RunSealError::new(
                    "BACKEND_UNAVAILABLE",
                    "console cancellation frontend unavailable",
                ));
            }
            let (stop, receiver) = mpsc::channel();
            let worker = std::thread::Builder::new()
                .name("execution-console-cancellation".into())
                .spawn(move || {
                    loop {
                        if INTERRUPTED.swap(false, Ordering::AcqRel) {
                            control.cancel();
                        }
                        match receiver.recv_timeout(Duration::from_millis(10)) {
                            Err(mpsc::RecvTimeoutError::Timeout) => {}
                            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                        }
                    }
                });
            match worker {
                Ok(worker) => Ok(Self {
                    exclusive: Some(exclusive),
                    registered: true,
                    stop: Some(stop),
                    worker: Some(worker),
                    cleanup_deadline: None,
                }),
                Err(_) => {
                    if unsafe { SetConsoleCtrlHandler(Some(console_control), 0) } == 0 {
                        std::mem::forget(exclusive);
                        return Err(RunSealError::new(
                            "EXECUTION_CLEANUP_FAILED",
                            "console cancellation handler restoration failed",
                        ));
                    }
                    Err(RunSealError::new(
                        "INTERNAL_ERROR",
                        "console cancellation worker unavailable",
                    ))
                }
            }
        }

        pub(crate) fn finish(&mut self, deadline: Instant) -> Result<(), String> {
            let deadline = self
                .cleanup_deadline
                .map_or(deadline, |previous| previous.min(deadline));
            self.cleanup_deadline = Some(deadline);
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(worker) = self.worker.as_ref() {
                while unsafe { WaitForSingleObject(worker.as_raw_handle(), 0) } != WAIT_OBJECT_0 {
                    if Instant::now() >= deadline {
                        return Err("console cancellation worker did not stop".into());
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            if let Some(worker) = self.worker.take() {
                worker
                    .join()
                    .map_err(|_| "console cancellation worker failed".to_string())?;
            }
            Ok(())
        }

        // Keep the static callback registered during final audit/result delivery.
        // Once execution cleanup has joined its worker, further interrupts cannot
        // change the already accepted cause or race through dangling references.
        pub(crate) fn unregister(&mut self) -> Result<(), String> {
            if self.registered {
                if unsafe { SetConsoleCtrlHandler(Some(console_control), 0) } == 0 {
                    return Err("console cancellation handler restoration failed".into());
                }
                self.registered = false;
            }
            Ok(())
        }
    }

    impl Drop for SignalFrontend {
        fn drop(&mut self) {
            let deadline = self
                .cleanup_deadline
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(2));
            let _ = self.finish(deadline);
            let _ = self.unregister();
            if let Some(worker) = self.worker.take() {
                crate::execution::retained::retain(worker);
                // A retained worker still observes the process-wide atomic.
                // Never let another execution acquire that callback owner.
                if let Some(exclusive) = self.exclusive.take() {
                    std::mem::forget(exclusive);
                }
            } else if self.registered
                && let Some(exclusive) = self.exclusive.take()
            {
                std::mem::forget(exclusive);
            }
        }
    }
}

#[cfg(windows)]
pub(super) use windows::SignalFrontend;

#[cfg(not(windows))]
pub(super) struct SignalFrontend;

#[cfg(not(windows))]
impl SignalFrontend {
    pub(crate) fn new(_: ExecutionControl) -> Result<Self, RunSealError> {
        Ok(Self)
    }
    pub(crate) fn finish(&mut self, _: Instant) -> Result<(), String> {
        Ok(())
    }
    pub(crate) fn unregister(&mut self) -> Result<(), String> {
        Ok(())
    }
}
