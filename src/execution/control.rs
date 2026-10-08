use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

/// A single cancellation request shared by the lifecycle owner and backend.
#[derive(Clone, Default)]
pub(crate) struct ExecutionControl {
    accepted_at: Arc<std::sync::OnceLock<std::time::Instant>>,
    cancelled: Arc<AtomicBool>,
    terminal_commands: Arc<Mutex<std::collections::VecDeque<TerminalCommand>>>,
    cause: Arc<Mutex<Option<TerminationCause>>>,
    cleanup_deadline: Arc<Mutex<Option<std::time::Instant>>>,
}

#[derive(Clone, Copy)]
pub(crate) enum TerminalCommand {
    #[cfg_attr(not(windows), allow(dead_code))]
    Resize {
        rows: u16,
        cols: u16,
    },
    Interrupt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminationCause {
    Exited,
    Cancelled,
    Timeout,
    OutputLimit,
    ClientDisconnected,
    Backpressure,
    InputFailed,
    ExecutionFailed,
    FailedToStart,
}

impl TerminationCause {
    pub(crate) fn from_error_code(code: &str) -> Self {
        match code {
            "EXECUTION_CANCELLED" => Self::Cancelled,
            "EXECUTION_TIMEOUT" => Self::Timeout,
            "OUTPUT_LIMIT_EXCEEDED" => Self::OutputLimit,
            "CLIENT_DISCONNECTED" => Self::ClientDisconnected,
            "CLIENT_BACKPRESSURE" => Self::Backpressure,
            "EXECUTION_INPUT_FAILED" => Self::InputFailed,
            _ => Self::FailedToStart,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exited => "exited",
            Self::Cancelled => "cancelled",
            Self::Timeout => "timeout",
            Self::OutputLimit => "output_limit",
            Self::ClientDisconnected => "client_disconnected",
            Self::Backpressure => "backpressure",
            Self::InputFailed => "input_failed",
            Self::ExecutionFailed => "execution_failed",
            Self::FailedToStart => "failed_to_start",
        }
    }
    pub fn error_code(self) -> Option<&'static str> {
        match self {
            Self::Exited | Self::FailedToStart | Self::ExecutionFailed => None,
            Self::Cancelled => Some("EXECUTION_CANCELLED"),
            Self::Timeout => Some("EXECUTION_TIMEOUT"),
            Self::OutputLimit => Some("OUTPUT_LIMIT_EXCEEDED"),
            Self::ClientDisconnected => Some("CLIENT_DISCONNECTED"),
            Self::Backpressure => Some("CLIENT_BACKPRESSURE"),
            Self::InputFailed => Some("EXECUTION_INPUT_FAILED"),
        }
    }

    pub(crate) fn from_started_error_code(code: &str) -> Self {
        match Self::from_error_code(code) {
            Self::FailedToStart => Self::ExecutionFailed,
            cause => cause,
        }
    }
}

impl ExecutionControl {
    /// Freeze the accepted execution clock across admission and worker startup.
    pub(crate) fn accept(&self) -> std::time::Instant {
        *self.accepted_at.get_or_init(std::time::Instant::now)
    }

    pub(crate) fn resize(&self, rows: u16, cols: u16) -> Result<(), crate::backend::InputError> {
        self.queue_terminal(TerminalCommand::Resize { rows, cols })
    }
    pub(crate) fn interrupt(&self) -> Result<(), crate::backend::InputError> {
        self.queue_terminal(TerminalCommand::Interrupt)
    }
    fn queue_terminal(&self, command: TerminalCommand) -> Result<(), crate::backend::InputError> {
        let mut queue = self
            .terminal_commands
            .lock()
            .map_err(|_| crate::backend::InputError::Unavailable)?;
        if self.cause().is_some() {
            return Err(crate::backend::InputError::Unavailable);
        }
        if queue.len() >= 64 {
            return Err(crate::backend::InputError::Backpressure);
        }
        queue.push_back(command);
        Ok(())
    }
    #[cfg(windows)]
    pub(crate) fn take_terminal_command(&self) -> Option<TerminalCommand> {
        self.terminal_commands.lock().ok()?.pop_front()
    }
    pub fn cancel(&self) {
        self.request(TerminationCause::Cancelled);
    }

    /// The first accepted cause owns termination; later requests cannot replace it.
    pub fn request(&self, candidate: TerminationCause) -> bool {
        let mut cause = self
            .cause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cause.is_some() {
            return false;
        }
        *cause = Some(candidate);
        if candidate != TerminationCause::Exited {
            self.begin_cleanup();
            self.cancelled.store(true, Ordering::Release);
        }
        true
    }

    pub fn cause(&self) -> Option<TerminationCause> {
        *self
            .cause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// One absolute host deadline, retained across backend and frontend phases.
    pub(crate) fn begin_cleanup(&self) -> std::time::Instant {
        let mut deadline = self
            .cleanup_deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *deadline.get_or_insert_with(|| {
            std::time::Instant::now() + crate::limits::deployment().cleanup_timeout()
        })
    }

    pub(crate) fn adopt_cleanup_deadline(
        &self,
        candidate: std::time::Instant,
    ) -> std::time::Instant {
        let mut deadline = self
            .cleanup_deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let candidate = candidate
            .min(std::time::Instant::now() + crate::limits::deployment().cleanup_timeout());
        let selected = deadline.map_or(candidate, |previous| previous.min(candidate));
        *deadline = Some(selected);
        selected
    }

    pub(crate) fn cleanup_deadline_expired(&self) -> bool {
        self.cleanup_deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    }
}

/// The lifecycle deadline remains independent of a blocked output observer or
/// backend cleanup. Explicit finish stops the worker before terminal commit;
/// Drop retains its owner when native exit is unconfirmed at the same deadline.
pub(super) struct ExecutionDeadline {
    stop: Option<std::sync::mpsc::Sender<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
    cleanup_deadline: Option<std::time::Instant>,
}

impl ExecutionDeadline {
    pub(super) fn start(
        start: std::time::Instant,
        timeout: Option<std::time::Duration>,
        control: ExecutionControl,
    ) -> std::io::Result<Option<Self>> {
        Self::start_with(start, timeout, control, || {})
    }

    pub(super) fn start_with(
        start: std::time::Instant,
        timeout: Option<std::time::Duration>,
        control: ExecutionControl,
        initialize: impl FnOnce() + Send + 'static,
    ) -> std::io::Result<Option<Self>> {
        let Some(timeout) = timeout else {
            return Ok(None);
        };
        let (stop, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("runseal-deadline".into())
            .spawn(move || {
                initialize();
                let remaining = timeout.saturating_sub(start.elapsed());
                if matches!(
                    receiver.recv_timeout(remaining),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ) {
                    control.request(TerminationCause::Timeout);
                }
            })?;
        Ok(Some(Self {
            stop: Some(stop),
            worker: Some(worker),
            cleanup_deadline: None,
        }))
    }

    pub(super) fn finish(
        &mut self,
        deadline: std::time::Instant,
    ) -> Result<(), crate::error::RunSealError> {
        let deadline = self
            .cleanup_deadline
            .map_or(deadline, |previous| previous.min(deadline));
        self.cleanup_deadline = Some(deadline);
        drop(self.stop.take());
        if let Some(worker) = self.worker.as_ref() {
            while !super::retained::thread_finished(worker) {
                if std::time::Instant::now() >= deadline {
                    return Err(crate::error::RunSealError::new(
                        "EXECUTION_CLEANUP_FAILED",
                        "execution deadline worker did not stop",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| {
                crate::error::RunSealError::new(
                    "EXECUTION_CLEANUP_FAILED",
                    "execution deadline worker failed",
                )
            })?;
        }
        Ok(())
    }
}

impl Drop for ExecutionDeadline {
    fn drop(&mut self) {
        let deadline = self
            .cleanup_deadline
            .unwrap_or_else(|| std::time::Instant::now() + std::time::Duration::from_secs(2));
        let _ = self.finish(deadline);
        if let Some(worker) = self.worker.take() {
            super::retained::retain(worker);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn first_accepted_cause_survives_later_timeout_and_cancellation() {
        for first in [
            TerminationCause::Cancelled,
            TerminationCause::Timeout,
            TerminationCause::OutputLimit,
            TerminationCause::ClientDisconnected,
            TerminationCause::Backpressure,
            TerminationCause::InputFailed,
        ] {
            let control = ExecutionControl::default();
            assert!(control.request(first));
            assert!(!control.request(TerminationCause::Timeout));
            control.cancel();
            assert!(!control.request(TerminationCause::Exited));
            assert_eq!(control.cause(), Some(first));
            assert!(control.is_cancelled());
        }
    }
    #[test]
    fn accepted_natural_exit_cannot_be_reclassified_as_cancellation() {
        let control = ExecutionControl::default();
        assert!(control.request(TerminationCause::Exited));
        control.cancel();
        assert_eq!(control.cause(), Some(TerminationCause::Exited));
        assert!(!control.is_cancelled());
    }

    #[cfg(windows)]
    #[test]
    fn expired_deadline_drop_retains_a_timer_with_pending_native_exit() -> anyhow::Result<()> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            mpsc,
        };
        use std::time::{Duration, Instant};
        use windows_sys::Win32::Foundation::{
            DUPLICATE_SAME_ACCESS, DuplicateHandle, WAIT_OBJECT_0, WAIT_TIMEOUT,
        };
        use windows_sys::Win32::System::Threading::{
            FlsAlloc, FlsFree, FlsSetValue, GetCurrentProcess, WaitForSingleObject,
        };
        struct ExitGate {
            ready: mpsc::Sender<()>,
            release: AtomicBool,
        }
        unsafe extern "system" fn hold_exit(value: *const std::ffi::c_void) {
            let gate = unsafe { Arc::from_raw(value.cast::<ExitGate>()) };
            let _ = gate.ready.send(());
            while !gate.release.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        struct ExitFixture {
            gate: Arc<ExitGate>,
            slot: u32,
            thread: Option<OwnedHandle>,
            spawned: bool,
        }
        impl Drop for ExitFixture {
            fn drop(&mut self) {
                self.gate.release.store(true, Ordering::Release);
                if !self.spawned
                    || self.thread.as_ref().is_some_and(|thread| unsafe {
                        WaitForSingleObject(thread.as_raw_handle(), 2000) == WAIT_OBJECT_0
                    })
                {
                    unsafe { FlsFree(self.slot) };
                }
            }
        }
        let control = ExecutionControl::default();
        control.request(TerminationCause::Exited);
        let (ready, entered) = mpsc::channel();
        let gate = Arc::new(ExitGate {
            ready,
            release: AtomicBool::new(false),
        });
        let slot = unsafe { FlsAlloc(Some(hold_exit)) };
        anyhow::ensure!(slot != u32::MAX, "native exit slot allocation");
        let mut fixture = ExitFixture {
            gate: gate.clone(),
            slot,
            thread: None,
            spawned: false,
        };
        let (stop, receiver) = mpsc::channel::<()>();
        let timer_control = control.clone();
        let worker = std::thread::spawn(move || {
            let pointer = Arc::into_raw(gate);
            if unsafe { FlsSetValue(slot, pointer.cast()) } == 0 {
                drop(unsafe { Arc::from_raw(pointer) });
                return;
            }
            if matches!(
                receiver.recv_timeout(Duration::from_secs(60)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                timer_control.request(TerminationCause::Timeout);
            }
        });
        fixture.spawned = true;
        let id = worker.thread().id();
        let process = unsafe { GetCurrentProcess() };
        let mut duplicate = std::ptr::null_mut();
        let duplicated = unsafe {
            DuplicateHandle(
                process,
                worker.as_raw_handle(),
                process,
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } != 0;
        if !duplicated {
            fixture.gate.release.store(true, Ordering::Release);
            drop(stop);
            if unsafe { WaitForSingleObject(worker.as_raw_handle(), 2000) } == WAIT_OBJECT_0 {
                let _ = worker.join();
            } else {
                std::mem::forget(worker);
            }
            anyhow::bail!("native timer observation handle unavailable");
        }
        fixture.thread = Some(unsafe { OwnedHandle::from_raw_handle(duplicate) });
        // The stop channel ends the actual timer wait, then its native exit
        // callback holds the thread after its Rust body has returned.
        drop(stop);
        entered.recv_timeout(Duration::from_secs(2))?;
        let native_pending = unsafe { WaitForSingleObject(duplicate, 0) } == WAIT_TIMEOUT;
        let rust_finished = worker.is_finished();
        let original_deadline = Instant::now();
        let mut timer = ExecutionDeadline {
            stop: None,
            worker: Some(worker),
            cleanup_deadline: None,
        };
        let first_error = timer
            .finish(original_deadline)
            .expect_err("unconfirmed native exit");
        let second_error = timer
            .finish(Instant::now() + Duration::from_secs(2))
            .expect_err("original deadline cannot renew");
        let (active, started) = mpsc::channel();
        let (returned, done) = mpsc::channel();
        let caller = std::thread::spawn(move || {
            let _ = active.send(());
            drop(timer);
            let _ = returned.send(());
        });
        started.recv_timeout(Duration::from_secs(2))?;
        let stopped_before_release = done.recv_timeout(Duration::from_millis(500)).is_ok();
        let retained_before_release =
            stopped_before_release && super::super::retained::contains(id);
        fixture.gate.release.store(true, Ordering::Release);
        anyhow::ensure!(
            unsafe { WaitForSingleObject(caller.as_raw_handle(), 2000) } == WAIT_OBJECT_0,
            "timer owner cleanup"
        );
        caller
            .join()
            .map_err(|_| anyhow::anyhow!("timer owner panic"))?;
        anyhow::ensure!(
            unsafe { WaitForSingleObject(duplicate, 2000) } == WAIT_OBJECT_0,
            "native timer exit cleanup"
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while super::super::retained::contains(id) {
            let _ = super::super::retained::join_finished(id);
            anyhow::ensure!(Instant::now() < deadline, "retained timer cleanup");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(native_pending && rust_finished);
        assert_eq!(first_error.code, "EXECUTION_CLEANUP_FAILED");
        assert_eq!(second_error.code, first_error.code);
        assert!(
            stopped_before_release && retained_before_release,
            "Drop must not wait or discard its pending timer owner"
        );
        assert_eq!(control.cause(), Some(TerminationCause::Exited));
        Ok(())
    }
}
