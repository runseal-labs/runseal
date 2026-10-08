use std::sync::{Mutex, OnceLock};
use std::thread::JoinHandle;
#[cfg(all(test, windows))]
use std::thread::ThreadId;

trait Worker: Send {
    fn finished(&self) -> bool;
    fn join(self: Box<Self>);
    #[cfg(all(test, windows))]
    fn id(&self) -> ThreadId;
}

/// On Windows, require native thread exit, including platform callbacks.
pub(crate) fn thread_finished<T>(worker: &JoinHandle<T>) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        unsafe { WaitForSingleObject(worker.as_raw_handle(), 0) == WAIT_OBJECT_0 }
    }
    #[cfg(not(windows))]
    worker.is_finished()
}

impl<T: Send + 'static> Worker for JoinHandle<T> {
    fn finished(&self) -> bool {
        thread_finished(self)
    }
    fn join(self: Box<Self>) {
        let _ = (*self).join();
    }
    #[cfg(all(test, windows))]
    fn id(&self) -> ThreadId {
        self.thread().id()
    }
}

fn workers() -> &'static Mutex<Vec<Box<dyn Worker>>> {
    static WORKERS: OnceLock<Mutex<Vec<Box<dyn Worker>>>> = OnceLock::new();
    WORKERS.get_or_init(Mutex::default)
}

/// Keep ownership after a cleanup deadline; reap only workers proven finished.
pub(crate) fn retain<T: Send + 'static>(worker: JoinHandle<T>) {
    let mut retained = workers()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut index = 0;
    while index < retained.len() {
        if retained[index].finished() {
            retained.swap_remove(index).join();
        } else {
            index += 1;
        }
    }
    retained.push(Box::new(worker));
}

#[cfg(all(test, windows))]
pub(crate) fn contains(id: ThreadId) -> bool {
    workers()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .any(|worker| worker.id() == id)
}

#[cfg(all(test, windows))]
pub(crate) fn join_finished(id: ThreadId) -> bool {
    let mut retained = workers()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(index) = retained
        .iter()
        .position(|worker| worker.id() == id && worker.finished())
    {
        retained.swap_remove(index).join();
        return true;
    }
    false
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::sync::{
        Arc,
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
        entered: mpsc::Sender<()>,
        release: AtomicBool,
    }

    unsafe extern "system" fn exit_callback(value: *const std::ffi::c_void) {
        let gate = unsafe { Arc::from_raw(value.cast::<ExitGate>()) };
        let _ = gate.entered.send(());
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
            let stopped = self.thread.as_ref().is_some_and(|thread| unsafe {
                WaitForSingleObject(thread.as_raw_handle(), 2000) == WAIT_OBJECT_0
            });
            if stopped || !self.spawned {
                unsafe { FlsFree(self.slot) };
            }
            // Preserve the slot if native thread exit cannot be confirmed.
        }
    }

    #[test]
    fn retained_reaping_does_not_join_a_rust_finished_thread_with_pending_native_exit()
    -> anyhow::Result<()> {
        use anyhow::Context;
        let (entered, ready) = mpsc::channel();
        let gate = Arc::new(ExitGate {
            entered,
            release: AtomicBool::new(false),
        });
        let slot = unsafe { FlsAlloc(Some(exit_callback)) };
        anyhow::ensure!(slot != u32::MAX, "native exit slot allocation");
        let mut fixture = ExitFixture {
            gate: gate.clone(),
            slot,
            thread: None,
            spawned: false,
        };
        let worker = std::thread::spawn(move || {
            let value = Arc::into_raw(gate);
            if unsafe { FlsSetValue(slot, value.cast()) } == 0 {
                drop(unsafe { Arc::from_raw(value) });
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
        fixture.spawned = true;
        let id = worker.thread().id();
        let mut duplicate = std::ptr::null_mut();
        let process = unsafe { GetCurrentProcess() };
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
            if unsafe { WaitForSingleObject(worker.as_raw_handle(), 2000) } == WAIT_OBJECT_0 {
                let _ = worker.join();
            } else {
                std::mem::forget(worker);
            }
            anyhow::bail!("native thread observation handle unavailable");
        }
        fixture.thread = Some(unsafe { OwnedHandle::from_raw_handle(duplicate) });
        ready
            .recv_timeout(Duration::from_secs(2))
            .context("native exit callback readiness")?;
        let rust_finished = worker.is_finished();
        let native_pending = unsafe { WaitForSingleObject(duplicate, 0) } == WAIT_TIMEOUT;
        retain(worker);
        let next = std::thread::spawn(|| {});
        let next_id = next.thread().id();
        let (started, active) = mpsc::channel();
        let (returned, done) = mpsc::channel();
        let caller = std::thread::spawn(move || {
            let _ = started.send(());
            retain(next);
            let _ = returned.send(());
        });
        active.recv_timeout(Duration::from_secs(2))?;
        let returned_before_native_release = done.recv_timeout(Duration::from_millis(500)).is_ok();
        fixture.gate.release.store(true, Ordering::Release);
        anyhow::ensure!(
            unsafe { WaitForSingleObject(caller.as_raw_handle(), 2000) } == WAIT_OBJECT_0,
            "retainer caller cleanup"
        );
        caller
            .join()
            .map_err(|_| anyhow::anyhow!("retainer caller panic"))?;
        anyhow::ensure!(
            unsafe { WaitForSingleObject(duplicate, 2000) } == WAIT_OBJECT_0,
            "native exit completion"
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        for worker_id in [id, next_id] {
            while contains(worker_id) {
                let _ = join_finished(worker_id);
                anyhow::ensure!(Instant::now() < deadline, "retained fixture cleanup");
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        assert!(
            rust_finished && native_pending,
            "actual native exit must outlive the Rust body"
        );
        assert!(
            returned_before_native_release,
            "reaping must not block on native thread exit"
        );
        Ok(())
    }
}
