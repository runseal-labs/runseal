use super::*;
#[cfg(windows)]
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::ffi::{OsStr, OsString};
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CreateMutexW, OpenProcess, ReleaseMutex, WaitForSingleObject,
};

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct WindowsSandboxPolicyCohortKey {
    pub(super) policy_hash: String,
    pub(super) binding_key: String,
}

#[cfg(windows)]
pub(super) struct WindowsSandboxExecutionGate {
    _in_process: WindowsSandboxInProcessGate,
    _cross_process: WindowsSandboxCrossProcessGate,
}

#[cfg(windows)]
pub(super) struct WindowsSandboxInProcessGate;

#[cfg(windows)]
struct WindowsSandboxExecutionGateLock {
    state: Mutex<WindowsSandboxExecutionGateState>,
}

#[cfg(windows)]
#[derive(Default)]
struct WindowsSandboxExecutionGateState {
    active_key: Option<WindowsSandboxPolicyCohortKey>,
    active_count: usize,
    contaminated: bool,
}

#[cfg(windows)]
impl WindowsSandboxExecutionGate {
    pub(super) fn finish_owned(self, deadline: std::time::Instant) -> io::Result<()> {
        let result = self._cross_process.finish_after_execution_cleanup(deadline);
        if result.is_err() {
            super::record_test_cleanup_trace("policy_gate_release_failed");
            let mut state = windows_sandbox_execution_gate_lock()
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.contaminated = true;
        }
        result
    }
    pub(super) fn mark_cleanup_failed(&self) -> io::Result<()> {
        let result = self._cross_process.mark_cleanup_failed();
        let mut state = windows_sandbox_execution_gate_lock()
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.contaminated = true;
        result
    }
}

#[cfg(windows)]
impl WindowsSandboxCrossProcessGate {
    fn mark_quarantined(&self) -> io::Result<()> {
        mark_cross_process_quarantined(&self.quarantined, &self.quarantine)
    }

    fn mark_cleanup_failed(&self) -> io::Result<()> {
        self.mark_quarantined()?;
        let _mutex = WindowsSandboxNamedMutexGuard::acquire(&self.mutex_name)?;
        fs::write(
            self.state_path.with_extension("cleanup-failed"),
            b"cleanup_failed",
        )
    }
}

#[cfg(windows)]
fn mark_cross_process_quarantined(
    quarantined: &AtomicBool,
    quarantine: &std::sync::Arc<WindowsSandboxQuarantineSignal>,
) -> io::Result<()> {
    quarantined.store(true, Ordering::Release);
    let mut retained = retained_quarantine_signals()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !retained.iter().any(|signal| signal.name == quarantine.name) {
        retained.push(quarantine.clone());
    }
    drop(retained);
    quarantine.signal()
}

#[cfg(windows)]
struct ReleaseOwner(WindowsSandboxCrossProcessGate);

#[cfg(windows)]
impl Drop for ReleaseOwner {
    fn drop(&mut self) {
        // Failed spawn, panic, or an incomplete release cannot re-enter file I/O.
        if !self.0.released {
            let _ = self.0.mark_quarantined();
        }
    }
}

#[cfg(windows)]
impl WindowsSandboxCrossProcessGate {
    fn finish_owned(self, deadline: std::time::Instant) -> io::Result<()> {
        self.finish_owned_with(deadline, || {})
    }

    fn finish_after_execution_cleanup(
        self,
        _execution_deadline: std::time::Instant,
    ) -> io::Result<()> {
        // The execution owner calls this only after native cleanup is confirmed.
        // Keep reservation publication bounded, but let it finish even when the
        // shared process-cleanup deadline was consumed by stopping the process tree.
        super::record_test_cleanup_trace("policy_release_after_cleanup_started");
        self.finish_owned(std::time::Instant::now() + std::time::Duration::from_secs(1))
    }

    fn finish_owned_with<F: FnOnce() + Send + 'static>(
        self,
        deadline: std::time::Instant,
        before_release: F,
    ) -> io::Result<()> {
        use crate::execution::retained;
        let deadline = self
            .cleanup_deadline
            .map_or(deadline, |old| old.min(deadline));
        let quarantined = self.quarantined.clone();
        let quarantine = self.quarantine.clone();
        let release_committed = std::sync::Arc::new(AtomicBool::new(false));
        let worker_release_committed = release_committed.clone();
        let mut owner = ReleaseOwner(self);
        let (completed, completion) = std::sync::mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("runseal-policy-release".into())
            .spawn(move || {
                super::record_test_cleanup_trace("policy_release_worker_entered");
                let result =
                    owner
                        .0
                        .release_with(deadline, before_release, Some(&worker_release_committed));
                drop(owner);
                let _ = completed.send(result);
            })
            .map_err(|_| {
                super::record_test_cleanup_trace("policy_release_worker_spawn_failed");
                let _ = mark_cross_process_quarantined(&quarantined, &quarantine);
                io::Error::other(BackendCleanupError)
            })?;
        super::record_test_cleanup_trace("policy_release_worker_spawned");
        loop {
            match policy_release_worker_state(&worker, deadline, &release_committed) {
                PolicyReleaseWorkerState::Committed => {
                    super::record_test_cleanup_trace("policy_release_committed_before_deadline");
                    retained::retain(worker);
                    return Ok(());
                }
                PolicyReleaseWorkerState::Finished => {
                    let joined = worker.join();
                    let result = completion.try_recv();
                    return match (joined, result) {
                        (Ok(()), Ok(Ok(()))) => Ok(()),
                        (Ok(()), Ok(Err(error))) => {
                            super::record_test_cleanup_trace("policy_release_operation_failed");
                            Err(error)
                        }
                        _ => {
                            super::record_test_cleanup_trace("policy_release_worker_failed");
                            let _ = mark_cross_process_quarantined(&quarantined, &quarantine);
                            Err(io::Error::other(BackendCleanupError))
                        }
                    };
                }
                PolicyReleaseWorkerState::TimedOut => {
                    super::record_test_cleanup_trace("policy_release_deadline");
                    let _ = mark_cross_process_quarantined(&quarantined, &quarantine);
                    retained::retain(worker);
                    return Err(io::Error::other(BackendCleanupError));
                }
                PolicyReleaseWorkerState::Pending => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyReleaseWorkerState {
    Committed,
    Finished,
    TimedOut,
    Pending,
}

#[cfg(windows)]
fn policy_release_worker_state(
    worker: &std::thread::JoinHandle<()>,
    deadline: std::time::Instant,
    release_committed: &AtomicBool,
) -> PolicyReleaseWorkerState {
    if release_committed.load(Ordering::Acquire) {
        PolicyReleaseWorkerState::Committed
    } else if crate::execution::retained::thread_finished(worker) {
        PolicyReleaseWorkerState::Finished
    } else if std::time::Instant::now() >= deadline {
        PolicyReleaseWorkerState::TimedOut
    } else {
        PolicyReleaseWorkerState::Pending
    }
}

#[cfg(windows)]
fn windows_sandbox_execution_gate_lock() -> &'static WindowsSandboxExecutionGateLock {
    static GATE: OnceLock<WindowsSandboxExecutionGateLock> = OnceLock::new();
    GATE.get_or_init(|| WindowsSandboxExecutionGateLock {
        state: Mutex::new(WindowsSandboxExecutionGateState::default()),
    })
}

#[cfg(windows)]
pub(super) fn windows_sandbox_execution_gate(
    plan: &PlatformSandboxPlan,
) -> io::Result<WindowsSandboxExecutionGate> {
    let key = WindowsSandboxPolicyCohortKey {
        policy_hash: plan.policy_hash.clone(),
        binding_key: windows_sandbox_binding_key()?,
    };
    let in_process = windows_sandbox_execution_gate_for_key(key.clone())?;
    let runtime_roots = plan.runtime_root.iter().cloned().collect::<Vec<_>>();
    let cross_process =
        WindowsSandboxCrossProcessGate::acquire_with_runtime_roots(&key, Some(runtime_roots))?;
    Ok(WindowsSandboxExecutionGate {
        _in_process: in_process,
        _cross_process: cross_process,
    })
}

#[cfg(windows)]
pub(super) fn windows_sandbox_execution_gate_for_key(
    key: WindowsSandboxPolicyCohortKey,
) -> io::Result<WindowsSandboxInProcessGate> {
    let gate = windows_sandbox_execution_gate_lock();
    let mut state = gate
        .state
        .lock()
        .map_err(|_| io::Error::other("windows sandbox execution gate poisoned"))?;
    // RunSeal MVP: one global Windows sandbox cohort; split by identity if multi-tenant throughput matters.
    if state.contaminated {
        return Err(io::Error::other(BackendCleanupError));
    }
    if state
        .active_key
        .as_ref()
        .is_some_and(|active_key| active_key != &key)
    {
        return Err(io::Error::other(PolicyTransitionBusyError {
            reason: POLICY_TRANSITION_BUSY_REASON,
        }));
    }
    state.active_key.get_or_insert(key);
    state.active_count += 1;
    Ok(WindowsSandboxInProcessGate)
}

#[cfg(windows)]
impl Drop for WindowsSandboxInProcessGate {
    fn drop(&mut self) {
        let gate = windows_sandbox_execution_gate_lock();
        let Ok(mut state) = gate.state.lock() else {
            return;
        };
        state.active_count = state.active_count.saturating_sub(1);
        if state.active_count == 0 {
            state.active_key = None;
        }
    }
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsSandboxCrossProcessGate {
    token: String,
    policy_hash: String,
    process_creation_time: u64,
    state_path: PathBuf,
    mutex_name: String,
    quarantined: std::sync::Arc<AtomicBool>,
    released: bool,
    cleanup_deadline: Option<std::time::Instant>,
    quarantine: std::sync::Arc<WindowsSandboxQuarantineSignal>,
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsSandboxQuarantineSignal {
    name: String,
    handle: std::os::windows::io::OwnedHandle,
}

#[cfg(windows)]
fn retained_quarantine_signals()
-> &'static Mutex<Vec<std::sync::Arc<WindowsSandboxQuarantineSignal>>> {
    static SIGNALS: OnceLock<Mutex<Vec<std::sync::Arc<WindowsSandboxQuarantineSignal>>>> =
        OnceLock::new();
    SIGNALS.get_or_init(Mutex::default)
}

#[cfg(windows)]
impl WindowsSandboxQuarantineSignal {
    fn open(binding: &str) -> io::Result<Self> {
        let name = format!(
            "Global\\RunSealExecutionUnsafe-{:x}",
            Sha256::digest(binding.as_bytes())
        );
        let handle = codex_windows_sandbox::create_host_coordinator_event(&name)
            .map_err(|_| io::Error::other("execution quarantine signal unavailable"))?;
        Ok(Self { name, handle })
    }
    fn signal(&self) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        if unsafe {
            windows_sys::Win32::System::Threading::SetEvent(self.handle.as_raw_handle().cast())
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    fn check(&self) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        match unsafe { WaitForSingleObject(self.handle.as_raw_handle().cast(), 0) } {
            258 => Ok(()),
            _ => Err(io::Error::other(BackendCleanupError)),
        }
    }

    /// Clears a quarantine signal after a repair has proved the range released.
    fn reset(&self) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        if unsafe {
            windows_sys::Win32::System::Threading::ResetEvent(self.handle.as_raw_handle().cast())
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
#[derive(Default)]
struct WindowsSandboxCrossProcessGateState {
    active: Vec<WindowsSandboxCrossProcessGateEntry>,
}

#[cfg(windows)]
struct WindowsSandboxCrossProcessGateEntry {
    pid: u32,
    process_creation_time: u64,
    token: String,
    policy_hash: String,
    /// Runtime roots created for this reservation.
    ///
    /// `None` marks a reservation written before roots were recorded; a repair
    /// may not treat that as evidence that the roots no longer exist.
    runtime_roots: Option<Vec<String>>,
}

#[cfg(windows)]
struct WindowsSandboxNamedMutexGuard {
    handle: HANDLE,
}

#[cfg(windows)]
impl WindowsSandboxCrossProcessGate {
    #[cfg(test)]
    fn acquire(key: &WindowsSandboxPolicyCohortKey) -> io::Result<WindowsSandboxCrossProcessGate> {
        Self::acquire_with_runtime_roots(key, None)
    }

    fn acquire_with_runtime_roots(
        key: &WindowsSandboxPolicyCohortKey,
        runtime_roots: Option<Vec<String>>,
    ) -> io::Result<WindowsSandboxCrossProcessGate> {
        let state_path = cross_process_gate_state_path(&key.binding_key)?;
        let mutex_name = cross_process_gate_mutex_name(&key.binding_key);
        let quarantine =
            std::sync::Arc::new(WindowsSandboxQuarantineSignal::open(&key.binding_key)?);
        quarantine.check()?;
        let _mutex = WindowsSandboxNamedMutexGuard::acquire(&mutex_name)?;
        quarantine.check()?;
        if state_path.with_extension("cleanup-failed").exists() {
            return Err(io::Error::other(BackendCleanupError));
        }
        let mut state = read_cross_process_gate_state(&state_path)?;
        // A dead host cannot acknowledge cleanup of the sandbox process range,
        // runtime roots, or shared constraints. Keep its reservation until an
        // explicit repair can prove those resources have been released.
        if state
            .active
            .iter()
            .any(|entry| !reservation_owner_is_live(entry).unwrap_or(false))
        {
            return Err(io::Error::other(BackendCleanupError));
        }
        if state
            .active
            .iter()
            .any(|entry| entry.policy_hash != key.policy_hash)
        {
            return Err(io::Error::other(PolicyTransitionBusyError {
                reason: POLICY_TRANSITION_BUSY_REASON,
            }));
        }

        let token = cross_process_gate_token();
        let process_creation_time = process_creation_time(unsafe {
            windows_sys::Win32::System::Threading::GetCurrentProcess()
        })?;
        state.active.push(WindowsSandboxCrossProcessGateEntry {
            pid: std::process::id(),
            process_creation_time,
            token: token.clone(),
            policy_hash: key.policy_hash.clone(),
            runtime_roots,
        });
        write_cross_process_gate_state(&state_path, &state)?;
        Ok(WindowsSandboxCrossProcessGate {
            token,
            policy_hash: key.policy_hash.clone(),
            process_creation_time,
            state_path,
            mutex_name,
            quarantined: std::sync::Arc::new(AtomicBool::new(false)),
            released: false,
            cleanup_deadline: None,
            quarantine,
        })
    }
}

#[cfg(windows)]
impl Drop for WindowsSandboxCrossProcessGate {
    fn drop(&mut self) {
        let deadline = self
            .cleanup_deadline
            .unwrap_or_else(|| std::time::Instant::now() + std::time::Duration::from_secs(1));
        let _ = self.release(deadline);
    }
}

#[cfg(windows)]
impl WindowsSandboxCrossProcessGate {
    fn release(&mut self, deadline: std::time::Instant) -> io::Result<()> {
        self.release_with(deadline, || {}, None)
    }

    fn release_with<F: FnOnce()>(
        &mut self,
        deadline: std::time::Instant,
        before_state_read: F,
        release_committed: Option<&AtomicBool>,
    ) -> io::Result<()> {
        if self.released {
            return Ok(());
        }
        super::record_test_cleanup_trace(if release_committed.is_some() {
            "policy_release_owned_started"
        } else {
            "policy_release_drop_started"
        });
        let deadline = self
            .cleanup_deadline
            .map_or(deadline, |previous| previous.min(deadline));
        self.cleanup_deadline = Some(deadline);
        let result = (|| {
            if self.quarantined.load(Ordering::Acquire) {
                return Err(io::Error::other(BackendCleanupError));
            }
            self.quarantine.check()?;
            super::record_test_cleanup_trace("policy_release_precheck_passed");
            let _mutex = WindowsSandboxNamedMutexGuard::acquire_until(&self.mutex_name, deadline)?;
            super::record_test_cleanup_trace("policy_release_mutex_acquired");
            before_state_read();
            self.quarantine.check()?;
            if self.quarantined.load(Ordering::Acquire) || std::time::Instant::now() >= deadline {
                return Err(io::Error::other(BackendCleanupError));
            }
            let mut state = read_cross_process_gate_state(&self.state_path)?;
            super::record_test_cleanup_trace("policy_release_state_read");
            let before = state.active.len();
            state.active.retain(|entry| {
                !(entry.pid == std::process::id()
                    && entry.process_creation_time == self.process_creation_time
                    && entry.token == self.token
                    && entry.policy_hash == self.policy_hash)
            });
            if before.checked_sub(state.active.len()) != Some(1)
                || std::time::Instant::now() >= deadline
            {
                return Err(io::Error::other(BackendCleanupError));
            }
            super::record_test_cleanup_trace("policy_release_entry_removed");
            self.quarantine.check()?;
            if self.quarantined.load(Ordering::Acquire) {
                return Err(io::Error::other(BackendCleanupError));
            }
            write_cross_process_gate_state(&self.state_path, &state)?;
            self.released = true;
            if let Some(release_committed) = release_committed {
                release_committed.store(true, Ordering::Release);
            }
            super::record_test_cleanup_trace(if release_committed.is_some() {
                "policy_release_owned_state_written"
            } else {
                "policy_release_drop_state_written"
            });
            Ok(())
        })();
        if result.is_err() {
            let _ = self.mark_quarantined();
        }
        result
    }
}

#[cfg(windows)]
impl WindowsSandboxNamedMutexGuard {
    fn acquire(name: &str) -> io::Result<WindowsSandboxNamedMutexGuard> {
        Self::acquire_until(
            name,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        )
    }

    fn acquire_until(
        name: &str,
        deadline: std::time::Instant,
    ) -> io::Result<WindowsSandboxNamedMutexGuard> {
        const WAIT_OBJECT_0: u32 = 0;
        const WAIT_ABANDONED: u32 = 0x80;

        let name_wide = to_wide(OsStr::new(name));
        let handle = unsafe { CreateMutexW(std::ptr::null_mut(), 0, name_wide.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::other(format!(
                "create windows sandbox execution gate mutex failed: {}",
                unsafe { GetLastError() }
            )));
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let wait_ms = remaining.as_millis().min(1000) as u32;
        if remaining.is_zero() {
            unsafe {
                CloseHandle(handle);
            }
            return Err(io::Error::other(BackendCleanupError));
        }
        let wait = unsafe { WaitForSingleObject(handle, wait_ms) };
        if wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED {
            return Ok(WindowsSandboxNamedMutexGuard { handle });
        }
        unsafe {
            CloseHandle(handle);
        }
        Err(io::Error::other(format!(
            "wait for windows sandbox execution gate mutex failed: {wait}"
        )))
    }
}

#[cfg(windows)]
impl Drop for WindowsSandboxNamedMutexGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = ReleaseMutex(self.handle);
            CloseHandle(self.handle);
        }
    }
}

#[cfg(windows)]
fn cross_process_gate_state_path(binding_key: &str) -> io::Result<PathBuf> {
    let state_dir = cross_process_gate_state_dir()?;
    fs::create_dir_all(&state_dir)?;
    let digest = Sha256::digest(binding_key.as_bytes());
    Ok(state_dir.join(format!("{digest:x}.json")))
}

#[cfg(windows)]
pub(super) fn cross_process_gate_state_dir() -> io::Result<PathBuf> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Security::{TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY};
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};
    let mut token = std::ptr::null_mut();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE,
            &mut token,
        )
    } == 0
    {
        return Err(io::Error::other(
            "execution gate state identity unavailable",
        ));
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token.cast()) };
    let mut path = std::ptr::null_mut();
    let status = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_ProgramData,
            0,
            token.as_raw_handle().cast(),
            &mut path,
        )
    };
    if status < 0 || path.is_null() {
        unsafe {
            CoTaskMemFree(path.cast());
        }
        return Err(io::Error::other(
            "execution gate state directory unavailable",
        ));
    }
    let mut length = 0;
    while length < 32768 && unsafe { *path.add(length) } != 0 {
        length += 1;
    }
    if length == 32768 {
        unsafe {
            CoTaskMemFree(path.cast());
        }
        return Err(io::Error::other("invalid execution gate state directory"));
    }
    let root = unsafe { OsString::from_wide(std::slice::from_raw_parts(path, length)) };
    unsafe {
        CoTaskMemFree(path.cast());
    }
    let root = PathBuf::from(root);
    if !root.is_absolute() {
        return Err(io::Error::other("invalid execution gate state directory"));
    }
    Ok(root.join("RunSeal").join("execution-gates"))
}

#[cfg(windows)]
fn windows_sandbox_binding_key() -> io::Result<String> {
    let binding = codex_windows_sandbox::resolve_sid(codex_windows_sandbox::SANDBOX_USERS_GROUP)
        .map_err(|_| {
            io::Error::other(BackendUnavailableError {
                reason: public_windows_setup_unavailable_reason("process_binding_unavailable"),
            })
        })?;
    Ok(format!("{:x}", Sha256::digest(binding)))
}

#[cfg(windows)]
fn cross_process_gate_mutex_name(binding_key: &str) -> String {
    let digest = Sha256::digest(binding_key.as_bytes());
    format!("Global\\RunSealExecutionGate-{digest:x}")
}

#[cfg(windows)]
fn cross_process_gate_token() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{sequence}", std::process::id())
}

#[cfg(windows)]
fn read_cross_process_gate_state(path: &Path) -> io::Result<WindowsSandboxCrossProcessGateState> {
    match fs::read_to_string(path) {
        Ok(contents) => parse_cross_process_gate_state(&contents),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            Ok(WindowsSandboxCrossProcessGateState::default())
        }
        Err(err) => Err(err),
    }
}

#[cfg(windows)]
fn write_cross_process_gate_state(
    path: &Path,
    state: &WindowsSandboxCrossProcessGateState,
) -> io::Result<()> {
    let active = state
        .active
        .iter()
        .map(|entry| {
            json!({
                "pid": entry.pid,
                "process_creation_time": entry.process_creation_time,
                "token": entry.token,
                "policy_hash": entry.policy_hash,
                "runtime_roots": entry.runtime_roots,
            })
        })
        .collect::<Vec<_>>();
    fs::write(path, json!({ "active": active }).to_string())
}

/// Result of an explicit execution-gate repair.
#[cfg(windows)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ExecutionGateRepair {
    pub(crate) repaired: bool,
    pub(crate) cleared_executions: usize,
    pub(crate) removed_runtime_roots: usize,
    pub(crate) cleared_cleanup_failed_marker: bool,
    pub(crate) cleared_quarantine: bool,
    pub(crate) unverified_runtime_roots: bool,
    pub(crate) uninspectable_processes: usize,
}

/// Explicitly repairs the current machine's Windows sandbox binding.
///
/// The repair only restores a binding whose recorded reservation owners are
/// gone, whose process range has no live sandbox-identity process, and whose
/// recorded runtime roots are absent or safely removable.
#[cfg(windows)]
pub(crate) fn repair_execution_gate(
    accept_unverified_release: bool,
    deadline: std::time::Instant,
) -> io::Result<ExecutionGateRepair> {
    let binding_key = windows_sandbox_binding_key()?;
    repair_execution_gate_for_binding(&binding_key, accept_unverified_release, deadline)
}

#[cfg(windows)]
pub(super) fn repair_execution_gate_for_binding(
    binding_key: &str,
    accept_unverified_release: bool,
    deadline: std::time::Instant,
) -> io::Result<ExecutionGateRepair> {
    repair_execution_gate_for_binding_with_process_probe(
        binding_key,
        accept_unverified_release,
        deadline,
        inspect_sandbox_process_group,
    )
}

#[cfg(windows)]
fn inspect_sandbox_process_group() -> io::Result<(Vec<u32>, usize)> {
    use crate::windows::processes::pids_with_token_group;

    let group_sid = codex_windows_sandbox::resolve_sid(codex_windows_sandbox::SANDBOX_USERS_GROUP)
        .map_err(|_| {
            io::Error::other(BackendUnavailableError {
                reason: public_windows_setup_unavailable_reason("process_binding_unavailable"),
            })
        })?;
    pids_with_token_group(&group_sid)
}

#[cfg(windows)]
fn repair_execution_gate_for_binding_with_process_probe(
    binding_key: &str,
    accept_unverified_release: bool,
    deadline: std::time::Instant,
    process_probe: impl FnOnce() -> io::Result<(Vec<u32>, usize)>,
) -> io::Result<ExecutionGateRepair> {
    let state_path = cross_process_gate_state_path(binding_key)?;
    let mutex_name = cross_process_gate_mutex_name(binding_key);
    let cleanup_marker = state_path.with_extension("cleanup-failed");
    let quarantine = WindowsSandboxQuarantineSignal::open(binding_key)?;
    let _mutex = WindowsSandboxNamedMutexGuard::acquire_until(&mutex_name, deadline)?;

    let state = read_cross_process_gate_state(&state_path)?;
    let marker_present = cleanup_marker.exists();
    let quarantine_signaled = quarantine.check().is_err();
    let mut report = ExecutionGateRepair::default();
    if state.active.is_empty() && !marker_present && !quarantine_signaled {
        return Ok(report);
    }

    // Every recorded reservation owner must be provably gone. A live owner is a
    // running execution, not stale state.
    for entry in &state.active {
        if reservation_owner_is_live(entry)? {
            return Err(io::Error::other(BackendCleanupError));
        }
    }
    // The single-identity model means the process range is empty exactly when no
    // process token belongs to the sandbox identity group.
    let (running, uninspectable) = process_probe()?;
    if !running.is_empty() {
        return Err(io::Error::other(BackendCleanupError));
    }
    report.uninspectable_processes = uninspectable;
    // An uninspectable token could still belong to the sandbox identity, so the
    // default repair refuses unless the caller accepts that residual evidence.
    if uninspectable > 0 && !accept_unverified_release {
        return Err(io::Error::other(BackendCleanupError));
    }

    // Recorded runtime roots must be absent or safely removable before the
    // reservation can be dropped.
    for entry in &state.active {
        report.cleared_executions += 1;
        match &entry.runtime_roots {
            Some(roots) => {
                for root in roots {
                    if remove_recorded_runtime_root(root)? {
                        report.removed_runtime_roots += 1;
                    }
                }
            }
            None => {
                if !accept_unverified_release {
                    return Err(io::Error::other(BackendCleanupError));
                }
                report.unverified_runtime_roots = true;
            }
        }
    }

    // All proofs passed: drop the reservation, the cleanup-failed marker, and the
    // cross-process quarantine.
    write_cross_process_gate_state(&state_path, &WindowsSandboxCrossProcessGateState::default())?;
    if marker_present {
        fs::remove_file(&cleanup_marker)?;
        report.cleared_cleanup_failed_marker = true;
    }
    if quarantine_signaled {
        quarantine.reset()?;
        report.cleared_quarantine = true;
    }
    report.repaired = true;
    Ok(report)
}

#[cfg(windows)]
fn remove_recorded_runtime_root(root: &str) -> io::Result<bool> {
    let path = Path::new(root);
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to repair a runtime root that is not absolute",
        ));
    }
    let expected_parent = Path::new(".runseal").join("runtime");
    if !path
        .parent()
        .is_some_and(|parent| parent.ends_with(&expected_parent))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to repair a runtime root outside the workspace runtime directory",
        ));
    }
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to repair a runtime root without a directory name",
        ));
    };
    if !path.exists() {
        return Ok(false);
    }
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to repair a symlinked runtime root",
        ));
    }
    let marker = path.join(RUNTIME_ROOT_MARKER);
    if !runtime_marker_is_regular_file(&marker)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to repair an unmarked runtime root",
        ));
    }
    if fs::read_to_string(&marker)? != name {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to repair a runtime root with a mismatched marker",
        ));
    }
    validate_runtime_tree_has_no_symlinks(path, "repair")?;
    fs::remove_dir_all(path)?;
    Ok(true)
}

#[cfg(windows)]
fn reservation_owner_is_live(entry: &WindowsSandboxCrossProcessGateEntry) -> io::Result<bool> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    let handle = unsafe {
        OpenProcess(
            SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            entry.pid,
        )
    };
    if handle.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error()
            == Some(windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER as i32)
        {
            return Ok(false);
        }
        return Err(error);
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
    if process_creation_time(handle.as_raw_handle().cast())? != entry.process_creation_time {
        return Ok(false);
    }
    match unsafe { WaitForSingleObject(handle.as_raw_handle().cast(), 0) } {
        258 => Ok(true),
        0 => Ok(false),
        _ => Err(io::Error::other("execution gate owner status unavailable")),
    }
}

#[cfg(windows)]
fn process_creation_time(handle: HANDLE) -> io::Result<u64> {
    use windows_sys::Win32::Foundation::FILETIME;
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe {
        windows_sys::Win32::System::Threading::GetProcessTimes(
            handle,
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

#[cfg(windows)]
fn parse_cross_process_gate_state(
    contents: &str,
) -> io::Result<WindowsSandboxCrossProcessGateState> {
    let value: Value = serde_json::from_str(contents).map_err(io::Error::other)?;
    let active = value
        .get("active")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::other("execution gate state active must be an array"))?
        .iter()
        .map(|entry| {
            let pid = entry
                .get("pid")
                .and_then(Value::as_u64)
                .and_then(|pid| u32::try_from(pid).ok())
                .ok_or_else(|| io::Error::other("execution gate entry pid must be u32"))?;
            let token = entry
                .get("token")
                .and_then(Value::as_str)
                .ok_or_else(|| io::Error::other("execution gate entry token must be a string"))?
                .to_string();
            let process_creation_time = entry
                .get("process_creation_time")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    io::Error::other("execution gate entry process_creation_time must be u64")
                })?;
            let policy_hash = entry
                .get("policy_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    io::Error::other("execution gate entry policy_hash must be a string")
                })?
                .to_string();
            let runtime_roots = entry
                .get("runtime_roots")
                .and_then(Value::as_array)
                .map(|roots| {
                    roots
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                });
            Ok(WindowsSandboxCrossProcessGateEntry {
                pid,
                process_creation_time,
                token,
                policy_hash,
                runtime_roots,
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    Ok(WindowsSandboxCrossProcessGateState { active })
}

#[cfg(windows)]
fn to_wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn completed_policy_release_worker_wins_over_elapsed_deadline() -> io::Result<()> {
        let worker = std::thread::spawn(|| {});
        let wait_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !crate::execution::retained::thread_finished(&worker) {
            if std::time::Instant::now() >= wait_deadline {
                return Err(io::Error::other("policy release worker did not finish"));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        assert_eq!(
            policy_release_worker_state(
                &worker,
                std::time::Instant::now() - std::time::Duration::from_millis(1),
                &AtomicBool::new(false),
            ),
            PolicyReleaseWorkerState::Finished
        );
        worker
            .join()
            .map_err(|_| io::Error::other("policy release worker panicked"))?;
        Ok(())
    }

    #[test]
    fn committed_policy_release_wins_over_elapsed_deadline() -> io::Result<()> {
        let (started, ready) = std::sync::mpsc::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _ = started.send(());
            let _ = wait.recv();
        });
        ready
            .recv_timeout(std::time::Duration::from_secs(2))
            .map_err(io::Error::other)?;
        let committed = AtomicBool::new(true);
        assert_eq!(
            policy_release_worker_state(
                &worker,
                std::time::Instant::now() - std::time::Duration::from_millis(1),
                &committed,
            ),
            PolicyReleaseWorkerState::Committed
        );
        release
            .send(())
            .map_err(|_| io::Error::other("policy release worker unavailable"))?;
        worker
            .join()
            .map_err(|_| io::Error::other("policy release worker panicked"))?;
        Ok(())
    }

    #[test]
    fn reservation_release_respects_held_native_mutex_deadline_and_preserves_quarantine()
    -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use std::time::{Duration, Instant};
        let tmp = TempDir::new()?;
        let key = WindowsSandboxPolicyCohortKey {
            binding_key: format!("release-deadline-fixture:{}", tmp.path().display()),
            policy_hash: "policy-a".into(),
        };
        let mut guard = WindowsSandboxCrossProcessGate::acquire(&key)?;
        let path = guard.state_path.clone();
        let signal_name = guard.quarantine.name.clone();
        let mutex_name = guard.mutex_name.clone();
        let (entered, ready) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || -> io::Result<()> {
            let _held = WindowsSandboxNamedMutexGuard::acquire(&mutex_name)?;
            let _ = entered.send(());
            let _ = released.recv_timeout(Duration::from_secs(3));
            Ok(())
        });
        ready
            .recv_timeout(Duration::from_secs(2))
            .map_err(io::Error::other)?;
        let deadline = Instant::now() + Duration::from_millis(30);
        let began = Instant::now();
        let failed = guard.release(deadline).is_err();
        let elapsed = began.elapsed();
        let repeated = guard
            .release(Instant::now() + Duration::from_secs(2))
            .is_err();
        let frozen = guard.cleanup_deadline == Some(deadline);
        let retained_before_unlock = read_cross_process_gate_state(&path)?.active.len();
        let signaled_before_unlock = guard.quarantine.check().is_err();
        let _ = release.send(());
        holder
            .join()
            .map_err(|_| io::Error::other("native mutex holder panic"))??;
        drop(guard);
        let same = WindowsSandboxCrossProcessGate::acquire(&key);
        let changed = WindowsSandboxCrossProcessGate::acquire(&WindowsSandboxPolicyCohortKey {
            policy_hash: "policy-b".into(),
            ..key
        });
        let refused =
            same.as_ref().is_err_and(cleanup_failed) && changed.as_ref().is_err_and(cleanup_failed);
        drop(same);
        drop(changed);
        let retained_after_drop = read_cross_process_gate_state(&path)?.active.len();
        // Release only the named signal and state created by this fixture.
        let signal = {
            let mut registry = retained_quarantine_signals()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let index = registry
                .iter()
                .position(|signal| signal.name == signal_name)
                .ok_or_else(|| io::Error::other("fixture signal missing"))?;
            registry.swap_remove(index)
        };
        let reset = unsafe {
            windows_sys::Win32::System::Threading::ResetEvent(signal.handle.as_raw_handle().cast())
        };
        fs::remove_file(path)?;
        assert!(failed && repeated && frozen);
        assert!(
            elapsed < Duration::from_millis(500),
            "release cannot wait the former fixed second"
        );
        assert_eq!(retained_before_unlock, 1);
        assert_eq!(retained_after_drop, 1);
        assert!(signaled_before_unlock && refused);
        assert_ne!(reset, 0);
        Ok(())
    }

    #[test]
    fn confirmed_reservation_release_finishes_after_execution_deadline() -> io::Result<()> {
        use std::time::{Duration, Instant};
        let tmp = TempDir::new()?;
        let key = WindowsSandboxPolicyCohortKey {
            binding_key: format!("confirmed-release-fixture:{}", tmp.path().display()),
            policy_hash: "policy-a".into(),
        };
        let guard = WindowsSandboxCrossProcessGate::acquire(&key)?;
        let path = guard.state_path.clone();
        let began = Instant::now();
        guard.finish_after_execution_cleanup(Instant::now() - Duration::from_millis(1))?;
        let elapsed = began.elapsed();
        let released = read_cross_process_gate_state(&path)?.active.is_empty();
        fs::remove_file(path)?;
        assert!(released, "confirmed cleanup must release its reservation");
        assert!(
            elapsed < Duration::from_secs(2),
            "available reservation metadata should release promptly"
        );
        Ok(())
    }

    #[test]
    fn explicit_reservation_release_removes_only_its_entry_and_drop_does_not_revisit_state()
    -> io::Result<()> {
        let tmp = TempDir::new()?;
        let key = WindowsSandboxPolicyCohortKey {
            binding_key: format!("release-owner-fixture:{}", tmp.path().display()),
            policy_hash: "policy-a".into(),
        };
        let mut own = WindowsSandboxCrossProcessGate::acquire(&key)?;
        let peer = WindowsSandboxCrossProcessGate::acquire(&key)?;
        let path = own.state_path.clone();
        own.release(std::time::Instant::now() + std::time::Duration::from_secs(2))?;
        let state = read_cross_process_gate_state(&path)?;
        let peer_preserved = state.active.len() == 1 && state.active[0].token == peer.token;
        // A completed owner cannot revisit or recreate its metadata in Drop.
        let absent = tmp.path().join("absent-parent").join("state.json");
        own.state_path = absent.clone();
        drop(own);
        let signal_clean = peer.quarantine.check().is_ok();
        drop(peer);
        let empty = read_cross_process_gate_state(&path)?.active.is_empty();
        fs::remove_file(path)?;
        assert!(peer_preserved && signal_clean && empty);
        assert!(!absent.exists());
        Ok(())
    }

    #[test]
    fn failed_quarantine_marker_write_cannot_release_or_readmit_the_binding() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let key = WindowsSandboxPolicyCohortKey {
            binding_key: format!("marker-failure-fixture:{}", tmp.path().display()),
            policy_hash: "policy-a".into(),
        };
        let mut guard = WindowsSandboxCrossProcessGate::acquire(&key)?;
        let signal_name = guard.quarantine.name.clone();
        let original_path = guard.state_path.clone();
        // Inject a real filesystem creation failure without changing directory
        // permissions or damaging any actual backend binding's metadata.
        guard.state_path = tmp.path().join("absent-parent").join("state.json");
        let failure = guard.mark_cleanup_failed();
        guard.state_path = original_path.clone();
        drop(guard);
        let retained = read_cross_process_gate_state(&original_path)?.active.len();
        let same = WindowsSandboxCrossProcessGate::acquire(&key);
        let changed = WindowsSandboxCrossProcessGate::acquire(&WindowsSandboxPolicyCohortKey {
            policy_hash: "policy-b".into(),
            ..key
        });
        let refused =
            same.as_ref().is_err_and(cleanup_failed) && changed.as_ref().is_err_and(cleanup_failed);
        drop(same);
        drop(changed);
        let peer = std::process::Command::new("python").args(["-u", "-c", "import ctypes,sys; k=ctypes.WinDLL('kernel32',use_last_error=True); k.OpenEventW.restype=ctypes.c_void_p; k.OpenEventW.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.c_wchar_p]; k.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_uint]; k.CloseHandle.argtypes=[ctypes.c_void_p]; h=k.OpenEventW(0x100000,False,sys.argv[1]); assert h; assert k.WaitForSingleObject(h,0)==0; k.CloseHandle(h); print('SIGNALED')"]).arg(&signal_name).output()?;
        let peer_observed = peer.status.success() && peer.stdout == b"SIGNALED\r\n";
        // Only this fixture's native signal and fake binding are released.
        // No actual execution, identity, or backend state is repaired here.
        let signal = {
            let mut registry = retained_quarantine_signals()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let index = registry
                .iter()
                .position(|signal| signal.name == signal_name)
                .ok_or_else(|| io::Error::other("fixture quarantine owner missing"))?;
            registry.swap_remove(index)
        };
        use std::os::windows::io::AsRawHandle;
        let reset = unsafe {
            windows_sys::Win32::System::Threading::ResetEvent(signal.handle.as_raw_handle().cast())
        };
        fs::remove_file(original_path)?;
        assert!(
            failure.is_err(),
            "marker write must fail on the real filesystem"
        );
        assert_eq!(
            retained, 1,
            "failed cleanup must retain its unverified reservation"
        );
        assert!(
            refused,
            "both policies must remain closed despite marker write failure"
        );
        assert!(
            peer_observed,
            "a real peer must observe quarantine after the guard is dropped"
        );
        assert_ne!(reset, 0);
        Ok(())
    }

    #[test]
    fn reused_pid_identity_cannot_admit_or_release_an_unverified_reservation() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let key = WindowsSandboxPolicyCohortKey {
            binding_key: format!("identity-fixture:{}", tmp.path().display()),
            policy_hash: "policy-a".into(),
        };
        let guard = WindowsSandboxCrossProcessGate::acquire(&key)?;
        let path = guard.state_path.clone();
        {
            let _mutex = WindowsSandboxNamedMutexGuard::acquire(&guard.mutex_name)?;
            let mut state = read_cross_process_gate_state(&path)?;
            // The native PID is live, but it is not the process incarnation
            // recorded by this reservation. Also exercise exact-token release.
            let other = WindowsSandboxCrossProcessGateEntry {
                pid: std::process::id(),
                process_creation_time: guard.process_creation_time + 1,
                token: guard.token.clone(),
                policy_hash: guard.policy_hash.clone(),
                runtime_roots: None,
            };
            assert!(!reservation_owner_is_live(&other)?);
            state.active.push(other);
            write_cross_process_gate_state(&path, &state)?;
        }
        drop(guard);
        let before = fs::read(&path)?;
        let retained = read_cross_process_gate_state(&path)?;
        let original = WindowsSandboxCrossProcessGate::acquire(&key);
        let changed = WindowsSandboxCrossProcessGate::acquire(&WindowsSandboxPolicyCohortKey {
            policy_hash: "policy-b".into(),
            ..key
        });
        let refused = original.as_ref().is_err_and(cleanup_failed)
            && changed.as_ref().is_err_and(cleanup_failed);
        drop(original);
        drop(changed);
        let unchanged = fs::read(&path)? == before;
        fs::remove_file(path)?;
        assert_eq!(retained.active.len(), 1);
        assert!(refused, "PID reuse cannot acknowledge cleanup");
        assert!(unchanged, "unverified identity must remain reserved");
        Ok(())
    }

    #[test]
    fn dead_host_reservation_survives_peer_release_while_its_descendant_is_live() -> io::Result<()>
    {
        use std::io::{BufRead, BufReader};
        use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle};
        use std::process::{Child, Command, Stdio};
        use windows_sys::Win32::System::Threading::{PROCESS_TERMINATE, TerminateProcess};
        struct Peer(Child);
        impl Drop for Peer {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        struct Descendant(OwnedHandle);
        impl Drop for Descendant {
            fn drop(&mut self) {
                unsafe {
                    TerminateProcess(self.0.as_raw_handle().cast(), 1);
                    WaitForSingleObject(self.0.as_raw_handle().cast(), 5000);
                }
            }
        }
        let tmp = TempDir::new()?;
        let heartbeat = tmp.path().join("heartbeat");
        let binding_key = format!("orphan-fixture:{}", tmp.path().display());
        let key = WindowsSandboxPolicyCohortKey {
            binding_key,
            policy_hash: "policy-a".into(),
        };
        let own_guard = WindowsSandboxCrossProcessGate::acquire(&key)?;
        let state_path = own_guard.state_path.clone();
        let mut peer = Peer(Command::new("python").args(["-u", "-c",
            "import subprocess,sys,os; script='import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); n=0\\nwhile True:\\n p.write_text(str(n)); n+=1; time.sleep(0.02)'; child=subprocess.Popen([sys.executable,'-u','-c',script,sys.argv[1]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); os.write(1,('READY '+str(child.pid)+'\\n').encode()); sys.stdin.buffer.read(1)"])
            .arg(&heartbeat).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?);
        let output = peer
            .0
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("peer output"))?;
        let output = unsafe { fs::File::from_raw_handle(output.into_raw_handle()) };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while codex_windows_sandbox::available_pipe_bytes(&output)?.is_none_or(|n| n < 6) {
            if peer.0.try_wait()?.is_some() || std::time::Instant::now() >= deadline {
                return Err(io::Error::other("peer readiness"));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let mut line = String::new();
        BufReader::new(output).read_line(&mut line)?;
        let pid: u32 = line
            .trim()
            .strip_prefix("READY ")
            .ok_or_else(|| io::Error::other("descendant readiness"))?
            .parse()
            .map_err(io::Error::other)?;
        let handle = unsafe { OpenProcess(0x0010_0000 | PROCESS_TERMINATE, 0, pid) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let descendant = Descendant(unsafe { OwnedHandle::from_raw_handle(handle.cast()) });
        while !heartbeat.exists() {
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::other("descendant heartbeat"));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let peer_pid = peer.0.id();
        let peer_creation_time = process_creation_time(peer.0.as_raw_handle().cast())?;
        {
            let _mutex = WindowsSandboxNamedMutexGuard::acquire(&own_guard.mutex_name)?;
            let mut state = read_cross_process_gate_state(&state_path)?;
            state.active.push(WindowsSandboxCrossProcessGateEntry {
                pid: peer_pid,
                process_creation_time: peer_creation_time,
                token: "owned-peer-reservation".into(),
                policy_hash: key.policy_hash.clone(),
                runtime_roots: None,
            });
            write_cross_process_gate_state(&state_path, &state)?;
        }
        peer.0.kill()?;
        peer.0.wait()?;
        assert!(!reservation_owner_is_live(
            &WindowsSandboxCrossProcessGateEntry {
                pid: peer_pid,
                process_creation_time: peer_creation_time,
                token: "owned-peer-reservation".into(),
                policy_hash: key.policy_hash.clone(),
                runtime_roots: None,
            }
        )?);
        let before = fs::read(&heartbeat)?;
        drop(own_guard);
        let retained = fs::read(&state_path)?;
        let same = WindowsSandboxCrossProcessGate::acquire(&key);
        let different = WindowsSandboxCrossProcessGate::acquire(&WindowsSandboxPolicyCohortKey {
            policy_hash: "policy-b".into(),
            ..key
        });
        let same_refused = same.as_ref().is_err_and(cleanup_failed);
        let different_refused = different.as_ref().is_err_and(cleanup_failed);
        drop(same);
        drop(different);
        let unchanged = fs::read(&state_path)? == retained;
        let retained_state = parse_cross_process_gate_state(
            std::str::from_utf8(&retained).map_err(io::Error::other)?,
        )?;
        let orphan_retained =
            retained_state.active.len() == 1 && retained_state.active[0].pid == peer_pid;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while fs::read(&heartbeat)? == before && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let child_progress = fs::read(&heartbeat)? != before;
        let child_live =
            unsafe { WaitForSingleObject(descendant.0.as_raw_handle().cast(), 0) } == 258;
        drop(descendant);
        fs::remove_file(state_path)?;
        assert!(
            orphan_retained,
            "healthy peer release must preserve a dead host's reservation"
        );
        assert!(
            same_refused && different_refused,
            "host death cannot prove cleanup for either policy"
        );
        assert!(
            unchanged,
            "refused admission must not erase the unverified reservation"
        );
        assert!(
            child_live && child_progress,
            "a real descendant must survive its host through refusal"
        );
        Ok(())
    }

    #[test]
    fn held_native_global_mutex_refuses_admission_before_peer_releases_it() -> io::Result<()> {
        use std::io::{BufRead, BufReader, Write};
        use std::os::windows::io::{FromRawHandle, IntoRawHandle};
        use std::process::{Child, Command, Stdio};
        struct Peer(Child);
        impl Drop for Peer {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let tmp = TempDir::new()?;
        let binding_key = format!("fixture:{}", tmp.path().display());
        let name = cross_process_gate_mutex_name(&binding_key);
        let mut peer = Peer(Command::new("python").args(["-u","-c","import ctypes,sys,os; k=ctypes.WinDLL('kernel32',use_last_error=True); k.CreateMutexW.restype=ctypes.c_void_p; k.CreateMutexW.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_wchar_p]; k.ReleaseMutex.argtypes=[ctypes.c_void_p]; k.CloseHandle.argtypes=[ctypes.c_void_p]; handle=k.CreateMutexW(None,True,sys.argv[1]); assert handle; os.write(1,b'READY\\n'); assert sys.stdin.buffer.read(1)==b'R'; assert k.ReleaseMutex(handle); k.CloseHandle(handle)", &name])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?);
        let output = peer
            .0
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("mutex peer output unavailable"))?;
        let output = unsafe { fs::File::from_raw_handle(output.into_raw_handle()) };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if codex_windows_sandbox::available_pipe_bytes(&output)?
                .is_some_and(|available| available >= 6)
            {
                break;
            }
            if peer.0.try_wait()?.is_some() || std::time::Instant::now() >= deadline {
                return Err(io::Error::other("mutex peer readiness failed"));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let mut output = BufReader::new(output);
        let mut line = String::new();
        output.read_line(&mut line)?;
        assert_eq!(line.trim(), "READY");
        let key = WindowsSandboxPolicyCohortKey {
            binding_key,
            policy_hash: "policy".into(),
        };
        let (sender, receiver) = std::sync::mpsc::channel();
        let pending_key = key.clone();
        let worker = std::thread::spawn(move || {
            let _ = sender.send(WindowsSandboxCrossProcessGate::acquire(&pending_key));
        });
        let observed = receiver.recv_timeout(std::time::Duration::from_secs(2));
        let refused_before_release = matches!(&observed, Ok(Err(_)));
        let holder_alive = peer.0.try_wait()?.is_none();
        let state_path = cross_process_gate_state_path(&key.binding_key)?;
        let no_admission = !state_path.exists();
        peer.0
            .stdin
            .as_mut()
            .ok_or_else(|| io::Error::other("mutex peer input unavailable"))?
            .write_all(b"R")?;
        assert!(peer.0.wait()?.success());
        worker
            .join()
            .map_err(|_| io::Error::other("mutex reservation worker failed"))?;
        drop(observed);
        drop(receiver);
        let guard = WindowsSandboxCrossProcessGate::acquire(&key)?;
        drop(guard);
        fs::remove_file(state_path)?;
        assert!(
            refused_before_release,
            "mutex wait must reject before the holder is released"
        );
        assert!(holder_alive, "holder must remain alive during refusal");
        assert!(
            no_admission,
            "failed reservation must not record an active execution"
        );
        Ok(())
    }

    #[test]
    fn cleanup_failure_marker_blocks_reuse_after_original_owner_releases_gate() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let sandbox_home = tmp.path().join("sandbox");
        let key = WindowsSandboxPolicyCohortKey {
            policy_hash: "hash-a".to_string(),
            binding_key: normalize_lexical(&sandbox_home)
                .to_string_lossy()
                .into_owned(),
        };
        let guard = WindowsSandboxCrossProcessGate::acquire(&key)?;
        let state_path = guard.state_path.clone();
        let marker = state_path.with_extension("cleanup-failed");
        fs::write(&marker, b"cleanup_failed")?;
        drop(guard);
        let error = WindowsSandboxCrossProcessGate::acquire(&key)
            .expect_err("unverified cleanup must block the same policy too");
        assert!(cleanup_failed(&error));
        let other = WindowsSandboxPolicyCohortKey {
            policy_hash: "hash-b".to_string(),
            ..key
        };
        assert!(cleanup_failed(
            &WindowsSandboxCrossProcessGate::acquire(&other)
                .expect_err("different policy cannot reuse unverified state")
        ));
        fs::remove_file(marker)?;
        fs::remove_file(state_path)?;
        Ok(())
    }

    #[test]
    fn cross_process_gate_allows_same_policy_and_rejects_mixed_policy() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let sandbox_home = tmp.path().join("sandbox");
        let policy_a = WindowsSandboxPolicyCohortKey {
            policy_hash: "hash-a".to_string(),
            binding_key: normalize_lexical(&sandbox_home)
                .to_string_lossy()
                .into_owned(),
        };
        let policy_b = WindowsSandboxPolicyCohortKey {
            policy_hash: "hash-b".to_string(),
            binding_key: policy_a.binding_key.clone(),
        };

        let guard = WindowsSandboxCrossProcessGate::acquire(&policy_a)?;
        let same_policy_guard = WindowsSandboxCrossProcessGate::acquire(&policy_a)?;
        drop(same_policy_guard);

        let err = WindowsSandboxCrossProcessGate::acquire(&policy_b)
            .expect_err("mixed-policy execution must be rejected");
        assert_eq!(
            policy_transition_busy_reason(&err),
            Some(POLICY_TRANSITION_BUSY_REASON)
        );

        drop(guard);
        let next_policy_guard = WindowsSandboxCrossProcessGate::acquire(&policy_b)?;
        drop(next_policy_guard);
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod release_worker_tests {
    use super::*;
    use crate::execution::retained;
    use std::io::Write;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType, ReadFile};
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        FlsAlloc, FlsFree, FlsSetValue, GetCurrentProcess, GetCurrentThread, ResetEvent,
    };

    #[derive(Default)]
    struct NativeGate {
        entered: AtomicBool,
        release: AtomicBool,
        target_started: AtomicBool,
        worker: Mutex<Option<(OwnedHandle, std::thread::ThreadId)>>,
    }
    unsafe extern "system" fn hold_exit(value: *const std::ffi::c_void) {
        let gate = unsafe { Arc::from_raw(value.cast::<NativeGate>()) };
        gate.entered.store(true, Ordering::Release);
        while !gate.release.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    struct Fixture {
        gate: Arc<NativeGate>,
        writer: Option<fs::File>,
        slot: Option<u32>,
        stop: Option<mpsc::Sender<()>>,
        watchdog: Option<std::thread::JoinHandle<()>>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            self.gate.release.store(true, Ordering::Release);
            if let Some(mut writer) = self.writer.take() {
                let _ = writer.write_all(b"R");
            }
            if let Some((handle, id)) = self
                .gate
                .worker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
            {
                let ended =
                    unsafe { WaitForSingleObject(handle.as_raw_handle(), 2000) } == WAIT_OBJECT_0;
                if ended {
                    retained::join_finished(*id);
                }
            }
            if let Some(watchdog) = self.watchdog.take() {
                let _ = watchdog.join();
            }
            if let Some(slot) = self.slot.take() {
                unsafe {
                    FlsFree(slot);
                }
            }
        }
    }

    #[test]
    fn owned_policy_release_preserves_native_worker_and_fail_closed_admission_until_exit()
    -> anyhow::Result<()> {
        for exit_callback in [true, false] {
            let tmp = tempfile::TempDir::new()?;
            let key = WindowsSandboxPolicyCohortKey {
                binding_key: format!("owned-release-fixture:{}", tmp.path().display()),
                policy_hash: "policy-a".into(),
            };
            let mut guard = WindowsSandboxCrossProcessGate::acquire(&key)?;
            let state_path = guard.state_path.clone();
            let mutex_name = guard.mutex_name.clone();
            let signal = guard.quarantine.clone();
            let original = fs::read(&state_path)?;
            let gate = Arc::new(NativeGate::default());
            let slot = if exit_callback {
                let slot = unsafe { FlsAlloc(Some(hold_exit)) };
                anyhow::ensure!(slot != u32::MAX, "native exit slot");
                Some(slot)
            } else {
                None
            };
            let (reader, writer) = if exit_callback {
                (None, None)
            } else {
                let mut reader = std::ptr::null_mut();
                let mut writer = std::ptr::null_mut();
                anyhow::ensure!(
                    unsafe { CreatePipe(&mut reader, &mut writer, std::ptr::null_mut(), 4096) }
                        != 0,
                    "native release pipe"
                );
                (
                    Some(unsafe { fs::File::from_raw_handle(reader) }),
                    Some(unsafe { fs::File::from_raw_handle(writer) }),
                )
            };
            let raw_reader = reader.as_ref().map(AsRawHandle::as_raw_handle);
            let safety_gate = gate.clone();
            let safety_writer = writer.as_ref().map(fs::File::try_clone).transpose()?;
            let (stop, stopped) = mpsc::channel();
            let watchdog = std::thread::spawn(move || {
                if matches!(
                    stopped.recv_timeout(Duration::from_secs(3)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    safety_gate.release.store(true, Ordering::Release);
                    if let Some(mut writer) = safety_writer {
                        let _ = writer.write_all(b"R");
                    }
                }
            });
            let fixture = Fixture {
                gate: gate.clone(),
                writer,
                slot,
                stop: Some(stop),
                watchdog: Some(watchdog),
            };
            let worker_gate = gate.clone();
            let deadline = Instant::now() + Duration::from_millis(100);
            // A later caller deadline must not renew this reservation's clock.
            guard.cleanup_deadline = Some(deadline);
            let result = guard.finish_owned_with(deadline + Duration::from_secs(10), move || {
                let mut thread = std::ptr::null_mut();
                let copied = unsafe {
                    DuplicateHandle(
                        GetCurrentProcess(),
                        GetCurrentThread(),
                        GetCurrentProcess(),
                        &mut thread,
                        0,
                        0,
                        DUPLICATE_SAME_ACCESS,
                    )
                };
                if copied != 0 {
                    *worker_gate
                        .worker
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((
                        unsafe { OwnedHandle::from_raw_handle(thread) },
                        std::thread::current().id(),
                    ));
                }
                if let Some(slot) = slot {
                    let raw = Arc::into_raw(worker_gate.clone());
                    if unsafe { FlsSetValue(slot, raw.cast()) } == 0 {
                        unsafe {
                            drop(Arc::from_raw(raw));
                        }
                    }
                } else if let Some(reader) = reader {
                    worker_gate.entered.store(true, Ordering::Release);
                    let mut byte = 0u8;
                    let mut read = 0;
                    unsafe {
                        ReadFile(
                            reader.as_raw_handle(),
                            &mut byte,
                            1,
                            &mut read,
                            std::ptr::null_mut(),
                        );
                    }
                }
            });
            let (pending, owned, id) = {
                let observed = gate
                    .worker
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let (handle, id) = observed
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("native worker observation"))?;
                (
                    unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) } == WAIT_TIMEOUT,
                    retained::contains(*id),
                    *id,
                )
            };
            let pipe_owned = exit_callback
                || raw_reader
                    .is_some_and(|handle| unsafe { GetFileType(handle) } == FILE_TYPE_PIPE);
            let before_release = !gate.release.load(Ordering::Acquire);
            let entered = gate.entered.load(Ordering::Acquire);
            let unchanged = fs::read(&state_path)? == original;
            let mutex_still_owned = exit_callback
                || WindowsSandboxNamedMutexGuard::acquire_until(
                    &mutex_name,
                    Instant::now() + Duration::from_millis(20),
                )
                .is_err();
            let original_denied = WindowsSandboxCrossProcessGate::acquire(&key)
                .is_err_and(|error| cleanup_failed(&error));
            let changed_denied =
                WindowsSandboxCrossProcessGate::acquire(&WindowsSandboxPolicyCohortKey {
                    policy_hash: "policy-b".into(),
                    ..key.clone()
                })
                .is_err_and(|error| cleanup_failed(&error));
            drop(fixture);
            let gone = {
                let observed = gate
                    .worker
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                observed.as_ref().is_some_and(|(handle,_)| unsafe { WaitForSingleObject(handle.as_raw_handle(),0) } == WAIT_OBJECT_0)
            };
            let late_unchanged = fs::read(&state_path)? == original;
            // Remove only this fixture's metadata and native signal after worker exit.
            let reset = unsafe { ResetEvent(signal.handle.as_raw_handle()) };
            retained_quarantine_signals()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retain(|value| value.name != signal.name);
            fs::remove_file(&state_path)?;
            anyhow::ensure!(
                result.is_err_and(|error| cleanup_failed(&error)),
                "unverified worker must fail cleanup"
            );
            assert!(pending && owned && pipe_owned && entered && before_release);
            assert!(mutex_still_owned && original_denied && changed_denied);
            assert!(gone && !retained::contains(id));
            assert_ne!(reset, 0);
            if !exit_callback {
                assert!(
                    unchanged && late_unchanged,
                    "expired state read cannot publish a late release"
                );
            }
        }
        Ok(())
    }
    struct ReleaseObserver {
        reservation: Option<WindowsSandboxCrossProcessGate>,
        hook: Option<Box<dyn FnOnce() + Send>>,
        control: crate::execution::ExecutionControl,
        gate: Arc<NativeGate>,
        cwd: PathBuf,
        target: Option<OwnedHandle>,
        terminal_pending: bool,
        target_exited: bool,
        terminal_durable: bool,
        events: Vec<Value>,
    }
    impl crate::execution::ExecutionObserver for ReleaseObserver {
        fn event(&mut self, event: &Value) -> Result<(), crate::error::RunSealError> {
            use windows_sys::Win32::System::Threading::{
                GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_SYNCHRONIZE,
            };
            let pid_path = self.cwd.join("target.pid");
            if self.target.is_none() && pid_path.exists() {
                let pid = fs::read_to_string(&pid_path)
                    .ok()
                    .and_then(|text| text.parse::<u32>().ok())
                    .unwrap_or(0);
                let handle = unsafe {
                    OpenProcess(
                        PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                        0,
                        pid,
                    )
                };
                if !handle.is_null() {
                    self.target = Some(unsafe { OwnedHandle::from_raw_handle(handle) });
                    self.gate.target_started.store(true, Ordering::Release);
                    fs::write(self.cwd.join("release"), b"R").map_err(|_| {
                        crate::error::RunSealError::new("INTERNAL_ERROR", "target release")
                    })?;
                }
            }
            if matches!(
                event["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            ) {
                self.terminal_pending = self.gate.entered.load(Ordering::Acquire)
                    && self.gate.worker.lock().unwrap_or_else(std::sync::PoisonError::into_inner).as_ref().is_some_and(|(handle,_)| unsafe { WaitForSingleObject(handle.as_raw_handle(),0) } == WAIT_TIMEOUT);
                self.target_exited = self.target.as_ref().is_some_and(|handle| {
                    let mut code = 0;
                    (unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) } == WAIT_OBJECT_0)
                        && unsafe { GetExitCodeProcess(handle.as_raw_handle(), &mut code) } != 0
                        && code == 7
                });
                self.terminal_durable = event["audit_path"]
                    .as_str()
                    .and_then(|path| fs::read_to_string(self.cwd.join(path)).ok())
                    .and_then(|text| {
                        text.lines()
                            .last()
                            .and_then(|line| serde_json::from_str::<Value>(line).ok())
                    })
                    .as_ref()
                    == Some(event);
            }
            self.events.push(event.clone());
            Ok(())
        }
        fn cleanup(
            &mut self,
            deadline: Instant,
            confirmed: bool,
        ) -> Result<(), crate::error::RunSealError> {
            let Some(mut guard) = self.reservation.take() else {
                return Ok(());
            };
            if !confirmed {
                let _ = guard.mark_quarantined();
                return Err(crate::error::RunSealError::new(
                    "EXECUTION_CLEANUP_FAILED",
                    "unconfirmed execution cleanup",
                ));
            }
            let deadline = deadline.min(Instant::now() + Duration::from_millis(100));
            self.control.adopt_cleanup_deadline(deadline);
            guard.cleanup_deadline = Some(deadline);
            let hook = self
                .hook
                .take()
                .ok_or_else(|| crate::error::RunSealError::new("INTERNAL_ERROR", "release hook"))?;
            guard
                .finish_owned_with(deadline + Duration::from_secs(10), hook)
                .map_err(|_| {
                    crate::error::RunSealError::new(
                        "EXECUTION_CLEANUP_FAILED",
                        "execution policy cleanup could not be verified",
                    )
                })
        }
    }

    #[test]
    fn native_policy_release_failure_commits_after_real_exit_before_worker_exit()
    -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let key = WindowsSandboxPolicyCohortKey {
            binding_key: format!("release-terminal-fixture:{}", tmp.path().display()),
            policy_hash: "policy-a".into(),
        };
        let guard = WindowsSandboxCrossProcessGate::acquire(&key)?;
        let state_path = guard.state_path.clone();
        let signal = guard.quarantine.clone();
        let gate = Arc::new(NativeGate::default());
        let slot = unsafe { FlsAlloc(Some(hold_exit)) };
        anyhow::ensure!(slot != u32::MAX, "native exit slot");
        let safety_gate = gate.clone();
        let (stop, stopped) = mpsc::channel();
        let watchdog = std::thread::spawn(move || {
            let startup_deadline = Instant::now() + Duration::from_secs(15);
            while !safety_gate.target_started.load(Ordering::Acquire) {
                if Instant::now() >= startup_deadline {
                    safety_gate.release.store(true, Ordering::Release);
                    return;
                }
                match stopped.recv_timeout(Duration::from_millis(50)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
            if matches!(
                stopped.recv_timeout(Duration::from_secs(3)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                safety_gate.release.store(true, Ordering::Release);
            }
        });
        let fixture = Fixture {
            gate: gate.clone(),
            writer: None,
            slot: Some(slot),
            stop: Some(stop),
            watchdog: Some(watchdog),
        };
        let worker_gate = gate.clone();
        let hook = Box::new(move || {
            let mut thread = std::ptr::null_mut();
            if unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    GetCurrentThread(),
                    GetCurrentProcess(),
                    &mut thread,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            } != 0
            {
                *worker_gate
                    .worker
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((
                    unsafe { OwnedHandle::from_raw_handle(thread) },
                    std::thread::current().id(),
                ));
            }
            let raw = Arc::into_raw(worker_gate);
            if unsafe { FlsSetValue(slot, raw.cast()) } == 0 {
                unsafe {
                    drop(Arc::from_raw(raw));
                }
            }
        });
        let control = crate::execution::ExecutionControl::default();
        let request=crate::execution::ExecutionRequest {
            ids:crate::events::new_execution_ids(),control:control.clone(),
            command:vec!["python".into(),"-u".into(),"-c".into(),"import os,pathlib,sys,time; p=pathlib.Path('target.pid'); t=p.with_suffix('.tmp'); t.write_text(str(os.getpid())); t.replace(p); print('READY',flush=True); deadline=time.monotonic()+5\nwhile not pathlib.Path('release').exists() and time.monotonic()<deadline: time.sleep(.01)\nsys.exit(7)".into()],
            cwd:tmp.path().to_owned(),policy:crate::policy::normalize_policy(&json!("danger-full-access"),tmp.path(),None).map_err(|error|anyhow::anyhow!(error.reason))?,
            stdin:crate::backend::ExecutionStdin::Empty,control_input:None,io:crate::backend::ExecutionIo::Pipe,env:crate::backend::ExecutionEnv::default(),metadata:None,timeout:Some(Duration::from_secs(30)),
        };
        let mut observer = ReleaseObserver {
            reservation: Some(guard),
            hook: Some(hook),
            control,
            gate: gate.clone(),
            cwd: tmp.path().to_owned(),
            target: None,
            terminal_pending: false,
            target_exited: false,
            terminal_durable: false,
            events: Vec::new(),
        };
        let result = crate::execution::execute_command_with_observer(request, &mut observer);
        let pending = observer.terminal_pending;
        let exited = observer.target_exited;
        let durable = observer.terminal_durable;
        let terminal = observer
            .events
            .iter()
            .find(|event| {
                matches!(
                    event["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                )
            })
            .cloned();
        let denied = WindowsSandboxCrossProcessGate::acquire(&key)
            .is_err_and(|error| cleanup_failed(&error));
        let worker_id = gate
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|(_, id)| *id);
        drop(fixture);
        let reset = unsafe { ResetEvent(signal.handle.as_raw_handle()) };
        retained_quarantine_signals()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|value| value.name != signal.name);
        fs::remove_file(state_path)?;
        assert!(pending && exited && durable && denied);
        assert!(worker_id.is_some_and(|id| !retained::contains(id)));
        assert_ne!(reset, 0);
        assert!(result.is_err_and(|error| error.code == "EXECUTION_CLEANUP_FAILED"));
        let terminal = terminal.ok_or_else(|| anyhow::anyhow!("terminal"))?;
        assert_eq!(terminal["result"]["cleanup_complete"], false);
        assert_eq!(terminal["result"]["exit_code"], 7);
        assert_eq!(terminal["result"]["requested_termination_reason"], "exited");
        assert_eq!(
            observer
                .events
                .iter()
                .filter(|event| matches!(
                    event["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                ))
                .count(),
            1
        );
        Ok(())
    }
    struct StateReaderFixture {
        gate: Arc<NativeGate>,
        server: Arc<Mutex<Option<fs::File>>>,
        server_worker: Option<std::thread::JoinHandle<()>>,
        stop: Option<mpsc::Sender<()>>,
        watchdog: Option<std::thread::JoinHandle<()>>,
    }
    impl Drop for StateReaderFixture {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            self.gate.release.store(true, Ordering::Release);
            self.server
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(worker) = self.server_worker.take() {
                unsafe {
                    windows_sys::Win32::System::IO::CancelSynchronousIo(worker.as_raw_handle());
                }
                let ended =
                    unsafe { WaitForSingleObject(worker.as_raw_handle(), 2000) } == WAIT_OBJECT_0;
                if ended {
                    let _ = worker.join();
                } else {
                    retained::retain(worker);
                }
            }
            if let Some((handle, id)) = self
                .gate
                .worker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                && unsafe { WaitForSingleObject(handle.as_raw_handle(), 2000) } == WAIT_OBJECT_0
            {
                retained::join_finished(*id);
            }
            if let Some(watchdog) = self.watchdog.take() {
                let _ = watchdog.join();
            }
        }
    }

    #[test]
    fn production_state_file_read_stall_retains_native_mutex_and_worker_before_server_eof()
    -> anyhow::Result<()> {
        use windows_sys::Win32::Foundation::{ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
        };
        let tmp = tempfile::TempDir::new()?;
        let key = WindowsSandboxPolicyCohortKey {
            binding_key: format!("state-reader-fixture:{}", tmp.path().display()),
            policy_hash: "policy-a".into(),
        };
        let mut guard = WindowsSandboxCrossProcessGate::acquire(&key)?;
        let original_path = guard.state_path.clone();
        let original = fs::read(&original_path)?;
        let signal = guard.quarantine.clone();
        let mutex_name = guard.mutex_name.clone();
        let pipe_name = format!(
            r"\\.\pipe\RunSealStateRead-{}",
            crate::events::new_execution_ids().execution_id
        );
        let name = to_wide(OsStr::new(&pipe_name));
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                0x0000_0002,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                std::ptr::null_mut(),
            )
        };
        anyhow::ensure!(handle != INVALID_HANDLE_VALUE, "state read native pipe");
        let server_file = unsafe { fs::File::from_raw_handle(handle) };
        let server = Arc::new(Mutex::new(None));
        let server_state = server.clone();
        let connected = Arc::new(AtomicBool::new(false));
        let server_connected = connected.clone();
        let bytes = original.clone();
        let server_worker = std::thread::spawn(move || {
            let mut file = server_file;
            let connected = unsafe { ConnectNamedPipe(file.as_raw_handle(), std::ptr::null_mut()) }
                != 0
                || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
            if connected && file.write_all(&bytes).is_ok() {
                *server_state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(file);
                server_connected.store(true, Ordering::Release);
            }
        });
        let mut native_server_thread = std::ptr::null_mut();
        let copied = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                server_worker.as_raw_handle(),
                GetCurrentProcess(),
                &mut native_server_thread,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        anyhow::ensure!(copied != 0, "server native observation");
        let native_server_thread = unsafe { OwnedHandle::from_raw_handle(native_server_thread) };
        let gate = Arc::new(NativeGate::default());
        let safety_gate = gate.clone();
        let safety_server = server.clone();
        let (stop, stopped) = mpsc::channel();
        let watchdog = std::thread::spawn(move || {
            if matches!(
                stopped.recv_timeout(Duration::from_secs(3)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                safety_gate.release.store(true, Ordering::Release);
                safety_server
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                unsafe {
                    windows_sys::Win32::System::IO::CancelSynchronousIo(
                        native_server_thread.as_raw_handle(),
                    );
                }
            }
        });
        let fixture = StateReaderFixture {
            gate: gate.clone(),
            server: server.clone(),
            server_worker: Some(server_worker),
            stop: Some(stop),
            watchdog: Some(watchdog),
        };
        guard.state_path = PathBuf::from(pipe_name);
        let deadline = Instant::now() + Duration::from_millis(100);
        guard.cleanup_deadline = Some(deadline);
        let worker_gate = gate.clone();
        let result = guard.finish_owned_with(deadline + Duration::from_secs(10), move || {
            let mut thread = std::ptr::null_mut();
            if unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    GetCurrentThread(),
                    GetCurrentProcess(),
                    &mut thread,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            } != 0
            {
                *worker_gate
                    .worker
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((
                    unsafe { OwnedHandle::from_raw_handle(thread) },
                    std::thread::current().id(),
                ));
            }
            worker_gate.entered.store(true, Ordering::Release);
            // The hook observes ownership only. Production fs::read_to_string
            // opens this named pipe and blocks waiting for the server's EOF.
        });
        let (pending, owned, id) = {
            let worker = gate
                .worker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (handle, id) = worker
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("native state reader observation"))?;
            (
                unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) } == WAIT_TIMEOUT,
                retained::contains(*id),
                *id,
            )
        };
        let real_connection = connected.load(Ordering::Acquire);
        let server_owned = server
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_some_and(|file| unsafe { GetFileType(file.as_raw_handle()) } == FILE_TYPE_PIPE);
        let before_eof = !gate.release.load(Ordering::Acquire);
        let mutex_owned = WindowsSandboxNamedMutexGuard::acquire_until(
            &mutex_name,
            Instant::now() + Duration::from_millis(20),
        )
        .is_err();
        let original_denied = WindowsSandboxCrossProcessGate::acquire(&key)
            .is_err_and(|error| cleanup_failed(&error));
        let changed_denied =
            WindowsSandboxCrossProcessGate::acquire(&WindowsSandboxPolicyCohortKey {
                policy_hash: "policy-b".into(),
                ..key
            })
            .is_err_and(|error| cleanup_failed(&error));
        let unchanged = fs::read(&original_path)? == original;
        drop(fixture);
        let native_gone=gate.worker.lock().unwrap_or_else(std::sync::PoisonError::into_inner).as_ref().is_some_and(|(handle,_)|unsafe {WaitForSingleObject(handle.as_raw_handle(),0)}==WAIT_OBJECT_0);
        let reset = unsafe { ResetEvent(signal.handle.as_raw_handle()) };
        retained_quarantine_signals()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|value| value.name != signal.name);
        fs::remove_file(original_path)?;
        assert!(result.is_err_and(|error| cleanup_failed(&error)));
        assert!(
            real_connection
                && server_owned
                && before_eof
                && pending
                && owned
                && mutex_owned
                && unchanged
        );
        assert!(original_denied && changed_denied);
        assert!(native_gone && !retained::contains(id));
        assert_ne!(reset, 0);
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod execution_gate_repair_tests {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use tempfile::TempDir;

    fn spawn_and_exit_dead_owner() -> io::Result<(u32, u64)> {
        let mut peer = std::process::Command::new("python")
            .args(["-c", "import time; time.sleep(30)"])
            .spawn()?;
        let pid = peer.id();
        let creation = process_creation_time(peer.as_raw_handle().cast())?;
        peer.kill()?;
        peer.wait()?;
        Ok((pid, creation))
    }

    fn inject_dead_reservation(
        key: &WindowsSandboxPolicyCohortKey,
        fixture: &WindowsSandboxCrossProcessGate,
        runtime_roots: Option<Vec<String>>,
    ) -> io::Result<(u32, std::path::PathBuf)> {
        let (pid, creation) = spawn_and_exit_dead_owner()?;
        let marker_path = fixture.state_path.with_extension("cleanup-failed");
        fixture.quarantine.signal()?;
        fs::write(&marker_path, b"cleanup_failed")?;
        let _mutex = WindowsSandboxNamedMutexGuard::acquire(&fixture.mutex_name)?;
        let state = WindowsSandboxCrossProcessGateState {
            active: vec![WindowsSandboxCrossProcessGateEntry {
                pid,
                process_creation_time: creation,
                token: "dead-host-reservation".into(),
                policy_hash: key.policy_hash.clone(),
                runtime_roots,
            }],
        };
        write_cross_process_gate_state(&fixture.state_path, &state)?;
        Ok((pid, marker_path))
    }

    fn repair_with_no_sandbox_processes(
        binding_key: &str,
        accept_unverified_release: bool,
    ) -> io::Result<ExecutionGateRepair> {
        repair_execution_gate_for_binding_with_process_probe(
            binding_key,
            accept_unverified_release,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
            || Ok((Vec::new(), 0)),
        )
    }

    #[test]
    fn execution_gate_repair_refuses_while_a_recorded_owner_is_live() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let key = WindowsSandboxPolicyCohortKey {
            binding_key: format!("repair-live-owner-fixture:{}", tmp.path().display()),
            policy_hash: "policy-a".into(),
        };
        let guard = WindowsSandboxCrossProcessGate::acquire(&key)?;
        let state_path = guard.state_path.clone();
        let before = fs::read(&state_path)?;
        let failed = repair_with_no_sandbox_processes(&key.binding_key, false)
            .is_err_and(|error| cleanup_failed(&error));
        let unchanged = fs::read(&state_path)? == before;
        drop(guard);
        fs::remove_file(&state_path)?;
        assert!(failed, "a live owner must refuse the repair");
        assert!(unchanged, "a refused repair must not modify any state");
        Ok(())
    }

    #[test]
    fn execution_gate_repair_refuses_while_process_probe_finds_live_processes() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let key = WindowsSandboxPolicyCohortKey {
            binding_key: format!("repair-live-process-fixture:{}", tmp.path().display()),
            policy_hash: "policy-a".into(),
        };
        let fixture = WindowsSandboxCrossProcessGate::acquire(&key)?;
        let state_path = fixture.state_path.clone();
        let (_, marker_path) = inject_dead_reservation(&key, &fixture, Some(Vec::new()))?;
        drop(fixture);
        let before = fs::read(&state_path)?;
        let failed = repair_execution_gate_for_binding_with_process_probe(
            &key.binding_key,
            false,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
            || Ok((vec![42], 0)),
        )
        .is_err_and(|error| cleanup_failed(&error));
        let unchanged = fs::read(&state_path)? == before;
        fs::remove_file(&state_path)?;
        let _ = fs::remove_file(marker_path);
        assert!(failed, "a live sandbox process must refuse the repair");
        assert!(unchanged, "a refused repair must preserve the binding");
        Ok(())
    }

    #[test]
    fn execution_gate_repair_clears_a_provably_dead_reservation_and_quarantine() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let key = WindowsSandboxPolicyCohortKey {
            binding_key: format!("repair-stale-fixture:{}", tmp.path().display()),
            policy_hash: "policy-a".into(),
        };
        let fixture = WindowsSandboxCrossProcessGate::acquire(&key)?;
        let state_path = fixture.state_path.clone();
        let (_, marker_path) = inject_dead_reservation(&key, &fixture, Some(Vec::new()))?;
        drop(fixture);
        let report = repair_with_no_sandbox_processes(&key.binding_key, true)?;
        let empty = read_cross_process_gate_state(&state_path)?
            .active
            .is_empty();
        let marker_gone = !marker_path.exists();
        let readmitted = WindowsSandboxCrossProcessGate::acquire(&key);
        let readmitted = readmitted.is_ok();
        fs::remove_file(&state_path)?;
        assert!(
            report.repaired,
            "a provably dead reservation must be repaired"
        );
        assert_eq!(report.cleared_executions, 1);
        assert!(report.cleared_cleanup_failed_marker);
        assert!(report.cleared_quarantine);
        assert_eq!(report.removed_runtime_roots, 0);
        assert!(!report.unverified_runtime_roots);
        assert!(
            empty && marker_gone,
            "repair must clear the poisoned binding"
        );
        assert!(readmitted, "the binding must be admissible after repair");
        Ok(())
    }

    #[test]
    fn execution_gate_repair_requires_acceptance_for_unrecorded_runtime_roots() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let key = WindowsSandboxPolicyCohortKey {
            binding_key: format!("repair-unrecorded-roots-fixture:{}", tmp.path().display()),
            policy_hash: "policy-a".into(),
        };
        let fixture = WindowsSandboxCrossProcessGate::acquire(&key)?;
        let state_path = fixture.state_path.clone();
        inject_dead_reservation(&key, &fixture, None)?;
        drop(fixture);
        let refused = repair_with_no_sandbox_processes(&key.binding_key, false)
            .is_err_and(|error| cleanup_failed(&error));
        let accepted = repair_with_no_sandbox_processes(&key.binding_key, true);
        let unverified = accepted
            .as_ref()
            .is_ok_and(|report| report.unverified_runtime_roots);
        drop(accepted);
        fs::remove_file(&state_path)?;
        assert!(
            refused,
            "unrecorded runtime roots must refuse the default repair"
        );
        assert!(
            unverified,
            "explicit acceptance must record the unverified roots"
        );
        Ok(())
    }
}
