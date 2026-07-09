use super::*;
#[cfg(windows)]
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CreateMutexW, INFINITE, OpenProcess, ReleaseMutex, WaitForSingleObject,
};

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct WindowsSandboxPolicyCohortKey {
    pub(super) policy_hash: String,
    pub(super) workspace_key: String,
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
    sandbox_home: &Path,
) -> io::Result<WindowsSandboxExecutionGate> {
    let key = WindowsSandboxPolicyCohortKey {
        policy_hash: plan.policy_hash.clone(),
        workspace_key: normalize_lexical(sandbox_home)
            .to_string_lossy()
            .into_owned(),
    };
    let in_process = windows_sandbox_execution_gate_for_key(key.clone())?;
    let cross_process = WindowsSandboxCrossProcessGate::acquire(&key, sandbox_home)?;
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
    state_path: PathBuf,
    mutex_name: String,
}

#[cfg(windows)]
#[derive(Default)]
struct WindowsSandboxCrossProcessGateState {
    active: Vec<WindowsSandboxCrossProcessGateEntry>,
}

#[cfg(windows)]
struct WindowsSandboxCrossProcessGateEntry {
    pid: u32,
    token: String,
    policy_hash: String,
}

#[cfg(windows)]
struct WindowsSandboxNamedMutexGuard {
    handle: HANDLE,
}

#[cfg(windows)]
impl WindowsSandboxCrossProcessGate {
    fn acquire(
        key: &WindowsSandboxPolicyCohortKey,
        sandbox_home: &Path,
    ) -> io::Result<WindowsSandboxCrossProcessGate> {
        let state_path = cross_process_gate_state_path(sandbox_home)?;
        let mutex_name = cross_process_gate_mutex_name(&key.workspace_key);
        let _mutex = WindowsSandboxNamedMutexGuard::acquire(&mutex_name)?;
        let mut state = read_cross_process_gate_state(&state_path)?;
        state.active.retain(|entry| process_is_running(entry.pid));
        if state
            .active
            .iter()
            .any(|entry| entry.policy_hash != key.policy_hash)
        {
            write_cross_process_gate_state(&state_path, &state)?;
            return Err(io::Error::other(PolicyTransitionBusyError {
                reason: POLICY_TRANSITION_BUSY_REASON,
            }));
        }

        let token = cross_process_gate_token();
        state.active.push(WindowsSandboxCrossProcessGateEntry {
            pid: std::process::id(),
            token: token.clone(),
            policy_hash: key.policy_hash.clone(),
        });
        write_cross_process_gate_state(&state_path, &state)?;
        Ok(WindowsSandboxCrossProcessGate {
            token,
            policy_hash: key.policy_hash.clone(),
            state_path,
            mutex_name,
        })
    }
}

#[cfg(windows)]
impl Drop for WindowsSandboxCrossProcessGate {
    fn drop(&mut self) {
        let Ok(_mutex) = WindowsSandboxNamedMutexGuard::acquire(&self.mutex_name) else {
            return;
        };
        let Ok(mut state) = read_cross_process_gate_state(&self.state_path) else {
            return;
        };
        state.active.retain(|entry| {
            !(entry.pid == std::process::id()
                && entry.token == self.token
                && entry.policy_hash == self.policy_hash)
                && process_is_running(entry.pid)
        });
        let _ = write_cross_process_gate_state(&self.state_path, &state);
    }
}

#[cfg(windows)]
impl WindowsSandboxNamedMutexGuard {
    fn acquire(name: &str) -> io::Result<WindowsSandboxNamedMutexGuard> {
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
        let wait = unsafe { WaitForSingleObject(handle, INFINITE) };
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
fn cross_process_gate_state_path(sandbox_home: &Path) -> io::Result<PathBuf> {
    let state_dir = cross_process_gate_state_dir();
    fs::create_dir_all(&state_dir)?;
    let digest = Sha256::digest(normalize_lexical(sandbox_home).to_string_lossy().as_bytes());
    Ok(state_dir.join(format!("{digest:x}.json")))
}

#[cfg(windows)]
fn cross_process_gate_state_dir() -> PathBuf {
    if let Some(appdata) = std::env::var_os("APPDATA") {
        return PathBuf::from(appdata)
            .join("RunSeal")
            .join("execution-gates");
    }
    std::env::temp_dir().join("RunSeal").join("execution-gates")
}

#[cfg(windows)]
fn cross_process_gate_mutex_name(workspace_key: &str) -> String {
    let digest = Sha256::digest(workspace_key.as_bytes());
    format!("Local\\RunSealExecutionGate-{digest:x}")
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
                "token": entry.token,
                "policy_hash": entry.policy_hash,
            })
        })
        .collect::<Vec<_>>();
    fs::write(path, json!({ "active": active }).to_string())
}

#[cfg(windows)]
fn process_is_running(pid: u32) -> bool {
    if pid == std::process::id() {
        return true;
    }
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const WAIT_TIMEOUT: u32 = 0x102;
    let handle = unsafe { OpenProcess(SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        return false;
    }
    let wait = unsafe { WaitForSingleObject(handle, 0) };
    unsafe {
        CloseHandle(handle);
    }
    wait == WAIT_TIMEOUT
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
            let policy_hash = entry
                .get("policy_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    io::Error::other("execution gate entry policy_hash must be a string")
                })?
                .to_string();
            Ok(WindowsSandboxCrossProcessGateEntry {
                pid,
                token,
                policy_hash,
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
    fn cross_process_gate_allows_same_policy_and_rejects_mixed_policy() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let sandbox_home = tmp.path().join("sandbox");
        let policy_a = WindowsSandboxPolicyCohortKey {
            policy_hash: "hash-a".to_string(),
            workspace_key: normalize_lexical(&sandbox_home)
                .to_string_lossy()
                .into_owned(),
        };
        let policy_b = WindowsSandboxPolicyCohortKey {
            policy_hash: "hash-b".to_string(),
            workspace_key: policy_a.workspace_key.clone(),
        };

        let guard = WindowsSandboxCrossProcessGate::acquire(&policy_a, &sandbox_home)?;
        let same_policy_guard = WindowsSandboxCrossProcessGate::acquire(&policy_a, &sandbox_home)?;
        drop(same_policy_guard);

        let err = WindowsSandboxCrossProcessGate::acquire(&policy_b, &sandbox_home)
            .expect_err("mixed-policy execution must be rejected");
        assert_eq!(
            policy_transition_busy_reason(&err),
            Some(POLICY_TRANSITION_BUSY_REASON)
        );

        drop(guard);
        let next_policy_guard = WindowsSandboxCrossProcessGate::acquire(&policy_b, &sandbox_home)?;
        drop(next_policy_guard);
        Ok(())
    }
}
