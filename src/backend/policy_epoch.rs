use super::*;

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct WindowsSandboxPolicyCohortKey {
    pub(super) policy_hash: String,
}

#[cfg(windows)]
pub(super) struct WindowsSandboxExecutionGate;

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
) -> io::Result<WindowsSandboxExecutionGate> {
    windows_sandbox_execution_gate_for_key(WindowsSandboxPolicyCohortKey {
        policy_hash: plan.policy_hash.clone(),
    })
}

#[cfg(windows)]
pub(super) fn windows_sandbox_execution_gate_for_key(
    key: WindowsSandboxPolicyCohortKey,
) -> io::Result<WindowsSandboxExecutionGate> {
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
    Ok(WindowsSandboxExecutionGate)
}

#[cfg(windows)]
impl Drop for WindowsSandboxExecutionGate {
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
