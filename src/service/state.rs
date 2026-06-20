use crate::error::RunSealError;
use crate::execution::ExecutionCancellation;
use serde_json::Value;

use super::executions::ExecutionStore;
use super::sessions::SessionStore;

#[derive(Default)]
pub(super) struct ServiceState {
    executions: ExecutionStore,
    sessions: SessionStore,
}

impl ServiceState {
    pub(super) fn record_running_execution(
        &mut self,
        result: Value,
        cancellation: ExecutionCancellation,
    ) {
        if let Some(session_id) = self.executions.record_running(result, cancellation) {
            self.sessions.record(session_id);
        }
    }

    pub(super) fn record_finished_execution(&mut self, result: &Value, events: &[Value]) {
        if let Some(session_id) = self.executions.record_finished(result, events) {
            self.sessions.record(session_id);
        }
    }

    pub(super) fn record_failed_execution(&mut self, err: &RunSealError) {
        if let Some(session_id) = self.executions.record_failed(err) {
            self.sessions.record(session_id);
        }
    }

    pub(super) fn execution_result(&self, execution_id: &str) -> Option<Value> {
        self.executions.result(execution_id)
    }

    pub(super) fn execution_summaries(&self) -> Vec<Value> {
        self.executions.summaries()
    }

    pub(super) fn execution_events(
        &self,
        execution_id: &str,
        types: &[String],
    ) -> Option<Vec<Value>> {
        self.executions.events(execution_id, types)
    }

    pub(super) fn audit_tail(&self, types: &[String]) -> Vec<Value> {
        self.executions.all_events(types)
    }

    pub(super) fn record_execution_event(&mut self, execution_id: &str, event: &Value) {
        self.executions.record_active_event(execution_id, event);
    }

    pub(super) fn dispose_session(&mut self, session_id: &str) -> bool {
        self.sessions.dispose(session_id)
    }

    pub(super) fn cancel_active_execution(&mut self, execution_id: &str) -> Option<Value> {
        self.executions.cancel_active(execution_id)
    }
}
