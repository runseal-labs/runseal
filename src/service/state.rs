use crate::error::RunSealError;
use serde_json::Value;

use super::executions::ExecutionStore;
use super::sessions::SessionStore;

#[derive(Default)]
pub(super) struct ServiceState {
    executions: ExecutionStore,
    sessions: SessionStore,
}

impl ServiceState {
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

    pub(super) fn has_execution(&self, execution_id: &str) -> bool {
        self.executions.contains(execution_id)
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

    pub(super) fn audit_events(&self, execution_id: &str, types: &[String]) -> Option<Vec<Value>> {
        self.executions.audit_events(execution_id, types)
    }

    pub(super) fn audit_tail(&self, types: &[String]) -> Vec<Value> {
        self.executions.all_events(types)
    }

    pub(super) fn dispose_session(&mut self, session_id: &str) -> usize {
        if self.sessions.dispose(session_id) {
            self.executions.remove_session(session_id)
        } else {
            0
        }
    }
}
