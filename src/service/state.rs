use serde_json::Value;

use super::executions::ExecutionStore;
use super::sessions::SessionStore;

#[derive(Default)]
pub(super) struct ServiceState {
    executions: ExecutionStore,
    sessions: SessionStore,
}

impl ServiceState {
    pub(super) fn truncated(&self) -> bool {
        self.executions.truncated()
    }
    pub(super) fn record_finished_execution(&mut self, result: &Value) {
        if let Some(session_id) = self.executions.record_finished(result) {
            self.sessions.record(session_id);
        }
    }

    pub(super) fn execution_result(&self, execution_id: &str) -> Option<Value> {
        self.executions.result(execution_id)
    }

    pub(super) fn execution_status(&self, execution_id: &str) -> Option<&str> {
        self.executions.status(execution_id)
    }

    pub(super) fn execution_summaries(&self) -> Vec<Value> {
        self.executions.summaries()
    }

    pub(super) fn execution_ids_for_session(&self, session_id: &str) -> Vec<String> {
        self.executions.ids_for_session(session_id)
    }

    pub(super) fn dispose_session(&mut self, session_id: &str) {
        self.sessions.dispose(session_id);
    }
}
