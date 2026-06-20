use crate::error::RunSealError;
use crate::execution::ExecutionCancellation;
use serde_json::Value;
use std::sync::mpsc::Sender;

use super::event_bus::EventBus;
use super::executions::ExecutionStore;
use super::sessions::SessionStore;

#[derive(Default)]
pub(super) struct ServiceState {
    executions: ExecutionStore,
    event_bus: EventBus,
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
        let execution_id = result
            .get("execution_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        if let Some(session_id) = self.executions.record_finished(result, events) {
            self.sessions.record(session_id);
        }
        if let Some(execution_id) = execution_id {
            self.event_bus.clear_execution(&execution_id);
        }
    }

    pub(super) fn record_failed_execution(
        &mut self,
        err: &RunSealError,
        active_execution_id: Option<&str>,
    ) {
        let execution_id = err
            .details
            .as_ref()
            .and_then(|details| details.get("execution_id"))
            .and_then(Value::as_str)
            .or(active_execution_id)
            .map(str::to_string);
        if let Some(session_id) = self.executions.record_failed(err, active_execution_id) {
            self.sessions.record(session_id);
        }
        if let Some(execution_id) = execution_id {
            self.event_bus.clear_execution(&execution_id);
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

    pub(super) fn subscribe_execution_events(
        &mut self,
        execution_id: &str,
        types: Vec<String>,
        sender: Option<Sender<Vec<Value>>>,
    ) -> Option<Vec<Value>> {
        let events = self.executions.events(execution_id, &types)?;
        if let Some(sender) = sender
            && self.executions.is_active(execution_id)
        {
            self.event_bus
                .subscribe(execution_id.to_string(), types, sender);
        }
        Some(events)
    }

    pub(super) fn audit_tail(&self, types: &[String]) -> Vec<Value> {
        self.executions.all_events(types)
    }

    pub(super) fn record_execution_event(&mut self, execution_id: &str, event: &Value) {
        self.executions.record_active_event(execution_id, event);
        self.event_bus.publish(event);
    }

    pub(super) fn dispose_session(&mut self, session_id: &str) -> (bool, usize) {
        let released_session = self.sessions.dispose(session_id);
        let released_executions = if released_session {
            self.executions.cancel_active_in_session(session_id)
        } else {
            0
        };
        (released_session, released_executions)
    }

    pub(super) fn cancel_active_execution(&mut self, execution_id: &str) -> Option<Value> {
        self.executions.cancel_active(execution_id)
    }

    pub(super) fn cancel_all_active_executions(&mut self) -> usize {
        let cancelled = self.executions.cancel_all_active();
        self.event_bus.clear();
        cancelled
    }
}
