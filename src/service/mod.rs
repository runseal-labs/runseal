use crate::backend::SandboxBackend;
use crate::backend::{ExecutionInput, ExecutionStdin};
use crate::commands;
use crate::error::RunSealError;
use crate::execution::ExecutionControl;
use crate::protocol::request_validation::execution_input_from_params;
use crate::protocol::request_validation::unsubscribe_execution_id_from_params;
use crate::protocol::request_validation::{
    audit_events_params, cancel_execution_id_from_params, execution_request_from_params,
    explain_policy_from_params, get_execution_id_from_params, session_id_from_params,
    setup_status_cwd_from_params, subscribe_events_params, tail_audit_params,
    validate_empty_params,
};
use crate::rpc;
use serde_json::{Value, json};
use state::ServiceState;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, Ordering},
};

pub(crate) enum LifecycleMessage {
    Event(Value),
    TerminalRange {
        event: Value,
        reply: SyncSender<u64>,
    },
    Complete {
        execution_id: String,
        outcome: Result<(Vec<Value>, Value), RunSealError>,
    },
}

struct ActiveExecution {
    result: Value,
    control: ExecutionControl,
    sequence: u64,
    stdin: Option<ExecutionInput>,
    control_input: Option<ExecutionInput>,
    audit_metadata: Option<Value>,
}

struct ReservedExecutionObserver<F> {
    events: F,
    reservation: crate::backend::ExecutionReservation,
}

impl<F: FnMut(&Value) -> Result<(), RunSealError>> crate::execution::ExecutionObserver
    for ReservedExecutionObserver<F>
{
    fn event(&mut self, event: &Value) -> Result<(), RunSealError> {
        (self.events)(event)
    }
    fn cleanup(
        &mut self,
        deadline: std::time::Instant,
        execution_cleanup_confirmed: bool,
    ) -> Result<(), RunSealError> {
        self.reservation
            .finish(deadline, execution_cleanup_confirmed)
            .map_err(|_| {
                RunSealError::new(
                    "EXECUTION_CLEANUP_FAILED",
                    "execution admission cleanup could not be verified",
                )
            })
    }
}

struct PendingDisposal {
    id: Value,
    remaining: BTreeSet<String>,
    execution_ids: BTreeSet<String>,
    deadline: std::time::Instant,
    failed: Vec<String>,
    released: usize,
}

struct Subscription {
    types: Vec<String>,
    after_seq: u64,
    valid: Arc<AtomicBool>,
}
struct EventHistory {
    events: Vec<Value>,
    earliest_seq: u64,
    latest_seq: u64,
}

mod admission;
mod audit_index;
mod event_bus;
mod executions;
mod replay_cache;
mod retention;
mod sessions;
mod snapshot;
mod state;

pub(crate) struct Service {
    state: ServiceState,
    mode: ServiceMode,
    active: BTreeMap<String, ActiveExecution>,
    disposals: BTreeMap<String, PendingDisposal>,
    unclean_sessions: BTreeMap<String, BTreeSet<String>>,
    lifecycle_sender: SyncSender<LifecycleMessage>,
    lifecycle_receiver: Receiver<LifecycleMessage>,
    pending_starts: Vec<SyncSender<()>>,
    pending_admissions: Vec<admission::PendingAdmission>,
    workers: Vec<admission::OwnedWorker>,
    admission_cleanup_failed: bool,
    subscriptions: BTreeMap<String, Subscription>,
    notification_guards: BTreeMap<String, Weak<AtomicBool>>,
    delivery_hold: Option<Arc<AtomicBool>>,
    audit_index: audit_index::AuditIndex,
    replay_cache: replay_cache::ReplayCache,
}

#[derive(Clone, Copy, Default)]
enum ServiceMode {
    Direct,
    #[default]
    Service,
}

impl Service {
    pub(crate) fn direct() -> Self {
        Self::new(ServiceMode::Direct)
    }

    pub(crate) fn stateful() -> Self {
        Self::new(ServiceMode::Service)
    }

    fn new(mode: ServiceMode) -> Self {
        let (lifecycle_sender, lifecycle_receiver) = mpsc::sync_channel(16);
        Self {
            state: ServiceState::default(),
            mode,
            active: BTreeMap::new(),
            disposals: BTreeMap::new(),
            unclean_sessions: BTreeMap::new(),
            lifecycle_sender,
            lifecycle_receiver,
            pending_starts: Vec::new(),
            pending_admissions: Vec::new(),
            workers: Vec::new(),
            admission_cleanup_failed: false,
            subscriptions: BTreeMap::new(),
            notification_guards: BTreeMap::new(),
            delivery_hold: None,
            audit_index: audit_index::AuditIndex::default(),
            replay_cache: replay_cache::ReplayCache::default(),
        }
    }

    pub(crate) fn take_admitted_starts(&mut self) -> Vec<SyncSender<()>> {
        self.pending_starts.drain(..).collect()
    }

    pub(crate) fn cancel_owned(&self) {
        self.cancel_owned_for(crate::execution::TerminationCause::ClientDisconnected);
    }
    pub(crate) fn cancel_owned_for(&self, cause: crate::execution::TerminationCause) {
        for active in self.active.values() {
            active.control.request(cause);
        }
        for pending in &self.pending_admissions {
            pending.control.request(cause);
        }
        for worker in &self.workers {
            worker.control.request(cause);
        }
    }

    pub(crate) fn delivery_guard(&self, message: &Value) -> Option<Arc<AtomicBool>> {
        if message["method"] != "event" {
            return None;
        }
        self.notification_guards
            .get(message["params"]["execution_id"].as_str()?)?
            .upgrade()
    }

    fn install_subscription(&mut self, id: String, types: Vec<String>, after_seq: u64) {
        if let Some(previous) = self.notification_guards.get(&id).and_then(Weak::upgrade) {
            previous.store(false, Ordering::Release);
        }
        let valid = Arc::new(AtomicBool::new(true));
        self.notification_guards
            .insert(id.clone(), Arc::downgrade(&valid));
        self.subscriptions.insert(
            id,
            Subscription {
                types,
                after_seq,
                valid,
            },
        );
    }

    pub(crate) fn has_active(&self) -> bool {
        !self.active.is_empty() || !self.pending_admissions.is_empty() || !self.workers.is_empty()
    }

    pub(crate) fn poll_lifecycle(&mut self) -> Vec<Value> {
        self.delivery_hold = None;
        self.notification_guards
            .retain(|_, guard| guard.strong_count() > 0);
        let Ok(message) = self.lifecycle_receiver.try_recv() else {
            return Vec::new();
        };
        match message {
            LifecycleMessage::TerminalRange { event, reply } => {
                let _ = reply.try_send(self.replay_cache.earliest_after(&event));
                Vec::new()
            }
            LifecycleMessage::Event(event) => {
                let Some(execution_id) = event["execution_id"].as_str().map(str::to_owned) else {
                    return Vec::new();
                };
                let Some(active) = self.active.get_mut(&execution_id) else {
                    return Vec::new();
                };
                active.sequence = event["event_seq"].as_u64().unwrap_or(active.sequence);
                let mut audit_event = crate::execution::audit_stream_event_metadata(&event);
                if let Some(metadata) = &active.audit_metadata {
                    audit_event["metadata"] = metadata.clone();
                }
                self.audit_index.record(&audit_event);
                if event["type"] == "execution.started" {
                    active.result["started_at"] = event["time"].clone();
                    if !active.control.is_cancelled() {
                        active.result["status"] = json!("running");
                    }
                }
                self.replay_cache.record(event.clone());
                active.result["latest_seq"] = json!(active.sequence);
                active.result["earliest_available_seq"] =
                    json!(self.replay_cache.earliest(&execution_id, active.sequence));
                self.deliver_event(event)
            }
            LifecycleMessage::Complete {
                execution_id,
                outcome,
            } => {
                let Some(mut active) = self.active.remove(&execution_id) else {
                    return Vec::new();
                };
                // Losing or rejecting a completion cannot release admission.
                // Keep the accepted identity until its terminal proves cleanup.
                let session_id = active.result["session_id"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned();
                self.unclean_sessions
                    .entry(session_id.clone())
                    .or_default()
                    .insert(execution_id.clone());
                let (mut result, terminal) = match outcome {
                    Ok((events, result)) => {
                        let Some(terminal) = events
                            .last()
                            .filter(|event| {
                                matches!(
                                    event["type"].as_str(),
                                    Some("execution.finished" | "execution.failed")
                                )
                            })
                            .cloned()
                        else {
                            return Vec::new();
                        };
                        (result, terminal)
                    }
                    Err(err) => {
                        let Some(terminal) = err.terminal_event else {
                            return Vec::new();
                        };
                        (terminal["result"].clone(), terminal)
                    }
                };
                if terminal["execution_id"] != execution_id
                    || terminal["result"]["execution_id"] != execution_id
                    || terminal["result"]["session_id"] != session_id
                    || result["execution_id"] != execution_id
                    || result["session_id"] != session_id
                    || result["cleanup_complete"] != terminal["result"]["cleanup_complete"]
                    || !matches!(
                        terminal["type"].as_str(),
                        Some("execution.finished" | "execution.failed")
                    )
                    || terminal["event_seq"]
                        .as_u64()
                        .is_none_or(|sequence| sequence <= active.sequence)
                    || !matches!(result["status"].as_str(), Some("finished" | "failed"))
                    || result["status"] != terminal["result"]["status"]
                    || !matches!(
                        (terminal["type"].as_str(), result["status"].as_str()),
                        (Some("execution.finished"), Some("finished"))
                            | (Some("execution.failed"), Some("failed"))
                    )
                    || ["policy_id", "policy_hash", "policy_epoch"]
                        .iter()
                        .any(|key| {
                            terminal[*key] != active.result[*key]
                                || result[*key] != active.result[*key]
                        })
                {
                    return Vec::new();
                }
                if let Some(object) = result.as_object_mut() {
                    object.remove("stdout");
                    object.remove("stderr");
                }
                active.sequence = terminal["event_seq"].as_u64().unwrap_or(active.sequence);
                self.replay_cache.record(terminal.clone());
                let mut audit_terminal = terminal.clone();
                if let Some(metadata) = &active.audit_metadata {
                    audit_terminal["metadata"] = metadata.clone();
                }
                self.audit_index.record(&audit_terminal);
                if matches!(self.mode, ServiceMode::Service) {
                    self.state.record_finished_execution(&result);
                }
                if result["cleanup_complete"] != true
                    || terminal["result"]["cleanup_complete"] != true
                {
                    self.unclean_sessions
                        .entry(session_id.clone())
                        .or_default()
                        .insert(execution_id.clone());
                } else if let Some(unclean) = self.unclean_sessions.get_mut(&session_id) {
                    unclean.remove(&execution_id);
                    if unclean.is_empty() {
                        self.unclean_sessions.remove(&session_id);
                    }
                }
                if let Some(disposal) = self.disposals.get_mut(&session_id)
                    && disposal.remaining.remove(&execution_id)
                {
                    if result["cleanup_complete"] == true {
                        disposal.released += 1;
                    } else {
                        disposal.failed.push(execution_id.clone());
                    }
                }
                let mut messages = self.deliver_event(terminal);
                if self
                    .disposals
                    .get(&session_id)
                    .is_some_and(|disposal| disposal.remaining.is_empty())
                {
                    messages.extend(self.finish_disposal(&session_id));
                }

                self.subscriptions.retain(|id, _| {
                    self.active.contains_key(id) || self.state.execution_status(id).is_some()
                });
                messages
            }
        }
    }

    pub(crate) fn handle_rpc_request(&mut self, request: &Value) -> Vec<Value> {
        let (id, method, params) = match rpc_request_parts(request) {
            Ok(parts) => parts,
            Err(err) => {
                return vec![rpc::invalid_request(request_id_for_error(request), err)];
            }
        };
        let Some(id) = id else {
            return Vec::new();
        };

        match method {
            "getVersion" => match validate_empty_params(&params, "getVersion") {
                Ok(()) => vec![rpc::result(id, commands::version::payload())],
                Err(err) => vec![rpc::error(id, err)],
            },
            "getCapabilities" => match validate_empty_params(&params, "getCapabilities") {
                Ok(()) => vec![rpc::result(id, commands::capabilities::payload())],
                Err(err) => vec![rpc::error(id, err)],
            },
            "getServiceStatus" => match validate_empty_params(&params, "getServiceStatus") {
                Ok(()) => vec![rpc::result(id, self.service_status())],
                Err(err) => vec![rpc::error(id, err)],
            },
            "explainPolicy" => match explain_policy_from_params(&params) {
                Ok(result) => vec![rpc::result(id, result)],
                Err(err) => vec![rpc::error(id, err)],
            },
            "getSetupStatus" => {
                let cwd = match setup_status_cwd_from_params(&params) {
                    Ok(cwd) => cwd,
                    Err(err) => return vec![rpc::error(id, err)],
                };
                match commands::setup::windows_sandbox_setup_status_for_cwd(&cwd) {
                    Ok(result) => vec![rpc::result(id, result)],
                    Err(err) => vec![rpc::error(
                        id,
                        RunSealError::new("SETUP_STATUS_FAILED", err),
                    )],
                }
            }
            "execute" => self.execute(id, &params),
            "getExecution" => self.get_execution(id, &params),
            "listExecutions" => match validate_empty_params(&params, "listExecutions") {
                Ok(()) => vec![self.list_executions(id)],
                Err(err) => vec![rpc::error(id, err)],
            },
            "cancelExecution" => self.cancel_execution(id, &params),
            "resizeExecution" => self.resize_execution(id, &params),
            "signalExecution" => self.signal_execution(id, &params),
            "writeExecutionInput" => self.execution_input(id, &params, true),
            "closeExecutionInput" => self.execution_input(id, &params, false),
            "subscribeEvents" => self.subscribe_events(id, &params),
            "unsubscribeEvents" => self.unsubscribe_events(id, &params),
            "getAuditEvents" => self.get_audit_events(id, &params),
            "tailAudit" => self.tail_audit(id, &params),
            "disposeSession" => self.dispose_session(id, &params),
            _ => vec![rpc::method_not_found(id, method)],
        }
    }

    fn service_status(&self) -> Value {
        let stateful = matches!(self.mode, ServiceMode::Service);
        json!({
            "status": "running",
            "mode": if stateful { "service" } else { "direct" },
            "transport": "stdio",
            "stateful": stateful,
            "local_only": true,
            "remote_listener": false,
        })
    }

    fn execute(&mut self, id: Value, params: &Value) -> Vec<Value> {
        if self.admission_cleanup_failed || !self.unclean_sessions.is_empty() {
            return vec![rpc::error(
                id,
                RunSealError::with_details(
                    "EXECUTION_CLEANUP_FAILED",
                    "unverified execution cleanup prevents admission",
                    json!({"cleanup_complete":false,"execution_ids":self.unclean_sessions.values().flatten().collect::<Vec<_>>()}),
                ),
            )];
        }
        if self.active.len().max(self.workers.len()) + self.pending_admissions.len()
            >= crate::limits::deployment().max_active_executions
        {
            return vec![rpc::error(
                id,
                RunSealError::new(
                    "EXECUTION_LIMIT_EXCEEDED",
                    "active execution limit exceeded",
                ),
            )];
        }
        match admission::spawn(id.clone(), params.clone(), self.lifecycle_sender.clone()) {
            Ok(pending) => {
                self.pending_admissions.push(pending);
                Vec::new()
            }
            Err(error) => vec![rpc::error(id, error)],
        }
    }

    pub(crate) fn poll_admissions(&mut self) -> Vec<Value> {
        use crate::execution::retained;
        let mut responses = Vec::new();
        let mut index = 0;
        while index < self.workers.len() {
            let worker = &self.workers[index];
            if retained::thread_finished(&worker.thread) {
                let worker = self.workers.swap_remove(index);
                if worker.thread.join().is_err() {
                    self.close_unconfirmed_worker(&worker.execution_id);
                }
            } else if worker.control.cleanup_deadline_expired() {
                let worker = self.workers.swap_remove(index);
                self.close_unconfirmed_worker(&worker.execution_id);
                retained::retain(worker.thread);
            } else {
                index += 1;
            }
        }
        let mut index = 0;
        while index < self.pending_admissions.len() {
            let pending = &mut self.pending_admissions[index];
            if pending.rejection.is_none() {
                match pending.receiver.try_recv() {
                    Ok(admission::AdmissionMessage::Ready(ready)) => {
                        if pending.control.is_cancelled()
                            || self.admission_cleanup_failed
                            || !self.unclean_sessions.is_empty()
                        {
                            pending
                                .control
                                .request(crate::execution::TerminationCause::FailedToStart);
                            let error = if self.admission_cleanup_failed
                                || !self.unclean_sessions.is_empty()
                            {
                                RunSealError::with_details(
                                    "EXECUTION_CLEANUP_FAILED",
                                    "unverified execution cleanup prevents admission",
                                    json!({"cleanup_complete":false}),
                                )
                            } else {
                                RunSealError::new(
                                    pending
                                        .control
                                        .cause()
                                        .and_then(crate::execution::TerminationCause::error_code)
                                        .unwrap_or("EXECUTION_CANCELLED"),
                                    "execution admission stopped",
                                )
                            };
                            let _ = pending.accept.try_send(Err(error));
                        } else {
                            let execution_id = ready.active.result["execution_id"]
                                .as_str()
                                .unwrap_or("")
                                .to_owned();
                            let receipt = ready.active.result.clone();
                            pending.control.accept();
                            if pending.accept.try_send(Ok(())).is_err() {
                                pending
                                    .control
                                    .request(crate::execution::TerminationCause::FailedToStart);
                                pending.rejection = Some(RunSealError::with_details(
                                    "EXECUTION_CLEANUP_FAILED",
                                    "execution admission acknowledgment unavailable",
                                    json!({"cleanup_complete":false}),
                                ));
                                continue;
                            }
                            self.active.insert(execution_id.clone(), ready.active);
                            self.install_subscription(execution_id.clone(), Vec::new(), 0);
                            self.pending_starts.push(ready.start);
                            let mut pending = self.pending_admissions.swap_remove(index);
                            if let Some(thread) = pending.worker.take() {
                                self.workers.push(admission::OwnedWorker {
                                    execution_id,
                                    control: pending.control,
                                    thread,
                                });
                            }
                            responses.push(rpc::result(pending.id, receipt));
                            continue;
                        }
                    }
                    Ok(admission::AdmissionMessage::Rejected(error)) => {
                        pending
                            .control
                            .request(crate::execution::TerminationCause::FailedToStart);
                        pending.rejection = Some(error);
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        pending
                            .control
                            .request(crate::execution::TerminationCause::FailedToStart);
                        pending.rejection = Some(RunSealError::with_details(
                            "EXECUTION_CLEANUP_FAILED",
                            "execution admission completion unavailable",
                            json!({"cleanup_complete":false}),
                        ));
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                }
            }
            let ended = pending
                .worker
                .as_ref()
                .is_some_and(retained::thread_finished);
            if pending.control.cleanup_deadline_expired() {
                let mut pending = self.pending_admissions.swap_remove(index);
                self.admission_cleanup_failed = true;
                if let Some(thread) = pending.worker.take() {
                    if retained::thread_finished(&thread) {
                        let _ = thread.join();
                    } else {
                        retained::retain(thread);
                    }
                }
                responses.push(rpc::error(
                    pending.id,
                    RunSealError::with_details(
                        "EXECUTION_CLEANUP_FAILED",
                        "execution admission cleanup could not be verified",
                        json!({"cleanup_complete":false}),
                    ),
                ));
            } else if ended && pending.rejection.is_some() {
                let mut pending = self.pending_admissions.swap_remove(index);
                if let Some(thread) = pending.worker.take() {
                    let _ = thread.join();
                }
                if let Some(error) = pending.rejection.take() {
                    if error.code == "EXECUTION_CLEANUP_FAILED" {
                        self.admission_cleanup_failed = true;
                    }
                    responses.push(rpc::error(pending.id, error));
                }
            } else {
                index += 1;
            }
        }
        responses
    }

    fn close_unconfirmed_worker(&mut self, execution_id: &str) {
        self.admission_cleanup_failed = true;
        if let Some(active) = self.active.remove(execution_id)
            && let Some(session_id) = active.result["session_id"].as_str()
        {
            self.unclean_sessions
                .entry(session_id.to_owned())
                .or_default()
                .insert(execution_id.to_owned());
        }
    }

    fn get_execution(&self, id: Value, params: &Value) -> Vec<Value> {
        let execution_id = match get_execution_id_from_params(params) {
            Ok(execution_id) => execution_id,
            Err(err) => return vec![rpc::error(id, err)],
        };
        match self
            .active
            .get(&execution_id)
            .map(|active| active.result.clone())
            .or_else(|| self.state.execution_result(&execution_id))
        {
            Some(mut result) => {
                let latest = result["latest_seq"].as_u64().unwrap_or(0);
                result["earliest_available_seq"] =
                    json!(self.replay_cache.earliest(&execution_id, latest));
                vec![rpc::result(id, result)]
            }
            None if self
                .unclean_sessions
                .values()
                .any(|ids| ids.contains(&execution_id)) =>
            {
                vec![rpc::error(
                    id,
                    RunSealError::with_details(
                        "EXECUTION_CLEANUP_FAILED",
                        "execution cleanup could not be verified",
                        json!({"execution_id":execution_id,"cleanup_complete":false}),
                    ),
                )]
            }
            None => vec![rpc::error(id, execution_not_found(&execution_id))],
        }
    }

    fn signal_execution(&self, id: Value, params: &Value) -> Vec<Value> {
        let execution_id = match crate::protocol::request_validation::signal_from_params(params) {
            Ok(request) => request,
            Err(error) => return vec![rpc::error(id, error)],
        };
        let Some(active) = self.active.get(&execution_id) else {
            let error = if self.state.execution_status(&execution_id).is_some() {
                RunSealError::new("EXECUTION_NOT_RUNNING", "execution is terminal")
            } else {
                execution_not_found(&execution_id)
            };
            return vec![rpc::error(id, error)];
        };
        if active.control.is_cancelled() || active.control.cause().is_some() {
            return vec![rpc::error(
                id,
                RunSealError::new("EXECUTION_NOT_RUNNING", "execution is stopping"),
            )];
        }
        if active.result["stderr_merged"] != true {
            return vec![rpc::error(
                id,
                RunSealError::with_details(
                    "BACKEND_CAPABILITY_MISSING",
                    "interrupt requires a PTY",
                    json!({"missing_features":["pty_interrupt"]}),
                ),
            )];
        }
        vec![match active.control.interrupt() {
            Ok(()) => rpc::result(
                id,
                json!({"execution_id":execution_id,"accepted":true,"signal":"interrupt"}),
            ),
            Err(error) => rpc::error(
                id,
                RunSealError::new(error.code(), "terminal control queue rejected interrupt"),
            ),
        }]
    }

    fn resize_execution(&self, id: Value, params: &Value) -> Vec<Value> {
        let (execution_id, rows, cols) =
            match crate::protocol::request_validation::resize_from_params(params) {
                Ok(request) => request,
                Err(error) => return vec![rpc::error(id, error)],
            };
        let Some(active) = self.active.get(&execution_id) else {
            let error = if self.state.execution_status(&execution_id).is_some() {
                RunSealError::new("EXECUTION_NOT_RUNNING", "execution is terminal")
            } else {
                execution_not_found(&execution_id)
            };
            return vec![rpc::error(id, error)];
        };
        if active.control.is_cancelled() {
            return vec![rpc::error(
                id,
                RunSealError::new("EXECUTION_NOT_RUNNING", "execution is stopping"),
            )];
        }
        if active.result["stderr_merged"] != true {
            return vec![rpc::error(
                id,
                RunSealError::with_details(
                    "BACKEND_CAPABILITY_MISSING",
                    "resize requires a PTY",
                    json!({"missing_features":["pty_resize"]}),
                ),
            )];
        }
        vec![match active.control.resize(rows, cols) {
            Ok(()) => rpc::result(
                id,
                json!({"execution_id":execution_id,"accepted":true,"rows":rows,"cols":cols}),
            ),
            Err(error) => rpc::error(
                id,
                RunSealError::new(error.code(), "terminal control queue rejected resize"),
            ),
        }]
    }

    fn execution_input(&self, id: Value, params: &Value, write: bool) -> Vec<Value> {
        let request = match execution_input_from_params(params, write) {
            Ok(request) => request,
            Err(err) => return vec![rpc::error(id, err)],
        };
        let Some(active) = self.active.get(&request.execution_id) else {
            let error = if self.state.execution_status(&request.execution_id).is_some() {
                RunSealError::new("EXECUTION_NOT_RUNNING", "execution is terminal")
            } else {
                execution_not_found(&request.execution_id)
            };
            return vec![rpc::error(id, error)];
        };
        if active.control.is_cancelled() {
            return vec![rpc::error(
                id,
                RunSealError::new("EXECUTION_NOT_RUNNING", "execution is stopping"),
            )];
        }
        let queue = if request.control_stream {
            &active.control_input
        } else {
            &active.stdin
        };
        let Some(queue) = queue else {
            return vec![rpc::error(
                id,
                RunSealError::new("INVALID_REQUEST", "execution input stream unavailable"),
            )];
        };
        if active.control.is_cancelled() {
            return vec![rpc::error(
                id,
                RunSealError::new("EXECUTION_NOT_RUNNING", "execution is terminating"),
            )];
        }
        if !request.control_stream
            && request.bytes.is_none()
            && active.result["stderr_merged"] == true
        {
            return vec![rpc::error(
                id,
                RunSealError::with_details(
                    "BACKEND_CAPABILITY_MISSING",
                    "PTY input cannot be closed as a pipe",
                    json!({"missing_features":["pty_eof"]}),
                ),
            )];
        }
        let result = match request.bytes {
            Some(bytes) => queue
                .write(bytes)
                .map(|accepted| json!({"accepted_bytes":accepted})),
            None => queue.close().map(|()| json!({"closed":true})),
        };
        vec![match result {
            Ok(result) => rpc::result(id, result),
            Err(err) => rpc::error(
                id,
                RunSealError::new(err.code(), "execution input request rejected"),
            ),
        }]
    }

    fn list_executions(&self, id: Value) -> Value {
        let mut executions = self.state.execution_summaries();
        executions.extend(self.active.values().map(|active| active.result.clone()));
        for result in &mut executions {
            if let (Some(execution_id), Some(latest)) = (
                result["execution_id"].as_str(),
                result["latest_seq"].as_u64(),
            ) {
                result["earliest_available_seq"] =
                    json!(self.replay_cache.earliest(execution_id, latest));
            }
        }
        snapshot::response(
            id,
            "executions",
            executions,
            json!({}),
            self.state.truncated(),
        )
    }

    fn cancel_execution(&mut self, id: Value, params: &Value) -> Vec<Value> {
        let execution_id = match cancel_execution_id_from_params(params) {
            Ok(execution_id) => execution_id,
            Err(err) => return vec![rpc::error(id, err)],
        };
        if let Some(active) = self.active.get_mut(&execution_id) {
            if active.control.cause() == Some(crate::execution::TerminationCause::Exited) {
                return vec![rpc::error(
                    id,
                    execution_not_cancellable(&execution_id, "finished"),
                )];
            }
            active.control.cancel();
            active.result["status"] = json!("canceling");
            return vec![rpc::result(
                id,
                json!({"execution_id":execution_id,"status":"canceling"}),
            )];
        }
        match self.state.execution_status(&execution_id) {
            Some(status) => vec![rpc::error(
                id,
                execution_not_cancellable(&execution_id, status),
            )],
            None => vec![rpc::error(id, execution_not_found(&execution_id))],
        }
    }

    fn subscribe_events(&mut self, id: Value, params: &Value) -> Vec<Value> {
        let request = match subscribe_events_params(params) {
            Ok(request) => request,
            Err(err) => return vec![rpc::error(id, err)],
        };
        let Some(history) = self.history(&request.execution_id) else {
            return vec![rpc::error(id, execution_not_found(&request.execution_id))];
        };
        if let Some(after) = request.after_seq {
            if after > history.latest_seq {
                return vec![rpc::error(
                    id,
                    RunSealError::new(
                        "INVALID_REQUEST",
                        "params.after_seq exceeds latest event sequence",
                    ),
                )];
            }
            if after.saturating_add(1) < history.earliest_seq {
                return vec![rpc::error(
                    id,
                    RunSealError::with_details(
                        "EVENT_HISTORY_UNAVAILABLE",
                        "requested event history was evicted",
                        json!({"execution_id":request.execution_id,"earliest_available_seq":history.earliest_seq,"latest_seq":history.latest_seq}),
                    ),
                )];
            }
        }
        let replay = request.after_seq.map_or_else(Vec::new, |after| {
            history
                .events
                .into_iter()
                .filter(|event| {
                    event["event_seq"].as_u64().is_some_and(|seq| seq > after)
                        && event_bus::event_matches_types(event, &request.types)
                })
                .collect::<Vec<_>>()
        });
        self.install_subscription(
            request.execution_id.clone(),
            request.types,
            history.latest_seq,
        );
        let mut messages = vec![rpc::result(
            id,
            json!({"execution_id":request.execution_id,"status":"subscribed","event_count":replay.len()}),
        )];
        messages.extend(
            replay
                .into_iter()
                .map(|event| json!({"jsonrpc":"2.0","method":"event","params":event})),
        );
        messages
    }

    fn unsubscribe_events(&mut self, id: Value, params: &Value) -> Vec<Value> {
        let execution_id = match unsubscribe_execution_id_from_params(params) {
            Ok(id) => id,
            Err(err) => return vec![rpc::error(id, err)],
        };
        self.subscriptions.remove(&execution_id);
        if let Some(guard) = self
            .notification_guards
            .get(&execution_id)
            .and_then(Weak::upgrade)
        {
            guard.store(false, Ordering::Release);
        }
        vec![rpc::result(
            id,
            json!({"execution_id":execution_id,"unsubscribed":true}),
        )]
    }

    fn history(&self, execution_id: &str) -> Option<EventHistory> {
        let latest_seq = if let Some(active) = self.active.get(execution_id) {
            active.sequence
        } else {
            self.state.execution_result(execution_id)?["latest_seq"]
                .as_u64()
                .unwrap_or(0)
        };
        let events = self.replay_cache.events(execution_id);
        let earliest_seq = self.replay_cache.earliest(execution_id, latest_seq);
        Some(EventHistory {
            events,
            earliest_seq,
            latest_seq,
        })
    }

    fn deliver_event(&mut self, event: Value) -> Vec<Value> {
        let Some(id) = event["execution_id"].as_str() else {
            return Vec::new();
        };
        let Some(subscription) = self.subscriptions.get_mut(id) else {
            return Vec::new();
        };
        self.delivery_hold = Some(subscription.valid.clone());
        let sequence = event["event_seq"].as_u64().unwrap_or(0);
        if sequence <= subscription.after_seq {
            return Vec::new();
        }
        subscription.after_seq = sequence;
        if !event_bus::event_matches_types(&event, &subscription.types) {
            return Vec::new();
        }
        vec![json!({"jsonrpc":"2.0","method":"event","params":event})]
    }

    fn get_audit_events(&self, id: Value, params: &Value) -> Vec<Value> {
        let (execution_id, types) = match audit_events_params(params) {
            Ok(params) => params,
            Err(err) => return vec![rpc::error(id, err)],
        };
        if !self.active.contains_key(&execution_id)
            && self.state.execution_status(&execution_id).is_none()
        {
            return vec![rpc::error(id, execution_not_found(&execution_id))];
        }
        let latest = self.active.get(&execution_id).map_or_else(
            || {
                self.state
                    .execution_result(&execution_id)
                    .and_then(|result| result["latest_seq"].as_u64())
                    .unwrap_or(0)
            },
            |active| active.sequence,
        );
        let (events, truncated) = self
            .audit_index
            .for_execution(&execution_id, &types, latest);
        vec![snapshot::response(
            id,
            "events",
            events,
            json!({"execution_id":execution_id}),
            truncated,
        )]
    }

    fn tail_audit(&self, id: Value, params: &Value) -> Vec<Value> {
        let types = match tail_audit_params(params) {
            Ok(types) => types,
            Err(err) => return vec![rpc::error(id, err)],
        };
        let (events, truncated) = self.audit_index.tail(&types);
        vec![snapshot::response(
            id,
            "events",
            events,
            json!({}),
            truncated,
        )]
    }

    fn dispose_session(&mut self, id: Value, params: &Value) -> Vec<Value> {
        let session_id = match session_id_from_params(params) {
            Ok(session_id) => session_id,
            Err(err) => return vec![rpc::error(id, err)],
        };
        if self.disposals.contains_key(&session_id) {
            return vec![rpc::error(
                id,
                RunSealError::new("INVALID_REQUEST", "session disposal already pending"),
            )];
        }
        let mut remaining = BTreeSet::new();
        for (execution_id, active) in &mut self.active {
            if active.result["session_id"] == session_id {
                active.control.cancel();
                active.result["status"] = json!("canceling");
                remaining.insert(execution_id.clone());
            }
        }
        let mut execution_ids = remaining.clone();
        execution_ids.extend(self.state.execution_ids_for_session(&session_id));
        let mut failed = self
            .unclean_sessions
            .get(&session_id)
            .cloned()
            .unwrap_or_default();
        execution_ids.extend(failed.iter().cloned());
        failed.extend(
            self.state
                .execution_ids_for_session(&session_id)
                .into_iter()
                .filter(|execution_id| {
                    self.state
                        .execution_result(execution_id)
                        .is_some_and(|result| result["cleanup_complete"] != true)
                }),
        );
        let failed = failed.into_iter().collect();
        self.disposals.insert(
            session_id.clone(),
            PendingDisposal {
                id,
                remaining,
                execution_ids,
                deadline: std::time::Instant::now() + crate::limits::deployment().cleanup_timeout(),
                failed,
                released: 0,
            },
        );
        if self.disposals[&session_id].remaining.is_empty() {
            self.finish_disposal(&session_id)
        } else {
            Vec::new()
        }
    }

    pub(crate) fn poll_disposal_deadlines(&mut self) -> Vec<Value> {
        let expired = self
            .disposals
            .iter()
            .filter(|(_, disposal)| {
                !disposal.remaining.is_empty() && std::time::Instant::now() >= disposal.deadline
            })
            .map(|(session, _)| session.clone())
            .collect::<Vec<_>>();
        let mut messages = Vec::new();
        for session in expired {
            if let Some(disposal) = self.disposals.get_mut(&session) {
                disposal.failed.extend(disposal.remaining.iter().cloned());
                self.unclean_sessions
                    .entry(session.clone())
                    .or_default()
                    .extend(disposal.remaining.iter().cloned());
            }
            messages.extend(self.finish_disposal(&session));
        }
        messages
    }

    fn finish_disposal(&mut self, session_id: &str) -> Vec<Value> {
        let Some(disposal) = self.disposals.remove(session_id) else {
            return Vec::new();
        };
        if !disposal.failed.is_empty() {
            return vec![rpc::error(
                disposal.id,
                RunSealError::with_details(
                    "EXECUTION_CLEANUP_FAILED",
                    "session cleanup could not be verified",
                    json!({"session_id":session_id,"cleanup_complete":false,"execution_ids":disposal.failed}),
                ),
            )];
        }
        for execution_id in disposal.execution_ids {
            self.subscriptions.remove(&execution_id);
            if let Some(guard) = self
                .notification_guards
                .get(&execution_id)
                .and_then(Weak::upgrade)
            {
                guard.store(false, Ordering::Release);
            }
            self.replay_cache.remove_execution(&execution_id);
        }
        self.state.dispose_session(session_id);
        vec![rpc::result(
            disposal.id,
            json!({"session_id":session_id,"status":"disposed","released_executions":disposal.released,"cleanup_complete":true}),
        )]
    }
}

fn execution_not_found(execution_id: &str) -> RunSealError {
    RunSealError::with_details(
        "EXECUTION_NOT_FOUND",
        format!("execution not found: {execution_id}"),
        json!({ "execution_id": execution_id }),
    )
}

fn execution_not_cancellable(execution_id: &str, status: &str) -> RunSealError {
    RunSealError::with_details(
        "EXECUTION_NOT_CANCELLABLE",
        format!("execution is not cancellable: {execution_id}"),
        json!({
            "execution_id": execution_id,
            "status": status,
        }),
    )
}

fn rpc_request_parts(request: &Value) -> Result<(Option<Value>, &str, Value), RunSealError> {
    if request.is_array() {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            "batch requests are not supported",
        ));
    }
    let request = request.as_object().ok_or_else(|| {
        RunSealError::new("INVALID_REQUEST", "JSON-RPC request must be an object")
    })?;
    let id = request.get("id").map(validated_request_id).transpose()?;
    let version = request.get("jsonrpc").and_then(Value::as_str);
    if version != Some("2.0") {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            "request.jsonrpc must be 2.0",
        ));
    }
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RunSealError::new("INVALID_REQUEST", "request.method is required"))?;
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
    Ok((id, method, params))
}

fn request_id_for_error(request: &Value) -> Value {
    request
        .get("id")
        .filter(|value| is_valid_request_id(value))
        .cloned()
        .unwrap_or(Value::Null)
}

fn validated_request_id(value: &Value) -> Result<Value, RunSealError> {
    if is_valid_request_id(value) {
        Ok(value.clone())
    } else {
        Err(RunSealError::new(
            "INVALID_REQUEST",
            "request.id must be a string, number, or null",
        ))
    }
}

fn is_valid_request_id(value: &Value) -> bool {
    value.is_string() || value.is_number() || value.is_null()
}

impl Drop for Service {
    fn drop(&mut self) {
        self.cancel_owned();
        for mut pending in self.pending_admissions.drain(..) {
            if let Some(worker) = pending.worker.take() {
                crate::execution::retained::retain(worker);
            }
        }
        for worker in self.workers.drain(..) {
            crate::execution::retained::retain(worker.thread);
        }
    }
}

#[cfg(test)]
mod disposal_tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn rejected_completion_keeps_native_owner_and_admission_closed_while_peer_controls_continue()
    -> anyhow::Result<()> {
        use anyhow::Context;
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use std::time::{Duration, Instant};
        use windows_sys::Win32::Foundation::{
            DUPLICATE_SAME_ACCESS, DuplicateHandle, WAIT_OBJECT_0, WAIT_TIMEOUT,
        };
        use windows_sys::Win32::System::Threading::{
            FlsAlloc, FlsFree, FlsSetValue, GetCurrentProcess, OpenProcess, PROCESS_SYNCHRONIZE,
            WaitForSingleObject,
        };
        struct Gate {
            entered: mpsc::Sender<()>,
            release: AtomicBool,
        }
        unsafe extern "system" fn hold_exit(value: *const std::ffi::c_void) {
            let gate = unsafe { Arc::from_raw(value.cast::<Gate>()) };
            let _ = gate.entered.send(());
            while !gate.release.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        struct Fixture {
            gate: Arc<Gate>,
            slot: u32,
            thread: OwnedHandle,
            id: std::thread::ThreadId,
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                self.gate.release.store(true, Ordering::Release);
                if unsafe { WaitForSingleObject(self.thread.as_raw_handle(), 2000) }
                    == WAIT_OBJECT_0
                {
                    let _ = crate::execution::retained::join_finished(self.id);
                    unsafe {
                        FlsFree(self.slot);
                    }
                }
            }
        }
        let python = String::from_utf8(
            std::process::Command::new("where.exe")
                .arg("python")
                .output()?
                .stdout,
        )?
        .lines()
        .next()
        .map(str::to_owned)
        .context("Python required")?;
        for direct in [true, false] {
            for fault in [
                "missing_error",
                "empty_success",
                "wrong_session",
                "wrong_execution",
                "conflicting_cleanup",
                "nonterminal_error",
                "stale_terminal",
                "conflicting_status",
                "kind_status_mismatch",
                "wrong_policy",
            ] {
                let tmp = tempfile::TempDir::new()?;
                let mut service = if direct {
                    Service::direct()
                } else {
                    Service::stateful()
                };
                // Start a real peer through ordinary controller admission.
                let mut peer_receipt=service.handle_rpc_request(&json!({"jsonrpc":"2.0","id":1,"method":"execute","params":{
                    "command":[python,"-u","-c","import os,pathlib,sys; p=pathlib.Path('peer.pid'); t=p.with_suffix('.tmp'); t.write_text(str(os.getpid())); t.replace(p); print('READY',flush=True); sys.stdin.buffer.read()"],
                    "cwd":tmp.path(),"policy":"danger-full-access","stdin":{"mode":"stream"}}}));
                let admission_watchdog = Instant::now() + Duration::from_secs(15);
                while peer_receipt.is_empty() {
                    peer_receipt.extend(service.poll_admissions());
                    anyhow::ensure!(
                        Instant::now() < admission_watchdog,
                        "peer admission watchdog"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                let peer = peer_receipt[0]["result"]["execution_id"]
                    .as_str()
                    .context("peer receipt")?
                    .to_owned();
                for start in service.take_admitted_starts() {
                    let _ = start.send(());
                }
                let watchdog = Instant::now() + Duration::from_secs(15);
                let peer_pid = loop {
                    if let Ok(contents) = std::fs::read_to_string(tmp.path().join("peer.pid"))
                        && let Ok(pid) = contents.parse::<u32>()
                    {
                        break pid;
                    }
                    service.poll_admissions();
                    service.poll_lifecycle();
                    anyhow::ensure!(Instant::now() < watchdog, "peer readiness watchdog");
                    std::thread::sleep(Duration::from_millis(5));
                };
                let peer_handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, peer_pid) };
                anyhow::ensure!(!peer_handle.is_null(), "peer native observation");
                let peer_handle = unsafe { OwnedHandle::from_raw_handle(peer_handle) };
                let (entered, ready) = mpsc::channel();
                let gate = Arc::new(Gate {
                    entered,
                    release: AtomicBool::new(false),
                });
                let slot = unsafe { FlsAlloc(Some(hold_exit)) };
                anyhow::ensure!(slot != u32::MAX, "native completion slot");
                let worker_gate = gate.clone();
                let worker_python = python.clone();
                let cwd = tmp.path().to_owned();
                let (returned, body) = mpsc::channel();
                let worker = std::thread::spawn(move || -> std::io::Result<()> {
                    let pointer = Arc::into_raw(worker_gate);
                    if unsafe { FlsSetValue(slot, pointer.cast()) } == 0 {
                        drop(unsafe { Arc::from_raw(pointer) });
                        return Err(std::io::Error::last_os_error());
                    }
                    let status = std::process::Command::new(worker_python)
                        .args(["-c", "import sys; sys.exit(7)"])
                        .current_dir(cwd)
                        .status()?;
                    let _ = returned.send(status.code());
                    Ok(())
                });
                let process = unsafe { GetCurrentProcess() };
                let mut handle = std::ptr::null_mut();
                let duplicated = unsafe {
                    DuplicateHandle(
                        process,
                        worker.as_raw_handle(),
                        process,
                        &mut handle,
                        0,
                        0,
                        DUPLICATE_SAME_ACCESS,
                    )
                } != 0;
                if !duplicated {
                    gate.release.store(true, Ordering::Release);
                    crate::execution::retained::retain(worker);
                    anyhow::bail!("native owner observation");
                }
                let id = worker.thread().id();
                let fixture = Fixture {
                    gate,
                    slot,
                    thread: unsafe { OwnedHandle::from_raw_handle(handle) },
                    id,
                };
                let native_child_exit = body.recv_timeout(Duration::from_secs(3))?;
                ready.recv_timeout(Duration::from_secs(2))?;
                let rust_returned = worker.is_finished();
                crate::execution::retained::retain(worker);
                // Inject only the controller completion-delivery fault. Its
                // accepted record stands for this still-owned native worker;
                // this does not replace the separate engine/backend FLS test.
                service.active.insert("exec_fixture".into(),ActiveExecution {
                    result:json!({"execution_id":"exec_fixture","session_id":"sess_fixture","status":"running",
                        "policy_id":peer_receipt[0]["result"]["policy_id"],"policy_hash":peer_receipt[0]["result"]["policy_hash"],"policy_epoch":peer_receipt[0]["result"]["policy_epoch"]}),
                    control:ExecutionControl::default(),sequence:0,stdin:None,control_input:None,audit_metadata:None,
                });
                let mut result = json!({"execution_id":"exec_fixture","session_id":"sess_fixture","status":"finished","cleanup_complete":true,
                    "policy_id":peer_receipt[0]["result"]["policy_id"],"policy_hash":peer_receipt[0]["result"]["policy_hash"],"policy_epoch":peer_receipt[0]["result"]["policy_epoch"]});
                let outcome = match fault {
                    "missing_error" => Err(RunSealError::new(
                        "EXECUTION_CLEANUP_FAILED",
                        "controlled missing terminal",
                    )),
                    "empty_success" => Ok((Vec::new(), result)),
                    _ => {
                        if fault == "wrong_session" {
                            result["session_id"] = json!("sess_other");
                        }
                        if fault == "wrong_execution" {
                            result["execution_id"] = json!("exec_other");
                        }
                        let mut terminal = json!({"type":"execution.finished","execution_id":"exec_fixture","event_seq":1,
                            "policy_id":result["policy_id"],"policy_hash":result["policy_hash"],"policy_epoch":result["policy_epoch"],"result":result});
                        if fault == "wrong_policy" {
                            terminal["policy_hash"] = json!("sha256:other");
                        }
                        if fault == "conflicting_cleanup" {
                            terminal["result"]["cleanup_complete"] = json!(false);
                        }
                        if fault == "stale_terminal" {
                            terminal["event_seq"] = json!(0);
                        }
                        if fault == "conflicting_status" {
                            terminal["result"]["status"] = json!("failed");
                        }
                        if fault == "kind_status_mismatch" {
                            terminal["type"] = json!("execution.failed");
                        }
                        if fault == "nonterminal_error" {
                            terminal["type"] = json!("execution.stdout");
                            let mut error = RunSealError::new(
                                "EXECUTION_CLEANUP_FAILED",
                                "controlled nonterminal completion",
                            );
                            error.terminal_event = Some(terminal);
                            Err(error)
                        } else {
                            Ok((vec![terminal], result))
                        }
                    }
                };
                service.lifecycle_sender.send(LifecycleMessage::Complete {
                    execution_id: "exec_fixture".into(),
                    outcome,
                })?;
                while service.active.contains_key("exec_fixture") {
                    service.poll_admissions();
                    service.poll_lifecycle();
                }
                // Cache removal and dispose cannot establish native cleanup.
                service.state.dispose_session("sess_fixture");
                let disposal=service.handle_rpc_request(&json!({"jsonrpc":"2.0","id":2,"method":"disposeSession","params":{"session_id":"sess_fixture"}}));
                let request = json!({"jsonrpc":"2.0","id":3,"method":"execute","params":{
                    "command":[python,"-c","import pathlib; pathlib.Path('must-not-run').write_text('ran')"],
                    "cwd":tmp.path(),"policy":"danger-full-access"}});
                let refused = service.handle_rpc_request(&request);
                let version = service
                    .handle_rpc_request(&json!({"jsonrpc":"2.0","id":4,"method":"getVersion"}));
                let unknown = service.handle_rpc_request(&json!({"jsonrpc":"2.0","id":40,"method":"getExecution","params":{"execution_id":"exec_fixture"}}));
                let native_pending =
                    unsafe { WaitForSingleObject(fixture.thread.as_raw_handle(), 0) }
                        == WAIT_TIMEOUT;
                let retained = crate::execution::retained::contains(id);
                let peer_alive =
                    unsafe { WaitForSingleObject(peer_handle.as_raw_handle(), 0) } == WAIT_TIMEOUT;
                // Old implementations may admit the extra finite target.
                // Release it and the peer, then verify before fixture cleanup.
                for start in service.take_admitted_starts() {
                    let _ = start.send(());
                }
                service.handle_rpc_request(&json!({"jsonrpc":"2.0","id":5,"method":"closeExecutionInput","params":{"execution_id":peer,"stream":"stdin"}}));
                let watchdog = Instant::now() + Duration::from_secs(5);
                while service.has_active() && Instant::now() < watchdog {
                    service.poll_admissions();
                    service.poll_lifecycle();
                    std::thread::sleep(Duration::from_millis(5));
                }
                let all_done = !service.has_active();
                let peer_gone =
                    unsafe { WaitForSingleObject(peer_handle.as_raw_handle(), 0) } == WAIT_OBJECT_0;
                let marker_absent = !tmp.path().join("must-not-run").exists();
                let scope_retained = service
                    .unclean_sessions
                    .get("sess_fixture")
                    .is_some_and(|ids| ids.contains("exec_fixture"));
                drop(fixture);
                assert!(all_done && peer_alive && peer_gone);
                assert!(!crate::execution::retained::contains(id));
                assert_eq!(native_child_exit, Some(7));
                assert!(rust_returned && native_pending && retained);
                assert_eq!(
                    refused[0]["error"]["data"]["code"], "EXECUTION_CLEANUP_FAILED",
                    "{fault}"
                );
                assert!(marker_absent && scope_retained);
                assert!(version[0]["result"].is_object());
                assert_eq!(
                    unknown[0]["error"]["data"]["code"],
                    "EXECUTION_CLEANUP_FAILED"
                );
                assert_eq!(unknown[0]["error"]["data"]["cleanup_complete"], false);
                assert_eq!(
                    disposal[0]["error"]["data"]["code"],
                    "EXECUTION_CLEANUP_FAILED"
                );
                assert_eq!(
                    disposal[0]["error"]["data"]["execution_ids"],
                    json!(["exec_fixture"])
                );
            }
        }
        Ok(())
    }

    #[test]
    fn disposal_deadline_keeps_unverified_owner_and_refuses_success() {
        let mut service = Service::direct();
        service.active.insert("exec_example".to_owned(),ActiveExecution {result:json!({"execution_id":"exec_example","session_id":"sess_example","status":"running"}),control:ExecutionControl::default(),sequence:0,stdin:None,control_input:None,audit_metadata:None});
        assert!(service.handle_rpc_request(&json!({"jsonrpc":"2.0","id":2,"method":"disposeSession","params":{"session_id":"sess_example"}})).is_empty());
        assert_eq!(service.active["exec_example"].result["status"], "canceling");
        assert!(service.active["exec_example"].control.is_cancelled());
        if let Some(disposal) = service.disposals.get_mut("sess_example") {
            disposal.deadline = std::time::Instant::now();
        }
        let response = service.poll_disposal_deadlines();
        assert_eq!(
            response[0]["error"]["data"]["code"],
            "EXECUTION_CLEANUP_FAILED"
        );
        assert_eq!(response[0]["error"]["data"]["cleanup_complete"], false);
        assert!(service.has_active(), "deadline cannot release a live owner");
        assert!(service.unclean_sessions.contains_key("sess_example"));
    }

    #[test]
    fn direct_mode_preserves_unclean_scope_after_terminal_index_release() {
        let mut service = Service::direct();
        service.active.insert(
            "exec_example".to_owned(),
            ActiveExecution {
                result: json!({"execution_id":"exec_example","session_id":"sess_example"}),
                control: ExecutionControl::default(),
                sequence: 0,
                stdin: None,
                control_input: None,
                audit_metadata: None,
            },
        );
        let result = json!({"execution_id":"exec_example","session_id":"sess_example","status":"failed","cleanup_complete":false,"latest_seq":1,"error":{"code":"EXECUTION_CLEANUP_FAILED"}});
        let terminal = json!({"type":"execution.failed","execution_id":"exec_example","event_seq":1,"result":result});
        assert!(
            service
                .lifecycle_sender
                .send(LifecycleMessage::Complete {
                    execution_id: "exec_example".to_owned(),
                    outcome: Ok((vec![terminal], result))
                })
                .is_ok()
        );
        service.poll_admissions();
        service.poll_lifecycle();
        assert!(!service.has_active());
        assert!(service.state.execution_result("exec_example").is_none());
        let disposal=service.handle_rpc_request(&json!({"jsonrpc":"2.0","id":2,"method":"disposeSession","params":{"session_id":"sess_example"}}));
        assert_eq!(
            disposal[0]["error"]["data"]["code"],
            "EXECUTION_CLEANUP_FAILED"
        );
        assert_eq!(disposal[0]["error"]["data"]["cleanup_complete"], false);
        assert_eq!(
            disposal[0]["error"]["data"]["execution_ids"],
            json!(["exec_example"])
        );
        assert!(service.unclean_sessions.contains_key("sess_example"));
    }
}
