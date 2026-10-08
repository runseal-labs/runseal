use super::ExecutionRequest;
use super::errors::backend_execution_error;
use super::journal::ExecutionJournal;
use super::output::truncate_output;
use crate::backend::{ExecutionOutputSink, OutputStream, SandboxBackend, active_backend};
use crate::error::RunSealError;
use crate::events::{
    ExecutionEventContext, backend_event_json, execution_event_at, execution_event_now,
    stream_event, timestamp_now,
};
use crate::policy::SandboxPolicy;
use crate::process_output::decode_process_output;
use crate::protocol::request_validation::duration_millis_u64;
use crate::stdin::stdin_audit_json;
use serde_json::{Value, json};
use std::time::Instant;

pub(crate) trait ExecutionObserver {
    fn event(&mut self, event: &Value) -> Result<(), RunSealError>;

    fn cleanup(
        &mut self,
        _deadline: Instant,
        _execution_cleanup_confirmed: bool,
    ) -> Result<(), RunSealError> {
        Ok(())
    }
}

impl<F: FnMut(&Value) -> Result<(), RunSealError>> ExecutionObserver for F {
    fn event(&mut self, event: &Value) -> Result<(), RunSealError> {
        self(event)
    }
}

pub(crate) fn execute_command_with_observer(
    request: ExecutionRequest,
    observer: &mut dyn ExecutionObserver,
) -> Result<(Vec<Value>, Value), RunSealError> {
    request.control.accept();
    let journal = match ExecutionJournal::prepare(&request) {
        Ok(journal) => journal,
        Err(error) => {
            request
                .control
                .request(super::TerminationCause::FailedToStart);
            return finalize_frontend(
                Err(error),
                &request.control,
                observer.cleanup(request.control.begin_cleanup(), true),
            )
            .map(|result| (Vec::new(), result));
        }
    };
    execute_prepared_with_observer(request, journal, observer)
}

fn finalize_frontend(
    outcome: Result<Value, RunSealError>,
    control: &super::ExecutionControl,
    cleanup: Result<(), RunSealError>,
) -> Result<Value, RunSealError> {
    let Err(error) = cleanup else { return outcome };
    let mut details = match outcome {
        Ok(result) => result,
        Err(error) => error.details.unwrap_or_else(|| json!({})),
    };
    details["cleanup_complete"] = json!(false);
    details["requested_termination_reason"] =
        json!(control.cause().map(super::TerminationCause::as_str));
    Err(RunSealError::with_details(
        "EXECUTION_CLEANUP_FAILED",
        error.reason,
        details,
    ))
}

fn check_preparing(
    control: &super::ExecutionControl,
    accepted_at: Instant,
    timeout: Option<std::time::Duration>,
) -> Result<(), RunSealError> {
    if timeout.is_some_and(|timeout| accepted_at.elapsed() >= timeout) {
        control.request(super::TerminationCause::Timeout);
    }
    if let Some(cause) = control
        .cause()
        .filter(|cause| *cause != super::TerminationCause::Exited)
    {
        return Err(RunSealError::with_details(
            cause.error_code().unwrap_or("EXECUTION_CANCELLED"),
            if cause == super::TerminationCause::Timeout {
                "execution timed out"
            } else {
                "execution stopped before spawn"
            },
            json!({"cleanup_complete":true,"timeout_ms":timeout.map(duration_millis_u64)}),
        ));
    }
    Ok(())
}

pub(crate) fn execute_command(
    request: ExecutionRequest,
) -> Result<(Vec<Value>, Value), RunSealError> {
    execute_command_with_events(request, &mut |_| Ok(()))
}

pub(crate) fn execute_command_with_events(
    request: ExecutionRequest,
    observer: &mut dyn FnMut(&Value) -> Result<(), RunSealError>,
) -> Result<(Vec<Value>, Value), RunSealError> {
    request.control.accept();
    let journal = ExecutionJournal::prepare(&request)?;
    execute_prepared_with_events(request, journal, observer)
}

pub(crate) fn execute_prepared_with_events(
    request: ExecutionRequest,
    journal: ExecutionJournal,
    observer: &mut dyn FnMut(&Value) -> Result<(), RunSealError>,
) -> Result<(Vec<Value>, Value), RunSealError> {
    execute_prepared_with_observer(request, journal, &mut |event: &Value| observer(event))
}

#[cfg(all(test, windows))]
fn execute_prepared_after_admission_with_events(
    request: ExecutionRequest,
    journal: ExecutionJournal,
    admission: std::sync::mpsc::Receiver<()>,
    observer: &mut dyn FnMut(&Value) -> Result<(), RunSealError>,
) -> Result<(Vec<Value>, Value), RunSealError> {
    execute_prepared_after_admission_with_observer(
        request,
        journal,
        admission,
        &mut |event: &Value| observer(event),
    )
}

pub(crate) fn execute_prepared_after_admission_with_observer(
    request: ExecutionRequest,
    journal: ExecutionJournal,
    admission: std::sync::mpsc::Receiver<()>,
    observer: &mut dyn ExecutionObserver,
) -> Result<(Vec<Value>, Value), RunSealError> {
    execute_prepared_with_backend_and_timer(
        request,
        journal,
        observer,
        std::sync::Arc::new(active_backend()),
        &mut super::control::ExecutionDeadline::start,
        Some(admission),
    )
}

fn wait_for_admission(
    admission: Option<std::sync::mpsc::Receiver<()>>,
    control: &super::ExecutionControl,
    accepted_at: Instant,
    timeout: Option<std::time::Duration>,
) -> Result<(), RunSealError> {
    let Some(admission) = admission else {
        return Ok(());
    };
    loop {
        check_preparing(control, accepted_at, timeout)?;
        match admission.recv_timeout(std::time::Duration::from_millis(5)) {
            Ok(()) => return check_preparing(control, accepted_at, timeout),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                control.request(super::TerminationCause::ClientDisconnected);
                return check_preparing(control, accepted_at, timeout);
            }
        }
    }
}

fn execute_prepared_with_observer(
    request: ExecutionRequest,
    journal: ExecutionJournal,
    observer: &mut dyn ExecutionObserver,
) -> Result<(Vec<Value>, Value), RunSealError> {
    execute_prepared_with_backend(
        request,
        journal,
        observer,
        std::sync::Arc::new(active_backend()),
    )
}

pub(super) fn execute_prepared_with_backend<B: SandboxBackend + Send + Sync + 'static>(
    request: ExecutionRequest,
    journal: ExecutionJournal,
    observer: &mut dyn ExecutionObserver,
    backend: std::sync::Arc<B>,
) -> Result<(Vec<Value>, Value), RunSealError> {
    execute_prepared_with_backend_and_timer(
        request,
        journal,
        observer,
        backend,
        &mut super::control::ExecutionDeadline::start,
        None,
    )
}

type DeadlineFactory<'a> = dyn FnMut(
        Instant,
        Option<std::time::Duration>,
        super::ExecutionControl,
    ) -> std::io::Result<Option<super::control::ExecutionDeadline>>
    + 'a;

fn execute_prepared_with_backend_and_timer<B: SandboxBackend + Send + Sync + 'static>(
    request: ExecutionRequest,
    mut journal: ExecutionJournal,
    observer: &mut dyn ExecutionObserver,
    backend: std::sync::Arc<B>,
    timer_factory: &mut DeadlineFactory<'_>,
    admission: Option<std::sync::mpsc::Receiver<()>>,
) -> Result<(Vec<Value>, Value), RunSealError> {
    let control = request.control.clone();
    let timeout = request.timeout;
    let command_args = request.command.len();
    let mut backend_entered = false;
    let mut reservation = None;
    let timer = control.accept();
    let (mut deadline, mut outcome) = match timer_factory(timer, request.timeout, control.clone()) {
        Ok(deadline) => (
            deadline,
            wait_for_admission(admission, &control, timer, request.timeout).and_then(|()| {
                execute_inner(
                    request,
                    &mut journal,
                    &mut |event| observer.event(event),
                    &mut backend_entered,
                    backend,
                    timer,
                    &mut reservation,
                )
            }),
        ),
        Err(_) => (
            None,
            Err(RunSealError::with_details(
                "EXECUTION_FAILED_TO_START",
                "execution deadline worker unavailable",
                json!({"cleanup_complete":true}),
            )),
        ),
    };
    // A request stopped after acceptance is a real failed Execution even if
    // setup never reaches the backend. Admission and policy failures stay
    // record-free and are handled by their structured pre-admission errors.
    let accepted_termination = matches!(
        control.cause(),
        Some(
            super::TerminationCause::Timeout
                | super::TerminationCause::Cancelled
                | super::TerminationCause::ClientDisconnected
                | super::TerminationCause::Backpressure
        )
    );
    if !journal.is_admitted()
        && (accepted_termination
            || outcome.as_ref().is_err_and(|error| {
                matches!(
                    error.code.as_str(),
                    "EXECUTION_TIMEOUT"
                        | "EXECUTION_CANCELLED"
                        | "CLIENT_DISCONNECTED"
                        | "CLIENT_BACKPRESSURE"
                )
            }))
        && let Err(error) = journal.admit(command_args)
    {
        outcome = Err(error);
    }
    if journal.is_admitted()
        && let Err(error) = journal.notify_requested_if_pending(&mut |event| observer.event(event))
        && outcome.is_ok()
    {
        outcome = Err(error);
    }
    if !backend_entered
        && journal.is_admitted()
        && control.cause() == Some(super::TerminationCause::Timeout)
    {
        let limit = json!({
            "type":"execution.resource.limit_exceeded",
            "decision":"limit_exceeded",
            "resource":"timeout_ms",
            "limit":timeout.map(duration_millis_u64),
            "duration_ms":duration_millis_u64(timer.elapsed()),
        });
        if let Err(error) = journal.emit(&limit, &mut |event| observer.event(event))
            && !outcome
                .as_ref()
                .is_err_and(|previous| previous.code == "EXECUTION_CLEANUP_FAILED")
        {
            outcome = Err(error);
        }
    }
    if !backend_entered && let Err(error) = &mut outcome {
        let details = error.details.get_or_insert_with(|| json!({}));
        if let Some(details) = details.as_object_mut() {
            details.entry("cleanup_complete").or_insert(json!(true));
            if control.cause() == Some(super::TerminationCause::Timeout) {
                details
                    .entry("timeout_ms")
                    .or_insert(json!(timeout.map(duration_millis_u64)));
            }
        }
    }
    if control.cause().is_none() {
        control.request(outcome.as_ref().map_or_else(
            |error| super::TerminationCause::from_error_code(&error.code),
            |_| super::TerminationCause::Exited,
        ));
    }
    let timer_cleanup = deadline
        .as_mut()
        .map_or(Ok(()), |deadline| deadline.finish(control.begin_cleanup()));
    let outcome = finalize_frontend(outcome, &control, timer_cleanup);
    let cleanup_confirmed = outcome.as_ref().map_or_else(
        |error| {
            error
                .details
                .as_ref()
                .is_some_and(|details| details["cleanup_complete"] == true)
        },
        |result| result["cleanup_complete"] == true,
    );
    let reservation_cleanup = reservation.as_mut().map_or(Ok(()), |reservation| {
        reservation
            .finish(control.begin_cleanup(), cleanup_confirmed)
            .map_err(|_| {
                RunSealError::new(
                    "EXECUTION_CLEANUP_FAILED",
                    "execution policy cleanup could not be verified",
                )
            })
    });
    let outcome = finalize_frontend(outcome, &control, reservation_cleanup);
    let cleanup_confirmed = outcome.as_ref().map_or_else(
        |error| {
            error
                .details
                .as_ref()
                .is_some_and(|details| details["cleanup_complete"] == true)
        },
        |result| result["cleanup_complete"] == true,
    );
    let cleanup = observer.cleanup(control.begin_cleanup(), cleanup_confirmed);
    let outcome = finalize_frontend(outcome, &control, cleanup);
    journal.finish(outcome, &control, &mut |event| observer.event(event))
}

fn execute_inner<B: SandboxBackend + Send + Sync + 'static>(
    request: ExecutionRequest,
    journal: &mut ExecutionJournal,
    observer: &mut dyn FnMut(&Value) -> Result<(), RunSealError>,
    backend_entered: &mut bool,
    backend: std::sync::Arc<B>,
    timer: Instant,
    reservation: &mut Option<crate::backend::ExecutionReservation>,
) -> Result<Value, RunSealError> {
    let ExecutionRequest {
        ids,
        control,
        command,
        cwd,
        policy,
        stdin,
        control_input,
        io,
        env,
        metadata: _,
        timeout,
    } = request;
    check_preparing(&control, timer, timeout)?;
    if io.has_control() != control_input.is_some() {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            "control input does not match execution I/O",
        ));
    }
    let command = command.as_slice();
    let cwd = cwd.as_path();
    let policy = &policy;
    let output_limit = policy
        .resources
        .max_output_bytes
        .filter(|limit| *limit <= crate::limits::deployment().max_output_bytes as u64)
        .ok_or_else(|| {
            RunSealError::new(
                "POLICY_INVALID",
                "effective policy output limit is missing or exceeds the deployment limit",
            )
        })?;
    if command.is_empty() {
        return Err(RunSealError::new("INVALID_REQUEST", "command is empty"));
    }

    let policy_id = policy.id.clone();
    let policy_hash = policy.hash();
    // RunSeal MVP: stdio has no mutable daemon epoch; promote to a real epoch store when concurrent policy transitions exist.
    let policy_epoch = policy_hash.clone();
    let stdin_audit = stdin_audit_json(&stdin);
    let env_keys = env.keys();
    let audit_path = journal.audit_path().to_string();
    let event_context = ExecutionEventContext {
        ids: &ids,
        policy_id: &policy_id,
        policy_hash: &policy_hash,
        policy_epoch: &policy_epoch,
        audit_path: &audit_path,
        backend: backend_event_json(backend.name(), backend.status(), backend.platform()),
    };

    if policy.requires_broad_write_approval() {
        return Err(journal.reject(
            "APPROVAL_REQUIRED",
            "filesystem broad write requires approval",
        ));
    }

    if policy.denies_execution_without_backend() {
        let requires_approval = policy.approval.on_violation == "request";
        let (code, reason) = if requires_approval {
            ("APPROVAL_REQUIRED", "filesystem write denied by policy")
        } else {
            ("POLICY_DENIED", "filesystem write denied by policy")
        };
        return Err(journal.reject(code, reason));
    }

    check_preparing(&control, timer, timeout)?;
    let compiled = super::preparation::compile_plan(
        backend.clone(),
        ids.execution_id.clone(),
        cwd.to_owned(),
        policy.clone(),
        &control,
    )?;
    check_preparing(&control, timer, timeout)?;
    let plan = match compiled {
        Ok(plan) => plan,
        Err(err) => {
            let details = err.details_json();
            let mut details = details;
            #[cfg(windows)]
            if err.code == "BACKEND_UNAVAILABLE"
                && let Some(object) = details.as_object_mut()
            {
                object.insert(
                    "setup_status".to_string(),
                    super::errors::windows_setup_status_for_backend_error(cwd),
                );
            }
            if let Some(object) = details.as_object_mut() {
                object.insert("cleanup_complete".to_string(), json!(true));
            }
            let error = RunSealError::with_details(err.code, err.reason, details);
            return Err(if error.code == "BACKEND_UNAVAILABLE" {
                journal.audit_pre_admission_failure(
                    error,
                    &json!({
                        "type":"sandbox.backend_capability",
                        "decision":"unavailable",
                        "reason":"sandbox backend unavailable",
                    }),
                )
            } else {
                error
            });
        }
    };

    let sandbox_enforced = plan.is_sandbox_enforced();
    check_preparing(&control, timer, timeout)?;
    *reservation = Some(crate::backend::reserve_execution(&plan).map_err(|error| {
        let cleanup_complete = !crate::backend::cleanup_failed(&error);
        let (code, reason, setup_status) = if cleanup_complete {
            backend_execution_error(&error, sandbox_enforced, cwd).unwrap_or_else(|| {
                (
                    "EXECUTION_FAILED_TO_START",
                    "execution admission rejected".into(),
                    None,
                )
            })
        } else {
            (
                "EXECUTION_CLEANUP_FAILED",
                "execution cleanup could not be verified".into(),
                None,
            )
        };
        let mut details = json!({"cleanup_complete":cleanup_complete});
        if let (Some(details), Some(setup_status)) = (details.as_object_mut(), setup_status) {
            details.insert("setup_status".to_string(), setup_status);
        }
        RunSealError::with_details(code, reason, details)
    })?);
    journal.admit(command.len())?;
    let requested = execution_event_now(
        json!({
            "type": "execution.requested",
            "decision": "requested",
            "command_args": command.len(),
        }),
        &event_context,
    );
    journal.emit(&requested, observer)?;

    let resolved = execution_event_now(
        json!({
            "type": "policy.resolved",
            "decision": "resolved",
            "sandbox_level": policy.sandbox_level.as_str(),
            "network": network_audit_json(policy),
            "backend_requirement": if policy.allows_local_execution() {
                "local-execution"
            } else {
                "sandbox-backend"
            },
            "required_backend_features": policy.required_backend_feature_names(),
        }),
        &event_context,
    );
    journal.emit(&resolved, observer)?;

    let allowed = execution_event_now(
        json!({
            "type": "policy.allowed",
            "decision": "allowed",
            "sandbox": {
                "level": policy.sandbox_level.as_str(),
                "enforced": sandbox_enforced,
            },
            "network": network_audit_json(policy),
        }),
        &event_context,
    );
    journal.emit(&allowed, observer)?;

    let mut started_at = None;
    check_preparing(&control, timer, timeout)?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(16);
    let output_sink = ExecutionOutputSink {
        io,
        control_input,
        sender,
        control: control.clone(),
    };
    let mut live_stdout = Vec::new();
    let mut live_stderr = Vec::new();
    let mut live_terminal = Vec::new();
    let mut terminal_bytes = 0u64;
    let mut control_bytes = 0u64;
    let mut live_control = Vec::new();
    let mut stdout_bytes = 0u64;
    let mut stderr_bytes = 0u64;
    let mut owner_error = None;
    let worker_plan = plan.clone();
    let worker_command = command.to_vec();
    let worker_cwd = cwd.to_owned();
    let worker_env = env;
    let worker_control = control.clone();
    let (completed, completion) = std::sync::mpsc::channel();
    let worker = std::thread::Builder::new()
        .name("runseal-backend".into())
        .spawn(move || {
            let result = backend.execute_plan(
                &worker_plan,
                &worker_command,
                &worker_cwd,
                stdin,
                &worker_env,
                crate::backend::BackendExecutionOptions {
                    timeout,
                    output: Some(output_sink),
                },
            );
            if result.as_ref().is_ok_and(|output| output.timed_out) {
                worker_control.request(super::TerminationCause::Timeout);
            }
            let _ = completed.send(result);
        })
        .map_err(|_| {
            RunSealError::with_details(
                "EXECUTION_FAILED_TO_START",
                "execution backend worker unavailable",
                json!({"cleanup_complete":true}),
            )
        })?;
    *backend_entered = true;
    let mut backend_result = None;
    loop {
        if backend_result.is_none() {
            match completion.try_recv() {
                Ok(result) => backend_result = Some(result),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    backend_result = Some(Err(std::io::Error::other(
                        "execution backend worker failed",
                    )))
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if control.cleanup_deadline_expired() {
            break;
        }
        let chunk = match receiver.recv_timeout(std::time::Duration::from_millis(20)) {
            Ok(chunk) => chunk,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                if backend_result.is_some() || super::retained::thread_finished(&worker) =>
            {
                break;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
        };
        let chunk = match chunk {
            crate::backend::BackendMessage::Started { time } => {
                if started_at.is_some() {
                    control.request(super::TerminationCause::ExecutionFailed);
                    owner_error = Some(RunSealError::new(
                        "INTERNAL_ERROR",
                        "duplicate backend start confirmation",
                    ));
                    continue;
                }
                let started = execution_event_at(
                    json!({
                        "type": "execution.started",
                        "execution_id": ids.execution_id,
                        "policy_id": policy_id,
                        "policy_hash": policy_hash,
                        "audit_path": audit_path,
                        "sandbox": {
                            "level": policy.sandbox_level.as_str(),
                            "enforced": sandbox_enforced,
                        },
                        "network": network_audit_json(policy),
                        "backend": {
                            "name": plan.backend,
                            "status": plan.backend_status,
                            "platform": plan.platform,
                        },
                        "platform_plan": plan.json(),
                        "stdin": stdin_audit,
                        "environment": {
                            "requested_keys": env_keys,
                        },
                    }),
                    &time,
                    &event_context,
                );
                started_at = Some(time);
                if let Err(err) = journal.emit(&started, observer) {
                    control.request(super::TerminationCause::from_started_error_code(&err.code));
                    owner_error = Some(err);
                }

                continue;
            }
            crate::backend::BackendMessage::Output(chunk) => chunk,
        };
        if started_at.is_none() {
            control.request(super::TerminationCause::ExecutionFailed);
            owner_error.get_or_insert_with(|| {
                RunSealError::new(
                    "INTERNAL_ERROR",
                    "backend output preceded start confirmation",
                )
            });
        }
        let (event_type, offset, retained) = match chunk.stream {
            OutputStream::Control => ("execution.control", &mut control_bytes, &mut live_control),
            OutputStream::Stdout => ("execution.stdout", &mut stdout_bytes, &mut live_stdout),
            OutputStream::Stderr => ("execution.stderr", &mut stderr_bytes, &mut live_stderr),
            OutputStream::Terminal => (
                "execution.terminal",
                &mut terminal_bytes,
                &mut live_terminal,
            ),
        };
        let event = stream_event(event_type, &event_context, &chunk.bytes, *offset);
        *offset += chunk.bytes.len() as u64;
        if stdout_bytes
            .saturating_add(stderr_bytes)
            .saturating_add(terminal_bytes)
            .saturating_add(control_bytes)
            > output_limit
        {
            if owner_error.is_none() {
                let previous_total = stdout_bytes
                    .saturating_add(stderr_bytes)
                    .saturating_add(terminal_bytes)
                    .saturating_add(control_bytes)
                    .saturating_sub(chunk.bytes.len() as u64);
                let remaining = output_limit.saturating_sub(previous_total) as usize;
                retained.extend_from_slice(&chunk.bytes[..remaining.min(chunk.bytes.len())]);
            }
            owner_error.get_or_insert_with(|| {
                RunSealError::new("OUTPUT_LIMIT_EXCEEDED", "output limit exceeded")
            });
            control.request(super::TerminationCause::OutputLimit);
            continue;
        }
        if owner_error.is_some() {
            continue;
        }
        retained.extend_from_slice(&chunk.bytes);
        let result = journal.emit(&event, observer);
        if let Err(err) = result {
            control.request(super::TerminationCause::from_started_error_code(&err.code));
            owner_error = Some(err);
        }
    }
    while backend_result.is_none() {
        match completion.try_recv() {
            Ok(result) => {
                backend_result = Some(result);
                break;
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                backend_result = Some(Err(std::io::Error::other(
                    "execution backend worker failed",
                )));
                break;
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        if control.cleanup_deadline_expired() || super::retained::thread_finished(&worker) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    if let Some(result) = backend_result.as_ref()
        && owner_error.is_none()
    {
        accept_backend_cause(&control, result, started_at.is_some());
    }
    let cleanup_deadline = control.begin_cleanup();
    while !super::retained::thread_finished(&worker) && Instant::now() < cleanup_deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    if backend_result.is_none() {
        backend_result = completion.try_recv().ok();
    }
    let backend_result = if super::retained::thread_finished(&worker) {
        let joined = worker.join();
        match (joined, backend_result) {
            (Ok(()), Some(result)) => result,
            _ => Err(std::io::Error::other("execution backend worker failed")),
        }
    } else {
        super::retained::retain(worker);
        match backend_result {
            Some(Ok(mut output)) => {
                output.cleanup_complete = false;
                Ok(output)
            }
            result => Err(std::io::Error::other(crate::backend::BackendCleanupFacts {
                exit_code: result
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .and_then(crate::backend::failure_exit_code),
                timed_out: result
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .is_some_and(crate::backend::failure_timed_out),
            })),
        }
    };
    if started_at.is_none()
        && (backend_result.is_ok()
            || backend_result
                .as_ref()
                .err()
                .and_then(crate::backend::failure_exit_code)
                .is_some())
    {
        control.request(super::TerminationCause::ExecutionFailed);
        owner_error.get_or_insert_with(|| {
            RunSealError::new("INTERNAL_ERROR", "backend omitted start confirmation")
        });
    }
    if owner_error.is_none() {
        accept_backend_cause(&control, &backend_result, started_at.is_some());
    }
    if let Some(cause) = control.cause()
        && let Some(code) = cause.error_code()
    {
        owner_error = Some(RunSealError::new(
            code,
            if cause == super::TerminationCause::Timeout {
                "execution timed out".to_string()
            } else {
                format!("execution terminated: {}", cause.as_str())
            },
        ));
    }
    let backend_error = backend_result.as_ref().err();
    let backend_input_failed = backend_error.is_some_and(crate::backend::input_failed);
    let backend_cleanup_failed = backend_error.is_some_and(crate::backend::cleanup_failed);
    let cleanup_complete = backend_result
        .as_ref()
        .is_ok_and(|output| output.cleanup_complete)
        || backend_input_failed
        // A backend that never reported a real spawn cannot have left a process
        // range, so a non-cleanup error is a completed pre-launch rollback.
        || (started_at.is_none() && backend_error.is_some() && !backend_cleanup_failed);
    if backend_input_failed {
        owner_error.get_or_insert_with(|| {
            RunSealError::new("EXECUTION_INPUT_FAILED", "execution input failed")
        });
    }
    let cleanup_failed = backend_result
        .as_ref()
        .is_ok_and(|output| !output.cleanup_complete)
        || backend_cleanup_failed
        || (started_at.is_some() && backend_result.is_err() && !backend_input_failed);
    if cleanup_failed {
        if backend_result
            .as_ref()
            .err()
            .and_then(crate::backend::failure_exit_code)
            .is_some()
        {
            let timed_out = backend_result
                .as_ref()
                .err()
                .is_some_and(crate::backend::failure_timed_out);
            control.request(if timed_out {
                super::TerminationCause::Timeout
            } else {
                super::TerminationCause::Exited
            });
        }
        owner_error = Some(RunSealError::new(
            "EXECUTION_CLEANUP_FAILED",
            "execution cleanup could not be verified",
        ));
    }
    if let Some(err) = owner_error {
        let details = json!({
            "execution_id": ids.execution_id, "session_id": ids.session_id,
            "policy_id": policy_id, "policy_hash": policy_hash, "policy_epoch": policy_epoch,
            "backend": event_context.backend, "audit_path": audit_path,
            "sandbox": {"level":policy.sandbox_level.as_str(),"enforced":sandbox_enforced},
            "network":network_audit_json(policy),
            "exit_code": backend_result.as_ref().ok().and_then(|output|output.output.status.code()).or_else(|| backend_result.as_ref().err().and_then(crate::backend::failure_exit_code)),
            "signal": backend_result.as_ref().ok().and_then(|output|exit_signal(output.output.status)),
            "stdout_bytes": stdout_bytes, "stderr_bytes": stderr_bytes,
            "control_bytes": control_bytes,
            "terminal_bytes": terminal_bytes, "stderr_merged": io.is_pty(),
            "retained_stdout_bytes": live_stdout.len(), "retained_stderr_bytes": live_stderr.len(),
            "max_output_bytes": output_limit,
            "termination_reason": if cleanup_failed { Some("cleanup_failed") } else { control.cause().map(super::TerminationCause::as_str) },
            "requested_termination_reason": control.cause().map(super::TerminationCause::as_str),
            "cleanup_complete": cleanup_complete,
            "timeout_ms": timeout.map(duration_millis_u64),
        });
        // Cleanup and the first termination cause are already established.
        // A failed informational delivery must not discard that evidence;
        // required audit failures still propagate with the cleanup details.
        let mut notify = |event: &Value| {
            let _ = observer(event);
            Ok(())
        };
        if err.code == "OUTPUT_LIMIT_EXCEEDED" {
            for payload in [
                json!({"type":"execution.output.truncated", "decision":"truncated", "stdout_bytes":stdout_bytes, "stderr_bytes":stderr_bytes}),
                json!({"type":"execution.resource.limit_exceeded", "decision":"limit_exceeded", "resource":"max_output_bytes", "limit":output_limit}),
            ] {
                let event = execution_event_now(payload, &event_context);
                journal.emit(&event, &mut notify).map_err(|audit_error| {
                    RunSealError::with_details(
                        audit_error.code,
                        audit_error.reason,
                        details.clone(),
                    )
                })?;
            }
        } else if err.code == "EXECUTION_TIMEOUT" {
            let event = execution_event_now(
                json!({"type":"execution.resource.limit_exceeded","decision":"limit_exceeded","resource":"timeout_ms","limit":timeout.map(duration_millis_u64),"duration_ms":duration_millis_u64(timer.elapsed())}),
                &event_context,
            );
            journal.emit(&event, &mut notify).map_err(|audit_error| {
                RunSealError::with_details(audit_error.code, audit_error.reason, details.clone())
            })?;
        }

        return Err(RunSealError::with_details(err.code, err.reason, details));
    }
    let execution_output = match backend_result {
        Ok(output) => output,
        Err(err) => {
            let backend_error = backend_execution_error(&err, sandbox_enforced, cwd);
            if let Some((code, reason, setup_status)) = backend_error {
                let mut details = json!({
                    "execution_id": ids.execution_id,
                    "session_id": ids.session_id,
                    "seal_id": ids.seal_id,
                    "policy_id": policy_id,
                    "policy_hash": policy_hash,
                    "policy_epoch": policy_epoch,
                    "audit_path": audit_path,
                    "backend": {
                        "name": plan.backend,
                        "status": plan.backend_status,
                        "platform": plan.platform,
                    },
                    "platform_plan": plan.json(),
                    "cleanup_complete": cleanup_complete,
                });
                if let (Some(details), Some(setup_status)) = (details.as_object_mut(), setup_status)
                {
                    details.insert("setup_status".to_string(), setup_status);
                }
                return Err(RunSealError::with_details(code, reason, details));
            }

            return Err(RunSealError::with_details(
                "EXECUTION_FAILED_TO_START",
                "execution failed to start",
                json!({
                    "execution_id": ids.execution_id,
                    "session_id": ids.session_id,
                    "seal_id": ids.seal_id,
                    "policy_id": policy_id,
                    "policy_hash": policy_hash,
                    "policy_epoch": policy_epoch,
                    "audit_path": audit_path,
                    "backend": {
                        "name": plan.backend,
                        "status": plan.backend_status,
                        "platform": plan.platform,
                    },
                    "platform_plan": plan.json(),
                    "cleanup_complete": cleanup_complete,
                }),
            ));
        }
    };
    let backend_events = execution_output
        .events
        .iter()
        .map(|event| execution_event_now(event.clone(), &event_context))
        .collect::<Vec<_>>();
    for event in &backend_events {
        journal.emit(event, observer)?;
    }
    let mut output = execution_output.output;
    output.stdout = live_stdout;
    output.stderr = live_stderr;
    let original_stdout_bytes = output.stdout.len();
    let original_stderr_bytes = output.stderr.len();
    let output_truncated = truncate_output(&mut output, policy.resources.max_output_bytes);
    let duration_ms = duration_millis_u64(timer.elapsed());
    if execution_output.timed_out {
        let timeout_ms = timeout.map(duration_millis_u64);
        let limit_exceeded = execution_event_now(
            json!({
                "type": "execution.resource.limit_exceeded",
                "decision": "limit_exceeded",
                "resource": "timeout_ms",
                "limit": timeout_ms,
                "duration_ms": duration_ms,
            }),
            &event_context,
        );
        journal.emit(&limit_exceeded, observer)?;

        return Err(RunSealError::with_details(
            "EXECUTION_TIMEOUT",
            "execution timed out",
            json!({
                "execution_id": ids.execution_id,
                "session_id": ids.session_id,
                "seal_id": ids.seal_id,
                "audit_path": audit_path,
                "timeout_ms": timeout_ms,
                "stdout_bytes": output.stdout.len(),
                "stderr_bytes": output.stderr.len(),
            }),
        ));
    }

    if output_truncated {
        let event = execution_event_now(
            json!({
                "type": "execution.output.truncated",
                "execution_id": ids.execution_id,
                "policy_id": policy_id,
                "policy_hash": policy_hash,
                "audit_path": audit_path,
                "decision": "truncated",
                "max_output_bytes": policy.resources.max_output_bytes,
                "stdout_bytes": output.stdout.len(),
                "stderr_bytes": output.stderr.len(),
                "original_stdout_bytes": original_stdout_bytes,
                "original_stderr_bytes": original_stderr_bytes,
            }),
            &event_context,
        );
        journal.emit(&event, observer)?;
    }
    let exit_code = output.status.code().unwrap_or(1);
    let output_program = command.first().map(String::as_str).unwrap_or("");
    let stdout = decode_process_output(output_program, &output.stdout);
    let stderr = decode_process_output(output_program, &output.stderr);
    let finished_at = timestamp_now();
    let resource_sample = execution_event_at(
        json!({
            "type": "execution.resource.sample",
            "duration_ms": duration_ms,
            "stdout_bytes": output.stdout.len(),
            "stderr_bytes": output.stderr.len(),
            "output_truncated": output_truncated,
        }),
        &finished_at,
        &event_context,
    );
    journal.emit(&resource_sample, observer)?;

    if output_truncated {
        let limit_exceeded = execution_event_at(
            json!({
                "type": "execution.resource.limit_exceeded",
                "decision": "limit_exceeded",
                "resource": "max_output_bytes",
                "limit": policy.resources.max_output_bytes,
                "stdout_bytes": original_stdout_bytes,
                "stderr_bytes": original_stderr_bytes,
                "retained_stdout_bytes": output.stdout.len(),
                "retained_stderr_bytes": output.stderr.len(),
            }),
            &finished_at,
            &event_context,
        );
        journal.emit(&limit_exceeded, observer)?;

        return Err(RunSealError::with_details(
            "OUTPUT_LIMIT_EXCEEDED",
            "output limit exceeded",
            json!({
                "execution_id": ids.execution_id,
                "session_id": ids.session_id,
                "seal_id": ids.seal_id,
                "audit_path": audit_path,
                "max_output_bytes": policy.resources.max_output_bytes,
                "stdout_bytes": original_stdout_bytes,
                "stderr_bytes": original_stderr_bytes,
                "retained_stdout_bytes": output.stdout.len(),
                "retained_stderr_bytes": output.stderr.len(),
            }),
        ));
    }

    let result = json!({
        "execution_id": ids.execution_id,
        "session_id": ids.session_id,
        "seal_id": ids.seal_id,
        "status": "finished",
        "termination_reason": control.cause().map(super::TerminationCause::as_str),
        "cleanup_complete": cleanup_complete,
        "exit_code": exit_code,
        "signal": null,
        "started_at": started_at,
        "finished_at": finished_at,
        "policy_id": policy_id,
        "policy_hash": policy_hash,
        "policy_epoch": policy_epoch,
        "audit_path": audit_path,
        "sandbox": {
            "level": policy.sandbox_level.as_str(),
            "enforced": sandbox_enforced,
        },
        "network": network_audit_json(policy),
        "backend": {
            "name": plan.backend,
            "status": plan.backend_status,
            "platform": plan.platform,
        },
        "platform_plan": plan.json(),
        "stdout_bytes": output.stdout.len(),
        "stderr_bytes": output.stderr.len(),
        "control_bytes": control_bytes,
            "terminal_bytes": terminal_bytes,
        "stderr_merged": io.is_pty(),
        "output_truncated": output_truncated,
        "stdout": stdout,
        "stderr": stderr,
        "resource_usage": {
            "duration_ms": duration_ms,
        }
    });

    Ok(result)
}

fn accept_backend_cause(
    control: &super::ExecutionControl,
    result: &std::io::Result<crate::backend::BackendExecutionOutput>,
    started: bool,
) {
    control.request(
        if result.as_ref().is_ok_and(|result| result.timed_out)
            || result
                .as_ref()
                .err()
                .is_some_and(crate::backend::failure_timed_out)
        {
            super::TerminationCause::Timeout
        } else if result
            .as_ref()
            .err()
            .is_some_and(crate::backend::input_failed)
        {
            super::TerminationCause::InputFailed
        } else if result.is_ok()
            || result
                .as_ref()
                .err()
                .and_then(crate::backend::failure_exit_code)
                .is_some()
        {
            super::TerminationCause::Exited
        } else {
            if started {
                super::TerminationCause::ExecutionFailed
            } else {
                super::TerminationCause::FailedToStart
            }
        },
    );
}

fn network_audit_json(policy: &SandboxPolicy) -> Value {
    json!({
        "mode": policy.network.mode.as_str(),
        "routes": policy.network.routes,
        "direct_allow_hosts": policy.network.direct_allow_hosts,
    })
}

fn exit_signal(status: std::process::ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

#[cfg(all(test, windows))]
mod backend_failure_tests {
    use super::*;
    use crate::backend::{
        BackendError, BackendExecutionOptions, BackendExecutionOutput, ExecutionEnv,
        ExecutionStdin, PlatformSandboxPlan,
    };
    use crate::policy::BackendFeature;
    use std::{io, path::Path};

    struct GatedCompilation {
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
        executed: std::sync::atomic::AtomicBool,
    }
    impl SandboxBackend for GatedCompilation {
        fn name(&self) -> &'static str {
            active_backend().name()
        }
        fn status(&self) -> &'static str {
            active_backend().status()
        }
        fn platform(&self) -> &'static str {
            active_backend().platform()
        }
        fn supported_features(&self) -> &'static [BackendFeature] {
            active_backend().supported_features()
        }
        fn capabilities_json(&self) -> Value {
            active_backend().capabilities_json()
        }
        fn compile_plan(
            &self,
            id: &str,
            cwd: &Path,
            policy: &SandboxPolicy,
        ) -> Result<PlatformSandboxPlan, BackendError> {
            let _ = self.entered.send(());
            let released = self
                .release
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .recv_timeout(std::time::Duration::from_secs(3));
            assert!(released.is_ok(), "fixture must release compilation");
            active_backend().compile_plan(id, cwd, policy)
        }
        fn execute_plan(
            &self,
            plan: &PlatformSandboxPlan,
            command: &[String],
            cwd: &Path,
            stdin: ExecutionStdin,
            env: &ExecutionEnv,
            options: BackendExecutionOptions,
        ) -> io::Result<BackendExecutionOutput> {
            self.executed
                .store(true, std::sync::atomic::Ordering::Release);
            active_backend().execute_plan(plan, command, cwd, stdin, env, options)
        }
    }

    #[test]
    fn preparing_timeout_and_cancellation_prevent_launch_after_compilation_gate_release()
    -> anyhow::Result<()> {
        use std::sync::{atomic::Ordering, mpsc};
        use std::time::Duration;
        for cancel_first in [false, true] {
            let tmp = tempfile::TempDir::new()?;
            let control = super::super::ExecutionControl::default();
            let request = ExecutionRequest {
                ids: crate::events::new_execution_ids(), control:control.clone(),
                command:vec!["python".into(),"-c".into(),
                    "import pathlib,sys; pathlib.Path('must-not-run').write_text('ran'); sys.exit(7)".into()],
                cwd:tmp.path().to_owned(),
                policy:crate::policy::normalize_policy(&json!("danger-full-access"),tmp.path(),None)
                    .map_err(|error|anyhow::anyhow!(error.reason))?,
                stdin:ExecutionStdin::Empty,control_input:None,io:crate::backend::ExecutionIo::Pipe,
                env:ExecutionEnv::default(),metadata:None,
                timeout:Some(Duration::from_millis(if cancel_first {1000} else {100})),
            };
            let journal = ExecutionJournal::prepare(&request)
                .map_err(|error| anyhow::anyhow!(error.reason))?;
            let (entered, ready) = mpsc::channel();
            let (release, released) = mpsc::channel();
            let backend = std::sync::Arc::new(GatedCompilation {
                entered,
                release: std::sync::Mutex::new(released),
                executed: std::sync::atomic::AtomicBool::new(false),
            });
            let actor_control = control.clone();
            let actor = std::thread::spawn(move || {
                let entered = ready.recv_timeout(Duration::from_secs(2)).is_ok();
                if entered && cancel_first {
                    actor_control.cancel();
                    actor_control.request(super::super::TerminationCause::Timeout);
                }
                let watchdog = Instant::now() + Duration::from_secs(2);
                while entered && actor_control.cause().is_none() && Instant::now() < watchdog {
                    std::thread::sleep(Duration::from_millis(5));
                }
                let cause_before_release = actor_control.cause();
                let _ = release.send(());
                (entered, cause_before_release)
            });
            let mut events = Vec::new();
            let outcome = execute_prepared_with_backend(
                request,
                journal,
                &mut |event: &Value| {
                    events.push(event.clone());
                    Ok(())
                },
                backend.clone(),
            );
            let (entered, cause_before_release) = actor
                .join()
                .map_err(|_| anyhow::anyhow!("preparation actor panic"))?;
            let expected = if cancel_first {
                super::super::TerminationCause::Cancelled
            } else {
                super::super::TerminationCause::Timeout
            };
            assert!(entered, "fault must hold plan compilation");
            assert_eq!(
                cause_before_release,
                Some(expected),
                "cause must be accepted while gate is held"
            );
            assert!(!backend.executed.load(Ordering::Acquire));
            assert!(!tmp.path().join("must-not-run").exists());
            assert!(
                outcome.is_err(),
                "preparing termination must refuse native launch"
            );
            let error = outcome.expect_err("verified error");
            assert_eq!(Some(error.code.as_str()), expected.error_code());
            let terminals: Vec<_> = events
                .iter()
                .filter(|event| {
                    matches!(
                        event["type"].as_str(),
                        Some("execution.finished" | "execution.failed")
                    )
                })
                .collect();
            assert_eq!(terminals.len(), 1);
            assert!(
                !events
                    .iter()
                    .any(|event| event["type"] == "execution.started")
            );
            assert_eq!(
                terminals[0]["result"]["termination_reason"],
                expected.as_str()
            );
            assert_eq!(terminals[0]["result"]["cleanup_complete"], true);
            assert!(terminals[0]["result"]["started_at"].is_null());
            assert!(terminals[0]["result"]["exit_code"].is_null());
            let limits: Vec<_> = events
                .iter()
                .filter(|event| {
                    event["type"] == "execution.resource.limit_exceeded"
                        && event["resource"] == "timeout_ms"
                })
                .collect();
            if cancel_first {
                assert!(
                    limits.is_empty(),
                    "timeout cannot replace accepted cancellation"
                );
            } else {
                assert_eq!(terminals[0]["result"]["timeout_ms"], 100);
                assert_eq!(
                    terminals[0]["result"]["error"]["reason"],
                    "execution timed out"
                );
                assert_eq!(limits.len(), 1);
                assert_eq!(limits[0]["limit"], 100);
                assert!(
                    limits[0]["duration_ms"]
                        .as_u64()
                        .is_some_and(|elapsed| elapsed >= 100)
                );
            }
            let audit = std::fs::read_to_string(
                tmp.path()
                    .join(terminals[0]["audit_path"].as_str().expect("audit path")),
            )?;
            let records: Vec<Value> = audit
                .lines()
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()?;
            assert_eq!(records.last(), Some(terminals[0]));
            assert_eq!(
                records
                    .iter()
                    .filter(|event| matches!(
                        event["type"].as_str(),
                        Some("execution.finished" | "execution.failed")
                    ))
                    .count(),
                1
            );
        }
        Ok(())
    }

    #[test]
    fn accepted_timeout_is_not_restarted_when_execution_worker_starts_late() -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let control = super::super::ExecutionControl::default();
        let accepted = control.accept();
        let timeout = std::time::Duration::from_millis(50);
        let request = ExecutionRequest {
            ids: crate::events::new_execution_ids(),
            control: control.clone(),
            command: vec![
                "python".into(),
                "-c".into(),
                "import pathlib,sys; pathlib.Path('must-not-run').write_text('ran'); sys.exit(7)"
                    .into(),
            ],
            cwd: tmp.path().to_owned(),
            policy: crate::policy::normalize_policy(&json!("danger-full-access"), tmp.path(), None)
                .map_err(|error| anyhow::anyhow!(error.reason))?,
            stdin: ExecutionStdin::Empty,
            control_input: None,
            io: crate::backend::ExecutionIo::Pipe,
            env: ExecutionEnv::default(),
            metadata: None,
            timeout: Some(timeout),
        };
        let journal =
            ExecutionJournal::prepare(&request).map_err(|error| anyhow::anyhow!(error.reason))?;
        while accepted.elapsed() < timeout {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let error = execute_prepared_with_backend(
            request,
            journal,
            &mut |_: &Value| Ok(()),
            std::sync::Arc::new(active_backend()),
        )
        .expect_err("expired accepted execution cannot restart budget");
        assert_eq!(control.accept(), accepted);
        assert_eq!(error.code, "EXECUTION_TIMEOUT");
        assert!(!tmp.path().join("must-not-run").exists());
        let terminal = error.terminal_event.expect("terminal");
        assert_eq!(terminal["result"]["termination_reason"], "timeout");
        assert_eq!(terminal["result"]["cleanup_complete"], true);
        assert!(terminal["result"]["started_at"].is_null());
        assert!(terminal["result"]["exit_code"].is_null());
        Ok(())
    }

    #[test]
    fn admission_barrier_timeout_finishes_before_release_without_launch() -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let control = super::super::ExecutionControl::default();
        control.accept();
        let request = ExecutionRequest {
            ids: crate::events::new_execution_ids(),
            control: control.clone(),
            command: vec![
                "python".into(),
                "-c".into(),
                "import pathlib; pathlib.Path('must-not-run').write_text('ran')".into(),
            ],
            cwd: tmp.path().to_owned(),
            policy: crate::policy::normalize_policy(&json!("danger-full-access"), tmp.path(), None)
                .map_err(|error| anyhow::anyhow!(error.reason))?,
            stdin: ExecutionStdin::Empty,
            control_input: None,
            io: crate::backend::ExecutionIo::Pipe,
            env: ExecutionEnv::default(),
            metadata: None,
            timeout: Some(std::time::Duration::from_millis(100)),
        };
        let journal =
            ExecutionJournal::prepare(&request).map_err(|error| anyhow::anyhow!(error.reason))?;
        let (release, admission) = std::sync::mpsc::channel();
        let mut events = Vec::new();
        let error = execute_prepared_after_admission_with_events(
            request,
            journal,
            admission,
            &mut |event| {
                events.push(event.clone());
                Ok(())
            },
        )
        .expect_err("timeout must finish while admission barrier is held");
        assert_eq!(error.code, "EXECUTION_TIMEOUT");
        assert_eq!(
            control.cause(),
            Some(super::super::TerminationCause::Timeout)
        );
        assert!(
            release.send(()).is_err(),
            "late release cannot revive execution"
        );
        assert!(!tmp.path().join("must-not-run").exists());
        assert!(
            !events
                .iter()
                .any(|event| event["type"] == "execution.started")
        );
        let terminals: Vec<_> = events
            .iter()
            .filter(|event| {
                matches!(
                    event["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                )
            })
            .collect();
        assert_eq!(terminals.len(), 1);
        assert_eq!(terminals[0]["result"]["cleanup_complete"], true);
        assert_eq!(terminals[0]["result"]["termination_reason"], "timeout");
        assert!(terminals[0]["result"]["started_at"].is_null());
        let audit = std::fs::read_to_string(
            tmp.path()
                .join(terminals[0]["audit_path"].as_str().expect("audit path")),
        )?;
        let records: Vec<Value> = audit
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        assert_eq!(records.last(), Some(terminals[0]));
        assert_eq!(
            records
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

    #[test]
    fn running_observer_failure_stops_real_range_without_claiming_start_failure()
    -> anyhow::Result<()> {
        for earlier_cancel in [false, true] {
            let tmp = tempfile::TempDir::new()?;
            let control = super::super::ExecutionControl::default();
            let request = ExecutionRequest {
                ids: crate::events::new_execution_ids(), control:control.clone(),
                command:vec!["python".into(),"-u".into(),"-c".into(),"import sys,os,pathlib,subprocess,time; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)']); pathlib.Path('target.pids').write_text(str(os.getpid())+' '+str(child.pid)); print('READY',flush=True); time.sleep(120)".into()],
                cwd:tmp.path().to_owned(), policy:crate::policy::normalize_policy(&json!("danger-full-access"),tmp.path(),None).map_err(|error|anyhow::anyhow!(error.reason))?,
                stdin:ExecutionStdin::Empty, control_input:None, io:crate::backend::ExecutionIo::Pipe,
                env:ExecutionEnv::default(), metadata:None, timeout:Some(std::time::Duration::from_secs(5)),
            };
            let mut events = Vec::new();
            let mut injected = false;
            let error = execute_command_with_events(request, &mut |event| {
                events.push(event.clone());
                if !injected && event["type"] == "execution.stdout" {
                    injected = true;
                    if earlier_cancel {
                        control.cancel();
                    }
                    return Err(RunSealError::new(
                        "INTERNAL_ERROR",
                        "controlled lifecycle observer failure",
                    ));
                }
                Ok(())
            })
            .expect_err("running management failure must be observable");
            assert!(injected, "fault must follow native child output");
            let pids = std::fs::read_to_string(tmp.path().join("target.pids"))?
                .split_whitespace()
                .map(str::parse::<u32>)
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(pids.len(), 2);
            for pid in pids {
                let handle = unsafe {
                    windows_sys::Win32::System::Threading::OpenProcess(0x0010_0000, 0, pid)
                };
                if !handle.is_null() {
                    assert_eq!(
                        unsafe {
                            windows_sys::Win32::System::Threading::WaitForSingleObject(handle, 0)
                        },
                        0,
                        "owned native range must be gone"
                    );
                    unsafe {
                        windows_sys::Win32::Foundation::CloseHandle(handle);
                    }
                } else {
                    assert_eq!(
                        unsafe { windows_sys::Win32::Foundation::GetLastError() },
                        87,
                        "owner status must be verifiable"
                    );
                }
            }
            let terminals: Vec<_> = events
                .iter()
                .filter(|event| {
                    matches!(
                        event["type"].as_str(),
                        Some("execution.finished" | "execution.failed")
                    )
                })
                .collect();
            assert_eq!(terminals.len(), 1);
            let terminal = terminals[0];
            assert!(terminal["result"]["started_at"].is_string());
            assert_eq!(terminal["result"]["cleanup_complete"], true);
            assert_eq!(
                terminal["result"]["termination_reason"],
                if earlier_cancel {
                    "cancelled"
                } else {
                    "execution_failed"
                }
            );
            assert_eq!(
                error.code,
                if earlier_cancel {
                    "EXECUTION_CANCELLED"
                } else {
                    "INTERNAL_ERROR"
                }
            );
            let records: Vec<Value> = std::fs::read_to_string(
                tmp.path().join(
                    terminal["audit_path"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("audit path"))?,
                ),
            )?
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
            assert_eq!(records.last(), Some(terminal));
            assert_eq!(
                records
                    .iter()
                    .filter(|event| matches!(
                        event["type"].as_str(),
                        Some("execution.finished" | "execution.failed")
                    ))
                    .count(),
                1
            );
        }
        Ok(())
    }

    struct AfterNativeExitFault {
        cleanup_failure: bool,
        unverified_failure: bool,
        earlier_cause: Option<super::super::TerminationCause>,
    }

    #[test]
    fn owned_backend_worker_retains_native_exit_callback_and_blocked_result_without_false_cleanup()
    -> anyhow::Result<()> {
        use anyhow::Context;
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        };
        use std::time::Duration;
        use windows_sys::Win32::Foundation::{
            DUPLICATE_SAME_ACCESS, DuplicateHandle, WAIT_OBJECT_0, WAIT_TIMEOUT,
        };
        use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType, ReadFile};
        use windows_sys::Win32::System::Pipes::CreatePipe;
        use windows_sys::Win32::System::Threading::{
            FlsAlloc, FlsFree, FlsSetValue, GetCurrentProcess, GetCurrentThread,
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SYNCHRONIZE, WaitForSingleObject,
        };
        struct Gate {
            entered: AtomicBool,
            release: AtomicBool,
            worker: Mutex<Option<(OwnedHandle, std::thread::ThreadId)>>,
            output: Mutex<Option<ExecutionOutputSink>>,
        }
        unsafe extern "system" fn hold_exit(value: *const std::ffi::c_void) {
            let gate = unsafe { Arc::from_raw(value.cast::<Gate>()) };
            gate.entered.store(true, Ordering::Release);
            while !gate.release.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        struct Fixture {
            gate: Arc<Gate>,
            slot: Option<u32>,
            writer: Option<std::fs::File>,
            stop_watchdog: Option<std::sync::mpsc::Sender<()>>,
            watchdog: Option<std::thread::JoinHandle<()>>,
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                if let Some(stop) = self.stop_watchdog.take() {
                    let _ = stop.send(());
                }
                self.gate.release.store(true, Ordering::Release);
                self.gate
                    .output
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some(mut writer) = self.writer.take() {
                    use std::io::Write;
                    let _ = writer.write_all(b"R");
                }
                let finished = self
                    .gate
                    .worker
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .as_ref()
                    .is_some_and(|(handle, id)| {
                        let finished = unsafe { WaitForSingleObject(handle.as_raw_handle(), 2000) }
                            == WAIT_OBJECT_0;
                        if finished {
                            let _ = super::super::retained::join_finished(*id);
                        }
                        finished
                    });
                if finished && let Some(slot) = self.slot {
                    unsafe {
                        FlsFree(slot);
                    }
                }
                if let Some(watchdog) = self.watchdog.take() {
                    if unsafe { WaitForSingleObject(watchdog.as_raw_handle(), 2000) }
                        == WAIT_OBJECT_0
                    {
                        let _ = watchdog.join();
                    } else {
                        super::super::retained::retain(watchdog);
                    }
                }
            }
        }
        struct NativeFaultBackend {
            gate: Arc<Gate>,
            slot: Option<u32>,
            reader: Option<std::fs::File>,
        }
        impl SandboxBackend for NativeFaultBackend {
            fn name(&self) -> &'static str {
                active_backend().name()
            }
            fn status(&self) -> &'static str {
                active_backend().status()
            }
            fn platform(&self) -> &'static str {
                active_backend().platform()
            }
            fn supported_features(&self) -> &'static [BackendFeature] {
                active_backend().supported_features()
            }
            fn capabilities_json(&self) -> Value {
                active_backend().capabilities_json()
            }
            fn compile_plan(
                &self,
                id: &str,
                cwd: &Path,
                policy: &SandboxPolicy,
            ) -> Result<PlatformSandboxPlan, BackendError> {
                active_backend().compile_plan(id, cwd, policy)
            }
            fn execute_plan(
                &self,
                plan: &PlatformSandboxPlan,
                command: &[String],
                cwd: &Path,
                stdin: ExecutionStdin,
                env: &ExecutionEnv,
                options: BackendExecutionOptions,
            ) -> io::Result<BackendExecutionOutput> {
                if let Some(slot) = self.slot {
                    let pointer = Arc::into_raw(self.gate.clone());
                    if unsafe { FlsSetValue(slot, pointer.cast()) } == 0 {
                        drop(unsafe { Arc::from_raw(pointer) });
                        return Err(io::Error::last_os_error());
                    }
                }
                let process = unsafe { GetCurrentProcess() };
                let mut handle = std::ptr::null_mut();
                if unsafe {
                    DuplicateHandle(
                        process,
                        GetCurrentThread(),
                        process,
                        &mut handle,
                        0,
                        0,
                        DUPLICATE_SAME_ACCESS,
                    )
                } == 0
                {
                    return Err(io::Error::last_os_error());
                }
                *self
                    .gate
                    .worker
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((
                    unsafe { OwnedHandle::from_raw_handle(handle) },
                    std::thread::current().id(),
                ));
                let control = options.output.as_ref().map(|output| output.control.clone());
                *self
                    .gate
                    .output
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = options.output.clone();
                let result =
                    active_backend().execute_plan(plan, command, cwd, stdin, env, options)?;
                if !result.cleanup_complete || result.output.status.code() != Some(7) {
                    return Err(io::Error::other("native target result required"));
                }
                if let Some(control) = control {
                    if self.reader.is_some() {
                        control.cancel();
                    }
                    control.adopt_cleanup_deadline(Instant::now() + Duration::from_millis(100));
                }
                if let Some(reader) = &self.reader {
                    self.gate.entered.store(true, Ordering::Release);
                    let mut byte = 0u8;
                    let mut count = 0u32;
                    if unsafe {
                        ReadFile(
                            reader.as_raw_handle(),
                            &mut byte,
                            1,
                            &mut count,
                            std::ptr::null_mut(),
                        )
                    } == 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(result)
            }
        }
        for exit_callback in [true, false] {
            let tmp = tempfile::TempDir::new()?;
            let gate = Arc::new(Gate {
                entered: AtomicBool::new(false),
                release: AtomicBool::new(false),
                worker: Mutex::new(None),
                output: Mutex::new(None),
            });
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
                    "native blocked-result pipe"
                );
                (
                    Some(unsafe { std::fs::File::from_raw_handle(reader) }),
                    Some(unsafe { std::fs::File::from_raw_handle(writer) }),
                )
            };
            let blocked_handle = reader.as_ref().map(AsRawHandle::as_raw_handle);
            let safety_writer = writer.as_ref().map(std::fs::File::try_clone).transpose()?;
            let safety_gate = gate.clone();
            let (stop_watchdog, stop) = std::sync::mpsc::channel();
            let watchdog = std::thread::spawn(move || {
                if matches!(
                    stop.recv_timeout(Duration::from_secs(3)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ) {
                    safety_gate.release.store(true, Ordering::Release);
                    if let Some(mut writer) = safety_writer {
                        use std::io::Write;
                        let _ = writer.write_all(b"R");
                    }
                }
            });
            let fixture = Fixture {
                gate: gate.clone(),
                slot,
                writer,
                stop_watchdog: Some(stop_watchdog),
                watchdog: Some(watchdog),
            };
            let backend = Arc::new(NativeFaultBackend {
                gate: gate.clone(),
                slot,
                reader,
            });
            let weak_backend = Arc::downgrade(&backend);
            let control = super::super::ExecutionControl::default();
            let request=ExecutionRequest {
                ids:crate::events::new_execution_ids(),control:control.clone(),
                command:vec!["python".into(),"-u".into(),"-c".into(),
                    "import os,pathlib,sys,time; pathlib.Path('target.pid').write_text(str(os.getpid())); print('READY',flush=True); deadline=time.monotonic()+5\nwhile not pathlib.Path('release').exists() and time.monotonic()<deadline: time.sleep(.005)\nsys.exit(7)".into()],
                cwd:tmp.path().to_owned(),policy:crate::policy::normalize_policy(&json!("danger-full-access"),tmp.path(),None)
                    .map_err(|error|anyhow::anyhow!(error.reason))?,
                stdin:ExecutionStdin::Empty,control_input:None,io:crate::backend::ExecutionIo::Pipe,
                env:ExecutionEnv::default(),metadata:None,timeout:Some(Duration::from_secs(30)),
            };
            let journal = ExecutionJournal::prepare(&request)
                .map_err(|error| anyhow::anyhow!(error.reason))?;
            let mut target = None;
            let mut events = Vec::new();
            let error = execute_prepared_with_backend(
                request,
                journal,
                &mut |event: &Value| {
                    let pid_path = tmp.path().join("target.pid");
                    if target.is_none() && pid_path.exists() {
                        let pid = std::fs::read_to_string(pid_path)
                            .ok()
                            .and_then(|text| text.parse().ok())
                            .unwrap_or(0);
                        let handle = unsafe {
                            OpenProcess(
                                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                0,
                                pid,
                            )
                        };
                        if !handle.is_null() {
                            target = Some(unsafe { OwnedHandle::from_raw_handle(handle) });
                            std::fs::write(tmp.path().join("release"), b"R").map_err(|_| {
                                RunSealError::new("INTERNAL_ERROR", "target release")
                            })?;
                        }
                    }
                    events.push(event.clone());
                    Ok(())
                },
                backend,
            )
            .expect_err("pending native backend cannot report cleanup success");
            let (native_pending, retained, id) = {
                let worker = gate
                    .worker
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let (handle, id) = worker
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("worker observation"))?;
                (
                    unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) } == WAIT_TIMEOUT,
                    super::super::retained::contains(*id),
                    *id,
                )
            };
            let blocked_owner_preserved = exit_callback
                || (weak_backend.upgrade().is_some()
                    && blocked_handle
                        .is_some_and(|handle| unsafe { GetFileType(handle) } == FILE_TYPE_PIPE));
            let mut native_exit = u32::MAX;
            let target_gone = target.as_ref().is_some_and(|handle| unsafe {
                WaitForSingleObject(handle.as_raw_handle(), 0) == WAIT_OBJECT_0
                    && GetExitCodeProcess(handle.as_raw_handle(), &mut native_exit) != 0
            });
            let entered = gate.entered.load(Ordering::Acquire);
            let terminal = error
                .terminal_event
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("terminal"))?
                .clone();
            let audit = std::fs::read_to_string(
                tmp.path()
                    .join(terminal["audit_path"].as_str().context("audit path")?),
            )?;
            let records: Vec<Value> = audit
                .lines()
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()?;
            // Record all ownership and audit facts before releasing the actual
            // blocked native call/callback. Join only this fixture before asserts.
            drop(fixture);
            assert!(!super::super::retained::contains(id));
            assert!(weak_backend.upgrade().is_none());
            assert!(entered && native_pending && retained && blocked_owner_preserved);
            assert!(target_gone);
            assert_eq!(native_exit, 7);
            assert_eq!(error.code, "EXECUTION_CLEANUP_FAILED");
            assert_eq!(terminal["result"]["cleanup_complete"], false);
            assert_eq!(terminal["result"]["termination_reason"], "cleanup_failed");
            assert_eq!(
                terminal["result"]["requested_termination_reason"],
                if exit_callback { "exited" } else { "cancelled" }
            );
            assert_eq!(
                terminal["result"]["exit_code"],
                if exit_callback { json!(7) } else { Value::Null }
            );
            assert!(terminal["result"]["started_at"].is_string());
            assert_eq!(records.last(), Some(&terminal));
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(
                        event["type"].as_str(),
                        Some("execution.finished" | "execution.failed")
                    ))
                    .count(),
                1
            );
            assert_eq!(
                records
                    .iter()
                    .filter(|event| matches!(
                        event["type"].as_str(),
                        Some("execution.finished" | "execution.failed")
                    ))
                    .count(),
                1
            );
        }
        Ok(())
    }
    #[derive(Default)]
    struct CleanupFactObserver {
        events: Vec<Value>,
        confirmed: Option<bool>,
    }
    impl ExecutionObserver for CleanupFactObserver {
        fn event(&mut self, event: &Value) -> Result<(), RunSealError> {
            if matches!(
                event["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            ) {
                assert!(
                    self.confirmed.is_some(),
                    "cleanup facts must reach resources before terminal"
                );
            }
            self.events.push(event.clone());
            Ok(())
        }
        fn cleanup(
            &mut self,
            _deadline: Instant,
            execution_cleanup_confirmed: bool,
        ) -> Result<(), RunSealError> {
            self.confirmed = Some(execution_cleanup_confirmed);
            Ok(())
        }
    }
    impl SandboxBackend for AfterNativeExitFault {
        fn name(&self) -> &'static str {
            active_backend().name()
        }
        fn status(&self) -> &'static str {
            active_backend().status()
        }
        fn platform(&self) -> &'static str {
            active_backend().platform()
        }
        fn supported_features(&self) -> &'static [BackendFeature] {
            active_backend().supported_features()
        }
        fn capabilities_json(&self) -> Value {
            active_backend().capabilities_json()
        }
        fn compile_plan(
            &self,
            id: &str,
            cwd: &Path,
            policy: &SandboxPolicy,
        ) -> Result<PlatformSandboxPlan, BackendError> {
            active_backend().compile_plan(id, cwd, policy)
        }
        fn execute_plan(
            &self,
            plan: &PlatformSandboxPlan,
            command: &[String],
            cwd: &Path,
            stdin: ExecutionStdin,
            env: &ExecutionEnv,
            options: BackendExecutionOptions,
        ) -> io::Result<BackendExecutionOutput> {
            let control = options.output.as_ref().map(|sink| sink.control.clone());
            let output = active_backend().execute_plan(plan, command, cwd, stdin, env, options)?;
            assert!(
                output.cleanup_complete,
                "the delegate must verify its native process range"
            );
            let code = output
                .output
                .status
                .code()
                .ok_or_else(|| io::Error::other("native exit status"))?;
            if let (Some(control), Some(cause)) = (control, self.earlier_cause) {
                control.request(cause);
            }
            if self.unverified_failure {
                return Err(io::Error::other("controlled private backend fault canary"));
            }
            if self.cleanup_failure {
                Err(io::Error::other(crate::backend::BackendCleanupFacts {
                    exit_code: Some(code),
                    timed_out: output.timed_out,
                }))
            } else {
                Err(io::Error::other(crate::backend::BackendInputFacts {
                    exit_code: code,
                    timed_out: output.timed_out,
                }))
            }
        }
    }

    #[test]
    fn native_exit_failure_facts_reach_one_durable_terminal_without_start_failure_or_cause_replacement()
    -> anyhow::Result<()> {
        for cleanup_failure in [false, true] {
            for earlier_cause in [
                None,
                Some(super::super::TerminationCause::Cancelled),
                Some(super::super::TerminationCause::Exited),
            ] {
                let tmp = tempfile::TempDir::new()?;
                let request = ExecutionRequest {
                    ids: crate::events::new_execution_ids(), control: super::super::ExecutionControl::default(),
                    command: vec!["python".into(), "-u".into(), "-c".into(), "import pathlib,sys; pathlib.Path('target.ran').write_text('ready'); print('TARGET',flush=True); sys.exit(7)".into()],
                    cwd: tmp.path().to_owned(), policy: crate::policy::normalize_policy(&json!("danger-full-access"), tmp.path(), None).map_err(|error| anyhow::anyhow!(error.reason))?,
                    stdin: ExecutionStdin::Empty, control_input: None, io: crate::backend::ExecutionIo::Pipe,
                    env: ExecutionEnv::default(), metadata: None, timeout: Some(std::time::Duration::from_secs(5)),
                };
                let journal = ExecutionJournal::prepare(&request)
                    .map_err(|error| anyhow::anyhow!(error.reason))?;
                let mut observer = CleanupFactObserver::default();
                let error = execute_prepared_with_backend(
                    request,
                    journal,
                    &mut observer,
                    std::sync::Arc::new(AfterNativeExitFault {
                        cleanup_failure,
                        unverified_failure: false,
                        earlier_cause,
                    }),
                )
                .expect_err("injected backend failure must be observable");
                assert_eq!(observer.confirmed, Some(!cleanup_failure));
                let events = observer.events;
                assert!(tmp.path().join("target.ran").exists());
                let terminals: Vec<_> = events
                    .iter()
                    .filter(|event| {
                        matches!(
                            event["type"].as_str(),
                            Some("execution.finished" | "execution.failed")
                        )
                    })
                    .collect();
                assert_eq!(terminals.len(), 1);
                let terminal = terminals[0];
                assert_eq!(terminal["result"]["exit_code"], 7);
                assert!(terminal["result"]["started_at"].is_string());
                assert_eq!(terminal["result"]["cleanup_complete"], !cleanup_failure);
                let original = if let Some(cause) = earlier_cause {
                    cause.as_str()
                } else if cleanup_failure {
                    "exited"
                } else {
                    "input_failed"
                };
                assert_eq!(terminal["result"]["requested_termination_reason"], original);
                assert_eq!(
                    terminal["result"]["termination_reason"],
                    if cleanup_failure {
                        "cleanup_failed"
                    } else {
                        original
                    }
                );
                assert_eq!(
                    error.code,
                    if cleanup_failure {
                        "EXECUTION_CLEANUP_FAILED"
                    } else if earlier_cause == Some(super::super::TerminationCause::Cancelled) {
                        "EXECUTION_CANCELLED"
                    } else {
                        "EXECUTION_INPUT_FAILED"
                    }
                );
                let audit = std::fs::read_to_string(
                    tmp.path().join(
                        terminal["audit_path"]
                            .as_str()
                            .ok_or_else(|| anyhow::anyhow!("audit path"))?,
                    ),
                )?;
                let records: Vec<Value> = audit
                    .lines()
                    .map(serde_json::from_str)
                    .collect::<Result<_, _>>()?;
                assert_eq!(records.last(), Some(terminal));
                assert_eq!(
                    records
                        .iter()
                        .filter(|event| matches!(
                            event["type"].as_str(),
                            Some("execution.finished" | "execution.failed")
                        ))
                        .count(),
                    1
                );
            }
        }
        Ok(())
    }

    #[test]
    fn unverified_backend_failure_after_native_start_keeps_exit_unknown_and_refuses_cleanup_success()
    -> anyhow::Result<()> {
        for earlier_cause in [None, Some(super::super::TerminationCause::Cancelled)] {
            let tmp = tempfile::TempDir::new()?;
            let request=ExecutionRequest {
                ids:crate::events::new_execution_ids(), control:super::super::ExecutionControl::default(),
                command:vec!["python".into(),"-u".into(),"-c".into(),"import pathlib,sys; pathlib.Path('target.ran').write_text('ready'); print('TARGET',flush=True); sys.exit(7)".into()],
                cwd:tmp.path().to_owned(),policy:crate::policy::normalize_policy(&json!("danger-full-access"),tmp.path(),None).map_err(|error|anyhow::anyhow!(error.reason))?,
                stdin:ExecutionStdin::Empty,control_input:None,io:crate::backend::ExecutionIo::Pipe,env:ExecutionEnv::default(),metadata:None,timeout:Some(std::time::Duration::from_secs(5)),
            };
            let journal = ExecutionJournal::prepare(&request)
                .map_err(|error| anyhow::anyhow!(error.reason))?;
            let mut observer = CleanupFactObserver::default();
            let error = execute_prepared_with_backend(
                request,
                journal,
                &mut observer,
                std::sync::Arc::new(AfterNativeExitFault {
                    cleanup_failure: false,
                    unverified_failure: true,
                    earlier_cause,
                }),
            )
            .expect_err("unverified backend result must fail closed");
            assert_eq!(observer.confirmed, Some(false));
            let events = observer.events;
            assert!(tmp.path().join("target.ran").exists());
            assert_eq!(error.code, "EXECUTION_CLEANUP_FAILED");
            let terminals: Vec<_> = events
                .iter()
                .filter(|event| {
                    matches!(
                        event["type"].as_str(),
                        Some("execution.finished" | "execution.failed")
                    )
                })
                .collect();
            assert_eq!(terminals.len(), 1);
            let terminal = terminals[0];
            assert!(terminal["result"]["started_at"].is_string());
            assert!(
                terminal["result"]["exit_code"].is_null(),
                "private native facts were not provided to owner"
            );
            assert_eq!(terminal["result"]["cleanup_complete"], false);
            assert_eq!(terminal["result"]["termination_reason"], "cleanup_failed");
            assert_eq!(
                terminal["result"]["requested_termination_reason"],
                earlier_cause.map_or("execution_failed", super::super::TerminationCause::as_str)
            );
            let audit = std::fs::read_to_string(
                tmp.path().join(
                    terminal["audit_path"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("audit path"))?,
                ),
            )?;
            assert!(!audit.contains("controlled private backend fault canary"));
            assert!(
                !error
                    .message
                    .contains("controlled private backend fault canary")
            );
            let records: Vec<Value> = audit
                .lines()
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()?;
            assert_eq!(records.last(), Some(terminal));
            assert_eq!(
                records
                    .iter()
                    .filter(|event| matches!(
                        event["type"].as_str(),
                        Some("execution.finished" | "execution.failed")
                    ))
                    .count(),
                1
            );
        }
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod frontend_tests {
    use super::*;
    use std::io::{BufRead, Read, Write};
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::time::Duration;

    #[test]
    fn pending_native_timer_exit_fails_real_execution_before_unique_durable_terminal()
    -> anyhow::Result<()> {
        use std::cell::{Cell, RefCell};
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        };
        use windows_sys::Win32::Foundation::{
            DUPLICATE_SAME_ACCESS, DuplicateHandle, WAIT_OBJECT_0, WAIT_TIMEOUT,
        };
        use windows_sys::Win32::System::Threading::{
            FlsAlloc, FlsFree, FlsSetValue, GetCurrentProcess, GetCurrentThread,
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SYNCHRONIZE, WaitForSingleObject,
        };
        struct Gate {
            entered: AtomicBool,
            release: AtomicBool,
        }
        unsafe extern "system" fn hold_exit(value: *const std::ffi::c_void) {
            let gate = unsafe { Arc::from_raw(value.cast::<Gate>()) };
            gate.entered.store(true, Ordering::Release);
            while !gate.release.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        struct Fixture {
            gate: Arc<Gate>,
            slot: u32,
            timer: RefCell<Option<(OwnedHandle, std::thread::ThreadId)>>,
            worker_created: Cell<bool>,
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                self.gate.release.store(true, Ordering::Release);
                let finished = self.timer.borrow().as_ref().map_or(
                    !self.worker_created.get(),
                    |(handle, id)| {
                        let finished = unsafe {
                            WaitForSingleObject(handle.as_raw_handle(), 2000) == WAIT_OBJECT_0
                        };
                        if finished {
                            let _ = super::super::retained::join_finished(*id);
                        }
                        finished
                    },
                );
                if finished {
                    unsafe { FlsFree(self.slot) };
                }
            }
        }
        let gate = Arc::new(Gate {
            entered: AtomicBool::new(false),
            release: AtomicBool::new(false),
        });
        let slot = unsafe { FlsAlloc(Some(hold_exit)) };
        anyhow::ensure!(slot != u32::MAX, "native timer exit slot");
        let fixture = Fixture {
            gate,
            slot,
            timer: RefCell::new(None),
            worker_created: Cell::new(false),
        };
        let tmp = tempfile::TempDir::new()?;
        let python = String::from_utf8(Command::new("where.exe").arg("python").output()?.stdout)?
            .lines()
            .next()
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("Python required"))?;
        let control = super::super::ExecutionControl::default();
        let request = ExecutionRequest {
            ids: crate::events::new_execution_ids(), control: control.clone(),
            command: vec![python, "-u".into(), "-c".into(),
                "import os,pathlib,sys,time; pathlib.Path('target.pid').write_text(str(os.getpid())); print('READY',flush=True); deadline=time.monotonic()+5\nwhile not pathlib.Path('release').exists() and time.monotonic()<deadline: time.sleep(.01)\nsys.exit(7)".into()],
            cwd: tmp.path().to_owned(),
            policy: crate::policy::normalize_policy(&json!("danger-full-access"),tmp.path(),None)
                .map_err(|error|anyhow::anyhow!(error.reason))?,
            stdin: crate::backend::ExecutionStdin::Empty, control_input: None,
            io: crate::backend::ExecutionIo::Pipe, env: crate::backend::ExecutionEnv::default(),
            metadata: None, timeout: Some(Duration::from_secs(30)),
        };
        let journal =
            ExecutionJournal::prepare(&request).map_err(|error| anyhow::anyhow!(error.reason))?;
        let mut target = None;
        let mut events = Vec::new();
        let mut terminal_observed_while_timer_pending = false;
        let mut terminal_observed_after_target_exit = false;
        let mut terminal_already_durable = false;
        let mut observer = |event: &Value| {
            let pid_path = tmp.path().join("target.pid");
            if target.is_none() && pid_path.exists() {
                let pid: u32 = std::fs::read_to_string(&pid_path)
                    .ok()
                    .and_then(|text| text.parse().ok())
                    .unwrap_or(0);
                let handle = unsafe {
                    OpenProcess(
                        PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                        0,
                        pid,
                    )
                };
                if !handle.is_null() {
                    target = Some(unsafe { OwnedHandle::from_raw_handle(handle) });
                    std::fs::write(tmp.path().join("release"), b"R")
                        .map_err(|_| RunSealError::new("INTERNAL_ERROR", "target release"))?;
                }
            }
            if matches!(
                event["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            ) {
                terminal_observed_while_timer_pending =
                    fixture.gate.entered.load(Ordering::Acquire)
                        && fixture
                            .timer
                            .borrow()
                            .as_ref()
                            .is_some_and(|(handle, _)| unsafe {
                                WaitForSingleObject(handle.as_raw_handle(), 0) == WAIT_TIMEOUT
                            });
                terminal_observed_after_target_exit =
                    target.as_ref().is_some_and(|handle| unsafe {
                        WaitForSingleObject(handle.as_raw_handle(), 0) == WAIT_OBJECT_0
                    });
                terminal_already_durable = event["audit_path"]
                    .as_str()
                    .and_then(|path| std::fs::read_to_string(tmp.path().join(path)).ok())
                    .and_then(|audit| audit.lines().last().map(str::to_owned))
                    .and_then(|line| serde_json::from_str::<Value>(&line).ok())
                    .as_ref()
                    == Some(event);
            }
            events.push(event.clone());
            Ok(())
        };
        // Only worker initialization is injected. The actual timer wait,
        // lifecycle owner, local backend, and durable journal remain in use.
        let timer_gate = fixture.gate.clone();
        let (sender, initialized) = mpsc::channel();
        let outcome = execute_prepared_with_backend_and_timer(
            request,
            journal,
            &mut observer,
            std::sync::Arc::new(active_backend()),
            &mut |start, timeout, control| {
                let gate = timer_gate.clone();
                let sender = sender.clone();
                let timer = super::super::control::ExecutionDeadline::start_with(
                    start,
                    timeout,
                    control,
                    move || {
                        let pointer = Arc::into_raw(gate);
                        if unsafe { FlsSetValue(slot, pointer.cast()) } == 0 {
                            drop(unsafe { Arc::from_raw(pointer) });
                            return;
                        }
                        let process = unsafe { GetCurrentProcess() };
                        let mut handle = std::ptr::null_mut();
                        if unsafe {
                            DuplicateHandle(
                                process,
                                GetCurrentThread(),
                                process,
                                &mut handle,
                                0,
                                0,
                                DUPLICATE_SAME_ACCESS,
                            )
                        } != 0
                        {
                            let _ = sender.send((
                                unsafe { OwnedHandle::from_raw_handle(handle) },
                                std::thread::current().id(),
                            ));
                        }
                    },
                )?;
                fixture.worker_created.set(timer.is_some());
                // The observer reads the duplicated handle through this cell.
                *fixture.timer.borrow_mut() = Some(
                    initialized
                        .recv_timeout(Duration::from_secs(2))
                        .map_err(std::io::Error::other)?,
                );
                Ok(timer)
            },
            None,
        );
        let pending_retained = fixture
            .timer
            .borrow()
            .as_ref()
            .is_some_and(|(_, id)| super::super::retained::contains(*id));
        let mut native_exit = u32::MAX;
        let native_exit_known = target.as_ref().is_some_and(|handle| unsafe {
            GetExitCodeProcess(handle.as_raw_handle(), &mut native_exit) != 0
        });
        let timer_id = fixture.timer.borrow().as_ref().map(|(_, id)| *id);
        fixture.gate.release.store(true, Ordering::Release);
        let released_native_timer =
            fixture
                .timer
                .borrow()
                .as_ref()
                .is_some_and(|(handle, _)| unsafe {
                    WaitForSingleObject(handle.as_raw_handle(), 2000) == WAIT_OBJECT_0
                });
        drop(fixture);
        assert!(released_native_timer);
        assert!(timer_id.is_some_and(|id| !super::super::retained::contains(id)));
        assert!(outcome.is_err(), "pending timer must fail cleanup");
        let error = outcome.expect_err("verified error");
        assert!(terminal_observed_while_timer_pending && pending_retained);
        assert!(terminal_observed_after_target_exit && native_exit_known);
        assert_eq!(native_exit, 7);
        assert!(terminal_already_durable);
        assert_eq!(error.code, "EXECUTION_CLEANUP_FAILED");
        let terminals: Vec<_> = events
            .iter()
            .filter(|event| {
                matches!(
                    event["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                )
            })
            .collect();
        assert_eq!(terminals.len(), 1);
        let result = &terminals[0]["result"];
        assert_eq!(result["exit_code"], 7);
        assert_eq!(result["cleanup_complete"], false);
        assert_eq!(result["termination_reason"], "cleanup_failed");
        assert_eq!(result["requested_termination_reason"], "exited");
        assert_eq!(
            control.cause(),
            Some(super::super::TerminationCause::Exited)
        );
        let audit = std::fs::read_to_string(
            tmp.path()
                .join(terminals[0]["audit_path"].as_str().expect("audit path")),
        )?;
        let records: Vec<Value> = audit
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        assert_eq!(records.last(), Some(terminals[0]));
        assert_eq!(
            records
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

    struct PipeFrontend {
        child: Child,
        input: Option<ChildStdin>,
        reader: Option<std::thread::JoinHandle<std::io::Result<Vec<u8>>>>,
        events: Vec<Value>,
        attempted: bool,
        release: bool,
    }

    impl PipeFrontend {
        fn release_and_join(&mut self) -> anyhow::Result<()> {
            if let Some(mut input) = self.input.take() {
                input.write_all(b"R")?;
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while self
                .reader
                .as_ref()
                .is_some_and(|reader| !reader.is_finished())
            {
                anyhow::ensure!(
                    Instant::now() < deadline,
                    "frontend reader release deadline"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            if let Some(reader) = self.reader.take() {
                let bytes = reader
                    .join()
                    .map_err(|_| anyhow::anyhow!("frontend reader panic"))??;
                assert_eq!(std::str::from_utf8(&bytes)?.trim(), "DRAINED");
            }
            assert!(self.child.wait()?.success());
            Ok(())
        }
    }

    impl ExecutionObserver for PipeFrontend {
        fn event(&mut self, event: &Value) -> Result<(), RunSealError> {
            if matches!(
                event["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            ) {
                assert!(self.attempted, "terminal cannot precede frontend cleanup");
                if self.release {
                    assert!(self.reader.is_none());
                    assert_eq!(event["result"]["cleanup_complete"], true);
                } else {
                    assert!(
                        self.reader
                            .as_ref()
                            .is_some_and(|reader| !reader.is_finished())
                    );
                    assert!(
                        self.child
                            .try_wait()
                            .map_err(|_| RunSealError::new(
                                "INTERNAL_ERROR",
                                "frontend status unavailable"
                            ))?
                            .is_none()
                    );
                    assert_eq!(event["result"]["cleanup_complete"], false);
                    assert_eq!(event["result"]["termination_reason"], "cleanup_failed");
                    assert_eq!(event["result"]["requested_termination_reason"], "exited");
                }
            }
            self.events.push(event.clone());
            Ok(())
        }

        fn cleanup(
            &mut self,
            _deadline: Instant,
            _execution_cleanup_confirmed: bool,
        ) -> Result<(), RunSealError> {
            self.attempted = true;
            if self.release {
                return self.release_and_join().map_err(|_| {
                    RunSealError::new("EXECUTION_CLEANUP_FAILED", "frontend reader join failed")
                });
            }
            let deadline = Instant::now() + Duration::from_millis(50);
            while self
                .reader
                .as_ref()
                .is_some_and(|reader| !reader.is_finished())
            {
                if Instant::now() >= deadline {
                    return Err(RunSealError::new(
                        "EXECUTION_CLEANUP_FAILED",
                        "frontend pipe reader cleanup deadline",
                    ));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            panic!("unreleased pipe must remain active");
        }
    }

    impl Drop for PipeFrontend {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
        }
    }

    #[test]
    fn closed_frontend_pipe_before_spawn_retains_disconnect_cause() -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let python = String::from_utf8(Command::new("where.exe").arg("python").output()?.stdout)?
            .lines()
            .next()
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("Python required"))?;
        let mut recipient = Command::new(&python)
            .args(["-c", "pass"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut pipe = recipient
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("frontend pipe"))?;
        assert!(recipient.wait()?.success());
        let request = ExecutionRequest {
            ids: crate::events::new_execution_ids(),
            control: super::super::ExecutionControl::default(),
            command: vec![
                python,
                "-c".into(),
                "import pathlib; pathlib.Path('must-not-run').write_text('ran')".into(),
            ],
            cwd: tmp.path().to_owned(),
            policy: crate::policy::normalize_policy(&json!("danger-full-access"), tmp.path(), None)
                .map_err(|error| anyhow::anyhow!(error.reason))?,
            stdin: crate::backend::ExecutionStdin::Empty,
            control_input: None,
            io: crate::backend::ExecutionIo::Pipe,
            env: crate::backend::ExecutionEnv::default(),
            metadata: None,
            timeout: Some(Duration::from_secs(2)),
        };
        let error = execute_command_with_events(request, &mut |event| {
            if event["type"] == "execution.requested" {
                pipe.write_all(b"frame")
                    .map_err(|_| RunSealError::new("CLIENT_DISCONNECTED", "output disconnected"))?;
            }
            Ok(())
        })
        .expect_err("closed pipe must reject before spawn");
        assert_eq!(error.code, "CLIENT_DISCONNECTED");
        let terminal = error.terminal_event.expect("terminal");
        assert_eq!(
            terminal["result"]["termination_reason"],
            "client_disconnected"
        );
        assert_eq!(terminal["result"]["cleanup_complete"], true);
        assert!(terminal["result"]["started_at"].is_null());
        assert!(terminal["result"]["exit_code"].is_null());
        assert!(!tmp.path().join("must-not-run").exists());
        let audit = std::fs::read_to_string(
            tmp.path()
                .join(terminal["audit_path"].as_str().expect("audit path")),
        )?;
        let records: Vec<Value> = audit
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        assert_eq!(records.last(), Some(&terminal));
        assert_eq!(
            records
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

    #[test]
    fn real_frontend_pipe_cleanup_precedes_unique_durable_terminal() -> anyhow::Result<()> {
        let python = String::from_utf8(Command::new("where.exe").arg("python").output()?.stdout)?
            .lines()
            .next()
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("Python required"))?;
        for release in [true, false] {
            let tmp = tempfile::TempDir::new()?;
            let mut child = Command::new(&python).args(["-u","-c","import sys; print('READY',flush=True); assert sys.stdin.buffer.read(1)==b'R'; print('DRAINED',flush=True)"])
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?;
            let input = child.stdin.take();
            let stdout = child.stdout.take().expect("frontend pipe");
            let (sender, ready) = std::sync::mpsc::channel();
            let reader = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
                let mut stdout = std::io::BufReader::new(stdout);
                let mut line = String::new();
                stdout.read_line(&mut line)?;
                assert_eq!(line.trim(), "READY");
                sender.send(()).expect("readiness receiver");
                let mut bytes = Vec::new();
                stdout.read_to_end(&mut bytes)?;
                Ok(bytes)
            });
            let mut frontend = PipeFrontend {
                child,
                input,
                reader: Some(reader),
                events: Vec::new(),
                attempted: false,
                release,
            };
            ready.recv_timeout(Duration::from_secs(2))?;
            let request = ExecutionRequest {
                ids:crate::events::new_execution_ids(), control:super::super::ExecutionControl::default(),
                command:vec![python.clone(),"-u".into(),"-c".into(),"import pathlib,sys; pathlib.Path('target.ran').write_text('ready'); print('TARGET',flush=True); sys.exit(7)".into()],
                cwd:tmp.path().to_owned(), policy:crate::policy::normalize_policy(&json!("danger-full-access"),tmp.path(),None).map_err(|error|anyhow::anyhow!(error.reason))?,
                stdin:crate::backend::ExecutionStdin::Empty, control_input:None, io:crate::backend::ExecutionIo::Pipe,
                env:crate::backend::ExecutionEnv::default(), metadata:None, timeout:Some(Duration::from_secs(2)),
            };
            let outcome = execute_command_with_observer(request, &mut frontend);
            assert!(tmp.path().join("target.ran").exists());
            if release {
                assert_eq!(
                    outcome.map_err(|error| anyhow::anyhow!(error.message))?.1["exit_code"],
                    7
                );
            } else {
                let error = outcome.expect_err("cleanup failure required");
                assert_eq!(error.code, "EXECUTION_CLEANUP_FAILED");
                assert_eq!(error.details.as_ref().expect("details")["exit_code"], 7);
                frontend.release_and_join()?;
            }
            let terminals: Vec<_> = frontend
                .events
                .iter()
                .filter(|event| {
                    matches!(
                        event["type"].as_str(),
                        Some("execution.finished" | "execution.failed")
                    )
                })
                .collect();
            assert_eq!(terminals.len(), 1);
            let terminal = terminals[0];
            assert_eq!(terminal["result"]["sandbox"]["level"], "danger-full-access");
            assert_eq!(terminal["result"]["sandbox"]["enforced"], false);
            let audit = std::fs::read_to_string(
                tmp.path()
                    .join(terminal["audit_path"].as_str().expect("audit path")),
            )?;
            let durable: Vec<Value> = audit
                .lines()
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()?;
            assert_eq!(durable.last(), Some(terminal));
            assert_eq!(
                durable
                    .iter()
                    .filter(|event| matches!(
                        event["type"].as_str(),
                        Some("execution.finished" | "execution.failed")
                    ))
                    .count(),
                1
            );
        }
        Ok(())
    }
}
