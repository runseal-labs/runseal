use super::*;
use std::thread::JoinHandle;
use std::time::Duration;

pub(super) struct ReadyAdmission {
    pub active: ActiveExecution,
    pub start: SyncSender<()>,
}

pub(super) enum AdmissionMessage {
    Ready(ReadyAdmission),
    Rejected(RunSealError),
}

pub(super) struct PendingAdmission {
    pub id: Value,
    pub control: ExecutionControl,
    pub worker: Option<JoinHandle<()>>,
    pub receiver: Receiver<AdmissionMessage>,
    pub accept: SyncSender<Result<(), RunSealError>>,
    pub rejection: Option<RunSealError>,
}

pub(super) struct OwnedWorker {
    pub execution_id: String,
    pub control: ExecutionControl,
    pub thread: JoinHandle<()>,
}

pub(super) fn spawn(
    id: Value,
    params: Value,
    lifecycle: SyncSender<LifecycleMessage>,
) -> Result<PendingAdmission, RunSealError> {
    spawn_with(id, params, lifecycle, || {})
}

fn spawn_with<F: FnOnce() + Send + 'static>(
    id: Value,
    params: Value,
    lifecycle: SyncSender<LifecycleMessage>,
    before_prepare: F,
) -> Result<PendingAdmission, RunSealError> {
    let control = ExecutionControl::default();
    let owner_control = control.clone();
    let (messages, receiver) = mpsc::channel();
    let (accept, accepted) = mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name("runseal-admission".into())
        .spawn(move || {
            before_prepare();
            if let Err(error) = prepare_and_run(
                params,
                owner_control.clone(),
                lifecycle,
                &messages,
                accepted,
            ) {
                owner_control.request(crate::execution::TerminationCause::FailedToStart);
                let _ = messages.send(AdmissionMessage::Rejected(error));
            }
        })
        .map_err(|_| {
            RunSealError::with_details(
                "EXECUTION_FAILED_TO_START",
                "execution admission worker unavailable",
                json!({"cleanup_complete":true}),
            )
        })?;
    Ok(PendingAdmission {
        id,
        control,
        worker: Some(worker),
        receiver,
        accept,
        rejection: None,
    })
}

fn finish_admission_error(
    journal: crate::execution::ExecutionJournal,
    control: &ExecutionControl,
    mut error: RunSealError,
) -> RunSealError {
    control.request(crate::execution::TerminationCause::FailedToStart);
    let details = error.details.get_or_insert_with(|| json!({}));
    if let Some(object) = details.as_object_mut() {
        object
            .entry("cleanup_complete")
            .or_insert_with(|| Value::Bool(true));
    }
    match journal.finish(Err(error), control, &mut |_| Ok(())) {
        Err(error) => error,
        Ok(_) => RunSealError::new(
            "INTERNAL_ERROR",
            "admission failure was not recorded as a terminal event",
        ),
    }
}

fn compile_backend_error(
    error: crate::backend::BackendError,
    cwd: &std::path::Path,
) -> RunSealError {
    let details = error.details_json();
    let code = error.code;
    let reason = error.reason;
    let details = attach_windows_setup_status(details, code, cwd);
    RunSealError::with_details(code, reason, details)
}

fn reservation_error(
    error: &std::io::Error,
    cwd: &std::path::Path,
    plan: &crate::backend::PlatformSandboxPlan,
) -> RunSealError {
    let cleanup_complete = !crate::backend::cleanup_failed(error);
    let code = if !cleanup_complete {
        "EXECUTION_CLEANUP_FAILED"
    } else if crate::backend::policy_transition_busy_reason(error).is_some() {
        "POLICY_TRANSITION_BUSY"
    } else {
        "BACKEND_UNAVAILABLE"
    };
    let details = attach_windows_setup_status(
        json!({
            "cleanup_complete":cleanup_complete,
            "platform_plan": plan.json(),
        }),
        code,
        cwd,
    );
    RunSealError::with_details(code, "execution admission rejected", details)
}

#[cfg(windows)]
fn attach_windows_setup_status(mut details: Value, code: &str, cwd: &std::path::Path) -> Value {
    if code == "BACKEND_UNAVAILABLE"
        && let Some(object) = details.as_object_mut()
    {
        object.insert(
            "setup_status".to_string(),
            crate::execution::windows_setup_status_for_backend_error(cwd),
        );
    }
    details
}

#[cfg(not(windows))]
fn attach_windows_setup_status(details: Value, _code: &str, _cwd: &std::path::Path) -> Value {
    details
}

fn prepare_and_run(
    params: Value,
    control: ExecutionControl,
    sender: SyncSender<LifecycleMessage>,
    messages: &mpsc::Sender<AdmissionMessage>,
    accepted: Receiver<Result<(), RunSealError>>,
) -> Result<(), RunSealError> {
    let mut request = execution_request_from_params(&params)?;
    request.control = control.clone();
    if control.is_cancelled() {
        return Err(RunSealError::new(
            "CLIENT_DISCONNECTED",
            "execution admission stopped",
        ));
    }
    if request.policy.requires_broad_write_approval()
        || request.policy.denies_execution_without_backend()
    {
        let approval = request.policy.requires_broad_write_approval()
            || request.policy.approval.on_violation == "request";
        let code = if approval {
            "APPROVAL_REQUIRED"
        } else {
            "POLICY_DENIED"
        };
        let reason = if request.policy.requires_broad_write_approval() {
            "filesystem broad write requires approval"
        } else {
            "filesystem write denied by policy"
        };
        return Err(crate::execution::ExecutionJournal::prepare(&request)?.reject(code, reason));
    }
    let mut journal = crate::execution::ExecutionJournal::prepare(&request)?;
    let plan = match crate::backend::active_backend().compile_plan(
        &request.ids.execution_id,
        &request.cwd,
        &request.policy,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            return Err(finish_admission_error(
                journal,
                &control,
                compile_backend_error(error, &request.cwd),
            ));
        }
    };
    if control.is_cancelled() {
        return Err(finish_admission_error(
            journal,
            &control,
            RunSealError::new("CLIENT_DISCONNECTED", "execution admission stopped"),
        ));
    }
    let mut reservation = match crate::backend::reserve_execution(&plan) {
        Ok(reservation) => reservation,
        Err(error) => {
            return Err(finish_admission_error(
                journal,
                &control,
                reservation_error(&error, &request.cwd, &plan),
            ));
        }
    };
    let execution_id = request.ids.execution_id.clone();
    let policy_hash = request.policy.hash();
    let receipt = json!({"execution_id":execution_id,"session_id":request.ids.session_id,"status":"preparing","policy_id":request.policy.id,"policy_hash":policy_hash,"policy_epoch":policy_hash,"stderr_merged":request.io.is_pty()});
    let (start, ready) = mpsc::sync_channel(1);
    let active = ActiveExecution {
        result: receipt,
        control: control.clone(),
        sequence: 0,
        audit_metadata: request
            .metadata
            .as_ref()
            .map(crate::audit::redact_audit_value),
        control_input: request.control_input.clone(),
        stdin: match &request.stdin {
            ExecutionStdin::Stream(queue) => Some(queue.clone()),
            _ => None,
        },
    };
    let delivered = messages
        .send(AdmissionMessage::Ready(ReadyAdmission { active, start }))
        .is_ok();
    let disconnected = || RunSealError::new("CLIENT_DISCONNECTED", "execution admission stopped");
    let permit = if delivered {
        loop {
            match accepted.recv_timeout(Duration::from_millis(5)) {
                Ok(permit) => break permit,
                // The controller owns the acceptance decision. A concurrent
                // cancellation must not make this worker discard an ack that
                // the controller can still successfully enqueue.
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break Err(disconnected()),
            }
        }
    } else {
        Err(disconnected())
    };
    if let Err(error) = permit {
        control.request(crate::execution::TerminationCause::FailedToStart);
        reservation
            .finish(control.begin_cleanup(), true)
            .map_err(|_| {
                RunSealError::with_details(
                    "EXECUTION_CLEANUP_FAILED",
                    "execution admission cleanup could not be verified",
                    json!({"cleanup_complete":false}),
                )
            })?;
        return Err(error);
    }
    let ranges = sender.clone();
    let range_control = control;
    journal.set_terminal_range(move |event| {
        let (reply, response) = mpsc::sync_channel(1);
        let deadline = range_control.begin_cleanup();
        let mut pending = LifecycleMessage::TerminalRange {
            event: event.clone(),
            reply,
        };
        loop {
            if std::time::Instant::now() >= deadline {
                return Err(RunSealError::new(
                    "EXECUTION_CLEANUP_FAILED",
                    "execution retention snapshot deadline expired",
                ));
            }
            match ranges.try_send(pending) {
                Ok(()) => break,
                Err(mpsc::TrySendError::Full(message)) => {
                    pending = message;
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    return Err(RunSealError::new(
                        "CLIENT_DISCONNECTED",
                        "execution connection closed before retention snapshot",
                    ));
                }
            }
        }
        response
            .recv_timeout(
                range_control
                    .begin_cleanup()
                    .saturating_duration_since(std::time::Instant::now()),
            )
            .map_err(|_| {
                RunSealError::new(
                    "CLIENT_DISCONNECTED",
                    "execution retention snapshot unavailable",
                )
            })
    });
    let mut observer = ReservedExecutionObserver {
        reservation,
        events: |event: &Value| {
            if matches!(
                event["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            ) {
                return Ok(());
            }
            sender
                .send(LifecycleMessage::Event(event.clone()))
                .map_err(|_| {
                    RunSealError::new("CLIENT_DISCONNECTED", "execution connection closed")
                })
        },
    };
    let outcome = crate::execution::execute_prepared_after_admission_with_observer(
        request,
        journal,
        ready,
        &mut observer,
    );
    let _ = sender.send(LifecycleMessage::Complete {
        execution_id,
        outcome,
    });
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::sync::Mutex;
    use std::time::Instant;
    use windows_sys::Win32::Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType, ReadFile};
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };

    struct Fixture {
        writer: Option<std::fs::File>,
        worker: Arc<Mutex<Option<(OwnedHandle, std::thread::ThreadId)>>>,
        stop: Option<mpsc::Sender<()>>,
        watchdog: Option<JoinHandle<()>>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(mut writer) = self.writer.take() {
                let _ = writer.write_all(b"R");
            }
            if let Some((handle, id)) = self
                .worker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                && unsafe { WaitForSingleObject(handle.as_raw_handle(), 2000) } == WAIT_OBJECT_0
            {
                crate::execution::retained::join_finished(*id);
            }
            if let Some(watchdog) = self.watchdog.take() {
                let _ = watchdog.join();
            }
        }
    }

    #[test]
    fn native_pending_admission_keeps_peer_controls_live_and_never_launches_after_cleanup_expiry()
    -> anyhow::Result<()> {
        for direct in [true, false] {
            let tmp = tempfile::TempDir::new()?;
            let python = String::from_utf8(
                std::process::Command::new("where.exe")
                    .arg("python")
                    .output()?
                    .stdout,
            )?
            .lines()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Python required"))?
            .to_owned();
            let mut service = if direct {
                Service::direct()
            } else {
                Service::stateful()
            };
            let mut reader = std::ptr::null_mut();
            let mut writer = std::ptr::null_mut();
            anyhow::ensure!(
                unsafe { CreatePipe(&mut reader, &mut writer, std::ptr::null_mut(), 4096) } != 0,
                "admission native pipe"
            );
            let reader = Arc::new(unsafe { std::fs::File::from_raw_handle(reader) });
            let writer = unsafe { std::fs::File::from_raw_handle(writer) };
            let raw_reader = reader.as_raw_handle();
            let weak_reader = Arc::downgrade(&reader);
            let worker = Arc::new(Mutex::new(None));
            let observe = worker.clone();
            let (entered, entry) = mpsc::channel();
            let params = json!({"command":[python,"-c","import pathlib; pathlib.Path('must-not-run').write_text('ran')"],"cwd":tmp.path(),"policy":"danger-full-access"});
            let pending = spawn_with(
                json!(1),
                params,
                service.lifecycle_sender.clone(),
                move || {
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
                        *observe
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((
                            unsafe { OwnedHandle::from_raw_handle(thread) },
                            std::thread::current().id(),
                        ));
                    }
                    let _ = entered.send(());
                    let mut byte = 0;
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
                },
            )
            .map_err(|error| anyhow::anyhow!(error.reason))?;
            let control = pending.control.clone();
            service.pending_admissions.push(pending);
            entry.recv_timeout(Duration::from_secs(2))?;
            let safety_writer = writer.try_clone()?;
            let (stop, stopped) = mpsc::channel();
            let watchdog = std::thread::spawn(move || {
                if matches!(
                    stopped.recv_timeout(Duration::from_secs(3)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    let mut writer = safety_writer;
                    let _ = writer.write_all(b"R");
                }
            });
            let fixture = Fixture {
                writer: Some(writer),
                worker: worker.clone(),
                stop: Some(stop),
                watchdog: Some(watchdog),
            };
            let version =
                service.handle_rpc_request(&json!({"jsonrpc":"2.0","id":2,"method":"getVersion"}));
            let mut peer=service.handle_rpc_request(&json!({"jsonrpc":"2.0","id":3,"method":"execute","params":{"command":[python,"-u","-c","import os,pathlib,sys; p=pathlib.Path('peer.pid'); t=p.with_suffix('.tmp'); t.write_text(str(os.getpid())); t.replace(p); print('READY',flush=True); sys.stdin.buffer.read()"],"cwd":tmp.path(),"policy":"danger-full-access","stdin":{"mode":"stream"}}}));
            let deadline = Instant::now() + Duration::from_secs(2);
            while peer.is_empty() {
                peer.extend(service.poll_admissions());
                anyhow::ensure!(Instant::now() < deadline, "peer receipt");
                std::thread::sleep(Duration::from_millis(5));
            }
            let peer_id = peer[0]["result"]["execution_id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("peer id"))?
                .to_owned();
            for start in service.take_admitted_starts() {
                let _ = start.send(());
            }
            while !tmp.path().join("peer.pid").exists() {
                service.poll_admissions();
                service.poll_lifecycle();
                anyhow::ensure!(Instant::now() < deadline, "peer readiness");
                std::thread::sleep(Duration::from_millis(5));
            }
            let pid = std::fs::read_to_string(tmp.path().join("peer.pid"))?.parse::<u32>()?;
            let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
            anyhow::ensure!(!handle.is_null(), "peer native observation");
            let peer_handle = unsafe { OwnedHandle::from_raw_handle(handle) };
            control.adopt_cleanup_deadline(Instant::now() + Duration::from_millis(100));
            control.cancel();
            let mut failed = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(1);
            while failed.is_empty() {
                failed.extend(service.poll_admissions());
                service.poll_lifecycle();
                anyhow::ensure!(Instant::now() < deadline, "admission expiry");
                std::thread::sleep(Duration::from_millis(5));
            }
            let (native_pending, retained, id) = {
                let observed = worker
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let (handle, id) = observed
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("worker observation"))?;
                (
                    unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) } == WAIT_TIMEOUT,
                    crate::execution::retained::contains(*id),
                    *id,
                )
            };
            let pipe_owned = weak_reader.upgrade().is_some()
                && unsafe { GetFileType(raw_reader) } == FILE_TYPE_PIPE;
            let refused=service.handle_rpc_request(&json!({"jsonrpc":"2.0","id":4,"method":"execute","params":{"command":[python,"-c","import pathlib; pathlib.Path('extra').write_text('ran')"],"cwd":tmp.path(),"policy":"danger-full-access"}}));
            let peer_live =
                unsafe { WaitForSingleObject(peer_handle.as_raw_handle(), 0) } == WAIT_TIMEOUT;
            service.handle_rpc_request(&json!({"jsonrpc":"2.0","id":5,"method":"closeExecutionInput","params":{"execution_id":peer_id,"stream":"stdin"}}));
            let deadline = Instant::now() + Duration::from_secs(2);
            while service.has_active() && Instant::now() < deadline {
                service.poll_admissions();
                service.poll_lifecycle();
                std::thread::sleep(Duration::from_millis(5));
            }
            let peer_gone =
                unsafe { WaitForSingleObject(peer_handle.as_raw_handle(), 0) } == WAIT_OBJECT_0;
            drop(fixture);
            assert!(version[0]["result"].is_object());
            assert!(native_pending && retained && pipe_owned && peer_live && peer_gone);
            assert_eq!(
                failed[0]["error"]["data"]["code"],
                "EXECUTION_CLEANUP_FAILED"
            );
            assert_eq!(failed[0]["error"]["data"]["cleanup_complete"], false);
            assert_eq!(
                refused[0]["error"]["data"]["code"],
                "EXECUTION_CLEANUP_FAILED"
            );
            assert!(!crate::execution::retained::contains(id) && weak_reader.upgrade().is_none());
            assert!(
                !tmp.path().join("must-not-run").exists() && !tmp.path().join("extra").exists()
            );
        }
        Ok(())
    }
    #[test]
    fn pending_admission_slots_reject_excess_without_hiding_a_target_queue() -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let python = String::from_utf8(
            std::process::Command::new("where.exe")
                .arg("python")
                .output()?
                .stdout,
        )?
        .lines()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Python required"))?
        .to_owned();
        let mut service = Service::direct();
        let limit = crate::limits::deployment().max_active_executions;
        let params = json!({"command":[python,"-c","import pathlib; pathlib.Path('must-not-run').write_text('ran')"],"cwd":tmp.path(),"policy":"danger-full-access"});
        let mut release = Vec::new();
        let mut native = Vec::new();
        for index in 0..limit {
            let (permit, waiting) = mpsc::channel();
            let (entered, entry) = mpsc::channel();
            let pending = spawn_with(
                json!(index),
                params.clone(),
                service.lifecycle_sender.clone(),
                move || {
                    let _ = entered.send(());
                    let _ = waiting.recv();
                },
            )
            .map_err(|error| anyhow::anyhow!(error.reason))?;
            entry.recv_timeout(Duration::from_secs(2))?;
            let worker = pending
                .worker
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("owned worker"))?;
            let mut handle = std::ptr::null_mut();
            anyhow::ensure!(
                unsafe {
                    DuplicateHandle(
                        GetCurrentProcess(),
                        worker.as_raw_handle(),
                        GetCurrentProcess(),
                        &mut handle,
                        0,
                        0,
                        DUPLICATE_SAME_ACCESS,
                    )
                } != 0,
                "native slot observation"
            );
            native.push((
                unsafe { OwnedHandle::from_raw_handle(handle) },
                worker.thread().id(),
            ));
            release.push(permit);
            service.pending_admissions.push(pending);
        }
        let full = service.pending_admissions.len() == limit && service.active.is_empty();
        let denied = service.handle_rpc_request(
            &json!({"jsonrpc":"2.0","id":1000,"method":"execute","params":params}),
        );
        let version =
            service.handle_rpc_request(&json!({"jsonrpc":"2.0","id":1001,"method":"getVersion"}));
        service.cancel_owned();
        for permit in release {
            let _ = permit.send(());
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while service.has_active() && Instant::now() < deadline {
            service.poll_admissions();
            service.poll_lifecycle();
            std::thread::sleep(Duration::from_millis(5));
        }
        let ended=native.iter().all(|(handle,_)|unsafe {WaitForSingleObject(handle.as_raw_handle(),0)}==WAIT_OBJECT_0);
        for (_, id) in &native {
            crate::execution::retained::join_finished(*id);
        }
        assert!(full && ended && !service.has_active());
        assert_eq!(
            denied[0]["error"]["data"]["code"],
            "EXECUTION_LIMIT_EXCEEDED"
        );
        assert!(version[0]["result"].is_object());
        assert!(!tmp.path().join("must-not-run").exists());
        Ok(())
    }
    struct ExitGate {
        entered: AtomicBool,
        release: AtomicBool,
    }
    unsafe extern "system" fn hold_exit(value: *const std::ffi::c_void) {
        let gate = unsafe { Arc::from_raw(value.cast::<ExitGate>()) };
        gate.entered.store(true, Ordering::Release);
        while !gate.release.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    struct ExitFixture {
        gate: Arc<ExitGate>,
        handle: OwnedHandle,
        id: std::thread::ThreadId,
        slot: u32,
        stop: Option<mpsc::Sender<()>>,
        watchdog: Option<JoinHandle<()>>,
    }
    impl Drop for ExitFixture {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            self.gate.release.store(true, Ordering::Release);
            if unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 2000) } == WAIT_OBJECT_0 {
                crate::execution::retained::join_finished(self.id);
                unsafe {
                    windows_sys::Win32::System::Threading::FlsFree(self.slot);
                }
            }
            if let Some(watchdog) = self.watchdog.take() {
                let _ = watchdog.join();
            }
        }
    }

    #[test]
    fn rejected_admission_waits_for_native_exit_and_cannot_accept_confirmation_after_deadline()
    -> anyhow::Result<()> {
        use windows_sys::Win32::System::Threading::{FlsAlloc, FlsSetValue};
        for direct in [true, false] {
            for late_exit in [false, true] {
                let tmp = tempfile::TempDir::new()?;
                let mut service = if direct {
                    Service::direct()
                } else {
                    Service::stateful()
                };
                let gate = Arc::new(ExitGate {
                    entered: AtomicBool::new(false),
                    release: AtomicBool::new(false),
                });
                let slot = unsafe { FlsAlloc(Some(hold_exit)) };
                anyhow::ensure!(slot != u32::MAX, "admission exit slot");
                let worker_gate = gate.clone();
                let params = json!({"command":["python","-c","import pathlib; pathlib.Path('must-not-run').write_text('ran')"],"cwd":tmp.path(),"policy":"danger-full-access","unexpected":true});
                let pending = spawn_with(
                    json!(1),
                    params,
                    service.lifecycle_sender.clone(),
                    move || {
                        let raw = Arc::into_raw(worker_gate);
                        if unsafe { FlsSetValue(slot, raw.cast()) } == 0 {
                            unsafe {
                                drop(Arc::from_raw(raw));
                            }
                        }
                    },
                )
                .map_err(|error| anyhow::anyhow!(error.reason))?;
                let worker = pending
                    .worker
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("owned worker"))?;
                let id = worker.thread().id();
                let mut handle = std::ptr::null_mut();
                anyhow::ensure!(
                    unsafe {
                        DuplicateHandle(
                            GetCurrentProcess(),
                            worker.as_raw_handle(),
                            GetCurrentProcess(),
                            &mut handle,
                            0,
                            0,
                            DUPLICATE_SAME_ACCESS,
                        )
                    } != 0,
                    "native rejection observation"
                );
                let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
                let safety_gate = gate.clone();
                let (stop, stopped) = mpsc::channel();
                let watchdog = std::thread::spawn(move || {
                    if matches!(
                        stopped.recv_timeout(Duration::from_secs(3)),
                        Err(mpsc::RecvTimeoutError::Timeout)
                    ) {
                        safety_gate.release.store(true, Ordering::Release);
                    }
                });
                let fixture = ExitFixture {
                    gate: gate.clone(),
                    handle,
                    id,
                    slot,
                    stop: Some(stop),
                    watchdog: Some(watchdog),
                };
                let control = pending.control.clone();
                service.pending_admissions.push(pending);
                let readiness = Instant::now() + Duration::from_secs(2);
                while !gate.entered.load(Ordering::Acquire) {
                    anyhow::ensure!(Instant::now() < readiness, "native rejection callback");
                    std::thread::sleep(Duration::from_millis(5));
                }
                let deadline = Instant::now() + Duration::from_millis(100);
                control.adopt_cleanup_deadline(deadline);
                let early = service.poll_admissions();
                let native_pending =
                    unsafe { WaitForSingleObject(fixture.handle.as_raw_handle(), 0) }
                        == WAIT_TIMEOUT;
                let rust_finished = service
                    .pending_admissions
                    .first()
                    .and_then(|pending| pending.worker.as_ref())
                    .is_some_and(JoinHandle::is_finished);
                let mut returned = Vec::new();
                if late_exit {
                    while Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    gate.release.store(true, Ordering::Release);
                    anyhow::ensure!(
                        unsafe { WaitForSingleObject(fixture.handle.as_raw_handle(), 2000) }
                            == WAIT_OBJECT_0,
                        "late native exit"
                    );
                    returned = service.poll_admissions();
                } else {
                    let watchdog = Instant::now() + Duration::from_secs(1);
                    while returned.is_empty() {
                        returned.extend(service.poll_admissions());
                        anyhow::ensure!(Instant::now() < watchdog, "native rejection expiry");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
                let retained = late_exit || crate::execution::retained::contains(id);
                let version = service
                    .handle_rpc_request(&json!({"jsonrpc":"2.0","id":2,"method":"getVersion"}));
                drop(fixture);
                assert!(early.is_empty() && native_pending && rust_finished && retained);
                assert_eq!(
                    returned[0]["error"]["data"]["code"],
                    "EXECUTION_CLEANUP_FAILED"
                );
                assert_eq!(returned[0]["error"]["data"]["cleanup_complete"], false);
                assert_eq!(
                    control.cause(),
                    Some(crate::execution::TerminationCause::FailedToStart)
                );
                assert!(service.admission_cleanup_failed && version[0]["result"].is_object());
                assert!(
                    !crate::execution::retained::contains(id)
                        && !tmp.path().join("must-not-run").exists()
                );
            }
        }
        Ok(())
    }
    #[test]
    fn closed_acceptance_receiver_cannot_publish_a_preparing_receipt() -> anyhow::Result<()> {
        for direct in [true, false] {
            let mut service = if direct {
                Service::direct()
            } else {
                Service::stateful()
            };
            let ids = crate::events::new_execution_ids();
            let control = ExecutionControl::default();
            let active = ActiveExecution {
                result: json!({"execution_id":ids.execution_id,"session_id":ids.session_id,"status":"preparing","policy_id":"danger-full-access","policy_hash":"sha256:fixture","policy_epoch":"sha256:fixture","stderr_merged":false}),
                control: control.clone(),
                sequence: 0,
                audit_metadata: None,
                control_input: None,
                stdin: None,
            };
            let (start, _ready) = mpsc::sync_channel(1);
            let (messages, receiver) = mpsc::channel();
            let (accept, accepted) = mpsc::sync_channel(1);
            // Inject only a completion-delivery fault: the preparation snapshot
            // arrives after its worker has dropped the acceptance receiver.
            let worker = std::thread::spawn(move || {
                drop(accepted);
                let _ = messages.send(AdmissionMessage::Ready(ReadyAdmission { active, start }));
            });
            let mut handle = std::ptr::null_mut();
            anyhow::ensure!(
                unsafe {
                    DuplicateHandle(
                        GetCurrentProcess(),
                        worker.as_raw_handle(),
                        GetCurrentProcess(),
                        &mut handle,
                        0,
                        0,
                        DUPLICATE_SAME_ACCESS,
                    )
                } != 0,
                "closed acceptance native observation"
            );
            let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
            anyhow::ensure!(
                unsafe { WaitForSingleObject(handle.as_raw_handle(), 2000) } == WAIT_OBJECT_0,
                "fault delivery worker exit"
            );
            service.pending_admissions.push(PendingAdmission {
                id: json!(1),
                control,
                worker: Some(worker),
                receiver,
                accept,
                rejection: None,
            });
            let response = service.poll_admissions();
            assert_eq!(
                response[0]["error"]["data"]["code"],
                "EXECUTION_CLEANUP_FAILED"
            );
            assert_eq!(response[0]["error"]["data"]["cleanup_complete"], false);
            assert!(
                service.active.is_empty()
                    && service.pending_starts.is_empty()
                    && !service.has_active()
            );
            assert!(service.admission_cleanup_failed);
        }
        Ok(())
    }
}
