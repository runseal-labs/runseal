use super::{ExecutionControl, TerminationCause, retained};
use crate::backend::{BackendError, PlatformSandboxPlan, SandboxBackend};
use crate::error::RunSealError;
use crate::policy::SandboxPolicy;
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

/// Compile with owned data so a blocked preparation cannot borrow the owner stack.
pub(super) fn compile_plan<B: SandboxBackend + Send + Sync + 'static>(
    backend: Arc<B>,
    execution_id: String,
    cwd: PathBuf,
    policy: SandboxPolicy,
    control: &ExecutionControl,
) -> Result<Result<PlatformSandboxPlan, BackendError>, RunSealError> {
    let (completed, completion) = mpsc::channel();
    let worker = std::thread::Builder::new()
        .name("runseal-preparation".into())
        .spawn(move || {
            let result = super::paths::validate_execution_cwd(&cwd)
                .map(|()| backend.compile_plan(&execution_id, &cwd, &policy));
            let _ = completed.send(result);
        })
        .map_err(|_| {
            RunSealError::with_details(
                "EXECUTION_FAILED_TO_START",
                "execution preparation worker unavailable",
                serde_json::json!({"cleanup_complete":true}),
            )
        })?;
    let mut result = None;
    let mut confirmation_deadline = None;
    loop {
        if result.is_none() {
            match completion.try_recv() {
                Ok(value) => {
                    result = Some(value);
                    // This confirms the preparation worker only. Do not start
                    // whole-execution cleanup on successful normal preparation.
                    confirmation_deadline =
                        Some(Instant::now() + crate::limits::deployment().cleanup_timeout());
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    control.request(TerminationCause::FailedToStart);
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(deadline) = confirmation_deadline
            && control.is_cancelled()
        {
            control.adopt_cleanup_deadline(deadline);
        }
        let confirmation_expired =
            confirmation_deadline.is_some_and(|deadline| Instant::now() >= deadline);
        if confirmation_expired || control.cleanup_deadline_expired() {
            if let Some(deadline) = confirmation_deadline {
                control.adopt_cleanup_deadline(deadline);
            }
            control.request(TerminationCause::FailedToStart);
            if retained::thread_finished(&worker) {
                let _ = worker.join();
            } else {
                retained::retain(worker);
            }
            return Err(RunSealError::with_details(
                "EXECUTION_CLEANUP_FAILED",
                "execution preparation cleanup could not be verified",
                serde_json::json!({"cleanup_complete":false}),
            ));
        }
        if retained::thread_finished(&worker) {
            let joined = worker.join();
            if result.is_none() {
                result = completion.try_recv().ok();
            }
            return match (joined, result) {
                (Ok(()), Some(result)) => result,
                _ => Err(RunSealError::with_details(
                    "EXECUTION_FAILED_TO_START",
                    "execution preparation worker failed",
                    serde_json::json!({"cleanup_complete":true}),
                )),
            };
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::backend::{
        BackendExecutionOptions, BackendExecutionOutput, ExecutionEnv, ExecutionStdin,
    };
    use crate::policy::BackendFeature;
    use serde_json::{Value, json};
    use std::io::{self, Write};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::Path;
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };
    use windows_sys::Win32::Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType, ReadFile};
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        FlsAlloc, FlsFree, FlsSetValue, GetCurrentProcess, GetCurrentThread, WaitForSingleObject,
    };

    struct Gate {
        entered: AtomicBool,
        release: AtomicBool,
        worker: Mutex<Option<(OwnedHandle, std::thread::ThreadId)>>,
        executed: AtomicBool,
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
                        let _ = retained::join_finished(*id);
                    }
                    finished
                });
            if finished && let Some(slot) = self.slot {
                unsafe {
                    FlsFree(slot);
                }
            }
            if let Some(watchdog) = self.watchdog.take() {
                if unsafe { WaitForSingleObject(watchdog.as_raw_handle(), 2000) } == WAIT_OBJECT_0 {
                    let _ = watchdog.join();
                } else {
                    retained::retain(watchdog);
                }
            }
        }
    }
    struct NativePreparation {
        gate: Arc<Gate>,
        control: ExecutionControl,
        slot: Option<u32>,
        reader: Option<std::fs::File>,
    }
    impl SandboxBackend for NativePreparation {
        fn name(&self) -> &'static str {
            crate::backend::active_backend().name()
        }
        fn status(&self) -> &'static str {
            crate::backend::active_backend().status()
        }
        fn platform(&self) -> &'static str {
            crate::backend::active_backend().platform()
        }
        fn supported_features(&self) -> &'static [BackendFeature] {
            crate::backend::active_backend().supported_features()
        }
        fn capabilities_json(&self) -> Value {
            crate::backend::active_backend().capabilities_json()
        }
        fn compile_plan(
            &self,
            id: &str,
            cwd: &Path,
            policy: &SandboxPolicy,
        ) -> Result<PlatformSandboxPlan, BackendError> {
            if let Some(slot) = self.slot {
                let pointer = Arc::into_raw(self.gate.clone());
                if unsafe { FlsSetValue(slot, pointer.cast()) } == 0 {
                    drop(unsafe { Arc::from_raw(pointer) });
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
            } != 0
            {
                *self
                    .gate
                    .worker
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((
                    unsafe { OwnedHandle::from_raw_handle(handle) },
                    std::thread::current().id(),
                ));
            }
            let result = crate::backend::active_backend().compile_plan(id, cwd, policy);
            if self.reader.is_some() {
                self.control.cancel();
            }
            self.control
                .adopt_cleanup_deadline(Instant::now() + Duration::from_millis(100));
            if let Some(reader) = &self.reader {
                self.gate.entered.store(true, Ordering::Release);
                let mut byte = 0u8;
                let mut count = 0u32;
                unsafe {
                    ReadFile(
                        reader.as_raw_handle(),
                        &mut byte,
                        1,
                        &mut count,
                        std::ptr::null_mut(),
                    );
                }
            }
            result
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
            self.gate.executed.store(true, Ordering::Release);
            crate::backend::active_backend().execute_plan(plan, command, cwd, stdin, env, options)
        }
    }

    #[test]
    fn native_preparation_retains_pending_call_or_exit_and_never_launches_after_expiry()
    -> anyhow::Result<()> {
        for exit_callback in [true, false] {
            let tmp = tempfile::TempDir::new()?;
            let control = ExecutionControl::default();
            let gate = Arc::new(Gate {
                entered: AtomicBool::new(false),
                release: AtomicBool::new(false),
                worker: Mutex::new(None),
                executed: AtomicBool::new(false),
            });
            let slot = if exit_callback {
                let slot = unsafe { FlsAlloc(Some(hold_exit)) };
                anyhow::ensure!(slot != u32::MAX, "native preparation slot");
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
                    "native preparation pipe"
                );
                (
                    Some(unsafe { std::fs::File::from_raw_handle(reader) }),
                    Some(unsafe { std::fs::File::from_raw_handle(writer) }),
                )
            };
            let raw_reader = reader.as_ref().map(AsRawHandle::as_raw_handle);
            let safety_gate = gate.clone();
            let safety_writer = writer.as_ref().map(std::fs::File::try_clone).transpose()?;
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
                slot,
                writer,
                stop: Some(stop),
                watchdog: Some(watchdog),
            };
            let backend = Arc::new(NativePreparation {
                gate: gate.clone(),
                control: control.clone(),
                slot,
                reader,
            });
            let weak = Arc::downgrade(&backend);
            let request = super::super::ExecutionRequest {
                ids: crate::events::new_execution_ids(),
                control: control.clone(),
                command: vec![
                    "python".into(),
                    "-c".into(),
                    "import pathlib; pathlib.Path('must-not-run').write_text('ran')".into(),
                ],
                cwd: tmp.path().to_owned(),
                policy: crate::policy::normalize_policy(
                    &json!("danger-full-access"),
                    tmp.path(),
                    None,
                )
                .map_err(|error| anyhow::anyhow!(error.reason))?,
                stdin: ExecutionStdin::Empty,
                control_input: None,
                io: crate::backend::ExecutionIo::Pipe,
                env: ExecutionEnv::default(),
                metadata: None,
                timeout: None,
            };
            let journal = super::super::journal::ExecutionJournal::prepare(&request)
                .map_err(|error| anyhow::anyhow!(error.reason))?;
            let mut events = Vec::new();
            let error = super::super::engine::execute_prepared_with_backend(
                request,
                journal,
                &mut |event: &Value| {
                    events.push(event.clone());
                    Ok(())
                },
                backend,
            )
            .expect_err("unconfirmed preparation must fail cleanup");
            let (pending, retained, id) = {
                let worker = gate
                    .worker
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let (handle, id) = worker
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("native worker observation"))?;
                (
                    unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) } == WAIT_TIMEOUT,
                    retained::contains(*id),
                    *id,
                )
            };
            let entered = gate.entered.load(Ordering::Acquire);
            let pipe_owned = exit_callback
                || (weak.upgrade().is_some()
                    && raw_reader
                        .is_some_and(|handle| unsafe { GetFileType(handle) } == FILE_TYPE_PIPE));
            let did_not_execute =
                !gate.executed.load(Ordering::Acquire) && !tmp.path().join("must-not-run").exists();
            let terminal = error
                .terminal_event
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("terminal"))?
                .clone();
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
            drop(fixture);
            assert!(!retained::contains(id));
            assert!(weak.upgrade().is_none());
            assert!(entered && pending && retained && pipe_owned && did_not_execute);
            assert!(
                !gate.executed.load(Ordering::Acquire) && !tmp.path().join("must-not-run").exists()
            );
            assert_eq!(error.code, "EXECUTION_CLEANUP_FAILED");
            assert_eq!(terminal["result"]["cleanup_complete"], false);
            assert_eq!(terminal["result"]["termination_reason"], "cleanup_failed");
            assert_eq!(
                terminal["result"]["requested_termination_reason"],
                if exit_callback {
                    "failed_to_start"
                } else {
                    "cancelled"
                }
            );
            assert!(terminal["result"]["started_at"].is_null());
            assert!(terminal["result"]["exit_code"].is_null());
            assert!(
                !events
                    .iter()
                    .any(|event| event["type"] == "execution.started")
            );
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
        }
        Ok(())
    }

    #[test]
    fn normal_preparation_does_not_begin_whole_execution_cleanup() -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let control = ExecutionControl::default();
        let policy =
            crate::policy::normalize_policy(&json!("danger-full-access"), tmp.path(), None)
                .map_err(|error| anyhow::anyhow!(error.reason))?;
        let result = compile_plan(
            Arc::new(crate::backend::active_backend()),
            "exec_fixture".into(),
            tmp.path().to_owned(),
            policy,
            &control,
        )
        .map_err(|error| anyhow::anyhow!(error.reason))?;
        assert!(result.is_ok());
        assert!(control.cause().is_none());
        // With no inherited preparation deadline, adopting a later real
        // cancellation deadline must select that exact value rather than an
        // earlier preparation teardown clock.
        let candidate = Instant::now() + Duration::from_secs(10);
        assert_eq!(control.adopt_cleanup_deadline(candidate), candidate);
        Ok(())
    }
}
