use codex_protocol::models::PermissionProfile;
use codex_utils_absolute_path::AbsolutePathBuf;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;

pub type SandboxOutputObserver<'a> = Box<dyn FnMut(crate::OutputStream, &[u8]) + Send + 'a>;
pub enum SandboxInputPoll {
    Data(Vec<u8>),
    Pending,
    Resize { rows: u16, cols: u16 },
    Interrupt,
    Eof,
    Failed,
}
pub type SandboxInputSource = Box<dyn FnMut() -> SandboxInputPoll + Send>;

pub struct ElevatedSandboxProfileCaptureRequest<'a> {
    pub permission_profile: &'a PermissionProfile,
    pub workspace_roots: &'a [AbsolutePathBuf],
    pub codex_home: &'a Path,
    pub command: Vec<String>,
    pub cwd: &'a Path,
    pub env_map: HashMap<String, String>,
    pub timeout_ms: Option<u64>,
    pub stdin: Vec<u8>,
    pub terminal_size: Option<crate::ResizePayload>,
    pub input_source: Option<SandboxInputSource>,
    pub input_acknowledged: Option<Box<dyn FnMut(usize) -> bool + Send>>,
    pub control_source: Option<SandboxInputSource>,
    pub control_acknowledged: Option<Box<dyn FnMut(usize) -> bool + Send>>,
    pub output_observer: Option<SandboxOutputObserver<'a>>,
    pub started_observer: Option<Box<dyn FnMut() + Send + 'a>>,
    pub cancellation: Option<crate::WindowsSandboxCancellationToken>,
    pub use_private_desktop: bool,
    pub proxy_enforced: bool,
    pub allow_network_proxy: bool,
    pub sandbox_proxy_settings: Option<crate::SandboxProxySettings>,
    pub read_cap_sid: Option<String>,
    pub read_roots_override: Option<&'a [PathBuf]>,
    pub read_roots_include_platform_defaults: bool,
    pub write_roots_override: Option<&'a [PathBuf]>,
    pub deny_write_paths_override: &'a [AbsolutePathBuf],
}

mod windows_impl {
    use super::ElevatedSandboxProfileCaptureRequest;
    use crate::acl::allow_null_device;
    use crate::appcontainer::appcontainer_capability_sid;
    use crate::appcontainer::workspace_appcontainer_write_capability_sid;
    use crate::cap::load_or_create_cap_sids;
    use crate::cap::workspace_write_cap_sid_for_root;
    use crate::env::ensure_non_interactive_pager;
    use crate::env::inherit_path_env;
    use crate::env::normalize_null_device_env;
    use crate::identity::require_logon_sandbox_creds;
    use crate::ipc_framed::EmptyPayload;
    use crate::ipc_framed::FramedMessage;
    use crate::ipc_framed::IPC_PROTOCOL_VERSION;
    use crate::ipc_framed::Message;
    use crate::ipc_framed::OutputStream;
    use crate::ipc_framed::SpawnRequest;
    use crate::ipc_framed::StdinPayload;
    use crate::ipc_framed::decode_bytes;
    use crate::ipc_framed::encode_bytes;
    use crate::ipc_framed::write_frame;
    use crate::ipc_framed::{FramePoll, PipeFrameReader};
    use crate::logging::log_failure;
    use crate::logging::log_start;
    use crate::logging::log_success;
    use crate::resolved_permissions::ResolvedWindowsSandboxPermissions;
    use crate::runner_client::spawn_runner_transport;
    use crate::sandbox_utils::ensure_codex_home_exists;
    use crate::sandbox_utils::inject_git_safe_directory;
    use crate::setup::effective_write_roots_for_permissions;
    use crate::token::LocalSid;
    use anyhow::Result;
    use codex_utils_absolute_path::AbsolutePathBuf;
    use std::fs::File;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    pub use crate::windows_impl::CaptureResult;

    fn input_transport_closed(error: &anyhow::Error) -> bool {
        error.downcast_ref::<std::io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::Interrupted
            ) || error.raw_os_error() == Some(995)
        })
    }

    type InputWorker = std::thread::JoinHandle<Result<()>>;

    struct InputWriter {
        worker: Option<InputWorker>,
        done: Arc<AtomicBool>,
        cleanup_deadline: Option<std::time::Instant>,
    }

    fn retained_input_writers() -> &'static std::sync::Mutex<Vec<InputWorker>> {
        static RETAINED: std::sync::OnceLock<std::sync::Mutex<Vec<InputWorker>>> =
            std::sync::OnceLock::new();
        RETAINED.get_or_init(std::sync::Mutex::default)
    }

    impl InputWriter {
        fn finish(&mut self, deadline: std::time::Instant) -> Result<Result<()>> {
            self.cleanup_deadline = Some(deadline);
            self.done.store(true, Ordering::Release);
            if let Some(worker) = &self.worker {
                worker.thread().unpark();
            }
            while let Some(worker) = &self.worker {
                if worker.is_finished() {
                    let worker = self
                        .worker
                        .take()
                        .ok_or_else(|| anyhow::anyhow!(crate::SandboxCleanupError))?;
                    return worker
                        .join()
                        .map_err(|_| anyhow::anyhow!(crate::SandboxCleanupError));
                }
                unsafe {
                    windows_sys::Win32::System::IO::CancelSynchronousIo(worker.as_raw_handle() as _);
                }
                if std::time::Instant::now() >= deadline {
                    return Err(anyhow::anyhow!(crate::SandboxCleanupError));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(Ok(()))
        }
    }

    impl Drop for InputWriter {
        fn drop(&mut self) {
            let deadline = self
                .cleanup_deadline
                .unwrap_or_else(|| std::time::Instant::now() + Duration::from_secs(2));
            let _ = self.finish(deadline);
            if let Some(worker) = self.worker.take() {
                // Failed cleanup must keep an owner for the native I/O thread.
                // Admission remains quarantined; do not detach it at return.
                let mut retained = retained_input_writers()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let mut index = 0;
                while index < retained.len() {
                    if retained[index].is_finished() {
                        let previous = retained.swap_remove(index);
                        let _ = previous.join();
                    } else {
                        index += 1;
                    }
                }
                retained.push(worker);
            }
        }
    }

    fn receive_runner_frame(
        reader: &mut PipeFrameReader,
        pipe: &mut File,
        cleanup_deadline: &mut Option<std::time::Instant>,
        cleanup_grace: Duration,
        cancellation: Option<&crate::WindowsSandboxCancellationToken>,
        mut cleanup_requested: impl FnMut() -> bool,
    ) -> Result<Option<FramedMessage>> {
        loop {
            if cleanup_requested() && cleanup_deadline.is_none() {
                *cleanup_deadline = Some(
                    cancellation
                        .and_then(crate::WindowsSandboxCancellationToken::cleanup_deadline)
                        .unwrap_or_else(|| std::time::Instant::now() + cleanup_grace),
                );
            }
            if cleanup_deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                return Err(anyhow::anyhow!(crate::SandboxCleanupError));
            }
            match reader.poll(pipe)? {
                FramePoll::Message(message) => return Ok(Some(message)),
                FramePoll::Closed => return Ok(None),
                FramePoll::Progress => continue,
                FramePoll::Pending => std::thread::sleep(Duration::from_millis(5)),
            }
        }
    }

    fn cleanup_wait(cancellation: Option<&crate::WindowsSandboxCancellationToken>) -> Duration {
        cancellation
            .map_or_else(
                crate::CleanupBudget::default,
                crate::WindowsSandboxCancellationToken::cleanup_budget,
            )
            .duration()
    }

    fn runner_exit_result(payload: crate::ipc_framed::ExitPayload) -> Result<(i32, bool)> {
        if payload.cleanup_complete {
            Ok((payload.exit_code, payload.timed_out))
        } else {
            Err(anyhow::anyhow!(crate::SandboxCaptureCleanupError {
                exit_code: Some(payload.exit_code),
                timed_out: payload.timed_out,
            }))
        }
    }

    fn observe_cleanup_started(
        payload: crate::CleanupStartedPayload,
        deadline: &mut Option<std::time::Instant>,
        cancellation: Option<&crate::WindowsSandboxCancellationToken>,
    ) -> Result<crate::SandboxCaptureCleanupError> {
        let candidate = payload.deadline.deadline()?;
        let selected = cancellation.map_or(candidate, |token| {
            token.adopt_cleanup_deadline(candidate, payload.exit_code, payload.timed_out)
        });
        *deadline = Some(deadline.map_or(selected, |previous| previous.min(selected)));
        Ok(crate::SandboxCaptureCleanupError {
            exit_code: payload.exit_code,
            timed_out: payload.timed_out,
        })
    }

    fn capture_cleanup_failure(result: &Result<(i32, bool)>) -> crate::SandboxCaptureCleanupError {
        match result {
            Ok((exit_code, timed_out)) => crate::SandboxCaptureCleanupError {
                exit_code: Some(*exit_code),
                timed_out: *timed_out,
            },
            Err(error) => error
                .downcast_ref::<crate::SandboxCaptureCleanupError>()
                .map_or(
                    crate::SandboxCaptureCleanupError {
                        exit_code: None,
                        timed_out: false,
                    },
                    |failure| crate::SandboxCaptureCleanupError {
                        exit_code: failure.exit_code,
                        timed_out: failure.timed_out,
                    },
                ),
        }
    }

    fn finish_capture_result(
        result: Result<(i32, bool)>,
        input_writer: &mut InputWriter,
        deadline: std::time::Instant,
    ) -> Result<(i32, bool)> {
        let spawn_failed = result
            .as_ref()
            .err()
            .is_some_and(|error| error.downcast_ref::<crate::SandboxSpawnFailed>().is_some());
        let failure = capture_cleanup_failure(&result);
        let input_result = input_writer.finish(deadline);
        // A definitive runner start failure means no execution range existed, so
        // a local input-worker teardown must not replace it with cleanup failure.
        if !spawn_failed {
            input_result
                .as_ref()
                .map_err(|_| anyhow::anyhow!(capture_cleanup_failure(&result)))?;
        }
        // Local I/O completion cannot replace a missing or failed cleanup frame.
        let (exit_code, timed_out) = result.map_err(|error| {
            if spawn_failed {
                error
            } else {
                anyhow::anyhow!(failure)
            }
        })?;
        // A child may exit before consuming stdin. Its confirmed exit remains real.
        if let Err(error) = input_result
            && !input_transport_closed(&error)
        {
            return Err(anyhow::anyhow!(crate::SandboxCaptureInputError {
                exit_code,
                timed_out
            }));
        }
        Ok((exit_code, timed_out))
    }

    /// One bounded in-flight chunk per input stream, with cancellation independent
    /// of either stream's actual-write acknowledgement.
    #[allow(clippy::too_many_arguments)]
    fn spawn_input_writer(
        mut pipe_write: File,
        stdin: Vec<u8>,
        mut input_source: Option<super::SandboxInputSource>,
        acknowledged_bytes: Arc<AtomicUsize>,
        mut control_source: Option<super::SandboxInputSource>,
        control_acknowledged_bytes: Arc<AtomicUsize>,
        cancellation: Option<crate::WindowsSandboxCancellationToken>,
    ) -> InputWriter {
        let done = Arc::new(AtomicBool::new(false));
        let done_for_thread = Arc::clone(&done);
        let handle = std::thread::spawn(move || {
            let mut submitted = [0usize; 2];
            let mut closed = [false, control_source.is_none()];
            let mut stdin_offset = 0usize;
            while !done_for_thread.load(Ordering::Acquire) {
                if cancellation
                    .as_ref()
                    .is_some_and(|token| token.is_cancelled())
                {
                    write_frame(
                        &mut pipe_write,
                        &FramedMessage {
                            version: IPC_PROTOCOL_VERSION,
                            message: Message::Terminate {
                                payload: crate::CleanupDeadlinePayload::new(
                                    cancellation.as_ref()
                                        .and_then(crate::WindowsSandboxCancellationToken::cleanup_deadline)
                                        .unwrap_or_else(|| std::time::Instant::now() + cleanup_wait(cancellation.as_ref()))
                                )?,
                            },
                        },
                    )?;
                    break;
                }
                let mut progress = false;
                for stream in 0..2 {
                    let acknowledged = if stream == 0 {
                        &acknowledged_bytes
                    } else {
                        &control_acknowledged_bytes
                    };
                    let in_flight = acknowledged.load(Ordering::Acquire) < submitted[stream];
                    if closed[stream]
                        || (in_flight
                            && (stream != 0
                                || input_source.is_none()
                                || stdin_offset < stdin.len()))
                    {
                        continue;
                    }
                    let next = if stream == 0 && stdin_offset < stdin.len() {
                        let end = stdin.len().min(stdin_offset + 64 * 1024);
                        let bytes = stdin[stdin_offset..end].to_vec();
                        stdin_offset = end;
                        super::SandboxInputPoll::Data(bytes)
                    } else {
                        let source = if stream == 0 {
                            &mut input_source
                        } else {
                            &mut control_source
                        };
                        source
                            .as_mut()
                            .map_or(super::SandboxInputPoll::Eof, |source| source())
                    };
                    let message = match next {
                        super::SandboxInputPoll::Data(bytes) => {
                            if in_flight || bytes.is_empty() || bytes.len() > 64 * 1024 {
                                anyhow::bail!("invalid execution input chunk");
                            }
                            submitted[stream] += bytes.len();
                            let payload = StdinPayload {
                                data_b64: encode_bytes(&bytes),
                            };
                            if stream == 0 {
                                Message::Stdin { payload }
                            } else {
                                Message::Control { payload }
                            }
                        }
                        super::SandboxInputPoll::Eof if in_flight => continue,
                        super::SandboxInputPoll::Eof => {
                            closed[stream] = true;
                            if stream == 0 {
                                Message::CloseStdin {
                                    payload: EmptyPayload::default(),
                                }
                            } else {
                                Message::CloseControl {
                                    payload: EmptyPayload::default(),
                                }
                            }
                        }
                        super::SandboxInputPoll::Resize { rows, cols } if stream == 0 => {
                            Message::Resize {
                                payload: crate::ResizePayload { rows, cols },
                            }
                        }
                        super::SandboxInputPoll::Interrupt if stream == 0 => Message::Interrupt {
                            payload: EmptyPayload::default(),
                        },
                        super::SandboxInputPoll::Pending => continue,
                        _ => anyhow::bail!("execution input source failed"),
                    };
                    write_frame(
                        &mut pipe_write,
                        &FramedMessage {
                            version: IPC_PROTOCOL_VERSION,
                            message,
                        },
                    )?;
                    progress = true;
                }
                if !progress {
                    std::thread::park_timeout(Duration::from_millis(10));
                }
            }
            Ok(())
        });
        InputWriter {
            worker: Some(handle),
            done,
            cleanup_deadline: None,
        }
    }

    /// Launches the command runner under the sandbox user and captures its output.
    #[allow(clippy::too_many_arguments)]
    pub fn run_windows_sandbox_capture_for_permission_profile(
        request: ElevatedSandboxProfileCaptureRequest<'_>,
    ) -> Result<CaptureResult> {
        let ElevatedSandboxProfileCaptureRequest {
            permission_profile,
            workspace_roots,
            codex_home,
            command,
            cwd,
            mut env_map,
            timeout_ms,
            stdin,
            terminal_size,
            input_source,
            mut input_acknowledged,
            control_source,
            mut control_acknowledged,
            mut output_observer,
            mut started_observer,
            cancellation,
            use_private_desktop,
            proxy_enforced,
            allow_network_proxy,
            sandbox_proxy_settings,
            read_cap_sid,
            read_roots_override,
            read_roots_include_platform_defaults,
            write_roots_override,
            deny_write_paths_override,
        } = request;
        let execution_deadline = timeout_ms
            .map(|milliseconds| {
                std::time::Instant::now()
                    .checked_add(Duration::from_millis(milliseconds))
                    .ok_or_else(|| anyhow::anyhow!("execution timeout unavailable"))
            })
            .transpose()?;
        let permissions =
            ResolvedWindowsSandboxPermissions::try_from_permission_profile_for_workspace_roots(
                permission_profile,
                workspace_roots,
            )?;
        let control_open = control_source.is_some();
        if control_open && (terminal_size.is_some() || output_observer.is_none()) {
            anyhow::bail!("control requires pipe output observation");
        }
        let deny_write_paths_override = deny_write_paths_override
            .iter()
            .map(AbsolutePathBuf::to_path_buf)
            .collect::<Vec<_>>();
        normalize_null_device_env(&mut env_map);
        ensure_non_interactive_pager(&mut env_map);
        inherit_path_env(&mut env_map);
        inject_git_safe_directory(&mut env_map, cwd);
        // Use a temp-based log dir that the sandbox user can write.
        let sandbox_base = codex_home.join(".sandbox");
        ensure_codex_home_exists(&sandbox_base)?;

        let logs_base_dir: Option<&Path> = Some(sandbox_base.as_path());
        log_start(&command, logs_base_dir);
        let sandbox_creds = require_logon_sandbox_creds(
            &permissions,
            cwd,
            &env_map,
            codex_home,
            read_roots_override,
            read_roots_include_platform_defaults,
            write_roots_override,
            &deny_write_paths_override,
            proxy_enforced,
            sandbox_proxy_settings.as_ref(),
            read_cap_sid.as_deref(),
        )?;
        // Build capability SID for ACL grants.
        let caps = load_or_create_cap_sids(codex_home)?;
        let (sid_for_null, cap_sids) = if permissions.uses_write_capabilities_for_cwd(cwd, &env_map)
        {
            let write_roots = effective_write_roots_for_permissions(
                &permissions,
                cwd,
                &env_map,
                codex_home,
                write_roots_override,
            );
            let mut cap_sids = write_roots
                .iter()
                .map(|root| {
                    if read_cap_sid.is_some() {
                        workspace_appcontainer_write_capability_sid(codex_home, cwd, root)
                    } else {
                        workspace_write_cap_sid_for_root(codex_home, cwd, root)
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            if cap_sids.is_empty() {
                anyhow::bail!("workspace-write sandbox has no writable root capability SIDs");
            }
            if let Some(read_cap_sid) = read_cap_sid {
                cap_sids.push(read_cap_sid);
                if allow_network_proxy {
                    cap_sids.push(appcontainer_capability_sid("internetClient")?);
                }
            }
            (LocalSid::from_string(&cap_sids[0])?, cap_sids)
        } else {
            let sid = LocalSid::from_string(&caps.readonly)?;
            (sid, vec![caps.readonly])
        };

        unsafe {
            allow_null_device(sid_for_null.as_ptr());
        }

        (|| -> Result<CaptureResult> {
            let spawn_request = SpawnRequest {
                command: command.clone(),
                cwd: cwd.to_path_buf(),
                env: env_map.clone(),
                permission_profile: permission_profile.clone(),
                workspace_roots: workspace_roots.to_vec(),
                codex_home: sandbox_base.clone(),
                real_codex_home: codex_home.to_path_buf(),
                cap_sids,
                timeout_ms,
                cleanup_budget: cancellation.as_ref().map_or_else(
                    crate::CleanupBudget::default,
                    crate::WindowsSandboxCancellationToken::cleanup_budget,
                ),
                tty: terminal_size.is_some(),
                terminal_size,
                stdin_open: true,
                control_open,
                use_private_desktop,
            };
            let transport = spawn_runner_transport(
                codex_home,
                cwd,
                &sandbox_creds,
                logs_base_dir,
                spawn_request,
                cancellation.clone(),
                execution_deadline,
            )?;
            // The transport returns only after consuming the runner's SpawnReady frame.
            if let Some(observer) = &mut started_observer {
                observer();
            }
            let (pipe_write, mut pipe_read) = transport.into_files();
            let acknowledged_bytes = Arc::new(AtomicUsize::new(0));
            let control_acknowledged_bytes = Arc::new(AtomicUsize::new(0));
            let mut input_writer = spawn_input_writer(
                pipe_write,
                stdin,
                input_source,
                acknowledged_bytes.clone(),
                control_source,
                control_acknowledged_bytes.clone(),
                cancellation.clone(),
            );

            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let mut frame_reader = PipeFrameReader::default();
            let mut cleanup_deadline = None;
            let mut cleanup_facts = None;
            let result = loop {
                let msg = match receive_runner_frame(
                    &mut frame_reader,
                    &mut pipe_read,
                    &mut cleanup_deadline,
                    cleanup_wait(cancellation.as_ref()),
                    cancellation.as_ref(),
                    || {
                        cancellation
                            .as_ref()
                            .is_some_and(|token| token.is_cancelled())
                            || execution_deadline
                                .is_some_and(|deadline| std::time::Instant::now() >= deadline)
                            || input_writer
                                .worker
                                .as_ref()
                                .is_some_and(std::thread::JoinHandle::is_finished)
                    },
                ) {
                    Ok(Some(msg)) => msg,
                    Ok(None) => break Err(anyhow::anyhow!("runner pipe closed before exit")),
                    Err(err) => break Err(err),
                };
                match msg.message {
                    Message::CleanupStarted { payload } => {
                        if cleanup_facts.is_some() {
                            break Err(anyhow::anyhow!("duplicate runner cleanup announcement"));
                        }
                        match observe_cleanup_started(
                            payload,
                            &mut cleanup_deadline,
                            cancellation.as_ref(),
                        ) {
                            Ok(facts) => cleanup_facts = Some(facts),
                            Err(error) => break Err(error),
                        }
                    }
                    Message::StdinAcknowledged { payload } => {
                        acknowledged_bytes.fetch_add(payload.bytes, Ordering::Release);
                        if input_acknowledged
                            .as_mut()
                            .is_some_and(|acknowledge| !acknowledge(payload.bytes))
                        {
                            break Err(anyhow::anyhow!("invalid execution input acknowledgement"));
                        }
                    }
                    Message::ControlAcknowledged { payload } => {
                        if !control_open || payload.bytes == 0 || payload.bytes > 64 * 1024 {
                            break Err(anyhow::anyhow!("invalid control acknowledgement"));
                        }
                        control_acknowledged_bytes.fetch_add(payload.bytes, Ordering::Release);
                        if control_acknowledged
                            .as_mut()
                            .is_some_and(|acknowledge| !acknowledge(payload.bytes))
                        {
                            break Err(anyhow::anyhow!("invalid control acknowledgement"));
                        }
                    }
                    Message::Output { payload } => match decode_bytes(&payload.data_b64) {
                        Ok(bytes) => {
                            if let Some(observer) = &mut output_observer {
                                observer(payload.stream, &bytes);
                            } else {
                                match payload.stream {
                                    OutputStream::Stdout => stdout.extend_from_slice(&bytes),
                                    OutputStream::Stderr => stderr.extend_from_slice(&bytes),
                                    OutputStream::Control => {
                                        break Err(anyhow::anyhow!(
                                            "control output requires observation"
                                        ));
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            break Err(err);
                        }
                    },
                    Message::Exit { mut payload } => {
                        if cleanup_facts.is_none() {
                            payload.cleanup_complete = false;
                        }
                        break runner_exit_result(payload);
                    }
                    Message::Error { payload } => {
                        if payload.code == "cleanup_failed" {
                            break Err(anyhow::anyhow!(crate::SandboxCleanupError));
                        }
                        if payload.code == "spawn_failed" {
                            break Err(anyhow::anyhow!(crate::SandboxSpawnFailed(payload.message)));
                        }
                        break Err(anyhow::anyhow!("runner error: {}", payload.message));
                    }
                    _ => {
                        break Err(anyhow::anyhow!("unexpected runner message during capture"));
                    }
                }
            };
            let (exit_code, timed_out) = finish_capture_result(
                result.map_err(|error| {
                    if error
                        .downcast_ref::<crate::SandboxCaptureCleanupError>()
                        .is_some()
                    {
                        return error;
                    }
                    cleanup_facts.map_or(error, |facts| anyhow::anyhow!(facts))
                }),
                &mut input_writer,
                cleanup_deadline
                    .or_else(|| {
                        cancellation
                            .as_ref()
                            .and_then(crate::WindowsSandboxCancellationToken::cleanup_deadline)
                    })
                    .unwrap_or_else(|| {
                        std::time::Instant::now() + cleanup_wait(cancellation.as_ref())
                    }),
            )?;

            if exit_code == 0 {
                log_success(&command, logs_base_dir);
            } else {
                log_failure(&command, &format!("exit code {exit_code}"), logs_base_dir);
            }

            Ok(CaptureResult {
                exit_code,
                stdout,
                stderr,
                timed_out,
            })
        })()
    }

    #[cfg(test)]
    mod input_cleanup_tests {
        use super::*;

        #[test]
        fn configured_parent_frame_wait_expires_while_native_writer_remains_open() -> Result<()> {
            let mut outcomes = Vec::new();
            for milliseconds in [100, 350] {
                let mut read = 0;
                let mut write = 0;
                if unsafe {
                    windows_sys::Win32::System::Pipes::CreatePipe(
                        &mut read,
                        &mut write,
                        std::ptr::null_mut(),
                        4096,
                    )
                } == 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                let mut reader = unsafe { File::from_raw_handle(read as _) };
                let writer = unsafe { File::from_raw_handle(write as _) };
                let token = crate::WindowsSandboxCancellationToken::new(|| true)
                    .with_cleanup_budget(
                        crate::CleanupBudget::try_from(milliseconds)
                            .map_err(|message| anyhow::anyhow!(message))?,
                    );
                let (tx, rx) = std::sync::mpsc::channel();
                let started = std::time::Instant::now();
                let worker = std::thread::spawn(move || {
                    let mut frames = PipeFrameReader::default();
                    let mut deadline = None;
                    let result = receive_runner_frame(
                        &mut frames,
                        &mut reader,
                        &mut deadline,
                        cleanup_wait(Some(&token)),
                        Some(&token),
                        || true,
                    );
                    let cleanup_failed = result.err().is_some_and(|error| {
                        error.downcast_ref::<crate::SandboxCleanupError>().is_some()
                    });
                    let _ = tx.send((cleanup_failed, started.elapsed()));
                });
                let before_release = rx.recv_timeout(Duration::from_millis(milliseconds + 500));
                let writer_open = unsafe {
                    windows_sys::Win32::Storage::FileSystem::GetFileType(writer.as_raw_handle() as _)
                } == windows_sys::Win32::Storage::FileSystem::FILE_TYPE_PIPE;
                drop(writer);
                worker
                    .join()
                    .map_err(|_| anyhow::anyhow!("native frame fixture panic"))?;
                outcomes.push((milliseconds, before_release, writer_open));
            }
            for (milliseconds, observed, writer_open) in outcomes {
                let (cleanup_failed, elapsed) = observed?;
                assert!(cleanup_failed && writer_open);
                assert!(elapsed >= Duration::from_millis(milliseconds.saturating_sub(30)));
                assert!(elapsed < Duration::from_millis(milliseconds + 500));
            }
            Ok(())
        }

        #[test]
        fn delayed_cleanup_announcement_limits_parent_wait_and_keeps_native_exit_facts()
        -> Result<()> {
            let python = String::from_utf8(
                std::process::Command::new("where.exe")
                    .arg("python")
                    .output()?
                    .stdout,
            )?;
            let python = python
                .lines()
                .next()
                .ok_or_else(|| anyhow::anyhow!("Python required"))?;
            let status = std::process::Command::new(python)
                .args(["-c", "import sys; sys.exit(7)"])
                .status()?;
            let native_exit = status
                .code()
                .ok_or_else(|| anyhow::anyhow!("native exit missing"))?;
            let mut read = 0;
            let mut write = 0;
            if unsafe {
                windows_sys::Win32::System::Pipes::CreatePipe(
                    &mut read,
                    &mut write,
                    std::ptr::null_mut(),
                    4096,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut reader = unsafe { File::from_raw_handle(read as _) };
            let mut writer = unsafe { File::from_raw_handle(write as _) };
            let deadline = std::time::Instant::now() + Duration::from_millis(80);
            write_frame(
                &mut writer,
                &FramedMessage {
                    version: IPC_PROTOCOL_VERSION,
                    message: Message::CleanupStarted {
                        payload: crate::CleanupStartedPayload {
                            deadline: crate::CleanupDeadlinePayload::new(deadline)?,
                            exit_code: Some(native_exit),
                            timed_out: false,
                        },
                    },
                },
            )?;
            std::thread::sleep(Duration::from_millis(100));
            let observed = Arc::new(std::sync::Mutex::new((None, None, false)));
            let getter = observed.clone();
            let observer = observed.clone();
            let token = crate::WindowsSandboxCancellationToken::new(|| false)
                .with_cleanup_deadline(move || {
                    *getter
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .0
                        .get_or_insert_with(|| std::time::Instant::now() + Duration::from_secs(10))
                })
                .with_cleanup_started(move |candidate, code, timed_out| {
                    let mut state = observer
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    state.0 = Some(
                        state
                            .0
                            .map_or(candidate, |previous| previous.min(candidate)),
                    );
                    state.1 = code;
                    state.2 = timed_out;
                    candidate
                });
            let (tx, rx) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || -> Result<()> {
                let mut frames = PipeFrameReader::default();
                let mut cleanup_deadline = None;
                let frame = receive_runner_frame(
                    &mut frames,
                    &mut reader,
                    &mut cleanup_deadline,
                    Duration::from_secs(10),
                    Some(&token),
                    || false,
                )?
                .ok_or_else(|| anyhow::anyhow!("cleanup announcement missing"))?;
                let Message::CleanupStarted { payload } = frame.message else {
                    anyhow::bail!("unexpected fixture frame");
                };
                let facts = observe_cleanup_started(payload, &mut cleanup_deadline, Some(&token))?;
                let next = receive_runner_frame(
                    &mut frames,
                    &mut reader,
                    &mut cleanup_deadline,
                    Duration::from_secs(10),
                    Some(&token),
                    || false,
                );
                tx.send((facts, next.is_err()))?;
                Ok(())
            });
            let before_release = rx.recv_timeout(Duration::from_millis(500));
            drop(writer);
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("cleanup announcement fixture panic"))??;
            let (facts, expired) = before_release?;
            let observed = observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(native_exit, 7);
            assert_eq!(facts.exit_code, Some(native_exit));
            assert!(!facts.timed_out);
            assert!(
                expired,
                "parent wait cannot renew an expired helper deadline"
            );
            assert!(
                observed
                    .0
                    .is_some_and(|deadline| deadline <= std::time::Instant::now())
            );
            assert_eq!(observed.1, Some(native_exit));
            assert!(!observed.2);
            Ok(())
        }

        #[test]
        fn actual_termination_frame_preserves_the_existing_host_deadline() -> Result<()> {
            let mut read = 0;
            let mut write = 0;
            if unsafe {
                windows_sys::Win32::System::Pipes::CreatePipe(
                    &mut read,
                    &mut write,
                    std::ptr::null_mut(),
                    4096,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut reader = unsafe { File::from_raw_handle(read as _) };
            let writer = unsafe { File::from_raw_handle(write as _) };
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let token = crate::WindowsSandboxCancellationToken::new(|| true)
                .with_cleanup_deadline(move || deadline);
            let mut input = spawn_input_writer(
                writer,
                Vec::new(),
                None,
                Arc::new(AtomicUsize::new(0)),
                None,
                Arc::new(AtomicUsize::new(0)),
                Some(token),
            );
            let mut frames = PipeFrameReader::default();
            let poll_deadline = std::time::Instant::now() + Duration::from_secs(2);
            let frame = loop {
                match frames.poll(&mut reader)? {
                    FramePoll::Message(frame) => break Some(frame),
                    FramePoll::Closed => break None,
                    _ if std::time::Instant::now() >= poll_deadline => break None,
                    _ => std::thread::sleep(Duration::from_millis(5)),
                }
            };
            input.finish(poll_deadline)??;
            let frame = frame.ok_or_else(|| anyhow::anyhow!("termination frame missing"))?;
            let Message::Terminate { payload } = frame.message else {
                anyhow::bail!("expected termination frame");
            };
            assert!(
                payload.deadline()? <= deadline,
                "the transport cannot allocate a fresh cleanup budget"
            );
            Ok(())
        }
        use std::os::windows::io::{FromRawHandle, OwnedHandle};

        #[test]
        fn failed_source_closes_actual_child_input_and_keeps_confirmed_exit_without_false_cleanup_failure()
        -> Result<()> {
            use std::os::windows::io::IntoRawHandle;
            use std::process::{Child, Command, Stdio};
            struct Peer(Child);
            impl Drop for Peer {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let tmp = tempfile::TempDir::new()?;
            let mut child = Peer(Command::new("python").args(["-u", "-c", "import pathlib,sys; assert sys.stdin.buffer.read()==b''; pathlib.Path('input.eof').write_text('seen'); sys.exit(7)"])
                .current_dir(tmp.path()).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::inherit()).spawn()?);
            let input = child
                .0
                .stdin
                .take()
                .ok_or_else(|| anyhow::anyhow!("child input"))?;
            let input = unsafe { File::from_raw_handle(input.into_raw_handle()) };
            let mut owner = spawn_input_writer(
                input,
                Vec::new(),
                Some(Box::new(|| super::super::SandboxInputPoll::Failed)),
                Arc::new(AtomicUsize::new(0)),
                None,
                Arc::new(AtomicUsize::new(0)),
                None,
            );
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let actual = loop {
                if let Some(status) = child.0.try_wait()? {
                    break status
                        .code()
                        .ok_or_else(|| anyhow::anyhow!("native status"))?;
                }
                if std::time::Instant::now() >= deadline {
                    anyhow::bail!("child did not observe failed-source EOF");
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(actual, 7);
            assert!(tmp.path().join("input.eof").exists());
            let (mut response, mut peer) = native_pipe()?;
            write_frame(
                &mut peer,
                &FramedMessage {
                    version: IPC_PROTOCOL_VERSION,
                    message: Message::Exit {
                        payload: crate::ipc_framed::ExitPayload {
                            exit_code: actual,
                            timed_out: false,
                            cleanup_complete: true,
                        },
                    },
                },
            )?;
            let message = receive_runner_frame(
                &mut PipeFrameReader::default(),
                &mut response,
                &mut None,
                Duration::from_secs(2),
                None,
                || false,
            )?
            .ok_or_else(|| anyhow::anyhow!("exit frame"))?;
            let Message::Exit { payload } = message.message else {
                anyhow::bail!("exit expected");
            };
            let error = finish_capture_result(runner_exit_result(payload), &mut owner, deadline)
                .expect_err("source failure must remain visible");
            let facts = error
                .downcast_ref::<crate::SandboxCaptureInputError>()
                .ok_or_else(|| anyhow::anyhow!("input exit facts missing: {error}"))?;
            assert_eq!(facts.exit_code, actual);
            assert!(!facts.timed_out);
            assert!(
                !error.is::<crate::SandboxCaptureCleanupError>()
                    && !error.is::<crate::SandboxCleanupError>()
            );
            assert!(
                owner.worker.is_none(),
                "failed source worker must actually join"
            );
            Ok(())
        }

        fn native_pipe() -> Result<(File, File)> {
            let mut read = 0;
            let mut write = 0;
            if unsafe {
                windows_sys::Win32::System::Pipes::CreatePipe(
                    &mut read,
                    &mut write,
                    std::ptr::null_mut(),
                    4096,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(unsafe {
                (
                    File::from_raw_handle(read as _),
                    File::from_raw_handle(write as _),
                )
            })
        }

        #[test]
        fn failed_cleanup_exit_frame_keeps_native_exit_facts_after_parent_input_join() -> Result<()>
        {
            for (code, timed_out) in [(7, false), (1, true)] {
                let actual = std::process::Command::new("python")
                    .args(["-c", &format!("import sys; sys.exit({code})")])
                    .status()?
                    .code()
                    .ok_or_else(|| anyhow::anyhow!("native exit status unavailable"))?;
                assert_eq!(actual, code);
                let (mut response, mut peer) = native_pipe()?;
                write_frame(
                    &mut peer,
                    &FramedMessage {
                        version: IPC_PROTOCOL_VERSION,
                        message: Message::Exit {
                            payload: crate::ipc_framed::ExitPayload {
                                exit_code: actual,
                                timed_out,
                                cleanup_complete: false,
                            },
                        },
                    },
                )?;
                let message = receive_runner_frame(
                    &mut PipeFrameReader::default(),
                    &mut response,
                    &mut None,
                    Duration::from_secs(2),
                    None,
                    || false,
                )?
                .ok_or_else(|| anyhow::anyhow!("exit response missing"))?;
                let Message::Exit { payload } = message.message else {
                    anyhow::bail!("exit response expected");
                };
                let (input_peer, input) = native_pipe()?;
                let mut owner = spawn_input_writer(
                    input,
                    vec![42; 64 * 1024],
                    None,
                    Arc::new(AtomicUsize::new(0)),
                    None,
                    Arc::new(AtomicUsize::new(0)),
                    None,
                );
                let deadline = std::time::Instant::now() + Duration::from_secs(2);
                while crate::available_pipe_bytes(&input_peer)?.is_none_or(|n| n == 0) {
                    if std::time::Instant::now() >= deadline {
                        anyhow::bail!("input write readiness");
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                let error =
                    finish_capture_result(runner_exit_result(payload), &mut owner, deadline)
                        .expect_err(
                            "failed range cleanup cannot become successful after a local join",
                        );
                let facts = error
                    .downcast_ref::<crate::SandboxCaptureCleanupError>()
                    .ok_or_else(|| anyhow::anyhow!("typed cleanup facts missing: {error}"))?;
                assert!(
                    owner.worker.is_none(),
                    "native input writer must actually join"
                );
                assert_eq!(facts.exit_code, Some(actual));
                assert_eq!(facts.timed_out, timed_out);
            }
            Ok(())
        }

        #[test]
        fn failed_cleanup_exit_facts_survive_expired_parent_join_and_missing_frame_stays_unknown()
        -> Result<()> {
            let native = std::process::Command::new("python")
                .args(["-c", "import sys; sys.exit(7)"])
                .status()?
                .code()
                .ok_or_else(|| anyhow::anyhow!("native exit"))?;
            let (input_peer, input) = native_pipe()?;
            let (release, held) = std::sync::mpsc::channel();
            let mut owner = InputWriter {
                worker: Some(std::thread::spawn(move || {
                    let _ = held.recv();
                    drop(input);
                    Ok(())
                })),
                done: Arc::new(AtomicBool::new(false)),
                cleanup_deadline: None,
            };
            let (mut response, mut peer) = native_pipe()?;
            write_frame(
                &mut peer,
                &FramedMessage {
                    version: IPC_PROTOCOL_VERSION,
                    message: Message::Exit {
                        payload: crate::ipc_framed::ExitPayload {
                            exit_code: native,
                            timed_out: false,
                            cleanup_complete: false,
                        },
                    },
                },
            )?;
            let message = receive_runner_frame(
                &mut PipeFrameReader::default(),
                &mut response,
                &mut None,
                Duration::from_secs(2),
                None,
                || false,
            )?
            .ok_or_else(|| anyhow::anyhow!("exit response"))?;
            let Message::Exit { payload } = message.message else {
                anyhow::bail!("exit expected");
            };
            let failure = finish_capture_result(
                runner_exit_result(payload),
                &mut owner,
                std::time::Instant::now(),
            );
            let retained = owner.worker.is_some();
            release.send(())?;
            let _ = owner.finish(std::time::Instant::now() + Duration::from_secs(2))?;
            let error = failure.expect_err("unjoined parent cannot acknowledge cleanup");
            let facts = error
                .downcast_ref::<crate::SandboxCaptureCleanupError>()
                .ok_or_else(|| anyhow::anyhow!("known facts missing"))?;
            assert!(retained && owner.worker.is_none());
            assert_eq!(facts.exit_code, Some(7));
            assert!(!facts.timed_out);
            assert_eq!(crate::available_pipe_bytes(&input_peer)?, None);
            drop(peer);
            let (mut response, peer) = native_pipe()?;
            drop(peer);
            assert!(
                receive_runner_frame(
                    &mut PipeFrameReader::default(),
                    &mut response,
                    &mut None,
                    Duration::from_secs(2),
                    None,
                    || false
                )?
                .is_none()
            );
            let unknown = finish_capture_result(
                Err(anyhow::anyhow!("runner closed without confirmation")),
                &mut owner,
                std::time::Instant::now(),
            )
            .expect_err("EOF cannot prove range cleanup");
            let facts = unknown
                .downcast_ref::<crate::SandboxCaptureCleanupError>()
                .ok_or_else(|| anyhow::anyhow!("unknown facts missing"))?;
            assert_eq!(
                facts.exit_code, None,
                "a locally observed child exit cannot replace the missing wire result"
            );
            assert!(!facts.timed_out);
            Ok(())
        }

        #[test]
        fn stalled_peer_process_response_does_not_outlive_capture_cleanup_deadline() -> Result<()> {
            use std::io::Write;
            use std::os::windows::io::IntoRawHandle;
            use std::process::{Child, Command, Stdio};
            struct Peer(Child);
            impl Drop for Peer {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let mut payload_prefix = 1024u32.to_le_bytes().to_vec();
            payload_prefix.extend_from_slice(b"{\"version\":8");
            for (prefix, by_timeout, expired_shared_deadline) in
                [Vec::new(), vec![0, 4], payload_prefix]
                    .into_iter()
                    .flat_map(|prefix| [(prefix.clone(), false), (prefix, true)])
                    .flat_map(|(prefix, by_timeout)| {
                        [
                            (prefix.clone(), by_timeout, false),
                            (prefix, by_timeout, true),
                        ]
                    })
            {
                let tmp = tempfile::TempDir::new()?;
                let ready = tmp.path().join("response-ready");
                let mut peer = Peer(Command::new("python").args(["-u", "-c", "import base64,os,sys,pathlib; os.write(1,base64.b64decode(sys.argv[1])); pathlib.Path(sys.argv[2]).write_text('ready'); sys.stdin.buffer.read(1)"])
                    .arg(encode_bytes(&prefix)).arg(&ready)
                    .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?);
                let startup = std::time::Instant::now() + Duration::from_secs(5);
                while !ready.exists() {
                    if peer.0.try_wait()?.is_some() || std::time::Instant::now() >= startup {
                        anyhow::bail!("response peer readiness");
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                let stdout = peer
                    .0
                    .stdout
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("response peer output"))?;
                let mut pipe = unsafe { File::from_raw_handle(stdout.into_raw_handle()) };
                let (sender, receiver) = std::sync::mpsc::channel();
                let worker = std::thread::spawn(move || {
                    let execution_deadline = std::time::Instant::now() + Duration::from_millis(40);
                    let already_expired = std::time::Instant::now();
                    let cancellation = expired_shared_deadline.then(|| {
                        crate::WindowsSandboxCancellationToken::new(|| true)
                            .with_cleanup_deadline(move || already_expired)
                    });
                    let result = receive_runner_frame(
                        &mut PipeFrameReader::default(),
                        &mut pipe,
                        &mut None,
                        if expired_shared_deadline {
                            Duration::from_secs(10)
                        } else {
                            Duration::from_millis(80)
                        },
                        cancellation.as_ref(),
                        || !by_timeout || std::time::Instant::now() >= execution_deadline,
                    );
                    let _ = sender.send(
                        result
                            .err()
                            .is_some_and(|error| error.is::<crate::SandboxCleanupError>()),
                    );
                });
                let observed = receiver.recv_timeout(Duration::from_millis(500));
                let refused_before_exit = matches!(observed, Ok(true));
                let peer_live = peer.0.try_wait()?.is_none();
                peer.0
                    .stdin
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("response peer input"))?
                    .write_all(b"R")?;
                let peer_success = peer.0.wait()?.success();
                worker
                    .join()
                    .map_err(|_| anyhow::anyhow!("response reader fixture failed"))?;
                assert!(
                    peer_success && peer_live && refused_before_exit,
                    "capture must expire while its real peer still holds an incomplete response: {prefix:?}, timeout={by_timeout}, shared_deadline={expired_shared_deadline}"
                );
            }
            Ok(())
        }

        #[test]
        fn expired_input_cleanup_drop_keeps_native_owner_without_a_new_grace_period() -> Result<()>
        {
            use std::io::{Read, Write};
            let mut read = 0;
            let mut write = 0;
            if unsafe {
                windows_sys::Win32::System::Pipes::CreatePipe(
                    &mut read,
                    &mut write,
                    std::ptr::null_mut(),
                    4096,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut pipe = unsafe { File::from_raw_handle(read as _) };
            let mut output = unsafe { File::from_raw_handle(write as _) };
            output.write_all(&[42; 4096])?;
            let (cancelled, native_cancelled) = std::sync::mpsc::channel();
            let (release, held) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                let result = write_frame(
                    &mut output,
                    &FramedMessage {
                        version: IPC_PROTOCOL_VERSION,
                        message: Message::CloseStdin {
                            payload: EmptyPayload::default(),
                        },
                    },
                );
                let _ = cancelled.send(result.as_ref().err().is_some_and(|error| {
                    error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.raw_os_error() == Some(995))
                }));
                let _ = held.recv();
                drop(output);
                result
            });
            let thread_id = worker.thread().id();
            let mut owner = InputWriter {
                worker: Some(worker),
                done: Arc::new(AtomicBool::new(false)),
                cleanup_deadline: None,
            };
            let expired = owner
                .finish(std::time::Instant::now() + Duration::from_millis(100))
                .is_err();
            let cancellation = native_cancelled.recv_timeout(Duration::from_secs(2));
            let started = std::time::Instant::now();
            drop(owner);
            let drop_duration = started.elapsed();
            let retained = retained_input_writers()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .any(|worker| worker.thread().id() == thread_id && !worker.is_finished());
            let mut bytes = vec![0; 4096];
            pipe.read_exact(&mut bytes)?;
            let native_writer_held = crate::available_pipe_bytes(&pipe)? == Some(0);
            release.send(())?;
            let worker = {
                let mut registry = retained_input_writers()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let index = registry
                    .iter()
                    .position(|worker| worker.thread().id() == thread_id)
                    .ok_or_else(|| anyhow::anyhow!("native worker owner lost"))?;
                registry.swap_remove(index)
            };
            let result = worker
                .join()
                .map_err(|_| anyhow::anyhow!("retained writer fixture failed"))?;
            assert!(result.is_err());
            assert!(
                matches!(cancellation, Ok(true)),
                "actual native blocked write must be cancelled"
            );
            assert!(
                expired && retained && native_writer_held,
                "unfinished native writer must remain owned after cleanup expires"
            );
            assert!(
                drop_duration < Duration::from_millis(200),
                "Drop must reuse the expired deadline: {drop_duration:?}"
            );
            assert_eq!(bytes, vec![42; 4096]);
            assert_eq!(crate::available_pipe_bytes(&pipe)?, None);
            Ok(())
        }

        #[test]
        fn incomplete_runner_frames_expire_after_cancellation_with_writer_still_open() -> Result<()>
        {
            use std::io::Write;
            let mut payload_prefix = 1024u32.to_le_bytes().to_vec();
            payload_prefix.extend_from_slice(b"{\"version\":8");
            for prefix in [Vec::new(), vec![0, 4], payload_prefix] {
                let mut read = 0;
                let mut write = 0;
                if unsafe {
                    windows_sys::Win32::System::Pipes::CreatePipe(
                        &mut read,
                        &mut write,
                        std::ptr::null_mut(),
                        4096,
                    )
                } == 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                let mut pipe = unsafe { File::from_raw_handle(read as _) };
                let mut peer = unsafe { File::from_raw_handle(write as _) };
                peer.write_all(&prefix)?;
                let cancelled = Arc::new(AtomicBool::new(false));
                let calls = Arc::new(AtomicUsize::new(0));
                let worker_cancelled = cancelled.clone();
                let worker_calls = calls.clone();
                let (sender, receiver) = std::sync::mpsc::channel();
                let worker = std::thread::spawn(move || {
                    let mut reader = PipeFrameReader::default();
                    let mut deadline = None;
                    let result = receive_runner_frame(
                        &mut reader,
                        &mut pipe,
                        &mut deadline,
                        Duration::from_millis(80),
                        None,
                        || {
                            worker_calls.fetch_add(1, Ordering::Release);
                            worker_cancelled.load(Ordering::Acquire)
                        },
                    );
                    let _ = sender.send(
                        result
                            .err()
                            .is_some_and(|error| error.is::<crate::SandboxCleanupError>()),
                    );
                });
                let startup = std::time::Instant::now() + Duration::from_secs(2);
                while calls.load(Ordering::Acquire) == 0 && std::time::Instant::now() < startup {
                    std::thread::sleep(Duration::from_millis(5));
                }
                let before_cancel = receiver.try_recv().is_err();
                cancelled.store(true, Ordering::Release);
                let observed = receiver.recv_timeout(Duration::from_millis(500));
                let refused_before_peer_close = matches!(observed, Ok(true));
                let peer_open = unsafe {
                    windows_sys::Win32::Storage::FileSystem::GetFileType(peer.as_raw_handle() as _)
                } != 0;
                // Release first and join even when the old blocking reader is
                // reinstated, so the regression cannot hang its test process.
                drop(peer);
                worker
                    .join()
                    .map_err(|_| anyhow::anyhow!("response reader fixture failed"))?;
                assert!(
                    calls.load(Ordering::Acquire) > 0 && before_cancel,
                    "an open idle pipe must remain pending before cancellation"
                );
                assert!(
                    peer_open && refused_before_peer_close,
                    "cleanup deadline must expire without waiting for peer EOF: prefix={prefix:?}"
                );
            }
            Ok(())
        }

        #[test]
        fn actual_blocked_input_frame_retains_owner_then_cancels_and_joins() -> Result<()> {
            let mut reader = 0;
            let mut writer = 0;
            if unsafe {
                windows_sys::Win32::System::Pipes::CreatePipe(
                    &mut reader,
                    &mut writer,
                    std::ptr::null_mut(),
                    4096,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let reader = unsafe { OwnedHandle::from_raw_handle(reader as _) };
            let file = unsafe { File::from_raw_handle(writer as _) };
            let mut owner = spawn_input_writer(
                file,
                vec![42; 64 * 1024],
                None,
                Arc::new(AtomicUsize::new(0)),
                None,
                Arc::new(AtomicUsize::new(0)),
                None,
            );
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                let mut available = 0;
                if unsafe {
                    windows_sys::Win32::System::Pipes::PeekNamedPipe(
                        reader.as_raw_handle() as _,
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null_mut(),
                        &mut available,
                        std::ptr::null_mut(),
                    )
                } == 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                if available > 0 {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "input frame must enter actual pipe"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(!owner.worker.as_ref().expect("owned writer").is_finished());
            assert!(owner.finish(std::time::Instant::now()).is_err());
            assert!(
                owner.worker.is_some(),
                "expired deadline must retain writer"
            );
            let result = owner.finish(deadline)?;
            assert!(owner.worker.is_none(), "joined native writer required");
            let error = result.expect_err("blocked native write must be cancelled");
            assert!(
                input_transport_closed(&error),
                "joined cancellation is expected after runner cleanup: {error}"
            );
            assert!(
                error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.raw_os_error() == Some(995)),
                "{error}"
            );
            assert_ne!(
                unsafe {
                    windows_sys::Win32::Storage::FileSystem::GetFileType(reader.as_raw_handle() as _)
                },
                0
            );
            Ok(())
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::run_windows_sandbox_capture_for_permission_profile;

#[cfg(not(target_os = "windows"))]
mod stub {
    use super::ElevatedSandboxProfileCaptureRequest;
    use anyhow::Result;
    use anyhow::bail;

    #[derive(Debug, Default)]
    pub struct CaptureResult {
        pub exit_code: i32,
        pub stdout: Vec<u8>,
        pub stderr: Vec<u8>,
        pub timed_out: bool,
    }

    /// Stub implementation for non-Windows targets; sandboxing only works on Windows.
    #[allow(clippy::too_many_arguments)]
    pub fn run_windows_sandbox_capture_for_permission_profile(
        _request: ElevatedSandboxProfileCaptureRequest<'_>,
    ) -> Result<CaptureResult> {
        bail!("Windows sandbox is only available on Windows")
    }
}

#[cfg(not(target_os = "windows"))]
pub use stub::run_windows_sandbox_capture_for_permission_profile;
