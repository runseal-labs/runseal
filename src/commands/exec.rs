use super::*;

mod control;
mod output;
mod signals;
mod terminal;

#[cfg(windows)]
pub(crate) fn run_console_output_worker(args: &[String]) -> Result<(), String> {
    output::run_console_output_worker(args)
}

const EXEC_HELP_TEXT: &str = "\
Usage: runseal exec [--json|--events] [--policy <policy>] [--network <mode>] [--cwd <path>] [--timeout-ms <ms>] -- <command> [args...]

Options:
  --policy       danger-full-access, read-only, workspace-contained, or workspace-write
  --network      unmanaged, disabled, or proxy
  --cwd          existing workspace directory
  --timeout-ms   execution timeout in milliseconds
  --stdin        empty (default) or inherit; inherit requires plain output
  --control-fd   forward caller duplex fd 3; requires plain pipe output
  --pty          use a terminal; requires --stdin inherit and plain output

On Windows, console Ctrl-C and Ctrl-Break request execution cancellation.
";

fn machine_output(args: &[String]) -> bool {
    args.iter()
        .take_while(|arg| arg.as_str() != "--")
        .any(|arg| arg == "--json" || arg == "--events")
}

fn failure_exit(error: &RunSealError) -> i32 {
    match error.code.as_str() {
        "EXECUTION_TIMEOUT" => 124,
        "EXECUTION_CANCELLED" => 130,
        _ => 125,
    }
}

pub(crate) fn run(args: &[String]) -> Result<i32, String> {
    let control = crate::execution::ExecutionControl::default();
    let result = signals::SignalFrontend::new(control.clone()).and_then(|mut signals| {
        let result = run_inner(args, control.clone(), &mut signals);
        let cleanup = signals
            .finish(control.begin_cleanup())
            .and_then(|()| signals.unregister())
            .map_err(|reason| RunSealError::new("EXECUTION_CLEANUP_FAILED", reason));
        match result {
            // A completed inner call may already have delivered a result or
            // diagnostic. Late frontend failure must not append another frame.
            Ok(code) => Ok(if cleanup.is_ok() { code } else { 125 }),
            Err(error) => cleanup.and(Err(error)),
        }
    });
    match result {
        Ok(code) => Ok(code),
        Err(error) => {
            let code = failure_exit(&error);
            let machine = machine_output(args);
            let bytes = if machine {
                format!("{}\n", cli_error_payload(error))
            } else {
                format!("[runseal:{}] {}\n", error.code, error.reason)
            };
            if let Ok(mut output) = output::Output::new(!machine, control.clone()) {
                let _ = output.write(bytes.as_bytes());
                let _ = output.finish(control.begin_cleanup());
            }
            Ok(code)
        }
    }
}

fn run_inner(
    args: &[String],
    control: crate::execution::ExecutionControl,
    signals: &mut signals::SignalFrontend,
) -> Result<i32, RunSealError> {
    if matches!(args, [flag] if flag == "--help" || flag == "-h") {
        print!("{EXEC_HELP_TEXT}");
        return Ok(0);
    }
    let request =
        parse_exec_args(args).map_err(|error| RunSealError::new("INVALID_REQUEST", error))?;
    let cwd = normalize_execution_cwd(&request.cwd)
        .map_err(|error| RunSealError::new(error.code, "execution cwd is unavailable"))?;
    let policy = normalize_policy(
        &Value::String(request.policy.clone()),
        &cwd,
        request.network,
    )
    .map_err(|error| RunSealError::new(error.code, "unknown policy profile"))?;
    let stdout = output::Output::new(false, control.clone())?;
    let stderr = output::Output::new(true, control.clone())?;
    let control_frontend = if request.control_fd3 {
        Some(control::ControlFrontend::new(control.clone())?)
    } else {
        None
    };
    let terminal = if request.pty {
        Some(
            terminal::TerminalFrontend::new(control.clone()).map_err(|_| {
                RunSealError::new(
                    if cfg!(windows) {
                        "BACKEND_UNAVAILABLE"
                    } else {
                        "BACKEND_CAPABILITY_MISSING"
                    },
                    "terminal frontend unavailable",
                )
            })?,
        )
    } else {
        None
    };
    let execution_io = terminal.as_ref().map_or(
        if request.control_fd3 {
            crate::backend::ExecutionIo::PipeControl
        } else {
            crate::backend::ExecutionIo::Pipe
        },
        |terminal| {
            let (rows, cols) = terminal.dimensions();
            crate::backend::ExecutionIo::Pty { rows, cols }
        },
    );
    let mut input_reader = None;
    let stdin = if request.stdin_inherit {
        let queue = crate::backend::ExecutionInput::default();
        input_reader = Some(
            spawn_stdin_reader(queue.clone(), control.clone(), request.pty).map_err(|_| {
                RunSealError::new("INTERNAL_ERROR", "execution input frontend unavailable")
            })?,
        );
        ExecutionStdin::Stream(queue)
    } else {
        ExecutionStdin::Empty
    };
    let execution = ExecutionRequest {
        control_input: control_frontend
            .as_ref()
            .and_then(control::ControlFrontend::input),
        io: execution_io,
        ids: crate::events::new_execution_ids(),
        control: control.clone(),
        command: request.command,
        cwd,
        policy,
        stdin,
        env: ExecutionEnv::default(),
        metadata: None,
        timeout: request.timeout,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let stdout_bytes = Vec::new();
    let stderr_bytes = Vec::new();
    let mut frontend = Frontend {
        signals,
        stdout,
        stderr,
        control_frontend,
        terminal,
        input_reader,
        json: request.json,
        events: request.events,
        stdout_bytes,
        stderr_bytes,
    };
    let execution_result =
        crate::execution::execute_command_with_observer(execution, &mut frontend);
    let Frontend {
        mut stdout,
        mut stderr,
        stdout_bytes,
        stderr_bytes,
        ..
    } = frontend;
    let (_events, mut result) = match execution_result {
        Ok(result) => result,
        Err(err) if request.events && err.terminal_event.is_some() => {
            return Ok(failure_exit(&err));
        }
        Err(err) => {
            let code = failure_exit(&err);
            let (target, bytes) = if request.json || request.events {
                (&mut stdout, format!("{}\n", cli_error_payload(err)))
            } else {
                (
                    &mut stderr,
                    format!("[runseal:{}] {}\n", err.code, err.reason),
                )
            };
            // The channel may be gone; never append a second diagnostic after a partial write.
            let _ = target.write(bytes.as_bytes());
            return Ok(code);
        }
    };

    if request.events {
        return Ok(0);
    }

    if request.json {
        if let Some(object) = result.as_object_mut() {
            object.remove("stdout");
            object.remove("stderr");
        }
        result["output"] = json!({
            "stdout":{"encoding":"base64","data":format!("base64:{}",STANDARD.encode(&stdout_bytes)),"bytes":stdout_bytes.len(),"truncated":false},
            "stderr":{"encoding":"base64","data":format!("base64:{}",STANDARD.encode(&stderr_bytes)),"bytes":stderr_bytes.len(),"truncated":false}
        });
        if let Err(error) = stdout.write(format!("{result}\n").as_bytes()) {
            let _ = stdout.finish(control.begin_cleanup());
            return Ok(failure_exit(&error));
        }
        if stdout.finish(control.begin_cleanup()).is_err() {
            return Ok(125);
        }
        return Ok(0);
    }
    let code = result["exit_code"]
        .as_i64()
        .ok_or_else(|| RunSealError::new("INTERNAL_ERROR", "execution result has no exit code"))?;
    i32::try_from(code)
        .map_err(|_| RunSealError::new("INTERNAL_ERROR", "execution exit code is out of range"))
}

struct Frontend<'a> {
    signals: &'a mut signals::SignalFrontend,
    stdout: output::Output,
    stderr: output::Output,
    control_frontend: Option<control::ControlFrontend>,
    terminal: Option<terminal::TerminalFrontend>,
    input_reader: Option<StdinReader>,
    json: bool,
    events: bool,
    stdout_bytes: Vec<u8>,
    stderr_bytes: Vec<u8>,
}

impl crate::execution::ExecutionObserver for Frontend<'_> {
    fn event(&mut self, event: &Value) -> Result<(), RunSealError> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        if !self.events {
            let stream = event["type"].as_str();
            if stream == Some("execution.control") {
                let bytes = STANDARD
                    .decode(
                        event["data"]
                            .as_str()
                            .and_then(|text| text.strip_prefix("base64:"))
                            .ok_or_else(|| {
                                RunSealError::new(
                                    "INTERNAL_ERROR",
                                    "invalid control output encoding",
                                )
                            })?,
                    )
                    .map_err(|_| {
                        RunSealError::new("INTERNAL_ERROR", "invalid control output bytes")
                    })?;
                return self
                    .control_frontend
                    .as_mut()
                    .ok_or_else(|| {
                        RunSealError::new("INTERNAL_ERROR", "control output endpoint unavailable")
                    })?
                    .write(&bytes);
            }

            if matches!(
                stream,
                Some("execution.stdout" | "execution.stderr" | "execution.terminal")
            ) {
                let encoded = event["data"]
                    .as_str()
                    .and_then(|text| text.strip_prefix("base64:"))
                    .ok_or_else(|| {
                        RunSealError::new("INTERNAL_ERROR", "invalid execution output encoding")
                    })?;
                let bytes = STANDARD.decode(encoded).map_err(|_| {
                    RunSealError::new("INTERNAL_ERROR", "invalid execution output bytes")
                })?;
                if self.json {
                    if stream == Some("execution.stdout") {
                        self.stdout_bytes.extend_from_slice(&bytes);
                    } else {
                        self.stderr_bytes.extend_from_slice(&bytes);
                    }
                    return Ok(());
                }
                let output = if stream != Some("execution.stderr") {
                    &mut self.stdout
                } else {
                    &mut self.stderr
                };
                return output.write(&bytes);
            }
            return Ok(());
        }
        self.stdout.write(format!("{event}\n").as_bytes())
    }

    fn cleanup(
        &mut self,
        deadline: std::time::Instant,
        _execution_cleanup_confirmed: bool,
    ) -> Result<(), RunSealError> {
        let output_deadline =
            deadline.min(std::time::Instant::now() + std::time::Duration::from_secs(2));
        let signals = self.signals.finish(output_deadline);
        let stdout = self.stdout.finish(output_deadline);
        let stderr = self.stderr.finish(output_deadline);
        let input = self
            .input_reader
            .as_mut()
            .map_or(Ok(()), |reader| reader.shutdown(output_deadline));
        let terminal = self
            .terminal
            .as_mut()
            .map_or(Ok(()), |terminal| terminal.finish(output_deadline));
        let control = self
            .control_frontend
            .as_mut()
            .map_or(Ok(()), |control| control.finish(output_deadline));
        input
            .and(signals)
            .and(terminal)
            .and(control)
            .and(stdout)
            .and(stderr)
            .map_err(|reason| RunSealError::new("EXECUTION_CLEANUP_FAILED", reason))
    }
}

struct StdinReader {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    cleanup_deadline: Option<std::time::Instant>,
    #[cfg(windows)]
    console: bool,
}

impl StdinReader {
    fn shutdown(&mut self, deadline: std::time::Instant) -> Result<(), String> {
        self.cleanup_deadline = Some(
            self.cleanup_deadline
                .map_or(deadline, |previous| previous.min(deadline)),
        );
        let deadline = self
            .cleanup_deadline
            .ok_or_else(|| "stdin cleanup deadline unavailable".to_string())?;
        use std::sync::atomic::Ordering;
        self.stop.store(true, Ordering::Release);
        let Some(thread) = self.thread.as_ref() else {
            return Ok(());
        };
        while !crate::execution::retained::thread_finished(thread) {
            #[cfg(windows)]
            {
                use std::os::windows::io::AsRawHandle;
                if !self.console {
                    unsafe {
                        windows_sys::Win32::System::IO::CancelSynchronousIo(
                            thread.as_raw_handle().cast(),
                        );
                    }
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err("execution stdin reader did not stop".to_string());
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let thread = self
            .thread
            .take()
            .ok_or_else(|| "execution stdin reader unavailable".to_string())?;
        thread
            .join()
            .map_err(|_| "execution stdin reader failed".to_string())
    }
}
impl Drop for StdinReader {
    fn drop(&mut self) {
        let deadline = self
            .cleanup_deadline
            .unwrap_or_else(|| std::time::Instant::now() + std::time::Duration::from_secs(2));
        let _ = self.shutdown(deadline);
        if let Some(thread) = self.thread.take() {
            crate::execution::retained::retain(thread);
        }
    }
}

fn spawn_stdin_reader(
    queue: crate::backend::ExecutionInput,
    control: crate::execution::ExecutionControl,
    pty: bool,
) -> Result<StdinReader, String> {
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let thread_stop = stop.clone();
    #[cfg(windows)]
    let console = {
        use std::io::IsTerminal;
        std::io::stdin().is_terminal()
    };
    #[cfg(not(windows))]
    let console = false;
    let thread = std::thread::Builder::new()
        .name("execution-stdin".to_string())
        .spawn(move || {
            use std::io::Read;
            use std::sync::atomic::Ordering;
            let mut input = (!console).then(|| std::io::stdin().lock());
            #[cfg(windows)]
            let mut console_input = terminal::ConsoleInput::default();
            #[cfg(windows)]
            let mut console_line = terminal::ConsoleLineInput::default();
            let mut buffer = [0; 64 * 1024];
            while !thread_stop.load(Ordering::Acquire) && !control.is_cancelled() {
                let capacity = match queue.remaining_capacity() {
                    Ok(capacity) => capacity
                        .min(buffer.len())
                        .min(crate::limits::deployment().stream_chunk_bytes),
                    Err(_) => return,
                };
                if capacity == 0 || (console && pty && capacity < 8192) {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                #[cfg(unix)]
                {
                    let mut descriptor = libc::pollfd {
                        fd: libc::STDIN_FILENO,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let ready = unsafe { libc::poll(&mut descriptor, 1, 20) };
                    if ready == 0 {
                        continue;
                    }
                    if ready < 0 {
                        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                        {
                            continue;
                        }
                        control.cancel();
                        return;
                    }
                }
                #[cfg(windows)]
                let read = if console && !pty {
                    console_line.read(capacity).map(|bytes| {
                        bytes.map(|bytes| {
                            buffer[..bytes.len()].copy_from_slice(&bytes);
                            bytes.len()
                        })
                    })
                } else if console {
                    console_input.read().map(|bytes| {
                        if bytes.is_empty() {
                            None
                        } else {
                            buffer[..bytes.len()].copy_from_slice(&bytes);
                            Some(bytes.len())
                        }
                    })
                } else {
                    input.as_mut().map_or(Ok(Some(0)), |input| {
                        input.read(&mut buffer[..capacity]).map(Some)
                    })
                };
                #[cfg(not(windows))]
                let read = input.as_mut().map_or(Ok(Some(0)), |input| {
                    input.read(&mut buffer[..capacity]).map(Some)
                });
                let count = match read {
                    Ok(None) => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
                    Ok(Some(0)) => {
                        if pty {
                            control.cancel();
                        } else {
                            let _ = queue.close();
                        }
                        return;
                    }
                    Ok(Some(count)) => count,
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        control.cancel();
                        return;
                    }
                };
                while !thread_stop.load(Ordering::Acquire) && !control.is_cancelled() {
                    match queue.write(buffer[..count].to_vec()) {
                        Ok(_) => break,
                        Err(crate::backend::InputError::Backpressure) => {
                            std::thread::sleep(std::time::Duration::from_millis(10))
                        }
                        Err(_) => {
                            control.cancel();
                            return;
                        }
                    }
                }
            }
        })
        .map_err(|_| "failed to start execution stdin reader".to_string())?;
    Ok(StdinReader {
        stop,
        thread: Some(thread),
        cleanup_deadline: None,
        #[cfg(windows)]
        console,
    })
}

#[cfg(all(test, windows))]
mod cleanup_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    struct Peer(Child);
    impl Drop for Peer {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn expired_frontend_deadline_is_reused_by_drop_and_retains_the_native_reader()
    -> anyhow::Result<()> {
        use anyhow::Context;
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::Foundation::{
            DUPLICATE_SAME_ACCESS, DuplicateHandle, WAIT_OBJECT_0,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, WaitForSingleObject};
        let tmp = tempfile::TempDir::new()?;
        let ready = tmp.path().join("ready");
        let mut peer = Peer(Command::new("python").args(["-u", "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('READY'); sys.stdin.buffer.read(1); sys.stdout.buffer.write(b'D'); sys.stdout.buffer.flush(); sys.exit(7)"])
            .arg(&ready).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?);
        let mut pipe = peer.0.stdout.take().context("native reader pipe")?;
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (returned_tx, returned_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _ = entered_tx.send(());
            let mut byte = [0; 1];
            let _ = pipe.read(&mut byte);
            let _ = returned_tx.send(());
            let _ = release_rx.recv();
        });
        let id = worker.thread().id();
        let mut native = std::ptr::null_mut();
        anyhow::ensure!(
            unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    worker.as_raw_handle(),
                    GetCurrentProcess(),
                    &mut native,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            } != 0,
            "native reader observation"
        );
        let native = unsafe { OwnedHandle::from_raw_handle(native) };
        let mut reader = StdinReader {
            stop: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            thread: Some(worker),
            cleanup_deadline: None,
            console: false,
        };
        let readiness = Instant::now() + Duration::from_secs(2);
        while !ready.exists() {
            anyhow::ensure!(Instant::now() < readiness, "owned peer readiness");
            std::thread::sleep(Duration::from_millis(5));
        }
        entered_rx.recv_timeout(Duration::from_secs(2))?;
        let original_deadline = Instant::now();
        assert!(reader.shutdown(original_deadline).is_err());
        assert!(
            peer.0.try_wait()?.is_none(),
            "peer retains its real writer endpoint"
        );
        let start = Instant::now();
        assert!(reader.shutdown(start + Duration::from_secs(2)).is_err());
        drop(reader);
        let duration = start.elapsed();
        let retained = crate::execution::retained::contains(id);
        // Release and join only this fixture before asserting the timing result.
        peer.0
            .stdin
            .take()
            .context("peer release")?
            .write_all(b"G")?;
        returned_rx.recv_timeout(Duration::from_secs(2))?;
        let peer_deadline = Instant::now() + Duration::from_secs(2);
        let code = loop {
            if let Some(status) = peer.0.try_wait()? {
                break status.code();
            }
            anyhow::ensure!(Instant::now() < peer_deadline, "owned peer exit");
            std::thread::sleep(Duration::from_millis(5));
        };
        release_tx.send(())?;
        anyhow::ensure!(
            unsafe { WaitForSingleObject(native.as_raw_handle(), 2000) } == WAIT_OBJECT_0,
            "owned native reader exit"
        );
        // Reproduce the state after another caller has already reaped this owner.
        let _ = crate::execution::retained::join_finished(id);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if unsafe { WaitForSingleObject(native.as_raw_handle(), 0) } == WAIT_OBJECT_0 {
                // A concurrent reaper may have joined this exact worker first.
                // Require native exit independently of which caller reaped it.
                let _ = crate::execution::retained::join_finished(id);
                if !crate::execution::retained::contains(id) {
                    break;
                }
            }
            anyhow::ensure!(Instant::now() < deadline, "retained native reader join");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(retained, "deadline failure must retain a real worker owner");
        assert!(
            duration < Duration::from_millis(500),
            "Drop cannot renew an expired deadline: {duration:?}"
        );
        assert_eq!(code, Some(7));
        assert!(!crate::execution::retained::contains(id));
        Ok(())
    }
}
