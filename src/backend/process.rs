#[cfg(target_os = "linux")]
use super::SandboxLevel;
use super::{
    BackendExecutionOutput, ExecutionEnv, ExecutionStdin, PlatformSandboxPlan,
    matches_environment_scrub_pattern,
};
use std::env;
use std::ffi::OsString;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::Path;
#[cfg(any(not(windows), test))]
use std::process::Child;
#[cfg(not(windows))]
use std::process::{Command, Stdio};
use std::process::{ExitStatus, Output};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
#[cfg(test)]
pub(super) fn spawn_local_command(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
) -> io::Result<BackendExecutionOutput> {
    spawn_local_command_with_output(plan, command, cwd, stdin, env, timeout, None)
}

#[cfg(windows)]
pub(super) fn spawn_local_command_with_output(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
    output: Option<super::ExecutionOutputSink>,
) -> io::Result<BackendExecutionOutput> {
    use std::os::windows::process::ExitStatusExt;
    if plan.is_sandbox_enforced() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "refusing to spawn sandboxed plan through local execution",
        ));
    }
    if output
        .as_ref()
        .is_some_and(|sink| sink.control.is_cancelled())
    {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "execution cancelled before spawn",
        ));
    }
    let mut environment = std::collections::HashMap::new();
    for (key, value) in minimal_environment(plan) {
        let key = key.into_string().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "environment key is not Unicode")
        })?;
        let value = value.into_string().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "environment value is not Unicode",
            )
        })?;
        environment.insert(key.to_ascii_uppercase(), value);
    }
    environment.extend(
        env.entries
            .iter()
            .map(|(key, value)| (key.to_ascii_uppercase(), value.clone())),
    );
    let terminal_size = output.as_ref().and_then(|sink| match sink.io {
        super::ExecutionIo::Pipe | super::ExecutionIo::PipeControl => None,
        super::ExecutionIo::Pty { rows, cols } => Some((rows, cols)),
    });
    let mut process = if output.as_ref().is_some_and(|sink| sink.io.has_control()) {
        codex_windows_sandbox::LocalExecutionProcess::spawn_with_control(
            command,
            cwd,
            &environment,
            !matches!(&stdin, ExecutionStdin::Empty),
        )
    } else {
        codex_windows_sandbox::LocalExecutionProcess::spawn_with_terminal(
            command,
            cwd,
            &environment,
            !matches!(&stdin, ExecutionStdin::Empty),
            terminal_size,
        )
    }
    .map_err(|error| {
        if error
            .downcast_ref::<codex_windows_sandbox::SandboxCleanupError>()
            .is_some()
        {
            io::Error::other(super::BackendCleanupError)
        } else {
            io::Error::other("local execution failed to start")
        }
    })?;
    if let Some(sink) = &output {
        let _ = sink.started();
    }
    let range_empty = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_readers = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stdout_reader = process.stdout.take().map(|pipe| {
        read_windows_pipe_in_thread(
            pipe,
            if terminal_size.is_some() {
                super::OutputStream::Terminal
            } else {
                super::OutputStream::Stdout
            },
            output.clone(),
            range_empty.clone(),
            stop_readers.clone(),
        )
    });
    let stderr_reader = process.stderr.take().map(|pipe| {
        read_windows_pipe_in_thread(
            pipe,
            super::OutputStream::Stderr,
            output.clone(),
            range_empty.clone(),
            stop_readers.clone(),
        )
    });
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let terminal = process.terminal();
    let input_failed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (control_writer, control_reader) = if let Some(control_pipe) = process.control.take() {
        let mut input = control_pipe.clone();
        let queue = output
            .as_ref()
            .and_then(|sink| sink.control_input.clone())
            .ok_or_else(|| io::Error::other("control input unavailable"))?;
        let writer_done = done.clone();
        let writer_sink = output.clone();
        let failed = input_failed.clone();
        let writer = thread::spawn(move || -> io::Result<()> {
            let result = (|| {
                loop {
                    if writer_done.load(std::sync::atomic::Ordering::Acquire)
                        || writer_sink
                            .as_ref()
                            .is_some_and(|sink| sink.control.is_cancelled())
                    {
                        return Ok(());
                    }
                    match queue
                        .poll()
                        .map_err(|_| io::Error::other("control input unavailable"))?
                    {
                        super::InputPoll::Data(bytes) => {
                            let mut offset = 0;
                            while offset < bytes.len() {
                                if writer_done.load(std::sync::atomic::Ordering::Acquire)
                                    || writer_sink
                                        .as_ref()
                                        .is_some_and(|sink| sink.control.is_cancelled())
                                {
                                    return Ok(());
                                }
                                match input.write(&bytes[offset..]) {
                                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                                    Ok(count) => offset += count,
                                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                        thread::sleep(Duration::from_millis(5))
                                    }
                                    Err(error) => return Err(error),
                                }
                            }
                            queue
                                .acknowledge(bytes.len())
                                .map_err(|_| io::Error::other("control acknowledgement failed"))?;
                        }
                        super::InputPoll::Eof => return input.close_input(),
                        super::InputPoll::Pending => thread::sleep(Duration::from_millis(5)),
                    }
                }
            })();
            if result.is_err() {
                failed.store(true, std::sync::atomic::Ordering::Release);
            }
            result
        });
        let reader_stop = stop_readers.clone();
        let reader_sink = output.clone();
        let failed = input_failed.clone();
        let reader = thread::spawn(move || -> io::Result<()> {
            let mut pipe = control_pipe;
            let mut bytes = [0; 64 * 1024];
            let result = (|| {
                while !reader_stop.load(std::sync::atomic::Ordering::Acquire) {
                    match pipe.read(&mut bytes) {
                        Ok(0) => return Ok(()),
                        Ok(count) => {
                            if let Some(sink) = &reader_sink {
                                sink.send(super::OutputStream::Control, &bytes[..count])?;
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(error) => return Err(error),
                    }
                }
                Ok(())
            })();
            if result
                .as_ref()
                .err()
                .is_some_and(|error: &io::Error| error.kind() != io::ErrorKind::Interrupted)
            {
                failed.store(true, std::sync::atomic::Ordering::Release);
            }
            result
        });
        (Some(writer), Some(reader))
    } else {
        (None, None)
    };
    let stdin_writer = match stdin {
        ExecutionStdin::Empty => None,
        ExecutionStdin::Bytes(bytes) | ExecutionStdin::File(bytes) => {
            write_stdin_in_thread(process.stdin.take(), bytes)
        }
        ExecutionStdin::Stream(queue) => process.stdin.take().map(|mut pipe| {
            let done = done.clone();
            let output = output.clone();
            let input_failed = input_failed.clone();
            thread::spawn(move || -> io::Result<()> {
                let result: io::Result<()> = (|| {
                    loop {
                        if done.load(std::sync::atomic::Ordering::Acquire)
                            || output
                                .as_ref()
                                .is_some_and(|sink| sink.control.is_cancelled())
                        {
                            return Ok(());
                        }
                        if let Some(terminal) = &terminal
                            && let Some(command) = output
                                .as_ref()
                                .and_then(|sink| sink.control.take_terminal_command())
                        {
                            match command {
                                crate::execution::TerminalCommand::Resize { rows, cols } => {
                                    terminal
                                        .resize(rows, cols)
                                        .map_err(|_| io::Error::other("terminal resize failed"))?
                                }
                                crate::execution::TerminalCommand::Interrupt => {
                                    pipe.write_all(&[3])?
                                }
                            }
                            continue;
                        }
                        match queue
                            .poll()
                            .map_err(|_| io::Error::other("execution input unavailable"))?
                        {
                            super::InputPoll::Data(bytes) => {
                                pipe.write_all(&bytes)?;
                                queue.acknowledge(bytes.len()).map_err(|_| {
                                    io::Error::other("execution input acknowledgement failed")
                                })?;
                            }
                            super::InputPoll::Eof => return Ok(()),
                            super::InputPoll::Pending => thread::sleep(Duration::from_millis(10)),
                        }
                    }
                })();
                if result.as_ref().err().is_some_and(|error| {
                    !matches!(
                        error.kind(),
                        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                    ) && error.raw_os_error()
                        != Some(windows_sys::Win32::Foundation::ERROR_OPERATION_ABORTED as i32)
                }) {
                    input_failed.store(true, std::sync::atomic::Ordering::Release);
                }
                result
            })
        }),
    };
    let started = Instant::now();
    let (status, timed_out) = loop {
        if input_failed.load(std::sync::atomic::Ordering::Acquire) {
            break (
                Err(io::Error::other(
                    "execution input or terminal control failed",
                )),
                false,
            );
        }
        let timed_out = timeout.is_some_and(|limit| started.elapsed() >= limit);
        if timed_out && let Some(sink) = &output {
            sink.control
                .request(crate::execution::TerminationCause::Timeout);
        }
        if timed_out
            || output
                .as_ref()
                .is_some_and(|sink| sink.control.is_cancelled())
        {
            break (Ok(()), timed_out);
        }
        match process.try_wait() {
            Ok(Some(_)) => break (Ok(()), false),
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => break (Err(error), false),
        }
    };
    done.store(true, std::sync::atomic::Ordering::Release);
    // One deadline covers the process range and owned I/O. A foreign writer reference
    // cannot keep an empty execution range waiting for pipe EOF indefinitely.
    let deadline = output.as_ref().map_or_else(
        || Instant::now() + crate::limits::deployment().cleanup_timeout(),
        |sink| sink.control.begin_cleanup(),
    );
    let cleanup = process.finish(deadline.saturating_duration_since(Instant::now()));
    range_empty.store(
        cleanup.is_ok() && terminal_size.is_none(),
        std::sync::atomic::Ordering::Release,
    );
    if cleanup.is_err() {
        stop_readers.store(true, std::sync::atomic::Ordering::Release);
    }
    let input = join_windows_io(stdin_writer, deadline, true);
    let control_input = join_windows_io(control_writer, deadline, false);
    let control_output = join_windows_io(control_reader, deadline, false);
    let terminal_close = join_windows_io(process.close_terminal(), deadline, false);
    range_empty.store(
        cleanup.is_ok() && terminal_close.as_ref().is_ok_and(Result::is_ok),
        std::sync::atomic::Ordering::Release,
    );
    let stdout = join_windows_io(stdout_reader, deadline, false);
    let stderr = join_windows_io(stderr_reader, deadline, false);
    if input.is_err()
        || stdout.is_err()
        || stderr.is_err()
        || control_input.is_err()
        || control_output.is_err()
    {
        stop_readers.store(true, std::sync::atomic::Ordering::Release);
    }
    let code = cleanup.map_err(|_| io::Error::other(super::BackendCleanupError))?;
    let io_complete = input.as_ref().is_ok_and(|result| {
        result.is_ok()
            || result.as_ref().err().is_some_and(|err| {
                matches!(
                    err.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                ) || err.raw_os_error()
                    == Some(windows_sys::Win32::Foundation::ERROR_OPERATION_ABORTED as i32)
            })
    }) && stdout.as_ref().is_ok_and(Result::is_ok)
        && stderr.as_ref().is_ok_and(Result::is_ok)
        && terminal_close.as_ref().is_ok_and(Result::is_ok)
        && control_input.as_ref().is_ok_and(Result::is_ok)
        && control_output.as_ref().is_ok_and(|result| {
            result.is_ok()
                || result
                    .as_ref()
                    .err()
                    .is_some_and(|error| error.kind() == io::ErrorKind::Interrupted)
        });
    let stdout = stdout.unwrap_or_else(|_| Err(io::Error::other(super::BackendCleanupError)));
    let stderr = stderr.unwrap_or_else(|_| Err(io::Error::other(super::BackendCleanupError)));
    status?;
    Ok(BackendExecutionOutput {
        output: Output {
            status: ExitStatus::from_raw(code),
            stdout: stdout.unwrap_or_default(),
            stderr: stderr.unwrap_or_default(),
        },
        timed_out,
        cleanup_complete: io_complete,
        events: Vec::new(),
    })
}

#[cfg(not(windows))]
pub(super) fn spawn_local_command_with_output(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
    output: Option<super::ExecutionOutputSink>,
) -> io::Result<BackendExecutionOutput> {
    if output
        .as_ref()
        .is_some_and(|sink| sink.control.is_cancelled())
    {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "execution cancelled before spawn",
        ));
    }
    if plan.is_sandbox_enforced() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "refusing to spawn sandboxed plan through local execution path",
        ));
    }

    let mut process = Command::new(&command[0]);
    process
        .args(&command[1..])
        .current_dir(cwd)
        .env_clear()
        .envs(minimal_environment(plan))
        .envs(env.entries.iter().map(|(key, value)| (key, value)));
    #[cfg(unix)]
    process.process_group(0);
    match &stdin {
        ExecutionStdin::Empty => {
            process.stdin(Stdio::null());
        }
        ExecutionStdin::Bytes(_) | ExecutionStdin::File(_) | ExecutionStdin::Stream(_) => {
            process.stdin(Stdio::piped());
        }
    }
    process.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(target_os = "linux")]
    if plan.sandbox_level != SandboxLevel::DangerFullAccess.as_str() {
        // SAFETY: the hook only invokes close_range, which is async-signal-safe and does not
        // allocate. CLOEXEC preserves Rust's spawn error pipe until exec while preventing
        // caller-owned descriptors from crossing the execution boundary.
        unsafe {
            process.pre_exec(|| {
                let result = libc::syscall(
                    libc::SYS_close_range,
                    3_u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                );
                if result == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        }
    }

    let mut child = process.spawn()?;
    if let Some(sink) = &output {
        let _ = sink.started();
    }
    let stdout_reader = child
        .stdout
        .take()
        .map(|pipe| read_pipe_in_thread(pipe, super::OutputStream::Stdout, output.clone()));
    let stderr_reader = child
        .stderr
        .take()
        .map(|pipe| read_pipe_in_thread(pipe, super::OutputStream::Stderr, output.clone()));
    let input_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stdin_writer = match stdin {
        ExecutionStdin::Empty => None,
        ExecutionStdin::Bytes(bytes) | ExecutionStdin::File(bytes) => {
            write_stdin_in_thread(child.stdin.take(), bytes)
        }
        ExecutionStdin::Stream(queue) => child.stdin.take().map(|mut stdin| {
            let output = output.clone();
            let input_done = input_done.clone();
            thread::spawn(move || -> io::Result<()> {
                loop {
                    if input_done.load(std::sync::atomic::Ordering::Acquire) {
                        return Ok(());
                    }
                    if output
                        .as_ref()
                        .is_some_and(|sink| sink.control.is_cancelled())
                    {
                        return Ok(());
                    }
                    match queue
                        .poll()
                        .map_err(|_| io::Error::other("execution input unavailable"))?
                    {
                        super::InputPoll::Data(bytes) => {
                            stdin.write_all(&bytes)?;
                            queue.acknowledge(bytes.len()).map_err(|_| {
                                io::Error::other("execution input acknowledgement failed")
                            })?;
                        }
                        super::InputPoll::Eof => return Ok(()),
                        super::InputPoll::Pending => thread::sleep(Duration::from_millis(10)),
                    }
                }
            })
        }),
    };

    let (status, timed_out) = wait_child_with_timeout(&mut child, timeout, output.as_ref())?;
    input_done.store(true, std::sync::atomic::Ordering::Release);
    if !timed_out {
        join_stdin_writer(stdin_writer)?;
    } else {
        let _ = join_stdin_writer(stdin_writer);
    }
    Ok(BackendExecutionOutput {
        output: Output {
            status,
            stdout: join_pipe_reader(stdout_reader)?,
            stderr: join_pipe_reader(stderr_reader)?,
        },
        timed_out,
        cleanup_complete: true,
        events: Vec::new(),
    })
}

fn write_stdin_in_thread(
    stdin: Option<impl Write + Send + 'static>,
    bytes: Vec<u8>,
) -> Option<JoinHandle<io::Result<()>>> {
    stdin.map(|mut stdin| thread::spawn(move || stdin.write_all(&bytes)))
}

#[cfg(not(windows))]
fn join_stdin_writer(writer: Option<JoinHandle<io::Result<()>>>) -> io::Result<()> {
    let Some(writer) = writer else {
        return Ok(());
    };
    match writer
        .join()
        .map_err(|_| io::Error::other("stdin writer thread panicked"))?
    {
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
            ) =>
        {
            Ok(())
        }
        result => result,
    }
}

#[cfg(not(windows))]
fn wait_child_with_timeout(
    child: &mut Child,
    timeout: Option<Duration>,
    output: Option<&super::ExecutionOutputSink>,
) -> io::Result<(ExitStatus, bool)> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            terminate_process_group(child.id())?;
            return Ok((status, false));
        }

        let timed_out = timeout.is_some_and(|timeout| start.elapsed() >= timeout);
        if timed_out && let Some(output) = output {
            output
                .control
                .request(crate::execution::TerminationCause::Timeout);
        }
        let cancelled = output.is_some_and(|output| output.control.is_cancelled());
        if timed_out || cancelled {
            let group_result = terminate_process_group(child.id());
            let child_result = child.kill();
            let status = child.wait()?;
            group_result?;
            // The group signal may reap the leader before the direct kill. A
            // failed redundant kill is benign only after wait() confirms exit.
            if let Err(err) = child_result
                && !child_kill_reports_already_exited(&err)
            {
                return Err(err);
            }
            return Ok((status, timed_out));
        }

        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn child_kill_reports_already_exited(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::InvalidInput || error.raw_os_error() == Some(libc::ESRCH)
}

#[cfg(unix)]
fn terminate_process_group(process_id: u32) -> io::Result<()> {
    let process_group = i32::try_from(process_id)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "process id is out of range"))?;
    if unsafe { libc::kill(-process_group, libc::SIGKILL) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(unix)]
#[cfg(test)]
mod process_group_cleanup_tests {
    use super::*;

    #[test]
    fn direct_kill_race_accepts_esrch_only_after_wait_proves_exit() {
        let error = io::Error::from_raw_os_error(libc::ESRCH);
        assert!(child_kill_reports_already_exited(&error));
        assert!(child_kill_reports_already_exited(&io::Error::new(
            io::ErrorKind::InvalidInput,
            "process already exited",
        )));
        assert!(!child_kill_reports_already_exited(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "permission denied",
        )));
    }
}

#[cfg(not(windows))]
fn read_pipe_in_thread(
    mut pipe: impl Read + Send + 'static,
    stream: super::OutputStream,
    output: Option<super::ExecutionOutputSink>,
) -> JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = pipe.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            if let Some(output) = &output {
                if output.send(stream, &buffer[..count]).is_err() {
                    break;
                }
            } else {
                bytes.extend_from_slice(&buffer[..count]);
            }
        }
        Ok(bytes)
    })
}

#[cfg(not(windows))]
fn join_pipe_reader(reader: Option<JoinHandle<io::Result<Vec<u8>>>>) -> io::Result<Vec<u8>> {
    let Some(reader) = reader else {
        return Ok(Vec::new());
    };
    reader
        .join()
        .map_err(|_| io::Error::other("output reader thread panicked"))?
}

#[cfg(test)]
pub(super) fn cleanup_child_after_setup_error(mut child: Child, setup_err: io::Error) -> io::Error {
    let kill_err = match child.kill() {
        Ok(()) => None,
        Err(err) if err.kind() == io::ErrorKind::InvalidInput => None,
        Err(err) => Some(err),
    };
    let wait_err = child.wait().err();

    match (kill_err, wait_err) {
        (None, None) => setup_err,
        (Some(kill_err), None) => io::Error::other(format!(
            "child setup failed ({setup_err}); cleanup kill failed ({kill_err})"
        )),
        (None, Some(wait_err)) => io::Error::other(format!(
            "child setup failed ({setup_err}); cleanup wait failed ({wait_err})"
        )),
        (Some(kill_err), Some(wait_err)) => io::Error::other(format!(
            "child setup failed ({setup_err}); cleanup kill failed ({kill_err}); cleanup wait failed ({wait_err})"
        )),
    }
}

pub(super) fn minimal_environment(plan: &PlatformSandboxPlan) -> Vec<(OsString, OsString)> {
    if plan.environment_inherit != "minimal" {
        return Vec::new();
    }

    let mut environment: Vec<(OsString, OsString)> = minimal_environment_keys()
        .into_iter()
        .filter(|key| {
            !plan
                .environment_scrub
                .iter()
                .any(|pattern| matches_environment_scrub_pattern(key, pattern))
        })
        .filter_map(|key| env::var_os(key).map(|value| (OsString::from(key), value)))
        .collect();
    environment.extend(
        plan.environment_runtime
            .iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value))),
    );
    environment
}

fn minimal_environment_keys() -> Vec<&'static str> {
    if cfg!(windows) {
        vec![
            "PATH",
            "Path",
            "PATHEXT",
            "SYSTEMROOT",
            "SystemRoot",
            "WINDIR",
            "COMSPEC",
            "TEMP",
            "TMP",
        ]
    } else {
        vec!["PATH", "TMPDIR", "LANG", "LC_ALL"]
    }
}

#[cfg(windows)]
fn join_windows_io<T: Default + Send + 'static>(
    worker: Option<JoinHandle<io::Result<T>>>,
    deadline: Instant,
    cancel: bool,
) -> io::Result<io::Result<T>> {
    use std::os::windows::io::AsRawHandle;
    let Some(worker) = worker else {
        return Ok(Ok(T::default()));
    };
    while !worker.is_finished() {
        if cancel || Instant::now() >= deadline {
            unsafe {
                windows_sys::Win32::System::IO::CancelSynchronousIo(worker.as_raw_handle().cast());
            }
        }
        if Instant::now() >= deadline {
            crate::execution::retained::retain(worker);
            return Err(io::Error::other(super::BackendCleanupError));
        }
        thread::sleep(Duration::from_millis(1));
    }
    worker
        .join()
        .map_err(|_| io::Error::other(super::BackendCleanupError))
}

#[cfg(windows)]
fn read_windows_pipe_in_thread(
    mut pipe: std::fs::File,
    stream: super::OutputStream,
    output: Option<super::ExecutionOutputSink>,
    range_empty: std::sync::Arc<std::sync::atomic::AtomicBool>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut captured = Vec::new();
        let mut buffer = [0u8; 64 * 1024];
        while !stop.load(std::sync::atomic::Ordering::Acquire) {
            let Some(available) = codex_windows_sandbox::available_pipe_bytes(&pipe)? else {
                break;
            };
            if available == 0 {
                if range_empty.load(std::sync::atomic::Ordering::Acquire) {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
                continue;
            }
            let limit = available.min(buffer.len());
            let count = pipe.read(&mut buffer[..limit])?;
            if count == 0 {
                break;
            }
            if let Some(output) = &output {
                if output.send(stream, &buffer[..count]).is_err() {
                    break;
                }
            } else {
                captured.extend_from_slice(&buffer[..count]);
            }
        }
        Ok(captured)
    })
}
