//! macOS native PTY and control-channel execution inside the guardian cohort.
//!
//! The root process is made a session leader with a real controlling terminal
//! (PTY) or a new session (control transport) inside the guardian's launchd
//! resource coalition. Ownership is the kernel coalition, never a local PID
//! tracker: cleanup calls `cohort::terminate_cohort_members` with the guardian as
//! the only keeper, reaps the direct child, joins the real I/O workers, and
//! returns `NativeFacts`. Because the keeper is alive and active in the coalition
//! this adapter never publishes `cleanup_complete: true`; the controller
//! finalizer proves guardian exit and `started == exited` at kernel zero.

use crate::backend::{
    BackendCleanupError, BackendExecutionOutput, ExecutionEnv, ExecutionIo, ExecutionOutputSink,
    ExecutionStdin, InputPoll, OutputStream, PlatformSandboxPlan,
};
use crate::execution::TerminalCommand;
use crate::macos::cohort;
use crate::macos::wire::{LaunchSpec, WireIo, WireStdin};
use std::ffi::CStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const TRACK_INTERVAL: Duration = Duration::from_millis(10);
const IO_POLL_INTERVAL: Duration = Duration::from_millis(5);

type Worker = JoinHandle<io::Result<()>>;

/// Explicit guardian cohort context. The guardian path never derives ownership
/// from the local process tracker; it uses this kernel cohort identity instead.
#[derive(Clone)]
pub(crate) struct CohortContext {
    pub(crate) resource: u64,
    pub(crate) keeper: cohort::ProcessIdentity,
}

/// Private native facts returned to the guardian. `children_drained` is a
/// cohort fact, not a public lifecycle completion claim.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeFacts {
    pub(crate) io_joined: bool,
    pub(crate) children_drained: bool,
    pub(crate) tasks_started: u64,
    pub(crate) tasks_exited: u64,
}

fn native_facts(report: Option<&cohort::CleanupReport>, io_joined: bool) -> NativeFacts {
    match report {
        Some(report) => NativeFacts {
            io_joined,
            children_drained: report.empty,
            tasks_started: report.usage.tasks_started,
            tasks_exited: report.usage.tasks_exited,
        },
        None => NativeFacts {
            io_joined,
            children_drained: false,
            tasks_started: 0,
            tasks_exited: 0,
        },
    }
}

pub(crate) fn prepared_environment(
    plan: &PlatformSandboxPlan,
    env: &ExecutionEnv,
) -> io::Result<Vec<(String, String)>> {
    let mut prepared = Vec::new();
    for (key, value) in crate::backend::minimal_environment(plan) {
        let key = String::from_utf8(key.into_vec()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "environment key is not UTF-8")
        })?;
        let value = String::from_utf8(value.into_vec()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "environment value is not UTF-8")
        })?;
        prepared.push((key, value));
    }
    prepared.extend(env.entries.iter().cloned());
    Ok(prepared)
}

/// Guardian-side native execution. `spec` was prepared by the controller and is
/// executed inside the guardian's launchd resource coalition. Cleanup uses the
/// cohort audit-token path only; the local process tracker is never started.
pub(crate) fn spawn_native_prepared(
    spec: &LaunchSpec,
    context: &CohortContext,
    stdin: ExecutionStdin,
    output: ExecutionOutputSink,
) -> io::Result<(BackendExecutionOutput, NativeFacts)> {
    if spec.argv.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guardian launch argv is empty",
        ));
    }
    let cwd = Path::new(&spec.cwd);
    if !cwd.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guardian launch cwd is not absolute",
        ));
    }
    if !native_io_matches(spec.io, output.io) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guardian output sink I/O does not match the launch spec",
        ));
    }
    let stdin = prepared_stdin(&spec.stdin, stdin)?;
    let timeout = spec.timeout_ms.map(Duration::from_millis);
    let (transport, command) = match spec.io {
        WireIo::Pty { rows, cols } => (
            NativeTransport::Pty {
                base_profile: &spec.base_profile,
                rows,
                cols,
            },
            spec.argv.clone(),
        ),
        WireIo::PipeControl {
            child_fd,
            byte_pipe,
        } => (
            NativeTransport::Control {
                child_fd: libc::c_int::from(child_fd),
                byte_pipe,
            },
            sandbox_wrapped_command(&spec.base_profile, &spec.argv),
        ),
        WireIo::Pipe => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "guardian native execution requires a control descriptor or a PTY",
            ));
        }
    };
    run_native(
        &command, cwd, &spec.env, stdin, timeout, transport, output, context,
    )
}

fn base_command_prepared(
    command: &[String],
    cwd: &Path,
    prepared_env: &[(String, String)],
) -> io::Result<Command> {
    let Some(program) = command.first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "command is empty",
        ));
    };
    let mut process = Command::new(program);
    process
        .args(&command[1..])
        .current_dir(cwd)
        .env_clear()
        .envs(prepared_env.iter().map(|(key, value)| (key, value)));
    Ok(process)
}

fn sandbox_wrapped_command(profile: &str, command: &[String]) -> Vec<String> {
    if profile.is_empty() {
        return command.to_vec();
    }
    let mut wrapped = Vec::with_capacity(command.len() + 3);
    wrapped.push("/usr/bin/sandbox-exec".to_string());
    wrapped.push("-p".to_string());
    wrapped.push(profile.to_string());
    wrapped.extend_from_slice(command);
    wrapped
}

/// The guardian creates the stream input queue before spawning the execution
/// thread. The prepared stdin must be exactly the form named by the launch spec.
fn prepared_stdin(spec: &WireStdin, stdin: ExecutionStdin) -> io::Result<ExecutionStdin> {
    match (spec, stdin) {
        (WireStdin::Empty, ExecutionStdin::Empty) => Ok(ExecutionStdin::Empty),
        (WireStdin::Bytes(bytes), ExecutionStdin::Bytes(provided))
            if provided.as_slice() == bytes.as_slice() =>
        {
            Ok(ExecutionStdin::Bytes(provided))
        }
        (WireStdin::Stream, ExecutionStdin::Stream(queue)) => Ok(ExecutionStdin::Stream(queue)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guardian prepared stdin does not match the launch spec",
        )),
    }
}

fn native_io_matches(wire: WireIo, io: ExecutionIo) -> bool {
    match (wire, io) {
        (WireIo::Pipe, ExecutionIo::Pipe) => true,
        (
            WireIo::PipeControl {
                child_fd,
                byte_pipe,
            },
            ExecutionIo::PipeControl {
                child_fd: actual_fd,
                byte_pipe: actual_byte_pipe,
            },
        ) => child_fd == actual_fd && byte_pipe == actual_byte_pipe,
        (
            WireIo::Pty { rows, cols },
            ExecutionIo::Pty {
                rows: actual_rows,
                cols: actual_cols,
            },
        ) => rows == actual_rows && cols == actual_cols,
        _ => false,
    }
}

enum NativeTransport<'a> {
    Pty {
        base_profile: &'a str,
        rows: u16,
        cols: u16,
    },
    Control {
        child_fd: libc::c_int,
        byte_pipe: bool,
    },
}

/// Result of a transport-specific spawn. Ownership and cleanup are always the
/// guardian's resource coalition; there is no local tracker or weak fallback.
struct NativeProcess {
    child: Child,
    root_pid: libc::pid_t,
    master: Option<Arc<File>>,
    reader_abort: Arc<AtomicBool>,
    writer_stop: Arc<AtomicBool>,
    input_failed: Arc<AtomicBool>,
    readers: [Option<Worker>; 3],
    writers: [Option<Worker>; 2],
}

#[allow(clippy::too_many_arguments)]
fn run_native(
    command: &[String],
    cwd: &Path,
    prepared_env: &[(String, String)],
    stdin: ExecutionStdin,
    timeout: Option<Duration>,
    transport: NativeTransport<'_>,
    output: ExecutionOutputSink,
    context: &CohortContext,
) -> io::Result<(BackendExecutionOutput, NativeFacts)> {
    let mut native = match transport {
        NativeTransport::Pty {
            base_profile,
            rows,
            cols,
        } => spawn_pty_process(
            command,
            cwd,
            prepared_env,
            base_profile,
            rows,
            cols,
            stdin,
            &output,
        )?,
        NativeTransport::Control {
            child_fd,
            byte_pipe,
        } => spawn_control_process(
            command,
            cwd,
            prepared_env,
            child_fd,
            byte_pipe,
            stdin,
            &output,
        )?,
    };
    if let Err(error) = validate_execution_cohort(native.root_pid, context) {
        let _ = native.child.kill();
        let _ = native.child.wait();
        let deadline = Instant::now() + crate::limits::deployment().cleanup_timeout();
        let _ = cohort::terminate_cohort_members(context.resource, Some(&context.keeper), deadline);
        return Err(error);
    }

    let started = Instant::now();
    let mut timed_out = false;
    let mut status = None;
    let mut wait_error = None;
    'wait: loop {
        if native.input_failed.load(Ordering::Acquire) {
            mark_input_failed(&output.control);
            break;
        }
        if timeout.is_some_and(|limit| started.elapsed() >= limit) {
            timed_out = true;
            output
                .control
                .request(crate::execution::TerminationCause::Timeout);
        }
        if output.control.is_cancelled() {
            break;
        }
        while let Some(command) = output.control.take_terminal_command() {
            if deliver_terminal_command(native.master.as_deref(), native.root_pid, command, &output)
                .is_err()
            {
                native.input_failed.store(true, Ordering::Release);
                mark_input_failed(&output.control);
                break 'wait;
            }
        }
        match native.child.try_wait() {
            Ok(Some(exit)) => {
                status = Some(exit);
                break;
            }
            Ok(None) => {}
            Err(error) => {
                wait_error = Some(error);
                break;
            }
        }
        thread::sleep(IO_POLL_INTERVAL);
    }

    let cleanup_deadline = output.control.begin_cleanup();
    let mut cohort_report = None;
    match cohort::terminate_cohort_members(
        context.resource,
        Some(&context.keeper),
        cleanup_deadline,
    ) {
        Ok(report) => cohort_report = Some(report),
        Err(_) => {
            // The audit-token path is unavailable. Kill only the direct child so
            // reaping cannot hang; children_drained stays false and the
            // controller keeps the ownership record.
            let _ = native.child.kill();
        }
    }
    if status.is_none() {
        match reap_direct_child(&mut native.child, cleanup_deadline) {
            Ok(reaped) => status = reaped,
            Err(error) => {
                // Never turn the bounded drain into an unbounded kill/wait.
                // The unreaped direct child stays owned by the registered
                // launchd job, and the adapter reports cleanup failure instead
                // of claiming native facts.
                wait_error = Some(error);
            }
        }
    }

    native.writer_stop.store(true, Ordering::Release);
    let reader_result = join_workers_many(native.readers, &native.reader_abort, cleanup_deadline);
    let writer_result = join_workers_many(native.writers, &native.reader_abort, cleanup_deadline);
    let io_joined = reader_result.and(writer_result).is_ok();
    if let Some(error) = &wait_error {
        return Err(io::Error::other(format!(
            "macOS native execution wait failed: {error}"
        )));
    }
    let status = status.ok_or_else(|| io::Error::other(BackendCleanupError))?;
    let facts = native_facts(cohort_report.as_ref(), io_joined);
    Ok((
        BackendExecutionOutput {
            output: Output {
                status,
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
            timed_out,
            // The guardian keeper is alive and active in the coalition, so the
            // native path can never publish a public lifecycle completion claim.
            cleanup_complete: false,
            events: Vec::new(),
        },
        facts,
    ))
}

#[allow(clippy::too_many_arguments)]
fn spawn_pty_process(
    command: &[String],
    cwd: &Path,
    prepared_env: &[(String, String)],
    base_profile: &str,
    rows: u16,
    cols: u16,
    stdin: ExecutionStdin,
    output: &ExecutionOutputSink,
) -> io::Result<NativeProcess> {
    let mut master_fd = -1;
    let mut slave_fd = -1;
    let mut dimensions = unsafe { std::mem::zeroed::<libc::winsize>() };
    dimensions.ws_row = rows;
    dimensions.ws_col = cols;
    if unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dimensions,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let master_owned = unsafe { OwnedFd::from_raw_fd(master_fd) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave_fd) };
    set_cloexec(master_owned.as_raw_fd())?;
    set_cloexec(slave.as_raw_fd())?;
    let tty_path = slave_tty_path(slave.as_raw_fd())?;
    let tty_literal = sandbox_literal(tty_path.to_string_lossy().as_ref());
    let profile = if base_profile.is_empty() {
        None
    } else {
        Some(format!(
            "{base_profile}\n(allow file-read* file-write* (literal \"{tty_literal}\"))\n(allow file-ioctl (literal \"{tty_literal}\"))"
        ))
    };
    let sandbox_command = match profile.as_deref() {
        Some(profile) => sandbox_wrapped_command(profile, command),
        None => command.to_vec(),
    };

    let mut process = base_command_prepared(&sandbox_command, cwd, prepared_env)?;
    let slave_in = slave.try_clone()?;
    let slave_out = slave.try_clone()?;
    let slave_err = slave.try_clone()?;
    process
        .stdin(Stdio::from(File::from(slave_in)))
        .stdout(Stdio::from(File::from(slave_out)))
        .stderr(Stdio::from(File::from(slave_err)));
    let controlling_fd = slave.as_raw_fd();
    unsafe {
        process.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(
                controlling_fd,
                libc::TIOCSCTTY as libc::c_ulong,
                0 as libc::c_int,
            ) == -1
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = process.spawn()?;
    drop(slave);
    if let Err(error) = set_nonblocking(master_owned.as_raw_fd()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let master = Arc::new(File::from(master_owned));

    let root_pid = child_pid(&child)?;
    let _ = output.started(child.id());

    let reader_abort = Arc::new(AtomicBool::new(false));
    let writer_stop = Arc::new(AtomicBool::new(false));
    let input_failed = Arc::new(AtomicBool::new(false));
    let terminal_reader = spawn_pty_reader(
        master.clone(),
        Some(output.clone()),
        reader_abort.clone(),
        input_failed.clone(),
    );
    let input_writer = spawn_pty_input(
        master.clone(),
        stdin,
        Some(output.clone()),
        writer_stop.clone(),
        input_failed.clone(),
    );

    Ok(NativeProcess {
        child,
        root_pid,
        master: Some(master),
        reader_abort,
        writer_stop,
        input_failed,
        readers: [Some(terminal_reader), None, None],
        writers: [input_writer, None],
    })
}

fn spawn_control_process(
    command: &[String],
    cwd: &Path,
    prepared_env: &[(String, String)],
    child_fd: libc::c_int,
    byte_pipe: bool,
    stdin: ExecutionStdin,
    output: &ExecutionOutputSink,
) -> io::Result<NativeProcess> {
    let target_guard = reserve_target_fd(child_fd)?;
    let (parent_end, child_end) = socket_pair()?;
    set_cloexec(parent_end.as_raw_fd())?;
    set_cloexec(child_end.as_raw_fd())?;
    set_nonblocking(parent_end.as_raw_fd())?;

    let mut process = base_command_prepared(command, cwd, prepared_env)?;
    match &stdin {
        ExecutionStdin::Empty => {
            process.stdin(Stdio::null());
        }
        ExecutionStdin::Bytes(_) | ExecutionStdin::File(_) | ExecutionStdin::Stream(_) => {
            process.stdin(Stdio::piped());
        }
    }
    process.stdout(Stdio::piped()).stderr(Stdio::piped());
    let source_fd = child_end.as_raw_fd();
    unsafe {
        process.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::dup2(source_fd, child_fd) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = process.spawn()?;
    drop(target_guard);
    drop(child_end);
    let parent = Arc::new(File::from(parent_end));

    let root_pid = child_pid(&child)?;
    let _ = output.started(child.id());

    let reader_abort = Arc::new(AtomicBool::new(false));
    let writer_stop = Arc::new(AtomicBool::new(false));
    let input_failed = Arc::new(AtomicBool::new(false));
    let stdout_reader = child.stdout.take().map(|pipe| {
        spawn_pipe_reader(
            pipe,
            OutputStream::Stdout,
            Some(output.clone()),
            reader_abort.clone(),
            input_failed.clone(),
        )
    });
    let stderr_reader = child.stderr.take().map(|pipe| {
        spawn_pipe_reader(
            pipe,
            OutputStream::Stderr,
            Some(output.clone()),
            reader_abort.clone(),
            input_failed.clone(),
        )
    });
    let control_reader = spawn_control_reader(
        parent.clone(),
        Some(output.clone()),
        reader_abort.clone(),
        input_failed.clone(),
    );
    let control_writer = spawn_control_writer(
        parent,
        byte_pipe,
        Some(output.clone()),
        writer_stop.clone(),
        input_failed.clone(),
    );
    let stdin_writer = spawn_pipe_stdin(
        child.stdin.take(),
        stdin,
        Some(output.clone()),
        writer_stop.clone(),
        input_failed.clone(),
    );

    Ok(NativeProcess {
        child,
        root_pid,
        master: None,
        reader_abort,
        writer_stop,
        input_failed,
        readers: [stdout_reader, stderr_reader, Some(control_reader)],
        writers: [Some(control_writer), stdin_writer],
    })
}

fn deliver_terminal_command(
    master: Option<&File>,
    root_pid: libc::pid_t,
    command: TerminalCommand,
    output: &ExecutionOutputSink,
) -> io::Result<()> {
    match command {
        TerminalCommand::Resize { rows, cols } => match master {
            Some(master) => set_winsize(master.as_raw_fd(), rows, cols),
            // Resize is only meaningful for a real terminal.
            None => Ok(()),
        },
        TerminalCommand::Interrupt { sequence } => match master {
            Some(master) => deliver_foreground_interrupt(master.as_raw_fd(), sequence, output),
            None => deliver_process_group_interrupt(root_pid, sequence, output),
        },
    }
}

/// Non-PTY executions are session leaders, so their process group is `root_pid`.
/// The direct child is unreaped, which also keeps its PID from being reused.
fn deliver_process_group_interrupt(
    root_pid: libc::pid_t,
    sequence: u64,
    output: &ExecutionOutputSink,
) -> io::Result<()> {
    if root_pid <= 1 {
        return Ok(());
    }
    if unsafe { libc::kill(-root_pid, libc::SIGINT) } == -1 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error)
        };
    }
    output.signal_delivered_with_group(sequence, u32::try_from(root_pid).ok())
}

/// The executed process must inherit the guardian's execution coalition. A
/// mismatch is fail-closed: the direct child is killed and the execution
/// coalition is drained before the adapter reports the error.
fn validate_execution_cohort(root_pid: libc::pid_t, context: &CohortContext) -> io::Result<()> {
    let snapshot = match cohort::snapshot(root_pid) {
        Ok(snapshot) => snapshot,
        // The process already exited; the coalition counters remain the
        // authoritative cleanup evidence.
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => return Ok(()),
        // Anything else is an observation failure, not proof of exit.
        Err(error) => return Err(error),
    };
    if snapshot.cohort.resource != context.resource {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "guardian execution left the execution resource cohort",
        ));
    }
    if snapshot.identity.same_process(&context.keeper) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "guardian execution identity matches its keeper",
        ));
    }
    Ok(())
}

/// Reap the direct child after the coalition drain. The kernel counters update
/// at exit even before a zombie is reaped, so this is bounded by the cleanup
/// deadline. A child that cannot be reaped in time is a cleanup failure, never a
/// reason to block the guardian; the caller reports the error instead of facts.
fn reap_direct_child(child: &mut Child, deadline: Instant) -> io::Result<Option<ExitStatus>> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other(
                "macOS guardian direct child was not reaped before the cleanup deadline",
            ));
        }
        thread::sleep(TRACK_INTERVAL);
    }
}

fn child_pid(child: &Child) -> io::Result<libc::pid_t> {
    libc::pid_t::try_from(child.id())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "child pid is out of range"))
}

fn mark_input_failed(control: &crate::execution::ExecutionControl) {
    if control.cause().is_none() {
        control.request(crate::execution::TerminationCause::InputFailed);
    }
}

fn socket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn slave_tty_path(fd: RawFd) -> io::Result<PathBuf> {
    let mut buffer: [libc::c_char; 256] = [0; 256];
    let result = unsafe { libc::ttyname_r(fd, buffer.as_mut_ptr(), buffer.len()) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    let name = unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_bytes();
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(name));
    if !path.starts_with("/dev/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PTY slave path is outside /dev",
        ));
    }
    Ok(path)
}

fn sandbox_literal(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Reserve exactly `target` so `Command`'s internal exec-error pipe and stdio
/// pipes cannot occupy it. The placeholder is close-on-exec and is replaced by
/// the real child endpoint in `pre_exec`; an already-occupied target is
/// rejected without closing the parent's existing descriptor.
fn reserve_target_fd(target: libc::c_int) -> io::Result<OwnedFd> {
    let source = open_dev_null()?;
    if source.as_raw_fd() == target {
        return Ok(source);
    }
    let guard = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD_CLOEXEC, target) };
    if guard == -1 {
        return Err(io::Error::last_os_error());
    }
    if guard != target {
        drop(unsafe { OwnedFd::from_raw_fd(guard) });
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "control descriptor is already in use",
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(guard) })
}

fn open_dev_null() -> io::Result<OwnedFd> {
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_winsize(fd: RawFd, rows: u16, cols: u16) -> io::Result<()> {
    let mut dimensions = unsafe { std::mem::zeroed::<libc::winsize>() };
    dimensions.ws_row = rows;
    dimensions.ws_col = cols;
    if unsafe {
        libc::ioctl(
            fd,
            libc::TIOCSWINSZ as libc::c_ulong,
            &dimensions as *const libc::winsize,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn spawn_pty_reader(
    master: Arc<File>,
    output: Option<ExecutionOutputSink>,
    abort: Arc<AtomicBool>,
    input_failed: Arc<AtomicBool>,
) -> Worker {
    thread::spawn(move || {
        let fd = master.as_raw_fd();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            if abort.load(Ordering::Acquire) {
                return Ok(());
            }
            let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            if count > 0 {
                if let Some(sink) = &output
                    && let Err(error) = sink.send(OutputStream::Terminal, &buffer[..count as usize])
                {
                    if sink.control.is_cancelled() {
                        return Ok(());
                    }
                    input_failed.store(true, Ordering::Release);
                    return Err(error);
                }
                continue;
            }
            if count == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => thread::sleep(IO_POLL_INTERVAL),
                _ if is_pty_eof(&error) => return Ok(()),
                _ => {
                    input_failed.store(true, Ordering::Release);
                    return Err(error);
                }
            }
        }
    })
}

fn spawn_pty_input(
    master: Arc<File>,
    stdin: ExecutionStdin,
    output: Option<ExecutionOutputSink>,
    writer_stop: Arc<AtomicBool>,
    input_failed: Arc<AtomicBool>,
) -> Option<Worker> {
    let sink = output?;
    Some(thread::spawn(move || {
        let fd = master.as_raw_fd();
        let (mut pending_bytes, queue, mut input_closed) = match stdin {
            ExecutionStdin::Empty => (None, None, true),
            ExecutionStdin::Bytes(bytes) | ExecutionStdin::File(bytes) => {
                (Some(bytes), None, false)
            }
            ExecutionStdin::Stream(queue) => (None, Some(queue), false),
        };
        loop {
            if writer_stop.load(Ordering::Acquire) || sink.control.is_cancelled() {
                return Ok(());
            }
            if let Some(bytes) = pending_bytes.take() {
                match write_all_nonblocking(fd, &bytes, &writer_stop, &sink.control) {
                    Ok(()) => input_closed = true,
                    Err(error) if is_pty_eof(&error) => input_closed = true,
                    Err(error) => {
                        input_failed.store(true, Ordering::Release);
                        return Err(error);
                    }
                }
                continue;
            }
            if input_closed {
                thread::sleep(IO_POLL_INTERVAL);
                continue;
            }
            let Some(queue) = queue.as_ref() else {
                input_closed = true;
                continue;
            };
            match queue
                .poll()
                .map_err(|_| io::Error::other("execution input unavailable"))?
            {
                InputPoll::Data(bytes) => {
                    match write_all_nonblocking(fd, &bytes, &writer_stop, &sink.control) {
                        Ok(()) => {}
                        Err(error) if is_pty_eof(&error) => {
                            input_closed = true;
                            continue;
                        }
                        Err(error) => {
                            input_failed.store(true, Ordering::Release);
                            return Err(error);
                        }
                    }
                    queue
                        .acknowledge(bytes.len())
                        .map_err(|_| io::Error::other("execution input acknowledgement failed"))?;
                }
                InputPoll::Eof => input_closed = true,
                InputPoll::Pending => thread::sleep(IO_POLL_INTERVAL),
            }
        }
    }))
}

fn deliver_foreground_interrupt(
    master_fd: RawFd,
    sequence: u64,
    sink: &ExecutionOutputSink,
) -> io::Result<()> {
    let process_group = unsafe { libc::tcgetpgrp(master_fd) };
    if process_group <= 0 {
        return Ok(());
    }
    if unsafe { libc::kill(-process_group, libc::SIGINT) } == -1 {
        return Ok(());
    }
    sink.signal_delivered_with_group(sequence, u32::try_from(process_group).ok())
}

fn spawn_control_reader(
    endpoint: Arc<File>,
    output: Option<ExecutionOutputSink>,
    abort: Arc<AtomicBool>,
    input_failed: Arc<AtomicBool>,
) -> Worker {
    thread::spawn(move || {
        let fd = endpoint.as_raw_fd();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            if abort.load(Ordering::Acquire) {
                return Ok(());
            }
            let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            if count > 0 {
                if let Some(sink) = &output
                    && let Err(error) = sink.send(OutputStream::Control, &buffer[..count as usize])
                {
                    if sink.control.is_cancelled() {
                        return Ok(());
                    }
                    input_failed.store(true, Ordering::Release);
                    return Err(error);
                }
                continue;
            }
            if count == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => thread::sleep(IO_POLL_INTERVAL),
                _ => {
                    input_failed.store(true, Ordering::Release);
                    return Err(error);
                }
            }
        }
    })
}

fn spawn_control_writer(
    endpoint: Arc<File>,
    byte_pipe: bool,
    output: Option<ExecutionOutputSink>,
    abort: Arc<AtomicBool>,
    input_failed: Arc<AtomicBool>,
) -> Worker {
    thread::spawn(move || {
        let result: io::Result<()> = (|| {
            let Some(sink) = output else {
                return Ok(());
            };
            let Some(queue) = sink.control_input.clone() else {
                return Ok(());
            };
            let fd = endpoint.as_raw_fd();
            loop {
                if abort.load(Ordering::Acquire) || sink.control.is_cancelled() {
                    return Ok(());
                }
                match queue
                    .poll()
                    .map_err(|_| io::Error::other("control input unavailable"))?
                {
                    InputPoll::Data(bytes) => {
                        write_all_nonblocking(fd, &bytes, &abort, &sink.control)?;
                        queue.acknowledge(bytes.len()).map_err(|_| {
                            io::Error::other("control input acknowledgement failed")
                        })?;
                    }
                    InputPoll::Eof => {
                        if !byte_pipe {
                            unsafe {
                                libc::shutdown(fd, libc::SHUT_WR);
                            }
                        }
                        return Ok(());
                    }
                    InputPoll::Pending => thread::sleep(IO_POLL_INTERVAL),
                }
            }
        })();
        if result.is_err() {
            input_failed.store(true, Ordering::Release);
        }
        result
    })
}

fn spawn_pipe_reader(
    mut reader: impl Read + AsRawFd + Send + 'static,
    stream: OutputStream,
    output: Option<ExecutionOutputSink>,
    abort: Arc<AtomicBool>,
    input_failed: Arc<AtomicBool>,
) -> Worker {
    if let Err(error) = set_nonblocking(reader.as_raw_fd()) {
        return thread::spawn(move || Err(error));
    }
    thread::spawn(move || {
        let mut buffer = [0u8; 64 * 1024];
        loop {
            if abort.load(Ordering::Acquire) {
                return Ok(());
            }
            match reader.read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(count) => {
                    if let Some(sink) = &output
                        && let Err(error) = sink.send(stream, &buffer[..count])
                    {
                        if sink.control.is_cancelled() {
                            return Ok(());
                        }
                        input_failed.store(true, Ordering::Release);
                        return Err(error);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(IO_POLL_INTERVAL);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    input_failed.store(true, Ordering::Release);
                    return Err(error);
                }
            }
        }
    })
}

fn spawn_pipe_stdin(
    pipe: Option<impl Write + AsRawFd + Send + 'static>,
    stdin: ExecutionStdin,
    output: Option<ExecutionOutputSink>,
    abort: Arc<AtomicBool>,
    input_failed: Arc<AtomicBool>,
) -> Option<Worker> {
    let pipe = pipe?;
    let control = output.as_ref().map(|sink| sink.control.clone());
    Some(thread::spawn(move || {
        let result: io::Result<()> = (|| {
            set_nonblocking(pipe.as_raw_fd())?;
            let fd = pipe.as_raw_fd();
            let write = |bytes: &[u8]| -> io::Result<()> {
                write_all_nonblocking(
                    fd,
                    bytes,
                    &abort,
                    control
                        .as_ref()
                        .ok_or_else(|| io::Error::other("execution control missing"))?,
                )
            };
            match stdin {
                ExecutionStdin::Empty => Ok(()),
                ExecutionStdin::Bytes(bytes) | ExecutionStdin::File(bytes) => {
                    write(&bytes)?;
                    drop(pipe);
                    Ok(())
                }
                ExecutionStdin::Stream(queue) => loop {
                    if abort.load(Ordering::Acquire)
                        || control
                            .as_ref()
                            .is_some_and(crate::execution::ExecutionControl::is_cancelled)
                    {
                        return Ok(());
                    }
                    match queue
                        .poll()
                        .map_err(|_| io::Error::other("execution input unavailable"))?
                    {
                        InputPoll::Data(bytes) => {
                            write(&bytes)?;
                            queue.acknowledge(bytes.len()).map_err(|_| {
                                io::Error::other("execution input acknowledgement failed")
                            })?;
                        }
                        InputPoll::Eof => {
                            drop(pipe);
                            return Ok(());
                        }
                        InputPoll::Pending => thread::sleep(IO_POLL_INTERVAL),
                    }
                },
            }
        })();
        if result.is_err() {
            input_failed.store(true, Ordering::Release);
        }
        result
    }))
}

fn write_all_nonblocking(
    fd: RawFd,
    bytes: &[u8],
    abort: &AtomicBool,
    control: &crate::execution::ExecutionControl,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        if abort.load(Ordering::Acquire) || control.is_cancelled() {
            return Ok(());
        }
        let count =
            unsafe { libc::write(fd, bytes[offset..].as_ptr().cast(), bytes.len() - offset) };
        if count > 0 {
            offset += count as usize;
            continue;
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => {
                if control.cleanup_deadline_expired() {
                    return Err(io::Error::other(BackendCleanupError));
                }
                thread::sleep(IO_POLL_INTERVAL);
            }
            _ => return Err(error),
        }
    }
    Ok(())
}

fn join_workers_many<const N: usize>(
    workers: [Option<Worker>; N],
    abort: &AtomicBool,
    deadline: Instant,
) -> io::Result<()> {
    let mut failed = false;
    for worker in workers.into_iter().flatten() {
        while !worker.is_finished() {
            if Instant::now() >= deadline {
                abort.store(true, Ordering::Release);
                return Err(io::Error::other(BackendCleanupError));
            }
            thread::sleep(Duration::from_millis(2));
        }
        let result = worker
            .join()
            .map_err(|_| io::Error::other("macOS I/O worker panicked"))?;
        if let Err(error) = result {
            if crate::backend::cleanup_failed(&error) {
                return Err(error);
            }
            failed = true;
        }
    }
    if failed {
        Err(io::Error::other(BackendCleanupError))
    } else {
        Ok(())
    }
}

fn is_pty_eof(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EIO) | Some(libc::ENXIO))
}
