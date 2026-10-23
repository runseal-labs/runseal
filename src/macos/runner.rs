//! Internal guardian entry point.
//!
//! The controller starts this hidden command through a transient launchd job.
//! The command connects back to the controller, verifies the controller's
//! kernel socket peer token, persists a one-shot spawn marker, and reads the
//! prepared `LaunchSpec`. Native execution runs inside the guardian's own
//! launchd resource coalition through `process::spawn_native_prepared`; this
//! module only bridges the private wire protocol to that adapter.

use crate::backend::{
    BackendExecutionOutput, BackendMessage, ExecutionInput, ExecutionIo, ExecutionOutputSink,
    ExecutionStdin, OutputStream,
};
use crate::execution::{ExecutionControl, TerminationCause};
use crate::macos::cohort;
use crate::macos::process::{self, CohortContext};
use crate::macos::wire::{
    self, ControllerFrame, GuardianFrame, LaunchSpec, WireInput, WireIo, WireStdin, WireStream,
};
use std::collections::VecDeque;
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const LOCAL_PEERTOKEN: libc::c_int = 6;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const FRAME_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const FRAME_SEND_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(5);
// Bounded bridge memory: the backend worker channel holds at most 32 queued
// output chunks (each at most the deployment stream chunk size) and the frame
// queue holds at most 16 frames before `send_frame` observes backpressure.
const BACKEND_QUEUE: usize = 32;
const FRAME_QUEUE: usize = 16;
const MAX_FRAMES_PER_READ: usize = 16;
const MAX_READ_BYTES_PER_CALL: usize = 256 * 1024;
const MAX_READ_TIME_PER_CALL: Duration = Duration::from_millis(10);
const MAX_BACKEND_MESSAGES_PER_ROUND: usize = 16;
const MAX_BUFFERED_BYTES: usize = wire::MAX_FRAME_BYTES + MAX_READ_BYTES_PER_CALL;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PeerToken {
    val: [u32; 8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RunnerArgs {
    socket: PathBuf,
    controller_pid: i32,
    controller_idversion: u32,
    marker: PathBuf,
}

fn parse_u32(value: &str, name: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| format!("invalid {name}: {value}"))
}

fn parse_args(arguments: &[String]) -> Result<RunnerArgs, String> {
    let mut socket = None;
    let mut controller_pid = None;
    let mut controller_idversion = None;
    let mut marker = None;
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index].as_str();
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag {
            "--socket" => socket = Some(PathBuf::from(value)),
            "--controller-pid" => {
                controller_pid = Some(
                    value
                        .parse::<i32>()
                        .map_err(|_| format!("invalid controller pid: {value}"))?,
                );
            }
            "--controller-idversion" => {
                controller_idversion = Some(parse_u32(value, "controller idversion")?);
            }
            "--marker" => marker = Some(PathBuf::from(value)),
            other => return Err(format!("unknown guardian argument: {other}")),
        }
        index += 2;
    }
    Ok(RunnerArgs {
        socket: socket.ok_or_else(|| "missing --socket".to_string())?,
        controller_pid: controller_pid.ok_or_else(|| "missing --controller-pid".to_string())?,
        controller_idversion: controller_idversion
            .ok_or_else(|| "missing --controller-idversion".to_string())?,
        marker: marker.ok_or_else(|| "missing --marker".to_string())?,
    })
}

fn peer_token(stream: &UnixStream) -> io::Result<PeerToken> {
    let mut token = PeerToken::default();
    let mut length = size_of::<PeerToken>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            LOCAL_PEERTOKEN,
            (&mut token as *mut PeerToken).cast::<c_void>(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<PeerToken>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected peer token size",
        ));
    }
    Ok(token)
}

/// The one-shot marker is created with `create_new` before native execution.
/// A guardian restart (including launchd restarting the same label) fails
/// closed because the marker already exists; it is never silently reused.
fn consume_spawn_marker(args: &RunnerArgs, execution_resource: u64) -> io::Result<File> {
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args.marker)?;
    writeln!(
        marker,
        "{}:{}:{}",
        args.controller_pid, args.controller_idversion, execution_resource
    )?;
    marker.sync_all()?;
    Ok(marker)
}

fn authenticate_controller(stream: &UnixStream, args: &RunnerArgs) -> io::Result<CohortContext> {
    let token = peer_token(stream)?;
    let pid = i32::try_from(token.val[5])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "peer pid"))?;
    if pid != args.controller_pid || token.val[7] != args.controller_idversion {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "guardian controller peer token mismatch",
        ));
    }
    let own_pid = i32::try_from(std::process::id())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "guardian pid"))?;
    let own = cohort::snapshot(own_pid)?;
    let controller = cohort::snapshot(pid)?;
    cohort::validate_resource_cohort(own.cohort.resource, controller.cohort.resource)?;
    Ok(CohortContext {
        resource: own.cohort.resource,
        keeper: own.identity,
    })
}

fn set_nonblocking(fd: libc::c_int, enabled: bool) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let updated = if enabled {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFL, updated) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn connect_with_deadline(path: &Path, timeout: Duration) -> io::Result<UnixStream> {
    use std::os::unix::ffi::OsStrExt;
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    if let Err(error) = crate::macos::guardian::set_cloexec(fd) {
        unsafe { libc::close(fd) };
        return Err(error);
    }
    if let Err(error) = set_nonblocking(fd, true) {
        unsafe { libc::close(fd) };
        return Err(error);
    }
    let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= address.sun_path.len() {
        unsafe { libc::close(fd) };
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guardian socket path is too long",
        ));
    }
    for (index, byte) in bytes.iter().enumerate() {
        address.sun_path[index] = *byte as libc::c_char;
    }
    address.sun_len =
        (size_of::<libc::sockaddr_un>() - address.sun_path.len() + bytes.len() + 1) as u8;
    let connect = unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_un).cast(),
            size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if connect != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            unsafe { libc::close(fd) };
            return Err(error);
        }
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                unsafe { libc::close(fd) };
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "guardian socket connect timed out",
                ));
            }
            let mut poll_fd = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            let result = unsafe {
                libc::poll(
                    &mut poll_fd,
                    1,
                    i32::try_from(remaining.as_millis().min(1_000_000)).unwrap_or(1_000_000),
                )
            };
            if result > 0 {
                break;
            }
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                unsafe { libc::close(fd) };
                return Err(error);
            }
        }
        let mut socket_error: libc::c_int = 0;
        let mut length = size_of::<libc::c_int>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut socket_error as *mut libc::c_int).cast(),
                &mut length,
            )
        };
        if result != 0 || socket_error != 0 {
            let error = if result != 0 {
                io::Error::last_os_error()
            } else {
                io::Error::from_raw_os_error(socket_error)
            };
            unsafe { libc::close(fd) };
            return Err(error);
        }
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    set_nonblocking(fd, false)?;
    stream.set_read_timeout(Some(FRAME_TIMEOUT))?;
    stream.set_write_timeout(Some(FRAME_TIMEOUT))?;
    Ok(stream)
}

fn execution_io(io: WireIo) -> ExecutionIo {
    match io {
        WireIo::Pipe => ExecutionIo::Pipe,
        WireIo::PipeControl {
            child_fd,
            byte_pipe,
        } => ExecutionIo::PipeControl {
            child_fd,
            byte_pipe,
        },
        WireIo::Pty { rows, cols } => ExecutionIo::Pty { rows, cols },
    }
}

fn bridge_stream(stream: OutputStream) -> WireStream {
    match stream {
        OutputStream::Stdout => WireStream::Stdout,
        OutputStream::Stderr => WireStream::Stderr,
        OutputStream::Terminal => WireStream::Terminal,
        OutputStream::Control => WireStream::Control,
    }
}

fn bridge_backend_message(message: BackendMessage) -> GuardianFrame {
    match message {
        BackendMessage::Started { time, process_id } => GuardianFrame::Started { time, process_id },
        BackendMessage::SignalDelivered {
            sequence,
            process_id,
            process_group_id,
        } => GuardianFrame::SignalDelivered {
            sequence,
            process_id,
            process_group_id,
        },
        BackendMessage::Output(chunk) => GuardianFrame::Output {
            stream: bridge_stream(chunk.stream),
            data: chunk.bytes,
        },
    }
}

fn done_frame(output: &BackendExecutionOutput, facts: &process::NativeFacts) -> GuardianFrame {
    GuardianFrame::Done {
        exit_code: output.output.status.code(),
        exit_signal: output.output.status.signal(),
        timed_out: output.timed_out,
        io_joined: facts.io_joined,
        children_drained: facts.children_drained,
        tasks_started: facts.tasks_started,
        tasks_exited: facts.tasks_exited,
    }
}

fn write_guardian_frames(
    mut stream: UnixStream,
    frames: Receiver<GuardianFrame>,
    control: ExecutionControl,
) -> io::Result<()> {
    while let Ok(frame) = frames.recv() {
        if let Err(error) = wire::write_frame(&mut stream, &frame) {
            control.request(TerminationCause::ClientDisconnected);
            return Err(error);
        }
    }
    Ok(())
}

/// Move a bounded number of queued backend messages per bridge round so a
/// continuously producing execution can never starve wire reads or control.
fn pump_backend_round(
    backend: &Receiver<BackendMessage>,
    frames: &SyncSender<GuardianFrame>,
    deadline: Instant,
) -> io::Result<()> {
    for _ in 0..MAX_BACKEND_MESSAGES_PER_ROUND {
        let Ok(message) = backend.try_recv() else {
            break;
        };
        send_frame(frames, bridge_backend_message(message), deadline)?;
    }
    Ok(())
}

/// Keep a dead wire from blocking the execution's I/O workers on a full backend
/// channel. Discarding is bounded per round for the same fairness reason.
fn discard_backend_round(backend: &Receiver<BackendMessage>) {
    for _ in 0..MAX_BACKEND_MESSAGES_PER_ROUND {
        if backend.try_recv().is_err() {
            break;
        }
    }
}

/// Queue one frame for the wire writer with a hard send deadline. The writer
/// uses a short socket write timeout, so a peer that stops reading makes the
/// stall observable instead of blocking the bridge indefinitely. The per-send
/// budget is always clamped to the shared cleanup deadline when one exists.
fn send_frame(
    frames: &SyncSender<GuardianFrame>,
    frame: GuardianFrame,
    deadline: Instant,
) -> io::Result<()> {
    let deadline = deadline.min(Instant::now() + FRAME_SEND_TIMEOUT);
    let mut frame = frame;
    loop {
        match frames.try_send(frame) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Full(pending)) => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "guardian wire writer stalled",
                    ));
                }
                frame = pending;
                thread::sleep(POLL_INTERVAL);
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "guardian wire writer stopped",
                ));
            }
        }
    }
}

/// Join a thread only until the shared cleanup deadline. A thread that does not
/// stop in time is left detached and the caller reports a cleanup error instead
/// of claiming completion.
fn join_thread<T>(handle: JoinHandle<T>, deadline: Instant, label: &str) -> io::Result<T> {
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("guardian {label} did not stop before the cleanup deadline"),
            ));
        }
        thread::sleep(POLL_INTERVAL);
    }
    handle
        .join()
        .map_err(|_| io::Error::other(format!("guardian {label} thread failed")))
}

/// Incremental frame reader for a socket whose read side has a short timeout.
/// Partial frames stay buffered until their declared length is complete.
#[derive(Default)]
struct FrameReader {
    buffer: Vec<u8>,
    eof: bool,
}

impl FrameReader {
    /// Parse bounded batches only. A controller that keeps writing can never
    /// keep the bridge inside this function: the main loop must regain control
    /// to drain backend output and observe cancellation on every batch.
    fn read_available(&mut self, stream: &mut UnixStream) -> io::Result<Vec<ControllerFrame>> {
        let mut received = Vec::new();
        let mut read_bytes = 0usize;
        let started = Instant::now();
        self.parse_buffered(&mut received)?;
        while received.len() < MAX_FRAMES_PER_READ
            && read_bytes < MAX_READ_BYTES_PER_CALL
            && started.elapsed() < MAX_READ_TIME_PER_CALL
        {
            let mut chunk = [0u8; 16 * 1024];
            match stream.read(&mut chunk) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(count) => {
                    read_bytes += count;
                    self.buffer.extend_from_slice(&chunk[..count]);
                    if self.buffer.len() > MAX_BUFFERED_BYTES {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "guardian controller buffer exceeded the frame limit",
                        ));
                    }
                    self.parse_buffered(&mut received)?;
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        // Every read above is immediately followed by `parse_buffered`, and that
        // helper deliberately leaves over-cap complete frames buffered for the
        // next batch. Parsing again here would exceed the batch limit.
        Ok(received)
    }

    fn parse_buffered(&mut self, received: &mut Vec<ControllerFrame>) -> io::Result<()> {
        while let Some(frame) = take_controller_frame(&mut self.buffer)? {
            received.push(frame);
            if received.len() >= MAX_FRAMES_PER_READ {
                break;
            }
        }
        Ok(())
    }
}

fn take_controller_frame(buffer: &mut Vec<u8>) -> io::Result<Option<ControllerFrame>> {
    if buffer.len() < 4 {
        return Ok(None);
    }
    let length = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
    if length == 0 || length > wire::MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "guardian frame length is out of range",
        ));
    }
    let total = 4 + length;
    if buffer.len() < total {
        return Ok(None);
    }
    let mut payload = &buffer[..total];
    let frame = wire::read_controller_frame(&mut payload)?;
    buffer.drain(..total);
    Ok(Some(frame))
}

/// One independent controller input stream. Stdin and control input never share
/// a queue. An `InputAccepted` acknowledgement means the guardian accepted the
/// bytes into its bounded native queue, not that the native process consumed
/// them; retained bytes per stream are wire-pending bytes plus native queue
/// occupancy, bounded by the wire in-flight budget plus the queue budget.
struct WireState {
    stream: WireInput,
    queue: Option<ExecutionInput>,
    pending: VecDeque<Vec<u8>>,
    pending_bytes: usize,
    close_requested: bool,
    close_acknowledged: bool,
}

impl WireState {
    fn new(stream: WireInput, queue: Option<ExecutionInput>) -> Self {
        Self {
            stream,
            queue,
            pending: VecDeque::new(),
            pending_bytes: 0,
            close_requested: false,
            close_acknowledged: false,
        }
    }

    fn accept(
        &mut self,
        data: Vec<u8>,
        frames: &SyncSender<GuardianFrame>,
        deadline: Instant,
    ) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if self.close_requested {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guardian input arrived after close",
            ));
        }
        if self.queue.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guardian input stream is not open",
            ));
        }
        if self.pending_bytes.saturating_add(data.len()) > wire::MAX_IN_FLIGHT_INPUT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guardian input budget exceeded",
            ));
        }
        let queue_limit = crate::limits::deployment().input_pending_bytes;
        let queued = match &self.queue {
            Some(queue) => {
                let remaining = queue
                    .remaining_capacity()
                    .map_err(|_| io::Error::other("execution input unavailable"))?;
                queue_limit.saturating_sub(remaining)
            }
            None => 0,
        };
        let retained_bound = wire::MAX_IN_FLIGHT_INPUT_BYTES + queue_limit;
        if self
            .pending_bytes
            .saturating_add(queued)
            .saturating_add(data.len())
            > retained_bound
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guardian retained input budget exceeded",
            ));
        }
        let chunk_limit = crate::limits::deployment().stream_chunk_bytes;
        for chunk in data.chunks(chunk_limit) {
            self.pending_bytes += chunk.len();
            self.pending.push_back(chunk.to_vec());
        }
        self.flush(frames, deadline)
    }

    fn request_close(
        &mut self,
        frames: &SyncSender<GuardianFrame>,
        deadline: Instant,
    ) -> io::Result<()> {
        self.close_requested = true;
        self.flush(frames, deadline)
    }

    /// Move opaque chunks into the native queue only when the queue has room,
    /// then acknowledge them. A close acknowledgement is sent only after every
    /// pending chunk has been accepted.
    fn flush(&mut self, frames: &SyncSender<GuardianFrame>, deadline: Instant) -> io::Result<()> {
        if let Some(queue) = &self.queue {
            while let Some(front_len) = self.pending.front().map(Vec::len) {
                let capacity = queue
                    .remaining_capacity()
                    .map_err(|_| io::Error::other("execution input unavailable"))?;
                if capacity < front_len {
                    break;
                }
                let data = match self.pending.pop_front() {
                    Some(data) => data,
                    None => break,
                };
                self.pending_bytes -= data.len();
                let bytes = u32::try_from(data.len()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "guardian input chunk too large")
                })?;
                queue
                    .write(data)
                    .map_err(|_| io::Error::other("execution input unavailable"))?;
                send_frame(
                    frames,
                    GuardianFrame::InputAccepted {
                        stream: self.stream,
                        bytes,
                    },
                    deadline,
                )?;
            }
        }
        if self.close_requested && self.pending.is_empty() && !self.close_acknowledged {
            if let Some(queue) = &self.queue {
                queue
                    .close()
                    .map_err(|_| io::Error::other("execution input close failed"))?;
            }
            self.close_acknowledged = true;
            send_frame(
                frames,
                GuardianFrame::InputClosed {
                    stream: self.stream,
                },
                deadline,
            )?;
        }
        Ok(())
    }
}

fn apply_controller_frame(
    frame: ControllerFrame,
    control: &ExecutionControl,
    stdin: &mut WireState,
    control_input: &mut WireState,
    frames: &SyncSender<GuardianFrame>,
    deadline: Instant,
) -> io::Result<()> {
    match frame {
        ControllerFrame::Input { stream, data } => match stream {
            WireInput::Stdin => stdin.accept(data, frames, deadline),
            WireInput::Control => control_input.accept(data, frames, deadline),
        },
        ControllerFrame::CloseInput { stream } => match stream {
            WireInput::Stdin => stdin.request_close(frames, deadline),
            WireInput::Control => control_input.request_close(frames, deadline),
        },
        ControllerFrame::Resize { rows, cols } => {
            if control.cause().is_some() {
                return Ok(());
            }
            control.resize(rows, cols).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "guardian resize rejected")
            })
        }
        ControllerFrame::Interrupt { sequence } => {
            if control.cause().is_some() {
                return Ok(());
            }
            // The accepted sequence crosses the wire and the native terminal
            // command unchanged; the guardian never renumbers it.
            control.interrupt_with_sequence(sequence).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "guardian interrupt rejected")
            })
        }
        ControllerFrame::Cancel { .. } => {
            control.request(TerminationCause::Cancelled);
            Ok(())
        }
    }
}

fn start_native(
    spec: &LaunchSpec,
    mut stream: UnixStream,
    marker: File,
    context: &CohortContext,
) -> io::Result<()> {
    // Keep the one-shot marker alive for the whole native execution so a
    // launchd restart of this label cannot silently reuse the guardian.
    let _marker = marker;
    let io = execution_io(spec.io);
    let stdin_queue = match &spec.stdin {
        WireStdin::Stream => Some(ExecutionInput::default()),
        _ => None,
    };
    let control_queue = match spec.io {
        WireIo::PipeControl { .. } => Some(ExecutionInput::default()),
        _ => None,
    };
    let stdin = match &spec.stdin {
        WireStdin::Empty => ExecutionStdin::Empty,
        WireStdin::Bytes(bytes) => ExecutionStdin::Bytes(bytes.clone()),
        WireStdin::Stream => match stdin_queue.clone() {
            Some(queue) => ExecutionStdin::Stream(queue),
            None => return Err(io::Error::other("guardian stdin queue missing")),
        },
    };

    let (backend_tx, backend_rx) = mpsc::sync_channel(BACKEND_QUEUE);
    let (frame_tx, frame_rx) = mpsc::sync_channel(FRAME_QUEUE);
    let control = ExecutionControl::default();
    let sink = ExecutionOutputSink {
        sender: backend_tx,
        io,
        control_input: control_queue.clone(),
        control: control.clone(),
    };
    let write_stream = stream.try_clone()?;
    write_stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    stream.set_read_timeout(Some(POLL_INTERVAL))?;
    let execution_spec = spec.clone();
    let execution_context = context.clone();
    let (done_tx, done_rx) = mpsc::channel();
    let execution = thread::spawn(move || {
        let result =
            process::spawn_native_prepared(&execution_spec, &execution_context, stdin, sink);
        let _ = done_tx.send(());
        result
    });
    let writer_control = control.clone();
    let writer =
        thread::spawn(move || write_guardian_frames(write_stream, frame_rx, writer_control));

    let mut frames = FrameReader::default();
    let mut stdin_state = WireState::new(WireInput::Stdin, stdin_queue);
    let mut control_state = WireState::new(WireInput::Control, control_queue);
    let mut wire_alive = true;
    let mut wire_eof = false;
    let mut bridge_error: Option<io::Error> = None;
    let mut execution_finished = false;
    // One cleanup deadline shared with the native adapter. `begin_cleanup`
    // returns the same instant for both sides, so a late join or drain can
    // never extend the cleanup budget with a fresh timeout.
    let mut cleanup_deadline: Option<Instant> = None;
    while !execution_finished {
        if cleanup_deadline.is_none() && control.cause().is_some() {
            cleanup_deadline = Some(control.begin_cleanup());
        }
        if control.cleanup_deadline_expired() {
            // The shared cleanup budget is spent. Stop touching the wire and
            // let the bounded join below report the cleanup failure.
            wire_alive = false;
            let _ = stream.shutdown(Shutdown::Both);
            if cleanup_deadline.is_none() {
                cleanup_deadline = Some(control.begin_cleanup());
            }
            break;
        }
        let round_deadline =
            cleanup_deadline.unwrap_or_else(|| Instant::now() + FRAME_SEND_TIMEOUT);
        if wire_alive && let Err(error) = pump_backend_round(&backend_rx, &frame_tx, round_deadline)
        {
            bridge_error.get_or_insert(error);
            wire_alive = false;
            let _ = stream.shutdown(Shutdown::Both);
            control.request(TerminationCause::ClientDisconnected);
        }
        if !wire_alive {
            discard_backend_round(&backend_rx);
        }
        if wire_alive {
            for state in [&mut stdin_state, &mut control_state] {
                if let Err(error) = state.flush(&frame_tx, round_deadline) {
                    bridge_error.get_or_insert(error);
                    control.request(TerminationCause::ExecutionFailed);
                    wire_alive = false;
                    let _ = stream.shutdown(Shutdown::Both);
                    break;
                }
            }
        }
        match done_rx.try_recv() {
            Ok(()) | Err(TryRecvError::Disconnected) => execution_finished = true,
            Err(TryRecvError::Empty) => {}
        }
        if execution_finished {
            break;
        }
        if !wire_eof && wire_alive {
            match frames.read_available(&mut stream) {
                Ok(received) => {
                    for frame in received {
                        if let Err(error) = apply_controller_frame(
                            frame,
                            &control,
                            &mut stdin_state,
                            &mut control_state,
                            &frame_tx,
                            round_deadline,
                        ) {
                            bridge_error.get_or_insert(error);
                            control.request(TerminationCause::ExecutionFailed);
                            wire_alive = false;
                            let _ = stream.shutdown(Shutdown::Both);
                            break;
                        }
                    }
                    if wire_alive && frames.eof {
                        wire_eof = true;
                        // The controller socket is gone; drain the execution
                        // coalition instead of waiting for a cancel frame.
                        wire_alive = false;
                        let _ = stream.shutdown(Shutdown::Both);
                        control.request(TerminationCause::ClientDisconnected);
                    }
                }
                Err(error) => {
                    wire_eof = true;
                    bridge_error.get_or_insert(error);
                    control.request(TerminationCause::ClientDisconnected);
                    wire_alive = false;
                    let _ = stream.shutdown(Shutdown::Both);
                }
            }
        }
        thread::sleep(POLL_INTERVAL);
    }

    let join_deadline = cleanup_deadline.unwrap_or_else(|| control.begin_cleanup());
    // Anything the I/O workers produced before the sink dropped is already
    // queued on the channel; drain it into frames before reporting completion.
    // The drain is bounded by both a short local window and the shared cleanup
    // deadline, and a timed-out worker join can leave retained threads holding
    // the sink, so it is never allowed to wait for disconnect.
    let drain_deadline = (Instant::now() + Duration::from_secs(1)).min(join_deadline);
    while Instant::now() < drain_deadline {
        match backend_rx.recv_timeout(POLL_INTERVAL) {
            Ok(message) => {
                if wire_alive
                    && let Err(error) =
                        send_frame(&frame_tx, bridge_backend_message(message), join_deadline)
                {
                    bridge_error.get_or_insert(error);
                    wire_alive = false;
                    let _ = stream.shutdown(Shutdown::Both);
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {}
        }
    }

    let execution_result = match join_thread(execution, join_deadline, "native execution") {
        Ok(result) => result,
        Err(error) => {
            drop(frame_tx);
            let _ = join_thread(writer, join_deadline, "wire writer");
            return Err(error);
        }
    };
    let result = match execution_result {
        Ok((output, facts)) => {
            if wire_alive
                && let Err(error) =
                    send_frame(&frame_tx, done_frame(&output, &facts), join_deadline)
            {
                bridge_error.get_or_insert(error);
            }
            Ok(())
        }
        Err(error) => Err(error),
    };
    drop(frame_tx);
    let writer_result = join_thread(writer, join_deadline, "wire writer");
    if let Some(error) = bridge_error {
        return Err(error);
    }
    if wire_alive {
        writer_result??;
    }
    result
}

fn run_inner(arguments: &[String]) -> io::Result<()> {
    let args = parse_args(arguments)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut stream = connect_with_deadline(&args.socket, CONNECT_TIMEOUT)?;
    let context = authenticate_controller(&stream, &args)?;
    let marker = consume_spawn_marker(&args, context.resource)?;
    let spec: LaunchSpec = wire::read_frame(&mut stream)?;
    start_native(&spec, stream, marker, &context)
}

/// Hidden CLI entry: `runseal __macos-cohort-guardian ...`.
pub(crate) fn run(arguments: &[String]) -> Result<(), String> {
    run_inner(arguments).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{BackendMessage, OutputChunk};

    fn filler(sequence: u8) -> BackendMessage {
        BackendMessage::Output(OutputChunk {
            stream: OutputStream::Stdout,
            bytes: vec![sequence; 4096],
        })
    }

    fn closed_input() -> GuardianFrame {
        GuardianFrame::InputClosed {
            stream: WireInput::Stdin,
        }
    }

    #[test]
    fn continuous_backend_output_cannot_starve_cancel_or_wire_rounds() -> io::Result<()> {
        let capacity = MAX_BACKEND_MESSAGES_PER_ROUND * 2;
        let (backend_tx, backend_rx) = mpsc::sync_channel(capacity);
        for sequence in 0..u8::try_from(capacity).unwrap_or(0) {
            backend_tx
                .try_send(filler(sequence))
                .map_err(|_| io::Error::other("backend queue unexpectedly full"))?;
        }
        let (frame_tx, frame_rx) = mpsc::sync_channel(capacity);
        let control = ExecutionControl::default();
        pump_backend_round(
            &backend_rx,
            &frame_tx,
            Instant::now() + Duration::from_secs(1),
        )?;
        assert_eq!(
            frame_rx.try_iter().count(),
            MAX_BACKEND_MESSAGES_PER_ROUND,
            "one bridge round must move a bounded number of output frames"
        );
        // The next thing the bridge does after a bounded round is observe
        // control/wire state; a continuous writer must never prevent this.
        control.request(TerminationCause::Cancelled);
        assert_eq!(control.cause(), Some(TerminationCause::Cancelled));
        pump_backend_round(
            &backend_rx,
            &frame_tx,
            Instant::now() + Duration::from_secs(1),
        )?;
        assert_eq!(frame_rx.try_iter().count(), MAX_BACKEND_MESSAGES_PER_ROUND);
        Ok(())
    }

    #[test]
    fn dead_wire_discard_round_is_bounded() -> io::Result<()> {
        let capacity = MAX_BACKEND_MESSAGES_PER_ROUND * 2;
        let (backend_tx, backend_rx) = mpsc::sync_channel(capacity);
        for sequence in 0..u8::try_from(capacity).unwrap_or(0) {
            backend_tx
                .try_send(filler(sequence))
                .map_err(|_| io::Error::other("backend queue unexpectedly full"))?;
        }
        discard_backend_round(&backend_rx);
        assert_eq!(
            backend_rx.try_iter().count(),
            MAX_BACKEND_MESSAGES_PER_ROUND,
            "a dead wire must discard a bounded number of backend frames per round"
        );
        Ok(())
    }

    #[test]
    fn controller_frame_reader_returns_bounded_batches() -> io::Result<()> {
        let (mut writer, mut reader) = UnixStream::pair()?;
        reader.set_read_timeout(Some(Duration::from_millis(50)))?;
        let mut encoded = Vec::new();
        for _ in 0..(MAX_FRAMES_PER_READ * 2) {
            wire::write_controller_frame(
                &mut encoded,
                &ControllerFrame::CloseInput {
                    stream: WireInput::Stdin,
                },
            )?;
        }
        writer.write_all(&encoded)?;
        writer.shutdown(Shutdown::Write)?;
        let mut frames = FrameReader::default();
        let first = frames.read_available(&mut reader)?;
        assert_eq!(first.len(), MAX_FRAMES_PER_READ);
        let second = frames.read_available(&mut reader)?;
        assert!(
            !second.is_empty(),
            "buffered frames must not be lost when a batch is capped"
        );
        Ok(())
    }

    #[test]
    fn frame_send_stall_is_bounded_by_the_shared_deadline() -> io::Result<()> {
        let (frame_tx, frame_rx) = mpsc::sync_channel(1);
        frame_tx
            .try_send(closed_input())
            .map_err(|_| io::Error::other("frame queue unexpectedly full"))?;
        let started = Instant::now();
        let error = send_frame(
            &frame_tx,
            closed_input(),
            Instant::now() + Duration::from_millis(25),
        )
        .err()
        .ok_or_else(|| io::Error::other("stalled frame send did not time out"))?;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(20));
        assert!(
            frame_rx.try_iter().next().is_some(),
            "the stalled frame queue still holds the original frame"
        );
        Ok(())
    }
}
