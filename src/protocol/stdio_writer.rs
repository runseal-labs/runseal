use serde_json::Value;
use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc::SyncSender,
};
use std::time::Instant;

#[cfg(test)]
const MAX_FRAME: usize = 1024 * 1024;
// Keep two MiB for controller staging and one MiB for control frames.
const FRAME_OVERHEAD: usize = 512;

pub(super) struct Frame {
    bytes: Vec<u8>,
    resident: usize,
    data: bool,
    guard: Option<Arc<AtomicBool>>,
    starts: Vec<SyncSender<()>>,
}

impl Frame {
    pub fn encode(
        message: &Value,
        guard: Option<Arc<AtomicBool>>,
        starts: Vec<SyncSender<()>>,
    ) -> io::Result<Self> {
        struct Counter(usize);
        impl Write for Counter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0 = self
                    .0
                    .checked_add(bytes.len())
                    .filter(|count| *count < crate::limits::deployment().rpc_frame_bytes)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "outgoing protocol frame exceeds limit",
                        )
                    })?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut counter = Counter(0);
        serde_json::to_writer(&mut counter, message)?;
        let mut bytes = Vec::with_capacity(counter.0 + 1);
        serde_json::to_writer(&mut bytes, message)?;
        bytes.push(b'\n');
        let resident = bytes.capacity() + FRAME_OVERHEAD;
        Ok(Self {
            bytes,
            resident,
            data: message["method"] == "event",
            guard,
            starts,
        })
    }
    fn valid(&self) -> bool {
        self.guard
            .as_ref()
            .is_none_or(|guard| guard.load(Ordering::Acquire))
    }
    pub fn resident(&self) -> usize {
        self.resident
    }
}

struct State {
    control: VecDeque<Frame>,
    data: VecDeque<Frame>,
    bytes: usize,
    data_bytes: usize,
    progress: Instant,
    writing: bool,
    failed: bool,
    stopping: bool,
}
struct Shared {
    state: Mutex<State>,
    ready: Condvar,
}

pub(super) struct ProtocolWriter {
    shared: Arc<Shared>,
    thread: std::thread::JoinHandle<()>,
}

impl ProtocolWriter {
    pub fn spawn() -> io::Result<Self> {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                control: VecDeque::new(),
                data: VecDeque::new(),
                bytes: 0,
                data_bytes: 0,
                progress: Instant::now(),
                writing: false,
                failed: false,
                stopping: false,
            }),
            ready: Condvar::new(),
        });
        let worker = shared.clone();
        let thread = std::thread::Builder::new()
            .name("protocol-writer".to_string())
            .spawn(move || {
                #[cfg(not(unix))]
                let stdout = io::stdout();
                #[cfg(not(unix))]
                let mut stdout = stdout.lock();
                #[cfg(unix)]
                let mut stdout = match PollOutput::new(worker.clone()) {
                    Ok(stdout) => stdout,
                    Err(_) => {
                        let mut state = worker
                            .state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        state.failed = true;
                        state.stopping = true;
                        worker.ready.notify_all();
                        return;
                    }
                };
                loop {
                    let frame = {
                        let mut state = worker
                            .state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        loop {
                            if state.stopping {
                                return;
                            }
                            let frame =
                                state.control.pop_front().or_else(|| state.data.pop_front());
                            if let Some(frame) = frame {
                                if !frame.valid() {
                                    state.bytes -= frame.resident;
                                    if frame.data {
                                        state.data_bytes -= frame.resident;
                                    }
                                    continue;
                                }
                                state.writing = true;
                                break frame;
                            }
                            state = worker
                                .ready
                                .wait(state)
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                        }
                    };
                    let result = (|| -> io::Result<()> {
                        let mut offset = 0;
                        while offset < frame.bytes.len() {
                            if worker
                                .state
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .stopping
                            {
                                return Err(io::Error::new(
                                    io::ErrorKind::Interrupted,
                                    "protocol writer stopped",
                                ));
                            }
                            let end = (offset + 4096).min(frame.bytes.len());
                            let written = stdout.write(&frame.bytes[offset..end])?;
                            if written == 0 {
                                return Err(io::ErrorKind::WriteZero.into());
                            }
                            offset += written;
                            worker
                                .state
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .progress = Instant::now();
                        }
                        stdout.flush()?;
                        // A buffered permit cannot block this writer or precede the flushed receipt.
                        for start in &frame.starts {
                            let _ = start.try_send(());
                        }
                        Ok(())
                    })();
                    let mut state = worker
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    state.bytes -= frame.resident;
                    if frame.data {
                        state.data_bytes -= frame.resident;
                    }
                    state.writing = false;
                    if result.is_err() {
                        state.failed = true;
                        state.stopping = true;
                        worker.ready.notify_all();
                        return;
                    }
                    state.progress = Instant::now();
                }
            })?;
        Ok(Self { shared, thread })
    }

    pub fn enqueue(&self, frame: Frame) -> Result<(), Frame> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.stopping
            || state.bytes + frame.resident > crate::limits::deployment().queued_protocol_bytes()
            || (frame.data
                && state.data_bytes + frame.resident
                    > crate::limits::deployment().protocol_data_bytes())
        {
            return Err(frame);
        }
        if state.bytes == 0 {
            state.progress = Instant::now();
        }
        state.bytes += frame.resident;
        if frame.data {
            state.data_bytes += frame.resident;
            state.data.push_back(frame);
        } else {
            state.control.push_back(frame);
        }
        self.shared.ready.notify_one();
        Ok(())
    }
    pub fn can_poll_events(&self) -> bool {
        let state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !state.stopping
            && state.bytes + crate::limits::deployment().rpc_frame_bytes + FRAME_OVERHEAD
                <= crate::limits::deployment().queued_protocol_bytes()
            && state.data_bytes + crate::limits::deployment().rpc_frame_bytes + FRAME_OVERHEAD
                <= crate::limits::deployment().protocol_data_bytes()
    }
    pub fn failed(&self) -> bool {
        self.shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .failed
    }
    pub fn stalled(&self) -> bool {
        let state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.bytes > 0
            && state.progress.elapsed() >= crate::limits::deployment().backpressure_timeout()
    }
    pub fn idle(&self) -> bool {
        self.shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .bytes
            == 0
    }
    pub fn stop(&self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.stopping = true;
        while let Some(frame) = state.control.pop_front().or_else(|| state.data.pop_front()) {
            state.bytes -= frame.resident;
            if frame.data {
                state.data_bytes -= frame.resident;
            }
        }
        self.shared.ready.notify_all();
    }
    pub fn thread(&self) -> &std::thread::JoinHandle<()> {
        &self.thread
    }
    pub fn join(self) -> std::thread::Result<()> {
        self.thread.join()
    }
    pub fn retain(self) {
        crate::execution::retained::retain(self.thread);
    }
}

// The protocol worker exclusively owns stdout. Nonblocking writes ensure a full pipe
// cannot retain the worker after connection cancellation; poll provides bounded waits.
#[cfg(unix)]
struct PollOutput {
    shared: Arc<Shared>,
    original_flags: libc::c_int,
}
#[cfg(unix)]
impl PollOutput {
    fn new(shared: Arc<Shared>) -> io::Result<Self> {
        let flags = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_SETFL, flags | libc::O_NONBLOCK) }
                < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            shared,
            original_flags: flags,
        })
    }
}
#[cfg(unix)]
impl Write for PollOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            if self
                .shared
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .stopping
            {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let mut descriptor = libc::pollfd {
                fd: libc::STDOUT_FILENO,
                events: libc::POLLOUT,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut descriptor, 1, 20) };
            if ready == 0 {
                continue;
            }
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let count =
                unsafe { libc::write(libc::STDOUT_FILENO, bytes.as_ptr().cast(), bytes.len()) };
            if count >= 0 {
                return Ok(count as usize);
            }
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(error);
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[cfg(unix)]
impl Drop for PollOutput {
    fn drop(&mut self) {
        unsafe {
            libc::fcntl(libc::STDOUT_FILENO, libc::F_SETFL, self.original_flags);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn outgoing_frame_limit_includes_newline() {
        let boundary = Value::String("x".repeat(MAX_FRAME - 3));
        let frame = Frame::encode(&boundary, None, Vec::new()).unwrap();
        assert_eq!(frame.bytes.len(), MAX_FRAME);
        assert_eq!(frame.resident(), MAX_FRAME + FRAME_OVERHEAD);
        let oversized = Value::String("x".repeat(MAX_FRAME - 2));
        assert!(Frame::encode(&oversized, None, Vec::new()).is_err());
    }

    #[test]
    fn queued_output_preserves_room_for_control_and_counts_inflight_bytes() {
        let writer = ProtocolWriter {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    control: VecDeque::new(),
                    data: VecDeque::new(),
                    bytes: 0,
                    data_bytes: 0,
                    progress: Instant::now(),
                    writing: false,
                    failed: false,
                    stopping: false,
                }),
                ready: Condvar::new(),
            }),
            thread: std::thread::spawn(|| {}),
        };
        let data =
            serde_json::json!({"method": "event", "params": {"data": "x".repeat(64 * 1024)}});
        loop {
            if writer
                .enqueue(Frame::encode(&data, None, Vec::new()).unwrap())
                .is_err()
            {
                break;
            }
        }
        let in_flight = writer
            .shared
            .state
            .lock()
            .unwrap()
            .data
            .pop_front()
            .unwrap();
        let before = writer.shared.state.lock().unwrap().bytes;
        // Removing a frame from the queue must not free its budget while write is pending.
        assert!(
            writer
                .enqueue(Frame::encode(&data, None, Vec::new()).unwrap())
                .is_err()
        );
        assert_eq!(writer.shared.state.lock().unwrap().bytes, before);
        let response = serde_json::json!({"jsonrpc":"2.0", "id":1, "result":{"cancelled":true}});
        assert!(
            writer
                .enqueue(Frame::encode(&response, None, Vec::new()).unwrap())
                .is_ok()
        );
        assert!(
            writer.shared.state.lock().unwrap().bytes
                <= crate::limits::deployment().queued_protocol_bytes()
        );
        writer.stop();
        assert_eq!(
            writer.shared.state.lock().unwrap().bytes,
            in_flight.resident()
        );
        writer.join().unwrap();
    }
}
