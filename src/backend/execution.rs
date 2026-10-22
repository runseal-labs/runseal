use super::*;
use std::sync::mpsc::{SyncSender, TrySendError};

#[derive(Clone, Copy, Debug)]
pub enum OutputStream {
    Stdout,
    Stderr,
    #[cfg_attr(not(windows), allow(dead_code))]
    Terminal,
    #[cfg_attr(not(windows), allow(dead_code))]
    Control,
}

#[derive(Clone, Copy, Debug, Default)]
pub enum ExecutionIo {
    #[default]
    Pipe,
    PipeControl {
        child_fd: u16,
        byte_pipe: bool,
    },
    // Parsed on every platform so unsupported requests can be rejected before
    // execution; only the Windows reference backend consumes the dimensions.
    #[cfg_attr(not(windows), allow(dead_code))]
    Pty {
        rows: u16,
        cols: u16,
    },
}
impl ExecutionIo {
    pub fn has_control(self) -> bool {
        self.control_fd().is_some()
    }
    pub fn control_fd(self) -> Option<u16> {
        match self {
            Self::PipeControl { child_fd, .. } => Some(child_fd),
            _ => None,
        }
    }
    pub fn byte_pipe(self) -> bool {
        matches!(
            self,
            Self::PipeControl {
                byte_pipe: true,
                ..
            }
        )
    }
    pub fn is_pty(self) -> bool {
        matches!(self, Self::Pty { .. })
    }
}

#[derive(Debug)]
pub struct OutputChunk {
    pub stream: OutputStream,
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub enum BackendMessage {
    Started { time: String, process_id: u32 },
    SignalDelivered { sequence: u64, process_id: u32 },
    Output(OutputChunk),
}

#[derive(Clone)]
pub struct ExecutionOutputSink {
    pub sender: SyncSender<BackendMessage>,
    #[cfg_attr(not(windows), allow(dead_code))]
    pub io: ExecutionIo,
    #[cfg_attr(not(windows), allow(dead_code))]
    pub control_input: Option<ExecutionInput>,
    pub(crate) control: crate::execution::ExecutionControl,
}

pub struct BackendExecutionOptions {
    pub timeout: Option<std::time::Duration>,
    pub output: Option<ExecutionOutputSink>,
}

impl ExecutionOutputSink {
    pub fn send(&self, stream: OutputStream, bytes: &[u8]) -> io::Result<()> {
        for bytes in bytes.chunks(crate::limits::deployment().stream_chunk_bytes) {
            self.deliver(
                BackendMessage::Output(OutputChunk {
                    stream,
                    bytes: bytes.to_vec(),
                }),
                true,
            )?;
        }
        Ok(())
    }

    pub fn started(&self, process_id: u32) -> io::Result<()> {
        let _ = self.control.process_id.set(process_id);
        self.deliver(
            BackendMessage::Started {
                time: timestamp_now(),
                process_id,
            },
            false,
        )
    }

    pub fn signal_delivered(&self) -> io::Result<()> {
        let process_id = *self
            .control
            .process_id
            .get()
            .ok_or_else(|| io::Error::other("missing terminal identity"))?;
        let sequence = self
            .control
            .delivered_sequence
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            + 1;
        self.deliver(
            BackendMessage::SignalDelivered {
                sequence,
                process_id,
            },
            false,
        )
    }

    fn deliver(&self, mut message: BackendMessage, stop_on_cancel: bool) -> io::Result<()> {
        let deadline =
            std::time::Instant::now() + crate::limits::deployment().backpressure_timeout();
        loop {
            if self.control.cleanup_deadline_expired() {
                return Err(io::Error::other(super::BackendCleanupError));
            }
            if stop_on_cancel && self.control.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "execution output stopped",
                ));
            }
            match self.sender.try_send(message) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Disconnected(_)) => {
                    self.control
                        .request(crate::execution::TerminationCause::ClientDisconnected);
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "execution output owner closed",
                    ));
                }
                Err(TrySendError::Full(pending)) => {
                    if std::time::Instant::now() >= deadline {
                        self.control
                            .request(crate::execution::TerminationCause::Backpressure);
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "execution output consumer stalled",
                        ));
                    }
                    message = pending;
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionStdin {
    Empty,
    Bytes(Vec<u8>),
    File(Vec<u8>),
    Stream(ExecutionInput),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExecutionEnv {
    pub entries: Vec<(String, String)>,
}

impl ExecutionEnv {
    pub fn keys(&self) -> Vec<String> {
        self.entries.iter().map(|(key, _)| key.clone()).collect()
    }
}

#[derive(Debug)]
pub struct BackendExecutionOutput {
    pub output: Output,
    pub timed_out: bool,
    pub cleanup_complete: bool,
    pub events: Vec<Value>,
}
