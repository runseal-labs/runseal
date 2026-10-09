//! Framed IPC protocol used between the parent (CLI) and the elevated command runner.
//!
//! This module defines the JSON message schema (spawn request/ready, output, stdin,
//! exit, error, terminate) plus length‑prefixed framing helpers for a byte stream.
//! It is **elevated-path only**: the parent uses it to bootstrap the runner and
//! stream unified_exec I/O over named pipes. The legacy restricted‑token path does
//! not use this protocol, and non‑unified exec capture uses it only when running
//! through the elevated runner.

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use codex_protocol::models::PermissionProfile;
use codex_utils_absolute_path::AbsolutePathBuf;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;

/// Safety cap for a single framed message payload.
///
/// This is not a protocol requirement; it simply bounds memory use and rejects
/// obviously invalid frames.
const MAX_FRAME_LEN: usize = 8 * 1024 * 1024;

/// Protocol version shared by the parent process and elevated command runner.
pub const IPC_PROTOCOL_VERSION: u8 = 12;

/// Validated deployment wait budget; distinct from the command execution timeout.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct CleanupBudget(u64);

impl Default for CleanupBudget {
    fn default() -> Self {
        Self(10000)
    }
}

impl TryFrom<u64> for CleanupBudget {
    type Error = &'static str;

    fn try_from(milliseconds: u64) -> std::result::Result<Self, Self::Error> {
        if (100..=60000).contains(&milliseconds) {
            Ok(Self(milliseconds))
        } else {
            Err("runner cleanup budget must be from 100 to 60000 milliseconds")
        }
    }
}

impl From<CleanupBudget> for u64 {
    fn from(budget: CleanupBudget) -> Self {
        budget.0
    }
}

impl CleanupBudget {
    pub fn duration(self) -> std::time::Duration {
        std::time::Duration::from_millis(self.0)
    }
}

/// Length-prefixed, JSON-encoded frame.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FramedMessage {
    pub version: u8,
    #[serde(flatten)]
    pub message: Message,
}

/// IPC message variants exchanged between parent and runner.
///
/// `SpawnRequest`, `Stdin`, `CloseStdin`, `Resize`, and `Terminate` are parent->runner commands.
/// `SpawnReady`, `Output`, `Exit`, and `Error` are runner->parent events/results.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    SpawnRequest { payload: Box<SpawnRequest> },
    SpawnReady { payload: SpawnReady },
    Output { payload: OutputPayload },
    Stdin { payload: StdinPayload },
    CloseStdin { payload: EmptyPayload },
    Control { payload: StdinPayload },
    CloseControl { payload: EmptyPayload },
    ControlAcknowledged { payload: StdinAcknowledgedPayload },
    StdinAcknowledged { payload: StdinAcknowledgedPayload },
    Resize { payload: ResizePayload },
    Exit { payload: ExitPayload },
    CleanupStarted { payload: CleanupStartedPayload },
    Error { payload: ErrorPayload },
    Terminate { payload: CleanupDeadlinePayload },
    Interrupt { payload: EmptyPayload },
}

/// Spawn parameters sent from parent to runner.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SpawnRequest {
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub env: HashMap<String, String>,
    pub permission_profile: PermissionProfile,
    pub workspace_roots: Vec<AbsolutePathBuf>,
    pub codex_home: PathBuf,
    pub real_codex_home: PathBuf,
    pub cap_sids: Vec<String>,
    pub timeout_ms: Option<u64>,
    pub cleanup_budget: CleanupBudget,
    pub tty: bool,
    pub terminal_size: Option<ResizePayload>,
    #[serde(default)]
    pub stdin_open: bool,
    pub control_open: bool,
    #[serde(default)]
    pub use_private_desktop: bool,
}

/// Ack from runner after it spawns the child process.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SpawnReady {
    pub process_id: u32,
}

/// Output data sent from runner to parent.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OutputPayload {
    pub data_b64: String,
    pub stream: OutputStream,
}

/// Output stream identifier for `OutputPayload`.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
    Control,
}

/// Stdin bytes sent from parent to runner.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StdinPayload {
    pub data_b64: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StdinAcknowledgedPayload {
    pub bytes: usize,
}

/// PTY resize request sent from parent to runner.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResizePayload {
    pub rows: u16,
    pub cols: u16,
}

/// Exit status sent from runner to parent.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CleanupFailureStage {
    CleanupAnnouncement,
    RunnerReport,
    ProcessRange,
    ExitStatus,
    ControlWorkers,
    ConptyClose,
    ControlsReader,
    StdinWriter,
    StdoutReader,
    StderrReader,
}

impl CleanupFailureStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CleanupAnnouncement => "cleanup_announcement",
            Self::RunnerReport => "runner_report",
            Self::ProcessRange => "process_range",
            Self::ExitStatus => "exit_status",
            Self::ControlWorkers => "control_workers",
            Self::ConptyClose => "conpty_close",
            Self::ControlsReader => "controls_reader",
            Self::StdinWriter => "stdin_writer",
            Self::StdoutReader => "stdout_reader",
            Self::StderrReader => "stderr_reader",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExitPayload {
    pub exit_code: i32,
    pub timed_out: bool,
    pub cleanup_complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_stage: Option<CleanupFailureStage>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CleanupStartedPayload {
    pub deadline: CleanupDeadlinePayload,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

/// Error payload sent when the runner fails to spawn or stream.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ErrorPayload {
    pub message: String,
    pub code: String,
}

/// Empty payload for control messages.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct EmptyPayload {}

/// Absolute native monotonic deadline shared by processes on this host.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CleanupDeadlinePayload {
    cleanup_deadline_ticks: i64,
}

#[cfg(windows)]
fn performance_counter() -> Result<(i64, i64)> {
    let mut frequency = 0;
    let mut counter = 0;
    if unsafe { windows_sys::Win32::System::Performance::QueryPerformanceFrequency(&mut frequency) }
        == 0
        || unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut counter) }
            == 0
        || frequency <= 0
    {
        anyhow::bail!("native execution clock unavailable");
    }
    Ok((counter, frequency))
}

#[cfg(windows)]
impl CleanupDeadlinePayload {
    pub fn expired() -> Self {
        Self {
            cleanup_deadline_ticks: 0,
        }
    }

    pub fn new(deadline: std::time::Instant) -> Result<Self> {
        // Sampling the native clock first and rounding down cannot renew the deadline.
        let (counter, frequency) = performance_counter()?;
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let ticks = remaining
            .as_nanos()
            .checked_mul(frequency as u128)
            .ok_or_else(|| anyhow::anyhow!("execution deadline overflow"))?
            / 1_000_000_000;
        let ticks = i64::try_from(ticks)?;
        Ok(Self {
            cleanup_deadline_ticks: counter
                .checked_add(ticks)
                .ok_or_else(|| anyhow::anyhow!("execution deadline overflow"))?,
        })
    }

    pub fn deadline(&self) -> Result<std::time::Instant> {
        let local_now = std::time::Instant::now();
        let (counter, frequency) = performance_counter()?;
        let ticks = self.cleanup_deadline_ticks.saturating_sub(counter).max(0) as u128;
        let nanos = ticks * 1_000_000_000 / frequency as u128;
        let duration = std::time::Duration::from_nanos(u64::try_from(nanos)?);
        local_now
            .checked_add(duration)
            .ok_or_else(|| anyhow::anyhow!("execution deadline overflow"))
    }
}

/// Base64-encode raw bytes for IPC payloads.
pub fn encode_bytes(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Decode base64 payload data into raw bytes.
pub fn decode_bytes(data: &str) -> Result<Vec<u8>> {
    Ok(STANDARD.decode(data.as_bytes())?)
}

/// Write a length-prefixed JSON frame.
pub fn write_frame<W: Write>(mut writer: W, msg: &FramedMessage) -> Result<()> {
    let payload = serde_json::to_vec(msg)?;
    if payload.len() > MAX_FRAME_LEN {
        anyhow::bail!("frame too large: {}", payload.len());
    }
    let len = payload.len() as u32;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

/// Read a length-prefixed JSON frame; returns `Ok(None)` on EOF.
pub fn read_frame<R: Read>(mut reader: R) -> Result<Option<FramedMessage>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        anyhow::bail!("frame too large: {len}");
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(Some(decode_frame_payload(&payload)?))
}

fn decode_frame_payload(payload: &[u8]) -> Result<FramedMessage> {
    let msg: FramedMessage =
        serde_json::from_slice(payload).map_err(|_| anyhow::anyhow!("invalid runner IPC frame"))?;
    if msg.version != IPC_PROTOCOL_VERSION {
        anyhow::bail!("runner IPC version mismatch");
    }
    Ok(msg)
}

#[cfg(windows)]
pub enum FramePoll {
    Pending,
    Progress,
    Closed,
    Message(FramedMessage),
}

/// Exclusive pipe reader that never waits for another byte or writer closure.
/// Each poll reads at most one available chunk, including partial frame headers.
#[cfg(windows)]
#[derive(Default)]
pub struct PipeFrameReader {
    header: [u8; 4],
    header_bytes: usize,
    payload: Vec<u8>,
    payload_bytes: usize,
    expected: Option<usize>,
}

#[cfg(windows)]
impl PipeFrameReader {
    pub fn poll(&mut self, pipe: &mut std::fs::File) -> Result<FramePoll> {
        let available = match crate::available_pipe_bytes(pipe)? {
            Some(0) => return Ok(FramePoll::Pending),
            Some(count) => count.min(64 * 1024),
            None if self.header_bytes == 0 => return Ok(FramePoll::Closed),
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "incomplete runner frame",
                )
                .into());
            }
        };
        if self.expected.is_none() {
            let end = 4.min(self.header_bytes + available);
            let count = pipe.read(&mut self.header[self.header_bytes..end])?;
            if count == 0 {
                anyhow::bail!("runner frame header closed unexpectedly");
            }
            self.header_bytes += count;
            if self.header_bytes == 4 {
                let expected = u32::from_le_bytes(self.header) as usize;
                if expected > MAX_FRAME_LEN {
                    anyhow::bail!("frame too large: {expected}");
                }
                self.expected = Some(expected);
                self.payload.resize(expected, 0);
            }
        } else {
            let expected = self
                .expected
                .ok_or_else(|| anyhow::anyhow!("runner frame length unavailable"))?;
            let end = expected.min(self.payload_bytes + available);
            let count = pipe.read(&mut self.payload[self.payload_bytes..end])?;
            if count == 0 {
                anyhow::bail!("runner frame payload closed unexpectedly");
            }
            self.payload_bytes += count;
        }
        if self.expected == Some(self.payload_bytes) {
            let message = decode_frame_payload(&self.payload)?;
            self.header_bytes = 0;
            self.payload_bytes = 0;
            self.expected = None;
            self.payload.clear();
            return Ok(FramePoll::Message(message));
        }
        Ok(FramePoll::Progress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[cfg(windows)]
    #[test]
    fn termination_deadline_survives_a_delayed_native_peer_without_a_new_grace_period() -> Result<()>
    {
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        struct Peer(std::process::Child);
        impl Drop for Peer {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let python = String::from_utf8(Command::new("where.exe").arg("python").output()?.stdout)?;
        let python = python
            .lines()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Python required"))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let payload = CleanupDeadlinePayload::new(deadline)?;
        let decoded = payload.deadline()?;
        let mut peer = Peer(Command::new(python).args(["-u", "-c", "import sys,ctypes; k=ctypes.WinDLL('kernel32',use_last_error=True); q=ctypes.c_longlong(); f=ctypes.c_longlong(); print('READY',flush=True); assert sys.stdin.buffer.read(1)==b'G'; assert k.QueryPerformanceFrequency(ctypes.byref(f)); assert k.QueryPerformanceCounter(ctypes.byref(q)); print((int(sys.argv[1])-q.value)/f.value,flush=True)"])
            .arg(payload.cleanup_deadline_ticks.to_string()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?);
        let mut output = std::io::BufReader::new(
            peer.0
                .stdout
                .take()
                .ok_or_else(|| anyhow::anyhow!("peer stdout"))?,
        );
        let mut ready = String::new();
        output.read_line(&mut ready)?;
        std::thread::sleep(std::time::Duration::from_millis(150));
        peer.0
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("peer stdin"))?
            .write_all(b"G")?;
        let mut remaining = String::new();
        output.read_line(&mut remaining)?;
        let status = peer.0.wait()?;
        assert_eq!(ready.trim(), "READY");
        assert!(status.success());
        assert!(
            decoded <= deadline,
            "encoding and decoding cannot extend the host deadline"
        );
        assert!(
            remaining.trim().parse::<f64>()? < 4.85,
            "the real peer must account for transport delay"
        );
        assert!(CleanupDeadlinePayload::expired().deadline()? <= std::time::Instant::now());
        assert!(serde_json::from_str::<CleanupDeadlinePayload>("{}").is_err());
        Ok(())
    }

    #[cfg(windows)]
    fn native_pipe() -> Result<(std::fs::File, std::fs::File)> {
        use std::os::windows::io::FromRawHandle;
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
                std::fs::File::from_raw_handle(read as _),
                std::fs::File::from_raw_handle(write as _),
            )
        })
    }

    #[cfg(windows)]
    #[test]
    fn native_poll_reader_decodes_fragmented_and_adjacent_frames_without_peer_eof() -> Result<()> {
        let frames = [
            FramedMessage {
                version: IPC_PROTOCOL_VERSION,
                message: Message::Output {
                    payload: OutputPayload {
                        data_b64: encode_bytes(b"\0\xff\xc3\xa9"),
                        stream: OutputStream::Stdout,
                    },
                },
            },
            FramedMessage {
                version: IPC_PROTOCOL_VERSION,
                message: Message::StdinAcknowledged {
                    payload: StdinAcknowledgedPayload { bytes: 4 },
                },
            },
            FramedMessage {
                version: IPC_PROTOCOL_VERSION,
                message: Message::Exit {
                    payload: ExitPayload {
                        exit_code: 7,
                        timed_out: false,
                        cleanup_complete: true,
                        cleanup_stage: None,
                    },
                },
            },
        ];
        let (mut pipe, mut peer) = native_pipe()?;
        let mut reader = PipeFrameReader::default();
        let mut first = Vec::new();
        write_frame(&mut first, &frames[0])?;
        let mut decoded = Vec::new();
        for byte in first {
            peer.write_all(&[byte])?;
            if let FramePoll::Message(message) = reader.poll(&mut pipe)? {
                decoded.push(message);
            }
        }
        let mut rest = Vec::new();
        for frame in &frames[1..] {
            write_frame(&mut rest, frame)?;
        }
        peer.write_all(&rest)?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while decoded.len() < frames.len() && std::time::Instant::now() < deadline {
            if let FramePoll::Message(message) = reader.poll(&mut pipe)? {
                decoded.push(message);
            }
        }
        assert_eq!(decoded.len(), frames.len());
        for (actual, expected) in decoded.iter().zip(&frames) {
            assert_eq!(
                serde_json::to_value(actual)?,
                serde_json::to_value(expected)?
            );
        }
        assert!(matches!(reader.poll(&mut pipe)?, FramePoll::Pending));
        drop(peer);
        assert!(matches!(reader.poll(&mut pipe)?, FramePoll::Closed));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn native_poll_reader_rejects_truncated_header_and_oversized_frame() -> Result<()> {
        let (mut pipe, mut peer) = native_pipe()?;
        let mut reader = PipeFrameReader::default();
        peer.write_all(&[1, 0])?;
        assert!(matches!(reader.poll(&mut pipe)?, FramePoll::Progress));
        drop(peer);
        let error = reader
            .poll(&mut pipe)
            .err()
            .ok_or_else(|| anyhow::anyhow!("truncated frame accepted"))?;
        assert!(
            error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::UnexpectedEof)
        );
        let (mut pipe, mut peer) = native_pipe()?;
        let mut reader = PipeFrameReader::default();
        peer.write_all(&((MAX_FRAME_LEN + 1) as u32).to_le_bytes())?;
        assert!(reader.poll(&mut pipe).is_err());
        Ok(())
    }

    #[test]
    fn framed_round_trip() {
        let msg = FramedMessage {
            version: IPC_PROTOCOL_VERSION,
            message: Message::Output {
                payload: OutputPayload {
                    data_b64: encode_bytes(b"hello"),
                    stream: OutputStream::Stdout,
                },
            },
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &msg).expect("write");
        let decoded = read_frame(buf.as_slice()).expect("read").expect("some");
        assert_eq!(decoded.version, IPC_PROTOCOL_VERSION);
        match decoded.message {
            Message::Output { payload } => {
                assert_eq!(payload.stream, OutputStream::Stdout);
                let data = decode_bytes(&payload.data_b64).expect("decode");
                assert_eq!(data, b"hello");
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn spawn_request_serializes_permission_profile() {
        let workspace_roots = vec![
            AbsolutePathBuf::from_absolute_path(PathBuf::from(r"C:\workspace"))
                .expect("absolute workspace root"),
        ];
        let msg = FramedMessage {
            version: IPC_PROTOCOL_VERSION,
            message: Message::SpawnRequest {
                payload: Box::new(SpawnRequest {
                    command: vec!["cmd.exe".to_string(), "/c".to_string(), "ver".to_string()],
                    cwd: PathBuf::from(r"C:\workspace"),
                    env: HashMap::new(),
                    permission_profile: PermissionProfile::read_only(),
                    workspace_roots: workspace_roots.clone(),
                    codex_home: PathBuf::from(r"C:\codex"),
                    real_codex_home: PathBuf::from(r"C:\Users\codex"),
                    cap_sids: vec!["S-1-15-3-1024-1".to_string()],
                    timeout_ms: Some(1000),
                    cleanup_budget: CleanupBudget::default(),
                    tty: false,
                    terminal_size: None,
                    stdin_open: false,
                    control_open: false,
                    use_private_desktop: false,
                }),
            },
        };

        let encoded = serde_json::to_value(&msg).expect("serialize");
        assert_eq!("spawn_request", encoded["type"]);
        assert_eq!("managed", encoded["payload"]["permission_profile"]["type"]);
        assert_eq!(None, encoded["payload"].get("policy_json_or_preset"));
        assert_eq!(None, encoded["payload"].get("sandbox_policy_cwd"));
        assert_eq!(None, encoded["payload"].get("permission_profile_cwd"));

        let decoded: FramedMessage = serde_json::from_value(encoded).expect("deserialize");
        let Message::SpawnRequest { payload } = decoded.message else {
            panic!("unexpected message");
        };
        assert_eq!(PermissionProfile::read_only(), payload.permission_profile);
        assert_eq!(workspace_roots, payload.workspace_roots);
    }
}
