//! Private guardian wire protocol.
//!
//! The controller and the trusted guardian exchange bounded, length-prefixed
//! JSON frames. Input/interrupt/cancel messages carry their accepted sequence
//! through unchanged; the guardian never acknowledges a signal before the
//! native delivery attempt has produced a `SignalDelivered` frame.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

/// One frame may not exceed this size. Both directions use the same limit.
pub(crate) const MAX_FRAME_BYTES: usize = 1024 * 1024;
/// A single input chunk is bounded independently of the whole frame budget.
pub(crate) const MAX_INPUT_BYTES: usize = 64 * 1024;
/// Total unacknowledged input bytes the controller may have in flight.
pub(crate) const MAX_IN_FLIGHT_INPUT_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WireIo {
    Pipe,
    PipeControl { child_fd: u16, byte_pipe: bool },
    Pty { rows: u16, cols: u16 },
}

impl From<super::super::backend::ExecutionIo> for WireIo {
    fn from(io: super::super::backend::ExecutionIo) -> Self {
        match io {
            super::super::backend::ExecutionIo::Pipe => Self::Pipe,
            super::super::backend::ExecutionIo::PipeControl {
                child_fd,
                byte_pipe,
            } => Self::PipeControl {
                child_fd,
                byte_pipe,
            },
            super::super::backend::ExecutionIo::Pty { rows, cols } => Self::Pty { rows, cols },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WireStdin {
    Empty,
    Bytes(Vec<u8>),
    Stream,
}

/// Prepared launch data. It deliberately does not serialize
/// `PlatformSandboxPlan`; the controller resolves the environment and profile
/// before sending this private spec.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct LaunchSpec {
    pub(crate) argv: Vec<String>,
    pub(crate) cwd: String,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) base_profile: String,
    pub(crate) io: WireIo,
    pub(crate) stdin: WireStdin,
    pub(crate) timeout_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WireStream {
    Stdout,
    Stderr,
    Terminal,
    Control,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WireInput {
    Stdin,
    Control,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ControllerFrame {
    Input {
        stream: WireInput,
        data: Vec<u8>,
    },
    CloseInput {
        stream: WireInput,
    },
    Resize {
        rows: u16,
        cols: u16,
    },
    /// `sequence` is the execution layer's accepted sequence, unchanged.
    Interrupt {
        sequence: u64,
    },
    Cancel {
        sequence: Option<u64>,
    },
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum GuardianFrame {
    Started {
        time: String,
        process_id: u32,
    },
    SignalDelivered {
        sequence: u64,
        process_id: u32,
        process_group_id: Option<u32>,
    },
    /// Accepted into the guardian's bounded native input queue. The controller
    /// releases this much wire budget only after receiving this acknowledgement;
    /// acceptance is not proof that the native process consumed the bytes.
    InputAccepted {
        stream: WireInput,
        bytes: u32,
    },
    InputClosed {
        stream: WireInput,
    },
    Output {
        stream: WireStream,
        data: Vec<u8>,
    },
    Done {
        exit_code: Option<i32>,
        exit_signal: Option<i32>,
        timed_out: bool,
        /// Native output/input workers have been joined.
        io_joined: bool,
        /// No owned children remain according to the guardian's drain.
        children_drained: bool,
        tasks_started: u64,
        tasks_exited: u64,
    },
}

fn validate_input(data: &[u8]) -> io::Result<()> {
    if data.len() > MAX_INPUT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guardian input chunk exceeds budget",
        ));
    }
    Ok(())
}

impl ControllerFrame {
    fn validate(&self) -> io::Result<()> {
        match self {
            Self::Input { data, .. } => validate_input(data),
            Self::CloseInput { .. }
            | Self::Resize { .. }
            | Self::Interrupt { .. }
            | Self::Cancel { .. } => Ok(()),
        }
    }
}

pub(crate) fn write_frame<T: Serialize>(writer: &mut impl Write, frame: &T) -> io::Result<()> {
    let payload = serde_json::to_vec(frame)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guardian frame exceeds budget",
        ));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "guardian frame length"))?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}

pub(crate) fn write_controller_frame(
    writer: &mut impl Write,
    frame: &ControllerFrame,
) -> io::Result<()> {
    frame.validate()?;
    write_frame(writer, frame)
}

pub(crate) fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> io::Result<T> {
    let mut length_bytes = [0u8; 4];
    reader.read_exact(&mut length_bytes)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "guardian frame length is out of range",
        ));
    }
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub(crate) fn read_controller_frame(reader: &mut impl Read) -> io::Result<ControllerFrame> {
    let frame: ControllerFrame = read_frame(reader)?;
    frame.validate()?;
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_spec() -> LaunchSpec {
        LaunchSpec {
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "exit 0".to_string(),
            ],
            cwd: "/tmp".to_string(),
            env: vec![("PATH".to_string(), "/usr/bin:/bin".to_string())],
            base_profile: "(version 1)(allow default)".to_string(),
            io: WireIo::Pty { rows: 24, cols: 80 },
            stdin: WireStdin::Stream,
            timeout_ms: Some(1_000),
        }
    }

    #[test]
    fn frames_round_trip_with_bounded_length_prefix() {
        let mut bytes = Vec::new();
        write_controller_frame(&mut bytes, &ControllerFrame::Interrupt { sequence: 17 }).unwrap();
        let decoded: ControllerFrame = read_controller_frame(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded, ControllerFrame::Interrupt { sequence: 17 });
    }

    #[test]
    fn launch_spec_round_trips_without_platform_plan() {
        let spec = sample_spec();
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &spec).unwrap();
        let decoded: LaunchSpec = read_frame(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded, spec);
    }

    #[test]
    fn oversized_input_is_rejected_before_write() {
        let mut bytes = Vec::new();
        let error = write_controller_frame(
            &mut bytes,
            &ControllerFrame::Input {
                stream: WireInput::Control,
                data: vec![0u8; MAX_INPUT_BYTES + 1],
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(bytes.is_empty());
    }

    #[test]
    fn oversized_frame_length_is_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes());
        let error = read_frame::<ControllerFrame>(&mut bytes.as_slice()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
