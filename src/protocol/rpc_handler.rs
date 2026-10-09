use crate::rpc;
use serde_json::Value;
use std::io::{self, BufRead};
use std::sync::mpsc;

pub(crate) fn run_rpc_stdio() -> Result<(), String> {
    run_stdio(false)
}
pub(crate) fn run_service_stdio() -> Result<(), String> {
    run_stdio(true)
}

fn run_stdio(stateful: bool) -> Result<(), String> {
    use super::stdio_writer::{Frame, ProtocolWriter};
    use std::collections::VecDeque;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let (input_sender, input_receiver) = mpsc::sync_channel(4);
    let reader_stop = Arc::new(AtomicBool::new(false));
    let stop = reader_stop.clone();
    let reader_thread = std::thread::Builder::new()
        .name("protocol-reader".to_string())
        .spawn(move || {
            #[cfg(windows)]
            let stdin = io::stdin();
            #[cfg(windows)]
            let mut reader = stdin.lock();
            #[cfg(not(windows))]
            let mut reader = io::BufReader::new(PollInput { stop: stop.clone() });
            while !stop.load(Ordering::Acquire) {
                let frame = read_frame(&mut reader);
                let finished = matches!(frame, Ok(None))
                    || frame
                        .as_ref()
                        .err()
                        .is_some_and(|err| err.kind() != io::ErrorKind::InvalidData);
                if input_sender.send(frame).is_err() || finished {
                    break;
                }
            }
        })
        .map_err(|_| "failed to start protocol reader".to_string())?;
    let writer =
        ProtocolWriter::spawn().map_err(|_| "failed to start protocol writer".to_string())?;
    let mut service = if stateful {
        crate::service::Service::stateful()
    } else {
        crate::service::Service::direct()
    };
    let mut pending = VecDeque::<Frame>::new();
    let mut pending_bytes = 0usize;
    let mut input_closed = false;
    let mut aborted = None;
    let service_tick = std::time::Duration::from_millis(10);
    loop {
        if aborted.is_none() && (writer.failed() || writer.stalled()) {
            let cause = if writer.failed() {
                crate::execution::TerminationCause::ClientDisconnected
            } else {
                crate::execution::TerminationCause::Backpressure
            };
            service.cancel_owned_for(cause);
            aborted = Some(cause);
            writer.stop();
            pending.clear();
            pending_bytes = 0;
            reader_stop.store(true, Ordering::Release);
        }
        while let Some(frame) = pending.pop_front() {
            let bytes = frame.resident();
            match writer.enqueue(frame) {
                Ok(()) => pending_bytes -= bytes,
                Err(frame) => {
                    pending.push_front(frame);
                    break;
                }
            }
        }
        let mut messages = Vec::new();
        if !input_closed
            && aborted.is_none()
            && pending_bytes < crate::limits::deployment().pending_input_pause_bytes()
        {
            match input_receiver.recv_timeout(service_tick) {
                Ok(Ok(Some(line))) => {
                    if !line.iter().all(u8::is_ascii_whitespace) {
                        messages = match serde_json::from_slice::<Value>(&line) {
                            Ok(request) => service.handle_rpc_request(&request),
                            Err(_) => {
                                vec![rpc::parse_error("invalid JSON-RPC request".to_string())]
                            }
                        };
                    }
                }
                Ok(Err(err)) if err.kind() == io::ErrorKind::InvalidData => messages.push(
                    rpc::parse_error("JSON-RPC frame exceeds maximum length".to_string()),
                ),
                Ok(Ok(None)) | Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    input_closed = true;
                    service.cancel_owned();
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        } else {
            std::thread::sleep(service_tick);
        }
        messages.extend(service.poll_admissions());
        messages.extend(service.poll_disposal_deadlines());
        let mut starts = service.take_admitted_starts();
        if messages.is_empty() {
            // A dropped start sender closes its one-shot gate, so an execution
            // cannot launch unless its receipt has a frame to carry the permit.
            drop(starts);
        } else {
            let last = messages.len() - 1;
            for (index, message) in messages.into_iter().enumerate() {
                let permits = if index == last {
                    std::mem::take(&mut starts)
                } else {
                    Vec::new()
                };
                match Frame::encode(&message, service.delivery_guard(&message), permits) {
                    Ok(frame) => {
                        pending_bytes += frame.resident();
                        pending.push_back(frame);
                    }
                    Err(_) => {
                        aborted = Some(crate::execution::TerminationCause::ClientDisconnected);
                    }
                }
            }
        }
        if pending_bytes > crate::limits::deployment().pending_protocol_bytes() {
            aborted = Some(crate::execution::TerminationCause::Backpressure);
        }
        if aborted.is_some() || (pending.is_empty() && writer.can_poll_events()) {
            for message in service.poll_lifecycle() {
                if aborted.is_some() {
                    continue;
                }
                match Frame::encode(&message, service.delivery_guard(&message), Vec::new()) {
                    Ok(frame) => {
                        pending_bytes += frame.resident();
                        pending.push_back(frame);
                    }
                    Err(_) => {
                        aborted = Some(crate::execution::TerminationCause::ClientDisconnected);
                    }
                }
            }
        }
        if let Some(cause) = aborted {
            service.cancel_owned_for(cause);
            writer.stop();
            pending.clear();
            pending_bytes = 0;
            reader_stop.store(true, Ordering::Release);
            if !service.has_active() {
                break;
            }
        } else if input_closed && !service.has_active() && pending.is_empty() && writer.idle() {
            break;
        }
    }
    reader_stop.store(true, Ordering::Release);
    drop(input_receiver);
    writer.stop();
    stop_io_thread(writer.thread());
    stop_io_thread(&reader_thread);
    if crate::execution::retained::thread_finished(writer.thread()) {
        let _ = writer.join();
    } else {
        writer.retain();
    }
    if crate::execution::retained::thread_finished(&reader_thread) {
        let _ = reader_thread.join();
    } else {
        crate::execution::retained::retain(reader_thread);
    }
    if aborted.is_some() {
        Err("protocol connection closed after transport failure".to_string())
    } else {
        Ok(())
    }
}

fn stop_io_thread(thread: &std::thread::JoinHandle<()>) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !crate::execution::retained::thread_finished(thread)
        && std::time::Instant::now() < deadline
    {
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            unsafe {
                windows_sys::Win32::System::IO::CancelSynchronousIo(thread.as_raw_handle().cast());
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(unix)]
struct PollInput {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
#[cfg(unix)]
impl std::io::Read for PollInput {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        use std::sync::atomic::Ordering;
        while !self.stop.load(Ordering::Acquire) {
            let mut descriptor = libc::pollfd {
                fd: 0,
                events: libc::POLLIN,
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
            let count = unsafe { libc::read(0, bytes.as_mut_ptr().cast(), bytes.len()) };
            if count >= 0 {
                return Ok(count as usize);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        Err(io::ErrorKind::Interrupted.into())
    }
}

// Bound allocations while draining an oversized frame to its newline.
fn read_frame(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let max_frame = crate::limits::deployment().rpc_frame_bytes;
    let mut frame = Vec::new();
    let mut oversized = false;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            if oversized {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "frame too large",
                ));
            }
            return Ok((!frame.is_empty()).then_some(frame));
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(buffer.len(), |index| index + 1);
        if !oversized {
            if frame.len().saturating_add(consumed) > max_frame {
                oversized = true;
                frame.clear();
            } else {
                frame.extend_from_slice(&buffer[..consumed]);
            }
        }
        reader.consume(consumed);
        if newline.is_some() {
            if oversized {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "frame too large",
                ));
            }
            return Ok(Some(frame));
        }
    }
}
