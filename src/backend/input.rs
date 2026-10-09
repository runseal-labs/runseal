use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[cfg(test)]
const MAX_CHUNK: usize = 64 * 1024;

#[derive(Default)]
struct State {
    pending: VecDeque<Vec<u8>>,
    bytes: usize,
    closed: bool,
    in_flight: usize,
}

#[derive(Clone, Default)]
pub struct ExecutionInput {
    state: Arc<Mutex<State>>,
}

impl std::fmt::Debug for ExecutionInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ExecutionInput")
    }
}
impl PartialEq for ExecutionInput {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }
}
impl Eq for ExecutionInput {}

pub enum InputPoll {
    Data(Vec<u8>),
    Pending,
    Eof,
}

#[derive(Debug)]
pub enum InputError {
    Oversized,
    Closed,
    Backpressure,
    Unavailable,
}

impl InputError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Oversized => "INVALID_REQUEST",
            Self::Closed => "EXECUTION_INPUT_CLOSED",
            Self::Backpressure => "INPUT_BACKPRESSURE",
            Self::Unavailable => "INTERNAL_ERROR",
        }
    }
}

impl ExecutionInput {
    pub fn remaining_capacity(&self) -> Result<usize, InputError> {
        self.state
            .lock()
            .map(|state| {
                crate::limits::deployment()
                    .input_pending_bytes
                    .saturating_sub(state.bytes)
            })
            .map_err(|_| InputError::Unavailable)
    }
    pub fn write(&self, bytes: Vec<u8>) -> Result<usize, InputError> {
        if bytes.len() > crate::limits::deployment().stream_chunk_bytes {
            return Err(InputError::Oversized);
        }
        let mut state = self.state.lock().map_err(|_| InputError::Unavailable)?;
        if state.closed {
            return Err(InputError::Closed);
        }
        if state.bytes.saturating_add(bytes.len()) > crate::limits::deployment().input_pending_bytes
        {
            return Err(InputError::Backpressure);
        }
        let count = bytes.len();
        if count > 0 {
            let chunk_limit = crate::limits::deployment().stream_chunk_bytes;
            let mut remaining = bytes.as_slice();
            if let Some(tail) = state.pending.back_mut() {
                let append = (chunk_limit - tail.len()).min(remaining.len());
                tail.extend_from_slice(&remaining[..append]);
                remaining = &remaining[append..];
            }
            if !remaining.is_empty() {
                // Only the last queued buffer may be partial. Fixed capacity
                // bounds retained storage for tiny writes and discards unused
                // caller capacity; protocol write boundaries are not byte-stream
                // boundaries. Never merge into an unacknowledged in-flight buffer.
                let mut packed = Vec::with_capacity(chunk_limit);
                packed.extend_from_slice(remaining);
                state.pending.push_back(packed);
            }
            state.bytes += count;
        }
        Ok(count)
    }
    pub fn close(&self) -> Result<(), InputError> {
        self.state
            .lock()
            .map_err(|_| InputError::Unavailable)?
            .closed = true;
        Ok(())
    }
    pub fn poll(&self) -> Result<InputPoll, InputError> {
        let mut state = self.state.lock().map_err(|_| InputError::Unavailable)?;
        if state.in_flight > 0 {
            return Ok(InputPoll::Pending);
        }
        if let Some(bytes) = state.pending.pop_front() {
            state.in_flight = bytes.len();
            return Ok(InputPoll::Data(bytes));
        }
        Ok(if state.closed {
            InputPoll::Eof
        } else {
            InputPoll::Pending
        })
    }
    pub fn acknowledge(&self, count: usize) -> Result<(), InputError> {
        let mut state = self.state.lock().map_err(|_| InputError::Unavailable)?;
        if count != state.in_flight || count == 0 {
            return Err(InputError::Unavailable);
        }
        state.bytes -= count;
        state.in_flight = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allocated_queue_storage(state: &State) -> usize {
        state.pending.capacity() * std::mem::size_of::<Vec<u8>>()
            + state.pending.iter().map(Vec::capacity).sum::<usize>()
    }

    #[test]
    fn single_byte_input_storage_stays_bounded_until_write_acknowledgement() {
        let limits = crate::limits::deployment();
        let budget = limits.input_pending_bytes;
        let chunk = limits.stream_chunk_bytes;
        let queue = ExecutionInput::default();
        for index in 0..budget {
            assert_eq!(queue.write(vec![(index % 256) as u8]).unwrap(), 1);
        }
        let storage_bound =
            budget + 2 * chunk + 2 * (budget.div_ceil(chunk) + 1) * std::mem::size_of::<Vec<u8>>();
        {
            let state = queue.state.lock().unwrap();
            assert!(
                allocated_queue_storage(&state) <= storage_bound,
                "retained buffer and node capacity exceeds the stream storage bound: {} > {storage_bound}",
                allocated_queue_storage(&state)
            );
            assert_eq!(state.bytes, budget);
        }
        queue.close().unwrap();
        let mut received = Vec::new();
        loop {
            let before = queue.state.lock().unwrap().bytes;
            match queue.poll().unwrap() {
                InputPoll::Data(bytes) => {
                    assert!(bytes.len() <= chunk);
                    assert_eq!(queue.state.lock().unwrap().bytes, before);
                    assert!(matches!(queue.poll().unwrap(), InputPoll::Pending));
                    let retained =
                        allocated_queue_storage(&queue.state.lock().unwrap()) + bytes.capacity();
                    assert!(retained <= storage_bound);
                    received.extend_from_slice(&bytes);
                    queue.acknowledge(bytes.len()).unwrap();
                    assert_eq!(queue.state.lock().unwrap().bytes, before - bytes.len());
                }
                InputPoll::Eof => break,
                InputPoll::Pending => panic!("no unacknowledged input remains"),
            }
        }
        assert_eq!(received.len(), budget);
        for (index, byte) in received.into_iter().enumerate() {
            assert_eq!(byte, (index % 256) as u8);
        }
    }

    #[test]
    fn input_queue_does_not_retain_the_callers_unused_vector_capacity() {
        let limits = crate::limits::deployment();
        let mut bytes = Vec::with_capacity(limits.input_pending_bytes * 4);
        bytes.extend_from_slice(b"allowed");
        let queue = ExecutionInput::default();
        assert_eq!(queue.write(bytes).unwrap(), 7);
        assert!(
            allocated_queue_storage(&queue.state.lock().unwrap())
                <= limits.stream_chunk_bytes + 8 * std::mem::size_of::<Vec<u8>>()
        );
        let InputPoll::Data(bytes) = queue.poll().unwrap() else {
            panic!("accepted input missing")
        };
        assert_eq!(bytes, b"allowed");
        assert!(bytes.capacity() <= limits.stream_chunk_bytes);
        queue.acknowledge(bytes.len()).unwrap();
    }

    #[test]
    fn pending_budget_includes_the_unacknowledged_write() {
        let queue = ExecutionInput::default();
        for byte in 0..4 {
            assert_eq!(queue.write(vec![byte; MAX_CHUNK]).unwrap(), MAX_CHUNK);
        }
        assert!(matches!(
            queue.write(vec![9]),
            Err(InputError::Backpressure)
        ));
        assert!(matches!(queue.poll().unwrap(), InputPoll::Data(_)));
        assert!(matches!(
            queue.write(vec![9]),
            Err(InputError::Backpressure)
        ));
        assert!(matches!(queue.poll().unwrap(), InputPoll::Pending));
        queue.acknowledge(MAX_CHUNK).unwrap();
        assert_eq!(queue.write(vec![9]).unwrap(), 1);
        queue.close().unwrap();
        queue.close().unwrap();
        assert!(matches!(queue.write(Vec::new()), Err(InputError::Closed)));
        for expected in [MAX_CHUNK, MAX_CHUNK, MAX_CHUNK, 1] {
            let InputPoll::Data(bytes) = queue.poll().unwrap() else {
                panic!("accepted input must drain before EOF")
            };
            assert_eq!(bytes.len(), expected);
            queue.acknowledge(expected).unwrap();
        }
        assert!(matches!(queue.poll().unwrap(), InputPoll::Eof));
    }

    #[test]
    fn rejected_chunk_cannot_partially_enter_the_queue() {
        let queue = ExecutionInput::default();
        assert!(matches!(
            queue.write(vec![0; MAX_CHUNK + 1]),
            Err(InputError::Oversized)
        ));
        assert!(matches!(queue.poll().unwrap(), InputPoll::Pending));
        assert_eq!(queue.write(b"allowed".to_vec()).unwrap(), 7);
        let InputPoll::Data(bytes) = queue.poll().unwrap() else {
            panic!("accepted input missing")
        };
        assert_eq!(bytes, b"allowed");
    }
}
