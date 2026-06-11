//! HTTP/2 stream state machine.
//!
//! Tracks stream lifecycle (Idle → Open → HalfClosed → Closed) and
//! per-stream flow control windows. Client streams use odd IDs.

use crate::H2Error;

/// Stream states per RFC 9113 §5.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Stream has not been opened yet.
    Idle,
    /// Stream is open for both directions.
    Open,
    /// Local side has sent END_STREAM; can still receive.
    HalfClosedLocal,
    /// Remote side has sent END_STREAM; can still send.
    HalfClosedRemote,
    /// Stream is fully closed.
    Closed,
}

/// Per-stream state tracker.
#[derive(Debug)]
pub struct Stream {
    /// Stream identifier.
    pub id: u32,
    /// Current state.
    pub state: StreamState,
    /// Send window (how much we can send before peer's ack).
    pub send_window: i32,
    /// Receive window (how much peer can send before our ack).
    pub recv_window: i32,
}

impl Stream {
    /// Create a new stream in Open state with the given initial window size.
    pub fn new(id: u32, initial_window_size: u32) -> Self {
        Self {
            id,
            state: StreamState::Open,
            send_window: initial_window_size as i32,
            recv_window: initial_window_size as i32,
        }
    }

    /// Transition to HalfClosedLocal (we sent END_STREAM).
    pub fn send_end_stream(&mut self) -> Result<(), H2Error> {
        match self.state {
            StreamState::Open => {
                self.state = StreamState::HalfClosedLocal;
                Ok(())
            }
            StreamState::HalfClosedRemote => {
                self.state = StreamState::Closed;
                Ok(())
            }
            _ => Err(H2Error::InvalidState(format!(
                "cannot send END_STREAM in state {:?}",
                self.state
            ))),
        }
    }

    /// Transition to HalfClosedRemote (received END_STREAM from peer).
    pub fn recv_end_stream(&mut self) -> Result<(), H2Error> {
        match self.state {
            StreamState::Open => {
                self.state = StreamState::HalfClosedRemote;
                Ok(())
            }
            StreamState::HalfClosedLocal => {
                self.state = StreamState::Closed;
                Ok(())
            }
            _ => Err(H2Error::InvalidState(format!(
                "cannot recv END_STREAM in state {:?}",
                self.state
            ))),
        }
    }

    /// Reset the stream (RST_STREAM received or sent).
    pub fn reset(&mut self) {
        self.state = StreamState::Closed;
    }
}

/// Allocates stream IDs for a client (odd numbers starting at 1).
#[derive(Debug)]
pub struct StreamIdAllocator {
    next: u32,
}

impl StreamIdAllocator {
    /// Create a new client-side allocator (starts at stream 1).
    pub fn new() -> Self {
        Self { next: 1 }
    }

    /// Allocate the next stream ID.
    pub fn next_id(&mut self) -> u32 {
        let id = self.next;
        self.next += 2;
        id
    }
}

impl Default for StreamIdAllocator {
    fn default() -> Self {
        Self::new()
    }
}
