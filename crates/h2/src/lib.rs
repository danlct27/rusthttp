//! Custom HTTP/2 client implementation with Chrome fingerprint parity.
//!
//! This crate does NOT use the `h2` crate. It implements a minimal client-only
//! HTTP/2 codec that matches Chrome's exact SETTINGS, WINDOW_UPDATE, and
//! pseudo-header ordering to pass Akamai/Cloudflare HTTP/2 fingerprinting.

pub mod codec;
pub mod connection;
pub mod frame;
pub mod hpack;
pub mod stream;

use thiserror::Error;

/// Chrome's HTTP/2 SETTINGS values (Chrome 137+).
/// Akamai fingerprint target: `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`
pub mod chrome {
    /// SETTINGS_HEADER_TABLE_SIZE = 65536
    pub const HEADER_TABLE_SIZE: u32 = 65536;
    /// SETTINGS_ENABLE_PUSH: u32 = 0
    pub const ENABLE_PUSH: u32 = 0;
    /// SETTINGS_INITIAL_WINDOW_SIZE = 6291456
    pub const INITIAL_WINDOW_SIZE: u32 = 6291456;
    /// SETTINGS_MAX_HEADER_LIST_SIZE = 262144
    pub const MAX_HEADER_LIST_SIZE: u32 = 262144;
    /// Connection-level WINDOW_UPDATE increment
    pub const CONNECTION_WINDOW_INCREMENT: u32 = 15663105;
    /// Chrome pseudo-header order: :method, :authority, :scheme, :path
    pub const PSEUDO_HEADER_ORDER: &[&str] = &[":method", ":authority", ":scheme", ":path"];
}

/// Errors from the HTTP/2 layer.
#[derive(Debug, Error)]
pub enum H2Error {
    /// IO error during read/write.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Received an unknown frame type.
    #[error("unknown frame type: {0}")]
    UnknownFrameType(u8),

    /// Protocol violation (e.g. bad preface, unexpected frame).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Connection closed by peer via GOAWAY.
    #[error("goaway: last_stream={last_stream_id}, error={error_code}")]
    GoAway {
        /// Last stream ID the peer processed.
        last_stream_id: u32,
        /// Error code from peer.
        error_code: u32,
    },

    /// Stream reset by peer.
    #[error("stream reset: stream={stream_id}, error={error_code}")]
    StreamReset {
        /// The reset stream ID.
        stream_id: u32,
        /// Error code from peer.
        error_code: u32,
    },

    /// Invalid stream state transition.
    #[error("invalid stream state: {0}")]
    InvalidState(String),
}
