//! HPACK encoder/decoder trait interface.
//!
//! The actual implementation lives in this module but is owned by another developer.
//! This file defines the trait that `connection.rs` depends on.

use bytes::BytesMut;

/// Trait for HPACK header encoding.
pub trait HpackEncoder {
    /// Encode a list of (name, value) header pairs into an HPACK block.
    fn encode(&mut self, headers: &[(String, String)]) -> BytesMut;
}

/// Trait for HPACK header decoding.
pub trait HpackDecoder {
    /// Decode an HPACK block into a list of (name, value) header pairs.
    fn decode(&mut self, buf: &[u8]) -> Result<Vec<(String, String)>, crate::H2Error>;
}
