//! HTTP/2 frame types and serialization.
//!
//! Implements encode/decode for all frame types needed to match Chrome 149's
//! HTTP/2 fingerprint.

use bytes::{BufMut, Bytes, BytesMut};

use crate::H2Error;

/// HTTP/2 connection preface (client must send first).
pub const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Size of the frame header in bytes.
pub const FRAME_HEADER_SIZE: usize = 9;

// Frame type constants
const TYPE_DATA: u8 = 0x0;
const TYPE_HEADERS: u8 = 0x1;
const TYPE_PRIORITY: u8 = 0x2;
const TYPE_RST_STREAM: u8 = 0x3;
const TYPE_SETTINGS: u8 = 0x4;
const TYPE_PING: u8 = 0x6;
const TYPE_GOAWAY: u8 = 0x7;
const TYPE_WINDOW_UPDATE: u8 = 0x8;

// Flag constants
/// END_STREAM flag for HEADERS/DATA frames.
pub const FLAG_END_STREAM: u8 = 0x1;
/// ACK flag for SETTINGS/PING frames.
pub const FLAG_ACK: u8 = 0x1;
/// END_HEADERS flag for HEADERS frames.
pub const FLAG_END_HEADERS: u8 = 0x4;
/// PRIORITY flag for HEADERS frames.
pub const FLAG_PRIORITY: u8 = 0x20;

// SETTINGS identifiers
const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
const SETTINGS_ENABLE_PUSH: u16 = 0x2;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;

/// 9-byte HTTP/2 frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Payload length (24-bit).
    pub length: u32,
    /// Frame type byte.
    pub frame_type: u8,
    /// Flags byte.
    pub flags: u8,
    /// Stream identifier (31-bit).
    pub stream_id: u32,
}

impl FrameHeader {
    /// Encode frame header into buffer (9 bytes).
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((self.length >> 16) as u8);
        buf.put_u8((self.length >> 8) as u8);
        buf.put_u8(self.length as u8);
        buf.put_u8(self.frame_type);
        buf.put_u8(self.flags);
        buf.put_u32(self.stream_id & 0x7FFF_FFFF);
    }

    /// Decode frame header from 9 bytes.
    pub fn decode(buf: &[u8; 9]) -> Self {
        let length = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
        Self {
            length,
            frame_type: buf[3],
            flags: buf[4],
            stream_id: u32::from_be_bytes([buf[5] & 0x7F, buf[6], buf[7], buf[8]]),
        }
    }
}

/// Parsed HTTP/2 frame.
#[derive(Debug, Clone)]
pub enum Frame {
    /// DATA frame (type 0x0).
    Data {
        /// Stream ID.
        stream_id: u32,
        /// Whether END_STREAM is set.
        end_stream: bool,
        /// Payload bytes.
        payload: Bytes,
    },
    /// HEADERS frame (type 0x1).
    Headers {
        /// Stream ID.
        stream_id: u32,
        /// Whether END_STREAM is set.
        end_stream: bool,
        /// Whether END_HEADERS is set.
        end_headers: bool,
        /// HPACK-encoded header block fragment.
        payload: Bytes,
    },
    /// PRIORITY frame (type 0x2).
    Priority {
        /// Stream ID.
        stream_id: u32,
        /// Exclusive dependency flag.
        exclusive: bool,
        /// Stream dependency.
        dependency: u32,
        /// Weight (1-256).
        weight: u16,
    },
    /// RST_STREAM frame (type 0x3).
    RstStream {
        /// Stream ID.
        stream_id: u32,
        /// Error code.
        error_code: u32,
    },
    /// SETTINGS frame (type 0x4).
    Settings {
        /// Whether this is an ACK.
        ack: bool,
        /// List of (id, value) pairs.
        params: Vec<(u16, u32)>,
    },
    /// PING frame (type 0x6).
    Ping {
        /// Whether this is an ACK.
        ack: bool,
        /// 8 bytes of opaque data.
        payload: [u8; 8],
    },
    /// GOAWAY frame (type 0x7).
    GoAway {
        /// Last stream ID processed by sender.
        last_stream_id: u32,
        /// Error code.
        error_code: u32,
        /// Debug data.
        debug_data: Bytes,
    },
    /// WINDOW_UPDATE frame (type 0x8).
    WindowUpdate {
        /// Stream ID (0 for connection-level).
        stream_id: u32,
        /// Window size increment.
        increment: u32,
    },
    /// Unknown frame type — stored raw.
    Unknown {
        /// The frame header.
        header: FrameHeader,
        /// Raw payload.
        payload: Bytes,
    },
}

impl Frame {
    /// Parse a frame from header + payload.
    pub fn decode(header: FrameHeader, payload: Bytes) -> Result<Self, H2Error> {
        match header.frame_type {
            TYPE_DATA => Ok(Frame::Data {
                stream_id: header.stream_id,
                end_stream: header.flags & FLAG_END_STREAM != 0,
                payload,
            }),
            TYPE_HEADERS => {
                let hpack_payload = if header.flags & FLAG_PRIORITY != 0 {
                    // PRIORITY flag: first 5 bytes are stream dependency (4) + weight (1)
                    if payload.len() < 5 {
                        return Err(H2Error::Protocol(
                            "HEADERS with PRIORITY flag too short".into(),
                        ));
                    }
                    payload.slice(5..)
                } else {
                    payload
                };
                Ok(Frame::Headers {
                    stream_id: header.stream_id,
                    end_stream: header.flags & FLAG_END_STREAM != 0,
                    end_headers: header.flags & FLAG_END_HEADERS != 0,
                    payload: hpack_payload,
                })
            }
            TYPE_PRIORITY => {
                if payload.len() < 5 {
                    return Err(H2Error::Protocol("PRIORITY frame too short".into()));
                }
                let dep_word = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let exclusive = dep_word & 0x8000_0000 != 0;
                let dependency = dep_word & 0x7FFF_FFFF;
                let weight = payload[4] as u16 + 1;
                Ok(Frame::Priority {
                    stream_id: header.stream_id,
                    exclusive,
                    dependency,
                    weight,
                })
            }
            TYPE_RST_STREAM => {
                if payload.len() < 4 {
                    return Err(H2Error::Protocol("RST_STREAM frame too short".into()));
                }
                let error_code =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                Ok(Frame::RstStream {
                    stream_id: header.stream_id,
                    error_code,
                })
            }
            TYPE_SETTINGS => {
                let ack = header.flags & FLAG_ACK != 0;
                let mut params = Vec::new();
                if !ack {
                    if !payload.len().is_multiple_of(6) {
                        return Err(H2Error::Protocol(
                            "SETTINGS frame size not multiple of 6".into(),
                        ));
                    }
                    let mut i = 0;
                    while i + 6 <= payload.len() {
                        let id = u16::from_be_bytes([payload[i], payload[i + 1]]);
                        let val = u32::from_be_bytes([
                            payload[i + 2],
                            payload[i + 3],
                            payload[i + 4],
                            payload[i + 5],
                        ]);
                        params.push((id, val));
                        i += 6;
                    }
                }
                Ok(Frame::Settings { ack, params })
            }
            TYPE_PING => {
                if payload.len() < 8 {
                    return Err(H2Error::Protocol("PING frame too short".into()));
                }
                let mut data = [0u8; 8];
                data.copy_from_slice(&payload[..8]);
                Ok(Frame::Ping {
                    ack: header.flags & FLAG_ACK != 0,
                    payload: data,
                })
            }
            TYPE_GOAWAY => {
                if payload.len() < 8 {
                    return Err(H2Error::Protocol("GOAWAY frame too short".into()));
                }
                let last_stream_id = u32::from_be_bytes([
                    payload[0] & 0x7F,
                    payload[1],
                    payload[2],
                    payload[3],
                ]);
                let error_code =
                    u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                let debug_data = if payload.len() > 8 {
                    payload.slice(8..)
                } else {
                    Bytes::new()
                };
                Ok(Frame::GoAway {
                    last_stream_id,
                    error_code,
                    debug_data,
                })
            }
            TYPE_WINDOW_UPDATE => {
                if payload.len() < 4 {
                    return Err(H2Error::Protocol("WINDOW_UPDATE frame too short".into()));
                }
                let increment = u32::from_be_bytes([
                    payload[0] & 0x7F,
                    payload[1],
                    payload[2],
                    payload[3],
                ]);
                if increment == 0 {
                    return Err(H2Error::Protocol(
                        "WINDOW_UPDATE increment must be non-zero".into(),
                    ));
                }
                Ok(Frame::WindowUpdate {
                    stream_id: header.stream_id,
                    increment,
                })
            }
            _ => Ok(Frame::Unknown { header, payload }),
        }
    }

    /// Encode this frame into a buffer.
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Frame::Data {
                stream_id,
                end_stream,
                payload,
            } => {
                let flags = if *end_stream { FLAG_END_STREAM } else { 0 };
                FrameHeader {
                    length: payload.len() as u32,
                    frame_type: TYPE_DATA,
                    flags,
                    stream_id: *stream_id,
                }
                .encode(buf);
                buf.extend_from_slice(payload);
            }
            Frame::Headers {
                stream_id,
                end_stream,
                end_headers,
                payload,
            } => {
                let mut flags = 0;
                if *end_stream {
                    flags |= FLAG_END_STREAM;
                }
                if *end_headers {
                    flags |= FLAG_END_HEADERS;
                }
                FrameHeader {
                    length: payload.len() as u32,
                    frame_type: TYPE_HEADERS,
                    flags,
                    stream_id: *stream_id,
                }
                .encode(buf);
                buf.extend_from_slice(payload);
            }
            Frame::Priority {
                stream_id,
                exclusive,
                dependency,
                weight,
            } => {
                FrameHeader {
                    length: 5,
                    frame_type: TYPE_PRIORITY,
                    flags: 0,
                    stream_id: *stream_id,
                }
                .encode(buf);
                let dep = if *exclusive {
                    *dependency | 0x8000_0000
                } else {
                    *dependency
                };
                buf.put_u32(dep);
                buf.put_u8((*weight - 1) as u8);
            }
            Frame::RstStream {
                stream_id,
                error_code,
            } => {
                FrameHeader {
                    length: 4,
                    frame_type: TYPE_RST_STREAM,
                    flags: 0,
                    stream_id: *stream_id,
                }
                .encode(buf);
                buf.put_u32(*error_code);
            }
            Frame::Settings { ack, params } => {
                let flags = if *ack { FLAG_ACK } else { 0 };
                let length = if *ack { 0 } else { params.len() as u32 * 6 };
                FrameHeader {
                    length,
                    frame_type: TYPE_SETTINGS,
                    flags,
                    stream_id: 0,
                }
                .encode(buf);
                if !ack {
                    for (id, val) in params {
                        buf.put_u16(*id);
                        buf.put_u32(*val);
                    }
                }
            }
            Frame::Ping { ack, payload } => {
                let flags = if *ack { FLAG_ACK } else { 0 };
                FrameHeader {
                    length: 8,
                    frame_type: TYPE_PING,
                    flags,
                    stream_id: 0,
                }
                .encode(buf);
                buf.extend_from_slice(payload);
            }
            Frame::GoAway {
                last_stream_id,
                error_code,
                debug_data,
            } => {
                FrameHeader {
                    length: 8 + debug_data.len() as u32,
                    frame_type: TYPE_GOAWAY,
                    flags: 0,
                    stream_id: 0,
                }
                .encode(buf);
                buf.put_u32(*last_stream_id & 0x7FFF_FFFF);
                buf.put_u32(*error_code);
                buf.extend_from_slice(debug_data);
            }
            Frame::WindowUpdate {
                stream_id,
                increment,
            } => {
                FrameHeader {
                    length: 4,
                    frame_type: TYPE_WINDOW_UPDATE,
                    flags: 0,
                    stream_id: *stream_id,
                }
                .encode(buf);
                buf.put_u32(*increment & 0x7FFF_FFFF);
            }
            Frame::Unknown { header, payload } => {
                header.encode(buf);
                buf.extend_from_slice(payload);
            }
        }
    }
}

/// Encode Chrome's SETTINGS frame (exactly 4 params in fingerprint order).
pub fn encode_chrome_settings(buf: &mut BytesMut) {
    use crate::chrome::*;
    let frame = Frame::Settings {
        ack: false,
        params: vec![
            (SETTINGS_HEADER_TABLE_SIZE, HEADER_TABLE_SIZE),
            (SETTINGS_ENABLE_PUSH, ENABLE_PUSH),
            (SETTINGS_INITIAL_WINDOW_SIZE, INITIAL_WINDOW_SIZE),
            (SETTINGS_MAX_HEADER_LIST_SIZE, MAX_HEADER_LIST_SIZE),
        ],
    };
    frame.encode(buf);
}

/// Encode SETTINGS ACK frame.
pub fn encode_settings_ack(buf: &mut BytesMut) {
    let frame = Frame::Settings {
        ack: true,
        params: vec![],
    };
    frame.encode(buf);
}

/// Encode Chrome's initial WINDOW_UPDATE on stream 0.
pub fn encode_chrome_window_update(buf: &mut BytesMut) {
    let frame = Frame::WindowUpdate {
        stream_id: 0,
        increment: crate::chrome::CONNECTION_WINDOW_INCREMENT,
    };
    frame.encode(buf);
}

/// Encode a PING ACK response.
pub fn encode_ping_ack(buf: &mut BytesMut, payload: [u8; 8]) {
    let frame = Frame::Ping { ack: true, payload };
    frame.encode(buf);
}
