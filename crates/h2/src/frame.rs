//! HTTP/2 frame types and serialization.

use bytes::{Buf, BufMut, Bytes, BytesMut};

/// HTTP/2 connection preface (client must send first).
pub const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const FRAME_HEADER_SIZE: usize = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    Goaway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SettingsId {
    HeaderTableSize = 0x1,
    EnablePush = 0x2,
    MaxConcurrentStreams = 0x3,
    InitialWindowSize = 0x4,
    MaxFrameSize = 0x5,
    MaxHeaderListSize = 0x6,
}

#[derive(Debug, Clone)]
pub struct FrameHeader {
    pub length: u32,
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u32,
}

impl FrameHeader {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((self.length >> 16) as u8);
        buf.put_u8((self.length >> 8) as u8);
        buf.put_u8(self.length as u8);
        buf.put_u8(self.frame_type);
        buf.put_u8(self.flags);
        buf.put_u32(self.stream_id & 0x7FFF_FFFF);
    }

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

/// Encode Chrome's SETTINGS frame (exactly 4 params, correct order).
pub fn encode_chrome_settings(buf: &mut BytesMut) {
    use super::chrome::*;
    // 4 settings × 6 bytes each = 24 bytes payload
    let header = FrameHeader {
        length: 24,
        frame_type: FrameType::Settings as u8,
        flags: 0,
        stream_id: 0,
    };
    header.encode(buf);
    // Order matters for fingerprint!
    buf.put_u16(SettingsId::HeaderTableSize as u16);
    buf.put_u32(HEADER_TABLE_SIZE);
    buf.put_u16(SettingsId::EnablePush as u16);
    buf.put_u32(ENABLE_PUSH);
    buf.put_u16(SettingsId::InitialWindowSize as u16);
    buf.put_u32(INITIAL_WINDOW_SIZE);
    buf.put_u16(SettingsId::MaxHeaderListSize as u16);
    buf.put_u32(MAX_HEADER_LIST_SIZE);
}

/// Encode Chrome's initial WINDOW_UPDATE on stream 0.
pub fn encode_chrome_window_update(buf: &mut BytesMut) {
    let header = FrameHeader {
        length: 4,
        frame_type: FrameType::WindowUpdate as u8,
        flags: 0,
        stream_id: 0,
    };
    header.encode(buf);
    buf.put_u32(super::chrome::CONNECTION_WINDOW_INCREMENT);
}
