//! Adversarial Tests — Malformed Input Handling
//!
//! These tests verify the H2 parser and HPACK decoder handle malicious/malformed
//! input gracefully (return errors, never panic).

use bytes::{Bytes, BytesMut};
use rusthttp_h2::frame::{Frame, FrameHeader};
use rusthttp_h2::hpack::{HpackDecoder, StandardDecoder};

// --- Frame Parsing Adversarial Tests ---

/// Malformed: SETTINGS frame with payload not multiple of 6
#[test]
fn adversarial_settings_bad_length() {
    let header = FrameHeader {
        length: 7, // not multiple of 6
        frame_type: 0x04,
        flags: 0x00,
        stream_id: 0,
    };
    let payload = Bytes::from(vec![0u8; 7]);
    let result = Frame::decode(header, payload);
    assert!(result.is_err());
}

/// Malformed: WINDOW_UPDATE with 0 increment (protocol error per RFC 9113 §6.9)
#[test]
fn adversarial_window_update_zero_increment() {
    let header = FrameHeader {
        length: 4,
        frame_type: 0x08,
        flags: 0x00,
        stream_id: 1,
    };
    let payload = Bytes::from(vec![0x00, 0x00, 0x00, 0x00]);
    let result = Frame::decode(header, payload);
    assert!(result.is_err());
}

/// Malformed: RST_STREAM too short (< 4 bytes)
#[test]
fn adversarial_rst_stream_short() {
    let header = FrameHeader {
        length: 2,
        frame_type: 0x03,
        flags: 0x00,
        stream_id: 1,
    };
    let payload = Bytes::from(vec![0x00, 0x01]);
    let result = Frame::decode(header, payload);
    assert!(result.is_err());
}

/// Malformed: GOAWAY too short (< 8 bytes)
#[test]
fn adversarial_goaway_short() {
    let header = FrameHeader {
        length: 4,
        frame_type: 0x07,
        flags: 0x00,
        stream_id: 0,
    };
    let payload = Bytes::from(vec![0x00; 4]);
    let result = Frame::decode(header, payload);
    assert!(result.is_err());
}

/// Malformed: PING too short (< 8 bytes)
#[test]
fn adversarial_ping_short() {
    let header = FrameHeader {
        length: 3,
        frame_type: 0x06,
        flags: 0x00,
        stream_id: 0,
    };
    let payload = Bytes::from(vec![0x01, 0x02, 0x03]);
    let result = Frame::decode(header, payload);
    assert!(result.is_err());
}

/// Malformed: HEADERS with PRIORITY flag but payload < 5 bytes
#[test]
fn adversarial_headers_priority_short() {
    let header = FrameHeader {
        length: 3,
        frame_type: 0x01,
        flags: 0x20, // FLAG_PRIORITY
        stream_id: 1,
    };
    let payload = Bytes::from(vec![0x00, 0x01, 0x02]);
    let result = Frame::decode(header, payload);
    assert!(result.is_err());
}

/// Malformed: PRIORITY frame too short (< 5 bytes)
#[test]
fn adversarial_priority_short() {
    let header = FrameHeader {
        length: 2,
        frame_type: 0x02,
        flags: 0x00,
        stream_id: 1,
    };
    let payload = Bytes::from(vec![0x00, 0x01]);
    let result = Frame::decode(header, payload);
    assert!(result.is_err());
}

/// Unknown frame type — should not panic, returns Unknown variant
#[test]
fn adversarial_unknown_frame_type() {
    let header = FrameHeader {
        length: 5,
        frame_type: 0xFF,
        flags: 0x00,
        stream_id: 99,
    };
    let payload = Bytes::from(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00]);
    let result = Frame::decode(header, payload);
    assert!(result.is_ok());
    match result.unwrap() {
        Frame::Unknown { header: h, .. } => assert_eq!(h.stream_id, 99),
        _ => panic!("expected Unknown variant"),
    }
}

/// Empty DATA frame (0 payload) — should not panic
#[test]
fn adversarial_empty_data_frame() {
    let header = FrameHeader {
        length: 0,
        frame_type: 0x00,
        flags: 0x01, // END_STREAM
        stream_id: 1,
    };
    let payload = Bytes::new();
    let result = Frame::decode(header, payload);
    assert!(result.is_ok());
}

// --- HPACK Adversarial Tests ---

/// HPACK: Invalid dynamic table index (way out of range)
#[test]
fn adversarial_hpack_invalid_index() {
    let mut decoder = StandardDecoder::new(4096);
    // 0xFF = indexed header, index = 127 (way beyond static + empty dynamic table)
    let data = vec![0xFF, 0x00]; // index 127
    let result = decoder.decode(&data);
    assert!(result.is_err());
}

/// HPACK: Index 0 (explicitly invalid per RFC 7541)
#[test]
fn adversarial_hpack_index_zero() {
    let mut decoder = StandardDecoder::new(4096);
    let data = vec![0x80]; // indexed, value = 0
    let result = decoder.decode(&data);
    assert!(result.is_err());
}

/// HPACK: Truncated string (length says 100 but only 5 bytes available)
#[test]
fn adversarial_hpack_truncated_string() {
    let mut decoder = StandardDecoder::new(4096);
    // Literal with incremental indexing, new name
    // 0x40 = literal incremental, index 0 (new name)
    // Then string length 100 but only 5 bytes follow
    let mut data = vec![0x40];
    data.push(100); // string length = 100
    data.extend_from_slice(&[0x61; 5]); // only 5 bytes of 'a'
    let result = decoder.decode(&data);
    assert!(result.is_err());
}

/// HPACK: Integer overflow in length prefix
#[test]
fn adversarial_hpack_integer_overflow() {
    let mut decoder = StandardDecoder::new(4096);
    // Indexed header with huge integer (many continuation bytes)
    let mut data = vec![0xFF]; // prefix = 127, needs continuation
    for _ in 0..10 {
        data.push(0xFF); // continuation bytes all max
    }
    data.push(0x01); // final byte
    let result = decoder.decode(&data);
    // Should either error (overflow) or return invalid index error — never panic
    assert!(result.is_err());
}

/// HPACK: Empty input — should return empty headers, not panic
#[test]
fn adversarial_hpack_empty_input() {
    let mut decoder = StandardDecoder::new(4096);
    let result = decoder.decode(&[]);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

/// HPACK: Huffman encoded with invalid padding (not all 1s)
#[test]
fn adversarial_hpack_bad_huffman_padding() {
    let mut decoder = StandardDecoder::new(4096);
    // Literal without indexing, index 1 (:authority), huffman-encoded value
    // 0x01 = literal no-index, name index 1
    // Then huffman string with bad padding
    let data = vec![
        0x01,       // literal no-index, name index 1
        0x83,       // string length 3, huffman=true (0x80 | 3)
        0x00, 0x00, 0x00, // all zeros — invalid huffman (padding should be 1s)
    ];
    let result = decoder.decode(&data);
    assert!(result.is_err());
}

/// Frame header encode/decode roundtrip with max values
#[test]
fn adversarial_frame_header_max_values() {
    let header = FrameHeader {
        length: 0x00FFFFFF, // max 24-bit
        frame_type: 0xFF,
        flags: 0xFF,
        stream_id: 0x7FFFFFFF, // max 31-bit
    };
    let mut buf = BytesMut::with_capacity(9);
    header.encode(&mut buf);
    let decoded = FrameHeader::decode(&buf[..9].try_into().unwrap());
    assert_eq!(decoded.length, 0x00FFFFFF);
    assert_eq!(decoded.frame_type, 0xFF);
    assert_eq!(decoded.flags, 0xFF);
    assert_eq!(decoded.stream_id, 0x7FFFFFFF);
}
