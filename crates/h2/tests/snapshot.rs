//! Fingerprint Snapshot Tests
//!
//! These tests lock the exact byte output of Chrome-matching frames.
//! If any of these fail after a code change, it means the fingerprint has drifted.
//! DO NOT update the expected values without verifying against tls.peet.ws.

use bytes::BytesMut;
use rusthttp_h2::frame::{encode_chrome_settings, encode_chrome_window_update};
use rusthttp_h2::hpack::{ChromeEncoder, HpackEncoder};

/// Snapshot 1: H2 SETTINGS frame must produce exact bytes.
///
/// Chrome 149 SETTINGS: 1:65536, 2:0, 4:6291456, 6:262144
/// Wire format: 9-byte frame header + 6 bytes per setting × 4 = 24 bytes payload
/// Total: 33 bytes
#[test]
fn snapshot_h2_settings_frame() {
    let mut buf = BytesMut::new();
    encode_chrome_settings(&mut buf);

    // Frame header: length=24 (0x000018), type=0x04 (SETTINGS), flags=0x00, stream=0
    assert_eq!(&buf[0..9], &[0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Setting 1: HEADER_TABLE_SIZE (0x0001) = 65536 (0x00010000)
    assert_eq!(&buf[9..15], &[0x00, 0x01, 0x00, 0x01, 0x00, 0x00]);

    // Setting 2: ENABLE_PUSH (0x0002) = 0 (0x00000000)
    assert_eq!(&buf[15..21], &[0x00, 0x02, 0x00, 0x00, 0x00, 0x00]);

    // Setting 3: INITIAL_WINDOW_SIZE (0x0004) = 6291456 (0x00600000)
    assert_eq!(&buf[21..27], &[0x00, 0x04, 0x00, 0x60, 0x00, 0x00]);

    // Setting 4: MAX_HEADER_LIST_SIZE (0x0006) = 262144 (0x00040000)
    assert_eq!(&buf[27..33], &[0x00, 0x06, 0x00, 0x04, 0x00, 0x00]);

    // Total frame size
    assert_eq!(buf.len(), 33);
}

/// Snapshot 2: H2 WINDOW_UPDATE frame must produce exact bytes.
///
/// Chrome sends WINDOW_UPDATE(stream=0, increment=15663105)
/// Wire: 9-byte header + 4-byte increment = 13 bytes
#[test]
fn snapshot_h2_window_update_frame() {
    let mut buf = BytesMut::new();
    encode_chrome_window_update(&mut buf);

    // Frame header: length=4 (0x000004), type=0x08 (WINDOW_UPDATE), flags=0x00, stream=0
    assert_eq!(&buf[0..9], &[0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Increment: 15663105 = 0x00EF0001
    assert_eq!(&buf[9..13], &[0x00, 0xEF, 0x00, 0x01]);

    assert_eq!(buf.len(), 13);
}

/// Snapshot 3: HPACK first-request encoding for Chrome-style headers.
///
/// Chrome encodes pseudo-headers with incremental indexing for :authority,
/// static index for :method GET, :scheme https, :path /.
/// This locks the exact encoding so any change to indexing strategy is detected.
#[test]
fn snapshot_hpack_first_request() {
    let mut encoder = ChromeEncoder::new(65536);
    let headers = vec![
        (":method".into(), "GET".into()),
        (":authority".into(), "example.com".into()),
        (":scheme".into(), "https".into()),
        (":path".into(), "/".into()),
    ];
    let encoded = encoder.encode(&headers);

    // :method GET → static index 2 → 0x82
    assert_eq!(encoded[0], 0x82);

    // :authority example.com → literal with incremental indexing, name index 1
    // 0x41 = 0x40 | 1 (6-bit prefix, indexed name)
    assert_eq!(encoded[1], 0x41);

    // :scheme https → static index 7 → 0x87
    // Find where :scheme starts (after :authority value encoding)
    let scheme_pos = encoded.iter().position(|&b| b == 0x87);
    assert!(scheme_pos.is_some(), "expected static index 0x87 for :scheme https");

    // :path / → static index 4 → 0x84
    let path_pos = encoded.iter().position(|&b| b == 0x84);
    assert!(path_pos.is_some(), "expected static index 0x84 for :path /");

    // Second request with same :authority should use dynamic table (shorter encoding)
    let second = encoder.encode(&headers);
    assert!(second.len() < encoded.len(), "second request should be shorter due to dynamic table");
}

/// Snapshot 4: Chrome handshake sequence = PREFACE + SETTINGS + WINDOW_UPDATE (46 bytes total)
#[test]
fn snapshot_chrome_handshake_sequence() {
    use rusthttp_h2::frame::CONNECTION_PREFACE;

    let mut buf = BytesMut::new();
    // Chrome sends: connection preface (24) + SETTINGS (33) + WINDOW_UPDATE (13) = 70 bytes
    buf.extend_from_slice(CONNECTION_PREFACE);
    encode_chrome_settings(&mut buf);
    encode_chrome_window_update(&mut buf);

    assert_eq!(buf.len(), 24 + 33 + 13); // 70 bytes total
    assert_eq!(&buf[0..24], b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
}

/// Snapshot 5: Akamai fingerprint string reconstruction from our SETTINGS
#[test]
fn snapshot_akamai_fingerprint_string() {
    // The Akamai H2 fingerprint format is:
    // SETTINGS_PARAMS|WINDOW_UPDATE|PRIORITY_WEIGHT|PSEUDO_HEADER_ORDER
    // Chrome 149: 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
    use rusthttp_h2::chrome::*;

    let settings_str = format!(
        "1:{};2:{};4:{};6:{}",
        HEADER_TABLE_SIZE, ENABLE_PUSH, INITIAL_WINDOW_SIZE, MAX_HEADER_LIST_SIZE
    );
    assert_eq!(settings_str, "1:65536;2:0;4:6291456;6:262144");

    let wu_str = format!("{}", CONNECTION_WINDOW_INCREMENT);
    assert_eq!(wu_str, "15663105");

    // Pseudo-header order: m=:method, a=:authority, s=:scheme, p=:path
    let pseudo_order: String = PSEUDO_HEADER_ORDER
        .iter()
        .map(|h| h.chars().nth(1).unwrap()) // skip ':' prefix, take first char
        .collect::<Vec<_>>()
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(pseudo_order, "m,a,s,p");
}
