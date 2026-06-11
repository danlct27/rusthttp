//! HPACK encoder/decoder with Chrome encoding style parity (RFC 7541).

use bytes::{BufMut, BytesMut};
use crate::H2Error;

/// Trait for HPACK encoding (used by connection.rs).
pub trait HpackEncoder {
    fn encode(&mut self, headers: &[(String, String)]) -> BytesMut;
    fn set_max_table_size(&mut self, size: usize);
}

/// Trait for HPACK decoding (used by connection.rs).
pub trait HpackDecoder {
    fn decode(&mut self, data: &[u8]) -> Result<Vec<(String, String)>, H2Error>;
}

// Static Table (RFC 7541 Appendix A)
const STATIC_TABLE: &[(&str, &str)] = &[
    ("", ""), // 0: unused
    (":authority", ""), (":method", "GET"), (":method", "POST"),
    (":path", "/"), (":path", "/index.html"), (":scheme", "http"),
    (":scheme", "https"), (":status", "200"), (":status", "204"),
    (":status", "206"), (":status", "304"), (":status", "400"),
    (":status", "404"), (":status", "500"), ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"), ("accept-language", ""),
    ("accept-ranges", ""), ("accept", ""),
    ("access-control-allow-origin", ""), ("age", ""), ("allow", ""),
    ("authorization", ""), ("cache-control", ""),
    ("content-disposition", ""), ("content-encoding", ""),
    ("content-language", ""), ("content-length", ""),
    ("content-location", ""), ("content-range", ""),
    ("content-type", ""), ("cookie", ""), ("date", ""), ("etag", ""),
    ("expect", ""), ("expires", ""), ("from", ""), ("host", ""),
    ("if-match", ""), ("if-modified-since", ""), ("if-none-match", ""),
    ("if-range", ""), ("if-unmodified-since", ""), ("last-modified", ""),
    ("link", ""), ("location", ""), ("max-forwards", ""),
    ("proxy-authenticate", ""), ("proxy-authorization", ""),
    ("range", ""), ("referer", ""), ("refresh", ""),
    ("retry-after", ""), ("server", ""), ("set-cookie", ""),
    ("strict-transport-security", ""), ("transfer-encoding", ""),
    ("user-agent", ""), ("vary", ""), ("via", ""),
    ("www-authenticate", ""), // 61
];

fn static_find_exact(name: &str, value: &str) -> Option<usize> {
    STATIC_TABLE.iter().position(|(n, v)| *n == name && *v == value)
}

fn static_find_name(name: &str) -> Option<usize> {
    STATIC_TABLE.iter().position(|(n, _)| *n == name)
}

// Dynamic Table
struct DynTable {
    entries: Vec<(String, String)>,
    size: usize,
    max_size: usize,
}

impl DynTable {
    fn new(max: usize) -> Self { Self { entries: Vec::new(), size: 0, max_size: max } }

    fn insert(&mut self, name: String, value: String) {
        let sz = name.len() + value.len() + 32;
        while self.size + sz > self.max_size && !self.entries.is_empty() {
            if let Some((n, v)) = self.entries.pop() { self.size -= n.len() + v.len() + 32; }
        }
        if sz <= self.max_size {
            self.entries.insert(0, (name, value));
            self.size += sz;
        }
    }

    fn get(&self, idx: usize) -> Option<(&str, &str)> {
        self.entries.get(idx).map(|(n, v)| (n.as_str(), v.as_str()))
    }

    fn set_max(&mut self, max: usize) {
        self.max_size = max;
        while self.size > self.max_size && !self.entries.is_empty() {
            if let Some((n, v)) = self.entries.pop() { self.size -= n.len() + v.len() + 32; }
        }
    }
}

// Integer codec (RFC 7541 §5.1)
fn encode_int(buf: &mut BytesMut, mut val: usize, prefix: u8, mask: u8) {
    let max = (1usize << prefix) - 1;
    if val < max {
        buf.put_u8(mask | val as u8);
    } else {
        buf.put_u8(mask | max as u8);
        val -= max;
        while val >= 128 { buf.put_u8((val % 128 + 128) as u8); val /= 128; }
        buf.put_u8(val as u8);
    }
}

fn decode_int(data: &[u8], pos: &mut usize, prefix: u8) -> Result<(u8, usize), H2Error> {
    if *pos >= data.len() { return Err(H2Error::Hpack("unexpected eof".into())); }
    let first = data[*pos]; *pos += 1;
    let max = (1usize << prefix) - 1;
    let mut val = (first as usize) & max;
    if val < max { return Ok((first, val)); }
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() { return Err(H2Error::Hpack("unexpected eof".into())); }
        let b = data[*pos]; *pos += 1;
        val += ((b & 0x7F) as usize) << shift; shift += 7;
        if b & 0x80 == 0 { break; }
        if shift > 28 { return Err(H2Error::Hpack("integer overflow".into())); }
    }
    Ok((first, val))
}

// Huffman table (RFC 7541 Appendix B) - (code, bit_length)
#[rustfmt::skip]
const HUFF: &[(u32, u8)] = &[
(0x1ff8,13),(0x7fffd8,23),(0xfffffe2,28),(0xfffffe3,28),(0xfffffe4,28),(0xfffffe5,28),
(0xfffffe6,28),(0xfffffe7,28),(0xfffffe8,28),(0xffffea,24),(0x3ffffffc,30),(0xfffffe9,28),
(0xfffffea,28),(0x3ffffffd,30),(0xfffffeb,28),(0xfffffec,28),(0xfffffed,28),(0xfffffee,28),
(0xfffffef,28),(0xffffff0,28),(0xffffff1,28),(0xffffff2,28),(0x3ffffffe,30),(0xffffff3,28),
(0xffffff4,28),(0xffffff5,28),(0xffffff6,28),(0xffffff7,28),(0xffffff8,28),(0xffffff9,28),
(0xffffffa,28),(0xffffffb,28),(0x14,6),(0x3f8,10),(0x3f9,10),(0xffa,12),(0x1ff9,13),
(0x15,6),(0xf8,8),(0x7fa,11),(0x3fa,10),(0x3fb,10),(0xf9,8),(0x7fb,11),(0xfa,8),
(0x16,6),(0x17,6),(0x18,6),(0x0,5),(0x1,5),(0x2,5),(0x19,6),(0x1a,6),(0x1b,6),
(0x1c,6),(0x1d,6),(0x1e,6),(0x1f,6),(0x5c,7),(0xfb,8),(0x7ffc,15),(0x20,6),(0xffb,12),
(0x3fc,10),(0x1ffa,13),(0x21,6),(0x5d,7),(0x5e,7),(0x5f,7),(0x60,7),(0x61,7),(0x62,7),
(0x63,7),(0x64,7),(0x65,7),(0x66,7),(0x67,7),(0x68,7),(0x69,7),(0x6a,7),(0x6b,7),
(0x6c,7),(0x6d,7),(0x6e,7),(0x6f,7),(0x70,7),(0x71,7),(0x72,7),(0xfc,8),(0x73,7),
(0xfd,8),(0x1ffb,13),(0x7fff0,19),(0x1ffc,13),(0x3ffc,14),(0x22,6),(0x7ffd,15),(0x3,5),
(0x23,6),(0x4,5),(0x24,6),(0x5,5),(0x25,6),(0x26,6),(0x27,6),(0x6,5),(0x74,7),
(0x75,7),(0x28,6),(0x29,6),(0x2a,6),(0x7,5),(0x2b,6),(0x76,7),(0x2c,6),(0x8,5),
(0x9,5),(0x2d,6),(0x77,7),(0x78,7),(0x79,7),(0x7a,7),(0x7b,7),(0x7ffe,15),(0x7fc,11),
(0x3ffd,14),(0x1ffd,13),(0xffffffc,28),(0xfffe6,20),(0x3fffd2,22),(0xfffe7,20),(0xfffe8,20),
(0x3fffd3,22),(0x3fffd4,22),(0x3fffd5,22),(0x7fffd9,23),(0x3fffd6,22),(0x7fffda,23),
(0x7fffdb,23),(0x7fffdc,23),(0x7fffdd,23),(0x7fffde,23),(0xffffeb,24),(0x7fffdf,23),
(0xffffec,24),(0xffffed,24),(0x3fffd7,22),(0x7fffe0,23),(0xffffee,24),(0x7fffe1,23),
(0x7fffe2,23),(0x7fffe3,23),(0x7fffe4,23),(0x1fffdc,21),(0x3fffd8,22),(0x7fffe5,23),
(0x3fffd9,22),(0x7fffe6,23),(0x7fffe7,23),(0xffffef,24),(0x3fffda,22),(0x1fffdd,21),
(0xfffe9,20),(0x3fffdb,22),(0x3fffdc,22),(0x7fffe8,23),(0x7fffe9,23),(0x1fffde,21),
(0x7fffea,23),(0x3fffdd,22),(0x3fffde,22),(0xfffff0,24),(0x1fffdf,21),(0x3fffdf,22),
(0x7fffeb,23),(0x7fffec,23),(0x1fffe0,21),(0x1fffe1,21),(0x3fffe0,22),(0x1fffe2,21),
(0x7fffed,23),(0x3fffe1,22),(0x7fffee,23),(0x7fffef,23),(0xfffea,20),(0x3fffe2,22),
(0x3fffe3,22),(0x3fffe4,22),(0x7ffff0,23),(0x3fffe5,22),(0x3fffe6,22),(0x7ffff1,23),
(0x3ffffe0,26),(0x3ffffe1,26),(0xfffeb,20),(0x7fff1,19),(0x3fffe7,22),(0x7ffff2,23),
(0x3fffe8,22),(0x1ffffec,25),(0x3ffffe2,26),(0x3ffffe3,26),(0x3ffffe4,26),(0x7ffffde,27),
(0x7ffffdf,27),(0x3ffffe5,26),(0xfffff1,24),(0x1ffffed,25),(0x7fff2,19),(0x1fffe3,21),
(0x3ffffe6,26),(0x7ffffe0,27),(0x7ffffe1,27),(0x3ffffe7,26),(0x7ffffe2,27),(0xfffff2,24),
(0x1fffe4,21),(0x1fffe5,21),(0x3ffffe8,26),(0x3ffffe9,26),(0xffffffd,28),(0x7ffffe3,27),
(0x7ffffe4,27),(0x7ffffe5,27),(0xfffec,20),(0xfffff3,24),(0xfffed,20),(0x1fffe6,21),
(0x3fffe9,22),(0x1fffe7,21),(0x1fffe8,21),(0x7ffff3,23),(0x3fffea,22),(0x3fffeb,22),
(0x1ffffee,25),(0x1ffffef,25),(0xfffff4,24),(0xfffff5,24),(0x3ffffea,26),(0x7ffff4,23),
(0x3ffffeb,26),(0x7ffffe6,27),(0x3ffffec,26),(0x3ffffed,26),(0x7ffffe7,27),(0x7ffffe8,27),
(0x7ffffe9,27),(0x7ffffea,27),(0x7ffffeb,27),(0xffffffe,28),(0x7ffffec,27),(0x7ffffed,27),
(0x7ffffee,27),(0x7ffffef,27),(0x7fffff0,27),(0x3ffffee,26),
];

fn huff_encode(input: &[u8]) -> Vec<u8> {
    let mut bits: u64 = 0;
    let mut nbits: u8 = 0;
    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        let (code, len) = HUFF[b as usize];
        bits = (bits << len) | code as u64;
        nbits += len;
        while nbits >= 8 { nbits -= 8; out.push((bits >> nbits) as u8); }
    }
    if nbits > 0 {
        out.push(((bits << (8 - nbits)) | ((1u64 << (8 - nbits)) - 1)) as u8);
    }
    out
}

fn huff_decode(input: &[u8]) -> Result<Vec<u8>, H2Error> {
    // Build a simple bit-by-bit decoder
    let mut out = Vec::new();
    let mut bits: u64 = 0;
    let mut nbits: u8 = 0;
    for &byte in input {
        bits = (bits << 8) | byte as u64;
        nbits += 8;
        'sym: loop {
            if nbits < 5 { break 'sym; }
            let mut found = false;
            for (sym, &(code, len)) in HUFF.iter().enumerate().take(256) {
                if len <= nbits {
                    if (bits >> (nbits - len)) as u32 == code {
                        out.push(sym as u8);
                        nbits -= len;
                        bits &= (1u64 << nbits) - 1;
                        found = true;
                        break;
                    }
                }
            }
            if !found { break 'sym; }
        }
    }
    if nbits > 7 { return Err(H2Error::Hpack("invalid huffman padding".into())); }
    if nbits > 0 {
        let mask = (1u64 << nbits) - 1;
        if bits & mask != mask { return Err(H2Error::Hpack("invalid huffman eos padding".into())); }
    }
    Ok(out)
}

// String encode/decode
fn encode_str_huff(buf: &mut BytesMut, s: &str) {
    let enc = huff_encode(s.as_bytes());
    encode_int(buf, enc.len(), 7, 0x80);
    buf.extend_from_slice(&enc);
}

fn decode_str(data: &[u8], pos: &mut usize) -> Result<String, H2Error> {
    let (first, len) = decode_int(data, pos, 7)?;
    if *pos + len > data.len() { return Err(H2Error::Hpack("unexpected eof in string".into())); }
    let raw = &data[*pos..*pos + len];
    *pos += len;
    let bytes = if first & 0x80 != 0 { huff_decode(raw)? } else { raw.to_vec() };
    String::from_utf8(bytes).map_err(|_| H2Error::Hpack("invalid utf8".into()))
}

// Chrome: these headers use literal-without-indexing
const NO_INDEX: &[&str] = &[
    "content-type", "accept", "user-agent", "cookie",
    "accept-encoding", "accept-language", "referer", "content-length",
];

/// Chrome-style HPACK encoder.
pub struct ChromeEncoder { dyn_table: DynTable }

impl ChromeEncoder {
    /// Create encoder with given max dynamic table size.
    pub fn new(max_table_size: usize) -> Self {
        Self { dyn_table: DynTable::new(max_table_size) }
    }
}

impl HpackEncoder for ChromeEncoder {
    fn encode(&mut self, headers: &[(String, String)]) -> BytesMut {
        let mut buf = BytesMut::with_capacity(256);
        for (name, value) in headers {
            // Try exact static match → indexed
            if let Some(idx) = static_find_exact(name, value) {
                encode_int(&mut buf, idx, 7, 0x80);
                continue;
            }
            let name_idx = static_find_name(name).unwrap_or(0);
            // Chrome: no-index for variable headers
            if NO_INDEX.contains(&name.as_str()) {
                encode_int(&mut buf, name_idx, 4, 0x00);
                if name_idx == 0 { encode_str_huff(&mut buf, name); }
                encode_str_huff(&mut buf, value);
            } else {
                // Literal with indexing
                encode_int(&mut buf, name_idx, 6, 0x40);
                if name_idx == 0 { encode_str_huff(&mut buf, name); }
                encode_str_huff(&mut buf, value);
                self.dyn_table.insert(name.clone(), value.clone());
            }
        }
        buf
    }

    fn set_max_table_size(&mut self, size: usize) { self.dyn_table.set_max(size); }
}

/// Standard HPACK decoder.
pub struct StandardDecoder { dyn_table: DynTable }

impl StandardDecoder {
    /// Create decoder with given max dynamic table size.
    pub fn new(max_table_size: usize) -> Self {
        Self { dyn_table: DynTable::new(max_table_size) }
    }

    fn get_entry(&self, idx: usize) -> Result<(String, String), H2Error> {
        if idx == 0 { return Err(H2Error::Hpack("index 0 invalid".into())); }
        if idx <= 61 {
            let (n, v) = STATIC_TABLE[idx];
            Ok((n.to_string(), v.to_string()))
        } else {
            self.dyn_table.get(idx - 62)
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .ok_or_else(|| H2Error::Hpack(format!("invalid index {idx}")))
        }
    }
}

impl HpackDecoder for StandardDecoder {
    fn decode(&mut self, data: &[u8]) -> Result<Vec<(String, String)>, H2Error> {
        let mut headers = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let byte = data[pos];
            if byte & 0x80 != 0 {
                let (_, idx) = decode_int(data, &mut pos, 7)?;
                headers.push(self.get_entry(idx)?);
            } else if byte & 0x40 != 0 {
                let (_, ni) = decode_int(data, &mut pos, 6)?;
                let name = if ni > 0 { self.get_entry(ni)?.0 } else { decode_str(data, &mut pos)? };
                let value = decode_str(data, &mut pos)?;
                self.dyn_table.insert(name.clone(), value.clone());
                headers.push((name, value));
            } else if byte & 0x20 != 0 {
                let (_, sz) = decode_int(data, &mut pos, 5)?;
                self.dyn_table.set_max(sz);
            } else {
                let (_, ni) = decode_int(data, &mut pos, 4)?;
                let name = if ni > 0 { self.get_entry(ni)?.0 } else { decode_str(data, &mut pos)? };
                let value = decode_str(data, &mut pos)?;
                headers.push((name, value));
            }
        }
        Ok(headers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_roundtrip() {
        let mut buf = BytesMut::new();
        encode_int(&mut buf, 1337, 5, 0x00);
        let mut pos = 0;
        let (_, val) = decode_int(&buf, &mut pos, 5).unwrap();
        assert_eq!(val, 1337);
    }

    #[test]
    fn test_huff_roundtrip() {
        let input = b"www.example.com";
        let enc = huff_encode(input);
        let dec = huff_decode(&enc).unwrap();
        assert_eq!(dec, input);
    }

    #[test]
    fn test_encode_static_index() {
        let mut enc = ChromeEncoder::new(4096);
        let h = vec![(":method".into(), "GET".into())];
        let buf = enc.encode(&h);
        assert_eq!(buf[0], 0x82); // static index 2
    }

    #[test]
    fn test_encode_authority_with_indexing() {
        let mut enc = ChromeEncoder::new(4096);
        let h = vec![(":authority".into(), "example.com".into())];
        let buf = enc.encode(&h);
        assert_eq!(buf[0], 0x41); // literal with indexing, name idx 1
    }

    #[test]
    fn test_encode_user_agent_no_index() {
        let mut enc = ChromeEncoder::new(4096);
        let h = vec![("user-agent".into(), "Chrome".into())];
        let buf = enc.encode(&h);
        // literal without indexing, name idx 58 → 0x0f then continuation
        assert_eq!(buf[0], 0x0f);
    }

    #[test]
    fn test_roundtrip() {
        let mut enc = ChromeEncoder::new(4096);
        let mut dec = StandardDecoder::new(4096);
        let h = vec![
            (":method".into(), "GET".into()),
            (":scheme".into(), "https".into()),
            (":path".into(), "/".into()),
            (":authority".into(), "example.com".into()),
        ];
        let encoded = enc.encode(&h);
        let decoded = dec.decode(&encoded).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn test_roundtrip_no_index() {
        let mut enc = ChromeEncoder::new(4096);
        let mut dec = StandardDecoder::new(4096);
        let h = vec![
            (":method".into(), "POST".into()),
            ("content-type".into(), "application/json".into()),
            ("user-agent".into(), "Mozilla/5.0".into()),
        ];
        let encoded = enc.encode(&h);
        let decoded = dec.decode(&encoded).unwrap();
        assert_eq!(decoded, h);
    }
}
