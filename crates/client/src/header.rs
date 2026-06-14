//! HTTP header types — thin, allocation-efficient wrappers compatible with rquest's API surface.
//!
//! Design: Vec-backed (not HashMap) to preserve insertion order — critical for fingerprinting.
//! Provides `.insert()` / `.get()` / `.from_static()` matching rquest usage patterns.

use std::fmt;

/// A header name (case-insensitive comparison, preserves original case for serialization).
#[derive(Clone, Eq)]
pub struct HeaderName(String);

impl HeaderName {
    pub fn from_static(s: &'static str) -> Self {
        Self(s.to_string())
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, InvalidHeaderName> {
        std::str::from_utf8(b)
            .map(|s| Self(s.to_lowercase()))
            .map_err(|_| InvalidHeaderName)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl PartialEq for HeaderName {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl std::hash::Hash for HeaderName {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_lowercase().hash(state);
    }
}

impl fmt::Display for HeaderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for HeaderName {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

#[derive(Debug)]
pub struct InvalidHeaderName;

/// A header value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderValue(String);

impl HeaderValue {
    pub fn from_static(s: &'static str) -> Self {
        Self(s.to_string())
    }

    pub fn from_str(s: &str) -> Result<Self, InvalidHeaderValue> {
        // HTTP header values must be visible ASCII + SP + HT
        if s.bytes().all(|b| b == b'\t' || (0x20..=0x7E).contains(&b)) {
            Ok(Self(s.to_string()))
        } else {
            Err(InvalidHeaderValue)
        }
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, InvalidHeaderValue> {
        std::str::from_utf8(b)
            .map_err(|_| InvalidHeaderValue)
            .and_then(Self::from_str)
    }

    pub fn to_str(&self) -> Result<&str, InvalidHeaderValue> {
        Ok(&self.0)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Display for HeaderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for HeaderValue {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for HeaderValue {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl std::str::FromStr for HeaderValue {
    type Err = InvalidHeaderValue;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str(s)
    }
}

#[derive(Debug)]
pub struct InvalidHeaderValue;

/// Ordered header map — preserves insertion order, last-write-wins on `.insert()`.
#[derive(Clone, Default)]
pub struct HeaderMap {
    entries: Vec<(HeaderName, HeaderValue)>,
}

impl HeaderMap {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self { entries: Vec::with_capacity(cap) }
    }

    /// Insert a header. If the name already exists, replaces the value (last-write-wins).
    /// Accepts &str, String, HeaderName, HeaderValue for convenience.
    pub fn insert(&mut self, name: impl Into<HeaderName>, value: impl Into<HeaderValue>) {
        let name = name.into();
        let value = value.into();
        if let Some(entry) = self.entries.iter_mut().find(|(k, _)| k == &name) {
            entry.1 = value;
        } else {
            self.entries.push((name, value));
        }
    }

    /// Append a header (allows duplicate names — needed for Set-Cookie etc).
    pub fn append(&mut self, name: impl Into<HeaderName>, value: impl Into<HeaderValue>) {
        self.entries.push((name.into(), value.into()));
    }

    /// Get the first value for a header name.
    pub fn get(&self, name: &str) -> Option<&HeaderValue> {
        let lower = name.to_lowercase();
        self.entries.iter()
            .find(|(k, _)| k.0.to_lowercase() == lower)
            .map(|(_, v)| v)
    }

    /// Get all values for a header name.
    pub fn get_all(&self, name: &str) -> Vec<&HeaderValue> {
        let lower = name.to_lowercase();
        self.entries.iter()
            .filter(|(k, _)| k.0.to_lowercase() == lower)
            .map(|(_, v)| v)
            .collect()
    }

    /// Check if a header name exists.
    pub fn contains_key(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Remove a header by name. Returns the removed value if it existed.
    pub fn remove(&mut self, name: impl Into<HeaderName>) -> Option<HeaderValue> {
        let name = name.into();
        let lower = name.0.to_lowercase();
        if let Some(pos) = self.entries.iter().position(|(k, _)| k.0.to_lowercase() == lower) {
            Some(self.entries.remove(pos).1)
        } else {
            None
        }
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all (name, value) pairs in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&HeaderName, &HeaderValue)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }

    /// Convert to Vec<(String, String)> for internal use.
    pub(crate) fn to_vec(&self) -> Vec<(String, String)> {
        self.entries.iter()
            .map(|(k, v)| (k.0.clone(), v.0.clone()))
            .collect()
    }
}

/// Well-known header name constants. Use with `HeaderName::from_static()` or these constants.
/// rquest pattern: `HeaderName::from_static("pragma")` — our from_static does the same.
pub mod header_name {
    pub const ACCEPT: &str = "accept";
    pub const ACCEPT_ENCODING: &str = "accept-encoding";
    pub const ACCEPT_LANGUAGE: &str = "accept-language";
    pub const CONTENT_TYPE: &str = "content-type";
    pub const COOKIE: &str = "cookie";
    pub const USER_AGENT: &str = "user-agent";
    pub const REFERER: &str = "referer";
    pub const ORIGIN: &str = "origin";
    pub const CACHE_CONTROL: &str = "cache-control";
    pub const PRAGMA: &str = "pragma";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_get() {
        let mut map = HeaderMap::new();
        map.insert(HeaderName::from_static("content-type"), HeaderValue::from_static("application/json"));
        assert_eq!(map.get("Content-Type").unwrap().to_str().unwrap(), "application/json");
    }

    #[test]
    fn test_insert_replaces() {
        let mut map = HeaderMap::new();
        map.insert(HeaderName::from_static("x-test"), HeaderValue::from_static("a"));
        map.insert(HeaderName::from_static("x-test"), HeaderValue::from_static("b"));
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("x-test").unwrap().to_str().unwrap(), "b");
    }

    #[test]
    fn test_append_duplicates() {
        let mut map = HeaderMap::new();
        map.append(HeaderName::from_static("set-cookie"), HeaderValue::from_static("a=1"));
        map.append(HeaderName::from_static("set-cookie"), HeaderValue::from_static("b=2"));
        assert_eq!(map.get_all("set-cookie").len(), 2);
    }

    #[test]
    fn test_case_insensitive() {
        let mut map = HeaderMap::new();
        map.insert(HeaderName::from_static("Content-Type"), HeaderValue::from_static("text/html"));
        assert!(map.contains_key("content-type"));
        assert!(map.contains_key("CONTENT-TYPE"));
    }

    #[test]
    fn test_preserves_order() {
        let mut map = HeaderMap::new();
        map.insert(HeaderName::from_static("pragma"), HeaderValue::from_static("no-cache"));
        map.insert(HeaderName::from_static("accept"), HeaderValue::from_static("*/*"));
        map.insert(HeaderName::from_static("user-agent"), HeaderValue::from_static("test"));
        let keys: Vec<&str> = map.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["pragma", "accept", "user-agent"]);
    }
}
