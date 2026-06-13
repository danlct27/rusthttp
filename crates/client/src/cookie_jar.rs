//! URL-scoped cookie jar — matches rquest::cookie::Jar API surface.
//!
//! Key APIs used by apple-bot:
//! - `Jar::default()` — create empty jar
//! - `jar.add_cookie_str("k=v; Domain=.apple.com; Path=/", &url)` — parse Set-Cookie string
//! - `jar.cookies(&url)` → `Option<HeaderValue>` — get "k1=v1; k2=v2" for a URL
//!
//! Domain matching follows simplified rules (suffix match on domain, prefix match on path).
//! NOT full RFC 6265 — just enough for apple.com + secure*.store.apple.com patterns.

use std::sync::Mutex;
use url::Url;
use crate::header::HeaderValue;

/// A single parsed cookie.
#[derive(Clone, Debug)]
struct Cookie {
    name: String,
    value: String,
    domain: String,       // lowercase, leading dot stripped for matching
    path: String,
    secure: bool,
    http_only: bool,
    host_only: bool,      // true = exact host match only (no Domain attr set)
}

/// Thread-safe cookie jar with URL-scoped storage.
/// Wrap in `Arc<CookieJar>` for shared ownership (same pattern as rquest).
pub struct CookieJar {
    cookies: Mutex<Vec<Cookie>>,
}

impl Default for CookieJar {
    fn default() -> Self {
        Self { cookies: Mutex::new(Vec::new()) }
    }
}

impl CookieJar {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a Set-Cookie header string and store it scoped to the given URL.
    /// Matches `rquest::cookie::Jar::add_cookie_str(raw, &url)`.
    pub fn add_cookie_str(&self, raw: &str, url: &Url) {
        if let Some(cookie) = parse_set_cookie(raw, url) {
            let mut jar = self.cookies.lock().unwrap();
            // Replace existing cookie with same name+domain+path
            jar.retain(|c| !(c.name == cookie.name && c.domain == cookie.domain && c.path == cookie.path));
            jar.push(cookie);
        }
    }

    /// Get all cookies matching a URL as a single "k1=v1; k2=v2" header value.
    /// Returns None if no cookies match.
    /// Matches `rquest::cookie::CookieStore::cookies(&url)`.
    pub fn cookies(&self, url: &Url) -> Option<HeaderValue> {
        let jar = self.cookies.lock().unwrap();
        let host = url.host_str().unwrap_or("");
        let path = if url.path().is_empty() { "/" } else { url.path() };
        let is_secure = url.scheme() == "https";

        let matching: Vec<&Cookie> = jar.iter()
            .filter(|c| {
                // Domain match
                if c.host_only {
                    // Host-only: exact match required
                    if host.to_lowercase() != c.domain {
                        return false;
                    }
                } else {
                    // Domain cookie: suffix match
                    if !domain_matches(host, &c.domain) {
                        return false;
                    }
                }
                // Path match: cookie path is prefix of request path
                if !path.starts_with(&c.path) {
                    return false;
                }
                // Secure flag
                if c.secure && !is_secure {
                    return false;
                }
                true
            })
            .collect();

        if matching.is_empty() {
            return None;
        }

        let cookie_str = matching.iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect::<Vec<_>>()
            .join("; ");

        Some(HeaderValue::from(cookie_str))
    }

    /// Clear all cookies.
    pub fn clear(&self) {
        self.cookies.lock().unwrap().clear();
    }

    /// Number of stored cookies.
    pub fn len(&self) -> usize {
        self.cookies.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Parse a Set-Cookie header string into a Cookie struct.
fn parse_set_cookie(raw: &str, url: &Url) -> Option<Cookie> {
    let parts: Vec<&str> = raw.splitn(2, ';').collect();
    let name_value = parts[0].trim();
    let (name, value) = name_value.split_once('=')?;

    let name = name.trim().to_string();
    let value = value.trim().to_string();

    if name.is_empty() {
        return None;
    }
    // Cookie size cap (4KB)
    if name.len() + value.len() > 4096 {
        return None;
    }

    let mut domain = url.host_str().unwrap_or("").to_lowercase();
    let mut path = url.path().to_string();
    if path.is_empty() { path = "/".to_string(); }
    if let Some(pos) = path.rfind('/') {
        path = path[..=pos].to_string();
    }
    let mut secure = url.scheme() == "https";
    let mut http_only = false;
    let mut host_only = true; // default: no Domain attr = host-only

    // Parse attributes
    if parts.len() > 1 {
        for attr in parts[1].split(';') {
            let attr = attr.trim().to_lowercase();
            if attr.starts_with("domain=") {
                let d = attr[7..].trim_start_matches('.');
                domain = d.to_string();
                host_only = false; // explicit Domain = NOT host-only
            } else if attr.starts_with("path=") {
                path = attr[5..].to_string();
                if path.is_empty() { path = "/".to_string(); }
            } else if attr == "secure" {
                secure = true;
            } else if attr == "httponly" {
                http_only = true;
            }
        }
    }

    Some(Cookie { name, value, domain, path, secure, http_only, host_only })
}

/// Domain matching: host == domain, or host ends with "."+domain.
fn domain_matches(host: &str, cookie_domain: &str) -> bool {
    let h = host.to_lowercase();
    let d = cookie_domain.to_lowercase();
    h == d || h.ends_with(&format!(".{}", d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_add_and_get() {
        let jar = CookieJar::new();
        let url = "https://www.apple.com/shop".parse::<Url>().unwrap();
        jar.add_cookie_str("as_dc=ucp5", &url);

        let cookies = jar.cookies(&url);
        assert!(cookies.is_some());
        assert_eq!(cookies.unwrap().to_str().unwrap(), "as_dc=ucp5");
    }

    #[test]
    fn test_domain_scoping() {
        let jar = CookieJar::new();
        let www = "https://www.apple.com/".parse::<Url>().unwrap();
        let secure = "https://secure6.store.apple.com/".parse::<Url>().unwrap();

        jar.add_cookie_str("test=1; Domain=.apple.com", &www);
        // Should match www.apple.com (subdomain of apple.com)
        assert!(jar.cookies(&www).is_some());
        // Should also match secure6.store.apple.com (subdomain of apple.com)
        assert!(jar.cookies(&secure).is_some());

        // Cookie scoped to only www.apple.com (no Domain attr = host-only)
        jar.add_cookie_str("hostonly=1", &www);
        // host-only cookie for www.apple.com should NOT match store subdomain
        let store = "https://store.apple.com/".parse::<Url>().unwrap();
        let store_cookies = jar.cookies(&store).unwrap();
        let s = store_cookies.to_str().unwrap();
        assert!(!s.contains("hostonly=1"));
    }

    #[test]
    fn test_multiple_cookies_one_domain() {
        let jar = CookieJar::new();
        let url = "https://www.apple.com/shop".parse::<Url>().unwrap();
        jar.add_cookie_str("a=1", &url);
        jar.add_cookie_str("b=2", &url);
        jar.add_cookie_str("c=3", &url);

        let cookies = jar.cookies(&url).unwrap();
        let s = cookies.to_str().unwrap();
        assert!(s.contains("a=1"));
        assert!(s.contains("b=2"));
        assert!(s.contains("c=3"));
    }

    #[test]
    fn test_replace_existing_cookie() {
        let jar = CookieJar::new();
        let url = "https://www.apple.com/".parse::<Url>().unwrap();
        jar.add_cookie_str("token=old", &url);
        jar.add_cookie_str("token=new", &url);

        let cookies = jar.cookies(&url).unwrap();
        assert_eq!(cookies.to_str().unwrap(), "token=new");
        assert_eq!(jar.len(), 1);
    }

    #[test]
    fn test_path_scoping() {
        let jar = CookieJar::new();
        let shop_url = "https://www.apple.com/shop/cart".parse::<Url>().unwrap();
        jar.add_cookie_str("cart=abc; Path=/shop", &shop_url);

        // Should match /shop/anything
        let match_url = "https://www.apple.com/shop/checkout".parse::<Url>().unwrap();
        assert!(jar.cookies(&match_url).is_some());

        // Should NOT match /other
        let no_match = "https://www.apple.com/other".parse::<Url>().unwrap();
        assert!(jar.cookies(&no_match).is_none());
    }

    #[test]
    fn test_secure_flag() {
        let jar = CookieJar::new();
        let https = "https://www.apple.com/".parse::<Url>().unwrap();
        jar.add_cookie_str("sec=1; Secure", &https);

        // Available over https
        assert!(jar.cookies(&https).is_some());

        // Not available over http
        let http = "http://www.apple.com/".parse::<Url>().unwrap();
        assert!(jar.cookies(&http).is_none());
    }

    #[test]
    fn test_oversized_cookie_rejected() {
        let jar = CookieJar::new();
        let url = "https://www.apple.com/".parse::<Url>().unwrap();
        let big_value = "x".repeat(5000);
        jar.add_cookie_str(&format!("big={}", big_value), &url);
        assert!(jar.cookies(&url).is_none());
    }
}
