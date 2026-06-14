//! rusthttp — Lightweight Rust HTTP client with Chrome TLS/HTTP2 fingerprint parity.

pub mod header;
pub mod cookie_jar;

use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::net::TcpStream;
use url::Url;

pub use rusthttp_h2 as h2;
pub use rusthttp_proxy as proxy;
pub use rusthttp_tls as tls;

pub use header::{HeaderMap, HeaderName, HeaderValue, header_name};
pub use cookie_jar::CookieJar;

use h2::connection::Connection;
use h2::hpack::{ChromeEncoder, StandardDecoder};
use proxy::{establish_tunnel, ProxyConfig};
use tls::{TlsConnector, TlsProfile};

// Pool entry: H2 connection + HPACK state for a single host:port
type TlsStream = tokio_boring::SslStream<TcpStream>;
struct PooledConn {
    conn: Connection<TlsStream>,
    encoder: ChromeEncoder,
    decoder: StandardDecoder,
}

/// Errors from the client layer.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("tls: {0}")]
    Tls(#[from] tls::TlsError),
    #[error("h2: {0}")]
    H2(#[from] h2::H2Error),
    #[error("proxy: {0}")]
    Proxy(#[from] proxy::ProxyError),
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// HTTP status code wrapper with helper methods (matches rquest API).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCode(pub u16);

impl StatusCode {
    /// Check if status is 2xx (success).
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.0)
    }

    /// Check if status is 3xx (redirect).
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.0)
    }

    /// Check if status is 4xx (client error).
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.0)
    }

    /// Check if status is 5xx (server error).
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.0)
    }

    /// Get the raw status code value.
    pub fn as_u16(&self) -> u16 {
        self.0
    }
}

impl std::fmt::Display for StatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq<u16> for StatusCode {
    fn eq(&self, other: &u16) -> bool {
        self.0 == *other
    }
}

impl PartialOrd<u16> for StatusCode {
    fn partial_cmp(&self, other: &u16) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

/// HTTP response.
pub struct Response {
    /// HTTP status code.
    pub status_code: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Bytes,
}

impl Response {
    /// Get the HTTP status code.
    pub fn status(&self) -> StatusCode {
        StatusCode(self.status_code)
    }

    /// Get all response headers as a slice.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// Get the response body as bytes.
    pub fn bytes(&self) -> &Bytes {
        &self.body
    }

    /// Get the response body as UTF-8 text (auto-decompresses).
    /// Compatible with rquest's `.text().await?` pattern (just remove .await).
    pub fn text(&self) -> Result<String, ClientError> {
        let bytes = self.decompress_body()?;
        String::from_utf8(bytes)
            .map_err(|e| ClientError::InvalidUrl(format!("utf8 error: {}", e)))
    }

    /// Deserialize the response body as JSON.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, ClientError> {
        let decompressed = self.decompress_body()?;
        serde_json::from_slice(&decompressed)
            .map_err(|e| ClientError::InvalidUrl(format!("json parse error: {}", e)))
    }

    /// Get the decompressed body (handles gzip, deflate, br).
    pub fn body_decompressed(&self) -> Result<Vec<u8>, ClientError> {
        self.decompress_body()
    }

    /// Get a header value by name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }

    /// Get all values for a header name (case-insensitive).
    pub fn headers_all(&self, name: &str) -> Vec<&str> {
        let lower = name.to_lowercase();
        self.headers
            .iter()
            .filter(|(k, _)| k.to_lowercase() == lower)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    fn decompress_body(&self) -> Result<Vec<u8>, ClientError> {
        let encoding = self.header("content-encoding").unwrap_or("");
        match encoding {
            "gzip" | "x-gzip" => {
                use flate2::read::GzDecoder;
                use std::io::Read;
                let mut decoder = GzDecoder::new(&self.body[..]);
                let mut out = Vec::new();
                decoder.read_to_end(&mut out)
                    .map_err(|e| ClientError::Io(e))?;
                Ok(out)
            }
            "deflate" => {
                use flate2::read::DeflateDecoder;
                use std::io::Read;
                let mut decoder = DeflateDecoder::new(&self.body[..]);
                let mut out = Vec::new();
                decoder.read_to_end(&mut out)
                    .map_err(|e| ClientError::Io(e))?;
                Ok(out)
            }
            "br" => {
                use std::io::Read;
                let mut decoder = brotli::Decompressor::new(&self.body[..], 4096);
                let mut out = Vec::new();
                decoder.read_to_end(&mut out)
                    .map_err(|e| ClientError::Io(e))?;
                Ok(out)
            }
            _ => Ok(self.body.to_vec()),
        }
    }
}

/// HTTP client with Chrome fingerprint parity.
pub struct Client {
    tls: TlsConnector,
    proxy: Option<ProxyConfig>,
    hpack_table_size: usize,
    /// Legacy simple cookie jar (used when no Arc<CookieJar> provided)
    cookies: Mutex<HashMap<String, Vec<(String, String)>>>,
    /// URL-scoped cookie jar (preferred — compatible with rquest::cookie::Jar)
    cookie_jar: Option<Arc<CookieJar>>,
    /// Connection pool: key = "host:port", reuses H2 connections
    pool: tokio::sync::Mutex<HashMap<String, PooledConn>>,
    /// Max redirects to follow (0 = disabled)
    max_redirects: u8,
    /// Request timeout
    timeout: Option<Duration>,
    /// Default headers applied to every request
    default_headers: HeaderMap,
    /// Default HTTP headers (from profile or hardcoded Chrome defaults)
    user_agent: String,
    sec_ch_ua: String,
    sec_ch_ua_mobile: String,
    sec_ch_ua_platform: String,
    accept: String,
    accept_language: String,
    accept_encoding: String,
}

impl Client {
    /// Create a new ClientBuilder.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Access the shared cookie jar (if configured via .cookie_provider()).
    pub fn cookie_jar(&self) -> Option<&Arc<CookieJar>> {
        self.cookie_jar.as_ref()
    }

    /// Send a GET request.
    pub fn get(&self, url: &str) -> RequestBuilder<'_> {
        RequestBuilder {
            client: self,
            method: "GET".into(),
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// Send a POST request.
    pub fn post(&self, url: &str) -> RequestBuilder<'_> {
        RequestBuilder {
            client: self,
            method: "POST".into(),
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// Send a PUT request.
    pub fn put(&self, url: &str) -> RequestBuilder<'_> {
        RequestBuilder {
            client: self,
            method: "PUT".into(),
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// Send a DELETE request.
    pub fn delete(&self, url: &str) -> RequestBuilder<'_> {
        RequestBuilder {
            client: self,
            method: "DELETE".into(),
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// Send a HEAD request.
    pub fn head(&self, url: &str) -> RequestBuilder<'_> {
        RequestBuilder {
            client: self,
            method: "HEAD".into(),
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }
}

/// Builder for configuring a Client.
#[derive(Default)]
pub struct ClientBuilder {
    profile: Option<TlsProfile>,
    proxy_url: Option<String>,
    proxy_auth: Option<(String, String)>,
    danger_accept_invalid_certs: bool,
    max_redirects: u8,
    default_headers: Option<HeaderMap>,
    cookie_jar: Option<Arc<CookieJar>>,
    timeout: Option<Duration>,
}

impl ClientBuilder {
    /// Use Chrome 149 TLS/HTTP2 fingerprint.
    pub fn chrome(mut self) -> Self {
        self.profile = Some(TlsProfile::chrome149());
        self.max_redirects = 10;
        self
    }

    /// Use a custom TLS profile.
    pub fn tls_profile(mut self, profile: TlsProfile) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Set an HTTP CONNECT proxy.
    pub fn proxy(mut self, url: &str) -> Self {
        self.proxy_url = Some(url.to_string());
        self
    }

    /// Set proxy authentication credentials.
    pub fn proxy_auth(mut self, user: &str, pass: &str) -> Self {
        self.proxy_auth = Some((user.to_string(), pass.to_string()));
        self
    }

    /// Skip TLS certificate verification (dangerous).
    pub fn danger_accept_invalid_certs(mut self) -> Self {
        self.danger_accept_invalid_certs = true;
        self
    }

    /// Set default headers applied to every request (same as rquest's .default_headers()).
    pub fn default_headers(mut self, headers: HeaderMap) -> Self {
        self.default_headers = Some(headers);
        self
    }

    /// Set a shared cookie jar (same pattern as rquest's .cookie_provider(Arc<Jar>)).
    pub fn cookie_provider(mut self, jar: Arc<CookieJar>) -> Self {
        self.cookie_jar = Some(jar);
        self
    }

    /// Set request timeout.
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = Some(duration);
        self
    }

    /// Enable gzip decompression (already always supported, this is for API compat).
    pub fn gzip(self, _enable: bool) -> Self {
        self // decompression is always on via accept-encoding
    }

    /// Enable brotli decompression (already always supported, this is for API compat).
    pub fn brotli(self, _enable: bool) -> Self {
        self // decompression is always on via accept-encoding
    }

    /// Disable redirect following (for 302 detection patterns).
    pub fn no_redirect(mut self) -> Self {
        self.max_redirects = 0;
        self
    }

    /// Build the Client.
    pub fn build(self) -> Result<Client, ClientError> {
        let profile = self.profile.unwrap_or_else(TlsProfile::chrome149);
        let table_size = h2::chrome::HEADER_TABLE_SIZE as usize;

        let mut connector = TlsConnector::new(profile);
        if self.danger_accept_invalid_certs {
            connector = connector.danger_accept_invalid_certs();
        }

        let proxy = self.proxy_url.map(|url| ProxyConfig {
            url,
            auth: self.proxy_auth,
        });

        Ok(Client {
            tls: connector,
            proxy,
            hpack_table_size: table_size,
            cookies: Mutex::new(HashMap::new()),
            cookie_jar: self.cookie_jar,
            pool: tokio::sync::Mutex::new(HashMap::new()),
            max_redirects: self.max_redirects,
            timeout: self.timeout,
            default_headers: self.default_headers.unwrap_or_default(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36".into(),
            sec_ch_ua: r#""Chromium";v="149", "Google Chrome";v="149", "Not:A-Brand";v="99""#.into(),
            sec_ch_ua_mobile: "?0".into(),
            sec_ch_ua_platform: r#""Windows""#.into(),
            accept: "*/*".into(),
            accept_language: "en-US,en;q=0.9".into(),
            accept_encoding: "gzip, deflate, br".into(),
        })
    }
}

impl Default for Client {
    fn default() -> Self {
        Client::builder().chrome().build().expect("default client build failed")
    }
}

/// A request being built.
pub struct RequestBuilder<'a> {
    client: &'a Client,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

impl<'a> RequestBuilder<'a> {
    /// Add a single header.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Add multiple headers from a HeaderMap (same as rquest's .headers(map)).
    pub fn headers(mut self, map: HeaderMap) -> Self {
        for (k, v) in map.iter() {
            self.headers.push((k.as_str().to_string(), v.to_str().unwrap_or("").to_string()));
        }
        self
    }

    /// Set the request body (accepts String, Vec<u8>, &[u8], etc).
    pub fn body(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.body = Some(data.into());
        self
    }

    /// Set a JSON request body (sets content-type automatically).
    /// Panics if serialization fails (matching rquest's infallible API).
    pub fn json<T: serde::Serialize>(mut self, value: &T) -> Self {
        let body = serde_json::to_vec(value)
            .expect("json serialize failed");
        self.headers.push(("content-type".to_string(), "application/json".to_string()));
        self.body = Some(body);
        self
    }

    /// Send the request and return the response.
    pub async fn send(self) -> Result<Response, ClientError> {
        let mut current_url = self.url.clone();
        let mut redirects = 0u8;
        let mut method = self.method.clone();

        loop {
            let resp = self.execute_single_with_method(&current_url, &method).await?;

            // Follow redirects (301, 302, 303, 307, 308)
            if self.client.max_redirects > 0
                && redirects < self.client.max_redirects
                && matches!(resp.status_code, 301 | 302 | 303 | 307 | 308)
            {
                if let Some(location) = resp.header("location") {
                    // Resolve relative URLs
                    let base = Url::parse(&current_url)
                        .map_err(|e| ClientError::InvalidUrl(e.to_string()))?;
                    let next = base.join(location)
                        .map_err(|e| ClientError::InvalidUrl(e.to_string()))?;
                    current_url = next.to_string();
                    redirects += 1;
                    // RFC 7231: 301/302/303 → change method to GET, drop body
                    // 307/308 → preserve method and body
                    if matches!(resp.status_code, 301 | 302 | 303) {
                        method = "GET".into();
                    }
                    continue;
                }
            }

            return Ok(resp);
        }
    }

    /// Execute a single request (no redirect following).
    async fn execute_single_with_method(&self, url_str: &str, method: &str) -> Result<Response, ClientError> {
        let url = Url::parse(url_str)
            .map_err(|e| ClientError::InvalidUrl(format!("{}: {}", url_str, e)))?;

        let host = url.host_str()
            .ok_or_else(|| ClientError::InvalidUrl("missing host".into()))?;
        let port = url.port_or_known_default().unwrap_or(443);
        let pool_key = format!("{}:{}", host, port);

        // Try to get a pooled connection
        let mut pooled = self.client.pool.lock().await.remove(&pool_key);

        // Step 4: Build headers (before connection — no borrow issues)
        let path = match url.query() {
            Some(q) => format!("{}?{}", if url.path().is_empty() { "/" } else { url.path() }, q),
            None => (if url.path().is_empty() { "/" } else { url.path() }).to_string(),
        };
        let authority = if port == 443 {
            host.to_string()
        } else {
            format!("{}:{}", host, port)
        };

        let mut h2_headers: Vec<(String, String)> = vec![
            (":method".into(), method.to_string()),
            (":authority".into(), authority),
            (":scheme".into(), "https".into()),
            (":path".into(), path.clone()),
        ];

        // Add default headers Chrome sends (from client profile)
        if !self.headers.iter().any(|(k, _)| k.to_lowercase() == "user-agent") {
            h2_headers.push(("user-agent".into(), self.client.user_agent.clone()));
        }
        if !self.headers.iter().any(|(k, _)| k.to_lowercase() == "accept") {
            h2_headers.push(("accept".into(), self.client.accept.clone()));
        }
        if !self.headers.iter().any(|(k, _)| k.to_lowercase() == "accept-encoding") {
            h2_headers.push(("accept-encoding".into(), self.client.accept_encoding.clone()));
        }
        if !self.headers.iter().any(|(k, _)| k.to_lowercase() == "accept-language") {
            h2_headers.push(("accept-language".into(), self.client.accept_language.clone()));
        }

        // Chrome Client Hints (sec-ch-ua) — required by Cloudflare/DataDome
        if !self.headers.iter().any(|(k, _)| k.to_lowercase() == "sec-ch-ua") {
            h2_headers.push(("sec-ch-ua".into(), self.client.sec_ch_ua.clone()));
            h2_headers.push(("sec-ch-ua-mobile".into(), self.client.sec_ch_ua_mobile.clone()));
            h2_headers.push(("sec-ch-ua-platform".into(), self.client.sec_ch_ua_platform.clone()));
        }

        // sec-fetch headers — Chrome always sends these
        if !self.headers.iter().any(|(k, _)| k.to_lowercase() == "sec-fetch-site") {
            h2_headers.push(("sec-fetch-site".into(), "none".into()));
            h2_headers.push(("sec-fetch-mode".into(), "navigate".into()));
            h2_headers.push(("sec-fetch-user".into(), "?1".into()));
            h2_headers.push(("sec-fetch-dest".into(), "document".into()));
        }

        // Cookie jar — inject stored cookies for this domain
        if let Some(ref jar) = self.client.cookie_jar {
            // Use the new URL-scoped cookie jar
            if let Some(cookie_val) = jar.cookies(&url) {
                h2_headers.push(("cookie".into(), cookie_val.to_str().unwrap_or("").to_string()));
            }
        } else if let Ok(jar) = self.client.cookies.lock() {
            // Legacy fallback: simple domain-keyed jar
            if let Some(domain_cookies) = jar.get(host) {
                if !domain_cookies.is_empty() {
                    let cookie_str: String = domain_cookies.iter()
                        .map(|(n, v)| format!("{}={}", n, v))
                        .collect::<Vec<_>>()
                        .join("; ");
                    h2_headers.push(("cookie".into(), cookie_str));
                }
            }
        }

        // Default headers from ClientBuilder.default_headers()
        for (k, v) in self.client.default_headers.iter() {
            let name = k.as_str().to_lowercase();
            if !h2_headers.iter().any(|(h, _)| h.to_lowercase() == name)
                && !self.headers.iter().any(|(h, _)| h.to_lowercase() == name)
            {
                h2_headers.push((k.as_str().to_string(), v.to_str().unwrap_or("").to_string()));
            }
        }

        // Append user-provided headers
        for (k, v) in &self.headers {
            h2_headers.push((k.clone(), v.clone()));
        }

        // Step 5: Send request via H2 — reuse pooled connection or create new
        let body_to_send = if method == "GET" || method == "HEAD" {
            None
        } else {
            self.body.as_deref()
        };

        // Try pooled connection first, fallback to new on error
        let (h2_resp, mut entry) = if let Some(mut entry) = pooled {
            match entry.conn.send_request(&h2_headers, body_to_send, &mut entry.encoder, &mut entry.decoder).await {
                Ok(resp) => (resp, entry),
                Err(_) => {
                    // Pooled conn stale/dead — create fresh
                    let entry = self.new_connection(host, port).await?;
                    let mut e = entry;
                    let resp = e.conn.send_request(&h2_headers, body_to_send, &mut e.encoder, &mut e.decoder).await?;
                    (resp, e)
                }
            }
        } else {
            let mut entry = self.new_connection(host, port).await?;
            let resp = entry.conn.send_request(&h2_headers, body_to_send, &mut entry.encoder, &mut entry.decoder).await?;
            (resp, entry)
        };

        // Return connection to pool for reuse
        self.client.pool.lock().await.insert(pool_key, entry);

        // Step 6: Parse status from response headers
        let status_code = h2_resp.headers.iter()
            .find(|(k, _)| k == ":status")
            .and_then(|(_, v)| v.parse::<u16>().ok())
            .unwrap_or(0);

        let headers: Vec<(String, String)> = h2_resp.headers.into_iter()
            .filter(|(k, _)| !k.starts_with(':'))
            .collect();

        // Store set-cookie headers in jar (cap individual cookie size at 4KB)
        if let Some(ref jar) = self.client.cookie_jar {
            for (k, v) in &headers {
                if k.to_lowercase() == "set-cookie" {
                    jar.add_cookie_str(v, &url);
                }
            }
        } else {
            for (k, v) in &headers {
                if k.to_lowercase() == "set-cookie" {
                    if v.len() > 4096 { continue; }
                    if let Some(cookie_part) = v.split(';').next() {
                        if let Some((name, value)) = cookie_part.split_once('=') {
                            if let Ok(mut jar) = self.client.cookies.lock() {
                                jar.entry(host.to_string())
                                    .or_default()
                                    .push((name.trim().to_string(), value.trim().to_string()));
                            }
                        }
                    }
                }
            }
        }

        Ok(Response {
            status_code,
            headers,
            body: h2_resp.body,
        })
    }

    /// Create a fresh TCP → TLS → H2 connection for the given host:port.
    async fn new_connection(&self, host: &str, port: u16) -> Result<PooledConn, ClientError> {
        let tcp = if let Some(ref proxy_config) = self.client.proxy {
            establish_tunnel(proxy_config, host, port).await?
        } else {
            TcpStream::connect((host, port)).await?
        };
        let tls_stream = self.client.tls.connect(host, port, tcp).await?;
        let conn = Connection::handshake(tls_stream).await?;
        let encoder = ChromeEncoder::new(self.client.hpack_table_size);
        let decoder = StandardDecoder::new(self.client.hpack_table_size);
        Ok(PooledConn { conn, encoder, decoder })
    }
}
