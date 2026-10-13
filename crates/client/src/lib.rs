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

// Pool entry: H2 or H1 connection for a single host:port
type TlsStream = tokio_boring::SslStream<TcpStream>;
enum PooledConn {
    H2 {
        conn: Connection<TlsStream>,
        encoder: ChromeEncoder,
        decoder: StandardDecoder,
    },
    H1 {
        stream: TlsStream,
    },
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
    #[error("h1: {0}")]
    H1(String),
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
    pub fn status(&self) -> u16 {
        self.status_code
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
    /// Returns lossy-converted string if bytes are not valid UTF-8.
    pub fn text(&self) -> String {
        match self.decompress_body() {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(_) => String::from_utf8_lossy(&self.body).into_owned(),
        }
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
            force_http1: false,
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
            force_http1: false,
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
            force_http1: false,
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
            force_http1: false,
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
            force_http1: false,
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
    // ========== Browser Profile Shortcuts ==========
    // .browser() = latest, .browser(version) = specific

    /// Chrome TLS fingerprint. `.chrome()` = latest, `.chrome(148)` = specific.
    pub fn chrome(self, version: impl Into<Option<u32>>) -> Self {
        let v = version.into().unwrap_or(149);
        self.chrome_inner(v)
    }
    fn chrome_inner(mut self, v: u32) -> Self {
        self.profile = Some(match v { 148 => TlsProfile::chrome148(), _ => TlsProfile::chrome149() });
        self.max_redirects = 10;
        self
    }

    /// Firefox TLS fingerprint. `.firefox()` = latest, `.firefox(150)` = specific.
    pub fn firefox(self, version: impl Into<Option<u32>>) -> Self {
        let v = version.into().unwrap_or(151);
        self.firefox_inner(v)
    }
    fn firefox_inner(mut self, v: u32) -> Self {
        self.profile = Some(match v { 150 => TlsProfile::firefox150(), _ => TlsProfile::firefox151() });
        self.max_redirects = 10;
        self
    }

    /// Safari TLS fingerprint. `.safari()` = latest.
    pub fn safari(self, version: impl Into<Option<u32>>) -> Self {
        let _ = version.into();
        self.safari_inner()
    }
    fn safari_inner(mut self) -> Self {
        self.profile = Some(TlsProfile::safari26());
        self.max_redirects = 10;
        self
    }

    /// Safari iOS TLS fingerprint.
    pub fn safari_ios(mut self) -> Self {
        self.profile = Some(TlsProfile::safari26_ios());
        self.max_redirects = 10;
        self
    }

    /// Edge TLS fingerprint. `.edge()` = latest.
    pub fn edge(self, version: impl Into<Option<u32>>) -> Self {
        let _ = version.into();
        self.edge_inner()
    }
    fn edge_inner(mut self) -> Self {
        self.profile = Some(TlsProfile::edge149());
        self.max_redirects = 10;
        self
    }

    /// Random mainstream browser profile.
    pub fn random(mut self) -> Self {
        self.profile = Some(TlsProfile::random_mainstream());
        self.max_redirects = 10;
        self
    }

    /// Custom TLS profile.
    pub fn tls_profile(mut self, profile: TlsProfile) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Set an HTTP CONNECT proxy. Credentials can be in URL: `http://user:pass@host:8080`
    pub fn proxy(mut self, url: &str) -> Self {
        // Parse credentials from URL if present
        if let Ok(parsed) = url::Url::parse(url) {
            let user = parsed.username();
            let pass = parsed.password().unwrap_or("");
            if !user.is_empty() {
                self.proxy_auth = Some((user.to_string(), pass.to_string()));
                // Rebuild URL without credentials
                let mut clean = parsed.clone();
                let _ = clean.set_username("");
                let _ = clean.set_password(None);
                self.proxy_url = Some(clean.to_string());
                return self;
            }
        }
        self.proxy_url = Some(url.to_string());
        self
    }

    /// Set proxy authentication credentials (alternative to URL-embedded).
    #[deprecated(note = "Use .proxy(\"http://user:pass@host:8080\") instead")]
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
        Client::builder().chrome(None).build().expect("default client build failed")
    }
}

/// A request being built.
pub struct RequestBuilder<'a> {
    client: &'a Client,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    /// Force HTTP/1.1 by using HTTP/1.1-only ALPN for this request.
    /// Mirrors Go's `azuretls.Request{ForceHTTP1: true}`.
    /// Used for endpoints that require HTTP/1.1 (e.g. Apple authx).
    force_http1: bool,
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

    /// Add headers from an ordered Vec, preserving insertion order exactly.
    ///
    /// Unlike `headers(HeaderMap)` which iterates a hash map in unspecified order,
    /// this method appends each pair to self.headers in the order given.
    /// Use this for requests where header ordering matters (e.g. authx with Akamai H2 fingerprinting).
    pub fn headers_ordered(mut self, vec: Vec<(String, String)>) -> Self {
        self.headers.extend(vec);
        self
    }

    /// Set the request body (accepts String, Vec<u8>, &[u8], etc).
    pub fn body(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.body = Some(data.into());
        self
    }

    /// Force HTTP/1.1 for this request by using HTTP/1.1-only ALPN.
    ///
    /// Mirrors Go's `azuretls.Request{ForceHTTP1: true}`.
    /// Use for endpoints that require HTTP/1.1 even when the server supports HTTP/2,
    /// such as Apple's `authx` sign-in endpoint on `secure{N}.store.apple.com`.
    pub fn force_http1(mut self) -> Self {
        self.force_http1 = true;
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
        let pooled = self.client.pool.lock().await.remove(&pool_key);

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
            (":authority".into(), authority.clone()),
            (":scheme".into(), "https".into()),
            (":path".into(), path.clone()),
        ];

        // Add default headers from Chrome profile — but only when neither the
        // per-request headers NOR the ClientBuilder default_headers already supply
        // the key.  This lets callers set the real values via default_headers()
        // (e.g. build_chrome_client puts CriOS/150 UA + sec-ch-ua there) and
        // prevents the hardcoded Chrome-149-Windows profile fallbacks from leaking
        // into requests that already know exactly what they want to send.
        if !self.headers.iter().any(|(k, _)| k.to_lowercase() == "user-agent") &&
           !self.client.default_headers.contains_key("user-agent") {
            h2_headers.push(("user-agent".into(), self.client.user_agent.clone()));
        }
        if !self.headers.iter().any(|(k, _)| k.to_lowercase() == "accept") &&
           !self.client.default_headers.contains_key("accept") {
            h2_headers.push(("accept".into(), self.client.accept.clone()));
        }
        if !self.headers.iter().any(|(k, _)| k.to_lowercase() == "accept-encoding") &&
           !self.client.default_headers.contains_key("accept-encoding") {
            h2_headers.push(("accept-encoding".into(), self.client.accept_encoding.clone()));
        }
        if !self.headers.iter().any(|(k, _)| k.to_lowercase() == "accept-language") &&
           !self.client.default_headers.contains_key("accept-language") {
            h2_headers.push(("accept-language".into(), self.client.accept_language.clone()));
        }

        // Chrome Client Hints (sec-ch-ua): only inject the profile fallback when
        // neither per-request headers nor default_headers already supply sec-ch-ua.
        if !self.headers.iter().any(|(k, _)| k.to_lowercase() == "sec-ch-ua") &&
           !self.client.default_headers.contains_key("sec-ch-ua") {
            h2_headers.push(("sec-ch-ua".into(), self.client.sec_ch_ua.clone()));
            h2_headers.push(("sec-ch-ua-mobile".into(), self.client.sec_ch_ua_mobile.clone()));
            h2_headers.push(("sec-ch-ua-platform".into(), self.client.sec_ch_ua_platform.clone()));
        }

        // sec-fetch-* headers are NOT auto-injected.
        // Callers that need them (navigation, shield CORS, Graviton checkoutx)
        // add them explicitly in per-request headers.  Callers that must omit
        // them (bag GET, AddToCart POST, fulfillment-messages) rely on this
        // non-injection to match Go's azuretls OrderedHeaders behavior exactly.

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

        // Step 5: Send request — reuse pooled connection or create new
        let body_to_send = if method == "GET" || method == "HEAD" {
            None
        } else {
            self.body.as_deref()
        };

        // ForceHTTP1 fast-path: bypass pool, create a fresh H1-only TLS connection.
        // Mirrors Go's azuretls.Request{ForceHTTP1: true}.
        // Used for Apple authx (/shop/signIn/idms/authx) which requires HTTP/1.1.
        if self.force_http1 {
            let mut stream = self.new_connection_h1_only(host, port).await?;
            let (h1_resp, _keep_alive) = execute_h1(
                &mut stream, method, &path, &authority, &h2_headers, body_to_send,
            ).await?;
            // Convert inner response → client Response (same as normal path below)
            let status_code = h1_resp.headers.iter()
                .find(|(k, _)| k == ":status")
                .and_then(|(_, v)| v.parse::<u16>().ok())
                .unwrap_or(0);
            let headers: Vec<(String, String)> = h1_resp.headers.into_iter()
                .filter(|(k, _)| !k.starts_with(':'))
                .collect();
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
            return Ok(Response { status_code, headers, body: h1_resp.body });
        }

        // Try pooled connection first, fallback to new on error
        let (h2_resp, pool_entry) = if let Some(entry) = pooled {
            match entry {
                PooledConn::H2 { mut conn, mut encoder, mut decoder } => {
                    match conn.send_request(&h2_headers, body_to_send, &mut encoder, &mut decoder).await {
                        Ok(resp) => (resp, Some(PooledConn::H2 { conn, encoder, decoder })),
                        Err(_) => {
                            // Pooled conn stale/dead — create fresh
                            let fresh = self.new_connection(host, port).await?;
                            match fresh {
                                PooledConn::H2 { mut conn, mut encoder, mut decoder } => {
                                    let resp = conn.send_request(&h2_headers, body_to_send, &mut encoder, &mut decoder).await?;
                                    (resp, Some(PooledConn::H2 { conn, encoder, decoder }))
                                }
                                PooledConn::H1 { mut stream } => {
                                    let (resp, keep_alive) = execute_h1(
                                        &mut stream, method, &path, &authority, &h2_headers, body_to_send,
                                    ).await?;
                                    let pe = if keep_alive { Some(PooledConn::H1 { stream }) } else { None };
                                    (resp, pe)
                                }
                            }
                        }
                    }
                }
                PooledConn::H1 { mut stream } => {
                    let (resp, keep_alive) = execute_h1(
                        &mut stream, method, &path, &authority, &h2_headers, body_to_send,
                    ).await?;
                    let pe = if keep_alive { Some(PooledConn::H1 { stream }) } else { None };
                    (resp, pe)
                }
            }
        } else {
            let fresh = self.new_connection(host, port).await?;
            match fresh {
                PooledConn::H2 { mut conn, mut encoder, mut decoder } => {
                    let resp = conn.send_request(&h2_headers, body_to_send, &mut encoder, &mut decoder).await?;
                    (resp, Some(PooledConn::H2 { conn, encoder, decoder }))
                }
                PooledConn::H1 { mut stream } => {
                    let (resp, keep_alive) = execute_h1(
                        &mut stream, method, &path, &authority, &h2_headers, body_to_send,
                    ).await?;
                    let pe = if keep_alive { Some(PooledConn::H1 { stream }) } else { None };
                    (resp, pe)
                }
            }
        };

        // Return connection to pool for reuse (H1 skips when Connection: close)
        if let Some(entry) = pool_entry {
            self.client.pool.lock().await.insert(pool_key, entry);
        }

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

    /// Create a fresh TCP → TLS connection for the given host:port.
    /// Returns H2 or H1 based on ALPN negotiation.
    async fn new_connection(&self, host: &str, port: u16) -> Result<PooledConn, ClientError> {
        let tcp = if let Some(ref proxy_config) = self.client.proxy {
            establish_tunnel(proxy_config, host, port).await?
        } else {
            TcpStream::connect((host, port)).await?
        };
        let tls_stream = self.client.tls.connect(host, port, tcp).await?;
        // Check negotiated ALPN — idmsa.apple.com returns http/1.1
        let is_h2 = tls_stream.ssl().selected_alpn_protocol() == Some(b"h2");
        if is_h2 {
            let conn = Connection::handshake(tls_stream).await?;
            let encoder = ChromeEncoder::new(self.client.hpack_table_size);
            let decoder = StandardDecoder::new(self.client.hpack_table_size);
            Ok(PooledConn::H2 { conn, encoder, decoder })
        } else {
            // http/1.1 or no ALPN — return the raw TLS stream for HTTP/1.1
            Ok(PooledConn::H1 { stream: tls_stream })
        }
    }

    /// Create a fresh HTTP/1.1 connection by advertising only "http/1.1" in ALPN.
    /// Returns the raw TLS stream ready for HTTP/1.1 (execute_h1).
    async fn new_connection_h1_only(&self, host: &str, port: u16) -> Result<TlsStream, ClientError> {
        let tcp = if let Some(ref proxy_config) = self.client.proxy {
            establish_tunnel(proxy_config, host, port).await?
        } else {
            TcpStream::connect((host, port)).await?
        };
        Ok(self.client.tls.connect_h1_only(host, port, tcp).await?)
    }
}

// ─── HTTP/1.1 helpers ────────────────────────────────────────────────────────

/// Find the end of HTTP headers (`\r\n\r\n`) and return the index of the last `\n`.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 3) // index of the final `\n`
}

/// Execute a single HTTP/1.1 request over an existing TLS stream.
///
/// `headers` contains the H2-style pseudo-headers (`:method`, `:path`, etc.) plus
/// regular headers.  We strip pseudo-headers and derive the real H1 request line.
///
/// Returns `(response, keep_alive)` where `keep_alive` indicates whether the
/// connection can be returned to the pool.
async fn execute_h1(
    stream: &mut TlsStream,
    method: &str,
    path: &str,
    authority: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<(h2::connection::Response, bool), ClientError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ── Build request ────────────────────────────────────────────────────────
    let mut req = format!("{} {} HTTP/1.1\r\n", method, path);
    req.push_str(&format!("Host: {}\r\n", authority));

    // Body length header — always send Content-Length for POST/PUT/PATCH,
    // even when the body is empty (required by HTTP/1.1 for request methods
    // that MAY carry a body, including Apple's authx POST with 0-byte body).
    if method == "POST" || method == "PUT" || method == "PATCH" {
        let body_len = body.map(|b| b.len()).unwrap_or(0);
        req.push_str(&format!("Content-Length: {}\r\n", body_len));
    } else if let Some(b) = body {
        if !b.is_empty() {
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
    }

    // Append regular headers (skip H2 pseudo-headers and hop-by-hop headers
    // that don't make sense over HTTP/1.1-inside-TLS)
    for (k, v) in headers {
        if k.starts_with(':') {
            continue; // skip :method, :path, :authority, :scheme
        }
        let kl = k.to_lowercase();
        // Transfer-Encoding is meaningless translating H2 → H1; skip it.
        if kl == "transfer-encoding" {
            continue;
        }
        req.push_str(&format!("{}: {}\r\n", k, v));
    }

    req.push_str("\r\n");

    // Write headers
    stream.write_all(req.as_bytes()).await?;

    // Write body (only for non-GET/HEAD)
    if let Some(b) = body {
        if !b.is_empty() {
            stream.write_all(b).await?;
        }
    }
    stream.flush().await?;

    // ── Read response headers ────────────────────────────────────────────────
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let header_end;
    loop {
        let mut tmp = [0u8; 4096];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(ClientError::H1(
                "connection closed before response headers complete".into(),
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        if buf.len() > 131_072 {
            return Err(ClientError::H1("response headers exceed 128 KB limit".into()));
        }
    }

    // ── Parse status + headers with httparse ─────────────────────────────────
    let mut header_storage = [httparse::EMPTY_HEADER; 128];
    let mut parsed = httparse::Response::new(&mut header_storage);
    parsed
        .parse(&buf[..header_end + 1])
        .map_err(|e| ClientError::H1(format!("httparse: {}", e)))?;

    let status = parsed.code.unwrap_or(0);

    // Build response headers list (including synthetic :status for H2-compat)
    let mut resp_headers: Vec<(String, String)> = Vec::with_capacity(parsed.headers.len() + 1);
    resp_headers.push((":status".into(), status.to_string()));

    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;
    let mut connection_close = false;

    for h in parsed.headers.iter() {
        let name = h.name.to_lowercase();
        let value = String::from_utf8_lossy(h.value).into_owned();
        if name == "content-length" {
            content_length = value.trim().parse().ok();
        }
        if name == "transfer-encoding" && value.to_lowercase().contains("chunked") {
            is_chunked = true;
        }
        if name == "connection" && value.to_lowercase().contains("close") {
            connection_close = true;
        }
        resp_headers.push((h.name.to_string(), value));
    }

    // ── Read body ────────────────────────────────────────────────────────────
    // Bytes already read past the header boundary
    let body_start = header_end + 1;
    let mut body_buf: Vec<u8> = buf[body_start..].to_vec();

    let body_bytes: Vec<u8> = if is_chunked {
        read_chunked_body(stream, body_buf).await?
    } else if let Some(len) = content_length {
        // Read until we have `len` bytes
        while body_buf.len() < len {
            let mut tmp = [0u8; 8192];
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break; // server closed before sending full body
            }
            body_buf.extend_from_slice(&tmp[..n]);
        }
        body_buf.truncate(len);
        body_buf
    } else {
        // No Content-Length and not chunked.
        // HEAD, 204, 304 → no body by spec.
        if method == "HEAD" || status == 204 || status == 304 {
            Vec::new()
        } else {
            // Read until connection close.
            loop {
                let mut tmp = [0u8; 8192];
                let n = stream.read(&mut tmp).await?;
                if n == 0 {
                    break;
                }
                body_buf.extend_from_slice(&tmp[..n]);
            }
            connection_close = true; // can't reuse after read-until-close
            body_buf
        }
    };

    Ok((
        h2::connection::Response {
            headers: resp_headers,
            body: bytes::Bytes::from(body_bytes),
        },
        !connection_close,
    ))
}

/// Read a chunked Transfer-Encoding body until the terminal zero-size chunk.
async fn read_chunked_body(
    stream: &mut TlsStream,
    initial: Vec<u8>,
) -> Result<Vec<u8>, ClientError> {
    use tokio::io::AsyncReadExt;

    let mut raw = initial;
    let mut output: Vec<u8> = Vec::new();

    loop {
        // Ensure we have enough data to parse a chunk header (size\r\n)
        // Keep reading until we find \r\n for the chunk size line.
        let chunk_size = loop {
            if let Some(nl) = raw.iter().position(|&b| b == b'\n') {
                let line = String::from_utf8_lossy(&raw[..nl])
                    .trim_end_matches('\r')
                    .trim()
                    .to_string();
                raw.drain(..=nl);
                // Chunk size is hex, may have extensions after ';'
                let hex_part = line.split(';').next().unwrap_or("").trim();
                let sz = usize::from_str_radix(hex_part, 16)
                    .map_err(|_| ClientError::H1(format!("invalid chunk size: {:?}", hex_part)))?;
                break sz;
            }
            // Need more data
            let mut tmp = [0u8; 4096];
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(ClientError::H1("connection closed inside chunked body".into()));
            }
            raw.extend_from_slice(&tmp[..n]);
        };

        if chunk_size == 0 {
            break; // terminal chunk
        }

        // Read chunk_size bytes + trailing \r\n
        let total_needed = chunk_size + 2;
        while raw.len() < total_needed {
            let mut tmp = [0u8; 8192];
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(ClientError::H1("connection closed inside chunk data".into()));
            }
            raw.extend_from_slice(&tmp[..n]);
        }
        output.extend_from_slice(&raw[..chunk_size]);
        raw.drain(..total_needed); // consume data + \r\n
    }

    Ok(output)
}

#[cfg(test)]
mod h1_tests {
    use super::find_header_end;

    #[test]
    fn test_find_header_end_basic() {
        let input = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let pos = find_header_end(input).expect("should find header end");
        // The \r\n\r\n starts at offset 36; the last \n is at offset 39.
        assert_eq!(&input[pos + 1..], b"hello");
    }

    #[test]
    fn test_find_header_end_no_body() {
        let input = b"HTTP/1.1 204 No Content\r\n\r\n";
        assert!(find_header_end(input).is_some());
    }

    #[test]
    fn test_find_header_end_absent() {
        let input = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";
        assert!(find_header_end(input).is_none());
    }

    #[test]
    fn test_find_header_end_empty() {
        assert!(find_header_end(b"").is_none());
    }
}
