//! rusthttp — Lightweight Rust HTTP client with Chrome TLS/HTTP2 fingerprint parity.
//!
//! # Example
//! ```no_run
//! use rusthttp::Client;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = Client::builder()
//!         .chrome()
//!         .proxy("http://user:pass@host:port")
//!         .build()?;
//!
//!     let resp = client.get("https://example.com").send().await?;
//!     println!("{}", resp.status());
//!     Ok(())
//! }
//! ```

use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Mutex;
use thiserror::Error;
use tokio::net::TcpStream;
use url::Url;

pub use rusthttp_h2 as h2;
pub use rusthttp_proxy as proxy;
pub use rusthttp_tls as tls;

use h2::connection::Connection;
use h2::hpack::{ChromeEncoder, StandardDecoder};
use proxy::{establish_tunnel, ProxyConfig};
use tls::{TlsConnector, TlsProfile};

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

    /// Get the response body as bytes.
    pub fn bytes(&self) -> &Bytes {
        &self.body
    }

    /// Get the response body as UTF-8 text.
    pub fn text(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }

    /// Get a header value by name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }
}

/// HTTP client with Chrome fingerprint parity.
pub struct Client {
    tls: TlsConnector,
    proxy: Option<ProxyConfig>,
    hpack_table_size: usize,
    /// Simple cookie jar: domain → Vec<(name, value)>
    cookies: Mutex<HashMap<String, Vec<(String, String)>>>,
    /// Max redirects to follow (0 = disabled)
    max_redirects: u8,
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
}

/// Builder for configuring a Client.
#[derive(Default)]
pub struct ClientBuilder {
    profile: Option<TlsProfile>,
    proxy_url: Option<String>,
    proxy_auth: Option<(String, String)>,
    danger_accept_invalid_certs: bool,
    max_redirects: u8,
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
            max_redirects: self.max_redirects,
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

/// A request being built.
pub struct RequestBuilder<'a> {
    client: &'a Client,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

impl<'a> RequestBuilder<'a> {
    /// Add a header.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Set the request body.
    pub fn body(mut self, data: Vec<u8>) -> Self {
        self.body = Some(data);
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

        // Step 1: Establish TCP (direct or via proxy)
        let tcp = if let Some(ref proxy_config) = self.client.proxy {
            establish_tunnel(proxy_config, host, port).await?
        } else {
            TcpStream::connect((host, port)).await?
        };

        // Step 2: TLS handshake (SNI + verify = target hostname)
        let tls_stream = self.client.tls.connect(host, port, tcp).await?;

        // Step 3: H2 handshake
        let mut conn = Connection::handshake(tls_stream).await?;

        // Step 4: Build Chrome-ordered pseudo-headers + user headers
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
        if let Ok(jar) = self.client.cookies.lock() {
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

        // Append user-provided headers
        for (k, v) in &self.headers {
            h2_headers.push((k.clone(), v.clone()));
        }

        // Step 5: Send request via H2 — fresh encoder/decoder per connection
        let mut encoder = ChromeEncoder::new(self.client.hpack_table_size);
        let mut decoder = StandardDecoder::new(self.client.hpack_table_size);

            // Body: only send if method is not GET/HEAD (redirects may have changed method)
            let body_to_send = if method == "GET" || method == "HEAD" {
                None
            } else {
                self.body.as_deref()
            };
            let h2_resp = conn.send_request(
            &h2_headers,
            body_to_send,
            &mut encoder,
            &mut decoder,
        ).await?;

        // Step 6: Parse status from response headers
        let status_code = h2_resp.headers.iter()
            .find(|(k, _)| k == ":status")
            .and_then(|(_, v)| v.parse::<u16>().ok())
            .unwrap_or(0);

        let headers: Vec<(String, String)> = h2_resp.headers.into_iter()
            .filter(|(k, _)| !k.starts_with(':'))
            .collect();

        // Store set-cookie headers in jar (cap individual cookie size at 4KB)
        for (k, v) in &headers {
            if k.to_lowercase() == "set-cookie" {
                if v.len() > 4096 { continue; } // Skip oversized cookies
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

        Ok(Response {
            status_code,
            headers,
            body: h2_resp.body,
        })
    }
}
