//! HTTP CONNECT tunnel establishment.

use base64::Engine;
use std::fmt;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use crate::error::ProxyError;

/// Default timeout for proxy connection and response reading.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(15);
/// Max response header bytes to consume from proxy.
const MAX_RESPONSE_HEADER_BYTES: usize = 8192;

/// Configuration for connecting through an HTTP proxy.
#[derive(Clone)]
pub struct ProxyConfig {
    /// Proxy URL in the form `http://host:port` or `http://user:pass@host:port`.
    pub url: String,
    /// Optional (username, password) for proxy authentication.
    pub auth: Option<(String, String)>,
}

// Custom Debug — never print credentials
impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host_port = parse_proxy_url(&self.url)
            .map(|(h, p, _)| format!("{h}:{p}"))
            .unwrap_or_else(|_| "<invalid>".into());
        f.debug_struct("ProxyConfig")
            .field("host", &host_port)
            .field("has_auth", &self.auth.is_some())
            .finish()
    }
}

/// Establish an HTTP CONNECT tunnel through the proxy to `target_host:target_port`.
///
/// Returns the raw `TcpStream` after the tunnel is established — the caller
/// is responsible for layering TLS on top.
pub async fn establish_tunnel(
    config: &ProxyConfig,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, ProxyError> {
    let (proxy_host, proxy_port, url_auth) = parse_proxy_url(&config.url)?;

    debug!(%proxy_host, proxy_port, %target_host, target_port, "establishing CONNECT tunnel");

    let mut stream = timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((proxy_host.as_str(), proxy_port)),
    )
    .await
    .map_err(|_| ProxyError::ConnectTimeout)??;

    // Build CONNECT request
    let target = format!("{target_host}:{target_port}");
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");

    // Auth: explicit config takes priority, then URL-embedded credentials
    let auth = config.auth.as_ref().or(url_auth.as_ref());
    if let Some((user, pass)) = auth {
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        req.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    req.push_str("\r\n");

    stream.write_all(req.as_bytes()).await?;

    // Read response with timeout and size limit
    let response = timeout(READ_TIMEOUT, read_proxy_response(&mut stream)).await
        .map_err(|_| ProxyError::ReadTimeout)??;

    let status_code = parse_status_code(&response)?;
    if status_code != 200 {
        return Err(ProxyError::TunnelRejected(status_code));
    }

    debug!("CONNECT tunnel established");
    Ok(stream)
}

/// Read HTTP response line + headers from proxy, byte-by-byte to avoid
/// buffering past the header boundary into TLS handshake data.
async fn read_proxy_response(stream: &mut TcpStream) -> Result<String, ProxyError> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::with_capacity(256);
    let mut total = 0usize;

    // Read until we see \r\n\r\n (end of HTTP headers)
    loop {
        let mut byte = [0u8; 1];
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(ProxyError::MalformedResponse);
        }
        buf.push(byte[0]);
        total += 1;
        if total > MAX_RESPONSE_HEADER_BYTES {
            return Err(ProxyError::MalformedResponse);
        }
        // Check for \r\n\r\n at the end
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
    }

    // Extract status line (first line up to \r\n)
    let header_str = String::from_utf8_lossy(&buf);
    let status_line = header_str.lines().next().unwrap_or("").to_string();
    Ok(status_line)
}

/// Parsed proxy URL result: (host, port, optional auth).
type ParsedProxy = (String, u16, Option<(String, String)>);

/// Parse `http://[user:pass@]host:port` into (host, port, optional auth).
fn parse_proxy_url(url: &str) -> Result<ParsedProxy, ProxyError> {
    let stripped = url
        .strip_prefix("http://")
        .ok_or_else(|| ProxyError::InvalidUrl(strip_credentials(url)))?;

    let (auth, host_port) = if let Some(at_pos) = stripped.find('@') {
        let auth_part = &stripped[..at_pos];
        let rest = &stripped[at_pos + 1..];
        let (user, pass) = auth_part
            .split_once(':')
            .ok_or_else(|| ProxyError::InvalidUrl(strip_credentials(url)))?;
        (Some((user.to_string(), pass.to_string())), rest)
    } else {
        (None, stripped)
    };

    // Strip trailing path if any
    let host_port = host_port.split('/').next().unwrap_or(host_port);

    let (host, port_str) = host_port
        .rsplit_once(':')
        .ok_or_else(|| ProxyError::InvalidUrl(strip_credentials(url)))?;

    let port: u16 = port_str
        .parse()
        .map_err(|_| ProxyError::InvalidUrl(strip_credentials(url)))?;

    Ok((host.to_string(), port, auth))
}

/// Strip credentials from URL for safe error messages.
fn strip_credentials(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let after_scheme = &url[scheme_end + 3..];
        if let Some(at) = after_scheme.find('@') {
            return format!("{}://***@{}", &url[..scheme_end], &after_scheme[at + 1..]);
        }
    }
    url.to_string()
}

/// Extract status code from HTTP status line like `HTTP/1.1 200 ...`.
fn parse_status_code(line: &str) -> Result<u16, ProxyError> {
    let mut parts = line.split_whitespace();
    let _version = parts.next().ok_or(ProxyError::MalformedResponse)?;
    let code_str = parts.next().ok_or(ProxyError::MalformedResponse)?;
    code_str.parse().map_err(|_| ProxyError::MalformedResponse)
}
