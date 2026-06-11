//! HTTP CONNECT tunnel establishment.

use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::debug;

use crate::error::ProxyError;

/// Configuration for connecting through an HTTP proxy.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Proxy URL in the form `http://host:port` or `http://user:pass@host:port`.
    pub url: String,
    /// Optional (username, password) for proxy authentication.
    pub auth: Option<(String, String)>,
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

    let mut stream = TcpStream::connect((proxy_host.as_str(), proxy_port)).await?;

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

    // Read response until \r\n\r\n
    let mut reader = BufReader::new(&mut stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;

    let status_code = parse_status_code(&status_line)?;
    if status_code != 200 {
        return Err(ProxyError::TunnelRejected(status_code));
    }

    // Consume remaining headers
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" {
            break;
        }
    }

    debug!("CONNECT tunnel established");
    Ok(stream)
}

/// Parse `http://[user:pass@]host:port` into (host, port, optional auth).
fn parse_proxy_url(url: &str) -> Result<(String, u16, Option<(String, String)>), ProxyError> {
    let stripped = url
        .strip_prefix("http://")
        .ok_or_else(|| ProxyError::InvalidUrl(url.to_string()))?;

    let (auth, host_port) = if let Some(at_pos) = stripped.find('@') {
        let auth_part = &stripped[..at_pos];
        let rest = &stripped[at_pos + 1..];
        let (user, pass) = auth_part
            .split_once(':')
            .ok_or_else(|| ProxyError::InvalidUrl(url.to_string()))?;
        (Some((user.to_string(), pass.to_string())), rest)
    } else {
        (None, stripped)
    };

    // Strip trailing path if any
    let host_port = host_port.split('/').next().unwrap_or(host_port);

    let (host, port_str) = host_port
        .rsplit_once(':')
        .ok_or_else(|| ProxyError::InvalidUrl(url.to_string()))?;

    let port: u16 = port_str
        .parse()
        .map_err(|_| ProxyError::InvalidUrl(url.to_string()))?;

    Ok((host.to_string(), port, auth))
}

/// Extract status code from HTTP status line like `HTTP/1.1 200 ...`.
fn parse_status_code(line: &str) -> Result<u16, ProxyError> {
    let mut parts = line.split_whitespace();
    let _version = parts.next().ok_or(ProxyError::MalformedResponse)?;
    let code_str = parts.next().ok_or(ProxyError::MalformedResponse)?;
    code_str.parse().map_err(|_| ProxyError::MalformedResponse)
}
