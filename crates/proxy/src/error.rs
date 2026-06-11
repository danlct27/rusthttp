//! Proxy error types.

use std::io;

/// Errors that can occur during proxy tunnel establishment.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Failed to connect to the proxy server.
    #[error("proxy connection failed: {0}")]
    Connect(#[from] io::Error),

    /// Invalid proxy URL format.
    #[error("invalid proxy url: {0}")]
    InvalidUrl(String),

    /// Proxy returned a non-200 status code.
    #[error("tunnel rejected with status {0}")]
    TunnelRejected(u16),

    /// Malformed HTTP response from proxy.
    #[error("malformed proxy response")]
    MalformedResponse,
}
