//! Proxy error types.

use std::io;

/// Errors that can occur during proxy tunnel establishment.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Failed to connect to the proxy server.
    #[error("proxy connection failed: {0}")]
    Connect(#[from] io::Error),

    /// Connection to proxy timed out.
    #[error("proxy connect timeout")]
    ConnectTimeout,

    /// Reading proxy response timed out.
    #[error("proxy read timeout")]
    ReadTimeout,

    /// Invalid proxy URL format (credentials stripped).
    #[error("invalid proxy url: {0}")]
    InvalidUrl(String),

    /// Proxy returned a non-200 status code.
    #[error("tunnel rejected with status {0}")]
    TunnelRejected(u16),

    /// Malformed HTTP response from proxy.
    #[error("malformed proxy response")]
    MalformedResponse,

    /// No healthy proxies available in the pool.
    #[error("no available proxies in pool")]
    PoolExhausted,
}
