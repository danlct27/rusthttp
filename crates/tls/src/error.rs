//! TLS error types for the `rusthttp-tls` crate.

/// Errors that can occur during TLS connection establishment.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// BoringSSL configuration error.
    #[error("tls config error: {0}")]
    Config(#[from] boring::error::ErrorStack),

    /// TLS handshake failed.
    #[error("tls handshake failed for {host}: {detail}")]
    Handshake { host: String, detail: String },

    /// SNI hostname is invalid.
    #[error("invalid sni hostname: {0}")]
    InvalidHostname(String),
}
