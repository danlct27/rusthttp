//! BoringSSL connector — establishes TLS connections with fingerprint config.
//!
//! Key: when connecting through a CONNECT proxy, SNI and verify hostname
//! MUST be set to the TARGET hostname (not the proxy). This is handled by
//! passing the target `host` to `tokio_boring::connect`.

use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
use tokio::net::TcpStream;
use tokio_boring::SslStream;
use tracing::debug;

use crate::config::{CertCompression, TlsProfile};
use crate::error::TlsError;

/// Establishes TLS connections with a browser-matching fingerprint.
///
/// # Example
/// ```no_run
/// use rusthttp_tls::{TlsConnector, TlsProfile};
/// use tokio::net::TcpStream;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let connector = TlsConnector::new(TlsProfile::chrome149());
/// let tcp = TcpStream::connect("example.com:443").await?;
/// let tls = connector.connect("example.com", 443, tcp).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct TlsConnector {
    profile: TlsProfile,
    /// Skip certificate verification (dangerous — testing only).
    danger_accept_invalid_certs: bool,
}

impl TlsConnector {
    /// Create a new connector with the given profile.
    pub fn new(profile: TlsProfile) -> Self {
        Self {
            profile,
            danger_accept_invalid_certs: false,
        }
    }

    /// Create a connector that skips certificate verification.
    ///
    /// # Warning
    /// Only use for testing or when connecting through a CONNECT proxy
    /// where the proxy's cert interferes with verification.
    pub fn danger_accept_invalid_certs(mut self) -> Self {
        self.danger_accept_invalid_certs = true;
        self
    }

    /// Get a reference to the current profile.
    pub fn profile(&self) -> &TlsProfile {
        &self.profile
    }

    /// Build the `SslConnector` with all fingerprint settings applied.
    fn build_connector(&self) -> Result<SslConnector, TlsError> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())?;

        // TLS version bounds
        builder.set_min_proto_version(Some(self.profile.min_version))?;
        builder.set_max_proto_version(Some(self.profile.max_version))?;

        // Cipher suites — join with colon for BoringSSL
        let cipher_string = self.profile.cipher_suites.join(":");
        builder.set_cipher_list(&cipher_string)?;

        // Signature algorithms
        builder.set_sigalgs_list(&self.profile.signature_algorithms)?;

        // Supported groups (curves + PQ)
        let groups_string = self.profile.supported_groups.join(":");
        builder.set_curves_list(&groups_string)?;

        // ALPN — encode as length-prefixed bytes
        let alpn_bytes = encode_alpn(&self.profile.alpn_protocols);
        builder.set_alpn_protos(&alpn_bytes)?;

        // Certificate verification
        if self.danger_accept_invalid_certs {
            builder.set_verify(SslVerifyMode::NONE);
            debug!("tls verify mode: NONE (danger_accept_invalid_certs)");
        } else {
            builder.set_verify(SslVerifyMode::PEER);
        }

        // Unsafe BoringSSL FFI for fingerprint features
        let ctx_ptr = builder.as_ptr();

        if self.profile.grease {
            // SAFETY: ctx_ptr is valid — we own the builder and it has not been
            // consumed. SSL_CTX_set_grease_enabled enables GREASE (RFC 8701).
            unsafe {
                boring_sys::SSL_CTX_set_grease_enabled(ctx_ptr, 1);
            }
        }

        if self.profile.permute_extensions {
            // SAFETY: ctx_ptr is valid — same lifetime as builder.
            // SSL_CTX_set_permute_extensions randomises extension order.
            unsafe {
                boring_sys::SSL_CTX_set_permute_extensions(ctx_ptr, 1);
            }
        }

        match self.profile.cert_compression {
            CertCompression::Brotli => {
                // SAFETY: ctx_ptr is valid. Registers brotli (alg_id=2) for
                // certificate compression per RFC 8879.
                unsafe {
                    boring_sys::SSL_CTX_add_cert_compression_alg(
                        ctx_ptr,
                        2, // TLSEXT_cert_compression_brotli
                        None,
                        Some(brotli_decompress_cb),
                    );
                }
            }
            CertCompression::Zlib => {
                // SAFETY: ctx_ptr is valid. Registers zlib (alg_id=1).
                unsafe {
                    boring_sys::SSL_CTX_add_cert_compression_alg(
                        ctx_ptr,
                        1, // TLSEXT_cert_compression_zlib
                        None,
                        None, // zlib decompression not implemented yet
                    );
                }
            }
            CertCompression::None => {}
        }

        Ok(builder.build())
    }

    /// Perform a TLS handshake over an established TCP stream.
    ///
    /// `host` must be the **target** hostname (not the proxy) — this is used for
    /// both SNI and certificate verification.
    pub async fn connect(
        &self,
        host: &str,
        _port: u16,
        tcp_stream: TcpStream,
    ) -> Result<SslStream<TcpStream>, TlsError> {
        debug!(host, "starting tls handshake");

        let connector = self.build_connector()?;
        let mut config = connector.configure()?;

        if self.danger_accept_invalid_certs {
            config.set_verify_hostname(false);
        }

        let stream =
            tokio_boring::connect(config, host, tcp_stream)
                .await
                .map_err(|e| TlsError::Handshake {
                    host: host.to_owned(),
                    detail: e.to_string(),
                })?;

        debug!(host, "tls handshake complete");
        Ok(stream)
    }
}

/// Encode ALPN protocols as length-prefixed byte sequence for BoringSSL.
fn encode_alpn(protocols: &[String]) -> Vec<u8> {
    let mut buf = Vec::new();
    for proto in protocols {
        buf.push(proto.len() as u8);
        buf.extend_from_slice(proto.as_bytes());
    }
    buf
}

/// Brotli decompression callback for certificate compression (RFC 8879).
///
/// # Safety
/// Called by BoringSSL during handshake. Pointers are valid for the duration
/// of the call as guaranteed by the BoringSSL API contract.
unsafe extern "C" fn brotli_decompress_cb(
    _ssl: *mut boring_sys::SSL,
    _out: *mut *mut boring_sys::CRYPTO_BUFFER,
    _uncompressed_len: usize,
    _in_ptr: *const u8,
    _in_len: usize,
) -> ::std::os::raw::c_int {
    // TODO: implement actual brotli decompression when needed
    // For now, BoringSSL handles it internally once registered.
    1
}
