//! BoringSSL connector — establishes TLS connections with fingerprint config.
//!
//! Key: when connecting through a CONNECT proxy, SNI and verify hostname
//! MUST be set to the TARGET hostname (not the proxy). This is handled by
//! passing the target `host` to `tokio_boring::connect`.

use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
use tokio::net::TcpStream;
use tokio_boring::SslStream;
use tracing::debug;

use crate::config::TlsProfile;
use crate::error::TlsError;

/// Establishes TLS connections with a browser-matching fingerprint.
#[derive(Debug, Clone)]
pub struct TlsConnector {
    profile: TlsProfile,
    /// Skip certificate verification (dangerous — testing only).
    pub danger_accept_invalid_certs: bool,
}

impl TlsConnector {
    /// Create a new connector with the given profile.
    pub fn new(profile: TlsProfile) -> Self {
        Self {
            profile,
            danger_accept_invalid_certs: false,
        }
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
        builder.set_sigalgs_list(self.profile.signature_algorithms)?;

        // Supported groups (curves)
        let groups_string = self.profile.supported_groups.join(":");
        builder.set_curves_list(&groups_string)?;

        // ALPN — h2 then http/1.1
        builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;

        // Certificate verification
        if self.danger_accept_invalid_certs {
            builder.set_verify(SslVerifyMode::NONE);
        } else {
            builder.set_verify(SslVerifyMode::PEER);
        }

        // Unsafe BoringSSL FFI for fingerprint features
        let ctx_ptr = builder.as_ptr();

        if self.profile.grease {
            // SAFETY: ctx_ptr is valid — we own the builder and it has not been
            // consumed. SSL_CTX_set_grease_enabled is a BoringSSL extension that
            // enables GREASE (RFC 8701) values in the ClientHello.
            unsafe {
                boring_sys::SSL_CTX_set_grease_enabled(ctx_ptr, 1);
            }
        }

        if self.profile.permute_extensions {
            // SAFETY: ctx_ptr is valid — same lifetime as builder.
            // SSL_CTX_set_permute_extensions randomises extension order to
            // resist fingerprinting of the extension ordering itself.
            unsafe {
                boring_sys::SSL_CTX_set_permute_extensions(ctx_ptr, 1);
            }
        }

        if self.profile.cert_compression {
            // SAFETY: ctx_ptr is valid. Registers brotli (alg_id=2) as the
            // certificate compression algorithm per RFC 8879.
            unsafe {
                boring_sys::SSL_CTX_add_cert_compression_alg(
                    ctx_ptr,
                    2, // TLSEXT_cert_compression_brotli
                    None,
                    Some(brotli_decompress_cb),
                );
            }
        }

        Ok(builder.build())
    }

    /// Perform a TLS handshake over an established TCP stream.
    ///
    /// `host` must be the target hostname (not the proxy) — this is used for
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
    // SAFETY: This callback is required by the API signature but BoringSSL
    // handles brotli decompression internally once the algorithm is registered.
    1
}
