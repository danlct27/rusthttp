//! BoringSSL connector — establishes TLS connections with fingerprint config.
//!
//! Key: when connecting through a CONNECT proxy, SNI and verify hostname
//! MUST be set to the TARGET hostname (not the proxy). This is handled by
//! passing the target `host` to `tokio_boring::connect`.

use boring::ssl::{CertificateCompressionAlgorithm, CertificateCompressor, SslConnector, SslMethod, SslVerifyMode};
use tokio::net::TcpStream;
use tokio_boring::SslStream;
use tracing::debug;

use crate::config::{CertCompression, TlsProfile};
use crate::error::TlsError;

// NOTE: Both Brotli and Zlib certificate decompressors are implemented.
// Chrome advertises brotli (algorithm ID 2) — servers may select it.

/// Brotli certificate compressor (decompress only).
struct BrotliCertCompressor;

impl CertificateCompressor for BrotliCertCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        let mut decoder = brotli::Decompressor::new(input, 4096);
        std::io::copy(&mut decoder, output)?;
        Ok(())
    }
}

/// Zlib certificate compressor using boring's safe CertificateCompressor trait.
struct ZlibCertCompressor;

impl CertificateCompressor for ZlibCertCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        use std::io::Read;
        let mut decoder = flate2::read::ZlibDecoder::new(input);
        let mut buf = Vec::new();
        decoder.read_to_end(&mut buf)?;
        output.write_all(&buf)?;
        Ok(())
    }
}

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

        // Load system CA certificates
        builder.set_default_verify_paths()?;

        // TLS version bounds
        builder.set_min_proto_version(Some(self.profile.min_version))?;
        builder.set_max_proto_version(Some(self.profile.max_version))?;

        // Cipher suites — convert IANA names to BoringSSL/OpenSSL names.
        // TLS 1.3 ciphers are auto-enabled in BoringSSL, but we set them via
        // set_ciphersuites() style names. TLS 1.2 ciphers need OpenSSL names.
        let openssl_names: Vec<&str> = self.profile.cipher_suites.iter()
            .filter_map(|name| iana_to_openssl(name))
            .collect();
        let cipher_string = openssl_names.join(":");
        builder.set_cipher_list(&cipher_string).map_err(|e| {
            TlsError::InvalidCipher(format!("failed to set cipher list '{}': {}", cipher_string, e))
        })?;

        // Signature algorithms
        builder
            .set_sigalgs_list(&self.profile.signature_algorithms)
            .map_err(|e| {
                TlsError::ConfigMsg(format!(
                    "failed to set signature algorithms '{}': {}",
                    self.profile.signature_algorithms, e
                ))
            })?;

        // Supported groups (curves + PQ) — normalize names and fallback without PQ
        let normalized_groups: Vec<String> = self.profile.supported_groups.iter()
            .map(|s| normalize_curve_name(s))
            .collect();
        let groups_string = normalized_groups.join(":");
        if builder.set_curves_list(&groups_string).is_err() {
            // Filter out PQ groups and retry with classical curves only (normalized)
            let classical: Vec<String> = normalized_groups.iter()
                .filter(|s| !s.contains("MLKEM") && !s.contains("Kyber"))
                .cloned()
                .collect();
            let fallback = classical.join(":");
            debug!(
                original = %groups_string,
                fallback = %fallback,
                "PQ groups not supported, falling back to classical curves"
            );
            builder.set_curves_list(&fallback).map_err(|e| {
                TlsError::InvalidCurve(format!("failed to set curves '{}': {}", fallback, e))
            })?;
        }

        // ALPN — encode as length-prefixed bytes
        let alpn_bytes = encode_alpn(&self.profile.alpn_protocols)?;
        builder.set_alpn_protos(&alpn_bytes).map_err(|e| {
            TlsError::ConfigMsg(format!("failed to set ALPN protocols: {}", e))
        })?;

        // Certificate verification
        if self.danger_accept_invalid_certs {
            builder.set_verify(SslVerifyMode::NONE);
            debug!("tls verify mode: NONE (danger_accept_invalid_certs)");
        } else {
            builder.set_verify(SslVerifyMode::PEER);
        }

        // GREASE (RFC 8701) — safe wrapper in boring v4
        if self.profile.grease {
            builder.set_grease_enabled(true);
        }

        // Extension permutation — safe wrapper in boring v4
        if self.profile.permute_extensions {
            builder.set_permute_extensions(true);
        }

        // Certificate compression — register appropriate decompressor
        match self.profile.cert_compression {
            CertCompression::Brotli => {
                builder.add_certificate_compression_algorithm(BrotliCertCompressor)?;
            }
            CertCompression::Zlib => {
                builder.add_certificate_compression_algorithm(ZlibCertCompressor)?;
            }
            CertCompression::None => {}
        }

        // Enable OCSP stapling
        builder.enable_ocsp_stapling();

        // Enable Signed Certificate Timestamps (SCT)
        builder.enable_signed_cert_timestamps();

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
        use std::time::Duration;
        use tokio::time::timeout;

        debug!(host, "starting tls handshake");

        let connector = self.build_connector()?;
        let mut config = connector.configure()?;

        if self.danger_accept_invalid_certs {
            config.set_verify_hostname(false);
        }

        let handshake_timeout = Duration::from_secs(10);
        let stream = timeout(handshake_timeout, tokio_boring::connect(config, host, tcp_stream))
            .await
            .map_err(|_| TlsError::Handshake {
                host: host.to_owned(),
                detail: "handshake timeout (10s)".into(),
            })?
            .map_err(|e| TlsError::Handshake {
                host: host.to_owned(),
                detail: e.to_string(),
            })?;

        debug!(host, "tls handshake complete");
        Ok(stream)
    }
}

/// Encode ALPN protocols as length-prefixed byte sequence per RFC 7301.
///
/// Each protocol is encoded as: `<length_byte><protocol_bytes>`.
/// Example: `["h2", "http/1.1"]` → `b"\x02h2\x08http/1.1"`.
///
/// This is the wire format expected by `SslConnectorBuilder::set_alpn_protos`.
fn encode_alpn(protocols: &[String]) -> Result<Vec<u8>, TlsError> {
    let mut buf = Vec::new();
    for proto in protocols {
        if proto.len() > 255 {
            return Err(TlsError::ConfigMsg(format!(
                "ALPN protocol name too long ({} bytes): {}", proto.len(), proto
            )));
        }
        buf.push(proto.len() as u8);
        buf.extend_from_slice(proto.as_bytes());
    }
    Ok(buf)
}

/// Normalize curve/group names from JSON profiles to BoringSSL-accepted format.
/// BoringSSL's set_curves_list() accepts: X25519, P-256, P-384, P-521.
fn normalize_curve_name(name: &str) -> String {
    match name.to_lowercase().as_str() {
        "x25519" => "X25519".into(),
        "p-256" | "secp256r1" | "prime256v1" => "P-256".into(),
        "p-384" | "secp384r1" => "P-384".into(),
        "p-521" | "secp521r1" => "P-521".into(),
        "x25519mlkem768" => "X25519MLKEM768".into(),
        _ => name.to_string(),
    }
}

/// Map IANA cipher suite names to BoringSSL/OpenSSL cipher string names.
/// TLS 1.3 ciphers use their own naming convention in BoringSSL.
fn iana_to_openssl(iana: &str) -> Option<&'static str> {
    match iana {
        // TLS 1.3 (BoringSSL accepts these names)
        "TLS_AES_128_GCM_SHA256" => Some("TLS_AES_128_GCM_SHA256"),
        "TLS_AES_256_GCM_SHA384" => Some("TLS_AES_256_GCM_SHA384"),
        "TLS_CHACHA20_POLY1305_SHA256" => Some("TLS_CHACHA20_POLY1305_SHA256"),
        // TLS 1.2 ECDHE
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => Some("ECDHE-ECDSA-AES128-GCM-SHA256"),
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => Some("ECDHE-RSA-AES128-GCM-SHA256"),
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => Some("ECDHE-ECDSA-AES256-GCM-SHA384"),
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => Some("ECDHE-RSA-AES256-GCM-SHA384"),
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => Some("ECDHE-ECDSA-CHACHA20-POLY1305"),
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => Some("ECDHE-RSA-CHACHA20-POLY1305"),
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" => Some("ECDHE-RSA-AES128-SHA"),
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" => Some("ECDHE-RSA-AES256-SHA"),
        // TLS 1.2 RSA
        "TLS_RSA_WITH_AES_128_GCM_SHA256" => Some("AES128-GCM-SHA256"),
        "TLS_RSA_WITH_AES_256_GCM_SHA384" => Some("AES256-GCM-SHA384"),
        "TLS_RSA_WITH_AES_128_CBC_SHA" => Some("AES128-SHA"),
        "TLS_RSA_WITH_AES_256_CBC_SHA" => Some("AES256-SHA"),
        // Unknown — skip with warning
        _ => {
            tracing::warn!(cipher = %iana, "unknown cipher suite name, skipping");
            None
        }
    }
}
