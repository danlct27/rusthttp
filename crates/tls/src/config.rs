//! TLS fingerprint configuration — browser profiles.
//!
//! Each profile defines the cipher suites, extensions, groups, and signature
//! algorithms that match a specific browser version's ClientHello.

use boring::ssl::SslVersion;

/// Chrome 149 cipher suite list (OpenSSL names, in order).
const CHROME_149_CIPHERS: &[&str] = &[
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
];

/// Chrome 149 supported groups (BoringSSL names).
const CHROME_149_GROUPS: &[&str] = &["X25519MLKEM768", "X25519", "P-256", "P-384"];

/// Chrome 149 signature algorithms (colon-separated for BoringSSL).
const CHROME_149_SIGALGS: &str = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";

/// A TLS fingerprint profile describing how the ClientHello should look.
#[derive(Debug, Clone)]
pub struct TlsProfile {
    /// Ordered cipher suite names (OpenSSL/BoringSSL notation).
    pub cipher_suites: Vec<&'static str>,
    /// Named groups for key exchange.
    pub supported_groups: Vec<&'static str>,
    /// Colon-separated signature algorithms string.
    pub signature_algorithms: &'static str,
    /// Enable GREASE values in ClientHello.
    pub grease: bool,
    /// Enable ALPS (Application-Layer Protocol Settings) extension.
    pub alps: bool,
    /// Enable brotli certificate compression.
    pub cert_compression: bool,
    /// Minimum TLS version.
    pub min_version: SslVersion,
    /// Maximum TLS version.
    pub max_version: SslVersion,
    /// Permute extension order (BoringSSL feature).
    pub permute_extensions: bool,
}

impl TlsProfile {
    /// Returns the Chrome 149 TLS fingerprint profile.
    ///
    /// This profile matches Chrome 149's ClientHello including cipher order,
    /// supported groups (with post-quantum X25519MLKEM768), GREASE, ALPS,
    /// brotli cert compression, and extension permutation.
    pub fn chrome149() -> Self {
        Self {
            cipher_suites: CHROME_149_CIPHERS.to_vec(),
            supported_groups: CHROME_149_GROUPS.to_vec(),
            signature_algorithms: CHROME_149_SIGALGS,
            grease: true,
            alps: true,
            cert_compression: true,
            min_version: SslVersion::TLS1_2,
            max_version: SslVersion::TLS1_3,
            permute_extensions: true,
        }
    }
}
