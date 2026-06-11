//! TLS fingerprint configuration — browser profiles.
//!
//! Supports:
//! - Preset profiles (Chrome, Firefox, Safari, etc.)
//! - JSON-loaded profiles
//! - Builder pattern for custom overrides
//! - Random GREASE per-handshake

use boring::ssl::SslVersion;

use crate::error::TlsError;
use crate::profile::{ProfileJson, TlsSection};

/// Certificate compression algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertCompression {
    None,
    Brotli,
    Zlib,
}

/// A TLS fingerprint profile describing how the ClientHello should look.
///
/// Use [`TlsProfile::chrome149()`] for a ready-made profile, or
/// [`TlsProfileBuilder`] for custom configurations.
#[derive(Debug, Clone)]
pub struct TlsProfile {
    /// Ordered cipher suite names (OpenSSL/BoringSSL notation).
    pub cipher_suites: Vec<String>,
    /// Named groups for key exchange.
    pub supported_groups: Vec<String>,
    /// Colon-separated signature algorithms string.
    pub signature_algorithms: String,
    /// Enable GREASE values in ClientHello (random per-handshake).
    pub grease: bool,
    /// Enable ALPS (Application-Layer Protocol Settings) extension.
    pub alps: bool,
    /// Certificate compression method.
    pub cert_compression: CertCompression,
    /// Minimum TLS version.
    pub min_version: SslVersion,
    /// Maximum TLS version.
    pub max_version: SslVersion,
    /// Permute extension order (BoringSSL feature, matches Chrome behavior).
    pub permute_extensions: bool,
    /// ALPN protocols to advertise (e.g., ["h2", "http/1.1"]).
    pub alpn_protocols: Vec<String>,
    /// Extension order from JSON profile (if provided).
    pub extensions_order: Option<Vec<String>>,
}

impl TlsProfile {
    /// Returns the Chrome 149 TLS fingerprint profile.
    pub fn chrome149() -> Self {
        Self {
            cipher_suites: vec![
                // TLS 1.3 ciphers
                "TLS_AES_128_GCM_SHA256".into(),
                "TLS_AES_256_GCM_SHA384".into(),
                "TLS_CHACHA20_POLY1305_SHA256".into(),
                // TLS 1.2 ECDHE ciphers
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into(),
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".into(),
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".into(),
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".into(),
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".into(),
                // CBC + RSA fallback (Chrome 149 includes these)
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA".into(),
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA".into(),
                "TLS_RSA_WITH_AES_128_GCM_SHA256".into(),
                "TLS_RSA_WITH_AES_256_GCM_SHA384".into(),
                "TLS_RSA_WITH_AES_128_CBC_SHA".into(),
                "TLS_RSA_WITH_AES_256_CBC_SHA".into(),
            ],
            supported_groups: vec![
                "X25519MLKEM768".into(),
                "X25519".into(),
                "P-256".into(),
                "P-384".into(),
            ],
            signature_algorithms: "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512".into(),
            grease: true,
            alps: true,
            cert_compression: CertCompression::Brotli,
            min_version: SslVersion::TLS1_2,
            max_version: SslVersion::TLS1_3,
            permute_extensions: true,
            alpn_protocols: vec!["h2".into(), "http/1.1".into()],
            extensions_order: None,
        }
    }

    /// Create a profile from a loaded JSON profile.
    pub fn from_json(json: &ProfileJson) -> Result<Self, TlsError> {
        Self::from_tls_section(&json.tls)
    }

    /// Create a profile from a TLS section of a JSON profile.
    pub fn from_tls_section(tls: &TlsSection) -> Result<Self, TlsError> {
        let cert_compression = match tls.compress_certificate_algorithms.as_deref() {
            Some(algos) if algos.iter().any(|a| a == "brotli") => CertCompression::Brotli,
            Some(algos) if algos.iter().any(|a| a == "zlib") => CertCompression::Zlib,
            _ => CertCompression::None,
        };

        let min_version = match tls.min_version.as_deref() {
            Some("1.0") => SslVersion::TLS1,
            Some("1.1") => SslVersion::TLS1_1,
            Some("1.3") => SslVersion::TLS1_3,
            _ => SslVersion::TLS1_2,
        };

        let max_version = match tls.max_version.as_deref() {
            Some("1.2") => SslVersion::TLS1_2,
            _ => SslVersion::TLS1_3,
        };

        Ok(Self {
            cipher_suites: tls.cipher_suites.clone(),
            supported_groups: tls.supported_groups.clone(),
            signature_algorithms: tls.signature_algorithms.join(":"),
            grease: tls.grease.enabled,
            alps: tls.alps.enabled,
            cert_compression,
            min_version,
            max_version,
            permute_extensions: tls.grease.enabled, // Chrome permutes when GREASE enabled
            alpn_protocols: tls.alps.protocols.clone().unwrap_or_else(|| vec!["h2".into(), "http/1.1".into()]),
            extensions_order: tls.extensions_order.clone(),
        })
    }

    /// Start building a custom profile from this one as a base.
    pub fn builder() -> TlsProfileBuilder {
        TlsProfileBuilder::default()
    }

    /// Create a builder pre-filled with this profile's settings.
    pub fn customize(self) -> TlsProfileBuilder {
        TlsProfileBuilder { profile: self }
    }
}

/// Builder for constructing custom TLS profiles with fine-grained control.
///
/// ```rust
/// use rusthttp_tls::TlsProfile;
///
/// let profile = TlsProfile::chrome149()
///     .customize()
///     .grease(false)
///     .add_cipher("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256")
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct TlsProfileBuilder {
    profile: TlsProfile,
}

impl Default for TlsProfileBuilder {
    fn default() -> Self {
        Self {
            profile: TlsProfile::chrome149(),
        }
    }
}

impl TlsProfileBuilder {
    /// Set cipher suites (replaces all).
    pub fn cipher_suites(mut self, suites: Vec<String>) -> Self {
        self.profile.cipher_suites = suites;
        self
    }

    /// Add a cipher suite to the end.
    pub fn add_cipher(mut self, cipher: impl Into<String>) -> Self {
        self.profile.cipher_suites.push(cipher.into());
        self
    }

    /// Set supported groups (replaces all).
    pub fn supported_groups(mut self, groups: Vec<String>) -> Self {
        self.profile.supported_groups = groups;
        self
    }

    /// Set signature algorithms (colon-separated string).
    pub fn signature_algorithms(mut self, sigalgs: impl Into<String>) -> Self {
        self.profile.signature_algorithms = sigalgs.into();
        self
    }

    /// Enable or disable GREASE.
    pub fn grease(mut self, enabled: bool) -> Self {
        self.profile.grease = enabled;
        self
    }

    /// Enable or disable ALPS.
    pub fn alps(mut self, enabled: bool) -> Self {
        self.profile.alps = enabled;
        self
    }

    /// Set certificate compression algorithm.
    pub fn cert_compression(mut self, compression: CertCompression) -> Self {
        self.profile.cert_compression = compression;
        self
    }

    /// Enable or disable extension permutation.
    pub fn permute_extensions(mut self, enabled: bool) -> Self {
        self.profile.permute_extensions = enabled;
        self
    }

    /// Set ALPN protocols.
    pub fn alpn_protocols(mut self, protocols: Vec<String>) -> Self {
        self.profile.alpn_protocols = protocols;
        self
    }

    /// Set minimum TLS version.
    pub fn min_version(mut self, version: SslVersion) -> Self {
        self.profile.min_version = version;
        self
    }

    /// Set maximum TLS version.
    pub fn max_version(mut self, version: SslVersion) -> Self {
        self.profile.max_version = version;
        self
    }

    /// Build the final TlsProfile.
    pub fn build(self) -> TlsProfile {
        self.profile
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chrome149_has_correct_cipher_count() {
        let p = TlsProfile::chrome149();
        assert_eq!(p.cipher_suites.len(), 15);
    }

    #[test]
    fn test_chrome149_first_cipher_is_aes128() {
        let p = TlsProfile::chrome149();
        assert_eq!(p.cipher_suites[0], "TLS_AES_128_GCM_SHA256");
    }

    #[test]
    fn test_chrome149_has_pq_group() {
        let p = TlsProfile::chrome149();
        assert_eq!(p.supported_groups[0], "X25519MLKEM768");
    }

    #[test]
    fn test_builder_override() {
        let p = TlsProfile::chrome149()
            .customize()
            .grease(false)
            .build();
        assert!(!p.grease);
        // Other fields unchanged
        assert_eq!(p.cipher_suites.len(), 15);
    }

    #[test]
    fn test_builder_add_cipher() {
        let p = TlsProfile::builder()
            .add_cipher("CUSTOM_CIPHER")
            .build();
        assert!(p.cipher_suites.contains(&"CUSTOM_CIPHER".to_string()));
    }
}
