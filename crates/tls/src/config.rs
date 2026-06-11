//! TLS fingerprint configuration — browser profiles.
//!
//! Supports:
//! - Preset profiles (Chrome, Firefox, Safari, etc.)
//! - JSON-loaded profiles
//! - Builder pattern for custom overrides
//! - Random GREASE per-handshake
//! - Extension order validation against known browser orders

use boring::ssl::SslVersion;
use tracing::warn;

use crate::error::TlsError;
use crate::profile::{ProfileJson, TlsSection};

// --- Cipher Suite ID Constants (IANA TLS registry) ---

/// TLS 1.3 cipher suite IDs.
pub mod cipher_id {
    /// TLS_AES_128_GCM_SHA256
    pub const TLS13_AES_128_GCM_SHA256: u16 = 0x1301;
    /// TLS_AES_256_GCM_SHA384
    pub const TLS13_AES_256_GCM_SHA384: u16 = 0x1302;
    /// TLS_CHACHA20_POLY1305_SHA256
    pub const TLS13_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
    /// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    pub const ECDHE_ECDSA_AES_128_GCM_SHA256: u16 = 0xC02B;
    /// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    pub const ECDHE_RSA_AES_128_GCM_SHA256: u16 = 0xC02F;
    /// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    pub const ECDHE_ECDSA_AES_256_GCM_SHA384: u16 = 0xC02C;
    /// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    pub const ECDHE_RSA_AES_256_GCM_SHA384: u16 = 0xC030;
    /// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    pub const ECDHE_ECDSA_CHACHA20_POLY1305: u16 = 0xCCA9;
    /// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    pub const ECDHE_RSA_CHACHA20_POLY1305: u16 = 0xCCA8;
    /// TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    pub const ECDHE_RSA_AES_128_CBC_SHA: u16 = 0xC013;
    /// TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    pub const ECDHE_RSA_AES_256_CBC_SHA: u16 = 0xC014;
    /// TLS_RSA_WITH_AES_128_GCM_SHA256
    pub const RSA_AES_128_GCM_SHA256: u16 = 0x009C;
    /// TLS_RSA_WITH_AES_256_GCM_SHA384
    pub const RSA_AES_256_GCM_SHA384: u16 = 0x009D;
    /// TLS_RSA_WITH_AES_128_CBC_SHA
    pub const RSA_AES_128_CBC_SHA: u16 = 0x002F;
    /// TLS_RSA_WITH_AES_256_CBC_SHA
    pub const RSA_AES_256_CBC_SHA: u16 = 0x0035;

    /// Map a cipher suite name to its IANA ID. Returns `None` for unknown names.
    pub fn from_name(name: &str) -> Option<u16> {
        match name {
            "TLS_AES_128_GCM_SHA256" => Some(TLS13_AES_128_GCM_SHA256),
            "TLS_AES_256_GCM_SHA384" => Some(TLS13_AES_256_GCM_SHA384),
            "TLS_CHACHA20_POLY1305_SHA256" => Some(TLS13_CHACHA20_POLY1305_SHA256),
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => Some(ECDHE_ECDSA_AES_128_GCM_SHA256),
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => Some(ECDHE_RSA_AES_128_GCM_SHA256),
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => Some(ECDHE_ECDSA_AES_256_GCM_SHA384),
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => Some(ECDHE_RSA_AES_256_GCM_SHA384),
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => Some(ECDHE_ECDSA_CHACHA20_POLY1305),
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => Some(ECDHE_RSA_CHACHA20_POLY1305),
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" => Some(ECDHE_RSA_AES_128_CBC_SHA),
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" => Some(ECDHE_RSA_AES_256_CBC_SHA),
            "TLS_RSA_WITH_AES_128_GCM_SHA256" => Some(RSA_AES_128_GCM_SHA256),
            "TLS_RSA_WITH_AES_256_GCM_SHA384" => Some(RSA_AES_256_GCM_SHA384),
            "TLS_RSA_WITH_AES_128_CBC_SHA" => Some(RSA_AES_128_CBC_SHA),
            "TLS_RSA_WITH_AES_256_CBC_SHA" => Some(RSA_AES_256_CBC_SHA),
            _ => None,
        }
    }

    /// Map a cipher suite IANA ID to its name. Returns `None` for unknown IDs.
    pub fn to_name(id: u16) -> Option<&'static str> {
        match id {
            TLS13_AES_128_GCM_SHA256 => Some("TLS_AES_128_GCM_SHA256"),
            TLS13_AES_256_GCM_SHA384 => Some("TLS_AES_256_GCM_SHA384"),
            TLS13_CHACHA20_POLY1305_SHA256 => Some("TLS_CHACHA20_POLY1305_SHA256"),
            ECDHE_ECDSA_AES_128_GCM_SHA256 => Some("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
            ECDHE_RSA_AES_128_GCM_SHA256 => Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
            ECDHE_ECDSA_AES_256_GCM_SHA384 => Some("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
            ECDHE_RSA_AES_256_GCM_SHA384 => Some("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
            ECDHE_ECDSA_CHACHA20_POLY1305 => Some("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
            ECDHE_RSA_CHACHA20_POLY1305 => Some("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
            ECDHE_RSA_AES_128_CBC_SHA => Some("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
            ECDHE_RSA_AES_256_CBC_SHA => Some("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
            RSA_AES_128_GCM_SHA256 => Some("TLS_RSA_WITH_AES_128_GCM_SHA256"),
            RSA_AES_256_GCM_SHA384 => Some("TLS_RSA_WITH_AES_256_GCM_SHA384"),
            RSA_AES_128_CBC_SHA => Some("TLS_RSA_WITH_AES_128_CBC_SHA"),
            RSA_AES_256_CBC_SHA => Some("TLS_RSA_WITH_AES_256_CBC_SHA"),
            _ => None,
        }
    }
}

/// Chrome 149 expected extension order (excluding GREASE placeholders).
const CHROME_149_EXTENSION_ORDER: &[&str] = &[
    "server_name",
    "extended_master_secret",
    "renegotiation_info",
    "supported_groups",
    "ec_point_formats",
    "session_ticket",
    "application_layer_protocol_negotiation",
    "status_request",
    "delegated_credentials",
    "key_share",
    "supported_versions",
    "signature_algorithms",
    "psk_key_exchange_modes",
    "record_size_limit",
    "padding",
    "compress_certificate",
    "application_settings",
];

/// Validate that the configured extension order matches Chrome's expected order.
///
/// Logs a warning if extensions differ. GREASE entries are stripped before comparison.
pub fn validate_extension_order(extensions: &[String]) {
    let filtered: Vec<&str> = extensions
        .iter()
        .map(|s| s.as_str())
        .filter(|s| *s != "grease")
        .collect();

    if filtered.as_slice() != CHROME_149_EXTENSION_ORDER {
        warn!(
            expected = ?CHROME_149_EXTENSION_ORDER,
            actual = ?filtered,
            "extension order differs from Chrome 149"
        );
    }
}

/// Certificate compression algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertCompression {
    /// No certificate compression.
    None,
    /// Brotli compression (used by Chrome).
    Brotli,
    /// Zlib compression.
    Zlib,
}

/// A TLS fingerprint profile describing how the ClientHello should look.
///
/// Contains all parameters needed to construct a browser-matching TLS ClientHello.
/// Use [`TlsProfile::chrome149()`] for a ready-made profile, or
/// [`TlsProfile::builder()`] for custom configurations.
///
/// # Clone cost
/// This type derives `Clone` because connectors may need to share profiles across
/// connections. The cost is proportional to the number of cipher suites and groups
/// (typically ~15 short strings). For hot paths, wrap in `Arc` instead.
///
/// # Examples
///
/// ```rust
/// use rusthttp_tls::TlsProfile;
///
/// // Use preset
/// let profile = TlsProfile::chrome149();
///
/// // Customize from preset
/// let custom = TlsProfile::chrome149()
///     .customize()
///     .grease(false)
///     .alps(false)
///     .build();
/// ```
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
    /// ALPN protocols to advertise (e.g., `["h2", "http/1.1"]`).
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
    ///
    /// Validates extension order against Chrome's expected order and logs a warning
    /// if they differ.
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

        // Validate extension order if provided
        if let Some(ref extensions) = tls.extensions_order {
            validate_extension_order(extensions);
        }

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

    /// Create a new builder starting from the Chrome 149 defaults.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rusthttp_tls::TlsProfile;
    ///
    /// let profile = TlsProfile::builder()
    ///     .grease(false)
    ///     .alps(false)
    ///     .build();
    /// assert!(!profile.grease);
    /// ```
    pub fn builder() -> TlsProfileBuilder {
        TlsProfileBuilder::default()
    }

    /// Create a builder pre-filled with this profile's settings.
    pub fn customize(self) -> TlsProfileBuilder {
        TlsProfileBuilder { profile: self }
    }
}

/// Known supported curves/groups for validation.
const KNOWN_GROUPS: &[&str] = &[
    "X25519MLKEM768", "X25519", "P-256", "P-384", "P-521",
];

/// Known valid TLS extension names.
const KNOWN_EXTENSIONS: &[&str] = &[
    "server_name", "extended_master_secret", "renegotiation_info",
    "supported_groups", "ec_point_formats", "session_ticket",
    "application_layer_protocol_negotiation", "status_request",
    "delegated_credentials", "key_share", "supported_versions",
    "signature_algorithms", "psk_key_exchange_modes", "record_size_limit",
    "padding", "compress_certificate", "application_settings", "grease",
];

impl TryFrom<ProfileJson> for TlsProfile {
    type Error = TlsError;

    fn try_from(json: ProfileJson) -> Result<Self, Self::Error> {
        TlsProfile::try_from(&json)
    }
}

impl TryFrom<&ProfileJson> for TlsProfile {
    type Error = TlsError;

    fn try_from(json: &ProfileJson) -> Result<Self, Self::Error> {
        // Validate cipher suites exist
        if json.tls.cipher_suites.is_empty() {
            return Err(TlsError::ConfigMsg("cipher_suites must not be empty".into()));
        }
        for cipher in &json.tls.cipher_suites {
            if cipher_id::from_name(cipher).is_none() {
                return Err(TlsError::InvalidCipher(cipher.clone()));
            }
        }

        // Validate supported groups
        if json.tls.supported_groups.is_empty() {
            return Err(TlsError::ConfigMsg("supported_groups must not be empty".into()));
        }
        for group in &json.tls.supported_groups {
            if !KNOWN_GROUPS.contains(&group.as_str()) {
                return Err(TlsError::InvalidCurve(group.clone()));
            }
        }

        // Validate extensions if provided
        if let Some(ref extensions) = json.tls.extensions_order {
            for ext in extensions {
                if !KNOWN_EXTENSIONS.contains(&ext.as_str()) {
                    return Err(TlsError::InvalidExtension(ext.clone()));
                }
            }
        }

        // Validate signature algorithms non-empty
        if json.tls.signature_algorithms.is_empty() {
            return Err(TlsError::ConfigMsg("signature_algorithms must not be empty".into()));
        }

        TlsProfile::from_tls_section(&json.tls)
    }
}

/// Builder for constructing custom TLS profiles with fine-grained control.
///
/// # Examples
///
/// ```rust
/// use rusthttp_tls::{TlsProfile, TlsProfileBuilder};
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

    #[test]
    fn test_builder_default_is_chrome149() {
        let p = TlsProfile::builder().build();
        assert!(p.grease);
        assert!(p.alps);
        assert_eq!(p.cert_compression, CertCompression::Brotli);
    }

    #[test]
    fn test_builder_set_cipher_suites_replaces_all() {
        let p = TlsProfile::builder()
            .cipher_suites(vec!["ONLY_ONE".into()])
            .build();
        assert_eq!(p.cipher_suites, vec!["ONLY_ONE"]);
    }

    #[test]
    fn test_builder_set_supported_groups() {
        let p = TlsProfile::builder()
            .supported_groups(vec!["X25519".into()])
            .build();
        assert_eq!(p.supported_groups, vec!["X25519"]);
    }

    #[test]
    fn test_builder_alpn_protocols() {
        let p = TlsProfile::builder()
            .alpn_protocols(vec!["h2".into()])
            .build();
        assert_eq!(p.alpn_protocols, vec!["h2"]);
    }

    #[test]
    fn test_cipher_id_from_name() {
        assert_eq!(cipher_id::from_name("TLS_AES_128_GCM_SHA256"), Some(0x1301));
        assert_eq!(cipher_id::from_name("TLS_AES_256_GCM_SHA384"), Some(0x1302));
        assert_eq!(cipher_id::from_name("UNKNOWN"), None);
    }

    #[test]
    fn test_cipher_id_to_name() {
        assert_eq!(cipher_id::to_name(0x1301), Some("TLS_AES_128_GCM_SHA256"));
        assert_eq!(cipher_id::to_name(0xFFFF), None);
    }

    #[test]
    fn test_cipher_id_roundtrip() {
        let name = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        let id = cipher_id::from_name(name).unwrap();
        assert_eq!(cipher_id::to_name(id), Some(name));
    }

    #[test]
    fn test_validate_extension_order_correct() {
        // Should not panic/warn for correct order
        let correct: Vec<String> = CHROME_149_EXTENSION_ORDER
            .iter()
            .map(|s| s.to_string())
            .collect();
        validate_extension_order(&correct);
    }

    #[test]
    fn test_validate_extension_order_with_grease() {
        // GREASE entries should be stripped before comparison
        let mut order: Vec<String> = vec!["grease".into()];
        order.extend(CHROME_149_EXTENSION_ORDER.iter().map(|s| s.to_string()));
        order.push("grease".into());
        validate_extension_order(&order);
    }

    #[test]
    fn test_from_tls_section_basic() {
        let tls = TlsSection {
            cipher_suites: vec!["TLS_AES_128_GCM_SHA256".into()],
            extensions_order: None,
            supported_groups: vec!["X25519".into()],
            signature_algorithms: vec!["ecdsa_secp256r1_sha256".into()],
            grease: Default::default(),
            alps: Default::default(),
            compress_certificate_algorithms: Some(vec!["brotli".into()]),
            record_size_limit: None,
            min_version: None,
            max_version: None,
        };
        let profile = TlsProfile::from_tls_section(&tls).unwrap();
        assert_eq!(profile.cipher_suites, vec!["TLS_AES_128_GCM_SHA256"]);
        assert_eq!(profile.cert_compression, CertCompression::Brotli);
    }
}
