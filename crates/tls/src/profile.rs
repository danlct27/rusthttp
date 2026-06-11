//! Browser profile definitions and JSON loader.

use rand::Rng;
use serde::Deserialize;
use std::path::Path;

use crate::TlsError;

/// All supported browser profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Profile {
    // Tier 1 — Primary targets
    Chrome149,
    Chrome148,
    Chrome149Android,
    Chrome149Ios,
    Firefox151,
    Firefox150,
    Firefox151Android,
    Safari26,
    Safari26Ios,
    Safari26Ipad,
    Edge149,
    // Tier 2 — Regional/alternative
    Brave191,
    Opera132,
    Samsung30,
    Vivaldi7,
    Yandex25,
    QQ15,
    UC16,
    DuckDuckGo,
    // Special
    Custom,
}

impl Profile {
    /// Returns the JSON filename for this profile.
    pub fn filename(&self) -> &'static str {
        match self {
            Self::Chrome149 => "chrome-149.json",
            Self::Chrome148 => "chrome-148.json",
            Self::Chrome149Android => "chrome-149-android.json",
            Self::Chrome149Ios => "chrome-149-ios.json",
            Self::Firefox151 => "firefox-151.json",
            Self::Firefox150 => "firefox-150.json",
            Self::Firefox151Android => "firefox-151-android.json",
            Self::Safari26 => "safari-26.json",
            Self::Safari26Ios => "safari-26-ios.json",
            Self::Safari26Ipad => "safari-26-ipad.json",
            Self::Edge149 => "edge-149.json",
            Self::Brave191 => "brave-1.91.json",
            Self::Opera132 => "opera-132.json",
            Self::Samsung30 => "samsung-30.json",
            Self::Vivaldi7 => "vivaldi-7.json",
            Self::Yandex25 => "yandex-25.json",
            Self::QQ15 => "qq-15.json",
            Self::UC16 => "uc-16.json",
            Self::DuckDuckGo => "duckduckgo-ios.json",
            Self::Custom => "",
        }
    }

    /// List all available profiles.
    pub fn all() -> &'static [Profile] {
        &[
            Self::Chrome149,
            Self::Chrome148,
            Self::Firefox151,
            Self::Firefox150,
            Self::Safari26,
            Self::Edge149,
            Self::Brave191,
            Self::Opera132,
            Self::Samsung30,
        ]
    }

    /// Pick a random mainstream profile.
    pub fn random_mainstream() -> Self {
        let profiles = [Self::Chrome149, Self::Firefox151, Self::Safari26, Self::Edge149];
        profiles[rand::thread_rng().gen_range(0..profiles.len())]
    }
}

/// Raw JSON structure matching profiles/*.json files.
#[derive(Debug, Deserialize)]
pub struct ProfileJson {
    #[serde(rename = "_meta")]
    pub meta: ProfileMeta,
    pub tls: TlsSection,
    pub h2: Option<H2Section>,
    pub http_headers: Option<HttpHeadersSection>,
}

#[derive(Debug, Deserialize)]
pub struct ProfileMeta {
    pub browser: String,
    pub version: String,
    pub captured: Option<String>,
    pub os: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TlsSection {
    pub cipher_suites: Vec<String>,
    pub extensions_order: Option<Vec<String>>,
    pub supported_groups: Vec<String>,
    pub signature_algorithms: Vec<String>,
    #[serde(default)]
    pub grease: GreaseConfig,
    #[serde(default)]
    pub alps: AlpsConfig,
    pub compress_certificate_algorithms: Option<Vec<String>>,
    pub record_size_limit: Option<u16>,
    pub min_version: Option<String>,
    pub max_version: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct GreaseConfig {
    #[serde(default)]
    pub enabled: bool,
    pub cipher_position: Option<usize>,
    pub extension_positions: Option<Vec<usize>>,
}

#[derive(Debug, Default, Deserialize)]
pub struct AlpsConfig {
    #[serde(default)]
    pub enabled: bool,
    pub protocols: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct H2Section {
    pub settings: Vec<H2Setting>,
    pub window_update: Option<u32>,
    pub pseudo_header_order: Option<Vec<String>>,
    pub header_order: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct H2Setting {
    pub id: u16,
    pub name: Option<String>,
    pub value: u32,
}

#[derive(Debug, Deserialize)]
pub struct HttpHeadersSection {
    pub user_agent: Option<String>,
    pub sec_ch_ua: Option<String>,
    pub sec_ch_ua_mobile: Option<String>,
    pub sec_ch_ua_platform: Option<String>,
    pub accept: Option<String>,
    pub accept_language: Option<String>,
    pub accept_encoding: Option<String>,
}

impl ProfileJson {
    /// Load a profile from a JSON file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, TlsError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| TlsError::ConfigMsg(format!("Failed to read profile: {e}")))?;
        Self::from_str(&content)
    }

    /// Parse a profile from a JSON string.
    pub fn from_str(json: &str) -> Result<Self, TlsError> {
        let profile: Self = serde_json::from_str(json)
            .map_err(|e| TlsError::ConfigMsg(format!("Failed to parse profile JSON: {e}")))?;
        profile.validate()?;
        Ok(profile)
    }

    /// Validate that required fields are non-empty.
    fn validate(&self) -> Result<(), TlsError> {
        if self.tls.cipher_suites.is_empty() {
            return Err(TlsError::ConfigMsg("cipher_suites must not be empty".into()));
        }
        if self.tls.supported_groups.is_empty() {
            return Err(TlsError::ConfigMsg("supported_groups must not be empty".into()));
        }
        if self.tls.signature_algorithms.is_empty() {
            return Err(TlsError::ConfigMsg("signature_algorithms must not be empty".into()));
        }
        Ok(())
    }

    /// Load a built-in profile by enum.
    pub fn load(profile: Profile, profiles_dir: impl AsRef<Path>) -> Result<Self, TlsError> {
        let filename = profile.filename();
        if filename.is_empty() {
            return Err(TlsError::ConfigMsg("Custom profile requires explicit path".into()));
        }
        let path = profiles_dir.as_ref().join(filename);
        Self::from_file(path)
    }
}

/// Generate a random GREASE value (RFC 8701).
pub fn random_grease_value() -> u16 {
    let grease_values: [u16; 8] = [
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    ];
    grease_values[rand::thread_rng().gen_range(0..grease_values.len())]
}

/// Generate a random GREASE cipher suite.
pub fn random_grease_cipher() -> u16 {
    random_grease_value()
}

/// Generate a random GREASE extension type.
pub fn random_grease_extension() -> u16 {
    random_grease_value()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_filename() {
        assert_eq!(Profile::Chrome149.filename(), "chrome-149.json");
        assert_eq!(Profile::Firefox151.filename(), "firefox-151.json");
    }

    #[test]
    fn test_random_grease() {
        for _ in 0..100 {
            let v = random_grease_value();
            assert_eq!(v & 0x0f0f, 0x0a0a, "GREASE value should match pattern");
        }
    }
}
