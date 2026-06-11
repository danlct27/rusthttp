//! BoringSSL TLS layer with Chrome ClientHello fingerprint parity.
//!
//! # Features
//! - Chrome/Firefox/Safari/Edge/Opera/Samsung/QQ cipher suite ordering
//! - GREASE values (random per-handshake, RFC 8701)
//! - Extension permutation
//! - X25519MLKEM768 (post-quantum key exchange)
//! - Certificate compression (brotli/zlib)
//! - SNI + hostname verification (correct for CONNECT tunnels)
//! - Builder pattern for custom profile creation
//! - JSON profile loading from `profiles/` directory
//!
//! # Usage
//! ```no_run
//! use rusthttp_tls::{TlsProfile, TlsConnector, Profile, ProfileJson};
//!
//! // Option 1: Use preset
//! let connector = TlsConnector::new(TlsProfile::chrome149());
//!
//! // Option 2: Load from JSON
//! let json = ProfileJson::from_file("profiles/chrome-149.json").unwrap();
//! let profile = TlsProfile::from_json(&json).unwrap();
//! let connector = TlsConnector::new(profile);
//!
//! // Option 3: Customize
//! let profile = TlsProfile::chrome149()
//!     .customize()
//!     .grease(false)
//!     .alps(false)
//!     .build();
//! let connector = TlsConnector::new(profile);
//! ```

pub mod config;
pub mod connector;
pub mod error;
pub mod profile;

pub use config::{CertCompression, TlsProfile, TlsProfileBuilder, cipher_id, extension_type, validate_extension_order};
pub use connector::TlsConnector;
pub use error::{TlsError, SslAlert};
pub use profile::{Profile, ProfileJson, random_grease_value};
