//! BoringSSL TLS layer with Chrome ClientHello fingerprint parity.
//!
//! Provides:
//! - Chrome cipher suite ordering
//! - GREASE values
//! - Extension permutation
//! - X25519MLKEM768 (post-quantum key exchange)
//! - Certificate compression (brotli)
//! - SNI + hostname verification (correct for CONNECT tunnels)

pub mod config;
pub mod connector;
pub mod error;

pub use config::TlsProfile;
pub use connector::TlsConnector;
pub use error::TlsError;
