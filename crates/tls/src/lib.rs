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
