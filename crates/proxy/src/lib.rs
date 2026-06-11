//! HTTP CONNECT proxy tunnel with authentication and rotation.
//!
//! Establishes a TCP tunnel through an HTTP proxy via the CONNECT method.
//! The returned `TcpStream` is handed to the TLS layer which sets SNI and
//! certificate verification to the target hostname.

pub mod error;
pub mod rotation;
pub mod tunnel;

pub use error::ProxyError;
pub use rotation::{ProxyPool, RotationStrategy};
pub use tunnel::{establish_tunnel, ProxyConfig};
