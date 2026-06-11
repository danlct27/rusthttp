//! HTTP CONNECT proxy tunnel with authentication and rotation.
//!
//! Architecture:
//! 1. TCP connect to proxy
//! 2. Send HTTP/1.1 CONNECT target:443
//! 3. Read 200 response
//! 4. Hand socket to TLS layer (SNI = target, verify = target)
