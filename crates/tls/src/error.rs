//! TLS error types for the `rusthttp-tls` crate.

/// Errors that can occur during TLS connection establishment.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// BoringSSL configuration error.
    #[error("tls config error: {0}")]
    Config(#[from] boring::error::ErrorStack),

    /// Configuration error with message.
    #[error("tls config error: {0}")]
    ConfigMsg(String),

    /// TLS handshake failed.
    #[error("tls handshake failed for {host}: {detail}")]
    Handshake { host: String, detail: String },

    /// SNI hostname is invalid.
    #[error("invalid sni hostname: {0}")]
    InvalidHostname(String),

    /// Invalid cipher suite name.
    #[error("invalid cipher suite: {0}")]
    InvalidCipher(String),

    /// Invalid curve/group name.
    #[error("invalid curve/group: {0}")]
    InvalidCurve(String),

    /// Invalid extension in profile.
    #[error("invalid extension: {0}")]
    InvalidExtension(String),
}

/// TLS alert descriptions (RFC 5246 §7.2 + RFC 8446 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SslAlert {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    RecordOverflow = 22,
    HandshakeFailure = 40,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    ECHRequired = 121,
}

impl SslAlert {
    /// Try to convert a raw alert byte to an enum variant.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::CloseNotify),
            10 => Some(Self::UnexpectedMessage),
            20 => Some(Self::BadRecordMac),
            22 => Some(Self::RecordOverflow),
            40 => Some(Self::HandshakeFailure),
            42 => Some(Self::BadCertificate),
            43 => Some(Self::UnsupportedCertificate),
            44 => Some(Self::CertificateRevoked),
            45 => Some(Self::CertificateExpired),
            46 => Some(Self::CertificateUnknown),
            47 => Some(Self::IllegalParameter),
            48 => Some(Self::UnknownCa),
            49 => Some(Self::AccessDenied),
            50 => Some(Self::DecodeError),
            51 => Some(Self::DecryptError),
            70 => Some(Self::ProtocolVersion),
            71 => Some(Self::InsufficientSecurity),
            80 => Some(Self::InternalError),
            86 => Some(Self::InappropriateFallback),
            90 => Some(Self::UserCanceled),
            109 => Some(Self::MissingExtension),
            110 => Some(Self::UnsupportedExtension),
            112 => Some(Self::UnrecognizedName),
            113 => Some(Self::BadCertificateStatusResponse),
            121 => Some(Self::ECHRequired),
            _ => None,
        }
    }

    /// Human-readable description of the alert.
    pub fn description(&self) -> &'static str {
        match self {
            Self::CloseNotify => "close_notify",
            Self::UnexpectedMessage => "unexpected_message",
            Self::BadRecordMac => "bad_record_mac",
            Self::RecordOverflow => "record_overflow",
            Self::HandshakeFailure => "handshake_failure",
            Self::BadCertificate => "bad_certificate",
            Self::UnsupportedCertificate => "unsupported_certificate",
            Self::CertificateRevoked => "certificate_revoked",
            Self::CertificateExpired => "certificate_expired",
            Self::CertificateUnknown => "certificate_unknown",
            Self::IllegalParameter => "illegal_parameter",
            Self::UnknownCa => "unknown_ca",
            Self::AccessDenied => "access_denied",
            Self::DecodeError => "decode_error",
            Self::DecryptError => "decrypt_error",
            Self::ProtocolVersion => "protocol_version",
            Self::InsufficientSecurity => "insufficient_security",
            Self::InternalError => "internal_error",
            Self::InappropriateFallback => "inappropriate_fallback",
            Self::UserCanceled => "user_canceled",
            Self::MissingExtension => "missing_extension",
            Self::UnsupportedExtension => "unsupported_extension",
            Self::UnrecognizedName => "unrecognized_name",
            Self::BadCertificateStatusResponse => "bad_certificate_status_response",
            Self::ECHRequired => "ech_required",
        }
    }
}
