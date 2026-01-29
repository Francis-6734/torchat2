//! Error types for TorChat 2.0.
//!
//! All errors are designed to avoid leaking sensitive information.
//! Error messages are intentionally generic for security.

use thiserror::Error;

/// Core error type for TorChat operations.
#[derive(Error, Debug)]
pub enum Error {
    /// Cryptographic operation failed.
    /// Details are intentionally vague to prevent oracle attacks.
    #[error("cryptographic operation failed")]
    Crypto(String),

    /// Key validation or derivation failed.
    #[error("invalid key material")]
    InvalidKey(String),

    /// Identity-related error.
    #[error("identity error")]
    Identity(String),

    /// Wire protocol error.
    /// Malformed packets are silently dropped per spec.
    #[error("protocol error")]
    Protocol(String),

    /// Message validation failed.
    #[error("invalid message")]
    InvalidMessage(String),

    /// Storage operation failed.
    #[error("storage error")]
    Storage(String),

    /// Tor connection or circuit error.
    #[error("tor error")]
    Tor(String),

    /// Encoding/decoding error.
    #[error("encoding error")]
    Encoding(String),

    /// Ratchet state error.
    #[error("ratchet error")]
    Ratchet(String),

    /// Session not established.
    #[error("no active session")]
    NoSession,

    /// Operation timed out.
    #[error("operation timed out")]
    Timeout,

    /// Rate limit exceeded.
    #[error("rate limit exceeded")]
    RateLimited,

    /// Resource not found.
    #[error("not found")]
    NotFound(String),
}

/// Result type alias using TorChat's Error.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Check if this error should cause silent packet drop (per spec).
    /// Protocol errors on malformed input are silently dropped.
    pub fn should_silent_drop(&self) -> bool {
        matches!(self, Error::Protocol(_) | Error::InvalidMessage(_))
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Storage(e.to_string())
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Storage(e.to_string())
    }
}
