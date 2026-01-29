//! Secure logging utilities with automatic sensitive data redaction.
//!
//! This module provides logging helpers that automatically redact sensitive
//! information like private keys, passwords, and onion addresses from log output.

use std::fmt;

/// A wrapper that redacts sensitive data when displayed.
pub struct Redacted<T>(pub T);

impl<T: fmt::Display> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl<T: fmt::Debug> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// Redact an onion address, showing only first and last 4 characters.
pub struct RedactedOnion<'a>(pub &'a str);

impl<'a> fmt::Display for RedactedOnion<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0;
        if s.len() > 12 {
            write!(f, "{}...{}", &s[..4], &s[s.len()-10..])
        } else {
            write!(f, "[REDACTED ONION]")
        }
    }
}

impl<'a> fmt::Debug for RedactedOnion<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Redact a byte slice, showing only length.
pub struct RedactedBytes<'a>(pub &'a [u8]);

impl<'a> fmt::Display for RedactedBytes<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{} bytes]", self.0.len())
    }
}

impl<'a> fmt::Debug for RedactedBytes<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Redact a hex string, showing only first and last 4 characters.
pub struct RedactedHex<'a>(pub &'a str);

impl<'a> fmt::Display for RedactedHex<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0;
        if s.len() > 12 {
            write!(f, "{}...{}", &s[..4], &s[s.len()-4..])
        } else {
            write!(f, "[REDACTED HEX]")
        }
    }
}

/// Patterns that should be redacted from logs.
const SENSITIVE_PATTERNS: &[&str] = &[
    "password",
    "secret",
    "private",
    "key",
    "token",
    "auth",
    "credential",
];

/// Check if a string appears to contain sensitive data.
pub fn appears_sensitive(s: &str) -> bool {
    let lower = s.to_lowercase();
    SENSITIVE_PATTERNS.iter().any(|p| lower.contains(p))
}

/// Sanitize a string for logging, redacting sensitive patterns.
pub fn sanitize_for_log(s: &str) -> String {
    if appears_sensitive(s) {
        "[REDACTED]".to_string()
    } else {
        s.to_string()
    }
}

/// A secure log event that can be serialized without leaking secrets.
#[derive(Debug)]
pub struct SecureLogEvent {
    /// Timestamp (Unix seconds)
    pub timestamp: i64,
    /// Log level
    pub level: LogLevel,
    /// Module/component name
    pub module: String,
    /// Log message (sanitized)
    pub message: String,
}

/// Log level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Trace-level logging (very verbose)
    Trace,
    /// Debug information
    Debug,
    /// Normal informational messages
    Info,
    /// Warnings that don't prevent operation
    Warn,
    /// Errors that may affect operation
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "TRACE"),
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redacted_display() {
        let secret = Redacted("my_secret_password");
        assert_eq!(format!("{}", secret), "[REDACTED]");
    }

    #[test]
    fn test_redacted_onion() {
        let onion = RedactedOnion("abcd1234567890abcdefghijklmnopqrstuvwxyz1234567890abcd.onion");
        let displayed = format!("{}", onion);
        assert!(displayed.contains("abcd"));
        assert!(displayed.contains(".onion"));
        assert!(displayed.contains("..."));
    }

    #[test]
    fn test_appears_sensitive() {
        assert!(appears_sensitive("user_password"));
        assert!(appears_sensitive("secret_key"));
        assert!(appears_sensitive("auth_token"));
        assert!(!appears_sensitive("hello_world"));
        assert!(!appears_sensitive("message_count"));
    }

    #[test]
    fn test_sanitize_for_log() {
        assert_eq!(sanitize_for_log("hello"), "hello");
        assert_eq!(sanitize_for_log("password123"), "[REDACTED]");
        assert_eq!(sanitize_for_log("my_secret"), "[REDACTED]");
    }
}
