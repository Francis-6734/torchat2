//! Identity management for TorChat 2.0.
//!
//! Identity is derived directly from Tor v3 onion service keypairs.
//! There are no usernames, emails, phone numbers, or recovery mechanisms.
//!
//! ## Identity Properties (Spec Section 4)
//!
//! - Ed25519 public key (32 bytes)
//! - Onion address as stable identifier (56 chars + ".onion")
//! - SHA-256 fingerprint for manual verification
//! - Identity persists until user explicitly resets
//!
//! ## Security
//!
//! - Secret keys are zeroized on drop
//! - No identity recovery mechanism (by design)
//! - Fingerprints enable out-of-band verification
//!
//! ## Automatic Identity
//!
//! For the simplest setup, use auto-init which generates and stores
//! identity automatically on first run:
//!
//! ```ignore
//! use torchat_core::identity::{auto_init, AutoIdentity};
//! let auto = auto_init("~/.torchat")?;
//! println!("Your address: {}", auto.identity().unwrap().onion_address());
//! ```

mod auto;
mod onion;

pub use auto::{auto_init, AutoIdentity};
pub use onion::{OnionAddress, TorIdentity};

use crate::error::Result;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// Generate a new random TorChat identity.
///
/// Creates a new Ed25519 keypair for use as a Tor v3 onion service identity.
/// The identity is permanent - there is no recovery if lost.
pub fn generate_identity() -> Result<TorIdentity> {
    let signing_key = SigningKey::generate(&mut OsRng);
    TorIdentity::from_signing_key(signing_key)
}

/// Compute SHA-256 fingerprint of a public key.
///
/// Returns a hex-encoded string that users can compare out-of-band
/// to verify they're communicating with the intended peer.
pub fn compute_fingerprint(public_key: &VerifyingKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key.as_bytes());
    let hash = hasher.finalize();
    hex::encode(hash)
}

/// Format a fingerprint for human-readable display.
///
/// Splits into groups of 4 characters for easier verbal comparison.
/// Example: "a1b2c3d4 e5f6g7h8 ..."
pub fn format_fingerprint(fingerprint: &str) -> String {
    fingerprint
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let identity = generate_identity().expect("should generate");

        // Onion address should be valid v3 format
        let onion = identity.onion_address();
        assert!(onion.as_str().ends_with(".onion"));
        assert_eq!(onion.as_str().len(), 62); // 56 + ".onion"

        // Fingerprint should be 64 hex chars (SHA-256)
        assert_eq!(identity.fingerprint().len(), 64);
    }

    #[test]
    fn test_identity_persistence() {
        let id1 = generate_identity().expect("should generate");
        let secret = id1.secret_key_bytes();

        let id2 = TorIdentity::from_secret_bytes(&secret).expect("should restore");

        assert_eq!(id1.onion_address(), id2.onion_address());
        assert_eq!(id1.fingerprint(), id2.fingerprint());
    }

    #[test]
    fn test_fingerprint_formatting() {
        let fp = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let formatted = format_fingerprint(fp);
        assert!(formatted.contains(' '));
        assert_eq!(formatted.split(' ').count(), 16);
    }
}
