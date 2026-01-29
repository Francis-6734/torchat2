//! Cryptographic primitives for TorChat 2.0.
//!
//! All cryptography uses well-audited primitives per spec section 5:
//!
//! - **X25519**: Key exchange (Diffie-Hellman)
//! - **Ed25519**: Digital signatures (identity)
//! - **ChaCha20-Poly1305**: Authenticated encryption (AEAD)
//! - **HKDF-SHA256**: Key derivation
//! - **Signal Double Ratchet**: Message encryption with PFS
//!
//! ## Security Properties
//!
//! - Perfect Forward Secrecy (PFS)
//! - Post-compromise security
//! - Message authentication and integrity
//! - Key zeroization on drop
//!
//! ## Forbidden
//!
//! - Custom cryptography
//! - Unaudited primitives
//! - Rolling your own anything

mod aead;
mod keys;
mod ratchet;
mod rotation;

pub use aead::{
    decrypt, decrypt_with_prepended_nonce, encrypt, encrypt_with_random_nonce, Nonce, NONCE_SIZE,
    TAG_SIZE,
};
pub use keys::{
    derive_shared_secret, EphemeralKeypair, SharedSecret, StaticKeypair, X25519PublicKey,
    X25519SecretKey, X25519_KEY_SIZE,
};
pub use ratchet::{DoubleRatchet, MessageKeys, RatchetHeader, RatchetState};
pub use rotation::{KeyRotationManager, RotationConfig, VersionedKey};

use crate::error::{Error, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Key size for ChaCha20-Poly1305.
pub const KEY_SIZE: usize = 32;

/// Derive keys using HKDF-SHA256.
///
/// This is the standard key derivation function used throughout TorChat.
pub fn hkdf_derive(
    salt: Option<&[u8]>,
    input_key_material: &[u8],
    info: &[u8],
    output_length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let hkdf = Hkdf::<Sha256>::new(salt, input_key_material);
    let mut output = Zeroizing::new(vec![0u8; output_length]);
    hkdf.expand(info, &mut output)
        .map_err(|_| Error::Crypto("HKDF expansion failed".into()))?;
    Ok(output)
}

/// Generate cryptographically secure random bytes.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    bytes
}

/// Constant-time comparison of byte slices.
///
/// Prevents timing attacks when comparing secrets.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_derive() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"TorChat key derivation";

        let out1 = hkdf_derive(Some(salt), ikm, info, 32).expect("should derive");
        assert_eq!(out1.len(), 32);

        // Deterministic
        let out2 = hkdf_derive(Some(salt), ikm, info, 32).expect("should derive");
        assert_eq!(&*out1, &*out2);

        // Different info -> different output
        let out3 = hkdf_derive(Some(salt), ikm, b"different", 32).expect("should derive");
        assert_ne!(&*out1, &*out3);
    }

    #[test]
    fn test_random_bytes() {
        let a: [u8; 32] = random_bytes();
        let b: [u8; 32] = random_bytes();
        assert_ne!(a, b);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hi"));
    }
}
