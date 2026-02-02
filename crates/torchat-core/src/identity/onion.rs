//! Tor v3 onion address derivation and identity management.
//!
//! Tor v3 (.onion) addresses are derived from Ed25519 public keys:
//!
//! 1. Compute checksum: SHA3-256(".onion checksum" || pubkey || version)[..2]
//! 2. Encode: base32(pubkey || checksum || version)
//! 3. Append ".onion"
//!
//! This produces a 56-character address + ".onion" suffix.

use crate::error::{Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha3::Sha3_256;
use std::fmt;
use zeroize::ZeroizeOnDrop;

/// Tor v3 onion service version byte.
const ONION_VERSION: u8 = 0x03;

/// Checksum prefix per Tor spec.
const CHECKSUM_PREFIX: &[u8] = b".onion checksum";

/// A Tor v3 onion address.
///
/// Format: `<56 base32 chars>.onion`
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OnionAddress(String);

impl OnionAddress {
    /// Parse and validate an onion address string.
    ///
    /// Validates format but does not verify cryptographic correctness
    /// (use `extract_public_key` and verify checksum for that).
    pub fn from_string(s: impl Into<String>) -> Result<Self> {
        let s = s.into().to_lowercase();

        if !s.ends_with(".onion") {
            return Err(Error::Identity("must end with .onion".into()));
        }

        let addr_part = &s[..s.len() - 6];
        if addr_part.len() != 56 {
            return Err(Error::Identity("v3 address must be 56 characters".into()));
        }

        // Validate base32
        if base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &addr_part.to_uppercase())
            .is_none()
        {
            return Err(Error::Identity("invalid base32 encoding".into()));
        }

        Ok(Self(s))
    }

    /// Get the full address as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get just the hostname (without .onion suffix).
    pub fn hostname(&self) -> &str {
        &self.0[..56]
    }

    /// Derive an onion address from an Ed25519 public key.
    pub fn from_public_key(public_key: &VerifyingKey) -> Self {
        let pubkey_bytes = public_key.as_bytes();

        // Checksum: SHA3-256(".onion checksum" || pubkey || version)[..2]
        let mut hasher = Sha3_256::new();
        hasher.update(CHECKSUM_PREFIX);
        hasher.update(pubkey_bytes);
        hasher.update([ONION_VERSION]);
        let checksum = hasher.finalize();

        // Address bytes: pubkey (32) || checksum (2) || version (1) = 35 bytes
        let mut addr_bytes = [0u8; 35];
        addr_bytes[..32].copy_from_slice(pubkey_bytes);
        addr_bytes[32..34].copy_from_slice(&checksum[..2]);
        addr_bytes[34] = ONION_VERSION;

        // Base32 encode -> 56 characters
        let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &addr_bytes);

        Self(format!("{}.onion", encoded.to_lowercase()))
    }

    /// Extract and verify the public key from this onion address.
    ///
    /// Returns error if checksum doesn't match or key is invalid.
    pub fn extract_public_key(&self) -> Result<VerifyingKey> {
        let decoded = base32::decode(
            base32::Alphabet::Rfc4648 { padding: false },
            &self.hostname().to_uppercase(),
        )
        .ok_or_else(|| Error::Identity("invalid base32".into()))?;

        if decoded.len() != 35 {
            return Err(Error::Identity("invalid address length".into()));
        }

        // Check version
        if decoded[34] != ONION_VERSION {
            return Err(Error::Identity("unsupported onion version".into()));
        }

        // Extract public key
        let pubkey_bytes: [u8; 32] = decoded[..32]
            .try_into()
            .map_err(|_| Error::Identity("invalid key length".into()))?;

        let public_key = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| Error::Identity(format!("invalid public key: {}", e)))?;

        // Verify checksum
        let mut hasher = Sha3_256::new();
        hasher.update(CHECKSUM_PREFIX);
        hasher.update(&pubkey_bytes);
        hasher.update([ONION_VERSION]);
        let expected = hasher.finalize();

        if decoded[32..34] != expected[..2] {
            return Err(Error::Identity("checksum mismatch".into()));
        }

        Ok(public_key)
    }
}

impl fmt::Display for OnionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for OnionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OnionAddress({})", self.0)
    }
}

/// A complete TorChat identity with Ed25519 keypair.
///
/// This is the user's persistent identity. The secret key is:
/// - Zeroized on drop
/// - Never transmitted
/// - Encrypted before storage
///
/// Loss of the secret key means loss of identity (by design).
#[derive(ZeroizeOnDrop)]
pub struct TorIdentity {
    #[zeroize(skip)] // SigningKey has its own zeroization
    signing_key: SigningKey,
    /// X25519 secret key for ECDH (used for group epoch key encryption).
    x25519_secret: x25519_dalek::StaticSecret,
    #[zeroize(skip)]
    onion_address: OnionAddress,
    #[zeroize(skip)]
    fingerprint: String,
}

impl TorIdentity {
    /// Create identity from an Ed25519 signing key.
    pub fn from_signing_key(signing_key: SigningKey) -> Result<Self> {
        let verifying_key = signing_key.verifying_key();
        let onion_address = OnionAddress::from_public_key(&verifying_key);
        let fingerprint = super::compute_fingerprint(&verifying_key);

        // Generate X25519 keypair for ECDH (used in group epoch key encryption)
        let x25519_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);

        Ok(Self {
            signing_key,
            x25519_secret,
            onion_address,
            fingerprint,
        })
    }

    /// Restore identity from secret key bytes.
    ///
    /// Used when loading identity from encrypted storage.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidKey("secret key must be 32 bytes".into()));
        }

        let secret_bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey("invalid length".into()))?;

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        Self::from_signing_key(signing_key)
    }

    /// Get this identity's onion address.
    pub fn onion_address(&self) -> &OnionAddress {
        &self.onion_address
    }

    /// Get the public key (verifying key).
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the SHA-256 fingerprint (hex-encoded).
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Get human-readable formatted fingerprint.
    pub fn formatted_fingerprint(&self) -> String {
        super::format_fingerprint(&self.fingerprint)
    }

    /// Sign a message with this identity.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verify a signature against a public key.
    pub fn verify(public_key: &VerifyingKey, message: &[u8], signature: &Signature) -> Result<()> {
        public_key
            .verify(message, signature)
            .map_err(|_| Error::Crypto("signature verification failed".into()))
    }

    /// Export secret key bytes for encrypted storage.
    ///
    /// # Security Warning
    ///
    /// These bytes must be:
    /// - Encrypted before storage
    /// - Zeroized after use
    /// - Never logged or transmitted
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Get reference to signing key (internal use for X25519 derivation).
    #[allow(dead_code)]
    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Get X25519 public key for ECDH.
    pub fn x25519_public_key(&self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(&self.x25519_secret)
    }

    /// Get X25519 secret key bytes for epoch key decryption.
    pub fn x25519_secret_bytes(&self) -> [u8; 32] {
        self.x25519_secret.to_bytes()
    }
}

impl fmt::Debug for TorIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TorIdentity")
            .field("onion_address", &self.onion_address)
            .field("fingerprint", &self.formatted_fingerprint())
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

impl Clone for TorIdentity {
    fn clone(&self) -> Self {
        // Clone by recreating from secret key bytes
        let signing_key = SigningKey::from_bytes(&self.signing_key.to_bytes());
        let x25519_secret = x25519_dalek::StaticSecret::from(self.x25519_secret.to_bytes());
        Self {
            signing_key,
            x25519_secret,
            onion_address: self.onion_address.clone(),
            fingerprint: self.fingerprint.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_onion_address_derivation() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let onion = OnionAddress::from_public_key(&verifying_key);

        assert!(onion.as_str().ends_with(".onion"));
        assert_eq!(onion.hostname().len(), 56);

        // Should extract same key back
        let extracted = onion.extract_public_key().expect("should extract");
        assert_eq!(extracted, verifying_key);
    }

    #[test]
    fn test_onion_address_validation() {
        // Wrong suffix
        assert!(OnionAddress::from_string("abc.com").is_err());

        // Wrong length
        assert!(OnionAddress::from_string("abc.onion").is_err());

        // Invalid base32
        assert!(OnionAddress::from_string(
            "0000000000000000000000000000000000000000000000000000000.onion"
        )
        .is_err());
    }

    #[test]
    fn test_signing_verification() {
        let identity = super::super::generate_identity().expect("should generate");
        let message = b"Hello, TorChat!";

        let signature = identity.sign(message);

        // Valid signature
        assert!(TorIdentity::verify(&identity.public_key(), message, &signature).is_ok());

        // Wrong message
        assert!(TorIdentity::verify(&identity.public_key(), b"wrong", &signature).is_err());
    }

    #[test]
    fn test_case_insensitive_parsing() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let onion = OnionAddress::from_public_key(&signing_key.verifying_key());

        let upper = onion.as_str().to_uppercase();
        let parsed = OnionAddress::from_string(upper).expect("should parse");

        assert_eq!(parsed, onion);
    }
}
