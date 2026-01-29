//! X25519 key types for Diffie-Hellman key exchange.
//!
//! Provides both static (long-term) and ephemeral (per-ratchet) keypairs.
//! All secret key material is zeroized on drop.

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size of X25519 keys in bytes.
pub const X25519_KEY_SIZE: usize = 32;

/// An X25519 public key for key exchange.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct X25519PublicKey(#[serde(with = "serde_bytes")] [u8; X25519_KEY_SIZE]);

impl X25519PublicKey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; X25519_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.0
    }

    /// Convert to x25519_dalek PublicKey.
    pub(crate) fn to_dalek(&self) -> PublicKey {
        PublicKey::from(self.0)
    }
}

impl fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only show first 8 bytes in debug output
        write!(f, "X25519PublicKey({}...)", hex::encode(&self.0[..8]))
    }
}

impl From<PublicKey> for X25519PublicKey {
    fn from(key: PublicKey) -> Self {
        Self(*key.as_bytes())
    }
}

impl From<[u8; X25519_KEY_SIZE]> for X25519PublicKey {
    fn from(bytes: [u8; X25519_KEY_SIZE]) -> Self {
        Self(bytes)
    }
}

/// An X25519 secret key.
///
/// Zeroized on drop to prevent key material from persisting in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519SecretKey([u8; X25519_KEY_SIZE]);

impl X25519SecretKey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; X25519_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    ///
    /// # Security
    /// Handle with care - this exposes secret key material.
    pub fn as_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.0
    }
}

impl fmt::Debug for X25519SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "X25519SecretKey([REDACTED])")
    }
}

/// A shared secret derived from X25519 key exchange.
///
/// Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; X25519_KEY_SIZE]);

impl SharedSecret {
    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.0
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SharedSecret([REDACTED])")
    }
}

/// A long-term (static) X25519 keypair.
///
/// Used for identity-based key exchange. The secret is zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct StaticKeypair {
    #[zeroize(skip)]
    secret: StaticSecret,
    public: X25519PublicKey,
}

impl StaticKeypair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(PublicKey::from(&secret));
        Self { secret, public }
    }

    /// Restore from secret key bytes.
    pub fn from_secret_bytes(bytes: [u8; X25519_KEY_SIZE]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = X25519PublicKey::from(PublicKey::from(&secret));
        Self { secret, public }
    }

    /// Get the public key.
    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public
    }

    /// Perform Diffie-Hellman key exchange.
    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> SharedSecret {
        let shared = self.secret.diffie_hellman(&their_public.to_dalek());
        SharedSecret(*shared.as_bytes())
    }

    /// Export secret key bytes for storage.
    ///
    /// # Security
    /// These bytes must be encrypted before storage.
    pub fn secret_bytes(&self) -> [u8; X25519_KEY_SIZE] {
        self.secret.to_bytes()
    }
}

impl fmt::Debug for StaticKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticKeypair")
            .field("public", &self.public)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// An ephemeral X25519 keypair for one-time use in the ratchet.
///
/// Used for Perfect Forward Secrecy - compromising one ephemeral key
/// doesn't reveal past or future messages.
///
/// Note: Uses StaticSecret internally because x25519-dalek's EphemeralSecret
/// can only perform DH once, but we need multiple DH operations in the ratchet.
#[derive(ZeroizeOnDrop)]
pub struct EphemeralKeypair {
    #[zeroize(skip)]
    secret: StaticSecret,
    public: X25519PublicKey,
}

impl EphemeralKeypair {
    /// Generate a new random ephemeral keypair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(PublicKey::from(&secret));
        Self { secret, public }
    }

    /// Get the public key.
    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public
    }

    /// Perform Diffie-Hellman key exchange.
    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> SharedSecret {
        let shared = self.secret.diffie_hellman(&their_public.to_dalek());
        SharedSecret(*shared.as_bytes())
    }
}

impl fmt::Debug for EphemeralKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralKeypair")
            .field("public", &self.public)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Perform X25519 Diffie-Hellman with raw key bytes.
pub fn derive_shared_secret(
    our_secret: &X25519SecretKey,
    their_public: &X25519PublicKey,
) -> SharedSecret {
    let secret = StaticSecret::from(our_secret.0);
    let shared = secret.diffie_hellman(&their_public.to_dalek());
    SharedSecret(*shared.as_bytes())
}

/// Serde helper for byte arrays.
mod serde_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<u8> = Vec::deserialize(deserializer)?;
        vec.try_into()
            .map_err(|_| serde::de::Error::custom("invalid byte array length"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_keypair() {
        let kp = StaticKeypair::generate();
        assert_eq!(kp.public_key().as_bytes().len(), X25519_KEY_SIZE);
    }

    #[test]
    fn test_ephemeral_keypair() {
        let kp = EphemeralKeypair::generate();
        assert_eq!(kp.public_key().as_bytes().len(), X25519_KEY_SIZE);
    }

    #[test]
    fn test_dh_agreement() {
        let alice = StaticKeypair::generate();
        let bob = StaticKeypair::generate();

        let alice_shared = alice.diffie_hellman(bob.public_key());
        let bob_shared = bob.diffie_hellman(alice.public_key());

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_mixed_dh() {
        let static_key = StaticKeypair::generate();
        let ephemeral_key = EphemeralKeypair::generate();

        let s1 = static_key.diffie_hellman(ephemeral_key.public_key());
        let s2 = ephemeral_key.diffie_hellman(static_key.public_key());

        assert_eq!(s1.as_bytes(), s2.as_bytes());
    }

    #[test]
    fn test_keypair_persistence() {
        let original = StaticKeypair::generate();
        let bytes = original.secret_bytes();

        let restored = StaticKeypair::from_secret_bytes(bytes);

        assert_eq!(
            original.public_key().as_bytes(),
            restored.public_key().as_bytes()
        );
    }
}
