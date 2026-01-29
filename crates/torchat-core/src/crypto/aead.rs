//! Authenticated encryption using ChaCha20-Poly1305.
//!
//! All message content is encrypted using AEAD to provide both
//! confidentiality and integrity. The authentication tag prevents
//! tampering, and associated data binds metadata to the ciphertext.

use crate::error::{Error, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce as ChaNonce,
};
use rand::RngCore;
use zeroize::Zeroizing;

/// Size of encryption key in bytes (256 bits).
pub const KEY_SIZE: usize = 32;

/// Size of nonce in bytes (96 bits).
pub const NONCE_SIZE: usize = 12;

/// Size of authentication tag in bytes (128 bits).
pub const TAG_SIZE: usize = 16;

/// A nonce for AEAD encryption.
///
/// Must be unique per key. Using a random nonce is safe for our use case
/// since we generate fresh keys frequently via the ratchet.
#[derive(Clone, Copy, Debug)]
pub struct Nonce([u8; NONCE_SIZE]);

impl Nonce {
    /// Create a new random nonce.
    pub fn random() -> Self {
        let mut bytes = [0u8; NONCE_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: [u8; NONCE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.0
    }
}

impl From<[u8; NONCE_SIZE]> for Nonce {
    fn from(bytes: [u8; NONCE_SIZE]) -> Self {
        Self(bytes)
    }
}

/// Encrypt plaintext using ChaCha20-Poly1305.
///
/// # Arguments
///
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce (must be unique per key)
/// * `plaintext` - Data to encrypt
/// * `associated_data` - Authenticated but not encrypted (e.g., headers)
///
/// # Returns
///
/// Ciphertext with appended 16-byte authentication tag.
pub fn encrypt(
    key: &[u8; KEY_SIZE],
    nonce: &Nonce,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let cha_nonce = ChaNonce::from_slice(nonce.as_bytes());

    cipher
        .encrypt(
            cha_nonce,
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| Error::Crypto("encryption failed".into()))
}

/// Decrypt ciphertext using ChaCha20-Poly1305.
///
/// # Arguments
///
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce used during encryption
/// * `ciphertext` - Encrypted data with authentication tag
/// * `associated_data` - Must match what was used during encryption
///
/// # Returns
///
/// Decrypted plaintext (zeroized container), or error if authentication fails.
///
/// # Security
///
/// Returns a generic error on failure to prevent oracle attacks.
pub fn decrypt(
    key: &[u8; KEY_SIZE],
    nonce: &Nonce,
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let cha_nonce = ChaNonce::from_slice(nonce.as_bytes());

    let plaintext = cipher
        .decrypt(
            cha_nonce,
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| Error::Crypto("decryption failed".into()))?;

    Ok(Zeroizing::new(plaintext))
}

/// Encrypt with a random nonce, prepending it to output.
///
/// Output format: `nonce (12 bytes) || ciphertext || tag (16 bytes)`
///
/// This is convenient for storage where nonce management is automatic.
pub fn encrypt_with_random_nonce(
    key: &[u8; KEY_SIZE],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    let nonce = Nonce::random();
    let ciphertext = encrypt(key, &nonce, plaintext, associated_data)?;

    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(nonce.as_bytes());
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt data encrypted with `encrypt_with_random_nonce`.
///
/// Expects format: `nonce (12 bytes) || ciphertext || tag (16 bytes)`
pub fn decrypt_with_prepended_nonce(
    key: &[u8; KEY_SIZE],
    data: &[u8],
    associated_data: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < NONCE_SIZE + TAG_SIZE {
        return Err(Error::Crypto("ciphertext too short".into()));
    }

    let nonce = Nonce::from_bytes(
        data[..NONCE_SIZE]
            .try_into()
            .map_err(|_| Error::Crypto("invalid nonce".into()))?,
    );
    let ciphertext = &data[NONCE_SIZE..];

    decrypt(key, &nonce, ciphertext, associated_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [42u8; KEY_SIZE];
        let nonce = Nonce::random();
        let plaintext = b"Hello, TorChat!";
        let aad = b"header";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("encrypt");
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);

        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).expect("decrypt");
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [42u8; KEY_SIZE];
        let key2 = [43u8; KEY_SIZE];
        let nonce = Nonce::random();

        let ciphertext = encrypt(&key1, &nonce, b"secret", b"").expect("encrypt");
        assert!(decrypt(&key2, &nonce, &ciphertext, b"").is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = [42u8; KEY_SIZE];
        let nonce = Nonce::random();

        let ciphertext = encrypt(&key, &nonce, b"secret", b"correct").expect("encrypt");
        assert!(decrypt(&key, &nonce, &ciphertext, b"wrong").is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [42u8; KEY_SIZE];
        let nonce = Nonce::random();

        let mut ciphertext = encrypt(&key, &nonce, b"secret", b"").expect("encrypt");
        ciphertext[0] ^= 0xFF;

        assert!(decrypt(&key, &nonce, &ciphertext, b"").is_err());
    }

    #[test]
    fn test_prepended_nonce() {
        let key = [42u8; KEY_SIZE];
        let plaintext = b"Hello with nonce!";
        let aad = b"header";

        let encrypted = encrypt_with_random_nonce(&key, plaintext, aad).expect("encrypt");
        assert_eq!(encrypted.len(), NONCE_SIZE + plaintext.len() + TAG_SIZE);

        let decrypted = decrypt_with_prepended_nonce(&key, &encrypted, aad).expect("decrypt");
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [42u8; KEY_SIZE];
        let nonce = Nonce::random();

        let ciphertext = encrypt(&key, &nonce, b"", b"").expect("encrypt");
        assert_eq!(ciphertext.len(), TAG_SIZE);

        let decrypted = decrypt(&key, &nonce, &ciphertext, b"").expect("decrypt");
        assert!(decrypted.is_empty());
    }
}
