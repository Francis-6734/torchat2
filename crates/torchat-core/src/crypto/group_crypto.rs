//! Group cryptography primitives.
//!
//! Implements cryptographic operations for decentralized group chat:
//! - Group ID generation
//! - Member ID derivation (anonymous)
//! - Message ID generation
//! - Epoch key derivation (forward secrecy)
//! - Group message encryption/decryption
//! - Invite token signing/verification

use crate::error::{Error, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Generate group ID from group name and founder's public key.
///
/// Group ID = SHA256("TorChat2_GroupID_v1" || group_name || founder_pubkey)
///
/// This creates a deterministic, globally unique identifier for the group.
pub fn generate_group_id(group_name: &str, founder_pubkey: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"TorChat2_GroupID_v1");
    hasher.update(group_name.as_bytes());
    hasher.update(founder_pubkey);
    hasher.finalize().into()
}

/// Generate anonymous member ID from group ID and member's public key.
///
/// Member ID = SHA256("TorChat2_MemberID_v1" || group_id || member_pubkey)[..16]
///
/// This creates a privacy-preserving identifier that:
/// - Is unique within the group
/// - Cannot be linked across groups
/// - Hides the member's actual onion address
pub fn generate_member_id(group_id: &[u8; 32], member_pubkey: &[u8; 32]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"TorChat2_MemberID_v1");
    hasher.update(group_id);
    hasher.update(member_pubkey);
    let hash = hasher.finalize();

    let mut member_id = [0u8; 16];
    member_id.copy_from_slice(&hash[..16]);
    member_id
}

/// Generate message ID for gossip deduplication.
///
/// Message ID = SHA256("TorChat2_GroupMsg_v1" || timestamp || sender_pubkey || nonce)
///
/// This ensures:
/// - Each message has a unique ID
/// - Messages can be deduplicated across the mesh
/// - Replay attacks are prevented
pub fn generate_message_id(
    timestamp: i64,
    sender_pubkey: &[u8; 32],
    nonce: &[u8; 16],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"TorChat2_GroupMsg_v1");
    hasher.update(&timestamp.to_le_bytes());
    hasher.update(sender_pubkey);
    hasher.update(nonce);
    hasher.finalize().into()
}

/// Derive epoch key for forward secrecy.
///
/// K_epoch = HKDF-SHA256(
///     salt: group_id,
///     ikm: previous_key,
///     info: "TorChat2_EpochKey_v1" || epoch_number
/// )
///
/// This implements key rotation with forward secrecy:
/// - Each epoch has a unique key
/// - Compromise of K_n doesn't reveal K_{n-1}
/// - Keys are deterministically derivable for all members
pub fn derive_epoch_key(
    previous_key: &[u8; 32],
    epoch_number: u64,
    group_id: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(group_id), previous_key);

    let mut info = Vec::with_capacity(24 + 8);
    info.extend_from_slice(b"TorChat2_EpochKey_v1");
    info.extend_from_slice(&epoch_number.to_le_bytes());

    let mut okm = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info, okm.as_mut())
        .map_err(|_| Error::Crypto("epoch key derivation failed".into()))?;

    Ok(okm)
}

/// Generate initial group key (founder only).
///
/// Uses cryptographically secure randomness for the root key.
pub fn generate_initial_group_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut());
    key
}

/// Encrypt group message with epoch key.
///
/// Uses ChaCha20-Poly1305 AEAD with:
/// - Key: Current epoch key (32 bytes)
/// - Nonce: Derived from message ID (12 bytes)
/// - AAD: Message ID (for binding)
///
/// This provides:
/// - Confidentiality (ChaCha20 stream cipher)
/// - Authenticity (Poly1305 MAC)
/// - Binding to message ID (prevents substitution)
pub fn encrypt_group_message(
    epoch_key: &[u8; 32],
    plaintext: &[u8],
    message_id: &[u8; 32],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(epoch_key));

    // Derive 12-byte nonce from 32-byte message_id
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&message_id[..12]);
    let nonce = ChaChaNonce::from(nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad: message_id, // Authenticate message ID
    };

    cipher
        .encrypt(&nonce, payload)
        .map_err(|_| Error::Crypto("group message encryption failed".into()))
}

/// Decrypt group message with epoch key.
///
/// Verifies authenticity and decrypts the message.
pub fn decrypt_group_message(
    epoch_key: &[u8; 32],
    ciphertext: &[u8],
    message_id: &[u8; 32],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(epoch_key));

    // Derive same nonce from message_id
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&message_id[..12]);
    let nonce = ChaChaNonce::from(nonce_bytes);

    let payload = Payload {
        msg: ciphertext,
        aad: message_id,
    };

    cipher
        .decrypt(&nonce, payload)
        .map_err(|_| Error::Crypto("group message decryption failed".into()))
}

/// Sign invite token with founder/admin's signing key.
///
/// Signs over all critical invite fields to prevent forgery.
pub fn sign_invite_token(
    signing_key: &SigningKey,
    group_id: &[u8; 32],
    inviter_pubkey: &[u8; 32],
    bootstrap_peer: &str,
    expires_at: i64,
    invite_id: &[u8; 16],
) -> [u8; 64] {
    let mut msg = Vec::with_capacity(32 + 32 + bootstrap_peer.len() + 8 + 16);
    msg.extend_from_slice(group_id);
    msg.extend_from_slice(inviter_pubkey);
    msg.extend_from_slice(bootstrap_peer.as_bytes());
    msg.extend_from_slice(&expires_at.to_le_bytes());
    msg.extend_from_slice(invite_id);

    signing_key.sign(&msg).to_bytes()
}

/// Verify invite token signature.
///
/// Ensures the invite was issued by an authorized admin.
pub fn verify_invite_token(
    verifying_key: &VerifyingKey,
    group_id: &[u8; 32],
    inviter_pubkey: &[u8; 32],
    bootstrap_peer: &str,
    expires_at: i64,
    invite_id: &[u8; 16],
    signature: &[u8; 64],
) -> Result<()> {
    let mut msg = Vec::with_capacity(32 + 32 + bootstrap_peer.len() + 8 + 16);
    msg.extend_from_slice(group_id);
    msg.extend_from_slice(inviter_pubkey);
    msg.extend_from_slice(bootstrap_peer.as_bytes());
    msg.extend_from_slice(&expires_at.to_le_bytes());
    msg.extend_from_slice(invite_id);

    let signature = Signature::from_bytes(signature);

    verifying_key
        .verify_strict(&msg, &signature)
        .map_err(|_| Error::Crypto("invite signature verification failed".into()))
}

/// Generate random nonce for message ID generation.
pub fn generate_random_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Generate random invite ID for revocation tracking.
pub fn generate_invite_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    id
}

/// Encrypt epoch key for a specific recipient using X25519 ECDH.
///
/// Protocol:
/// 1. Generate ephemeral X25519 keypair
/// 2. Perform ECDH with recipient's public key to derive shared secret
/// 3. Derive encryption key from shared secret using HKDF
/// 4. Encrypt epoch key with ChaCha20-Poly1305
/// 5. Return (ephemeral_pubkey || nonce || ciphertext)
///
/// This ensures only the recipient can decrypt the epoch key.
pub fn encrypt_epoch_key_for_member(
    epoch_key: &[u8; 32],
    recipient_x25519_pubkey: &[u8; 32],
) -> Result<Vec<u8>> {
    use x25519_dalek::{EphemeralSecret, PublicKey};

    // Generate ephemeral keypair for ECDH
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // Perform ECDH
    let recipient_pubkey = PublicKey::from(*recipient_x25519_pubkey);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pubkey);

    // Derive encryption key from shared secret using HKDF
    let hkdf = Hkdf::<Sha256>::new(Some(b"TorChat2_EpochKeyEncryption_v1"), shared_secret.as_bytes());
    let mut encryption_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"epoch_key", &mut *encryption_key)
        .map_err(|_| Error::Crypto("HKDF expansion failed".into()))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = ChaChaNonce::from_slice(&nonce_bytes);

    // Encrypt epoch key
    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(&*encryption_key));
    let ciphertext = cipher
        .encrypt(nonce, epoch_key.as_ref())
        .map_err(|_| Error::Crypto("Encryption failed".into()))?;

    // Return ephemeral_pubkey || nonce || ciphertext
    let mut result = Vec::with_capacity(32 + 12 + ciphertext.len());
    result.extend_from_slice(ephemeral_public.as_bytes());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt epoch key encrypted by encrypt_epoch_key_for_member.
///
/// Protocol:
/// 1. Extract ephemeral public key, nonce, and ciphertext
/// 2. Perform ECDH with our private key to derive shared secret
/// 3. Derive encryption key from shared secret using HKDF
/// 4. Decrypt ciphertext with ChaCha20-Poly1305
/// 5. Return epoch key
pub fn decrypt_epoch_key_from_sender(
    encrypted_data: &[u8],
    our_x25519_secret: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    use x25519_dalek::{PublicKey, StaticSecret};

    // Validate length (32 ephemeral_pubkey + 12 nonce + at least 16 tag)
    if encrypted_data.len() < 32 + 12 + 16 {
        return Err(Error::Crypto("Invalid encrypted data length".into()));
    }
    
    // Extract components
    let ephemeral_pubkey_bytes: [u8; 32] = encrypted_data[0..32]
        .try_into()
        .map_err(|_| Error::Crypto("Invalid ephemeral public key".into()))?;
    let nonce_bytes: [u8; 12] = encrypted_data[32..44]
        .try_into()
        .map_err(|_| Error::Crypto("Invalid nonce".into()))?;
    let ciphertext = &encrypted_data[44..];

    // Perform ECDH
    let our_secret = StaticSecret::from(*our_x25519_secret);
    let ephemeral_pubkey = PublicKey::from(ephemeral_pubkey_bytes);
    let shared_secret = our_secret.diffie_hellman(&ephemeral_pubkey);

    // Derive encryption key from shared secret using HKDF
    let hkdf = Hkdf::<Sha256>::new(Some(b"TorChat2_EpochKeyEncryption_v1"), shared_secret.as_bytes());
    let mut encryption_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"epoch_key", &mut *encryption_key)
        .map_err(|_| Error::Crypto("HKDF expansion failed".into()))?;

    // Decrypt
    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(&*encryption_key));
    let nonce = ChaChaNonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::Crypto("Decryption failed".into()))?;

    // Convert to epoch key
    if plaintext.len() != 32 {
        return Err(Error::Crypto("Invalid epoch key length".into()));
    }

    let mut epoch_key = Zeroizing::new([0u8; 32]);
    epoch_key.copy_from_slice(&plaintext);

    Ok(epoch_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_group_id_generation() {
        let founder_pubkey = [1u8; 32];
        let group_name = "Test Group";

        let group_id = generate_group_id(group_name, &founder_pubkey);

        // Should be deterministic
        let group_id2 = generate_group_id(group_name, &founder_pubkey);
        assert_eq!(group_id, group_id2);

        // Different founder should give different ID
        let different_founder = [2u8; 32];
        let different_id = generate_group_id(group_name, &different_founder);
        assert_ne!(group_id, different_id);
    }

    #[test]
    fn test_member_id_generation() {
        let group_id = [1u8; 32];
        let member_pubkey = [2u8; 32];

        let member_id = generate_member_id(&group_id, &member_pubkey);

        // Should be deterministic
        let member_id2 = generate_member_id(&group_id, &member_pubkey);
        assert_eq!(member_id, member_id2);

        // Different member should give different ID
        let different_member = [3u8; 32];
        let different_id = generate_member_id(&group_id, &different_member);
        assert_ne!(member_id, different_id);

        // Same member in different group should give different ID
        let different_group = [4u8; 32];
        let different_group_id = generate_member_id(&different_group, &member_pubkey);
        assert_ne!(member_id, different_group_id);
    }

    #[test]
    fn test_message_id_generation() {
        let timestamp = 1234567890;
        let sender_pubkey = [1u8; 32];
        let nonce = [2u8; 16];

        let msg_id = generate_message_id(timestamp, &sender_pubkey, &nonce);

        // Should be deterministic
        let msg_id2 = generate_message_id(timestamp, &sender_pubkey, &nonce);
        assert_eq!(msg_id, msg_id2);

        // Different nonce should give different ID
        let different_nonce = [3u8; 16];
        let different_id = generate_message_id(timestamp, &sender_pubkey, &different_nonce);
        assert_ne!(msg_id, different_id);
    }

    #[test]
    fn test_epoch_key_derivation() {
        let initial_key = [1u8; 32];
        let group_id = [2u8; 32];

        let epoch1 = derive_epoch_key(&initial_key, 1, &group_id).unwrap();
        let epoch2 = derive_epoch_key(&*epoch1, 2, &group_id).unwrap();

        // Different epochs should have different keys
        assert_ne!(&*epoch1, &*epoch2);

        // Should be deterministic
        let epoch1_again = derive_epoch_key(&initial_key, 1, &group_id).unwrap();
        assert_eq!(&*epoch1, &*epoch1_again);
    }

    #[test]
    fn test_group_message_encryption_decryption() {
        let epoch_key = [1u8; 32];
        let plaintext = b"Hello, group!";
        let message_id = [2u8; 32];

        // Encrypt
        let ciphertext = encrypt_group_message(&epoch_key, plaintext, &message_id).unwrap();

        // Should be different from plaintext
        assert_ne!(ciphertext.as_slice(), plaintext);

        // Decrypt
        let decrypted = decrypt_group_message(&epoch_key, &ciphertext, &message_id).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);

        // Wrong key should fail
        let wrong_key = [2u8; 32];
        assert!(decrypt_group_message(&wrong_key, &ciphertext, &message_id).is_err());

        // Wrong message ID should fail (AAD mismatch)
        let wrong_msg_id = [3u8; 32];
        assert!(decrypt_group_message(&epoch_key, &ciphertext, &wrong_msg_id).is_err());
    }

    #[test]
    fn test_invite_token_signing() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let group_id = [1u8; 32];
        let inviter_pubkey = [2u8; 32];
        let bootstrap_peer = "founder.onion";
        let expires_at = 1234567890;
        let invite_id = [3u8; 16];

        // Sign
        let signature = sign_invite_token(
            &signing_key,
            &group_id,
            &inviter_pubkey,
            bootstrap_peer,
            expires_at,
            &invite_id,
        );

        // Verify
        assert!(verify_invite_token(
            &verifying_key,
            &group_id,
            &inviter_pubkey,
            bootstrap_peer,
            expires_at,
            &invite_id,
            &signature,
        ).is_ok());

        // Wrong signature should fail
        let wrong_signature = [0u8; 64];
        assert!(verify_invite_token(
            &verifying_key,
            &group_id,
            &inviter_pubkey,
            bootstrap_peer,
            expires_at,
            &invite_id,
            &wrong_signature,
        ).is_err());

        // Tampered invite should fail
        let tampered_expires = expires_at + 1;
        assert!(verify_invite_token(
            &verifying_key,
            &group_id,
            &inviter_pubkey,
            bootstrap_peer,
            tampered_expires,
            &invite_id,
            &signature,
        ).is_err());
    }

    #[test]
    fn test_random_nonce_generation() {
        let nonce1 = generate_random_nonce();
        let nonce2 = generate_random_nonce();

        // Should be different (with very high probability)
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_epoch_key_encryption_decryption() {
        use x25519_dalek::{PublicKey, StaticSecret};
        use rand::rngs::OsRng;

        // Generate recipient's X25519 keypair
        let recipient_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_public = PublicKey::from(&recipient_secret);

        // Epoch key to encrypt
        let epoch_key = [0x42u8; 32];

        // Encrypt for recipient
        let encrypted = encrypt_epoch_key_for_member(&epoch_key, recipient_public.as_bytes()).unwrap();

        // Should be longer than plaintext (includes ephemeral pubkey + nonce + tag)
        assert!(encrypted.len() > 32);
        assert_eq!(encrypted.len(), 32 + 12 + 32 + 16); // ephemeral_pubkey + nonce + plaintext + tag

        // Decrypt with recipient's secret key
        let decrypted = decrypt_epoch_key_from_sender(&encrypted, recipient_secret.as_bytes()).unwrap();
        assert_eq!(*decrypted, epoch_key);

        // Wrong secret key should fail
        let wrong_secret = StaticSecret::random_from_rng(OsRng);
        assert!(decrypt_epoch_key_from_sender(&encrypted, wrong_secret.as_bytes()).is_err());

        // Corrupted ciphertext should fail
        let mut corrupted = encrypted.clone();
        corrupted[50] ^= 0xFF; // Flip a bit in the ciphertext
        assert!(decrypt_epoch_key_from_sender(&corrupted, recipient_secret.as_bytes()).is_err());

        // Truncated data should fail
        assert!(decrypt_epoch_key_from_sender(&encrypted[..20], recipient_secret.as_bytes()).is_err());
    }
}
