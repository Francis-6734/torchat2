//! Signal Double Ratchet protocol implementation.
//!
//! The Double Ratchet provides:
//!
//! - **Perfect Forward Secrecy**: Past messages remain secure if keys are compromised
//! - **Post-compromise security**: Future messages become secure after a compromise
//! - **Out-of-order delivery**: Messages can arrive in any order
//!
//! ## How It Works
//!
//! 1. **DH Ratchet**: Each party maintains a DH keypair. When receiving a message
//!    with a new public key, both parties derive new shared secrets.
//!
//! 2. **Symmetric Ratchet**: Each message advances a chain key, deriving unique
//!    message keys. Old chain keys are deleted after use.
//!
//! 3. **Skipped Keys**: If messages arrive out of order, we store skipped keys
//!    temporarily to decrypt late-arriving messages.
//!
//! Based on the Signal Protocol specification.

use super::{
    aead::{self, KEY_SIZE, NONCE_SIZE},
    hkdf_derive,
    keys::{EphemeralKeypair, SharedSecret, X25519PublicKey},
};
use crate::error::{Error, Result};
use crate::MAX_SKIP;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// KDF info strings - domain separation for different key derivations
const ROOT_KDF_INFO: &[u8] = b"TorChat2 Root KDF v1";
const CHAIN_KDF_INFO: &[u8] = b"TorChat2 Chain KDF v1";
const MSG_KDF_INFO: &[u8] = b"TorChat2 Message KDF v1";

/// Header sent with each ratcheted message.
///
/// Contains the sender's current DH public key and chain position,
/// allowing the receiver to synchronize their ratchet state.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RatchetHeader {
    /// Sender's current ratchet public key.
    pub dh_public: X25519PublicKey,
    /// Number of messages in the previous sending chain.
    pub previous_chain_length: u32,
    /// Message number in current sending chain.
    pub message_number: u32,
}

impl RatchetHeader {
    /// Size of serialized header: 32 (pubkey) + 4 + 4 = 40 bytes
    pub const SIZE: usize = 40;

    /// Serialize header to bytes (for use as associated data).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::SIZE);
        bytes.extend_from_slice(self.dh_public.as_bytes());
        bytes.extend_from_slice(&self.previous_chain_length.to_le_bytes());
        bytes.extend_from_slice(&self.message_number.to_le_bytes());
        bytes
    }

    /// Deserialize header from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::SIZE {
            return Err(Error::Protocol("header too short".into()));
        }

        let dh_public = X25519PublicKey::from_bytes(
            bytes[..32]
                .try_into()
                .map_err(|_| Error::Protocol("invalid DH key".into()))?,
        );

        let previous_chain_length = u32::from_le_bytes(
            bytes[32..36]
                .try_into()
                .map_err(|_| Error::Protocol("invalid chain length".into()))?,
        );

        let message_number = u32::from_le_bytes(
            bytes[36..40]
                .try_into()
                .map_err(|_| Error::Protocol("invalid message number".into()))?,
        );

        Ok(Self {
            dh_public,
            previous_chain_length,
            message_number,
        })
    }
}

/// Keys derived for encrypting/decrypting a single message.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MessageKeys {
    /// Encryption key (ChaCha20-Poly1305).
    pub encryption_key: [u8; KEY_SIZE],
    /// Nonce for AEAD.
    pub nonce: [u8; NONCE_SIZE],
}

/// Persistent state of a Double Ratchet session.
///
/// This must be stored encrypted at rest. All key material is zeroized on drop.
#[derive(Serialize, Deserialize)]
pub struct RatchetState {
    /// Our current ratchet keypair (secret stored separately for serialization).
    #[serde(skip)]
    dh_self: Option<EphemeralKeypair>,

    /// Serialized DH public key (our current public key).
    dh_self_public: Option<[u8; 32]>,

    /// Their current ratchet public key.
    dh_remote: Option<X25519PublicKey>,

    /// Current root key (used to derive new chain keys).
    root_key: [u8; 32],

    /// Current sending chain key.
    chain_key_send: Option<[u8; 32]>,

    /// Current receiving chain key.
    chain_key_recv: Option<[u8; 32]>,

    /// Messages sent in current sending chain.
    send_count: u32,

    /// Messages received in current receiving chain.
    recv_count: u32,

    /// Previous sending chain length (for header).
    previous_send_count: u32,

    /// Skipped message keys: (DH public key, message number) -> chain key
    skipped_keys: HashMap<([u8; 32], u32), [u8; 32]>,
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        self.root_key.zeroize();
        if let Some(ref mut k) = self.chain_key_send {
            k.zeroize();
        }
        if let Some(ref mut k) = self.chain_key_recv {
            k.zeroize();
        }
        for (_, k) in self.skipped_keys.iter_mut() {
            k.zeroize();
        }
    }
}

/// The Double Ratchet session manager.
///
/// Handles encryption and decryption of messages with automatic key rotation.
pub struct DoubleRatchet {
    state: RatchetState,
}

impl DoubleRatchet {
    /// Initialize as the session initiator (Alice).
    ///
    /// Alice has Bob's public key from the initial key exchange and
    /// sends the first message.
    pub fn init_initiator(
        shared_secret: &SharedSecret,
        their_public: &X25519PublicKey,
    ) -> Result<Self> {
        let dh_self = EphemeralKeypair::generate();

        // Perform DH with their public key
        let dh_output = dh_self.diffie_hellman(their_public);

        // Derive root key and initial sending chain key
        let (root_key, chain_key_send) = kdf_root_key(shared_secret.as_bytes(), dh_output.as_bytes())?;

        let dh_self_public = Some(*dh_self.public_key().as_bytes());

        let state = RatchetState {
            dh_self: Some(dh_self),
            dh_self_public,
            dh_remote: Some(their_public.clone()),
            root_key,
            chain_key_send: Some(chain_key_send),
            chain_key_recv: None,
            send_count: 0,
            recv_count: 0,
            previous_send_count: 0,
            skipped_keys: HashMap::new(),
        };

        Ok(Self { state })
    }

    /// Initialize as the session responder (Bob).
    ///
    /// Bob waits for Alice's first message, which contains her public key.
    pub fn init_responder(shared_secret: &SharedSecret, our_keypair: EphemeralKeypair) -> Self {
        let dh_self_public = Some(*our_keypair.public_key().as_bytes());

        let state = RatchetState {
            dh_self: Some(our_keypair),
            dh_self_public,
            dh_remote: None,
            root_key: *shared_secret.as_bytes(),
            chain_key_send: None,
            chain_key_recv: None,
            send_count: 0,
            recv_count: 0,
            previous_send_count: 0,
            skipped_keys: HashMap::new(),
        };

        Self { state }
    }

    /// Encrypt a message.
    ///
    /// Returns the header and ciphertext. The header must be sent alongside
    /// the ciphertext (it's authenticated but not encrypted).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(RatchetHeader, Vec<u8>)> {
        let chain_key = self
            .state
            .chain_key_send
            .as_ref()
            .ok_or_else(|| Error::Ratchet("no sending chain".into()))?;

        // Derive message keys and advance chain
        let (new_chain_key, message_keys) = kdf_chain_key(chain_key)?;
        self.state.chain_key_send = Some(new_chain_key);

        // Build header
        let dh_self = self
            .state
            .dh_self
            .as_ref()
            .ok_or_else(|| Error::Ratchet("no DH keypair".into()))?;

        let header = RatchetHeader {
            dh_public: dh_self.public_key().clone(),
            previous_chain_length: self.state.previous_send_count,
            message_number: self.state.send_count,
        };

        // Encrypt with header as associated data
        let header_bytes = header.to_bytes();
        let nonce = aead::Nonce::from_bytes(message_keys.nonce);
        let ciphertext = aead::encrypt(
            &message_keys.encryption_key,
            &nonce,
            plaintext,
            &header_bytes,
        )?;

        self.state.send_count += 1;

        Ok((header, ciphertext))
    }

    /// Decrypt a message.
    ///
    /// Handles DH ratchet steps and out-of-order delivery automatically.
    pub fn decrypt(&mut self, header: &RatchetHeader, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Check for skipped message key
        let key_id = (*header.dh_public.as_bytes(), header.message_number);
        if let Some(stored_ck) = self.state.skipped_keys.remove(&key_id) {
            let message_keys = derive_message_keys(&stored_ck)?;
            return decrypt_with_keys(&message_keys, header, ciphertext);
        }

        // Check if we need a DH ratchet step
        let need_dh_ratchet = self
            .state
            .dh_remote
            .as_ref()
            .map(|r| r != &header.dh_public)
            .unwrap_or(true);

        if need_dh_ratchet {
            // Skip remaining messages in current receiving chain
            if self.state.chain_key_recv.is_some() && self.state.dh_remote.is_some() {
                self.skip_message_keys(header.previous_chain_length)?;
            }

            // Perform DH ratchet
            self.dh_ratchet(&header.dh_public)?;
        }

        // Skip to this message number
        self.skip_message_keys(header.message_number)?;

        // Derive message keys
        let chain_key = self
            .state
            .chain_key_recv
            .as_ref()
            .ok_or_else(|| Error::Ratchet("no receiving chain".into()))?;

        let (new_chain_key, message_keys) = kdf_chain_key(chain_key)?;
        self.state.chain_key_recv = Some(new_chain_key);
        self.state.recv_count += 1;

        decrypt_with_keys(&message_keys, header, ciphertext)
    }

    /// Perform a DH ratchet step.
    fn dh_ratchet(&mut self, their_public: &X25519PublicKey) -> Result<()> {
        self.state.previous_send_count = self.state.send_count;
        self.state.send_count = 0;
        self.state.recv_count = 0;
        self.state.dh_remote = Some(their_public.clone());

        // Derive new receiving chain
        let dh_self = self
            .state
            .dh_self
            .as_ref()
            .ok_or_else(|| Error::Ratchet("no DH keypair".into()))?;

        let dh_output = dh_self.diffie_hellman(their_public);
        let (root_key, chain_key_recv) =
            kdf_root_key(&self.state.root_key, dh_output.as_bytes())?;

        self.state.root_key = root_key;
        self.state.chain_key_recv = Some(chain_key_recv);

        // Generate new DH keypair and derive sending chain
        let new_dh = EphemeralKeypair::generate();
        let dh_output = new_dh.diffie_hellman(their_public);
        let (root_key, chain_key_send) =
            kdf_root_key(&self.state.root_key, dh_output.as_bytes())?;

        self.state.root_key = root_key;
        self.state.chain_key_send = Some(chain_key_send);
        self.state.dh_self_public = Some(*new_dh.public_key().as_bytes());
        self.state.dh_self = Some(new_dh);

        Ok(())
    }

    /// Store skipped message keys for out-of-order delivery.
    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        if self.state.recv_count + MAX_SKIP as u32 <= until {
            return Err(Error::Ratchet("too many skipped messages".into()));
        }

        let chain_key = match self.state.chain_key_recv.as_ref() {
            Some(k) => k,
            None => return Ok(()),
        };

        let dh_remote = match self.state.dh_remote.as_ref() {
            Some(k) => k,
            None => return Ok(()),
        };

        let mut current_ck = *chain_key;

        while self.state.recv_count < until {
            // Store the current chain key (before deriving) for this message number
            let key_id = (*dh_remote.as_bytes(), self.state.recv_count);
            self.state.skipped_keys.insert(key_id, current_ck);

            // Advance the chain
            let (new_ck, _msg_keys) = kdf_chain_key(&current_ck)?;
            current_ck = new_ck;
            self.state.recv_count += 1;

            // Enforce limit
            if self.state.skipped_keys.len() > MAX_SKIP {
                // Remove oldest (simplified - real impl would track by time)
                if let Some(&oldest) = self.state.skipped_keys.keys().next() {
                    self.state.skipped_keys.remove(&oldest);
                }
            }
        }

        self.state.chain_key_recv = Some(current_ck);
        Ok(())
    }

    /// Get our current public key.
    pub fn public_key(&self) -> Option<&X25519PublicKey> {
        self.state.dh_self.as_ref().map(|kp| kp.public_key())
    }

    /// Get the ratchet state for persistence.
    pub fn state(&self) -> &RatchetState {
        &self.state
    }

    /// Initialize as initiator from raw shared secret bytes.
    ///
    /// Convenience method for testing and cases where the shared secret
    /// is available as raw bytes.
    pub fn init_initiator_from_bytes(
        shared_secret: &[u8; 32],
        their_public: &X25519PublicKey,
    ) -> Result<Self> {
        let dh_self = EphemeralKeypair::generate();

        // Perform DH with their public key
        let dh_output = dh_self.diffie_hellman(their_public);

        // Derive root key and initial sending chain key
        let (root_key, chain_key_send) = kdf_root_key(shared_secret, dh_output.as_bytes())?;

        let dh_self_public = Some(*dh_self.public_key().as_bytes());

        let state = RatchetState {
            dh_self: Some(dh_self),
            dh_self_public,
            dh_remote: Some(their_public.clone()),
            root_key,
            chain_key_send: Some(chain_key_send),
            chain_key_recv: None,
            send_count: 0,
            recv_count: 0,
            previous_send_count: 0,
            skipped_keys: HashMap::new(),
        };

        Ok(Self { state })
    }

    /// Initialize as responder from raw shared secret bytes.
    ///
    /// Convenience method for testing and cases where the shared secret
    /// is available as raw bytes.
    pub fn init_responder_from_bytes(shared_secret: &[u8; 32], our_keypair: EphemeralKeypair) -> Self {
        let dh_self_public = Some(*our_keypair.public_key().as_bytes());

        let state = RatchetState {
            dh_self: Some(our_keypair),
            dh_self_public,
            dh_remote: None,
            root_key: *shared_secret,
            chain_key_send: None,
            chain_key_recv: None,
            send_count: 0,
            recv_count: 0,
            previous_send_count: 0,
            skipped_keys: HashMap::new(),
        };

        Self { state }
    }
}

/// Root key derivation: (root_key, dh_output) -> (new_root_key, chain_key)
fn kdf_root_key(root_key: &[u8], dh_output: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let output = hkdf_derive(Some(root_key), dh_output, ROOT_KDF_INFO, 64)?;

    let mut new_root = [0u8; 32];
    let mut chain_key = [0u8; 32];
    new_root.copy_from_slice(&output[..32]);
    chain_key.copy_from_slice(&output[32..]);

    Ok((new_root, chain_key))
}

/// Chain key derivation: chain_key -> (new_chain_key, message_keys)
fn kdf_chain_key(chain_key: &[u8; 32]) -> Result<([u8; 32], MessageKeys)> {
    // Derive new chain key
    let new_ck = hkdf_derive(None, chain_key, CHAIN_KDF_INFO, 32)?;
    let mut new_chain_key = [0u8; 32];
    new_chain_key.copy_from_slice(&new_ck);

    // Derive message keys
    let msg_bytes = hkdf_derive(None, chain_key, MSG_KDF_INFO, KEY_SIZE + NONCE_SIZE)?;
    let mut encryption_key = [0u8; KEY_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];
    encryption_key.copy_from_slice(&msg_bytes[..KEY_SIZE]);
    nonce.copy_from_slice(&msg_bytes[KEY_SIZE..]);

    Ok((new_chain_key, MessageKeys { encryption_key, nonce }))
}

/// Derive message keys from stored chain key.
fn derive_message_keys(chain_key: &[u8; 32]) -> Result<MessageKeys> {
    let msg_bytes = hkdf_derive(None, chain_key, MSG_KDF_INFO, KEY_SIZE + NONCE_SIZE)?;
    let mut encryption_key = [0u8; KEY_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];
    encryption_key.copy_from_slice(&msg_bytes[..KEY_SIZE]);
    nonce.copy_from_slice(&msg_bytes[KEY_SIZE..]);

    Ok(MessageKeys { encryption_key, nonce })
}

/// Decrypt with derived message keys.
fn decrypt_with_keys(
    keys: &MessageKeys,
    header: &RatchetHeader,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let header_bytes = header.to_bytes();
    let nonce = aead::Nonce::from_bytes(keys.nonce);
    let plaintext = aead::decrypt(&keys.encryption_key, &nonce, ciphertext, &header_bytes)?;
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::StaticKeypair;

    fn setup_session() -> (DoubleRatchet, DoubleRatchet) {
        // Simulate X3DH key agreement (simplified)
        let alice_identity = StaticKeypair::generate();
        let bob_prekey = EphemeralKeypair::generate();

        // Shared secret from key exchange
        let shared_secret = alice_identity.diffie_hellman(bob_prekey.public_key());

        // Alice initiates, Bob responds
        let alice = DoubleRatchet::init_initiator(&shared_secret, bob_prekey.public_key())
            .expect("init alice");
        let bob = DoubleRatchet::init_responder(&shared_secret, bob_prekey);

        (alice, bob)
    }

    #[test]
    fn test_basic_exchange() {
        let (mut alice, mut bob) = setup_session();

        // Alice -> Bob
        let plaintext = b"Hello, Bob!";
        let (header, ciphertext) = alice.encrypt(plaintext).expect("encrypt");
        let decrypted = bob.decrypt(&header, &ciphertext).expect("decrypt");
        assert_eq!(&decrypted, plaintext);

        // Bob -> Alice
        let reply = b"Hello, Alice!";
        let (header, ciphertext) = bob.encrypt(reply).expect("encrypt");
        let decrypted = alice.decrypt(&header, &ciphertext).expect("decrypt");
        assert_eq!(&decrypted, reply);
    }

    #[test]
    fn test_multiple_messages() {
        let (mut alice, mut bob) = setup_session();

        for i in 0..10 {
            let msg = format!("Message {}", i);
            let (h, c) = alice.encrypt(msg.as_bytes()).expect("encrypt");
            let d = bob.decrypt(&h, &c).expect("decrypt");
            assert_eq!(d, msg.as_bytes());
        }
    }

    #[test]
    fn test_alternating_messages() {
        let (mut alice, mut bob) = setup_session();

        for i in 0..10 {
            if i % 2 == 0 {
                let msg = format!("Alice: {}", i);
                let (h, c) = alice.encrypt(msg.as_bytes()).expect("encrypt");
                let d = bob.decrypt(&h, &c).expect("decrypt");
                assert_eq!(d, msg.as_bytes());
            } else {
                let msg = format!("Bob: {}", i);
                let (h, c) = bob.encrypt(msg.as_bytes()).expect("encrypt");
                let d = alice.decrypt(&h, &c).expect("decrypt");
                assert_eq!(d, msg.as_bytes());
            }
        }
    }

    #[test]
    fn test_out_of_order() {
        let (mut alice, mut bob) = setup_session();

        // Alice sends 3 messages
        let (h1, c1) = alice.encrypt(b"msg 1").expect("encrypt");
        let (h2, c2) = alice.encrypt(b"msg 2").expect("encrypt");
        let (h3, c3) = alice.encrypt(b"msg 3").expect("encrypt");

        // Bob receives out of order
        assert_eq!(bob.decrypt(&h3, &c3).expect("decrypt"), b"msg 3");
        assert_eq!(bob.decrypt(&h1, &c1).expect("decrypt"), b"msg 1");
        assert_eq!(bob.decrypt(&h2, &c2).expect("decrypt"), b"msg 2");
    }

    #[test]
    fn test_header_serialization() {
        let header = RatchetHeader {
            dh_public: X25519PublicKey::from_bytes([42u8; 32]),
            previous_chain_length: 5,
            message_number: 10,
        };

        let bytes = header.to_bytes();
        let parsed = RatchetHeader::from_bytes(&bytes).expect("parse");

        assert_eq!(header, parsed);
    }
}
