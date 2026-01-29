//! Chat session management.
//!
//! A session represents an ongoing conversation with a peer.
//! Each session has its own Double Ratchet state for encryption.

use super::message::{Message, MessageContent, MessageId, MessageStatus};
use crate::crypto::{DoubleRatchet, EphemeralKeypair, SharedSecret, X25519PublicKey};
use crate::error::{Error, Result};
use crate::identity::OnionAddress;
use crate::protocol::MessagePayload;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Unique identifier for a session.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub [u8; 32]);

impl SessionId {
    /// Create from bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from peer's onion address.
    pub fn from_onion(onion: &OnionAddress) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(onion.as_str().as_bytes());
        let hash = hasher.finalize();
        Self(hash.into())
    }

    /// Get as bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({})", hex::encode(&self.0[..8]))
    }
}

/// Session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Session not yet established.
    Pending,
    /// Key exchange in progress.
    Establishing,
    /// Session active and ready for messages.
    Active,
    /// Session closed.
    Closed,
}

/// A chat session with a peer.
pub struct Session {
    /// Session identifier.
    id: SessionId,
    /// Peer's onion address.
    peer_address: OnionAddress,
    /// Peer's identity public key (Ed25519).
    _peer_identity_key: Option<[u8; 32]>,
    /// Double Ratchet for encryption.
    ratchet: Option<DoubleRatchet>,
    /// Session state.
    state: SessionState,
    /// Messages in this session (keyed by ID).
    messages: HashMap<MessageId, Message>,
    /// Message order (for display).
    message_order: Vec<MessageId>,
    /// Unread message count.
    unread_count: u32,
    /// Last activity timestamp.
    last_activity: i64,
}

impl Session {
    /// Create a new session (initiator side).
    ///
    /// Call `establish_initiator` after key exchange to activate.
    pub fn new_initiator(peer_address: OnionAddress) -> Self {
        Self {
            id: SessionId::from_onion(&peer_address),
            peer_address,
            _peer_identity_key: None,
            ratchet: None,
            state: SessionState::Pending,
            messages: HashMap::new(),
            message_order: Vec::new(),
            unread_count: 0,
            last_activity: chrono::Utc::now().timestamp(),
        }
    }

    /// Create a new session (responder side).
    ///
    /// Call `establish_responder` after key exchange to activate.
    pub fn new_responder(peer_address: OnionAddress, peer_identity_key: [u8; 32]) -> Self {
        Self {
            id: SessionId::from_onion(&peer_address),
            peer_address,
            _peer_identity_key: Some(peer_identity_key),
            ratchet: None,
            state: SessionState::Pending,
            messages: HashMap::new(),
            message_order: Vec::new(),
            unread_count: 0,
            last_activity: chrono::Utc::now().timestamp(),
        }
    }

    /// Establish session as initiator.
    ///
    /// Called after X3DH key exchange completes.
    pub fn establish_initiator(
        &mut self,
        shared_secret: &SharedSecret,
        their_prekey: &X25519PublicKey,
    ) -> Result<()> {
        let ratchet = DoubleRatchet::init_initiator(shared_secret, their_prekey)?;
        self.ratchet = Some(ratchet);
        self.state = SessionState::Active;
        self.last_activity = chrono::Utc::now().timestamp();

        // Add system message
        let sys_msg = Message::system("Session established");
        self.add_message(sys_msg);

        Ok(())
    }

    /// Establish session as responder.
    ///
    /// Called after X3DH key exchange completes.
    pub fn establish_responder(
        &mut self,
        shared_secret: &SharedSecret,
        our_prekey: EphemeralKeypair,
    ) {
        let ratchet = DoubleRatchet::init_responder(shared_secret, our_prekey);
        self.ratchet = Some(ratchet);
        self.state = SessionState::Active;
        self.last_activity = chrono::Utc::now().timestamp();

        // Add system message
        let sys_msg = Message::system("Session established");
        self.add_message(sys_msg);
    }

    /// Get session ID.
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// Get peer's onion address.
    pub fn peer_address(&self) -> &OnionAddress {
        &self.peer_address
    }

    /// Get session state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Check if session is active.
    pub fn is_active(&self) -> bool {
        self.state == SessionState::Active
    }

    /// Get unread message count.
    pub fn unread_count(&self) -> u32 {
        self.unread_count
    }

    /// Get last activity timestamp.
    pub fn last_activity(&self) -> i64 {
        self.last_activity
    }

    /// Encrypt a message for sending.
    pub fn encrypt_message(&mut self, message: &mut Message) -> Result<MessagePayload> {
        let ratchet = self
            .ratchet
            .as_mut()
            .ok_or_else(|| Error::NoSession)?;

        // Serialize content
        let plaintext = message.content.to_bytes()?;

        // Encrypt
        let (header, ciphertext) = ratchet.encrypt(&plaintext)?;

        // Update message status
        message.mark_sent();

        // Update activity
        self.last_activity = chrono::Utc::now().timestamp();

        Ok(MessagePayload {
            header,
            ciphertext,
            message_id: *message.id.as_bytes(),
            timestamp: super::add_timestamp_jitter(message.timestamp, 5),
        })
    }

    /// Decrypt a received message.
    pub fn decrypt_message(&mut self, payload: &MessagePayload) -> Result<Message> {
        let ratchet = self
            .ratchet
            .as_mut()
            .ok_or_else(|| Error::NoSession)?;

        // Decrypt
        let plaintext = ratchet.decrypt(&payload.header, &payload.ciphertext)?;

        // Parse content
        let content = MessageContent::from_bytes(&plaintext)?;

        // Create message
        let message = Message {
            id: MessageId::from_bytes(payload.message_id),
            content,
            timestamp: payload.timestamp,
            outgoing: false,
            status: MessageStatus::Delivered,
            disappear_after: None,
        };

        // Update activity
        self.last_activity = chrono::Utc::now().timestamp();

        Ok(message)
    }

    /// Add a message to the session.
    pub fn add_message(&mut self, message: Message) {
        let id = message.id;
        // Only count as unread if it's an incoming non-system message that hasn't been read
        let is_system = matches!(message.content, MessageContent::System(_));
        if !message.outgoing && !is_system && message.status != MessageStatus::Read {
            self.unread_count += 1;
        }
        self.message_order.push(id);
        self.messages.insert(id, message);
    }

    /// Get a message by ID.
    pub fn get_message(&self, id: &MessageId) -> Option<&Message> {
        self.messages.get(id)
    }

    /// Get a mutable message by ID.
    pub fn get_message_mut(&mut self, id: &MessageId) -> Option<&mut Message> {
        self.messages.get_mut(id)
    }

    /// Delete a message.
    pub fn delete_message(&mut self, id: &MessageId) -> Option<Message> {
        if let Some(msg) = self.messages.remove(id) {
            self.message_order.retain(|mid| mid != id);
            Some(msg)
        } else {
            None
        }
    }

    /// Get all messages in order.
    pub fn messages(&self) -> impl Iterator<Item = &Message> {
        self.message_order
            .iter()
            .filter_map(|id| self.messages.get(id))
    }

    /// Mark all messages as read.
    pub fn mark_all_read(&mut self) {
        for msg in self.messages.values_mut() {
            if !msg.outgoing && msg.status == MessageStatus::Delivered {
                msg.mark_read();
            }
        }
        self.unread_count = 0;
    }

    /// Close the session.
    pub fn close(&mut self) {
        self.state = SessionState::Closed;
        let sys_msg = Message::system("Session closed");
        self.add_message(sys_msg);
    }

    /// Get message count.
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("peer_address", &self.peer_address)
            .field("state", &self.state)
            .field("message_count", &self.messages.len())
            .field("unread_count", &self.unread_count)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::StaticKeypair;

    fn create_test_session_pair() -> (Session, Session) {
        let alice_addr =
            OnionAddress::from_string("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaid.onion")
                .expect("valid");
        let bob_addr =
            OnionAddress::from_string("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbid.onion")
                .expect("valid");

        // Simplified key exchange
        let alice_identity = StaticKeypair::generate();
        let bob_prekey = EphemeralKeypair::generate();
        let shared_secret = alice_identity.diffie_hellman(bob_prekey.public_key());

        let mut alice_session = Session::new_initiator(bob_addr);
        alice_session
            .establish_initiator(&shared_secret, bob_prekey.public_key())
            .expect("establish");

        let mut bob_session = Session::new_responder(alice_addr, [0u8; 32]);
        bob_session.establish_responder(&shared_secret, bob_prekey);

        (alice_session, bob_session)
    }

    #[test]
    fn test_session_creation() {
        let addr =
            OnionAddress::from_string("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaid.onion")
                .expect("valid");
        let session = Session::new_initiator(addr.clone());

        assert_eq!(session.state(), SessionState::Pending);
        assert_eq!(session.peer_address(), &addr);
        assert_eq!(session.message_count(), 0);
    }

    #[test]
    fn test_message_exchange() {
        let (mut alice, mut bob) = create_test_session_pair();

        // Alice sends message
        let mut msg = Message::new_text("Hello, Bob!");
        let payload = alice.encrypt_message(&mut msg).expect("encrypt");
        alice.add_message(msg);

        // Bob receives
        let received = bob.decrypt_message(&payload).expect("decrypt");
        assert_eq!(received.content.as_text(), Some("Hello, Bob!"));
        bob.add_message(received);

        assert_eq!(alice.message_count(), 2); // system + message
        assert_eq!(bob.message_count(), 2);
    }

    #[test]
    fn test_unread_count() {
        let (mut alice, mut bob) = create_test_session_pair();

        // Initial unread is 0 (system message doesn't count as unread)
        assert_eq!(bob.unread_count(), 0);

        // Alice sends message
        let mut msg = Message::new_text("Test");
        let payload = alice.encrypt_message(&mut msg).expect("encrypt");

        // Bob receives
        let received = bob.decrypt_message(&payload).expect("decrypt");
        bob.add_message(received);

        assert_eq!(bob.unread_count(), 1); // add_message adds 1 for non-system messages

        // Mark all read
        bob.mark_all_read();
        assert_eq!(bob.unread_count(), 0);
    }
}
