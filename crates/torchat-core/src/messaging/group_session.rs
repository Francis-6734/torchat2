//! Group session management.
//!
//! Manages the lifecycle and state of decentralized group chats:
//! - Group creation (founder)
//! - Joining via invite
//! - Message sending/receiving
//! - Epoch key rotation
//! - Member management
//! - Mesh topology maintenance

use crate::crypto::{
    decrypt_group_message, derive_epoch_key, encrypt_group_message, generate_group_id,
    generate_initial_group_key, generate_invite_id, generate_member_id, generate_message_id,
    generate_random_nonce, sign_invite_token, verify_invite_token,
};
use crate::error::{Error, Result};
use crate::identity::TorIdentity;
use crate::messaging::group_gossip::{GossipManager, ReceivedGroupMessage};
use crate::messaging::group_mesh::{MeshTopology, DEFAULT_NEIGHBOR_COUNT};
use crate::protocol::{
    GroupInvitePayload, GroupJoinAcceptPayload, GroupMember, GroupMessagePayload, GroupPolicy,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

/// Group state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupState {
    /// Group is active.
    Active,
    /// Group is archived (left or inactive).
    Archived,
}

/// Group message (stored locally).
#[derive(Debug, Clone)]
pub struct GroupMessage {
    /// Message ID.
    pub id: [u8; 32],
    /// Sender's anonymous ID.
    pub sender_id: [u8; 16],
    /// Message content (plaintext).
    pub content: String,
    /// Message timestamp.
    pub timestamp: i64,
    /// Is this an outgoing message.
    pub outgoing: bool,
}

/// Group session.
///
/// Represents a single decentralized group chat session.
pub struct GroupSession {
    /// Group ID (unique identifier).
    pub id: [u8; 32],
    /// Group name.
    pub name: String,
    /// Founder's public key.
    pub founder_pubkey: [u8; 32],
    /// Our member ID (anonymous).
    pub our_member_id: [u8; 16],
    /// Our signing key (for signatures).
    our_signing_key: SigningKey,
    /// Group policy.
    pub policy: GroupPolicy,
    /// Group state.
    pub state: GroupState,

    // Cryptography
    /// Current epoch number.
    pub current_epoch_number: u64,
    /// Current epoch key (encrypted messages).
    current_epoch_key: Zeroizing<[u8; 32]>,
    /// Epoch key history (for decrypting old messages).
    epoch_history: VecDeque<(Zeroizing<[u8; 32]>, u64)>,

    // Members
    /// All known members (member_id -> info).
    pub members: HashMap<[u8; 16], GroupMember>,
    /// Admin member IDs.
    pub admins: HashSet<[u8; 16]>,

    // Mesh & Gossip
    /// Mesh topology manager.
    pub mesh: MeshTopology,
    /// Gossip protocol manager.
    pub gossip: GossipManager,

    // Messages
    /// Recent messages (in-memory cache).
    pub messages: VecDeque<GroupMessage>,
    /// Maximum messages to keep in memory.
    max_messages_in_memory: usize,
}

impl GroupSession {
    /// Create a new group as founder.
    pub fn create_as_founder(
        name: String,
        identity: &TorIdentity,
        policy: GroupPolicy,
    ) -> Result<Self> {
        let founder_pubkey = identity.public_key().to_bytes();
        let group_id = generate_group_id(&name, &founder_pubkey);
        let initial_key = generate_initial_group_key();
        let our_member_id = generate_member_id(&group_id, &founder_pubkey);

        // Create founder as first member
        let mut members = HashMap::new();
        members.insert(
            our_member_id,
            GroupMember {
                member_id: our_member_id,
                onion_address: Some(identity.onion_address().to_string()),
                pubkey: founder_pubkey,
                is_admin: true,
                joined_at: chrono::Utc::now().timestamp(),
            },
        );

        let mut admins = HashSet::new();
        admins.insert(our_member_id);

        info!(
            group_id = ?group_id,
            name = %name,
            "Created new group as founder"
        );

        Ok(Self {
            id: group_id,
            name,
            founder_pubkey,
            our_member_id,
            our_signing_key: identity.signing_key().clone(),
            policy,
            state: GroupState::Active,
            current_epoch_number: 0,
            current_epoch_key: initial_key,
            epoch_history: VecDeque::new(),
            members,
            admins,
            mesh: MeshTopology::new(group_id, DEFAULT_NEIGHBOR_COUNT),
            gossip: GossipManager::new(group_id, 1000, 10),
            messages: VecDeque::new(),
            max_messages_in_memory: 1000,
        })
    }

    /// Restore a group session from database.
    ///
    /// Used to restore groups when the daemon starts.
    pub fn restore_from_database(
        group_id: [u8; 32],
        name: String,
        founder_pubkey: [u8; 32],
        our_member_id: [u8; 16],
        epoch_number: u64,
        epoch_key: [u8; 32],
        policy: GroupPolicy,
        state: GroupState,
        identity: &TorIdentity,
        members: HashMap<[u8; 16], GroupMember>,
    ) -> Result<Self> {
        let mut admins = HashSet::new();
        for (member_id, member) in &members {
            if member.is_admin {
                admins.insert(*member_id);
            }
        }

        info!(
            group_id = ?group_id,
            name = %name,
            members = members.len(),
            "Restored group from database"
        );

        Ok(Self {
            id: group_id,
            name,
            founder_pubkey,
            our_member_id,
            our_signing_key: identity.signing_key().clone(),
            policy,
            state,
            current_epoch_number: epoch_number,
            current_epoch_key: Zeroizing::new(epoch_key),
            epoch_history: VecDeque::new(),
            members,
            admins,
            mesh: MeshTopology::new(group_id, DEFAULT_NEIGHBOR_COUNT),
            gossip: GossipManager::new(group_id, 1000, 10),
            messages: VecDeque::new(),
            max_messages_in_memory: 1000,
        })
    }

    /// Generate an invite token for a new member.
    pub fn generate_invite(
        &self,
        expires_at: i64,
        bootstrap_peer: &str,
    ) -> Result<GroupInvitePayload> {
        if !self.is_admin(&self.our_member_id) {
            return Err(Error::Permission("only admins can invite members".into()));
        }

        let invite_id = generate_invite_id();
        let inviter_pubkey = self.our_signing_key.verifying_key().to_bytes();

        // Encrypt metadata (group name + policy)
        let metadata = format!("{}|{}", self.name, self.policy.blind_membership);
        let encrypted_metadata = metadata.as_bytes().to_vec(); // TODO: Encrypt with recipient's pubkey

        let signature = sign_invite_token(
            &self.our_signing_key,
            &self.id,
            &inviter_pubkey,
            bootstrap_peer,
            expires_at,
            &invite_id,
        );

        Ok(GroupInvitePayload {
            group_id: self.id,
            inviter_pubkey,
            bootstrap_peer: bootstrap_peer.to_string(),
            expires_at,
            invite_id,
            encrypted_metadata,
            invite_signature: signature,
        })
    }

    /// Join a group via invite (called after receiving GroupJoinAccept).
    pub fn join_via_invite(
        invite: GroupInvitePayload,
        identity: &TorIdentity,
        encrypted_epoch_key: &[u8],
        epoch_number: u64,
        founder_member: GroupMember,
    ) -> Result<Self> {
        // Decrypt the epoch key using our X25519 secret key
        let epoch_key = crate::crypto::decrypt_epoch_key_from_sender(
            encrypted_epoch_key,
            &identity.x25519_secret_bytes(),
        )?;

        // Convert inviter pubkey to VerifyingKey
        let inviter_key = ed25519_dalek::VerifyingKey::from_bytes(&invite.inviter_pubkey)
            .map_err(|_| Error::Crypto("Invalid inviter public key".into()))?;

        // Verify invite signature
        verify_invite_token(
            &inviter_key,
            &invite.group_id,
            &invite.inviter_pubkey,
            &invite.bootstrap_peer,
            invite.expires_at,
            &invite.invite_id,
            &invite.invite_signature,
        )?;

        // Check expiration
        let now = chrono::Utc::now().timestamp();
        if now > invite.expires_at {
            return Err(Error::Protocol("invite expired".into()));
        }

        // Decrypt metadata to get group name and policy
        // TODO: Proper encryption - for now just parse plaintext
        let metadata_str = String::from_utf8(invite.encrypted_metadata.clone())
            .map_err(|_| Error::Protocol("invalid metadata".into()))?;
        let parts: Vec<&str> = metadata_str.split('|').collect();
        let group_name = parts.get(0).ok_or(Error::Protocol("invalid metadata".to_string()))?.to_string();
        let blind_membership = parts.get(1).map(|s| *s == "true").unwrap_or(false);

        let our_pubkey = identity.public_key().to_bytes();
        let our_member_id = generate_member_id(&invite.group_id, &our_pubkey);

        // Create policy
        let policy = GroupPolicy {
            blind_membership,
            max_size: 50,
            allow_member_invite: false,
            key_rotation_interval: 86400,
            address_rotation_enabled: false,
        };

        // Initialize members with founder
        let mut members = HashMap::new();
        members.insert(founder_member.member_id, founder_member.clone());

        // Add ourselves
        members.insert(
            our_member_id,
            GroupMember {
                member_id: our_member_id,
                onion_address: Some(identity.onion_address().to_string()),
                pubkey: our_pubkey,
                is_admin: false,
                joined_at: now,
            },
        );

        // Initialize mesh with founder as first neighbor
        let mut mesh = MeshTopology::new(invite.group_id, DEFAULT_NEIGHBOR_COUNT);
        mesh.add_neighbor(founder_member);

        info!(
            group_id = ?invite.group_id,
            name = %group_name,
            "Joined group via invite"
        );

        Ok(Self {
            id: invite.group_id,
            name: group_name,
            founder_pubkey: invite.inviter_pubkey,
            our_member_id,
            our_signing_key: identity.signing_key().clone(),
            policy,
            state: GroupState::Active,
            current_epoch_number: epoch_number,
            current_epoch_key: epoch_key,
            epoch_history: VecDeque::new(),
            members,
            admins: HashSet::new(), // Founder admin status managed separately
            mesh,
            gossip: GossipManager::new(invite.group_id, 1000, 10),
            messages: VecDeque::new(),
            max_messages_in_memory: 1000,
        })
    }

    /// Send a message to the group.
    pub fn send_message(&mut self, content: &str) -> Result<GroupMessagePayload> {
        if self.state != GroupState::Active {
            return Err(Error::State("group is not active".into()));
        }

        let timestamp = chrono::Utc::now().timestamp();
        let nonce = generate_random_nonce();
        let msg_id = generate_message_id(
            timestamp,
            &self.our_signing_key.verifying_key().to_bytes(),
            &nonce,
        );

        // Sign message ID
        let signature = self.our_signing_key.sign(&msg_id);

        // Create outgoing message payload
        let payload = self.gossip.create_outgoing_message(
            msg_id,
            self.our_member_id,
            content,
            self.current_epoch_number,
            &*self.current_epoch_key,
            timestamp,
            signature.to_bytes(),
        )?;

        // Store locally
        self.messages.push_back(GroupMessage {
            id: msg_id,
            sender_id: self.our_member_id,
            content: content.to_string(),
            timestamp,
            outgoing: true,
        });

        // Trim message cache
        if self.messages.len() > self.max_messages_in_memory {
            self.messages.pop_front();
        }

        info!(msg_id = ?msg_id, "Sent group message");

        Ok(payload)
    }

    /// Receive and process an incoming group message.
    pub fn receive_message(&mut self, payload: &GroupMessagePayload) -> Result<Option<ReceivedGroupMessage>> {
        // Process through gossip manager
        let received = self.gossip.handle_incoming_message(
            payload,
            &*self.current_epoch_key,
        )?;

        if let Some(ref msg) = received {
            // Store locally
            self.messages.push_back(GroupMessage {
                id: msg.msg_id,
                sender_id: msg.sender_id,
                content: msg.content.clone(),
                timestamp: msg.timestamp,
                outgoing: false,
            });

            // Trim cache
            if self.messages.len() > self.max_messages_in_memory {
                self.messages.pop_front();
            }

            // Update mesh neighbor activity
            self.mesh.mark_neighbor_seen(&msg.sender_id);
            self.mesh.increment_neighbor_messages(&msg.sender_id);

            debug!(
                msg_id = ?msg.msg_id,
                sender_id = ?msg.sender_id,
                "Received group message"
            );
        }

        Ok(received)
    }

    /// Rotate epoch key (admin only).
    pub fn rotate_epoch_key(&mut self) -> Result<()> {
        if !self.is_admin(&self.our_member_id) {
            return Err(Error::Permission("only admins can rotate keys".into()));
        }

        let new_epoch = self.current_epoch_number + 1;
        let new_key = derive_epoch_key(
            &*self.current_epoch_key,
            new_epoch,
            &self.id,
        )?;

        // Store old key in history (keep last 7 for decrypting old messages)
        self.epoch_history.push_back((
            self.current_epoch_key.clone(),
            self.current_epoch_number,
        ));
        if self.epoch_history.len() > 7 {
            self.epoch_history.pop_front();
        }

        // Update current
        self.current_epoch_number = new_epoch;
        self.current_epoch_key = new_key;

        info!(
            epoch_number = new_epoch,
            "Rotated epoch key"
        );

        Ok(())
    }

    /// Add a member to the group.
    pub fn add_member(&mut self, member: GroupMember) {
        let member_id = member.member_id;
        self.members.insert(member_id, member.clone());

        // Add to mesh if we have their onion address
        if member.onion_address.is_some() {
            self.mesh.add_neighbor(member);
        }

        debug!(member_id = ?member_id, "Added member to group");
    }

    /// Remove a member from the group (admin only).
    pub fn remove_member(&mut self, member_id: &[u8; 16]) -> Result<()> {
        if !self.is_admin(&self.our_member_id) {
            return Err(Error::Permission("only admins can remove members".into()));
        }

        self.members.remove(member_id);
        self.admins.remove(member_id);
        self.mesh.remove_neighbor(member_id);

        info!(member_id = ?member_id, "Removed member from group");

        Ok(())
    }

    /// Check if a member is an admin.
    pub fn is_admin(&self, member_id: &[u8; 16]) -> bool {
        self.admins.contains(member_id)
    }

    /// Get the current epoch key for encryption.
    pub fn current_epoch_key(&self) -> &[u8; 32] {
        &*self.current_epoch_key
    }

    /// Get member count.
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Get message count.
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Get recent messages.
    pub fn recent_messages(&self, limit: usize) -> Vec<&GroupMessage> {
        self.messages
            .iter()
            .rev()
            .take(limit)
            .collect()
    }

    /// Archive the group (leave).
    pub fn archive(&mut self) {
        self.state = GroupState::Archived;
        info!(group_id = ?self.id, "Archived group");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::TorIdentity;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn create_test_identity() -> TorIdentity {
        let signing_key = SigningKey::generate(&mut OsRng);
        TorIdentity::from_signing_key(signing_key).unwrap()
    }

    #[test]
    fn test_create_group_as_founder() {
        let identity = create_test_identity();
        let policy = GroupPolicy::default();

        let session = GroupSession::create_as_founder(
            "Test Group".to_string(),
            &identity,
            policy,
        ).unwrap();

        assert_eq!(session.name, "Test Group");
        assert_eq!(session.state, GroupState::Active);
        assert_eq!(session.member_count(), 1);
        assert!(session.is_admin(&session.our_member_id));
        assert_eq!(session.current_epoch_number, 0);
    }

    #[test]
    fn test_generate_invite() {
        let identity = create_test_identity();
        let policy = GroupPolicy::default();

        let session = GroupSession::create_as_founder(
            "Test Group".to_string(),
            &identity,
            policy,
        ).unwrap();

        let expires_at = chrono::Utc::now().timestamp() + 86400; // 1 day
        let invite = session.generate_invite(expires_at, "founder.onion").unwrap();

        assert_eq!(invite.group_id, session.id);
        assert_eq!(invite.bootstrap_peer, "founder.onion");
    }

    #[test]
    fn test_send_message() {
        let identity = create_test_identity();
        let policy = GroupPolicy::default();

        let mut session = GroupSession::create_as_founder(
            "Test Group".to_string(),
            &identity,
            policy,
        ).unwrap();

        let payload = session.send_message("Hello, group!").unwrap();

        assert_eq!(payload.group_id, session.id);
        assert_eq!(payload.hop_count, 0);
        assert_eq!(session.message_count(), 1);
    }

    #[test]
    fn test_rotate_epoch_key() {
        let identity = create_test_identity();
        let policy = GroupPolicy::default();

        let mut session = GroupSession::create_as_founder(
            "Test Group".to_string(),
            &identity,
            policy,
        ).unwrap();

        let old_epoch = session.current_epoch_number;
        session.rotate_epoch_key().unwrap();

        assert_eq!(session.current_epoch_number, old_epoch + 1);
        assert_eq!(session.epoch_history.len(), 1);
    }

    #[test]
    fn test_add_remove_member() {
        let identity = create_test_identity();
        let policy = GroupPolicy::default();

        let mut session = GroupSession::create_as_founder(
            "Test Group".to_string(),
            &identity,
            policy,
        ).unwrap();

        let new_member = GroupMember {
            member_id: [2u8; 16],
            onion_address: Some("peer2.onion".to_string()),
            pubkey: [2u8; 32],
            is_admin: false,
            joined_at: 0,
        };

        session.add_member(new_member.clone());
        assert_eq!(session.member_count(), 2);

        session.remove_member(&new_member.member_id).unwrap();
        assert_eq!(session.member_count(), 1);
    }

    #[test]
    fn test_archive() {
        let identity = create_test_identity();
        let policy = GroupPolicy::default();

        let mut session = GroupSession::create_as_founder(
            "Test Group".to_string(),
            &identity,
            policy,
        ).unwrap();

        assert_eq!(session.state, GroupState::Active);

        session.archive();
        assert_eq!(session.state, GroupState::Archived);

        // Should not be able to send messages when archived
        let result = session.send_message("Test");
        assert!(result.is_err());
    }
}
