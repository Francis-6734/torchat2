//! Packet types and payload definitions.
//!
//! Defines all packet types from spec section 6.1:
//! HELLO, SESSION_INIT, MESSAGE, ACK, REACTION, DELETE, CALL_SIGNAL, FILE_CHUNK

use crate::crypto::{RatchetHeader, X25519PublicKey};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// Serde helper for [u8; 64] arrays (signatures).
mod serde_signature {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<u8> = Vec::deserialize(deserializer)?;
        vec.try_into()
            .map_err(|_| serde::de::Error::custom("invalid signature length"))
    }
}

/// Packet types as defined in spec section 6.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PacketType {
    /// Initial handshake packet.
    Hello = 0x01,
    /// Session initialization with key exchange.
    SessionInit = 0x02,
    /// Encrypted message.
    Message = 0x03,
    /// Acknowledgment (delivery receipt).
    Ack = 0x04,
    /// Message reaction.
    Reaction = 0x05,
    /// Delete message request.
    Delete = 0x06,
    /// Voice call signaling.
    CallSignal = 0x07,
    /// File transfer chunk.
    FileChunk = 0x08,
    /// File transfer offer (metadata).
    FileOffer = 0x09,
    /// Group creation.
    GroupCreate = 0x0A,
    /// Group invite token.
    GroupInvite = 0x0B,
    /// Group join request.
    GroupJoinRequest = 0x0C,
    /// Group join acceptance.
    GroupJoinAccept = 0x0D,
    /// Group message (gossip).
    GroupMessage = 0x0E,
    /// Group member synchronization.
    GroupMemberSync = 0x0F,
    /// Group epoch key rotation.
    GroupKeyRotation = 0x10,
    /// Group admin handover.
    GroupAdminHandover = 0x11,
    /// Member leave notification.
    GroupMemberLeave = 0x12,
    /// Neighbor request (blind mode).
    GroupNeighborRequest = 0x13,
}

impl PacketType {
    /// Parse packet type from byte.
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0x01 => Ok(Self::Hello),
            0x02 => Ok(Self::SessionInit),
            0x03 => Ok(Self::Message),
            0x04 => Ok(Self::Ack),
            0x05 => Ok(Self::Reaction),
            0x06 => Ok(Self::Delete),
            0x07 => Ok(Self::CallSignal),
            0x08 => Ok(Self::FileChunk),
            0x09 => Ok(Self::FileOffer),
            0x0A => Ok(Self::GroupCreate),
            0x0B => Ok(Self::GroupInvite),
            0x0C => Ok(Self::GroupJoinRequest),
            0x0D => Ok(Self::GroupJoinAccept),
            0x0E => Ok(Self::GroupMessage),
            0x0F => Ok(Self::GroupMemberSync),
            0x10 => Ok(Self::GroupKeyRotation),
            0x11 => Ok(Self::GroupAdminHandover),
            0x12 => Ok(Self::GroupMemberLeave),
            0x13 => Ok(Self::GroupNeighborRequest),
            _ => Err(Error::Protocol(format!("unknown packet type: {:#04x}", byte))),
        }
    }

    /// Convert to byte.
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// HELLO packet payload.
///
/// Sent when initiating contact. Contains the sender's identity public key
/// and optional display name (encrypted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloPayload {
    /// Sender's Ed25519 public key (32 bytes).
    pub identity_key: [u8; 32],
    /// Sender's ephemeral X25519 public key for session setup.
    pub ephemeral_key: X25519PublicKey,
    /// Protocol features supported (bitmask).
    pub features: u32,
    /// Optional encrypted display name.
    pub encrypted_name: Option<Vec<u8>>,
}

impl HelloPayload {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// SESSION_INIT packet payload.
///
/// Completes session establishment with prekey bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInitPayload {
    /// Responder's Ed25519 identity key.
    pub identity_key: [u8; 32],
    /// Responder's signed prekey.
    pub signed_prekey: X25519PublicKey,
    /// Signature over the signed prekey.
    #[serde(with = "serde_signature")]
    pub prekey_signature: [u8; 64],
    /// One-time prekey (if available).
    pub one_time_prekey: Option<X25519PublicKey>,
    /// Initial ratchet header.
    pub ratchet_header: RatchetHeader,
    /// First encrypted message (optional).
    pub initial_ciphertext: Option<Vec<u8>>,
}

impl SessionInitPayload {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// MESSAGE packet payload.
///
/// Contains an encrypted message with ratchet header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePayload {
    /// Ratchet header for decryption.
    pub header: RatchetHeader,
    /// Encrypted message content.
    pub ciphertext: Vec<u8>,
    /// Message ID (random, for deduplication).
    pub message_id: [u8; 16],
    /// Timestamp (Unix seconds, with jitter for privacy).
    pub timestamp: i64,
}

impl MessagePayload {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// ACK packet payload.
///
/// Acknowledges receipt of a message. Used for delivery receipts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckPayload {
    /// ID of the message being acknowledged.
    pub message_id: [u8; 16],
    /// Type of acknowledgment.
    pub ack_type: AckType,
    /// Timestamp of acknowledgment.
    pub timestamp: i64,
}

/// Types of message acknowledgment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AckType {
    /// Message received by device.
    Delivered = 0x01,
    /// Message read by user.
    Read = 0x02,
}

impl AckPayload {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// REACTION packet payload.
///
/// Adds a reaction to a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionPayload {
    /// ID of the message being reacted to.
    pub message_id: [u8; 16],
    /// Reaction emoji (UTF-8 encoded).
    pub reaction: String,
    /// True to add, false to remove.
    pub add: bool,
    /// Ratchet header for encryption.
    pub header: RatchetHeader,
    /// Encrypted reaction data.
    pub ciphertext: Vec<u8>,
}

impl ReactionPayload {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// DELETE packet payload.
///
/// Requests deletion of a message on both sides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletePayload {
    /// ID of the message to delete.
    pub message_id: [u8; 16],
    /// Ratchet header.
    pub header: RatchetHeader,
    /// Encrypted delete request (proves ownership).
    pub ciphertext: Vec<u8>,
}

impl DeletePayload {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// CALL_SIGNAL packet payload.
///
/// Voice call signaling (spec section 9).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSignalPayload {
    /// Call ID (random, identifies the call session).
    pub call_id: [u8; 16],
    /// Signal type.
    pub signal_type: CallSignalType,
    /// Ratchet header.
    pub header: RatchetHeader,
    /// Encrypted signal data.
    pub ciphertext: Vec<u8>,
}

/// Types of call signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CallSignalType {
    /// Initiate a call.
    Offer = 0x01,
    /// Accept a call.
    Answer = 0x02,
    /// Call ended.
    Hangup = 0x03,
    /// Call declined.
    Decline = 0x04,
    /// Call busy.
    Busy = 0x05,
    /// Ringing.
    Ringing = 0x06,
}

impl CallSignalPayload {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// FILE_CHUNK packet payload.
///
/// File transfer chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunkPayload {
    /// Transfer ID (identifies the file transfer).
    pub transfer_id: [u8; 16],
    /// Chunk index (0-based).
    pub chunk_index: u32,
    /// Total number of chunks.
    pub total_chunks: u32,
    /// Ratchet header.
    pub header: RatchetHeader,
    /// Encrypted chunk data.
    pub ciphertext: Vec<u8>,
}

impl FileChunkPayload {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// FILE_OFFER packet payload.
///
/// Sent before file transfer to provide metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOfferPayload {
    /// Transfer ID (identifies the file transfer).
    pub transfer_id: [u8; 16],
    /// Original filename.
    pub filename: String,
    /// Total file size in bytes.
    pub size: u64,
    /// SHA-256 hash of file content.
    pub hash: [u8; 32],
    /// Total number of chunks.
    pub total_chunks: u32,
    /// Ratchet header.
    pub header: RatchetHeader,
    /// Encrypted metadata (for forward secrecy).
    pub ciphertext: Vec<u8>,
}

impl FileOfferPayload {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

// ============================================================================
// Group Protocol Payloads
// ============================================================================

/// Group policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupPolicy {
    /// Hide full member roster (members only know neighbors).
    pub blind_membership: bool,
    /// Maximum number of members allowed.
    pub max_size: u32,
    /// Allow members to invite others (or founder-only).
    pub allow_member_invite: bool,
    /// Epoch key rotation interval in seconds.
    pub key_rotation_interval: u64,
    /// Enable periodic group address rotation.
    pub address_rotation_enabled: bool,
}

impl Default for GroupPolicy {
    fn default() -> Self {
        Self {
            blind_membership: true,
            max_size: 50,
            allow_member_invite: false,
            key_rotation_interval: 86400, // 24 hours
            address_rotation_enabled: false,
        }
    }
}

/// GROUP_CREATE packet payload.
///
/// Sent by founder when creating a new group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupCreatePayload {
    /// Group ID (hash of group_name + founder_pubkey).
    pub group_id: [u8; 32],
    /// Group name (encrypted with initial symmetric key).
    pub group_name: String,
    /// Founder's Ed25519 public key.
    pub founder_pubkey: [u8; 32],
    /// Founder's signature over group_id.
    #[serde(with = "serde_signature")]
    pub founder_signature: [u8; 64],
    /// Group policy configuration.
    pub policy: GroupPolicy,
    /// Creation timestamp.
    pub created_at: i64,
}

impl GroupCreatePayload {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// GROUP_INVITE packet payload.
///
/// Cryptographic invite token that cannot be forged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInvitePayload {
    /// Group ID this invite is for.
    pub group_id: [u8; 32],
    /// Inviter's Ed25519 public key.
    pub inviter_pubkey: [u8; 32],
    /// Bootstrap peer onion address (founder or another member).
    pub bootstrap_peer: String,
    /// Expiration timestamp (Unix seconds).
    pub expires_at: i64,
    /// Unique invite ID for revocation.
    pub invite_id: [u8; 16],
    /// Encrypted metadata (group name, policy hints).
    pub encrypted_metadata: Vec<u8>,
    /// Signature over invite fields.
    #[serde(with = "serde_signature")]
    pub invite_signature: [u8; 64],
}

impl GroupInvitePayload {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// GROUP_JOIN_REQUEST packet payload.
///
/// Sent by new member to join a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupJoinRequestPayload {
    /// Group ID to join.
    pub group_id: [u8; 32],
    /// Requester's onion address.
    pub requester_onion: String,
    /// Requester's Ed25519 public key.
    pub requester_pubkey: [u8; 32],
    /// Requester's X25519 public key for epoch key encryption.
    pub requester_x25519_pubkey: [u8; 32],
    /// Invite token proving authorization.
    pub invite_token: GroupInvitePayload,
    /// Signature over join request.
    #[serde(with = "serde_signature")]
    pub request_signature: [u8; 64],
}

impl GroupJoinRequestPayload {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// Group member information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    /// Anonymous member ID (derived from pubkey + group_id).
    pub member_id: [u8; 16],
    /// Member's onion address (optional in blind mode).
    pub onion_address: Option<String>,
    /// Member's Ed25519 public key.
    pub pubkey: [u8; 32],
    /// Is this member an admin.
    pub is_admin: bool,
    /// Join timestamp.
    pub joined_at: i64,
}

/// GROUP_JOIN_ACCEPT packet payload.
///
/// Sent by founder/admin to approve membership.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupJoinAcceptPayload {
    /// Group ID.
    pub group_id: [u8; 32],
    /// New member's onion address.
    pub member_onion: String,
    /// Current epoch key (encrypted for new member).
    pub current_epoch_key: Vec<u8>,
    /// Current epoch number.
    pub epoch_number: u64,
    /// Full member list (None if blind mode).
    pub member_list: Option<Vec<GroupMember>>,
    /// Initial neighbor list (3-5 onion addresses).
    pub neighbor_list: Vec<String>,
    /// Encrypted group metadata (name, policy).
    pub encrypted_metadata: Vec<u8>,
    /// Acceptor's signature.
    #[serde(with = "serde_signature")]
    pub acceptor_signature: [u8; 64],
}

impl GroupJoinAcceptPayload {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// GROUP_MESSAGE packet payload.
///
/// Gossip-replicated group message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMessagePayload {
    /// Group ID.
    pub group_id: [u8; 32],
    /// Message ID (hash of timestamp + sender_key + nonce).
    pub msg_id: [u8; 32],
    /// Epoch number for encryption.
    pub epoch_number: u64,
    /// Anonymous sender ID.
    pub sender_anon_id: [u8; 16],
    /// Encrypted message content (with epoch key).
    pub ciphertext: Vec<u8>,
    /// Sender's signature (proves membership).
    #[serde(with = "serde_signature")]
    pub sender_signature: [u8; 64],
    /// Message timestamp.
    pub timestamp: i64,
    /// Gossip hop count (TTL).
    pub hop_count: u8,
}

impl GroupMessagePayload {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// Member action type for synchronization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemberAction {
    /// Member joined the group.
    Joined { pubkey: [u8; 32] },
    /// Member left the group.
    Left,
    /// Member promoted to admin.
    PromotedToAdmin,
}

/// Member update for synchronization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberUpdate {
    /// Member ID.
    pub member_id: [u8; 16],
    /// Action performed.
    pub action: MemberAction,
    /// Timestamp of action.
    pub timestamp: i64,
}

/// GROUP_MEMBER_SYNC packet payload.
///
/// Synchronizes member changes across the mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMemberSyncPayload {
    /// Group ID.
    pub group_id: [u8; 32],
    /// List of member updates.
    pub member_updates: Vec<MemberUpdate>,
    /// Sender's signature.
    #[serde(with = "serde_signature")]
    pub sender_signature: [u8; 64],
}

impl GroupMemberSyncPayload {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// Encrypted key share for a member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeyShare {
    /// Member ID this key is for.
    pub member_id: [u8; 16],
    /// Epoch key encrypted to member's public key.
    pub encrypted_key: Vec<u8>,
}

/// GROUP_KEY_ROTATION packet payload.
///
/// Distributes new epoch key to all members.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupKeyRotationPayload {
    /// Group ID.
    pub group_id: [u8; 32],
    /// New epoch number.
    pub new_epoch_number: u64,
    /// Encrypted key shares (one per member).
    pub new_epoch_key_encrypted: Vec<EncryptedKeyShare>,
    /// Admin's signature.
    #[serde(with = "serde_signature")]
    pub rotation_signature: [u8; 64],
}

impl GroupKeyRotationPayload {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// GROUP_ADMIN_HANDOVER packet payload.
///
/// Transfers founder/admin rights to another member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupAdminHandoverPayload {
    /// Group ID.
    pub group_id: [u8; 32],
    /// New admin's member ID.
    pub new_admin_id: [u8; 16],
    /// New admin's public key.
    pub new_admin_pubkey: [u8; 32],
    /// Current admin's signature.
    #[serde(with = "serde_signature")]
    pub handover_signature: [u8; 64],
    /// Timestamp.
    pub timestamp: i64,
}

impl GroupAdminHandoverPayload {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// GROUP_MEMBER_LEAVE packet payload.
///
/// Member voluntarily leaves the group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMemberLeavePayload {
    /// Group ID.
    pub group_id: [u8; 32],
    /// Leaving member's ID.
    pub member_id: [u8; 16],
    /// Member's signature.
    #[serde(with = "serde_signature")]
    pub member_signature: [u8; 64],
    /// Timestamp.
    pub timestamp: i64,
}

impl GroupMemberLeavePayload {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// GROUP_NEIGHBOR_REQUEST packet payload.
///
/// Request new neighbors in blind membership mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupNeighborRequestPayload {
    /// Group ID.
    pub group_id: [u8; 32],
    /// Requester's member ID.
    pub requester_id: [u8; 16],
    /// Number of neighbors requested.
    pub requested_count: u8,
    /// Requester's signature.
    #[serde(with = "serde_signature")]
    pub signature: [u8; 64],
}

impl GroupNeighborRequestPayload {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_type_roundtrip() {
        for pt in [
            PacketType::Hello,
            PacketType::SessionInit,
            PacketType::Message,
            PacketType::Ack,
            PacketType::Reaction,
            PacketType::Delete,
            PacketType::CallSignal,
            PacketType::FileChunk,
            PacketType::FileOffer,
            PacketType::GroupCreate,
            PacketType::GroupInvite,
            PacketType::GroupJoinRequest,
            PacketType::GroupJoinAccept,
            PacketType::GroupMessage,
            PacketType::GroupMemberSync,
            PacketType::GroupKeyRotation,
            PacketType::GroupAdminHandover,
            PacketType::GroupMemberLeave,
            PacketType::GroupNeighborRequest,
        ] {
            let byte = pt.to_byte();
            let parsed = PacketType::from_byte(byte).expect("should parse");
            assert_eq!(pt, parsed);
        }
    }

    #[test]
    fn test_unknown_packet_type() {
        assert!(PacketType::from_byte(0xFF).is_err());
    }
}
