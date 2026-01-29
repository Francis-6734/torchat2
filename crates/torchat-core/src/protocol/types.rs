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
