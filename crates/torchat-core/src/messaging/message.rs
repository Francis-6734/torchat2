//! Message types and handling.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for a message.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub [u8; 16]);

impl MessageId {
    /// Create from bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Get as bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MessageId({})", hex::encode(&self.0[..4]))
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

/// Message delivery/read status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageStatus {
    /// Message is being sent.
    Sending,
    /// Message sent but not yet delivered.
    Sent,
    /// Message delivered to recipient's device.
    Delivered,
    /// Message read by recipient.
    Read,
    /// Message failed to send.
    Failed,
}

/// Content types for messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageContent {
    /// Plain text message.
    Text(String),
    /// Reaction to another message.
    Reaction {
        /// ID of message being reacted to.
        target_id: MessageId,
        /// Reaction emoji.
        emoji: String,
    },
    /// Delete request.
    Delete {
        /// ID of message to delete.
        target_id: MessageId,
    },
    /// System message (e.g., "session started").
    System(String),
}

impl MessageContent {
    /// Serialize content to bytes for encryption.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Deserialize content from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Check if this is a text message.
    pub fn is_text(&self) -> bool {
        matches!(self, Self::Text(_))
    }

    /// Get text content if this is a text message.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s),
            _ => None,
        }
    }
}

/// A complete message with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Unique message identifier.
    pub id: MessageId,
    /// Message content.
    pub content: MessageContent,
    /// Unix timestamp (seconds).
    pub timestamp: i64,
    /// Whether this message was sent by us.
    pub outgoing: bool,
    /// Delivery status.
    pub status: MessageStatus,
    /// Disappearing message timeout (seconds), if enabled.
    pub disappear_after: Option<u32>,
}

impl Message {
    /// Create a new outgoing text message.
    pub fn new_text(text: impl Into<String>) -> Self {
        Self {
            id: super::generate_message_id(),
            content: MessageContent::Text(text.into()),
            timestamp: chrono::Utc::now().timestamp(),
            outgoing: true,
            status: MessageStatus::Sending,
            disappear_after: None,
        }
    }

    /// Create a new reaction.
    pub fn new_reaction(target_id: MessageId, emoji: impl Into<String>) -> Self {
        Self {
            id: super::generate_message_id(),
            content: MessageContent::Reaction {
                target_id,
                emoji: emoji.into(),
            },
            timestamp: chrono::Utc::now().timestamp(),
            outgoing: true,
            status: MessageStatus::Sending,
            disappear_after: None,
        }
    }

    /// Create a delete request.
    pub fn new_delete(target_id: MessageId) -> Self {
        Self {
            id: super::generate_message_id(),
            content: MessageContent::Delete { target_id },
            timestamp: chrono::Utc::now().timestamp(),
            outgoing: true,
            status: MessageStatus::Sending,
            disappear_after: None,
        }
    }

    /// Create a system message.
    pub fn system(text: impl Into<String>) -> Self {
        Self {
            id: super::generate_message_id(),
            content: MessageContent::System(text.into()),
            timestamp: chrono::Utc::now().timestamp(),
            outgoing: false,
            status: MessageStatus::Delivered,
            disappear_after: None,
        }
    }

    /// Set disappearing message timeout.
    pub fn with_disappear_after(mut self, seconds: u32) -> Self {
        self.disappear_after = Some(seconds);
        self
    }

    /// Check if message should have disappeared by now.
    pub fn should_disappear(&self) -> bool {
        if let Some(timeout) = self.disappear_after {
            let now = chrono::Utc::now().timestamp();
            // Disappear after timeout from when it was read
            if self.status == MessageStatus::Read {
                return now - self.timestamp > timeout as i64;
            }
        }
        false
    }

    /// Mark message as delivered.
    pub fn mark_delivered(&mut self) {
        if self.status == MessageStatus::Sent || self.status == MessageStatus::Sending {
            self.status = MessageStatus::Delivered;
        }
    }

    /// Mark message as read.
    pub fn mark_read(&mut self) {
        self.status = MessageStatus::Read;
    }

    /// Mark message as sent.
    pub fn mark_sent(&mut self) {
        if self.status == MessageStatus::Sending {
            self.status = MessageStatus::Sent;
        }
    }

    /// Mark message as failed.
    pub fn mark_failed(&mut self) {
        self.status = MessageStatus::Failed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_creation() {
        let msg = Message::new_text("Hello!");

        assert!(msg.content.is_text());
        assert_eq!(msg.content.as_text(), Some("Hello!"));
        assert!(msg.outgoing);
        assert_eq!(msg.status, MessageStatus::Sending);
    }

    #[test]
    fn test_message_id_display() {
        let id = MessageId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let display = format!("{}", id);
        assert_eq!(display.len(), 16); // 8 bytes hex
    }

    #[test]
    fn test_message_status_transitions() {
        let mut msg = Message::new_text("Test");

        assert_eq!(msg.status, MessageStatus::Sending);

        msg.mark_sent();
        assert_eq!(msg.status, MessageStatus::Sent);

        msg.mark_delivered();
        assert_eq!(msg.status, MessageStatus::Delivered);

        msg.mark_read();
        assert_eq!(msg.status, MessageStatus::Read);
    }

    #[test]
    fn test_content_serialization() {
        let content = MessageContent::Text("Hello, TorChat!".into());
        let bytes = content.to_bytes().expect("should serialize");
        let parsed = MessageContent::from_bytes(&bytes).expect("should parse");

        match parsed {
            MessageContent::Text(s) => assert_eq!(s, "Hello, TorChat!"),
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn test_reaction_content() {
        let target = MessageId([0u8; 16]);
        let msg = Message::new_reaction(target, "👍");

        match &msg.content {
            MessageContent::Reaction { target_id, emoji } => {
                assert_eq!(target_id, &target);
                assert_eq!(emoji, "👍");
            }
            _ => panic!("wrong type"),
        }
    }
}
