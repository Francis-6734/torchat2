//! Gossip protocol for decentralized group messaging.
//!
//! Implements epidemic gossip (flooding) for message replication:
//! - Message deduplication (prevent loops)
//! - TTL-based forwarding (hop count limit)
//! - Eventual consistency across the mesh
//! - No central relay or coordinator

use crate::crypto::{decrypt_group_message, encrypt_group_message};
use crate::error::{Error, Result};
use crate::protocol::GroupMessagePayload;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};
use tracing::debug;

/// Maximum hop count for gossip messages (TTL).
pub const MAX_HOP_COUNT: u8 = 10;

/// Deduplication cache size (number of message IDs to remember).
pub const DEDUP_CACHE_SIZE: usize = 1000;

/// Message ID TTL in deduplication cache (1 hour).
pub const DEDUP_TTL: Duration = Duration::from_secs(3600);

/// Received group message (decrypted).
#[derive(Debug, Clone)]
pub struct ReceivedGroupMessage {
    /// Message ID.
    pub msg_id: [u8; 32],
    /// Sender's anonymous ID.
    pub sender_id: [u8; 16],
    /// Message content (plaintext).
    pub content: String,
    /// Message timestamp.
    pub timestamp: i64,
    /// Epoch number used for encryption.
    pub epoch_number: u64,
    /// Hop count when received.
    pub hop_count: u8,
}

/// Deduplication cache entry.
#[derive(Debug, Clone)]
struct DeduplicationEntry {
    /// When this message was first seen.
    first_seen: Instant,
}

/// Gossip manager for group messages.
///
/// Handles message flooding, deduplication, and forwarding logic.
pub struct GossipManager {
    /// Group ID this gossip manager belongs to.
    group_id: [u8; 32],
    /// Deduplication cache (msg_id -> entry).
    seen_messages: LruCache<[u8; 32], DeduplicationEntry>,
    /// Maximum hop count (TTL).
    max_hop_count: u8,
    /// Message ID TTL.
    message_ttl: Duration,
}

impl GossipManager {
    /// Create a new gossip manager.
    pub fn new(group_id: [u8; 32], cache_size: usize, max_hops: u8) -> Self {
        Self {
            group_id,
            seen_messages: LruCache::new(
                NonZeroUsize::new(cache_size).unwrap_or(NonZeroUsize::new(DEDUP_CACHE_SIZE).unwrap())
            ),
            max_hop_count: max_hops,
            message_ttl: DEDUP_TTL,
        }
    }

    /// Check if we've already seen this message.
    pub fn is_seen(&mut self, msg_id: &[u8; 32]) -> bool {
        if let Some(entry) = self.seen_messages.get(msg_id) {
            // Check if still within TTL
            if entry.first_seen.elapsed() < self.message_ttl {
                return true;
            }
        }
        false
    }

    /// Mark a message as seen.
    pub fn mark_seen(&mut self, msg_id: [u8; 32]) {
        let entry = DeduplicationEntry {
            first_seen: Instant::now(),
        };
        self.seen_messages.put(msg_id, entry);
    }

    /// Check if a message should be forwarded (based on hop count).
    pub fn should_forward(&self, hop_count: u8) -> bool {
        hop_count < self.max_hop_count
    }

    /// Handle an incoming group message.
    ///
    /// Returns `Ok(Some(message))` if this is a new message that should be processed.
    /// Returns `Ok(None)` if this is a duplicate (already seen).
    /// Returns `Err` if decryption fails.
    pub fn handle_incoming_message(
        &mut self,
        payload: &GroupMessagePayload,
        epoch_key: &[u8; 32],
    ) -> Result<Option<ReceivedGroupMessage>> {
        // 1. Check group ID
        if payload.group_id != self.group_id {
            return Err(Error::Protocol(format!(
                "Message for wrong group (expected {:?}, got {:?})",
                self.group_id, payload.group_id
            )));
        }

        // 2. Check if already seen (deduplication)
        if self.is_seen(&payload.msg_id) {
            debug!(msg_id = ?payload.msg_id, "Dropping duplicate message");
            return Ok(None);
        }

        // 3. Decrypt message
        let plaintext = decrypt_group_message(
            epoch_key,
            &payload.ciphertext,
            &payload.msg_id,
        )?;

        let content = String::from_utf8(plaintext)
            .map_err(|_| Error::Encoding("invalid UTF-8 in message".into()))?;

        // 4. Mark as seen
        self.mark_seen(payload.msg_id);

        // 5. Create received message
        let received = ReceivedGroupMessage {
            msg_id: payload.msg_id,
            sender_id: payload.sender_anon_id,
            content,
            timestamp: payload.timestamp,
            epoch_number: payload.epoch_number,
            hop_count: payload.hop_count,
        };

        debug!(
            msg_id = ?payload.msg_id,
            hop_count = payload.hop_count,
            "Received new group message"
        );

        Ok(Some(received))
    }

    /// Prepare a message for forwarding (increment hop count).
    pub fn prepare_for_forward(&self, mut payload: GroupMessagePayload) -> Option<GroupMessagePayload> {
        if !self.should_forward(payload.hop_count) {
            debug!(
                msg_id = ?payload.msg_id,
                hop_count = payload.hop_count,
                "Message reached max hop count, not forwarding"
            );
            return None;
        }

        payload.hop_count += 1;
        Some(payload)
    }

    /// Create a new outgoing message payload.
    pub fn create_outgoing_message(
        &mut self,
        msg_id: [u8; 32],
        sender_id: [u8; 16],
        content: &str,
        epoch_number: u64,
        epoch_key: &[u8; 32],
        timestamp: i64,
        sender_signature: [u8; 64],
    ) -> Result<GroupMessagePayload> {
        // Encrypt message
        let ciphertext = encrypt_group_message(
            epoch_key,
            content.as_bytes(),
            &msg_id,
        )?;

        // Mark as seen (we created it)
        self.mark_seen(msg_id);

        let payload = GroupMessagePayload {
            group_id: self.group_id,
            msg_id,
            epoch_number,
            sender_anon_id: sender_id,
            ciphertext,
            sender_signature,
            timestamp,
            hop_count: 0, // Start at 0
        };

        debug!(msg_id = ?msg_id, "Created outgoing group message");

        Ok(payload)
    }

    /// Get cache statistics.
    pub fn cache_stats(&self) -> (usize, usize) {
        (self.seen_messages.len(), self.seen_messages.cap().get())
    }

    /// Cleanup expired entries from cache.
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let expired_keys: Vec<_> = self
            .seen_messages
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.first_seen) >= self.message_ttl)
            .map(|(k, _)| *k)
            .collect();

        for key in expired_keys {
            self.seen_messages.pop(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_message_id, generate_random_nonce};

    fn create_test_payload(
        group_id: [u8; 32],
        msg_id: [u8; 32],
        hop_count: u8,
    ) -> GroupMessagePayload {
        GroupMessagePayload {
            group_id,
            msg_id,
            epoch_number: 1,
            sender_anon_id: [1u8; 16],
            ciphertext: vec![],
            sender_signature: [0u8; 64],
            timestamp: 1234567890,
            hop_count,
        }
    }

    #[test]
    fn test_deduplication() {
        let group_id = [1u8; 32];
        let mut gossip = GossipManager::new(group_id, 100, 10);

        let msg_id = [2u8; 32];

        // First time: not seen
        assert!(!gossip.is_seen(&msg_id));

        // Mark as seen
        gossip.mark_seen(msg_id);

        // Second time: seen
        assert!(gossip.is_seen(&msg_id));
    }

    #[test]
    fn test_should_forward() {
        let group_id = [1u8; 32];
        let gossip = GossipManager::new(group_id, 100, 5);

        assert!(gossip.should_forward(0));
        assert!(gossip.should_forward(4));
        assert!(!gossip.should_forward(5));
        assert!(!gossip.should_forward(10));
    }

    #[test]
    fn test_prepare_for_forward() {
        let group_id = [1u8; 32];
        let gossip = GossipManager::new(group_id, 100, 5);

        let payload = create_test_payload(group_id, [2u8; 32], 3);

        // Should forward and increment
        let forwarded = gossip.prepare_for_forward(payload.clone());
        assert!(forwarded.is_some());
        assert_eq!(forwarded.unwrap().hop_count, 4);

        // At max, should not forward
        let payload_at_max = create_test_payload(group_id, [3u8; 32], 5);
        let not_forwarded = gossip.prepare_for_forward(payload_at_max);
        assert!(not_forwarded.is_none());
    }

    #[test]
    fn test_cache_stats() {
        let group_id = [1u8; 32];
        let mut gossip = GossipManager::new(group_id, 100, 10);

        gossip.mark_seen([1u8; 32]);
        gossip.mark_seen([2u8; 32]);

        let (len, cap) = gossip.cache_stats();
        assert_eq!(len, 2);
        assert_eq!(cap, 100);
    }

    #[test]
    fn test_create_outgoing_message() {
        let group_id = [1u8; 32];
        let mut gossip = GossipManager::new(group_id, 100, 10);

        let msg_id = [2u8; 32];
        let sender_id = [3u8; 16];
        let content = "Hello, group!";
        let epoch_key = [4u8; 32];

        let payload = gossip.create_outgoing_message(
            msg_id,
            sender_id,
            content,
            1,
            &epoch_key,
            1234567890,
            [0u8; 64],
        ).unwrap();

        assert_eq!(payload.group_id, group_id);
        assert_eq!(payload.msg_id, msg_id);
        assert_eq!(payload.hop_count, 0);
        assert_eq!(payload.epoch_number, 1);

        // Should be marked as seen
        assert!(gossip.is_seen(&msg_id));
    }

    #[test]
    fn test_wrong_group_id() {
        let group_id = [1u8; 32];
        let mut gossip = GossipManager::new(group_id, 100, 10);

        let wrong_group_id = [2u8; 32];
        let payload = create_test_payload(wrong_group_id, [3u8; 32], 0);
        let epoch_key = [4u8; 32];

        let result = gossip.handle_incoming_message(&payload, &epoch_key);
        assert!(result.is_err());
    }
}
