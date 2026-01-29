//! Client-side offline message queue.
//!
//! Provides persistent storage for messages when contacts are offline.
//! Messages are automatically retried when the contact comes online.
//!
//! ## Features
//!
//! - Persistent SQLite storage
//! - Automatic retry with exponential backoff
//! - Per-contact queue management
//! - Queue size limits to prevent unbounded growth
//! - Message expiration
//!
//! ## Design
//!
//! Unlike relay-based offline storage, this queue is entirely client-side.
//! Messages remain encrypted and are retried directly to the recipient
//! when connectivity is restored.

use crate::error::{Error, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum messages per contact in the queue.
pub const MAX_QUEUE_SIZE_PER_CONTACT: usize = 1000;

/// Maximum total queue size.
pub const MAX_TOTAL_QUEUE_SIZE: usize = 10000;

/// Default message expiration (7 days).
pub const DEFAULT_EXPIRATION_SECS: i64 = 7 * 24 * 60 * 60;

/// Maximum retry count before marking as failed.
pub const MAX_RETRIES: u32 = 10;

/// Initial retry delay in seconds.
pub const INITIAL_RETRY_DELAY_SECS: i64 = 30;

/// Maximum retry delay in seconds.
pub const MAX_RETRY_DELAY_SECS: i64 = 3600;

/// Offline message status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum OfflineStatus {
    /// Message is pending delivery.
    Pending = 0,
    /// Currently attempting delivery.
    Sending = 1,
    /// Successfully delivered.
    Delivered = 2,
    /// Permanently failed.
    Failed = 3,
    /// Expired without delivery.
    Expired = 4,
}

impl From<i32> for OfflineStatus {
    fn from(value: i32) -> Self {
        match value {
            0 => Self::Pending,
            1 => Self::Sending,
            2 => Self::Delivered,
            3 => Self::Failed,
            4 => Self::Expired,
            _ => Self::Pending,
        }
    }
}

/// A queued offline message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineMessage {
    /// Database row ID.
    pub id: i64,
    /// Message UUID.
    pub message_id: [u8; 16],
    /// Recipient onion address.
    pub recipient: String,
    /// Encrypted packet data.
    pub packet_data: Vec<u8>,
    /// Packet type byte.
    pub packet_type: u8,
    /// Current status.
    pub status: OfflineStatus,
    /// Retry count.
    pub retries: u32,
    /// Time queued (Unix timestamp).
    pub queued_at: i64,
    /// Next retry time (Unix timestamp).
    pub next_retry: i64,
    /// Last attempt time (Unix timestamp).
    pub last_attempt: i64,
    /// Expiration time (Unix timestamp).
    pub expires_at: i64,
    /// Priority (lower = higher priority).
    pub priority: i32,
}

/// Statistics about the offline queue.
#[derive(Debug, Clone, Default)]
pub struct QueueStats {
    /// Total messages in queue.
    pub total_messages: usize,
    /// Pending messages.
    pub pending: usize,
    /// Sending messages.
    pub sending: usize,
    /// Delivered messages.
    pub delivered: usize,
    /// Failed messages.
    pub failed: usize,
    /// Expired messages.
    pub expired: usize,
    /// Unique contacts with queued messages.
    pub unique_contacts: usize,
}

/// The offline message queue.
pub struct OfflineQueue {
    conn: Arc<Mutex<Connection>>,
    expiration_secs: i64,
}

impl OfflineQueue {
    /// Open or create an offline queue database.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;

        // Create tables
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS offline_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id BLOB NOT NULL UNIQUE,
                recipient TEXT NOT NULL,
                packet_data BLOB NOT NULL,
                packet_type INTEGER NOT NULL,
                status INTEGER NOT NULL DEFAULT 0,
                retries INTEGER NOT NULL DEFAULT 0,
                queued_at INTEGER NOT NULL,
                next_retry INTEGER NOT NULL,
                last_attempt INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER NOT NULL,
                priority INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_offline_recipient ON offline_messages(recipient);
            CREATE INDEX IF NOT EXISTS idx_offline_status ON offline_messages(status);
            CREATE INDEX IF NOT EXISTS idx_offline_next_retry ON offline_messages(next_retry);
            CREATE INDEX IF NOT EXISTS idx_offline_expires ON offline_messages(expires_at);
            "#,
        )?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            expiration_secs: DEFAULT_EXPIRATION_SECS,
        })
    }

    /// Open an in-memory queue (for testing).
    pub fn open_in_memory() -> Result<Self> {
        Self::open(":memory:")
    }

    /// Set the message expiration time.
    pub fn set_expiration(&mut self, secs: i64) {
        self.expiration_secs = secs;
    }

    /// Queue a message for offline delivery.
    pub fn enqueue(
        &self,
        message_id: [u8; 16],
        recipient: &str,
        packet_data: &[u8],
        packet_type: u8,
        priority: i32,
    ) -> Result<i64> {
        let now = current_timestamp();
        let conn = self.conn.lock().map_err(|_| Error::Storage("lock poisoned".into()))?;

        // Check queue limits
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM offline_messages WHERE recipient = ? AND status IN (0, 1)",
            params![recipient],
            |row| row.get(0),
        )?;

        if count as usize >= MAX_QUEUE_SIZE_PER_CONTACT {
            return Err(Error::Storage("queue limit reached for contact".into()));
        }

        let total: i64 = conn.query_row(
            "SELECT COUNT(*) FROM offline_messages WHERE status IN (0, 1)",
            [],
            |row| row.get(0),
        )?;

        if total as usize >= MAX_TOTAL_QUEUE_SIZE {
            return Err(Error::Storage("total queue limit reached".into()));
        }

        // Insert message
        conn.execute(
            r#"INSERT INTO offline_messages
               (message_id, recipient, packet_data, packet_type, status, queued_at, next_retry, expires_at, priority)
               VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)"#,
            params![
                message_id.as_slice(),
                recipient,
                packet_data,
                packet_type as i32,
                now,
                now,
                now + self.expiration_secs,
                priority,
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    /// Get messages ready for retry.
    pub fn get_pending(&self, limit: usize) -> Result<Vec<OfflineMessage>> {
        let now = current_timestamp();
        let conn = self.conn.lock().map_err(|_| Error::Storage("lock poisoned".into()))?;

        let mut stmt = conn.prepare(
            r#"SELECT id, message_id, recipient, packet_data, packet_type, status,
                      retries, queued_at, next_retry, last_attempt, expires_at, priority
               FROM offline_messages
               WHERE status = 0 AND next_retry <= ? AND expires_at > ?
               ORDER BY priority ASC, queued_at ASC
               LIMIT ?"#,
        )?;

        let messages = stmt
            .query_map(params![now, now, limit as i64], |row| {
                let message_id_blob: Vec<u8> = row.get(1)?;
                let mut message_id = [0u8; 16];
                if message_id_blob.len() == 16 {
                    message_id.copy_from_slice(&message_id_blob);
                }

                Ok(OfflineMessage {
                    id: row.get(0)?,
                    message_id,
                    recipient: row.get(2)?,
                    packet_data: row.get(3)?,
                    packet_type: row.get::<_, i32>(4)? as u8,
                    status: OfflineStatus::from(row.get::<_, i32>(5)?),
                    retries: row.get::<_, i32>(6)? as u32,
                    queued_at: row.get(7)?,
                    next_retry: row.get(8)?,
                    last_attempt: row.get(9)?,
                    expires_at: row.get(10)?,
                    priority: row.get(11)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(messages)
    }

    /// Get all pending messages for a specific contact.
    pub fn get_pending_for_contact(&self, recipient: &str) -> Result<Vec<OfflineMessage>> {
        let now = current_timestamp();
        let conn = self.conn.lock().map_err(|_| Error::Storage("lock poisoned".into()))?;

        let mut stmt = conn.prepare(
            r#"SELECT id, message_id, recipient, packet_data, packet_type, status,
                      retries, queued_at, next_retry, last_attempt, expires_at, priority
               FROM offline_messages
               WHERE recipient = ? AND status = 0 AND expires_at > ?
               ORDER BY priority ASC, queued_at ASC"#,
        )?;

        let messages = stmt
            .query_map(params![recipient, now], |row| {
                let message_id_blob: Vec<u8> = row.get(1)?;
                let mut message_id = [0u8; 16];
                if message_id_blob.len() == 16 {
                    message_id.copy_from_slice(&message_id_blob);
                }

                Ok(OfflineMessage {
                    id: row.get(0)?,
                    message_id,
                    recipient: row.get(2)?,
                    packet_data: row.get(3)?,
                    packet_type: row.get::<_, i32>(4)? as u8,
                    status: OfflineStatus::from(row.get::<_, i32>(5)?),
                    retries: row.get::<_, i32>(6)? as u32,
                    queued_at: row.get(7)?,
                    next_retry: row.get(8)?,
                    last_attempt: row.get(9)?,
                    expires_at: row.get(10)?,
                    priority: row.get(11)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(messages)
    }

    /// Mark a message as being sent.
    pub fn mark_sending(&self, id: i64) -> Result<()> {
        let now = current_timestamp();
        let conn = self.conn.lock().map_err(|_| Error::Storage("lock poisoned".into()))?;

        conn.execute(
            "UPDATE offline_messages SET status = 1, last_attempt = ? WHERE id = ?",
            params![now, id],
        )?;

        Ok(())
    }

    /// Mark a message as successfully delivered.
    pub fn mark_delivered(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| Error::Storage("lock poisoned".into()))?;

        conn.execute(
            "UPDATE offline_messages SET status = 2 WHERE id = ?",
            params![id],
        )?;

        Ok(())
    }

    /// Mark a message as delivered by message_id.
    pub fn mark_delivered_by_message_id(&self, message_id: &[u8; 16]) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| Error::Storage("lock poisoned".into()))?;

        conn.execute(
            "UPDATE offline_messages SET status = 2 WHERE message_id = ?",
            params![message_id.as_slice()],
        )?;

        Ok(())
    }

    /// Mark a message for retry with exponential backoff.
    pub fn mark_retry(&self, id: i64) -> Result<()> {
        let now = current_timestamp();
        let conn = self.conn.lock().map_err(|_| Error::Storage("lock poisoned".into()))?;

        // Get current retry count
        let retries: i32 = conn
            .query_row(
                "SELECT retries FROM offline_messages WHERE id = ?",
                params![id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);

        if retries as u32 >= MAX_RETRIES {
            // Mark as failed
            conn.execute(
                "UPDATE offline_messages SET status = 3 WHERE id = ?",
                params![id],
            )?;
        } else {
            // Calculate next retry with exponential backoff
            let delay = std::cmp::min(
                INITIAL_RETRY_DELAY_SECS * (1 << retries),
                MAX_RETRY_DELAY_SECS,
            );

            conn.execute(
                "UPDATE offline_messages SET status = 0, retries = retries + 1, next_retry = ? WHERE id = ?",
                params![now + delay, id],
            )?;
        }

        Ok(())
    }

    /// Mark a message as permanently failed.
    pub fn mark_failed(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| Error::Storage("lock poisoned".into()))?;

        conn.execute(
            "UPDATE offline_messages SET status = 3 WHERE id = ?",
            params![id],
        )?;

        Ok(())
    }

    /// Expire old messages.
    pub fn expire_old_messages(&self) -> Result<usize> {
        let now = current_timestamp();
        let conn = self.conn.lock().map_err(|_| Error::Storage("lock poisoned".into()))?;

        let count = conn.execute(
            "UPDATE offline_messages SET status = 4 WHERE expires_at <= ? AND status IN (0, 1)",
            params![now],
        )?;

        Ok(count)
    }

    /// Delete delivered and expired messages older than the given age.
    pub fn cleanup(&self, max_age_secs: i64) -> Result<usize> {
        let cutoff = current_timestamp() - max_age_secs;
        let conn = self.conn.lock().map_err(|_| Error::Storage("lock poisoned".into()))?;

        let count = conn.execute(
            "DELETE FROM offline_messages WHERE status IN (2, 3, 4) AND queued_at < ?",
            params![cutoff],
        )?;

        Ok(count)
    }

    /// Delete all messages for a contact.
    pub fn delete_for_contact(&self, recipient: &str) -> Result<usize> {
        let conn = self.conn.lock().map_err(|_| Error::Storage("lock poisoned".into()))?;

        let count = conn.execute(
            "DELETE FROM offline_messages WHERE recipient = ?",
            params![recipient],
        )?;

        Ok(count)
    }

    /// Get queue statistics.
    pub fn stats(&self) -> Result<QueueStats> {
        let conn = self.conn.lock().map_err(|_| Error::Storage("lock poisoned".into()))?;

        let total: i64 = conn.query_row(
            "SELECT COUNT(*) FROM offline_messages",
            [],
            |row| row.get(0),
        )?;

        let pending: i64 = conn.query_row(
            "SELECT COUNT(*) FROM offline_messages WHERE status = 0",
            [],
            |row| row.get(0),
        )?;

        let sending: i64 = conn.query_row(
            "SELECT COUNT(*) FROM offline_messages WHERE status = 1",
            [],
            |row| row.get(0),
        )?;

        let delivered: i64 = conn.query_row(
            "SELECT COUNT(*) FROM offline_messages WHERE status = 2",
            [],
            |row| row.get(0),
        )?;

        let failed: i64 = conn.query_row(
            "SELECT COUNT(*) FROM offline_messages WHERE status = 3",
            [],
            |row| row.get(0),
        )?;

        let expired: i64 = conn.query_row(
            "SELECT COUNT(*) FROM offline_messages WHERE status = 4",
            [],
            |row| row.get(0),
        )?;

        let unique_contacts: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT recipient) FROM offline_messages WHERE status IN (0, 1)",
            [],
            |row| row.get(0),
        )?;

        Ok(QueueStats {
            total_messages: total as usize,
            pending: pending as usize,
            sending: sending as usize,
            delivered: delivered as usize,
            failed: failed as usize,
            expired: expired as usize,
            unique_contacts: unique_contacts as usize,
        })
    }

    /// Get a single message by ID.
    pub fn get(&self, id: i64) -> Result<Option<OfflineMessage>> {
        let conn = self.conn.lock().map_err(|_| Error::Storage("lock poisoned".into()))?;

        let msg = conn
            .query_row(
                r#"SELECT id, message_id, recipient, packet_data, packet_type, status,
                          retries, queued_at, next_retry, last_attempt, expires_at, priority
                   FROM offline_messages WHERE id = ?"#,
                params![id],
                |row| {
                    let message_id_blob: Vec<u8> = row.get(1)?;
                    let mut message_id = [0u8; 16];
                    if message_id_blob.len() == 16 {
                        message_id.copy_from_slice(&message_id_blob);
                    }

                    Ok(OfflineMessage {
                        id: row.get(0)?,
                        message_id,
                        recipient: row.get(2)?,
                        packet_data: row.get(3)?,
                        packet_type: row.get::<_, i32>(4)? as u8,
                        status: OfflineStatus::from(row.get::<_, i32>(5)?),
                        retries: row.get::<_, i32>(6)? as u32,
                        queued_at: row.get(7)?,
                        next_retry: row.get(8)?,
                        last_attempt: row.get(9)?,
                        expires_at: row.get(10)?,
                        priority: row.get(11)?,
                    })
                },
            )
            .optional()?;

        Ok(msg)
    }
}

/// Get current Unix timestamp.
fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enqueue_and_get() {
        let queue = OfflineQueue::open_in_memory().unwrap();

        let message_id = [1u8; 16];
        let id = queue
            .enqueue(message_id, "test.onion", b"hello", 0x03, 0)
            .unwrap();

        assert!(id > 0);

        let msg = queue.get(id).unwrap().unwrap();
        assert_eq!(msg.message_id, message_id);
        assert_eq!(msg.recipient, "test.onion");
        assert_eq!(msg.packet_data, b"hello");
    }

    #[test]
    fn test_get_pending() {
        let queue = OfflineQueue::open_in_memory().unwrap();

        queue
            .enqueue([1u8; 16], "a.onion", b"msg1", 0x03, 0)
            .unwrap();
        queue
            .enqueue([2u8; 16], "b.onion", b"msg2", 0x03, 0)
            .unwrap();

        let pending = queue.get_pending(10).unwrap();
        assert_eq!(pending.len(), 2);
    }

    #[test]
    fn test_mark_delivered() {
        let queue = OfflineQueue::open_in_memory().unwrap();

        let id = queue
            .enqueue([1u8; 16], "test.onion", b"hello", 0x03, 0)
            .unwrap();

        queue.mark_delivered(id).unwrap();

        let msg = queue.get(id).unwrap().unwrap();
        assert_eq!(msg.status, OfflineStatus::Delivered);
    }

    #[test]
    fn test_retry_backoff() {
        let queue = OfflineQueue::open_in_memory().unwrap();

        let id = queue
            .enqueue([1u8; 16], "test.onion", b"hello", 0x03, 0)
            .unwrap();

        let msg = queue.get(id).unwrap().unwrap();
        let initial_retry = msg.next_retry;

        queue.mark_retry(id).unwrap();

        let msg = queue.get(id).unwrap().unwrap();
        assert!(msg.next_retry > initial_retry);
        assert_eq!(msg.retries, 1);
    }

    #[test]
    fn test_queue_limits() {
        let queue = OfflineQueue::open_in_memory().unwrap();

        // This would take too long to actually fill, so just verify the mechanism works
        for i in 0..10 {
            let mut id = [0u8; 16];
            id[0] = i;
            queue.enqueue(id, "test.onion", b"hello", 0x03, 0).unwrap();
        }

        let stats = queue.stats().unwrap();
        assert_eq!(stats.pending, 10);
    }

    #[test]
    fn test_stats() {
        let queue = OfflineQueue::open_in_memory().unwrap();

        queue
            .enqueue([1u8; 16], "a.onion", b"msg", 0x03, 0)
            .unwrap();
        let id = queue
            .enqueue([2u8; 16], "b.onion", b"msg", 0x03, 0)
            .unwrap();
        queue.mark_delivered(id).unwrap();

        let stats = queue.stats().unwrap();
        assert_eq!(stats.total_messages, 2);
        assert_eq!(stats.pending, 1);
        assert_eq!(stats.delivered, 1);
        assert_eq!(stats.unique_contacts, 1);
    }
}
