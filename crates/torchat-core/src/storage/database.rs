//! Encrypted database operations.

use super::schema::{CREATE_SCHEMA, SCHEMA_VERSION};
use crate::error::{Error, Result};
use crate::identity::TorIdentity;
use crate::messaging::{Message, MessageContent, MessageId, MessageStatus};
use crate::messaging::{GroupSession, GroupState, GroupMessage};
use crate::protocol::{GroupMember, GroupPolicy, GroupInvitePayload};
use rusqlite::{params, Connection, OpenFlags};
use serde::Serialize;
use std::path::Path;
use zeroize::Zeroizing;

/// Database configuration.
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Path to the database file.
    pub path: String,
    /// Whether to use in-memory database (for testing).
    pub in_memory: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: super::DEFAULT_DB_NAME.to_string(),
            in_memory: false,
        }
    }
}

/// Encrypted database handle.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open or create an encrypted database.
    ///
    /// The encryption key should be derived from user credentials using PBKDF2 or similar.
    pub fn open(config: &DatabaseConfig, encryption_key: &[u8]) -> Result<Self> {
        let conn = if config.in_memory {
            Connection::open_in_memory()
        } else {
            // Create parent directories if needed
            if let Some(parent) = Path::new(&config.path).parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| Error::Storage(format!("failed to create directory: {}", e)))?;
            }

            Connection::open_with_flags(
                &config.path,
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_CREATE
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
        }
        .map_err(|e| Error::Storage(format!("failed to open database: {}", e)))?;

        // Set encryption key (SQLCipher)
        let key_hex = hex::encode(encryption_key);
        conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", key_hex))
            .map_err(|e| Error::Storage(format!("failed to set encryption key: {}", e)))?;

        // Security settings
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = DELETE;
            PRAGMA secure_delete = ON;
            PRAGMA auto_vacuum = FULL;
            PRAGMA temp_store = MEMORY;
            "#,
        )
        .map_err(|e| Error::Storage(format!("failed to set security pragmas: {}", e)))?;

        let db = Self { conn };
        db.init_schema()?;

        Ok(db)
    }

    /// Initialize database schema.
    fn init_schema(&self) -> Result<()> {
        self.conn
            .execute_batch(&CREATE_SCHEMA.replace("?", &SCHEMA_VERSION.to_string()))
            .map_err(|e| Error::Storage(format!("failed to create schema: {}", e)))?;
        Ok(())
    }

    /// Store identity (only one allowed).
    pub fn store_identity(&self, identity: &TorIdentity) -> Result<()> {
        let secret = identity.secret_key_bytes();
        let now = chrono::Utc::now().timestamp();

        self.conn
            .execute(
                "INSERT OR REPLACE INTO identity (id, secret_key, created_at) VALUES (1, ?, ?)",
                params![secret.as_slice(), now],
            )
            .map_err(|e| Error::Storage(format!("failed to store identity: {}", e)))?;

        Ok(())
    }

    /// Load identity.
    pub fn load_identity(&self) -> Result<Option<TorIdentity>> {
        let mut stmt = self
            .conn
            .prepare("SELECT secret_key FROM identity WHERE id = 1")
            .map_err(|e| Error::Storage(e.to_string()))?;

        let result = stmt.query_row([], |row| {
            let secret: Vec<u8> = row.get(0)?;
            Ok(secret)
        });

        match result {
            Ok(secret) => {
                let identity = TorIdentity::from_secret_bytes(&secret)?;
                Ok(Some(identity))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(Error::Storage(e.to_string())),
        }
    }

    /// Add a contact.
    pub fn add_contact(&self, onion_address: &str, display_name: Option<&str>) -> Result<i64> {
        let now = chrono::Utc::now().timestamp();

        self.conn
            .execute(
                r#"
                INSERT INTO contacts (onion_address, display_name, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                "#,
                params![onion_address, display_name, now, now],
            )
            .map_err(|e| Error::Storage(format!("failed to add contact: {}", e)))?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Get contact ID by onion address.
    pub fn get_contact_id(&self, onion_address: &str) -> Result<Option<i64>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM contacts WHERE onion_address = ?")
            .map_err(|e| Error::Storage(e.to_string()))?;

        let result = stmt.query_row(params![onion_address], |row| row.get(0));

        match result {
            Ok(id) => Ok(Some(id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(Error::Storage(e.to_string())),
        }
    }

    /// Store a message.
    pub fn store_message(&self, session_db_id: i64, message: &Message) -> Result<()> {
        let content_bytes = message
            .content
            .to_bytes()
            .map_err(|e| Error::Storage(e.to_string()))?;

        let status_str = match message.status {
            MessageStatus::Sending => "sending",
            MessageStatus::Sent => "sent",
            MessageStatus::Delivered => "delivered",
            MessageStatus::Read => "read",
            MessageStatus::Failed => "failed",
        };

        let now = chrono::Utc::now().timestamp();

        self.conn
            .execute(
                r#"
                INSERT OR REPLACE INTO messages
                (session_id, message_id, content, timestamp, outgoing, status, disappear_after, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                "#,
                params![
                    session_db_id,
                    message.id.as_bytes().as_slice(),
                    content_bytes,
                    message.timestamp,
                    message.outgoing as i32,
                    status_str,
                    message.disappear_after,
                    now,
                ],
            )
            .map_err(|e| Error::Storage(format!("failed to store message: {}", e)))?;

        Ok(())
    }

    /// Load messages for a session.
    pub fn load_messages(&self, session_db_id: i64, limit: u32) -> Result<Vec<Message>> {
        let mut stmt = self
            .conn
            .prepare(
                r#"
                SELECT message_id, content, timestamp, outgoing, status, disappear_after
                FROM messages
                WHERE session_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                "#,
            )
            .map_err(|e| Error::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(params![session_db_id, limit], |row| {
                let message_id: Vec<u8> = row.get(0)?;
                let content: Vec<u8> = row.get(1)?;
                let timestamp: i64 = row.get(2)?;
                let outgoing: i32 = row.get(3)?;
                let status_str: String = row.get(4)?;
                let disappear_after: Option<u32> = row.get(5)?;

                Ok((
                    message_id,
                    content,
                    timestamp,
                    outgoing,
                    status_str,
                    disappear_after,
                ))
            })
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut messages = Vec::new();
        for row in rows {
            let (message_id, content, timestamp, outgoing, status_str, disappear_after) =
                row.map_err(|e| Error::Storage(e.to_string()))?;

            let id_bytes: [u8; 16] = message_id
                .try_into()
                .map_err(|_| Error::Storage("invalid message ID".into()))?;

            let content =
                MessageContent::from_bytes(&content).map_err(|e| Error::Storage(e.to_string()))?;

            let status = match status_str.as_str() {
                "sending" => MessageStatus::Sending,
                "sent" => MessageStatus::Sent,
                "delivered" => MessageStatus::Delivered,
                "read" => MessageStatus::Read,
                "failed" => MessageStatus::Failed,
                _ => MessageStatus::Sent,
            };

            messages.push(Message {
                id: MessageId::from_bytes(id_bytes),
                content,
                timestamp,
                outgoing: outgoing != 0,
                status,
                disappear_after,
            });
        }

        // Reverse to get chronological order
        messages.reverse();
        Ok(messages)
    }

    /// Delete a message.
    pub fn delete_message(&self, message_id: &MessageId) -> Result<bool> {
        let rows = self
            .conn
            .execute(
                "DELETE FROM messages WHERE message_id = ?",
                params![message_id.as_bytes().as_slice()],
            )
            .map_err(|e| Error::Storage(e.to_string()))?;

        Ok(rows > 0)
    }

    /// Update message status.
    pub fn update_message_status(&self, message_id: &MessageId, status: MessageStatus) -> Result<()> {
        let status_str = match status {
            MessageStatus::Sending => "sending",
            MessageStatus::Sent => "sent",
            MessageStatus::Delivered => "delivered",
            MessageStatus::Read => "read",
            MessageStatus::Failed => "failed",
        };

        self.conn
            .execute(
                "UPDATE messages SET status = ? WHERE message_id = ?",
                params![status_str, message_id.as_bytes().as_slice()],
            )
            .map_err(|e| Error::Storage(e.to_string()))?;

        Ok(())
    }

    /// Store a setting.
    pub fn set_setting(&self, key: &str, value: &[u8]) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                params![key, value],
            )
            .map_err(|e| Error::Storage(e.to_string()))?;

        Ok(())
    }

    /// Get a setting.
    pub fn get_setting(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM settings WHERE key = ?")
            .map_err(|e| Error::Storage(e.to_string()))?;

        let result = stmt.query_row(params![key], |row| row.get(0));

        match result {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(Error::Storage(e.to_string())),
        }
    }

    // ========================================================================
    // Group Chat Methods
    // ========================================================================

    /// Store a group session.
    pub fn store_group(&self, session: &GroupSession) -> Result<i64> {
        let now = chrono::Utc::now().timestamp();

        // Serialize policy
        let policy_blob = bincode::serialize(&session.policy)
            .map_err(|e| Error::Storage(format!("failed to serialize policy: {}", e)))?;

        let state_str = match session.state {
            GroupState::Active => "active",
            GroupState::Archived => "archived",
        };

        self.conn
            .execute(
                r#"
                INSERT OR REPLACE INTO groups
                (group_id, group_name, founder_pubkey, our_member_id, current_epoch_number,
                 current_epoch_key, epoch_key_updated_at, policy_blob, state, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
                params![
                    session.id.as_slice(),
                    &session.name,
                    session.founder_pubkey.as_slice(),
                    session.our_member_id.as_slice(),
                    session.current_epoch_number as i64,
                    session.current_epoch_key().as_slice(),
                    now,
                    policy_blob,
                    state_str,
                    now,
                    now,
                ],
            )
            .map_err(|e| Error::Storage(format!("failed to store group: {}", e)))?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Load a group session by group ID.
    /// Returns group metadata including epoch key for session restoration.
    pub fn load_group_metadata(&self, group_id: &[u8; 32]) -> Result<Option<(String, [u8; 32], [u8; 16], u64, [u8; 32], GroupPolicy, GroupState)>> {
        let mut stmt = self
            .conn
            .prepare(
                r#"
                SELECT group_name, founder_pubkey, our_member_id, current_epoch_number, current_epoch_key, policy_blob, state
                FROM groups WHERE group_id = ?
                "#
            )
            .map_err(|e| Error::Storage(e.to_string()))?;

        let result = stmt.query_row(params![group_id.as_slice()], |row| {
            let name: String = row.get(0)?;
            let founder_bytes: Vec<u8> = row.get(1)?;
            let member_bytes: Vec<u8> = row.get(2)?;
            let epoch: i64 = row.get(3)?;
            let epoch_key_bytes: Vec<u8> = row.get(4)?;
            let policy_blob: Vec<u8> = row.get(5)?;
            let state_str: String = row.get(6)?;

            let mut founder_pubkey = [0u8; 32];
            founder_pubkey.copy_from_slice(&founder_bytes);

            let mut our_member_id = [0u8; 16];
            our_member_id.copy_from_slice(&member_bytes);

            let mut epoch_key = [0u8; 32];
            if epoch_key_bytes.len() == 32 {
                epoch_key.copy_from_slice(&epoch_key_bytes);
            }

            Ok((name, founder_pubkey, our_member_id, epoch as u64, epoch_key, policy_blob, state_str))
        });

        match result {
            Ok((name, founder_pubkey, our_member_id, epoch, epoch_key, policy_blob, state_str)) => {
                let policy: GroupPolicy = bincode::deserialize(&policy_blob)
                    .map_err(|e| Error::Storage(format!("failed to deserialize policy: {}", e)))?;

                let state = match state_str.as_str() {
                    "active" => GroupState::Active,
                    "archived" => GroupState::Archived,
                    _ => GroupState::Archived,
                };

                Ok(Some((name, founder_pubkey, our_member_id, epoch, epoch_key, policy, state)))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(Error::Storage(e.to_string())),
        }
    }

    /// List all groups.
    pub fn list_groups(&self) -> Result<Vec<([u8; 32], String, GroupState)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT group_id, group_name, state FROM groups ORDER BY group_name")
            .map_err(|e| Error::Storage(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                let id_bytes: Vec<u8> = row.get(0)?;
                let name: String = row.get(1)?;
                let state_str: String = row.get(2)?;
                Ok((id_bytes, name, state_str))
            })
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut groups = Vec::new();
        for row in rows {
            let (id_bytes, name, state_str) = row.map_err(|e| Error::Storage(e.to_string()))?;
            let mut group_id = [0u8; 32];
            group_id.copy_from_slice(&id_bytes);

            let state = match state_str.as_str() {
                "active" => GroupState::Active,
                "archived" => GroupState::Archived,
                _ => GroupState::Archived,
            };

            groups.push((group_id, name, state));
        }

        Ok(groups)
    }

    /// Store a group member.
    pub fn store_group_member(&self, group_id: &[u8; 32], member: &GroupMember) -> Result<()> {
        let now = chrono::Utc::now().timestamp();

        self.conn
            .execute(
                r#"
                INSERT OR REPLACE INTO group_members
                (group_id, member_id, onion_address, pubkey, is_admin, is_neighbor, joined_at, last_seen, updated_at)
                VALUES (
                    (SELECT id FROM groups WHERE group_id = ?),
                    ?, ?, ?, ?, 0, ?, ?, ?
                )
                "#,
                params![
                    group_id.as_slice(),
                    member.member_id.as_slice(),
                    member.onion_address.as_ref(),
                    member.pubkey.as_slice(),
                    member.is_admin as i32,
                    member.joined_at,
                    now,
                    now,
                ],
            )
            .map_err(|e| Error::Storage(format!("failed to store group member: {}", e)))?;

        Ok(())
    }

    /// Load all members for a group.
    pub fn load_group_members(&self, group_id: &[u8; 32]) -> Result<Vec<GroupMember>> {
        let mut stmt = self
            .conn
            .prepare(
                r#"
                SELECT member_id, onion_address, pubkey, is_admin, joined_at
                FROM group_members
                WHERE group_id = (SELECT id FROM groups WHERE group_id = ?)
                ORDER BY joined_at
                "#
            )
            .map_err(|e| Error::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(params![group_id.as_slice()], |row| {
                let member_id_bytes: Vec<u8> = row.get(0)?;
                let onion_address: Option<String> = row.get(1)?;
                let pubkey_bytes: Vec<u8> = row.get(2)?;
                let is_admin: i32 = row.get(3)?;
                let joined_at: i64 = row.get(4)?;
                Ok((member_id_bytes, onion_address, pubkey_bytes, is_admin, joined_at))
            })
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut members = Vec::new();
        for row in rows {
            let (member_id_bytes, onion_address, pubkey_bytes, is_admin, joined_at) =
                row.map_err(|e| Error::Storage(e.to_string()))?;

            let mut member_id = [0u8; 16];
            member_id.copy_from_slice(&member_id_bytes);

            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(&pubkey_bytes);

            members.push(GroupMember {
                member_id,
                onion_address,
                pubkey,
                is_admin: is_admin != 0,
                joined_at,
            });
        }

        Ok(members)
    }

    /// Store a group message.
    pub fn store_group_message(&self, group_id: &[u8; 32], message: &GroupMessage) -> Result<()> {
        let now = chrono::Utc::now().timestamp();

        self.conn
            .execute(
                r#"
                INSERT OR REPLACE INTO group_messages
                (group_db_id, msg_id, sender_anon_id, epoch_number, content, timestamp, received_at, hop_count, is_delivered)
                VALUES (
                    (SELECT id FROM groups WHERE group_id = ?),
                    ?, ?, 0, ?, ?, ?, 0, 1
                )
                "#,
                params![
                    group_id.as_slice(),
                    message.id.as_slice(),
                    message.sender_id.as_slice(),
                    &message.content,
                    message.timestamp,
                    now,
                ],
            )
            .map_err(|e| Error::Storage(format!("failed to store group message: {}", e)))?;

        Ok(())
    }

    /// Load recent messages for a group.
    pub fn load_group_messages(&self, group_id: &[u8; 32], limit: u32) -> Result<Vec<GroupMessage>> {
        let mut stmt = self
            .conn
            .prepare(
                r#"
                SELECT msg_id, sender_anon_id, content, timestamp
                FROM group_messages
                WHERE group_db_id = (SELECT id FROM groups WHERE group_id = ?)
                ORDER BY timestamp DESC
                LIMIT ?
                "#
            )
            .map_err(|e| Error::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(params![group_id.as_slice(), limit], |row| {
                let msg_id_bytes: Vec<u8> = row.get(0)?;
                let sender_id_bytes: Vec<u8> = row.get(1)?;
                let content_blob: Vec<u8> = row.get(2)?;
                let timestamp: i64 = row.get(3)?;
                Ok((msg_id_bytes, sender_id_bytes, content_blob, timestamp))
            })
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut messages = Vec::new();
        for row in rows {
            let (msg_id_bytes, sender_id_bytes, content_blob, timestamp) =
                row.map_err(|e| Error::Storage(e.to_string()))?;

            let mut msg_id = [0u8; 32];
            msg_id.copy_from_slice(&msg_id_bytes);

            let mut sender_id = [0u8; 16];
            sender_id.copy_from_slice(&sender_id_bytes);

            // Content is stored as BLOB, convert to String
            let content = String::from_utf8_lossy(&content_blob).to_string();

            messages.push(GroupMessage {
                id: msg_id,
                sender_id,
                content,
                timestamp,
                outgoing: false, // Will be determined by comparing sender_id with our member_id
            });
        }

        // Reverse to get chronological order
        messages.reverse();
        Ok(messages)
    }

    /// Mark a group message as seen (for gossip deduplication).
    pub fn mark_message_seen(&self, group_id: &[u8; 32], msg_id: &[u8; 32]) -> Result<()> {
        let now = chrono::Utc::now().timestamp();

        self.conn
            .execute(
                r#"
                INSERT OR IGNORE INTO group_gossip_seen (group_id, msg_id, seen_at)
                VALUES ((SELECT id FROM groups WHERE group_id = ?), ?, ?)
                "#,
                params![group_id.as_slice(), msg_id.as_slice(), now],
            )
            .map_err(|e| Error::Storage(format!("failed to mark message seen: {}", e)))?;

        Ok(())
    }

    /// Check if a message has been seen (for gossip deduplication).
    pub fn is_message_seen(&self, group_id: &[u8; 32], msg_id: &[u8; 32]) -> Result<bool> {
        let mut stmt = self
            .conn
            .prepare(
                r#"
                SELECT 1 FROM group_gossip_seen
                WHERE group_id = (SELECT id FROM groups WHERE group_id = ?)
                AND msg_id = ?
                "#
            )
            .map_err(|e| Error::Storage(e.to_string()))?;

        let result = stmt.query_row(params![group_id.as_slice(), msg_id.as_slice()], |_| Ok(()));

        match result {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(Error::Storage(e.to_string())),
        }
    }

    /// Store a group invite.
    pub fn store_invite(
        &self,
        group_id: &[u8; 32],
        invite_id: &[u8; 32],
        invitee_onion: Option<&str>,
        issued_by: &[u8; 16],
        expires_at: i64,
    ) -> Result<()> {
        let now = chrono::Utc::now().timestamp();

        self.conn
            .execute(
                r#"
                INSERT INTO group_invites
                (group_id, invite_id, invitee_onion, issued_by, expires_at, revoked, created_at)
                VALUES ((SELECT id FROM groups WHERE group_id = ?), ?, ?, ?, ?, 0, ?)
                "#,
                params![
                    group_id.as_slice(),
                    invite_id.as_slice(),
                    invitee_onion,
                    issued_by.as_slice(),
                    expires_at,
                    now,
                ],
            )
            .map_err(|e| Error::Storage(format!("failed to store invite: {}", e)))?;

        Ok(())
    }

    /// Revoke a group invite.
    pub fn revoke_invite(&self, invite_id: &[u8; 32]) -> Result<()> {
        self.conn
            .execute(
                "UPDATE group_invites SET revoked = 1 WHERE invite_id = ?",
                params![invite_id.as_slice()],
            )
            .map_err(|e| Error::Storage(format!("failed to revoke invite: {}", e)))?;

        Ok(())
    }

    /// Check if an invite is valid (exists, not revoked, not expired).
    pub fn is_invite_valid(&self, invite_id: &[u8; 32]) -> Result<bool> {
        let now = chrono::Utc::now().timestamp();

        let mut stmt = self
            .conn
            .prepare(
                r#"
                SELECT 1 FROM group_invites
                WHERE invite_id = ? AND revoked = 0 AND expires_at > ?
                "#
            )
            .map_err(|e| Error::Storage(e.to_string()))?;

        let result = stmt.query_row(params![invite_id.as_slice(), now], |_| Ok(()));

        match result {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(Error::Storage(e.to_string())),
        }
    }

    /// Store an epoch key (for key rotation history).
    pub fn store_epoch_key(
        &self,
        group_id: &[u8; 32],
        epoch_number: u64,
        _epoch_key: &[u8; 32], // Not stored for security
    ) -> Result<()> {
        let now = chrono::Utc::now().timestamp();

        self.conn
            .execute(
                r#"
                INSERT OR REPLACE INTO group_epoch_keys
                (group_id, epoch_number, epoch_key, created_at)
                VALUES ((SELECT id FROM groups WHERE group_id = ?), ?, ?, ?)
                "#,
                params![
                    group_id.as_slice(),
                    epoch_number as i64,
                    vec![0u8; 32], // Placeholder - not stored for security
                    now,
                ],
            )
            .map_err(|e| Error::Storage(format!("failed to store epoch key: {}", e)))?;

        Ok(())
    }

    /// Get the latest epoch number for a group.
    pub fn get_latest_epoch_number(&self, group_id: &[u8; 32]) -> Result<Option<u64>> {
        let mut stmt = self
            .conn
            .prepare(
                r#"
                SELECT epoch_number FROM group_epoch_keys
                WHERE group_id = (SELECT id FROM groups WHERE group_id = ?)
                ORDER BY epoch_number DESC
                LIMIT 1
                "#
            )
            .map_err(|e| Error::Storage(e.to_string()))?;

        let result = stmt.query_row(params![group_id.as_slice()], |row| {
            let epoch: i64 = row.get(0)?;
            Ok(epoch as u64)
        });

        match result {
            Ok(epoch) => Ok(Some(epoch)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(Error::Storage(e.to_string())),
        }
    }

    /// Close the database securely.
    pub fn close(self) -> Result<()> {
        // SQLite will close the connection when dropped
        drop(self.conn);
        Ok(())
    }

    // ========================================================================
    // Simple helper methods for web interface
    // ========================================================================

    /// List all contacts (returns id, address, name).
    pub fn list_contacts(&self) -> Result<Vec<(i64, String, Option<String>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, onion_address, display_name FROM contacts ORDER BY display_name, onion_address")
            .map_err(|e| Error::Storage(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                let id: i64 = row.get(0)?;
                let address: String = row.get(1)?;
                let name: Option<String> = row.get(2)?;
                Ok((id, address, name))
            })
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut contacts = Vec::new();
        for row in rows {
            contacts.push(row.map_err(|e| Error::Storage(e.to_string()))?);
        }

        Ok(contacts)
    }

    /// Store a simple text message (for web interface).
    pub fn store_simple_message(
        &self,
        contact_id: i64,
        content: &str,
        is_outgoing: bool,
        timestamp: i64,
    ) -> Result<i64> {
        // Ensure the simple_messages table exists
        self.conn
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS simple_messages (
                    id INTEGER PRIMARY KEY,
                    contact_id INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    is_outgoing INTEGER NOT NULL,
                    timestamp INTEGER NOT NULL,
                    FOREIGN KEY (contact_id) REFERENCES contacts(id)
                )
                "#,
                [],
            )
            .map_err(|e| Error::Storage(format!("failed to create table: {}", e)))?;

        self.conn
            .execute(
                r#"
                INSERT INTO simple_messages (contact_id, content, is_outgoing, timestamp)
                VALUES (?, ?, ?, ?)
                "#,
                params![contact_id, content, is_outgoing as i32, timestamp],
            )
            .map_err(|e| Error::Storage(format!("failed to store message: {}", e)))?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Load simple messages for a contact (for web interface).
    pub fn load_simple_messages(&self, contact_id: i64, limit: u32) -> Result<Vec<SimpleMessage>> {
        // First, ensure the simple_messages table exists
        self.conn
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS simple_messages (
                    id INTEGER PRIMARY KEY,
                    contact_id INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    is_outgoing INTEGER NOT NULL,
                    timestamp INTEGER NOT NULL,
                    FOREIGN KEY (contact_id) REFERENCES contacts(id)
                )
                "#,
                [],
            )
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut stmt = self
            .conn
            .prepare(
                r#"
                SELECT id, content, is_outgoing, timestamp
                FROM simple_messages
                WHERE contact_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                "#,
            )
            .map_err(|e| Error::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(params![contact_id, limit], |row| {
                let id: i64 = row.get(0)?;
                let content: String = row.get(1)?;
                let is_outgoing: i32 = row.get(2)?;
                let timestamp: i64 = row.get(3)?;
                Ok(SimpleMessage {
                    id,
                    content,
                    is_outgoing: is_outgoing != 0,
                    timestamp,
                })
            })
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut messages = Vec::new();
        for row in rows {
            messages.push(row.map_err(|e| Error::Storage(e.to_string()))?);
        }

        // Reverse to get chronological order
        messages.reverse();
        Ok(messages)
    }

    /// Create a new user with a unique session token.
    pub fn create_user(&self, session_token: &str, identity: &TorIdentity, display_name: Option<&str>) -> Result<i64> {
        let now = chrono::Utc::now().timestamp();
        let onion_addr = identity.onion_address().to_string();
        let secret_key = identity.secret_key_bytes();

        self.conn
            .execute(
                r#"
                INSERT INTO users (session_token, onion_address, secret_key, display_name, last_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                "#,
                params![session_token, onion_addr, secret_key, display_name, now, now],
            )
            .map_err(|e| Error::Storage(format!("failed to create user: {}", e)))?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Get user by session token.
    pub fn get_user_by_session(&self, session_token: &str) -> Result<Option<(i64, TorIdentity, Option<String>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, secret_key, onion_address, display_name FROM users WHERE session_token = ?")
            .map_err(|e| Error::Storage(e.to_string()))?;

        let result = stmt.query_row(params![session_token], |row| {
            let user_id: i64 = row.get(0)?;
            let secret_key: Vec<u8> = row.get(1)?;
            let onion_addr: String = row.get(2)?;
            let display_name: Option<String> = row.get(3)?;

            Ok((user_id, secret_key, onion_addr, display_name))
        });

        match result {
            Ok((user_id, secret_key, _onion_addr, display_name)) => {
                // Reconstruct identity from secret key
                let secret_bytes: [u8; 32] = secret_key
                    .try_into()
                    .map_err(|_| Error::Storage("invalid secret key length".into()))?;

                let identity = TorIdentity::from_secret_bytes(&secret_bytes)?;
                Ok(Some((user_id, identity, display_name)))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(Error::Storage(e.to_string())),
        }
    }

    /// Update user's last active timestamp.
    pub fn update_user_activity(&self, user_id: i64) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        self.conn
            .execute(
                "UPDATE users SET last_active = ? WHERE id = ?",
                params![now, user_id],
            )
            .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }

    /// Add a contact for a specific user.
    pub fn add_user_contact(&self, user_id: i64, onion_address: &str, display_name: Option<&str>) -> Result<i64> {
        let now = chrono::Utc::now().timestamp();

        self.conn
            .execute(
                r#"
                INSERT INTO contacts (user_id, onion_address, display_name, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                "#,
                params![user_id, onion_address, display_name, now, now],
            )
            .map_err(|e| Error::Storage(format!("failed to add contact: {}", e)))?;

        Ok(self.conn.last_insert_rowid())
    }

    /// List contacts for a specific user.
    pub fn list_user_contacts(&self, user_id: i64) -> Result<Vec<(i64, String, Option<String>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, onion_address, display_name FROM contacts WHERE user_id = ? ORDER BY created_at DESC")
            .map_err(|e| Error::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(params![user_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut contacts = Vec::new();
        for row in rows {
            contacts.push(row.map_err(|e| Error::Storage(e.to_string()))?);
        }

        Ok(contacts)
    }

    /// List all users (for admin/debugging).
    pub fn list_all_users(&self) -> Result<Vec<UserInfo>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, onion_address, display_name, last_active, created_at FROM users ORDER BY created_at DESC")
            .map_err(|e| Error::Storage(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(UserInfo {
                    id: row.get(0)?,
                    onion_address: row.get(1)?,
                    display_name: row.get(2)?,
                    last_active: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut users = Vec::new();
        for row in rows {
            users.push(row.map_err(|e| Error::Storage(e.to_string()))?);
        }

        Ok(users)
    }

    /// Store a simple message by peer address (creates contact if needed).
    pub fn store_simple_message_by_address(&self, user_id: i64, peer_address: &str, content: &str, is_outgoing: bool) -> Result<i64> {
        // Ensure simple_messages table exists
        self.conn
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS simple_messages (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    peer_address TEXT NOT NULL,
                    content TEXT NOT NULL,
                    is_outgoing INTEGER NOT NULL,
                    timestamp INTEGER NOT NULL
                )
                "#,
                [],
            )
            .map_err(|e| Error::Storage(e.to_string()))?;

        let timestamp = chrono::Utc::now().timestamp();

        self.conn
            .execute(
                r#"
                INSERT INTO simple_messages (user_id, peer_address, content, is_outgoing, timestamp)
                VALUES (?, ?, ?, ?, ?)
                "#,
                params![user_id, peer_address, content, is_outgoing as i32, timestamp],
            )
            .map_err(|e| Error::Storage(format!("failed to store message: {}", e)))?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Get simple messages by peer address for a specific user.
    pub fn get_simple_messages_by_address(&self, user_id: i64, peer_address: &str, limit: u32) -> Result<Vec<SimpleMessage>> {
        // Ensure table exists
        self.conn
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS simple_messages (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    peer_address TEXT NOT NULL,
                    content TEXT NOT NULL,
                    is_outgoing INTEGER NOT NULL,
                    timestamp INTEGER NOT NULL
                )
                "#,
                [],
            )
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut stmt = self
            .conn
            .prepare(
                r#"
                SELECT id, content, is_outgoing, timestamp
                FROM simple_messages
                WHERE user_id = ? AND peer_address = ?
                ORDER BY timestamp DESC
                LIMIT ?
                "#,
            )
            .map_err(|e| Error::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(params![user_id, peer_address, limit], |row| {
                Ok(SimpleMessage {
                    id: row.get(0)?,
                    content: row.get(1)?,
                    is_outgoing: row.get::<_, i32>(2)? != 0,
                    timestamp: row.get(3)?,
                })
            })
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut messages = Vec::new();
        for row in rows {
            messages.push(row.map_err(|e| Error::Storage(e.to_string()))?);
        }

        // Reverse to get chronological order
        messages.reverse();
        Ok(messages)
    }
}

/// User info for listing.
#[derive(Debug, Clone, Serialize)]
pub struct UserInfo {
    /// User's unique database ID.
    pub id: i64,
    /// User's onion address.
    pub onion_address: String,
    /// Optional display name.
    pub display_name: Option<String>,
    /// Unix timestamp of last activity.
    pub last_active: i64,
    /// Unix timestamp of account creation.
    pub created_at: i64,
}

/// Simple message for web interface.
#[derive(Debug, Clone)]
pub struct SimpleMessage {
    /// Message ID.
    pub id: i64,
    /// Message content.
    pub content: String,
    /// Whether this is an outgoing message.
    pub is_outgoing: bool,
    /// Timestamp (Unix epoch seconds).
    pub timestamp: i64,
}

/// Derive database encryption key from password using PBKDF2.
///
/// # Panics
/// This function will not panic under normal circumstances as PBKDF2
/// with valid parameters (non-empty password, valid iteration count)
/// is mathematically guaranteed to succeed.
pub fn derive_db_key(password: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    use hmac::Hmac;
    use sha2::Sha256;

    let mut key = Zeroizing::new([0u8; 32]);

    // PBKDF2 only fails if output length is too large (> 2^32 - 1 blocks)
    // or if the HMAC itself fails. Neither can happen with 32-byte output.
    if pbkdf2::pbkdf2::<Hmac<Sha256>>(
        password,
        salt,
        super::KEY_DERIVATION_ITERATIONS,
        key.as_mut(),
    ).is_err() {
        // This branch is unreachable with valid parameters, but we handle it
        // gracefully by zeroing the key (already zeroed) and returning.
        // The caller will get an invalid key and database open will fail safely.
    }

    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_identity;

    fn test_db() -> Database {
        let config = DatabaseConfig {
            path: String::new(),
            in_memory: true,
        };
        let key = [0u8; 32];
        Database::open(&config, &key).expect("should open")
    }

    #[test]
    fn test_database_creation() {
        let _db = test_db();
    }

    #[test]
    fn test_identity_storage() {
        let db = test_db();
        let identity = generate_identity().expect("should generate");

        db.store_identity(&identity).expect("should store");

        let loaded = db.load_identity().expect("should load").expect("should exist");

        assert_eq!(
            identity.onion_address().as_str(),
            loaded.onion_address().as_str()
        );
    }

    #[test]
    fn test_contact_storage() {
        let db = test_db();

        // Create a user first (required for multi-user schema)
        let identity = generate_identity().expect("should generate identity");
        let user_id = db
            .create_user("test_session", &identity, Some("TestUser"))
            .expect("should create user");

        let id = db
            .add_user_contact(user_id, "test1234567890123456789012345678901234567890123456789012.onion", Some("Alice"))
            .expect("should add");

        assert!(id > 0);

        let contacts = db.list_user_contacts(user_id).expect("should list");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].0, id);
        assert_eq!(contacts[0].1, "test1234567890123456789012345678901234567890123456789012.onion");
        assert_eq!(contacts[0].2, Some("Alice".to_string()));
    }

    #[test]
    fn test_message_storage() {
        let db = test_db();

        // Create user first (required for multi-user schema)
        let identity = generate_identity().expect("should generate identity");
        let user_id = db
            .create_user("test_session", &identity, Some("TestUser"))
            .expect("should create user");

        // Add contact for that user
        let contact_id = db
            .add_user_contact(user_id, "test1234567890123456789012345678901234567890123456789012.onion", None)
            .expect("add contact");

        // Create a minimal session entry
        let now = chrono::Utc::now().timestamp();
        db.conn
            .execute(
                "INSERT INTO sessions (contact_id, session_id, ratchet_state, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                params![contact_id, vec![0u8; 32], vec![0u8; 1], now, now],
            )
            .expect("insert session");
        let session_id = db.conn.last_insert_rowid();

        // Store message
        let msg = Message::new_text("Hello!");
        db.store_message(session_id, &msg).expect("store");

        // Load messages
        let messages = db.load_messages(session_id, 100).expect("load");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].content.as_text(), Some("Hello!"));
    }

    #[test]
    fn test_settings() {
        let db = test_db();

        db.set_setting("test_key", b"test_value").expect("set");

        let value = db.get_setting("test_key").expect("get").expect("exists");
        assert_eq!(value, b"test_value");
    }

    #[test]
    fn test_key_derivation() {
        let key = derive_db_key(b"password", b"salt");
        assert_eq!(key.len(), 32);

        // Same inputs should produce same key
        let key2 = derive_db_key(b"password", b"salt");
        assert_eq!(&*key, &*key2);

        // Different password should produce different key
        let key3 = derive_db_key(b"different", b"salt");
        assert_ne!(&*key, &*key3);
    }
}
