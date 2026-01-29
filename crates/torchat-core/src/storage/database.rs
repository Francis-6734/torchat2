//! Encrypted database operations.

use super::schema::{CREATE_SCHEMA, SCHEMA_VERSION};
use crate::error::{Error, Result};
use crate::identity::TorIdentity;
use crate::messaging::{Message, MessageContent, MessageId, MessageStatus};
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
