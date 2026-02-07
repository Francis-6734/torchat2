//! Encrypted local storage for TorChat 2.0.
//!
//! All local data is stored in encrypted SQLite databases using SQLCipher.
//! No plaintext logs or caches are permitted.
//!
//! ## Storage Rules (Spec Section 10)
//!
//! - Encrypted messages
//! - Encrypted ratchet state
//! - Secure key zeroization
//! - Optional application lock
//!
//! ## Security
//!
//! - Database encryption key derived from user password/PIN
//! - Key material is zeroized after use
//! - WAL mode disabled to prevent plaintext leakage

mod database;
mod offline_queue;
mod schema;

pub use database::{derive_db_key, BanRecord, Database, DatabaseConfig, GroupFileRecord, PendingGroupInvite, SimpleMessage, UserInfo};
pub use offline_queue::{OfflineMessage, OfflineQueue, OfflineStatus, QueueStats};

/// Default database filename.
pub const DEFAULT_DB_NAME: &str = "torchat.db";

/// Key derivation iterations for database encryption key.
pub const KEY_DERIVATION_ITERATIONS: u32 = 100_000;
