//! Messaging system for TorChat 2.0.
//!
//! Handles encrypted message creation, parsing, and management.
//!
//! ## Features (Spec Section 7)
//!
//! - Text messages
//! - Read receipts (with jitter for privacy)
//! - Message reactions
//! - Delete for both sides
//! - Optional disappearing messages
//!
//! All messages are end-to-end encrypted using the Double Ratchet.

mod daemon;
mod file_transfer;
mod message;
mod relay;
mod session;
pub mod stream_transfer;

pub use daemon::{DaemonCommand, DaemonEvent, MessagingDaemon};
pub use file_transfer::{
    FileMetadata, FileTransferManager, IncomingTransfer, OutgoingTransfer, TransferEvent,
    TransferState, MAX_CHUNK_SIZE,
};
pub use stream_transfer::{
    send_file_stream, receive_file_stream, is_file_transfer_magic,
    StreamFileMetadata, TransferResult, MAX_FILE_SIZE,
};
pub use message::{Message, MessageContent, MessageId, MessageStatus};
pub use relay::{
    ConnectionState, DeliveryStatus, QueuedMessage, RelayConfig, RelayEvent, RelayHandler,
};
pub use session::{Session, SessionId, SessionState};

use rand::RngCore;

/// Generate a random message ID.
pub fn generate_message_id() -> MessageId {
    let mut id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id);
    MessageId(id)
}

/// Add timing jitter to a timestamp for privacy.
///
/// This prevents exact timing correlation attacks on read receipts.
/// Jitter is uniformly distributed in [-max_jitter, +max_jitter] seconds.
pub fn add_timestamp_jitter(timestamp: i64, max_jitter_secs: i64) -> i64 {
    use rand::Rng;
    let jitter = rand::rngs::OsRng.gen_range(-max_jitter_secs..=max_jitter_secs);
    timestamp.saturating_add(jitter)
}

/// Default jitter for read receipts (30 seconds).
pub const DEFAULT_RECEIPT_JITTER: i64 = 30;
