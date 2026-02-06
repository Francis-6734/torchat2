//! Data models for the web API

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use torchat_core::messaging::{FileTransferManager, MessagingDaemon};
use torchat_core::storage::Database;

/// Received file info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedFile {
    pub transfer_id: String,
    pub filename: String,
    pub size: u64,
    pub from: String,
    pub output_path: String,
    pub timestamp: i64,
}

/// Outgoing transfer status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutgoingTransferStatus {
    pub transfer_id: String,
    pub filename: String,
    pub to: String,
    pub size: u64,
    pub status: String,  // "pending", "connecting", "transferring", "completed", "failed"
    pub error: Option<String>,
    pub timestamp: i64,
}

/// Application shared state (multi-user P2P server)
pub struct AppState {
    /// Database for storing all users and their data
    pub database: Arc<TokioMutex<Database>>,
    /// Data directory
    #[allow(dead_code)]
    pub data_dir: String,
    /// Daemons managing P2P connections for each user
    pub daemons: Arc<TokioMutex<HashMap<i64, Arc<MessagingDaemon>>>>,
    /// File transfer manager for handling file exchanges
    #[allow(dead_code)]
    pub file_manager: Arc<FileTransferManager>,
    /// Received files per user (user_id -> list of received files)
    pub received_files: Arc<TokioMutex<HashMap<i64, Vec<ReceivedFile>>>>,
    /// Outgoing transfer statuses (transfer_id -> status)
    pub outgoing_transfers: Arc<TokioMutex<HashMap<String, OutgoingTransferStatus>>>,
}

/// User identity with session info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub onion_address: String,
    pub fingerprint: String,
    pub display_name: Option<String>,
    pub session_token: Option<String>,
}

/// User registration request
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub display_name: Option<String>,
}

/// Contact information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub id: String,
    pub address: String,
    pub name: Option<String>,
    pub last_message: Option<String>,
}

/// Chat message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub content: String,
    pub timestamp: i64,
    pub is_outgoing: bool,
    pub status: String,
}

/// API request to add contact
#[derive(Debug, Deserialize)]
pub struct AddContactRequest {
    pub address: String,
    pub name: Option<String>,
}

/// API request to send message
#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    pub to: String,
    pub content: String,
}

/// File transfer info
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct FileTransfer {
    pub transfer_id: String,
    pub filename: String,
    pub size: u64,
    pub progress: u64,
    pub state: String,
}

/// Voice call info
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct VoiceCallInfo {
    pub call_id: String,
    pub peer_address: String,
    pub state: String,
    pub duration: Option<u64>,
}

/// Group chat information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub group_id: String,
    pub name: String,
    pub member_count: usize,
    pub state: String,
    pub is_founder: bool,
    /// Role: "founder", "admin", or "member"
    pub role: String,
}

/// Group member information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMemberInfo {
    pub member_id: String,
    pub onion_address: Option<String>,
    pub is_admin: bool,
    pub joined_at: i64,
    /// Role: "founder", "admin", or "member"
    pub role: String,
}

/// Group message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMessageInfo {
    pub message_id: String,
    pub sender_id: String,
    pub content: String,
    pub timestamp: i64,
    pub outgoing: bool,
}

/// Create group request
#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub blind_membership: Option<bool>,
    pub max_size: Option<u32>,
}

/// Send invite request
#[derive(Debug, Deserialize)]
pub struct SendInviteRequest {
    pub invitee_onion: String,
}

/// Join group request
#[derive(Debug, Deserialize)]
pub struct JoinGroupRequest {
    pub invite_token: String, // Base64-encoded invite payload
}

/// Send group message request
#[derive(Debug, Deserialize)]
pub struct SendGroupMessageRequest {
    pub content: String,
}

/// Promote member to admin request
#[derive(Debug, Deserialize)]
pub struct PromoteMemberRequest {
    pub member_id: String, // Hex-encoded 16-byte member ID
}

/// Group file information for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupFileInfo {
    pub file_id: String,
    pub filename: String,
    pub size: u64,
    pub sender_id: String,
    pub sender_onion: String,
    pub status: String,
    pub shared_at: i64,
    pub is_ours: bool,
}

/// Pending group invite information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingInviteInfo {
    pub id: i64,
    pub group_id: String,
    pub group_name: Option<String>,
    pub inviter_pubkey: String,
    pub bootstrap_peer: String,
    pub expires_at: i64,
    pub received_at: i64,
}


/// API response
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn ok_none() -> Self {
        Self {
            success: true,
            data: None,
            error: None,
        }
    }
}
