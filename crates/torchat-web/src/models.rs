//! Data models for the web API

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use torchat_core::messaging::{FileTransferManager, MessagingDaemon};
use torchat_core::storage::Database;

/// Application shared state (multi-user P2P server)
pub struct AppState {
    /// Database for storing all users and their data
    pub database: Arc<TokioMutex<Database>>,
    /// Data directory
    pub data_dir: String,
    /// Daemons managing P2P connections for each user
    pub daemons: Arc<TokioMutex<HashMap<i64, Arc<MessagingDaemon>>>>,
    /// File transfer manager for handling file exchanges
    #[allow(dead_code)]
    pub file_manager: Arc<FileTransferManager>,
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
