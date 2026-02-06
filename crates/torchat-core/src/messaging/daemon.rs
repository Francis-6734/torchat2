//! TorChat messaging daemon.
//!
//! Manages the complete messaging lifecycle:
//! - Starts onion service to receive incoming connections
//! - Manages encrypted sessions with contacts
//! - Handles message sending and receiving
//! - Provides event notifications to the UI

use crate::crypto::{DoubleRatchet, EphemeralKeypair, X25519PublicKey};
use crate::error::{Error, Result};
use crate::identity::{OnionAddress, TorIdentity};
use crate::protocol::{
    AckPayload, AckType, CallSignalPayload, CallSignalType, FileChunkPayload,
    FileOfferPayload, MessagePayload, Packet, PacketHeader, PacketType
};
use crate::storage::Database;
use crate::tor::{OnionService, OnionServiceConfig, TorConnection, TorConnectionConfig};
use crate::messaging::file_transfer::{FileMetadata, FileTransferManager};

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, Mutex as TokioMutex, RwLock};
use tracing::{debug, error, info, warn};

/// Maximum packet size (64KB).
const MAX_PACKET_SIZE: usize = 65536;

/// Maximum retry attempts for message delivery.
const MAX_RETRY_ATTEMPTS: u32 = 5;

/// Base retry delay in seconds (exponential backoff).
const RETRY_BASE_DELAY_SECS: u64 = 2;

/// Connection timeout in seconds.
const _CONNECTION_TIMEOUT_SECS: u64 = 30;

/// Message pending delivery confirmation.
#[derive(Debug, Clone)]
struct PendingMessage {
    /// Message ID.
    message_id: [u8; 16],
    /// Recipient address.
    to: String,
    /// Message content.
    content: String,
    /// Number of send attempts.
    attempts: u32,
    /// Time of last attempt.
    last_attempt: Instant,
    /// Time message was queued.
    _queued_at: Instant,
}

/// Simple chat hello payload (includes sender address for initial handshake).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatHello {
    /// Sender's onion address.
    sender_address: String,
    /// Sender's ephemeral public key for key exchange.
    ephemeral_public: [u8; 32],
    /// Sender's identity public key.
    identity_public: [u8; 32],
    /// Timestamp.
    timestamp: i64,
}

impl ChatHello {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// Simple chat hello response.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatHelloResponse {
    /// Responder's ephemeral public key.
    ephemeral_public: [u8; 32],
    /// Responder's identity public key.
    identity_public: [u8; 32],
    /// Responder's onion address.
    responder_address: String,
}

impl ChatHelloResponse {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// Events emitted by the daemon.
#[derive(Debug, Clone)]
pub enum DaemonEvent {
    /// Daemon started successfully.
    Started {
        /// The onion address of the daemon.
        onion_address: String,
    },
    /// Daemon stopped.
    Stopped,
    /// Connected to a peer.
    PeerConnected {
        /// The peer's onion address.
        address: String,
    },
    /// Disconnected from a peer.
    PeerDisconnected {
        /// The peer's onion address.
        address: String,
    },
    /// Received a message from a peer.
    MessageReceived {
        /// Sender's onion address.
        from: String,
        /// Unique message identifier.
        message_id: [u8; 16],
        /// Message content.
        content: String,
        /// Unix timestamp of message.
        timestamp: i64,
    },
    /// Message was delivered to peer.
    MessageDelivered {
        /// The delivered message ID.
        message_id: [u8; 16],
    },
    /// Message delivery failed.
    MessageFailed {
        /// The failed message ID.
        message_id: [u8; 16],
        /// Error description.
        error: String,
    },
    /// Acknowledgment received.
    AckReceived {
        /// The acknowledged message ID.
        message_id: [u8; 16],
        /// Type of acknowledgment.
        ack_type: AckType,
    },
    /// Error occurred.
    Error {
        /// Error message.
        message: String,
    },
    /// File chunk received.
    FileChunkReceived {
        /// Transfer ID.
        transfer_id: [u8; 16],
        /// Chunk index.
        chunk_index: u32,
        /// Total chunks.
        total_chunks: u32,
        /// Sender's address.
        from: String,
        /// Decrypted chunk data.
        data: Vec<u8>,
    },
    /// File offer received (incoming transfer request).
    FileOfferReceived {
        /// Transfer ID.
        transfer_id: [u8; 16],
        /// Filename.
        filename: String,
        /// File size in bytes.
        size: u64,
        /// SHA-256 hash.
        hash: [u8; 32],
        /// Total chunks.
        total_chunks: u32,
        /// Sender's address.
        from: String,
    },
    /// File transfer started (incoming).
    FileTransferStarted {
        /// Transfer ID.
        transfer_id: [u8; 16],
        /// File metadata.
        metadata: FileMetadata,
        /// Sender's address.
        from: String,
    },
    /// File transfer completed.
    FileTransferCompleted {
        /// Transfer ID.
        transfer_id: [u8; 16],
        /// Output file path.
        output_path: String,
        /// Original filename.
        filename: String,
        /// Sender's address.
        from: String,
        /// File size in bytes.
        size: u64,
    },
    /// File transfer failed.
    FileTransferFailed {
        /// Transfer ID.
        transfer_id: [u8; 16],
        /// Error description.
        error: String,
    },
    /// Voice call signal received.
    CallSignalReceived {
        /// Call ID.
        call_id: [u8; 16],
        /// Signal type.
        signal_type: CallSignalType,
        /// Caller's address.
        from: String,
        /// Decrypted signal data.
        data: Vec<u8>,
    },
    /// Group created successfully.
    GroupCreated {
        /// Group ID.
        group_id: [u8; 32],
        /// Group name.
        name: String,
    },
    /// Group invite generated.
    GroupInviteGenerated {
        /// Group ID.
        group_id: [u8; 32],
        /// Invite token.
        invite: crate::protocol::GroupInvitePayload,
    },
    /// Group invite successfully sent to invitee.
    GroupInviteSent {
        /// Group ID.
        group_id: [u8; 32],
        /// Invitee onion address.
        invitee: String,
    },
    /// Group invite received.
    GroupInviteReceived {
        /// Invite token.
        invite: crate::protocol::GroupInvitePayload,
    },
    /// Successfully joined a group.
    GroupJoined {
        /// Group ID.
        group_id: [u8; 32],
        /// Group name.
        name: String,
    },
    /// Group message received.
    GroupMessageReceived {
        /// Group ID.
        group_id: [u8; 32],
        /// Sender's anonymous ID.
        sender_id: [u8; 16],
        /// Message content.
        content: String,
        /// Message timestamp.
        timestamp: i64,
    },
    /// Member joined the group.
    GroupMemberJoined {
        /// Group ID.
        group_id: [u8; 32],
        /// Member ID.
        member_id: [u8; 16],
    },
    /// Member left the group.
    GroupMemberLeft {
        /// Group ID.
        group_id: [u8; 32],
        /// Member ID.
        member_id: [u8; 16],
    },
    /// Group epoch key rotated.
    GroupKeyRotated {
        /// Group ID.
        group_id: [u8; 32],
        /// New epoch number.
        new_epoch: u64,
    },
    /// Group join accept ready to send (bootstrap peer).
    GroupJoinAcceptReady {
        /// Group ID.
        group_id: [u8; 32],
        /// Joiner's onion address.
        joiner_onion: String,
        /// Join accept payload.
        accept_payload: crate::protocol::GroupJoinAcceptPayload,
    },
    /// Group join accept received (joiner).
    GroupJoinAcceptReceived {
        /// Group ID.
        group_id: [u8; 32],
        /// Current epoch number.
        epoch_number: u64,
        /// Encrypted epoch key.
        encrypted_epoch_key: Vec<u8>,
        /// Initial member list.
        member_list: Vec<crate::protocol::GroupMember>,
    },
    /// A file was shared in a group (metadata received via gossip).
    GroupFileShared {
        /// Group ID.
        group_id: [u8; 32],
        /// File ID.
        file_id: String,
        /// Filename.
        filename: String,
        /// File size.
        size: u64,
        /// Sender's onion address.
        sender_onion: String,
    },
    /// A group file download completed.
    GroupFileDownloaded {
        /// Group ID.
        group_id: [u8; 32],
        /// File ID.
        file_id: String,
        /// Local output path.
        output_path: String,
    },
    /// A group file download failed.
    GroupFileDownloadFailed {
        /// Group ID.
        group_id: [u8; 32],
        /// File ID.
        file_id: String,
        /// Error description.
        error: String,
    },
}

/// Commands to send to the daemon.
#[derive(Debug)]
pub enum DaemonCommand {
    /// Send a text message to a peer.
    SendMessage {
        /// Recipient's onion address.
        to: String,
        /// Message content.
        content: String,
        /// Unique message identifier.
        message_id: [u8; 16],
    },
    /// Send acknowledgment for a message.
    SendAck {
        /// Recipient's onion address.
        to: String,
        /// Message ID to acknowledge.
        message_id: [u8; 16],
        /// Type of acknowledgment.
        ack_type: AckType,
    },
    /// Connect to a peer.
    Connect {
        /// Peer's onion address.
        address: String,
    },
    /// Disconnect from a peer.
    Disconnect {
        /// Peer's onion address.
        address: String,
    },
    /// Stop the daemon.
    Stop,
    /// Send file offer (metadata) to a peer.
    SendFileOffer {
        /// Recipient's onion address.
        to: String,
        /// Transfer ID.
        transfer_id: [u8; 16],
        /// Filename.
        filename: String,
        /// File size.
        size: u64,
        /// SHA-256 hash.
        hash: [u8; 32],
        /// Total chunks.
        total_chunks: u32,
    },
    /// Send a file to a peer (legacy, not used).
    SendFile {
        /// Recipient's onion address.
        to: String,
        /// File path to send.
        file_path: std::path::PathBuf,
        /// Transfer ID.
        transfer_id: [u8; 16],
    },
    /// Send file chunk.
    SendFileChunk {
        /// Recipient's onion address.
        to: String,
        /// Transfer ID.
        transfer_id: [u8; 16],
        /// Chunk index.
        chunk_index: u32,
        /// Total chunks.
        total_chunks: u32,
        /// Chunk data.
        data: Vec<u8>,
    },
    /// Send call signal.
    SendCallSignal {
        /// Recipient's onion address.
        to: String,
        /// Call ID.
        call_id: [u8; 16],
        /// Signal type.
        signal_type: CallSignalType,
        /// Signal data.
        data: Vec<u8>,
    },
    /// Create a new group.
    CreateGroup {
        /// Group name.
        name: String,
        /// Group policy.
        policy: crate::protocol::GroupPolicy,
    },
    /// Generate and send an invite token for a group.
    SendGroupInvite {
        /// Group ID.
        group_id: [u8; 32],
        /// Invitee's onion address.
        invitee_onion: String,
        /// Expiration timestamp (Unix seconds).
        expires_at: i64,
    },
    /// Join a group via invite token.
    JoinGroup {
        /// Invite token.
        invite: crate::protocol::GroupInvitePayload,
    },
    /// Send a message to a group.
    SendGroupMessage {
        /// Group ID.
        group_id: [u8; 32],
        /// Message content.
        content: String,
    },
    /// Leave a group.
    LeaveGroup {
        /// Group ID.
        group_id: [u8; 32],
    },
    /// Rotate group epoch key (admin only).
    RotateGroupKey {
        /// Group ID.
        group_id: [u8; 32],
    },
    /// Share a file in a group chat.
    SendGroupFile {
        /// Group ID.
        group_id: [u8; 32],
        /// Path to the file on disk.
        file_path: std::path::PathBuf,
        /// Original filename.
        filename: String,
    },
    /// Download a file shared in a group chat.
    DownloadGroupFile {
        /// Group ID.
        group_id: [u8; 32],
        /// File ID (hex transfer ID from the metadata announcement).
        file_id: String,
        /// Sender's onion address.
        sender_onion: String,
    },
    /// Promote a group member to admin (founder only).
    PromoteToAdmin {
        /// Group ID.
        group_id: [u8; 32],
        /// Member ID to promote.
        member_id: [u8; 16],
    },
}

/// Peer session state.
#[allow(dead_code)]
struct PeerSession {
    /// Peer's onion address.
    address: OnionAddress,
    /// Double ratchet for encryption.
    ratchet: Option<DoubleRatchet>,
    /// Our ephemeral key for this session.
    our_ephemeral: Option<EphemeralKeypair>,
    /// Shared secret established.
    shared_secret: Option<[u8; 32]>,
    /// Session established.
    established: bool,
    /// Persistent TCP connection (if available).
    connection: Option<TorConnection>,
    /// Last connection attempt time.
    last_connect_attempt: Option<Instant>,
    /// Messages awaiting acknowledgment.
    pending_acks: HashMap<[u8; 16], PendingMessage>,
}

impl PeerSession {
    fn new(address: OnionAddress) -> Self {
        Self {
            address,
            ratchet: None,
            our_ephemeral: None,
            shared_secret: None,
            established: false,
            connection: None,
            last_connect_attempt: None,
            pending_acks: HashMap::new(),
        }
    }

    /// Check if we should retry connecting (with backoff).
    fn _should_retry_connect(&self) -> bool {
        match self.last_connect_attempt {
            Some(last) => last.elapsed() > Duration::from_secs(RETRY_BASE_DELAY_SECS),
            None => true,
        }
    }
}

/// TorChat messaging daemon.
pub struct MessagingDaemon {
    /// Our identity.
    identity: TorIdentity,
    /// User ID for database operations.
    user_id: i64,
    /// Database for persistence (wrapped in Mutex for thread safety).
    database: Arc<TokioMutex<Database>>,
    /// Active sessions.
    sessions: Arc<RwLock<HashMap<String, PeerSession>>>,
    /// Tor connection config.
    tor_config: TorConnectionConfig,
    /// Command sender.
    cmd_tx: mpsc::Sender<DaemonCommand>,
    /// Command receiver (used internally).
    cmd_rx: Arc<TokioMutex<mpsc::Receiver<DaemonCommand>>>,
    /// Event broadcaster.
    event_tx: broadcast::Sender<DaemonEvent>,
    /// Running flag.
    running: Arc<RwLock<bool>>,
    /// Pending message retry queue.
    pending_queue: Arc<TokioMutex<VecDeque<PendingMessage>>>,
    /// File transfer manager.
    file_transfers: Arc<FileTransferManager>,
    /// Active group sessions.
    group_sessions: Arc<RwLock<HashMap<[u8; 32], crate::messaging::group_session::GroupSession>>>,
}

impl MessagingDaemon {
    /// Create a new messaging daemon.
    /// Takes a shared database reference so the daemon uses the same database as the API.
    pub fn new(identity: TorIdentity, database: Arc<TokioMutex<Database>>, user_id: i64) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(100);
        let (event_tx, _) = broadcast::channel(100);

        Self {
            identity,
            user_id,
            database,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            tor_config: TorConnectionConfig::default(),
            cmd_tx,
            cmd_rx: Arc::new(TokioMutex::new(cmd_rx)),
            event_tx,
            running: Arc::new(RwLock::new(false)),
            pending_queue: Arc::new(TokioMutex::new(VecDeque::new())),
            file_transfers: Arc::new(FileTransferManager::new()),
            group_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the file transfer manager.
    pub fn file_transfer_manager(&self) -> Arc<FileTransferManager> {
        self.file_transfers.clone()
    }

    /// Get a command sender to control the daemon.
    pub fn command_sender(&self) -> mpsc::Sender<DaemonCommand> {
        self.cmd_tx.clone()
    }

    /// Subscribe to daemon events.
    pub fn subscribe(&self) -> broadcast::Receiver<DaemonEvent> {
        self.event_tx.subscribe()
    }

    /// Get our onion address.
    pub fn onion_address(&self) -> &OnionAddress {
        self.identity.onion_address()
    }

    /// Start the daemon.
    pub async fn start(&self, service_config: OnionServiceConfig) -> Result<()> {
        // Check if already running
        {
            let running = self.running.read().await;
            if *running {
                return Err(Error::Tor("Daemon already running".into()));
            }
        }

        info!("Starting messaging daemon...");

        // Start onion service
        let service = OnionService::start(self.identity.clone(), service_config).await?;
        let onion_addr = service.onion_address().to_string();

        info!(address = %onion_addr, "Onion service started");

        // Ensure download directory exists for receiving files
        let download_dir = std::env::var("TORCHAT_DOWNLOAD_DIR")
            .unwrap_or_else(|_| format!("{}/.torchat/downloads", std::env::var("HOME").unwrap_or_else(|_| ".".to_string())));
        if let Err(e) = tokio::fs::create_dir_all(&download_dir).await {
            warn!(path = %download_dir, error = %e, "Failed to create download directory");
        } else {
            info!(path = %download_dir, "Download directory ready");
        }

        // Mark as running
        {
            let mut running = self.running.write().await;
            *running = true;
        }

        // Load existing groups from database
        {
            let db = self.database.lock().await;
            match db.list_groups() {
                Ok(groups) => {
                    for (group_id, name, _founder_pubkey, _state) in groups {
                        // Load full group metadata
                        match db.load_group_metadata(&group_id) {
                            Ok(Some((name, founder_pubkey, our_member_id, epoch_number, epoch_key, policy, state))) => {
                                // Load members
                                let members = db.load_group_members(&group_id).unwrap_or_default();
                                let members_map: std::collections::HashMap<[u8; 16], crate::protocol::GroupMember> =
                                    members.into_iter().map(|m| (m.member_id, m)).collect();

                                // Restore session
                                match crate::messaging::group_session::GroupSession::restore_from_database(
                                    group_id,
                                    name.clone(),
                                    founder_pubkey,
                                    our_member_id,
                                    epoch_number,
                                    epoch_key,
                                    policy,
                                    state,
                                    &self.identity,
                                    members_map,
                                ) {
                                    Ok(session) => {
                                        self.group_sessions.write().await.insert(group_id, session);
                                        info!(group_name = %name, "Loaded group from database");
                                    }
                                    Err(e) => {
                                        warn!(group_name = %name, error = %e, "Failed to restore group session");
                                    }
                                }
                            }
                            Ok(None) => {
                                warn!(group_name = %name, "Group metadata not found");
                            }
                            Err(e) => {
                                warn!(group_name = %name, error = %e, "Failed to load group metadata");
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to list groups from database");
                }
            }
        }

        // Emit started event
        let _ = self.event_tx.send(DaemonEvent::Started {
            onion_address: onion_addr.clone(),
        });

        // Shared map for invites awaiting acceptance (JoinGroup -> GroupJoinAccept)
        let pending_join_invites: Arc<RwLock<HashMap<[u8; 32], crate::protocol::GroupInvitePayload>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Shared map for files we're serving to group members (file_id -> path)
        let staged_group_files: Arc<RwLock<HashMap<String, std::path::PathBuf>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Load existing staged group files from database
        {
            let db = self.database.lock().await;
            let groups = self.group_sessions.read().await;
            for group_id in groups.keys() {
                if let Ok(files) = db.load_group_files(group_id, 1000) {
                    let mut staged = staged_group_files.write().await;
                    for file in files {
                        if let Some(ref path) = file.local_path {
                            if std::path::Path::new(path).exists() {
                                staged.insert(file.file_id, std::path::PathBuf::from(path));
                            }
                        }
                    }
                }
            }
        }

        // Spawn listener task
        let sessions = self.sessions.clone();
        let event_tx = self.event_tx.clone();
        let running = self.running.clone();
        let identity = self.identity.clone();
        let database = self.database.clone();
        let user_id = self.user_id;
        let group_sessions = self.group_sessions.clone();
        let tor_config_listen = self.tor_config.clone();
        let pending_join_invites_listen = pending_join_invites.clone();
        let staged_group_files_listen = staged_group_files.clone();

        tokio::spawn(async move {
            Self::listen_loop(service, sessions, event_tx, running, identity, database, user_id, group_sessions, tor_config_listen, pending_join_invites_listen, staged_group_files_listen).await;
        });

        // Spawn command handler
        let cmd_rx = self.cmd_rx.clone();
        let sessions = self.sessions.clone();
        let event_tx = self.event_tx.clone();
        let running = self.running.clone();
        let tor_config = self.tor_config.clone();
        let identity = self.identity.clone();
        let pending_queue = self.pending_queue.clone();
        let group_sessions = self.group_sessions.clone();
        let database = self.database.clone();
        let pending_join_invites_cmd = pending_join_invites.clone();
        let staged_group_files_cmd = staged_group_files.clone();

        tokio::spawn(async move {
            Self::command_loop(cmd_rx, sessions, event_tx, running, tor_config, identity, pending_queue, group_sessions, database, pending_join_invites_cmd, staged_group_files_cmd).await;
        });

        // Spawn retry worker for failed messages
        let pending_queue = self.pending_queue.clone();
        let sessions = self.sessions.clone();
        let event_tx = self.event_tx.clone();
        let running = self.running.clone();
        let tor_config = self.tor_config.clone();
        let identity = self.identity.clone();

        tokio::spawn(async move {
            Self::retry_loop(pending_queue, sessions, event_tx, running, tor_config, identity).await;
        });

        Ok(())
    }

    /// Retry loop for failed message delivery.
    async fn retry_loop(
        pending_queue: Arc<TokioMutex<VecDeque<PendingMessage>>>,
        sessions: Arc<RwLock<HashMap<String, PeerSession>>>,
        event_tx: broadcast::Sender<DaemonEvent>,
        running: Arc<RwLock<bool>>,
        tor_config: TorConnectionConfig,
        identity: TorIdentity,
    ) {
        info!("Message retry worker started");

        loop {
            // Check if still running
            {
                let is_running = running.read().await;
                if !*is_running {
                    break;
                }
            }

            // Sleep before checking queue
            tokio::time::sleep(Duration::from_secs(RETRY_BASE_DELAY_SECS)).await;

            // Process pending messages
            let mut messages_to_retry = Vec::new();
            {
                let mut queue = pending_queue.lock().await;
                let now = Instant::now();

                // Collect messages ready for retry
                while let Some(msg) = queue.pop_front() {
                    let backoff = Duration::from_secs(RETRY_BASE_DELAY_SECS * (1 << msg.attempts.min(5)));
                    if now.duration_since(msg.last_attempt) >= backoff {
                        messages_to_retry.push(msg);
                    } else {
                        // Not ready yet, put back
                        queue.push_back(msg);
                        break;
                    }
                }
            }

            // Retry each message
            for mut msg in messages_to_retry {
                if msg.attempts >= MAX_RETRY_ATTEMPTS {
                    warn!(to = %msg.to, message_id = ?msg.message_id, "Message delivery failed after max retries");
                    let _ = event_tx.send(DaemonEvent::MessageFailed {
                        message_id: msg.message_id,
                        error: "Max retries exceeded".to_string(),
                    });
                    continue;
                }

                msg.attempts += 1;
                msg.last_attempt = Instant::now();

                info!(to = %msg.to, attempt = msg.attempts, "Retrying message delivery");

                match Self::send_message_to_peer(
                    &msg.to,
                    &msg.content,
                    msg.message_id,
                    &sessions,
                    &tor_config,
                    &identity,
                ).await {
                    Ok(()) => {
                        info!(to = %msg.to, "Message delivered on retry");
                        let _ = event_tx.send(DaemonEvent::MessageDelivered {
                            message_id: msg.message_id,
                        });
                    }
                    Err(e) => {
                        warn!(to = %msg.to, error = %e, "Retry failed, requeuing");
                        let mut queue = pending_queue.lock().await;
                        queue.push_back(msg);
                    }
                }
            }
        }

        info!("Message retry worker stopped");
    }

    /// Listen for incoming connections.
    async fn listen_loop(
        service: OnionService,
        sessions: Arc<RwLock<HashMap<String, PeerSession>>>,
        event_tx: broadcast::Sender<DaemonEvent>,
        running: Arc<RwLock<bool>>,
        identity: TorIdentity,
        database: Arc<TokioMutex<Database>>,
        user_id: i64,
        group_sessions: Arc<RwLock<HashMap<[u8; 32], crate::messaging::group_session::GroupSession>>>,
        tor_config: TorConnectionConfig,
        pending_join_invites: Arc<RwLock<HashMap<[u8; 32], crate::protocol::GroupInvitePayload>>>,
        staged_group_files: Arc<RwLock<HashMap<String, std::path::PathBuf>>>,
    ) {
        info!("Listening for incoming connections...");

        loop {
            // Check if still running
            {
                let is_running = running.read().await;
                if !*is_running {
                    break;
                }
            }

            // Accept connection with timeout
            let accept_result = tokio::time::timeout(
                tokio::time::Duration::from_secs(1),
                service.accept(),
            )
            .await;

            match accept_result {
                Ok(Ok(stream)) => {
                    let sessions = sessions.clone();
                    let event_tx = event_tx.clone();
                    let identity = identity.clone();
                    let database = database.clone();
                    let group_sessions = group_sessions.clone();
                    let tor_config = tor_config.clone();
                    let pending_join_invites = pending_join_invites.clone();
                    let staged_group_files = staged_group_files.clone();

                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_incoming(stream, sessions, event_tx, identity, database, user_id, group_sessions, tor_config, pending_join_invites, staged_group_files).await
                        {
                            warn!(error = %e, "Error handling incoming connection");
                        }
                    });
                }
                Ok(Err(e)) => {
                    error!(error = %e, "Accept failed");
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
                Err(_) => {
                    // Timeout, continue loop to check running flag
                    continue;
                }
            }
        }

        // Cleanup
        if let Err(e) = service.stop().await {
            warn!(error = %e, "Error stopping service");
        }

        let _ = event_tx.send(DaemonEvent::Stopped);
        info!("Listener stopped");
    }

    /// Handle an incoming connection.
    async fn handle_incoming(
        mut stream: TcpStream,
        sessions: Arc<RwLock<HashMap<String, PeerSession>>>,
        event_tx: broadcast::Sender<DaemonEvent>,
        identity: TorIdentity,
        database: Arc<TokioMutex<Database>>,
        user_id: i64,
        group_sessions: Arc<RwLock<HashMap<[u8; 32], crate::messaging::group_session::GroupSession>>>,
        tor_config: TorConnectionConfig,
        pending_join_invites: Arc<RwLock<HashMap<[u8; 32], crate::protocol::GroupInvitePayload>>>,
        staged_group_files: Arc<RwLock<HashMap<String, std::path::PathBuf>>>,
    ) -> Result<()> {
        use tokio::io::AsyncReadExt;

        debug!("Handling incoming connection");

        // Peek at first 8 bytes to detect file transfer or file request
        let mut magic_buf = [0u8; 8];
        stream.read_exact(&mut magic_buf).await
            .map_err(|e| Error::Tor(format!("Failed to read magic: {}", e)))?;

        // Check if this is a file request (group file download)
        if crate::messaging::stream_transfer::is_file_request_magic(&magic_buf) {
            info!("Detected incoming file request stream");
            let our_address = identity.onion_address().to_string();
            match crate::messaging::stream_transfer::handle_file_request(
                &mut stream,
                &staged_group_files,
                &our_address,
            ).await {
                Ok(()) => info!("File request served successfully"),
                Err(e) => warn!(error = %e, "Failed to serve file request"),
            }
            return Ok(());
        }

        // Check if this is a file transfer
        if crate::messaging::stream_transfer::is_file_transfer_magic(&magic_buf) {
            info!("Detected incoming file transfer stream");

            // Get download directory
            let download_dir = std::env::var("TORCHAT_DOWNLOAD_DIR")
                .unwrap_or_else(|_| format!("{}/.torchat/downloads", std::env::var("HOME").unwrap_or_else(|_| ".".to_string())));

            // Create directory if needed - log errors instead of ignoring
            if let Err(e) = tokio::fs::create_dir_all(&download_dir).await {
                warn!(path = %download_dir, error = %e, "Failed to create download directory");
            } else {
                info!(path = %download_dir, "Download directory ready");
            }

            // Handle file transfer
            match crate::messaging::stream_transfer::receive_file_stream(
                &mut stream,
                std::path::PathBuf::from(&download_dir),
            ).await {
                Ok(result) => {
                    if result.success {
                        info!(
                            transfer_id = ?result.transfer_id,
                            path = ?result.output_path,
                            filename = ?result.filename,
                            from = ?result.sender_address,
                            "File received successfully"
                        );
                        let _ = event_tx.send(DaemonEvent::FileTransferCompleted {
                            transfer_id: result.transfer_id,
                            output_path: result.output_path.map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
                            filename: result.filename.unwrap_or_default(),
                            from: result.sender_address.unwrap_or_default(),
                            size: result.size.unwrap_or(0),
                        });
                    } else {
                        warn!(
                            transfer_id = ?result.transfer_id,
                            error = ?result.error,
                            "File transfer failed"
                        );
                        let _ = event_tx.send(DaemonEvent::FileTransferFailed {
                            transfer_id: result.transfer_id,
                            error: result.error.unwrap_or_else(|| "Unknown error".to_string()),
                        });
                    }
                }
                Err(e) => {
                    warn!(error = %e, "File transfer error");
                }
            }
            return Ok(());
        }

        // Not a file transfer - reconstruct packet header and read rest
        // The 8 bytes we read are: [version, type, length(4 bytes), payload_start(2 bytes)]
        // Actually the header is 6 bytes: version(1) + type(1) + length(4)
        // So we have header(6) + first 2 bytes of payload

        // Read remaining header bytes (we have 8, header is 6, so we have 2 extra payload bytes)
        let version = magic_buf[0];
        let packet_type_byte = magic_buf[1];
        let payload_len = u32::from_be_bytes([magic_buf[2], magic_buf[3], magic_buf[4], magic_buf[5]]) as usize;

        // Validate
        crate::protocol::validate_version(version)?;
        let packet_type = PacketType::from_byte(packet_type_byte)?;

        if payload_len > crate::protocol::MAX_PAYLOAD_SIZE {
            return Err(Error::Protocol(format!("Payload too large: {}", payload_len)));
        }

        // We already have 2 bytes of payload (magic_buf[6], magic_buf[7])
        let mut payload = vec![0u8; payload_len];
        if payload_len >= 2 {
            payload[0] = magic_buf[6];
            payload[1] = magic_buf[7];
            if payload_len > 2 {
                stream.read_exact(&mut payload[2..]).await
                    .map_err(|e| Error::Tor(format!("Failed to read payload: {}", e)))?;
            }
        } else if payload_len == 1 {
            payload[0] = magic_buf[6];
        }
        // If payload_len == 0, nothing to do

        let packet = Packet {
            header: PacketHeader {
                version,
                packet_type,
                length: payload_len as u32,
            },
            payload,
        };

        match packet.header.packet_type {
            PacketType::Hello => {
                // Parse chat hello
                let hello = ChatHello::from_bytes(&packet.payload)?;
                let peer_addr_str = hello.sender_address.clone();

                info!(from = %peer_addr_str, "Received Hello");

                // Parse peer address
                let peer_addr = OnionAddress::from_string(&peer_addr_str)
                    .map_err(|_| Error::Protocol("Invalid sender address".into()))?;

                // Generate our ephemeral key for key exchange
                let our_ephemeral = EphemeralKeypair::generate();
                let our_public = *our_ephemeral.public_key().as_bytes();

                // Derive shared secret from their ephemeral key
                let their_public = X25519PublicKey::from(hello.ephemeral_public);
                let shared = our_ephemeral.diffie_hellman(&their_public);

                // Send hello response
                let response_payload = ChatHelloResponse {
                    ephemeral_public: our_public,
                    identity_public: *identity.public_key().as_bytes(),
                    responder_address: identity.onion_address().to_string(),
                };

                let response = Packet::new(PacketType::SessionInit, response_payload.to_bytes()?)?;
                Self::write_packet(&mut stream, &response).await?;

                // Initialize ratchet as responder
                // Use the same ephemeral key we sent in the response, so Alice can derive the same chain
                let ratchet = DoubleRatchet::init_responder_from_bytes(
                    shared.as_bytes(),
                    our_ephemeral,
                );

                // Store session
                let mut sessions_guard = sessions.write().await;
                let session = sessions_guard
                    .entry(peer_addr_str.clone())
                    .or_insert_with(|| PeerSession::new(peer_addr));

                session.ratchet = Some(ratchet);
                session.shared_secret = Some(*shared.as_bytes());
                // our_ephemeral is now owned by the ratchet
                session.established = true;

                let _ = event_tx.send(DaemonEvent::PeerConnected {
                    address: peer_addr_str.clone(),
                });

                // Handle subsequent packets on this connection
                drop(sessions_guard);
                Self::handle_connection_loop(stream, peer_addr_str, sessions, event_tx, database, user_id, group_sessions, identity, tor_config.clone(), pending_join_invites.clone()).await?;

                Ok(())
            }
            PacketType::Message => {
                // Received message on existing connection (sender has session, didn't need Hello)
                Self::handle_message_packet(&packet, &sessions, &event_tx, &database, user_id).await
            }
            PacketType::Ack => {
                let ack = AckPayload::from_bytes(&packet.payload)?;
                let _ = event_tx.send(DaemonEvent::AckReceived {
                    message_id: ack.message_id,
                    ack_type: ack.ack_type,
                });
                Ok(())
            }
            PacketType::FileChunk => {
                // Handle file chunk on direct connection
                Self::handle_file_chunk_packet(&packet, &sessions, &event_tx).await
            }
            PacketType::CallSignal => {
                // Handle call signal on direct connection
                Self::handle_call_signal_packet(&packet, &sessions, &event_tx).await
            }
            PacketType::FileOffer => {
                // Handle file offer on direct connection
                Self::handle_file_offer_packet(&packet, &sessions, &event_tx).await
            }
            PacketType::GroupInvite => {
                // Handle incoming group invite
                Self::handle_group_invite_packet(&packet, &event_tx).await
            }
            PacketType::GroupMessage => {
                // Handle group message (gossip)
                Self::handle_group_message_packet(&packet, &event_tx, &group_sessions, &database, &sessions, &tor_config).await
            }
            PacketType::GroupJoinRequest => {
                // Handle join request from new member
                Self::handle_group_join_request_packet(&packet, &event_tx, &group_sessions, &identity, &tor_config, &database).await
            }
            PacketType::GroupJoinAccept => {
                // Handle join accept from bootstrap peer
                Self::handle_group_join_accept_packet(&packet, &event_tx, &group_sessions, &identity, &database, user_id, &pending_join_invites).await
            }
            _ => {
                warn!(packet_type = ?packet.header.packet_type, "Unhandled packet type");
                Ok(())
            }
        }
    }

    /// Handle continuous messages on a connection.
    async fn handle_connection_loop(
        mut stream: TcpStream,
        peer_address: String,
        sessions: Arc<RwLock<HashMap<String, PeerSession>>>,
        event_tx: broadcast::Sender<DaemonEvent>,
        database: Arc<TokioMutex<Database>>,
        user_id: i64,
        group_sessions: Arc<RwLock<HashMap<[u8; 32], crate::messaging::group_session::GroupSession>>>,
        identity: TorIdentity,
        tor_config: TorConnectionConfig,
        pending_join_invites: Arc<RwLock<HashMap<[u8; 32], crate::protocol::GroupInvitePayload>>>,
    ) -> Result<()> {
        debug!(peer = %peer_address, "Entering connection loop");
        loop {
            match Self::read_packet(&mut stream).await {
                Ok(packet) => {
                    debug!(peer = %peer_address, packet_type = ?packet.header.packet_type, "Received packet");
                    match packet.header.packet_type {
                        PacketType::Message => {
                            // Decrypt and process message
                            let payload = MessagePayload::from_bytes(&packet.payload)?;
                            let message_id = payload.message_id;

                            let mut sessions_guard = sessions.write().await;
                            if let Some(session) = sessions_guard.get_mut(&peer_address) {
                                if let Some(ratchet) = &mut session.ratchet {
                                    match ratchet.decrypt(&payload.header, &payload.ciphertext) {
                                        Ok(plaintext) => {
                                            let content = String::from_utf8_lossy(&plaintext).to_string();

                                            info!(from = %peer_address, "Message received and decrypted");

                                            // Store received message in database
                                            {
                                                let db = database.lock().await;
                                                if let Err(e) = db.store_simple_message_by_address(
                                                    user_id,
                                                    &peer_address,
                                                    &content,
                                                    false, // is_outgoing = false for received messages
                                                ) {
                                                    warn!(error = %e, "Failed to store received message");
                                                } else {
                                                    debug!(from = %peer_address, "Received message stored in database");
                                                }
                                            }

                                            let _ = event_tx.send(DaemonEvent::MessageReceived {
                                                from: peer_address.clone(),
                                                message_id,
                                                content,
                                                timestamp: payload.timestamp,
                                            });

                                            // Send ACK back to sender
                                            let ack = AckPayload {
                                                message_id,
                                                ack_type: AckType::Delivered,
                                                timestamp: chrono::Utc::now().timestamp(),
                                            };

                                            if let Ok(ack_bytes) = ack.to_bytes() {
                                                if let Ok(ack_packet) = Packet::new(PacketType::Ack, ack_bytes) {
                                                    let _ = Self::write_packet(&mut stream, &ack_packet).await;
                                                    debug!(to = %peer_address, "Delivery ACK sent");
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!(peer = %peer_address, error = %e, "Failed to decrypt message");
                                        }
                                    }
                                } else {
                                    warn!(peer = %peer_address, "No ratchet found for session");
                                }
                            } else {
                                warn!(peer = %peer_address, "No session found");
                            }
                        }
                        PacketType::Ack => {
                            let ack = AckPayload::from_bytes(&packet.payload)?;
                            let _ = event_tx.send(DaemonEvent::AckReceived {
                                message_id: ack.message_id,
                                ack_type: ack.ack_type,
                            });
                        }
                        PacketType::FileChunk => {
                            // Decrypt and process file chunk
                            if let Err(e) = Self::handle_file_chunk_in_session(
                                &packet, &peer_address, &sessions, &event_tx
                            ).await {
                                warn!(error = %e, "Failed to handle file chunk");
                            }
                        }
                        PacketType::CallSignal => {
                            // Decrypt and process call signal
                            if let Err(e) = Self::handle_call_signal_in_session(
                                &packet, &peer_address, &sessions, &event_tx
                            ).await {
                                warn!(error = %e, "Failed to handle call signal");
                            }
                        }
                        PacketType::FileOffer => {
                            // Decrypt and process file offer
                            if let Err(e) = Self::handle_file_offer_in_session(
                                &packet, &peer_address, &sessions, &event_tx
                            ).await {
                                warn!(error = %e, "Failed to handle file offer");
                            }
                        }
                        PacketType::GroupInvite => {
                            // Handle incoming group invite
                            if let Err(e) = Self::handle_group_invite_packet(&packet, &event_tx).await {
                                warn!(error = %e, "Failed to handle group invite");
                            }
                        }
                        PacketType::GroupMessage => {
                            // Handle group message (gossip)
                            if let Err(e) = Self::handle_group_message_packet(&packet, &event_tx, &group_sessions, &database, &sessions, &tor_config).await {
                                warn!(error = %e, "Failed to handle group message");
                            }
                        }
                        PacketType::GroupJoinRequest => {
                            // Handle join request from new member
                            if let Err(e) = Self::handle_group_join_request_packet(&packet, &event_tx, &group_sessions, &identity, &tor_config, &database).await {
                                warn!(error = %e, "Failed to handle group join request");
                            }
                        }
                        PacketType::GroupJoinAccept => {
                            // Handle join accept from bootstrap peer
                            if let Err(e) = Self::handle_group_join_accept_packet(&packet, &event_tx, &group_sessions, &identity, &database, user_id, &pending_join_invites).await {
                                warn!(error = %e, "Failed to handle group join accept");
                            }
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    // Connection closed or error
                    debug!(peer = %peer_address, error = %e, "Connection loop ended");
                    let _ = event_tx.send(DaemonEvent::PeerDisconnected {
                        address: peer_address,
                    });
                    break;
                }
            }
        }
        Ok(())
    }

    /// Handle a message packet that arrived on a new connection (sender already had session).
    async fn handle_message_packet(
        packet: &Packet,
        sessions: &Arc<RwLock<HashMap<String, PeerSession>>>,
        event_tx: &broadcast::Sender<DaemonEvent>,
        database: &Arc<TokioMutex<Database>>,
        user_id: i64,
    ) -> Result<()> {
        let payload = MessagePayload::from_bytes(&packet.payload)?;

        // Try all established sessions (we don't know sender from packet alone)
        let mut sessions_guard = sessions.write().await;
        for (addr, session) in sessions_guard.iter_mut() {
            if session.established {
                if let Some(ratchet) = &mut session.ratchet {
                    if let Ok(plaintext) = ratchet.decrypt(&payload.header, &payload.ciphertext) {
                        let content = String::from_utf8_lossy(&plaintext).to_string();

                        info!(from = %addr, "Message received and decrypted (direct connection)");

                        // Store received message in database (same as handle_connection_loop)
                        {
                            let db = database.lock().await;
                            if let Err(e) = db.store_simple_message_by_address(
                                user_id,
                                addr,
                                &content,
                                false, // is_outgoing = false for received messages
                            ) {
                                warn!(error = %e, "Failed to store received message");
                            } else {
                                debug!(from = %addr, "Received message stored in database");
                            }
                        }

                        let _ = event_tx.send(DaemonEvent::MessageReceived {
                            from: addr.clone(),
                            message_id: payload.message_id,
                            content,
                            timestamp: payload.timestamp,
                        });
                        return Ok(());
                    }
                }
            }
        }

        Err(Error::NoSession)
    }

    /// Handle a file chunk packet on a direct connection (no established session context).
    async fn handle_file_chunk_packet(
        packet: &Packet,
        sessions: &Arc<RwLock<HashMap<String, PeerSession>>>,
        event_tx: &broadcast::Sender<DaemonEvent>,
    ) -> Result<()> {
        let payload = FileChunkPayload::from_bytes(&packet.payload)?;

        // Try all established sessions to decrypt
        let mut sessions_guard = sessions.write().await;
        for (addr, session) in sessions_guard.iter_mut() {
            if session.established {
                if let Some(ratchet) = &mut session.ratchet {
                    if let Ok(chunk_data) = ratchet.decrypt(&payload.header, &payload.ciphertext) {
                        info!(
                            from = %addr,
                            transfer_id = ?payload.transfer_id,
                            chunk = payload.chunk_index,
                            total = payload.total_chunks,
                            size = chunk_data.len(),
                            "File chunk received"
                        );

                        let _ = event_tx.send(DaemonEvent::FileChunkReceived {
                            transfer_id: payload.transfer_id,
                            chunk_index: payload.chunk_index,
                            total_chunks: payload.total_chunks,
                            from: addr.clone(),
                            data: chunk_data,
                        });
                        return Ok(());
                    }
                }
            }
        }

        Err(Error::NoSession)
    }

    /// Handle a file chunk within an established session.
    async fn handle_file_chunk_in_session(
        packet: &Packet,
        peer_address: &str,
        sessions: &Arc<RwLock<HashMap<String, PeerSession>>>,
        event_tx: &broadcast::Sender<DaemonEvent>,
    ) -> Result<()> {
        let payload = FileChunkPayload::from_bytes(&packet.payload)?;

        let mut sessions_guard = sessions.write().await;
        if let Some(session) = sessions_guard.get_mut(peer_address) {
            if let Some(ratchet) = &mut session.ratchet {
                let chunk_data = ratchet.decrypt(&payload.header, &payload.ciphertext)?;

                info!(
                    from = %peer_address,
                    transfer_id = ?payload.transfer_id,
                    chunk = payload.chunk_index,
                    total = payload.total_chunks,
                    size = chunk_data.len(),
                    "File chunk received and decrypted"
                );

                let _ = event_tx.send(DaemonEvent::FileChunkReceived {
                    transfer_id: payload.transfer_id,
                    chunk_index: payload.chunk_index,
                    total_chunks: payload.total_chunks,
                    from: peer_address.to_string(),
                    data: chunk_data,
                });

                return Ok(());
            }
        }

        Err(Error::NoSession)
    }

    /// Handle a call signal packet on a direct connection.
    async fn handle_call_signal_packet(
        packet: &Packet,
        sessions: &Arc<RwLock<HashMap<String, PeerSession>>>,
        event_tx: &broadcast::Sender<DaemonEvent>,
    ) -> Result<()> {
        let payload = CallSignalPayload::from_bytes(&packet.payload)?;

        // Try all established sessions to decrypt
        let mut sessions_guard = sessions.write().await;
        for (addr, session) in sessions_guard.iter_mut() {
            if session.established {
                if let Some(ratchet) = &mut session.ratchet {
                    if let Ok(signal_data) = ratchet.decrypt(&payload.header, &payload.ciphertext) {
                        info!(
                            from = %addr,
                            call_id = ?payload.call_id,
                            signal_type = ?payload.signal_type,
                            "Call signal received"
                        );

                        let _ = event_tx.send(DaemonEvent::CallSignalReceived {
                            call_id: payload.call_id,
                            signal_type: payload.signal_type,
                            from: addr.clone(),
                            data: signal_data,
                        });
                        return Ok(());
                    }
                }
            }
        }

        Err(Error::NoSession)
    }

    /// Handle a call signal within an established session.
    async fn handle_call_signal_in_session(
        packet: &Packet,
        peer_address: &str,
        sessions: &Arc<RwLock<HashMap<String, PeerSession>>>,
        event_tx: &broadcast::Sender<DaemonEvent>,
    ) -> Result<()> {
        let payload = CallSignalPayload::from_bytes(&packet.payload)?;

        let mut sessions_guard = sessions.write().await;
        if let Some(session) = sessions_guard.get_mut(peer_address) {
            if let Some(ratchet) = &mut session.ratchet {
                let signal_data = ratchet.decrypt(&payload.header, &payload.ciphertext)?;

                info!(
                    from = %peer_address,
                    call_id = ?payload.call_id,
                    signal_type = ?payload.signal_type,
                    "Call signal received and decrypted"
                );

                let _ = event_tx.send(DaemonEvent::CallSignalReceived {
                    call_id: payload.call_id,
                    signal_type: payload.signal_type,
                    from: peer_address.to_string(),
                    data: signal_data,
                });

                return Ok(());
            }
        }

        Err(Error::NoSession)
    }

    /// Handle a file offer packet on a direct connection.
    async fn handle_file_offer_packet(
        packet: &Packet,
        sessions: &Arc<RwLock<HashMap<String, PeerSession>>>,
        event_tx: &broadcast::Sender<DaemonEvent>,
    ) -> Result<()> {
        let payload = FileOfferPayload::from_bytes(&packet.payload)?;

        // Try all established sessions to decrypt
        let mut sessions_guard = sessions.write().await;
        for (addr, session) in sessions_guard.iter_mut() {
            if session.established {
                if let Some(ratchet) = &mut session.ratchet {
                    if let Ok(_decrypted) = ratchet.decrypt(&payload.header, &payload.ciphertext) {
                        info!(
                            from = %addr,
                            transfer_id = ?payload.transfer_id,
                            filename = %payload.filename,
                            size = payload.size,
                            "File offer received"
                        );

                        let _ = event_tx.send(DaemonEvent::FileOfferReceived {
                            transfer_id: payload.transfer_id,
                            filename: payload.filename.clone(),
                            size: payload.size,
                            hash: payload.hash,
                            total_chunks: payload.total_chunks,
                            from: addr.clone(),
                        });
                        return Ok(());
                    }
                }
            }
        }

        Err(Error::NoSession)
    }

    /// Handle a file offer within an established session.
    async fn handle_file_offer_in_session(
        packet: &Packet,
        peer_address: &str,
        sessions: &Arc<RwLock<HashMap<String, PeerSession>>>,
        event_tx: &broadcast::Sender<DaemonEvent>,
    ) -> Result<()> {
        let payload = FileOfferPayload::from_bytes(&packet.payload)?;

        let mut sessions_guard = sessions.write().await;
        if let Some(session) = sessions_guard.get_mut(peer_address) {
            if let Some(ratchet) = &mut session.ratchet {
                let _decrypted = ratchet.decrypt(&payload.header, &payload.ciphertext)?;

                info!(
                    from = %peer_address,
                    transfer_id = ?payload.transfer_id,
                    filename = %payload.filename,
                    size = payload.size,
                    "File offer received and decrypted"
                );

                let _ = event_tx.send(DaemonEvent::FileOfferReceived {
                    transfer_id: payload.transfer_id,
                    filename: payload.filename,
                    size: payload.size,
                    hash: payload.hash,
                    total_chunks: payload.total_chunks,
                    from: peer_address.to_string(),
                });

                return Ok(());
            }
        }

        Err(Error::NoSession)
    }

    /// Command processing loop.
    async fn command_loop(
        cmd_rx: Arc<TokioMutex<mpsc::Receiver<DaemonCommand>>>,
        sessions: Arc<RwLock<HashMap<String, PeerSession>>>,
        event_tx: broadcast::Sender<DaemonEvent>,
        running: Arc<RwLock<bool>>,
        tor_config: TorConnectionConfig,
        identity: TorIdentity,
        pending_queue: Arc<TokioMutex<VecDeque<PendingMessage>>>,
        group_sessions: Arc<RwLock<HashMap<[u8; 32], crate::messaging::group_session::GroupSession>>>,
        database: Arc<TokioMutex<Database>>,
        pending_join_invites: Arc<RwLock<HashMap<[u8; 32], crate::protocol::GroupInvitePayload>>>,
        staged_group_files: Arc<RwLock<HashMap<String, std::path::PathBuf>>>,
    ) {
        let mut cmd_rx: tokio::sync::MutexGuard<'_, mpsc::Receiver<DaemonCommand>> = cmd_rx.lock().await;

        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                DaemonCommand::SendMessage {
                    to,
                    content,
                    message_id,
                } => {
                    info!(to = %to, "Attempting to send message via Tor");

                    let result = Self::send_message_to_peer(
                        &to,
                        &content,
                        message_id,
                        &sessions,
                        &tor_config,
                        &identity,
                    )
                    .await;

                    match result {
                        Ok(()) => {
                            info!(to = %to, "Message delivered successfully");
                            let _ = event_tx.send(DaemonEvent::MessageDelivered { message_id });
                        }
                        Err(e) => {
                            warn!(to = %to, error = %e, "Message delivery failed, queuing for retry");

                            // Add to retry queue instead of immediately failing
                            let pending = PendingMessage {
                                message_id,
                                to: to.clone(),
                                content: content.clone(),
                                attempts: 1,
                                last_attempt: Instant::now(),
                                _queued_at: Instant::now(),
                            };

                            let mut queue = pending_queue.lock().await;
                            queue.push_back(pending);

                            // Still emit event so UI knows it's pending
                            let _ = event_tx.send(DaemonEvent::MessageFailed {
                                message_id,
                                error: format!("Queued for retry: {}", e),
                            });
                        }
                    }
                }
                DaemonCommand::SendAck {
                    to,
                    message_id,
                    ack_type,
                } => {
                    if let Err(e) =
                        Self::send_ack_to_peer(&to, message_id, ack_type, &tor_config).await
                    {
                        warn!(error = %e, "Failed to send ack");
                    }
                }
                DaemonCommand::Connect { address } => {
                    if let Err(e) =
                        Self::connect_to_peer(&address, &sessions, &tor_config, &identity).await
                    {
                        let _ = event_tx.send(DaemonEvent::Error {
                            message: format!("Connect failed: {}", e),
                        });
                    } else {
                        let _ = event_tx.send(DaemonEvent::PeerConnected { address });
                    }
                }
                DaemonCommand::Disconnect { address } => {
                    let mut sessions = sessions.write().await;
                    if sessions.remove(&address).is_some() {
                        let _ = event_tx.send(DaemonEvent::PeerDisconnected { address });
                    }
                }
                DaemonCommand::Stop => {
                    let mut is_running = running.write().await;
                    *is_running = false;
                    break;
                }
                DaemonCommand::SendFileOffer { to, transfer_id, filename, size, hash, total_chunks } => {
                    match Self::send_file_offer_to_peer(
                        &to, transfer_id, &filename, size, hash, total_chunks,
                        &sessions, &tor_config, &identity
                    ).await {
                        Ok(()) => {
                            info!(to = %to, filename = %filename, size = size, "File offer sent");
                        }
                        Err(e) => {
                            warn!(to = %to, error = %e, "Failed to send file offer");
                            let _ = event_tx.send(DaemonEvent::FileTransferFailed {
                                transfer_id,
                                error: e.to_string(),
                            });
                        }
                    }
                }
                DaemonCommand::SendFile { to, file_path, transfer_id: _ } => {
                    info!(to = %to, file = ?file_path, "SendFile command received (legacy)");
                    // File transfer is now handled via SendFileOffer + SendFileChunk commands
                }
                DaemonCommand::SendFileChunk { to, transfer_id, chunk_index, total_chunks, data } => {
                    match Self::send_file_chunk_to_peer(
                        &to, transfer_id, chunk_index, total_chunks, &data,
                        &sessions, &tor_config, &identity
                    ).await {
                        Ok(()) => {
                            debug!(to = %to, chunk = chunk_index, "File chunk sent");
                        }
                        Err(e) => {
                            warn!(to = %to, error = %e, "Failed to send file chunk");
                            let _ = event_tx.send(DaemonEvent::FileTransferFailed {
                                transfer_id,
                                error: e.to_string(),
                            });
                        }
                    }
                }
                DaemonCommand::SendCallSignal { to, call_id, signal_type, data } => {
                    match Self::send_call_signal_to_peer(
                        &to, call_id, signal_type, &data,
                        &sessions, &tor_config, &identity
                    ).await {
                        Ok(()) => {
                            info!(to = %to, signal = ?signal_type, "Call signal sent");
                        }
                        Err(e) => {
                            warn!(to = %to, error = %e, "Failed to send call signal");
                        }
                    }
                }
                DaemonCommand::CreateGroup { name, policy } => {
                    match crate::messaging::group_session::GroupSession::create_as_founder(
                        name.clone(),
                        &identity,
                        policy,
                    ) {
                        Ok(session) => {
                            let group_id = session.id;
                            let name = session.name.clone();

                            // Persist group to database
                            if let Err(e) = database.lock().await.store_group(&session) {
                                warn!(error = %e, "Failed to persist group to database");
                            }

                            group_sessions.write().await.insert(group_id, session);
                            let _ = event_tx.send(DaemonEvent::GroupCreated { group_id, name });
                            info!(group_id = ?group_id, "Group created");
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to create group");
                            let _ = event_tx.send(DaemonEvent::Error {
                                message: format!("Failed to create group: {}", e),
                            });
                        }
                    }
                }
                DaemonCommand::SendGroupInvite { group_id, invitee_onion, expires_at } => {
                    let groups = group_sessions.read().await;
                    if let Some(session) = groups.get(&group_id) {
                        let bootstrap_peer = identity.onion_address().to_string();
                        match session.generate_invite(expires_at, &bootstrap_peer) {
                            Ok(invite) => {
                                // Emit event for local tracking
                                let _ = event_tx.send(DaemonEvent::GroupInviteGenerated {
                                    group_id,
                                    invite: invite.clone(),
                                });

                                // Actually send the invite to the invitee over the network
                                let invite_bytes = match invite.to_bytes() {
                                    Ok(bytes) => bytes,
                                    Err(e) => {
                                        warn!(error = %e, "Failed to serialize invite");
                                        continue;
                                    }
                                };

                                // Create the packet
                                let packet = match Packet::new(PacketType::GroupInvite, invite_bytes) {
                                    Ok(p) => p,
                                    Err(e) => {
                                        warn!(error = %e, "Failed to create invite packet");
                                        continue;
                                    }
                                };

                                // Connect to invitee and send the invite
                                let invitee_clone = invitee_onion.clone();
                                let tor_config_clone = tor_config.clone();
                                let event_tx_clone = event_tx.clone();

                                tokio::spawn(async move {
                                    // Parse invitee onion address
                                    let peer_addr = match OnionAddress::from_string(&invitee_clone) {
                                        Ok(addr) => addr,
                                        Err(_) => {
                                            warn!(invitee = %invitee_clone, "Invalid invitee onion address");
                                            let _ = event_tx_clone.send(DaemonEvent::Error {
                                                message: "Invalid invitee onion address".to_string(),
                                            });
                                            return;
                                        }
                                    };

                                    match TorConnection::connect(&tor_config_clone, &peer_addr).await {
                                        Ok(mut conn) => {
                                            match Self::write_packet(conn.stream_mut(), &packet).await {
                                                Ok(_) => {
                                                    info!(invitee = %invitee_clone, "Group invite sent successfully");
                                                    let _ = event_tx_clone.send(DaemonEvent::GroupInviteSent {
                                                        group_id,
                                                        invitee: invitee_clone,
                                                    });
                                                }
                                                Err(e) => {
                                                    warn!(invitee = %invitee_clone, error = %e, "Failed to send invite packet");
                                                    let _ = event_tx_clone.send(DaemonEvent::Error {
                                                        message: format!("Failed to send invite: {}", e),
                                                    });
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!(invitee = %invitee_clone, error = %e, "Failed to connect to invitee");
                                            let _ = event_tx_clone.send(DaemonEvent::Error {
                                                message: format!("Failed to connect to invitee: {}", e),
                                            });
                                        }
                                    }
                                });

                                info!(group_id = ?group_id, invitee = %invitee_onion, "Group invite generated and being sent");
                            }
                            Err(e) => {
                                warn!(group_id = ?group_id, error = %e, "Failed to generate invite");
                            }
                        }
                    } else {
                        warn!(group_id = ?group_id, "Group not found");
                    }
                }
                DaemonCommand::JoinGroup { invite } => {
                    // Verify invite hasn't expired
                    let now = chrono::Utc::now().timestamp();
                    if now > invite.expires_at {
                        warn!("Attempt to join with expired invite");
                        let _ = event_tx.send(DaemonEvent::Error {
                            message: "Invite has expired".to_string(),
                        });
                        continue;
                    }

                    // Generate our member ID and sign the join request
                    let our_pubkey = identity.public_key().to_bytes();
                    let our_x25519_pubkey = identity.x25519_public_key().to_bytes();
                    let requester_onion = identity.onion_address().to_string();

                    // Sign the join request
                    let mut message_to_sign = Vec::new();
                    message_to_sign.extend_from_slice(&invite.group_id);
                    message_to_sign.extend_from_slice(&our_pubkey);
                    message_to_sign.extend_from_slice(requester_onion.as_bytes());
                    let request_signature = identity.signing_key().sign(&message_to_sign).to_bytes();

                    // Create join request payload
                    let join_request = crate::protocol::GroupJoinRequestPayload {
                        group_id: invite.group_id,
                        requester_onion: requester_onion.clone(),
                        requester_pubkey: our_pubkey,
                        requester_x25519_pubkey: our_x25519_pubkey,
                        invite_token: invite.clone(),
                        request_signature,
                    };

                    // Store invite so we can create the session when accept arrives
                    {
                        let mut invites = pending_join_invites.write().await;
                        invites.insert(invite.group_id, invite.clone());
                    }

                    // Connect to bootstrap peer and send join request
                    info!(
                        bootstrap_peer = %invite.bootstrap_peer,
                        group_id = ?invite.group_id,
                        "Connecting to bootstrap peer to join group"
                    );

                    // Clone for async move
                    let bootstrap_peer = invite.bootstrap_peer.clone();
                    let sessions_clone = sessions.clone();
                    let tor_config_clone = tor_config.clone();

                    tokio::spawn(async move {
                        match Self::send_group_join_request(
                            &bootstrap_peer,
                            &join_request,
                            &sessions_clone,
                            &tor_config_clone,
                        ).await {
                            Ok(_) => {
                                info!(
                                    bootstrap_peer = %bootstrap_peer,
                                    "Join request sent successfully"
                                );
                            }
                            Err(e) => {
                                warn!(
                                    bootstrap_peer = %bootstrap_peer,
                                    error = %e,
                                    "Failed to send join request"
                                );
                            }
                        }
                    });
                }
                DaemonCommand::SendGroupMessage { group_id, content } => {
                    let send_result = {
                        let mut groups = group_sessions.write().await;
                        if let Some(session) = groups.get_mut(&group_id) {
                            match session.send_message(&content) {
                                Ok(payload) => {
                                    // Store message in database
                                    if let Some(last_message) = session.messages.back() {
                                        if let Err(e) = database.lock().await.store_group_message(&group_id, last_message) {
                                            warn!(error = %e, "Failed to persist group message to database");
                                        }
                                    }

                                    // Collect all neighbor addresses before releasing write lock
                                    let neighbor_addrs: Vec<String> = session.mesh.all_neighbors()
                                        .map(|n| n.onion_address.clone())
                                        .collect();
                                    Some((payload, neighbor_addrs))
                                }
                                Err(e) => {
                                    warn!(group_id = ?group_id, error = %e, "Failed to send group message");
                                    None
                                }
                            }
                        } else {
                            warn!(group_id = ?group_id, "Group not found");
                            None
                        }
                    }; // Write lock released here

                    // Forward to all neighbors without holding group_sessions lock
                    if let Some((payload, neighbor_addrs)) = send_result {
                        for addr in &neighbor_addrs {
                            let _ = Self::send_group_message_to_peer(
                                addr,
                                &payload,
                                &sessions,
                                &tor_config,
                            ).await;
                        }
                        info!(group_id = ?group_id, "Group message sent to {} neighbors", neighbor_addrs.len());
                    }
                }
                DaemonCommand::LeaveGroup { group_id } => {
                    let mut groups = group_sessions.write().await;
                    if let Some(session) = groups.get_mut(&group_id) {
                        session.archive();
                        info!(group_id = ?group_id, "Left group");
                    }
                }
                DaemonCommand::RotateGroupKey { group_id } => {
                    let mut groups = group_sessions.write().await;
                    if let Some(session) = groups.get_mut(&group_id) {
                        match session.rotate_epoch_key() {
                            Ok(()) => {
                                let new_epoch = session.current_epoch_number;
                                let _ = event_tx.send(DaemonEvent::GroupKeyRotated {
                                    group_id,
                                    new_epoch,
                                });
                                info!(group_id = ?group_id, epoch = new_epoch, "Rotated group key");
                            }
                            Err(e) => {
                                warn!(group_id = ?group_id, error = %e, "Failed to rotate group key");
                            }
                        }
                    } else {
                        warn!(group_id = ?group_id, "Group not found");
                    }
                }
                DaemonCommand::SendGroupFile { group_id, file_path, filename } => {
                    info!(group_id = ?group_id, filename = %filename, "Sharing file with group");

                    // Compute file hash and size
                    let hash = match crate::messaging::stream_transfer::compute_file_hash(&file_path).await {
                        Ok(h) => h,
                        Err(e) => {
                            warn!(error = %e, "Failed to compute file hash");
                            continue;
                        }
                    };
                    let file_size = match tokio::fs::metadata(&file_path).await {
                        Ok(m) => m.len(),
                        Err(e) => {
                            warn!(error = %e, "Failed to read file metadata");
                            continue;
                        }
                    };

                    // Generate file_id
                    let file_id_bytes: [u8; 16] = crate::crypto::random_bytes();
                    let file_id_hex = hex::encode(file_id_bytes);

                    // Stage file for serving
                    let staged_dir = format!("{}/.torchat/group_uploads",
                        std::env::var("HOME").unwrap_or_else(|_| ".".to_string()));
                    if let Err(e) = tokio::fs::create_dir_all(&staged_dir).await {
                        warn!(error = %e, "Failed to create group uploads directory");
                        continue;
                    }
                    let staged_path = format!("{}/{}_{}", staged_dir, file_id_hex, filename);
                    if let Err(e) = tokio::fs::copy(&file_path, &staged_path).await {
                        warn!(error = %e, "Failed to stage file for serving");
                        continue;
                    }

                    // Register in staged files map
                    {
                        let mut staged = staged_group_files.write().await;
                        staged.insert(file_id_hex.clone(), std::path::PathBuf::from(&staged_path));
                    }

                    // Store in database
                    let sender_onion = identity.onion_address().to_string();
                    let our_member_id = {
                        let groups = group_sessions.read().await;
                        groups.get(&group_id).map(|s| s.our_member_id)
                    };
                    if let Some(member_id) = our_member_id {
                        let db = database.lock().await;
                        if let Err(e) = db.store_group_file(
                            &group_id, &file_id_hex, &filename, file_size,
                            &hash, &member_id, &sender_onion,
                            Some(&staged_path), "available",
                        ) {
                            warn!(error = %e, "Failed to store group file in database");
                        }
                    }

                    // Build [FILE_META] JSON and send as group message
                    let meta_json = serde_json::json!({
                        "file_id": file_id_hex,
                        "filename": filename,
                        "size": file_size,
                        "hash": hex::encode(hash),
                        "sender_onion": sender_onion,
                    });
                    let content = format!("[FILE_META]{}", meta_json);

                    // Send via existing group message path
                    let file_send_result = {
                        let mut groups = group_sessions.write().await;
                        if let Some(session) = groups.get_mut(&group_id) {
                            match session.send_message(&content) {
                                Ok(payload) => {
                                    // Store message in database
                                    if let Some(last_message) = session.messages.back() {
                                        if let Err(e) = database.lock().await.store_group_message(&group_id, last_message) {
                                            warn!(error = %e, "Failed to persist group file message");
                                        }
                                    }
                                    let neighbor_addrs: Vec<String> = session.mesh.all_neighbors()
                                        .map(|n| n.onion_address.clone())
                                        .collect();
                                    Some((payload, neighbor_addrs))
                                }
                                Err(e) => {
                                    warn!(group_id = ?group_id, error = %e, "Failed to send group file announcement");
                                    None
                                }
                            }
                        } else {
                            warn!(group_id = ?group_id, "Group not found for file sharing");
                            None
                        }
                    };

                    if let Some((payload, neighbor_addrs)) = file_send_result {
                        for addr in &neighbor_addrs {
                            let _ = Self::send_group_message_to_peer(
                                addr,
                                &payload,
                                &sessions,
                                &tor_config,
                            ).await;
                        }
                        info!(group_id = ?group_id, file_id = %file_id_hex, "Group file shared to {} neighbors", neighbor_addrs.len());
                    }
                }
                DaemonCommand::DownloadGroupFile { group_id, file_id, sender_onion } => {
                    info!(group_id = ?group_id, file_id = %file_id, sender = %sender_onion, "Downloading group file");

                    // Update status to downloading
                    {
                        let db = database.lock().await;
                        let _ = db.update_group_file_status(&file_id, "downloading", None);
                    }

                    // Spawn download task
                    let tor_config_dl = tor_config.clone();
                    let database_dl = database.clone();
                    let event_tx_dl = event_tx.clone();
                    let file_id_dl = file_id.clone();
                    let staged_files_dl = staged_group_files.clone();

                    tokio::spawn(async move {
                        let download_dir = std::env::var("TORCHAT_DOWNLOAD_DIR")
                            .unwrap_or_else(|_| format!("{}/.torchat/downloads",
                                std::env::var("HOME").unwrap_or_else(|_| ".".to_string())));
                        let _ = tokio::fs::create_dir_all(&download_dir).await;

                        match crate::messaging::stream_transfer::request_file_from_peer(
                            &file_id_dl,
                            &sender_onion,
                            std::path::PathBuf::from(&download_dir),
                            &tor_config_dl,
                        ).await {
                            Ok(result) if result.success => {
                                let output_path = result.output_path
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default();

                                // Update database
                                {
                                    let db = database_dl.lock().await;
                                    let _ = db.update_group_file_status(&file_id_dl, "downloaded", Some(&output_path));
                                }

                                // Also register in staged files so we can serve it to others
                                {
                                    let mut staged = staged_files_dl.write().await;
                                    staged.insert(file_id_dl.clone(), std::path::PathBuf::from(&output_path));
                                }

                                let _ = event_tx_dl.send(DaemonEvent::GroupFileDownloaded {
                                    group_id,
                                    file_id: file_id_dl,
                                    output_path,
                                });
                                info!("Group file downloaded successfully");
                            }
                            Ok(result) => {
                                let error = result.error.unwrap_or_else(|| "Transfer failed".to_string());
                                {
                                    let db = database_dl.lock().await;
                                    let _ = db.update_group_file_status(&file_id_dl, "failed", None);
                                }
                                let _ = event_tx_dl.send(DaemonEvent::GroupFileDownloadFailed {
                                    group_id,
                                    file_id: file_id_dl,
                                    error,
                                });
                            }
                            Err(e) => {
                                {
                                    let db = database_dl.lock().await;
                                    let _ = db.update_group_file_status(&file_id_dl, "failed", None);
                                }
                                let _ = event_tx_dl.send(DaemonEvent::GroupFileDownloadFailed {
                                    group_id,
                                    file_id: file_id_dl,
                                    error: e.to_string(),
                                });
                                warn!(error = %e, "Group file download failed");
                            }
                        }
                    });
                }
                DaemonCommand::PromoteToAdmin { group_id, member_id } => {
                    let our_pubkey = identity.public_key().to_bytes();
                    let mut groups = group_sessions.write().await;
                    if let Some(session) = groups.get_mut(&group_id) {
                        match session.promote_to_admin(&our_pubkey, &member_id) {
                            Ok(()) => {
                                // Persist the admin change to database
                                if let Err(e) = database.lock().await.update_member_admin_status(&group_id, &member_id, true) {
                                    warn!(error = %e, "Failed to persist admin promotion to database");
                                }
                                info!(group_id = ?group_id, member_id = ?member_id, "Promoted member to admin");
                            }
                            Err(e) => {
                                warn!(group_id = ?group_id, member_id = ?member_id, error = %e, "Failed to promote member");
                                let _ = event_tx.send(DaemonEvent::Error {
                                    message: format!("Failed to promote member: {}", e),
                                });
                            }
                        }
                    } else {
                        warn!(group_id = ?group_id, "Group not found for admin promotion");
                    }
                }
            }
        }

        info!("Command loop stopped");
    }

    /// Connect to a peer.
    async fn connect_to_peer(
        address: &str,
        sessions: &Arc<RwLock<HashMap<String, PeerSession>>>,
        tor_config: &TorConnectionConfig,
        identity: &TorIdentity,
    ) -> Result<()> {
        let peer_addr = OnionAddress::from_string(address)
            .map_err(|_| Error::Protocol("Invalid address".into()))?;

        info!(address = %address, "Connecting to peer...");

        // Connect via Tor
        let mut conn = TorConnection::connect(tor_config, &peer_addr).await?;

        // Generate ephemeral key for key exchange
        let our_ephemeral = EphemeralKeypair::generate();
        let our_public = *our_ephemeral.public_key().as_bytes();

        // Send Hello packet
        let hello = ChatHello {
            sender_address: identity.onion_address().to_string(),
            ephemeral_public: our_public,
            identity_public: *identity.public_key().as_bytes(),
            timestamp: chrono::Utc::now().timestamp(),
        };

        let packet = Packet::new(PacketType::Hello, hello.to_bytes()?)?;
        Self::write_packet(conn.stream_mut(), &packet).await?;

        // Wait for SessionInit response
        let response = Self::read_packet(conn.stream_mut()).await?;

        if response.header.packet_type != PacketType::SessionInit {
            return Err(Error::Protocol("Expected SessionInit response".into()));
        }

        let init = ChatHelloResponse::from_bytes(&response.payload)?;

        // Derive shared secret
        let their_public = X25519PublicKey::from(init.ephemeral_public);
        let shared = our_ephemeral.diffie_hellman(&their_public);

        // Initialize ratchet as initiator
        let ratchet = DoubleRatchet::init_initiator_from_bytes(shared.as_bytes(), &their_public)?;

        // Store session
        let mut sessions = sessions.write().await;
        let session = sessions
            .entry(address.to_string())
            .or_insert_with(|| PeerSession::new(peer_addr));

        session.ratchet = Some(ratchet);
        session.shared_secret = Some(*shared.as_bytes());
        session.our_ephemeral = Some(our_ephemeral);
        session.established = true;

        info!(address = %address, "Connected and session established");

        Ok(())
    }

    /// Send a message to a peer.
    ///
    /// Opens a connection, performs handshake if needed, then sends the message
    /// all on the same connection.
    async fn send_message_to_peer(
        address: &str,
        content: &str,
        message_id: [u8; 16],
        sessions: &Arc<RwLock<HashMap<String, PeerSession>>>,
        tor_config: &TorConnectionConfig,
        identity: &TorIdentity,
    ) -> Result<()> {
        let peer_addr = OnionAddress::from_string(address)
            .map_err(|_| Error::Protocol("Invalid address".into()))?;

        info!(address = %address, "Connecting to peer for message delivery...");

        // Open connection to peer
        let mut conn = TorConnection::connect(tor_config, &peer_addr).await?;

        // Check if we need to establish a session
        let need_handshake = {
            let sessions = sessions.read().await;
            match sessions.get(address) {
                Some(s) => !s.established,
                None => true,
            }
        };

        // Perform handshake on this connection if needed
        if need_handshake {
            info!(address = %address, "Performing handshake...");

            // Generate ephemeral key for key exchange
            let our_ephemeral = EphemeralKeypair::generate();
            let our_public = *our_ephemeral.public_key().as_bytes();

            // Send Hello packet
            let hello = ChatHello {
                sender_address: identity.onion_address().to_string(),
                ephemeral_public: our_public,
                identity_public: *identity.public_key().as_bytes(),
                timestamp: chrono::Utc::now().timestamp(),
            };

            let packet = Packet::new(PacketType::Hello, hello.to_bytes()?)?;
            Self::write_packet(conn.stream_mut(), &packet).await?;

            // Wait for SessionInit response
            let response = Self::read_packet(conn.stream_mut()).await?;

            if response.header.packet_type != PacketType::SessionInit {
                return Err(Error::Protocol("Expected SessionInit response".into()));
            }

            let init = ChatHelloResponse::from_bytes(&response.payload)?;

            // Derive shared secret
            let their_public = X25519PublicKey::from(init.ephemeral_public);
            let shared = our_ephemeral.diffie_hellman(&their_public);

            // Initialize ratchet as initiator
            let ratchet = DoubleRatchet::init_initiator_from_bytes(shared.as_bytes(), &their_public)?;

            // Store session
            let mut sessions_guard = sessions.write().await;
            let session = sessions_guard
                .entry(address.to_string())
                .or_insert_with(|| PeerSession::new(peer_addr.clone()));

            session.ratchet = Some(ratchet);
            session.shared_secret = Some(*shared.as_bytes());
            session.our_ephemeral = Some(our_ephemeral);
            session.established = true;

            info!(address = %address, "Handshake complete, session established");
        }

        // Now encrypt and send the message on the same connection
        let encrypted_payload = {
            let mut sessions_guard = sessions.write().await;
            let session = sessions_guard
                .get_mut(address)
                .ok_or_else(|| Error::NoSession)?;

            let ratchet = session.ratchet.as_mut().ok_or_else(|| Error::NoSession)?;

            // Encrypt message
            let (header, ciphertext) = ratchet.encrypt(content.as_bytes())?;

            MessagePayload {
                header,
                ciphertext,
                message_id,
                timestamp: chrono::Utc::now().timestamp(),
            }
        };

        // Send the encrypted message
        let packet = Packet::new(PacketType::Message, encrypted_payload.to_bytes()?)?;
        Self::write_packet(conn.stream_mut(), &packet).await?;

        info!(to = %address, "Message sent, waiting for ACK...");

        // Wait for delivery ACK (with timeout)
        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            Self::read_packet(conn.stream_mut())
        ).await {
            Ok(Ok(ack_packet)) => {
                if ack_packet.header.packet_type == PacketType::Ack {
                    let ack = AckPayload::from_bytes(&ack_packet.payload)?;
                    if ack.message_id == message_id {
                        info!(to = %address, "Received delivery ACK");
                    }
                }
            }
            Ok(Err(e)) => {
                warn!(to = %address, error = %e, "Error reading ACK");
            }
            Err(_) => {
                warn!(to = %address, "Timeout waiting for ACK");
            }
        }

        info!(to = %address, "Message sent successfully");

        Ok(())
    }

    /// Send an acknowledgment to a peer.
    async fn send_ack_to_peer(
        address: &str,
        message_id: [u8; 16],
        ack_type: AckType,
        tor_config: &TorConnectionConfig,
    ) -> Result<()> {
        let peer_addr = OnionAddress::from_string(address)
            .map_err(|_| Error::Protocol("Invalid address".into()))?;

        let ack = AckPayload {
            message_id,
            ack_type,
            timestamp: chrono::Utc::now().timestamp(),
        };

        let mut conn = TorConnection::connect(tor_config, &peer_addr).await?;
        let packet = Packet::new(PacketType::Ack, ack.to_bytes()?)?;
        Self::write_packet(conn.stream_mut(), &packet).await?;

        Ok(())
    }

    /// Send a file offer (metadata) to a peer.
    async fn send_file_offer_to_peer(
        address: &str,
        transfer_id: [u8; 16],
        filename: &str,
        size: u64,
        hash: [u8; 32],
        total_chunks: u32,
        sessions: &Arc<RwLock<HashMap<String, PeerSession>>>,
        tor_config: &TorConnectionConfig,
        identity: &TorIdentity,
    ) -> Result<()> {
        let peer_addr = OnionAddress::from_string(address)
            .map_err(|_| Error::Protocol("Invalid address".into()))?;

        // Open connection to peer
        let mut conn = TorConnection::connect(tor_config, &peer_addr).await?;

        // Check if we need to establish a session
        let need_handshake = {
            let sessions = sessions.read().await;
            match sessions.get(address) {
                Some(s) => !s.established,
                None => true,
            }
        };

        // Perform handshake if needed
        if need_handshake {
            info!(address = %address, "Performing handshake for file offer...");

            let our_ephemeral = EphemeralKeypair::generate();
            let our_public = *our_ephemeral.public_key().as_bytes();

            let hello = ChatHello {
                sender_address: identity.onion_address().to_string(),
                ephemeral_public: our_public,
                identity_public: *identity.public_key().as_bytes(),
                timestamp: chrono::Utc::now().timestamp(),
            };

            let packet = Packet::new(PacketType::Hello, hello.to_bytes()?)?;
            Self::write_packet(conn.stream_mut(), &packet).await?;

            let response = Self::read_packet(conn.stream_mut()).await?;

            if response.header.packet_type != PacketType::SessionInit {
                return Err(Error::Protocol("Expected SessionInit response".into()));
            }

            let init = ChatHelloResponse::from_bytes(&response.payload)?;
            let their_public = X25519PublicKey::from(init.ephemeral_public);
            let shared = our_ephemeral.diffie_hellman(&their_public);
            let ratchet = DoubleRatchet::init_initiator_from_bytes(shared.as_bytes(), &their_public)?;

            let mut sessions_guard = sessions.write().await;
            let session = sessions_guard
                .entry(address.to_string())
                .or_insert_with(|| PeerSession::new(peer_addr.clone()));

            session.ratchet = Some(ratchet);
            session.shared_secret = Some(*shared.as_bytes());
            session.our_ephemeral = Some(our_ephemeral);
            session.established = true;

            info!(address = %address, "Handshake complete for file offer");
        }

        // Encrypt metadata and send file offer
        let encrypted_payload = {
            let mut sessions_guard = sessions.write().await;
            let session = sessions_guard
                .get_mut(address)
                .ok_or_else(|| Error::NoSession)?;

            let ratchet = session.ratchet.as_mut().ok_or_else(|| Error::NoSession)?;

            // Encrypt a simple marker (metadata is in the packet itself)
            let (header, ciphertext) = ratchet.encrypt(b"file_offer")?;

            FileOfferPayload {
                transfer_id,
                filename: filename.to_string(),
                size,
                hash,
                total_chunks,
                header,
                ciphertext,
            }
        };

        let packet = Packet::new(PacketType::FileOffer, encrypted_payload.to_bytes()?)?;
        Self::write_packet(conn.stream_mut(), &packet).await?;

        info!(to = %address, filename = %filename, size = size, "File offer sent");

        Ok(())
    }

    /// Send a file chunk to a peer.
    async fn send_file_chunk_to_peer(
        address: &str,
        transfer_id: [u8; 16],
        chunk_index: u32,
        total_chunks: u32,
        chunk_data: &[u8],
        sessions: &Arc<RwLock<HashMap<String, PeerSession>>>,
        tor_config: &TorConnectionConfig,
        identity: &TorIdentity,
    ) -> Result<()> {
        let peer_addr = OnionAddress::from_string(address)
            .map_err(|_| Error::Protocol("Invalid address".into()))?;

        // Open connection to peer
        let mut conn = TorConnection::connect(tor_config, &peer_addr).await?;

        // Check if we need to establish a session
        let need_handshake = {
            let sessions = sessions.read().await;
            match sessions.get(address) {
                Some(s) => !s.established,
                None => true,
            }
        };

        // Perform handshake on this connection if needed
        if need_handshake {
            info!(address = %address, "Performing handshake for file transfer...");

            // Generate ephemeral key for key exchange
            let our_ephemeral = EphemeralKeypair::generate();
            let our_public = *our_ephemeral.public_key().as_bytes();

            // Send Hello packet
            let hello = ChatHello {
                sender_address: identity.onion_address().to_string(),
                ephemeral_public: our_public,
                identity_public: *identity.public_key().as_bytes(),
                timestamp: chrono::Utc::now().timestamp(),
            };

            let packet = Packet::new(PacketType::Hello, hello.to_bytes()?)?;
            Self::write_packet(conn.stream_mut(), &packet).await?;

            // Wait for SessionInit response
            let response = Self::read_packet(conn.stream_mut()).await?;

            if response.header.packet_type != PacketType::SessionInit {
                return Err(Error::Protocol("Expected SessionInit response".into()));
            }

            let init = ChatHelloResponse::from_bytes(&response.payload)?;

            // Derive shared secret
            let their_public = X25519PublicKey::from(init.ephemeral_public);
            let shared = our_ephemeral.diffie_hellman(&their_public);

            // Initialize ratchet as initiator
            let ratchet = DoubleRatchet::init_initiator_from_bytes(shared.as_bytes(), &their_public)?;

            // Store session
            let mut sessions_guard = sessions.write().await;
            let session = sessions_guard
                .entry(address.to_string())
                .or_insert_with(|| PeerSession::new(peer_addr.clone()));

            session.ratchet = Some(ratchet);
            session.shared_secret = Some(*shared.as_bytes());
            session.our_ephemeral = Some(our_ephemeral);
            session.established = true;

            info!(address = %address, "Handshake complete for file transfer");
        }

        // Now encrypt and send the file chunk
        let encrypted_payload = {
            let mut sessions_guard = sessions.write().await;
            let session = sessions_guard
                .get_mut(address)
                .ok_or_else(|| Error::NoSession)?;

            let ratchet = session.ratchet.as_mut().ok_or_else(|| Error::NoSession)?;
            let (header, ciphertext) = ratchet.encrypt(chunk_data)?;

            FileChunkPayload {
                transfer_id,
                chunk_index,
                total_chunks,
                header,
                ciphertext,
            }
        };

        let packet = Packet::new(PacketType::FileChunk, encrypted_payload.to_bytes()?)?;
        Self::write_packet(conn.stream_mut(), &packet).await?;

        debug!(to = %address, chunk = chunk_index, total = total_chunks, "File chunk sent");

        Ok(())
    }

    /// Send a call signal to a peer.
    async fn send_call_signal_to_peer(
        address: &str,
        call_id: [u8; 16],
        signal_type: CallSignalType,
        signal_data: &[u8],
        sessions: &Arc<RwLock<HashMap<String, PeerSession>>>,
        tor_config: &TorConnectionConfig,
        identity: &TorIdentity,
    ) -> Result<()> {
        let peer_addr = OnionAddress::from_string(address)
            .map_err(|_| Error::Protocol("Invalid address".into()))?;

        // Open connection to peer
        let mut conn = TorConnection::connect(tor_config, &peer_addr).await?;

        // Check if we need to establish a session
        let need_handshake = {
            let sessions = sessions.read().await;
            match sessions.get(address) {
                Some(s) => !s.established,
                None => true,
            }
        };

        // Perform handshake on this connection if needed
        if need_handshake {
            info!(address = %address, "Performing handshake for call...");

            // Generate ephemeral key for key exchange
            let our_ephemeral = EphemeralKeypair::generate();
            let our_public = *our_ephemeral.public_key().as_bytes();

            // Send Hello packet
            let hello = ChatHello {
                sender_address: identity.onion_address().to_string(),
                ephemeral_public: our_public,
                identity_public: *identity.public_key().as_bytes(),
                timestamp: chrono::Utc::now().timestamp(),
            };

            let packet = Packet::new(PacketType::Hello, hello.to_bytes()?)?;
            Self::write_packet(conn.stream_mut(), &packet).await?;

            // Wait for SessionInit response
            let response = Self::read_packet(conn.stream_mut()).await?;

            if response.header.packet_type != PacketType::SessionInit {
                return Err(Error::Protocol("Expected SessionInit response".into()));
            }

            let init = ChatHelloResponse::from_bytes(&response.payload)?;

            // Derive shared secret
            let their_public = X25519PublicKey::from(init.ephemeral_public);
            let shared = our_ephemeral.diffie_hellman(&their_public);

            // Initialize ratchet as initiator
            let ratchet = DoubleRatchet::init_initiator_from_bytes(shared.as_bytes(), &their_public)?;

            // Store session
            let mut sessions_guard = sessions.write().await;
            let session = sessions_guard
                .entry(address.to_string())
                .or_insert_with(|| PeerSession::new(peer_addr.clone()));

            session.ratchet = Some(ratchet);
            session.shared_secret = Some(*shared.as_bytes());
            session.our_ephemeral = Some(our_ephemeral);
            session.established = true;

            info!(address = %address, "Handshake complete for call");
        }

        // Now encrypt and send the call signal
        let encrypted_payload = {
            let mut sessions_guard = sessions.write().await;
            let session = sessions_guard
                .get_mut(address)
                .ok_or_else(|| Error::NoSession)?;

            let ratchet = session.ratchet.as_mut().ok_or_else(|| Error::NoSession)?;
            let (header, ciphertext) = ratchet.encrypt(signal_data)?;

            CallSignalPayload {
                call_id,
                signal_type,
                header,
                ciphertext,
            }
        };

        let packet = Packet::new(PacketType::CallSignal, encrypted_payload.to_bytes()?)?;
        Self::write_packet(conn.stream_mut(), &packet).await?;

        info!(to = %address, signal = ?signal_type, "Call signal sent");

        Ok(())
    }

    /// Send a group message packet to a peer.
    async fn send_group_message_to_peer(
        address: &str,
        payload: &crate::protocol::GroupMessagePayload,
        _sessions: &Arc<RwLock<HashMap<String, PeerSession>>>,
        tor_config: &TorConnectionConfig,
    ) -> Result<()> {
        let peer_addr = OnionAddress::from_string(address)
            .map_err(|_| Error::Protocol("Invalid address".into()))?;

        // Open connection to peer
        let mut conn = TorConnection::connect(tor_config, &peer_addr).await?;

        // Create and send packet
        let packet = Packet::new(PacketType::GroupMessage, payload.to_bytes()?)?;
        Self::write_packet(conn.stream_mut(), &packet).await?;

        debug!(to = %address, msg_id = ?payload.msg_id, "Group message forwarded");

        Ok(())
    }

    /// Send group join request to bootstrap peer.
    async fn send_group_join_request(
        address: &str,
        payload: &crate::protocol::GroupJoinRequestPayload,
        _sessions: &Arc<RwLock<HashMap<String, PeerSession>>>,
        tor_config: &TorConnectionConfig,
    ) -> Result<()> {
        let peer_addr = OnionAddress::from_string(address)
            .map_err(|_| Error::Protocol("Invalid address".into()))?;

        // Open connection to bootstrap peer
        let mut conn = TorConnection::connect(tor_config, &peer_addr).await?;

        // Create and send join request packet
        let packet = Packet::new(PacketType::GroupJoinRequest, payload.to_bytes()?)?;
        Self::write_packet(conn.stream_mut(), &packet).await?;

        info!(to = %address, group_id = ?payload.group_id, "Join request sent to bootstrap peer");

        // Note: Connection stays open to receive join accept response
        // The accept will be handled by handle_group_join_accept_packet

        Ok(())
    }

    /// Handle group message packet.
    async fn handle_group_message_packet(
        packet: &Packet,
        event_tx: &broadcast::Sender<DaemonEvent>,
        group_sessions: &Arc<RwLock<HashMap<[u8; 32], crate::messaging::group_session::GroupSession>>>,
        database: &Arc<TokioMutex<Database>>,
        sessions: &Arc<RwLock<HashMap<String, PeerSession>>>,
        tor_config: &TorConnectionConfig,
    ) -> Result<()> {
        let payload = crate::protocol::GroupMessagePayload::from_bytes(&packet.payload)?;

        debug!(
            group_id = ?payload.group_id,
            msg_id = ?payload.msg_id,
            hop_count = payload.hop_count,
            "Received group message"
        );

        // Process message and collect relay info while holding the lock
        let process_result = {
            let mut groups = group_sessions.write().await;
            if let Some(session) = groups.get_mut(&payload.group_id) {
                let group_id = payload.group_id;
                match session.receive_message(&payload) {
                    Ok(Some(received)) => {
                        // Prepare gossip relay - forward to all neighbors
                        let forward_payload = session.gossip.prepare_for_forward(payload.clone());
                        let neighbor_addrs: Vec<String> = session.mesh.all_neighbors()
                            .map(|n| n.onion_address.clone())
                            .collect();
                        Some((group_id, received, forward_payload, neighbor_addrs))
                    }
                    Ok(None) => {
                        debug!(
                            group_id = ?payload.group_id,
                            msg_id = ?payload.msg_id,
                            "Duplicate group message (already seen)"
                        );
                        None
                    }
                    Err(e) => {
                        warn!(
                            group_id = ?payload.group_id,
                            error = %e,
                            "Failed to process group message"
                        );
                        None
                    }
                }
            } else {
                debug!(
                    group_id = ?payload.group_id,
                    "Received message for unknown group"
                );
                None
            }
        }; // Write lock released here

        // Process the received message outside the lock
        if let Some((group_id, received, forward_payload, neighbor_addrs)) = process_result {
            // Store received message in database
            {
                let received_msg = crate::messaging::group_session::GroupMessage {
                    id: received.msg_id,
                    sender_id: received.sender_id,
                    content: received.content.clone(),
                    timestamp: received.timestamp,
                    outgoing: false,
                };
                let db = database.lock().await;
                if let Err(e) = db.store_group_message(&group_id, &received_msg) {
                    warn!(error = %e, "Failed to persist received group message to database");
                }
            }

            // Check if this is a file metadata message
            if received.content.starts_with("[FILE_META]") {
                let json_str = &received.content["[FILE_META]".len()..];
                if let Ok(meta) = serde_json::from_str::<serde_json::Value>(json_str) {
                    let file_id = meta["file_id"].as_str().unwrap_or_default().to_string();
                    let filename = meta["filename"].as_str().unwrap_or_default().to_string();
                    let size = meta["size"].as_u64().unwrap_or(0);
                    let hash_hex = meta["hash"].as_str().unwrap_or_default();
                    let sender_onion = meta["sender_onion"].as_str().unwrap_or_default().to_string();

                    let mut file_hash = [0u8; 32];
                    if let Ok(bytes) = hex::decode(hash_hex) {
                        if bytes.len() == 32 {
                            file_hash.copy_from_slice(&bytes);
                        }
                    }

                    // Store file metadata in database
                    {
                        let db = database.lock().await;
                        if let Err(e) = db.store_group_file(
                            &group_id, &file_id, &filename, size,
                            &file_hash, &received.sender_id, &sender_onion,
                            None, "available",
                        ) {
                            warn!(error = %e, "Failed to store group file metadata");
                        }
                    }

                    // Emit file shared event
                    let _ = event_tx.send(DaemonEvent::GroupFileShared {
                        group_id,
                        file_id: file_id.clone(),
                        filename: filename.clone(),
                        size,
                        sender_onion,
                    });

                    info!(
                        group_id = ?group_id,
                        file_id = %file_id,
                        filename = %filename,
                        "Group file metadata received"
                    );
                }
            }

            // Always emit GroupMessageReceived so message appears in chat
            let _ = event_tx.send(DaemonEvent::GroupMessageReceived {
                group_id,
                sender_id: received.sender_id,
                content: received.content,
                timestamp: received.timestamp,
            });

            // Gossip relay: forward to other neighbors
            if let Some(fwd_payload) = forward_payload {
                for addr in &neighbor_addrs {
                    let _ = Self::send_group_message_to_peer(
                        addr,
                        &fwd_payload,
                        sessions,
                        tor_config,
                    ).await;
                }
                debug!(group_id = ?group_id, "Relayed group message to {} neighbors", neighbor_addrs.len());
            }

            info!(
                group_id = ?group_id,
                msg_id = ?received.msg_id,
                "New group message received and processed"
            );
        }

        Ok(())
    }

    /// Handle group join request packet (received by bootstrap peer/founder).
    async fn handle_group_join_request_packet(
        packet: &Packet,
        event_tx: &broadcast::Sender<DaemonEvent>,
        group_sessions: &Arc<RwLock<HashMap<[u8; 32], crate::messaging::group_session::GroupSession>>>,
        identity: &TorIdentity,
        tor_config: &TorConnectionConfig,
        database: &Arc<TokioMutex<Database>>,
    ) -> Result<()> {
        let payload = crate::protocol::GroupJoinRequestPayload::from_bytes(&packet.payload)?;

        debug!(
            group_id = ?payload.group_id,
            invite_id = ?payload.invite_token.invite_id,
            "Received group join request"
        );

        // Look up group session (write lock so we can add the new member)
        let mut groups = group_sessions.write().await;
        if let Some(session) = groups.get_mut(&payload.group_id) {
            // Convert inviter pubkey to VerifyingKey
            let inviter_key = ed25519_dalek::VerifyingKey::from_bytes(&payload.invite_token.inviter_pubkey)
                .map_err(|_| Error::Crypto("Invalid inviter public key".into()))?;

            // Verify invite signature
            match crate::crypto::verify_invite_token(
                &inviter_key,
                &payload.group_id,
                &payload.invite_token.inviter_pubkey,
                &identity.onion_address().to_string(),
                payload.invite_token.expires_at,
                &payload.invite_token.invite_id,
                &payload.invite_token.invite_signature,
            ) {
                Ok(_) => {
                    // Check expiration
                    let now = chrono::Utc::now().timestamp();
                    if now > payload.invite_token.expires_at {
                        warn!(
                            group_id = ?payload.group_id,
                            "Join request with expired invite"
                        );
                        return Ok(());
                    }

                    // Collect member list and neighbors
                    let member_list: Vec<_> = session.members.values().cloned().collect();
                    let neighbor_list: Vec<_> = session.mesh.all_neighbors()
                        .map(|n| n.onion_address.clone())
                        .take(3)
                        .collect();

                    // Create encrypted metadata (group name + policy)
                    let metadata = bincode::serialize(&(session.name.clone(), session.policy.clone()))
                        .map_err(|e| Error::Encoding(e.to_string()))?;

                    // Encrypt epoch key for the joining member
                    let encrypted_epoch_key = crate::crypto::encrypt_epoch_key_for_member(
                        session.current_epoch_key(),
                        &payload.requester_x25519_pubkey,
                    )?;

                    // Sign the accept payload
                    let mut message_to_sign = Vec::new();
                    message_to_sign.extend_from_slice(&payload.group_id);
                    message_to_sign.extend_from_slice(payload.requester_onion.as_bytes());
                    let acceptor_signature = identity.signing_key().sign(&message_to_sign);

                    // Create join accept payload
                    let accept = crate::protocol::GroupJoinAcceptPayload {
                        group_id: payload.group_id,
                        member_onion: payload.requester_onion.clone(),
                        current_epoch_key: encrypted_epoch_key,
                        epoch_number: session.current_epoch_number,
                        member_list: Some(member_list),
                        neighbor_list,
                        encrypted_metadata: metadata,
                        acceptor_signature: acceptor_signature.to_bytes(),
                    };

                    // Add the new member to our session and database
                    let new_member_id = crate::crypto::generate_member_id(
                        &payload.group_id,
                        &payload.requester_pubkey,
                    );
                    let new_member = crate::protocol::GroupMember {
                        member_id: new_member_id,
                        onion_address: Some(payload.requester_onion.clone()),
                        pubkey: payload.requester_pubkey,
                        is_admin: false,
                        joined_at: now,
                    };

                    // Add to in-memory session (members + mesh)
                    session.add_member(new_member.clone());

                    // Persist new member to database
                    {
                        let db = database.lock().await;
                        if let Err(e) = db.store_group_member(&payload.group_id, &new_member) {
                            warn!(error = %e, "Failed to store new group member in database");
                        }
                    }

                    info!(
                        group_id = ?payload.group_id,
                        joiner = %payload.requester_onion,
                        member_count = session.member_count(),
                        "Accepting join request, added new member"
                    );

                    // Emit event for tracking
                    let _ = event_tx.send(DaemonEvent::GroupJoinAcceptReady {
                        group_id: payload.group_id,
                        joiner_onion: payload.requester_onion.clone(),
                        accept_payload: accept.clone(),
                    });

                    // Send accept packet directly to the joiner
                    let joiner_onion = payload.requester_onion.clone();
                    let tor_config_clone = tor_config.clone();
                    tokio::spawn(async move {
                        let accept_bytes = match accept.to_bytes() {
                            Ok(b) => b,
                            Err(e) => {
                                warn!(error = %e, "Failed to serialize join accept");
                                return;
                            }
                        };
                        let accept_packet = match Packet::new(PacketType::GroupJoinAccept, accept_bytes) {
                            Ok(p) => p,
                            Err(e) => {
                                warn!(error = %e, "Failed to create join accept packet");
                                return;
                            }
                        };
                        let peer_addr = match OnionAddress::from_string(&joiner_onion) {
                            Ok(a) => a,
                            Err(e) => {
                                warn!(error = %e, joiner = %joiner_onion, "Invalid joiner address");
                                return;
                            }
                        };
                        match TorConnection::connect(&tor_config_clone, &peer_addr).await {
                            Ok(mut conn) => {
                                match Self::write_packet(conn.stream_mut(), &accept_packet).await {
                                    Ok(_) => info!(joiner = %joiner_onion, "Sent join accept to joiner"),
                                    Err(e) => warn!(error = %e, joiner = %joiner_onion, "Failed to send join accept"),
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, joiner = %joiner_onion, "Failed to connect to joiner for accept");
                            }
                        }
                    });
                }
                Err(e) => {
                    warn!(
                        group_id = ?payload.group_id,
                        error = %e,
                        "Invalid join request signature"
                    );
                }
            }
        } else {
            debug!(
                group_id = ?payload.group_id,
                "Received join request for unknown group"
            );
        }

        Ok(())
    }

    /// Handle incoming group invite packet.
    async fn handle_group_invite_packet(
        packet: &Packet,
        event_tx: &broadcast::Sender<DaemonEvent>,
    ) -> Result<()> {
        let invite = crate::protocol::GroupInvitePayload::from_bytes(&packet.payload)?;

        info!(
            group_id = ?invite.group_id,
            bootstrap_peer = %invite.bootstrap_peer,
            expires_at = invite.expires_at,
            "Received group invite"
        );

        // Emit event for application layer to handle (show to user)
        let _ = event_tx.send(DaemonEvent::GroupInviteReceived {
            invite,
        });

        Ok(())
    }

    /// Handle group join accept packet (received by joiner).
    async fn handle_group_join_accept_packet(
        packet: &Packet,
        event_tx: &broadcast::Sender<DaemonEvent>,
        group_sessions: &Arc<RwLock<HashMap<[u8; 32], crate::messaging::group_session::GroupSession>>>,
        identity: &TorIdentity,
        database: &Arc<TokioMutex<Database>>,
        _user_id: i64,
        pending_join_invites: &Arc<RwLock<HashMap<[u8; 32], crate::protocol::GroupInvitePayload>>>,
    ) -> Result<()> {
        let payload = crate::protocol::GroupJoinAcceptPayload::from_bytes(&packet.payload)?;

        debug!(
            group_id = ?payload.group_id,
            member_onion = %payload.member_onion,
            epoch = payload.epoch_number,
            "Received group join accept"
        );

        // Look up the original invite we stored when sending the join request
        let invite = {
            let mut invites = pending_join_invites.write().await;
            invites.remove(&payload.group_id)
        };

        let invite = match invite {
            Some(inv) => inv,
            None => {
                warn!(
                    group_id = ?payload.group_id,
                    "Received join accept but no pending invite found"
                );
                // Still emit event for tracking
                let _ = event_tx.send(DaemonEvent::GroupJoinAcceptReceived {
                    group_id: payload.group_id,
                    epoch_number: payload.epoch_number,
                    encrypted_epoch_key: payload.current_epoch_key,
                    member_list: payload.member_list.unwrap_or_default(),
                });
                return Ok(());
            }
        };

        // Create a founder member from the invite's inviter pubkey
        let founder_member_id = crate::crypto::generate_member_id(
            &payload.group_id,
            &invite.inviter_pubkey,
        );
        let founder_member = crate::protocol::GroupMember {
            member_id: founder_member_id,
            onion_address: Some(invite.bootstrap_peer.clone()),
            pubkey: invite.inviter_pubkey,
            is_admin: true,
            joined_at: chrono::Utc::now().timestamp(),
        };

        // Create the group session
        match crate::messaging::group_session::GroupSession::join_via_invite(
            invite,
            identity,
            &payload.current_epoch_key,
            payload.epoch_number,
            founder_member,
        ) {
            Ok(session) => {
                let group_name = session.name.clone();
                let group_id = session.id;

                // Store group in database
                {
                    let db = database.lock().await;
                    if let Err(e) = db.store_group(&session) {
                        warn!(error = %e, "Failed to store joined group in database");
                    }
                    // Store members
                    for member in session.members.values() {
                        if let Err(e) = db.store_group_member(&group_id, member) {
                            warn!(error = %e, "Failed to store group member");
                        }
                    }
                }

                // Add session to active group sessions
                group_sessions.write().await.insert(group_id, session);

                // Emit GroupJoined event
                let _ = event_tx.send(DaemonEvent::GroupJoined {
                    group_id,
                    name: group_name.clone(),
                });

                info!(
                    group_id = ?group_id,
                    name = %group_name,
                    "Successfully joined group"
                );
            }
            Err(e) => {
                warn!(
                    group_id = ?payload.group_id,
                    error = %e,
                    "Failed to create group session from join accept"
                );
                let _ = event_tx.send(DaemonEvent::Error {
                    message: format!("Failed to join group: {}", e),
                });
            }
        }

        Ok(())
    }

    /// Read a packet from a stream.
    async fn read_packet(stream: &mut TcpStream) -> Result<Packet> {
        

        // Read header (6 bytes)
        let mut header_buf = [0u8; 6];
        stream
            .read_exact(&mut header_buf)
            .await
            .map_err(|e| Error::Tor(format!("Read header failed: {}", e)))?;

        let header = PacketHeader::from_bytes(&header_buf)?;

        // Validate payload length
        if header.length as usize > MAX_PACKET_SIZE {
            return Err(Error::Protocol("Packet too large".into()));
        }

        // Read payload
        let mut payload = vec![0u8; header.length as usize];
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|e| Error::Tor(format!("Read payload failed: {}", e)))?;

        Ok(Packet { header, payload })
    }

    /// Write a packet to a stream.
    async fn write_packet(stream: &mut TcpStream, packet: &Packet) -> Result<()> {
        let bytes = packet.to_bytes();
        stream
            .write_all(&bytes)
            .await
            .map_err(|e| Error::Tor(format!("Write failed: {}", e)))?;
        stream
            .flush()
            .await
            .map_err(|e| Error::Tor(format!("Flush failed: {}", e)))?;
        Ok(())
    }

    /// Stop the daemon.
    pub async fn stop(&self) -> Result<()> {
        let _ = self.cmd_tx.send(DaemonCommand::Stop).await;
        Ok(())
    }

    /// Check if daemon is running.
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}
