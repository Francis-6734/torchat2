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
use crate::messaging::file_transfer::{FileMetadata, FileTransferManager, TransferState};

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
const CONNECTION_TIMEOUT_SECS: u64 = 30;

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
    queued_at: Instant,
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
    fn should_retry_connect(&self) -> bool {
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

        // Mark as running
        {
            let mut running = self.running.write().await;
            *running = true;
        }

        // Emit started event
        let _ = self.event_tx.send(DaemonEvent::Started {
            onion_address: onion_addr.clone(),
        });

        // Spawn listener task
        let sessions = self.sessions.clone();
        let event_tx = self.event_tx.clone();
        let running = self.running.clone();
        let identity = self.identity.clone();
        let database = self.database.clone();
        let user_id = self.user_id;

        tokio::spawn(async move {
            Self::listen_loop(service, sessions, event_tx, running, identity, database, user_id).await;
        });

        // Spawn command handler
        let cmd_rx = self.cmd_rx.clone();
        let sessions = self.sessions.clone();
        let event_tx = self.event_tx.clone();
        let running = self.running.clone();
        let tor_config = self.tor_config.clone();
        let identity = self.identity.clone();
        let pending_queue = self.pending_queue.clone();

        tokio::spawn(async move {
            Self::command_loop(cmd_rx, sessions, event_tx, running, tor_config, identity, pending_queue).await;
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

                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_incoming(stream, sessions, event_tx, identity, database, user_id).await
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
    ) -> Result<()> {
        debug!("Handling incoming connection");

        // Read packet
        let packet = Self::read_packet(&mut stream).await?;

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
                Self::handle_connection_loop(stream, peer_addr_str, sessions, event_tx, database, user_id).await?;

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
                                queued_at: Instant::now(),
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
