//! Relay protocol handler for message routing and delivery.
//!
//! Handles the end-to-end message delivery pipeline:
//! - Outgoing message queuing and retry
//! - Incoming message processing
//! - Connection state management
//! - Offline message persistence
//!
//! ## Architecture
//!
//! The relay operates as a background task that:
//! 1. Maintains connections to active peers
//! 2. Queues outgoing messages for delivery
//! 3. Retries failed deliveries with exponential backoff
//! 4. Persists undelivered messages for offline contacts

use crate::crypto::DoubleRatchet;
use crate::error::{Error, Result};
use crate::protocol::{
    AckPayload, AckType, CallSignalPayload, DeletePayload, MessagePayload,
    Packet, PacketType,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
// Duration and Instant available for future use
use tokio::sync::{mpsc, Mutex, RwLock};

/// Maximum retry attempts for message delivery.
pub const MAX_DELIVERY_RETRIES: u32 = 5;

/// Base delay for exponential backoff (seconds).
pub const BACKOFF_BASE_SECS: u64 = 5;

/// Maximum backoff delay (seconds).
pub const BACKOFF_MAX_SECS: u64 = 300;

/// Keepalive interval for active connections (seconds).
#[allow(dead_code)]
pub const KEEPALIVE_INTERVAL_SECS: u64 = 60;

/// Connection timeout (seconds).
#[allow(dead_code)]
pub const CONNECTION_TIMEOUT_SECS: u64 = 30;

/// Message delivery status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    /// Message is queued for delivery.
    Queued,
    /// Currently attempting delivery.
    Sending,
    /// Successfully delivered.
    Delivered,
    /// Delivery failed after all retries.
    Failed,
}

/// A queued outgoing message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedMessage {
    /// Unique message identifier.
    pub id: [u8; 16],
    /// Recipient's onion address.
    pub recipient: String,
    /// Serialized packet data.
    pub packet_data: Vec<u8>,
    /// Packet type.
    pub packet_type: u8,
    /// Current delivery status.
    pub status: DeliveryStatus,
    /// Number of delivery attempts.
    pub attempts: u32,
    /// Timestamp of last attempt.
    pub last_attempt: i64,
    /// Next retry time (Unix timestamp).
    pub next_retry: i64,
    /// Original queue time.
    pub queued_at: i64,
}

/// Connection state for a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected.
    Disconnected,
    /// Attempting to connect.
    Connecting,
    /// Connected and ready.
    Connected,
    /// Connection failed.
    Failed,
}

/// Events emitted by the relay handler.
#[derive(Debug, Clone)]
pub enum RelayEvent {
    /// A message was received.
    MessageReceived {
        /// Sender's address.
        sender: String,
        /// Message identifier.
        message_id: [u8; 16],
        /// Message content.
        content: Vec<u8>,
    },
    /// A message was delivered.
    MessageDelivered {
        /// Message identifier.
        message_id: [u8; 16],
    },
    /// A message delivery failed.
    MessageFailed {
        /// Message identifier.
        message_id: [u8; 16],
        /// Error description.
        error: String,
    },
    /// An acknowledgment was received.
    AckReceived {
        /// Message identifier.
        message_id: [u8; 16],
        /// Acknowledgment type.
        ack_type: AckType,
    },
    /// A call signal was received.
    CallSignalReceived {
        /// Sender's address.
        sender: String,
        /// Call identifier.
        call_id: [u8; 16],
        /// Call signal payload.
        signal: CallSignalPayload,
    },
    /// Connection state changed.
    ConnectionChanged {
        /// Peer address.
        peer: String,
        /// New connection state.
        state: ConnectionState,
    },
}

/// Configuration for the relay handler.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// SOCKS5 proxy address for Tor.
    pub socks_addr: String,
    /// Maximum concurrent connections.
    pub max_connections: usize,
    /// Enable message persistence.
    pub persist_messages: bool,
    /// Path for message queue persistence.
    pub queue_path: Option<String>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            socks_addr: "127.0.0.1:9050".to_string(),
            max_connections: 10,
            persist_messages: true,
            queue_path: None,
        }
    }
}

/// The relay protocol handler.
///
/// Manages all outgoing and incoming message traffic.
pub struct RelayHandler {
    /// Configuration.
    config: RelayConfig,
    /// Outgoing message queue.
    queue: Arc<RwLock<Vec<QueuedMessage>>>,
    /// Peer connection states.
    peer_states: Arc<RwLock<HashMap<String, ConnectionState>>>,
    /// Event sender for relay events.
    event_tx: mpsc::Sender<RelayEvent>,
    /// Shutdown signal.
    shutdown: Arc<Mutex<bool>>,
}

impl RelayHandler {
    /// Create a new relay handler.
    pub fn new(config: RelayConfig) -> (Self, mpsc::Receiver<RelayEvent>) {
        let (event_tx, event_rx) = mpsc::channel(100);

        let handler = Self {
            config,
            queue: Arc::new(RwLock::new(Vec::new())),
            peer_states: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            shutdown: Arc::new(Mutex::new(false)),
        };

        (handler, event_rx)
    }

    /// Queue a message for delivery.
    pub async fn queue_message(
        &self,
        recipient: &str,
        packet_type: PacketType,
        packet_data: Vec<u8>,
    ) -> Result<[u8; 16]> {
        let message_id = crate::crypto::random_bytes::<16>();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let queued = QueuedMessage {
            id: message_id,
            recipient: recipient.to_string(),
            packet_data,
            packet_type: packet_type.to_byte(),
            status: DeliveryStatus::Queued,
            attempts: 0,
            last_attempt: 0,
            next_retry: now,
            queued_at: now,
        };

        let mut queue = self.queue.write().await;
        queue.push(queued);

        // Persist if enabled
        if self.config.persist_messages {
            self.save_queue(&queue).await?;
        }

        Ok(message_id)
    }

    /// Send a text message to a peer.
    pub async fn send_message(
        &self,
        recipient: &str,
        content: &[u8],
        ratchet: &mut DoubleRatchet,
    ) -> Result<[u8; 16]> {
        // Encrypt with Double Ratchet
        let (header, ciphertext) = ratchet.encrypt(content)?;

        let message_id = crate::crypto::random_bytes::<16>();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let payload = MessagePayload {
            header,
            ciphertext,
            message_id,
            timestamp: crate::messaging::add_timestamp_jitter(
                timestamp,
                crate::messaging::DEFAULT_RECEIPT_JITTER,
            ),
        };

        let packet_data = payload.to_bytes()?;
        self.queue_message(recipient, PacketType::Message, packet_data)
            .await
    }

    /// Send an acknowledgment.
    pub async fn send_ack(
        &self,
        recipient: &str,
        message_id: [u8; 16],
        ack_type: AckType,
    ) -> Result<()> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let payload = AckPayload {
            message_id,
            ack_type,
            timestamp: crate::messaging::add_timestamp_jitter(
                timestamp,
                crate::messaging::DEFAULT_RECEIPT_JITTER,
            ),
        };

        let packet_data = payload.to_bytes()?;
        self.queue_message(recipient, PacketType::Ack, packet_data)
            .await?;
        Ok(())
    }

    /// Process an incoming packet.
    pub async fn process_incoming(
        &self,
        sender: &str,
        packet: &Packet,
        ratchet: &mut DoubleRatchet,
    ) -> Result<()> {
        match packet.header.packet_type {
            PacketType::Message => {
                let payload = MessagePayload::from_bytes(&packet.payload)?;
                let plaintext = ratchet.decrypt(&payload.header, &payload.ciphertext)?;

                self.event_tx
                    .send(RelayEvent::MessageReceived {
                        sender: sender.to_string(),
                        message_id: payload.message_id,
                        content: plaintext.to_vec(),
                    })
                    .await
                    .map_err(|_| Error::Protocol("event channel closed".into()))?;

                // Send delivery ack
                self.send_ack(sender, payload.message_id, AckType::Delivered)
                    .await?;
            }

            PacketType::Ack => {
                let payload = AckPayload::from_bytes(&packet.payload)?;
                self.event_tx
                    .send(RelayEvent::AckReceived {
                        message_id: payload.message_id,
                        ack_type: payload.ack_type,
                    })
                    .await
                    .map_err(|_| Error::Protocol("event channel closed".into()))?;

                // Update message status in queue
                self.mark_delivered(&payload.message_id).await;
            }

            PacketType::CallSignal => {
                let payload = CallSignalPayload::from_bytes(&packet.payload)?;
                self.event_tx
                    .send(RelayEvent::CallSignalReceived {
                        sender: sender.to_string(),
                        call_id: payload.call_id,
                        signal: payload,
                    })
                    .await
                    .map_err(|_| Error::Protocol("event channel closed".into()))?;
            }

            PacketType::Delete => {
                let payload = DeletePayload::from_bytes(&packet.payload)?;
                // Verify ownership by decrypting
                let _ = ratchet.decrypt(&payload.header, &payload.ciphertext)?;
                // Forward delete event to application layer
            }

            _ => {
                // Handle other packet types
            }
        }

        Ok(())
    }

    /// Mark a message as delivered.
    async fn mark_delivered(&self, message_id: &[u8; 16]) {
        let mut queue = self.queue.write().await;
        if let Some(msg) = queue.iter_mut().find(|m| &m.id == message_id) {
            msg.status = DeliveryStatus::Delivered;
        }
    }

    /// Get the number of pending messages.
    pub async fn pending_count(&self) -> usize {
        let queue = self.queue.read().await;
        queue
            .iter()
            .filter(|m| m.status == DeliveryStatus::Queued || m.status == DeliveryStatus::Sending)
            .count()
    }

    /// Get the connection state for a peer.
    pub async fn peer_state(&self, address: &str) -> ConnectionState {
        let states = self.peer_states.read().await;
        states
            .get(address)
            .copied()
            .unwrap_or(ConnectionState::Disconnected)
    }

    /// Set the connection state for a peer.
    pub async fn set_peer_state(&self, address: &str, state: ConnectionState) {
        let mut states = self.peer_states.write().await;
        states.insert(address.to_string(), state);

        let _ = self.event_tx
            .send(RelayEvent::ConnectionChanged {
                peer: address.to_string(),
                state,
            })
            .await;
    }

    /// Get all pending messages for a recipient.
    pub async fn get_pending_for(&self, recipient: &str) -> Vec<QueuedMessage> {
        let queue = self.queue.read().await;
        queue
            .iter()
            .filter(|m| m.recipient == recipient && m.status == DeliveryStatus::Queued)
            .cloned()
            .collect()
    }

    /// Mark a message as sent (awaiting ack).
    pub async fn mark_sent(&self, message_id: &[u8; 16]) {
        let mut queue = self.queue.write().await;
        if let Some(msg) = queue.iter_mut().find(|m| &m.id == message_id) {
            msg.status = DeliveryStatus::Sending;
            msg.attempts += 1;
            msg.last_attempt = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
        }
    }

    /// Mark a message as failed and schedule retry.
    pub async fn mark_retry(&self, message_id: &[u8; 16]) {
        let mut queue = self.queue.write().await;
        if let Some(msg) = queue.iter_mut().find(|m| &m.id == message_id) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);

            if msg.attempts >= MAX_DELIVERY_RETRIES {
                msg.status = DeliveryStatus::Failed;
            } else {
                let backoff = std::cmp::min(
                    BACKOFF_BASE_SECS * (1 << msg.attempts),
                    BACKOFF_MAX_SECS,
                );
                msg.next_retry = now + backoff as i64;
                msg.status = DeliveryStatus::Queued;
            }
        }
    }

    /// Shutdown the relay handler.
    pub async fn shutdown(&self) {
        let mut shutdown = self.shutdown.lock().await;
        *shutdown = true;

        // Persist queue before shutdown
        if self.config.persist_messages {
            let queue = self.queue.read().await;
            let _ = self.save_queue(&queue).await;
        }
    }

    /// Save queue to persistence.
    async fn save_queue(&self, queue: &[QueuedMessage]) -> Result<()> {
        if let Some(path) = &self.config.queue_path {
            let data = bincode::serialize(&queue)
                .map_err(|e| Error::Storage(e.to_string()))?;
            tokio::fs::write(path, data).await?;
        }
        Ok(())
    }

    /// Load queue from persistence.
    pub async fn load_queue(&self) -> Result<()> {
        if let Some(path) = &self.config.queue_path {
            let path = std::path::Path::new(path);
            if path.exists() {
                let data = tokio::fs::read(path).await?;
                let messages: Vec<QueuedMessage> = bincode::deserialize(&data)
                    .map_err(|e| Error::Storage(e.to_string()))?;

                let mut queue = self.queue.write().await;
                *queue = messages;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delivery_status() {
        assert_eq!(DeliveryStatus::Queued, DeliveryStatus::Queued);
        assert_ne!(DeliveryStatus::Queued, DeliveryStatus::Delivered);
    }

    #[test]
    fn test_connection_state() {
        assert_eq!(ConnectionState::Disconnected, ConnectionState::Disconnected);
        assert_ne!(ConnectionState::Disconnected, ConnectionState::Connected);
    }

    #[test]
    fn test_backoff_calculation() {
        // Test exponential backoff
        assert_eq!(BACKOFF_BASE_SECS * 2, 10); // 2nd attempt: 5 * 2 = 10
        // At attempt 6: 5 * 64 = 320 which exceeds max of 300
        assert!(BACKOFF_BASE_SECS * (1 << 6) >= BACKOFF_MAX_SECS);
    }
}
