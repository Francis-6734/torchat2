//! File transfer functionality.
//!
//! Handles secure file transfers between peers using chunked delivery.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info};

/// Maximum chunk size (32KB).
pub const MAX_CHUNK_SIZE: usize = 32 * 1024;

/// File metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    /// Original filename.
    pub filename: String,
    /// File size in bytes.
    pub size: u64,
    /// MIME type.
    pub mime_type: String,
    /// SHA-256 hash of file content.
    pub hash: [u8; 32],
}

/// File transfer state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    /// Preparing transfer.
    Pending,
    /// Currently transferring.
    Active,
    /// Transfer completed successfully.
    Completed,
    /// Transfer failed.
    Failed,
    /// Transfer cancelled.
    Cancelled,
}

/// Outgoing file transfer.
pub struct OutgoingTransfer {
    /// Transfer ID.
    pub transfer_id: [u8; 16],
    /// File metadata.
    pub metadata: FileMetadata,
    /// File path.
    pub file_path: PathBuf,
    /// Current state.
    pub state: TransferState,
    /// Chunks sent.
    pub chunks_sent: u32,
    /// Total chunks.
    pub total_chunks: u32,
    /// Bytes sent.
    pub bytes_sent: u64,
}

/// Incoming file transfer.
pub struct IncomingTransfer {
    /// Transfer ID.
    pub transfer_id: [u8; 16],
    /// File metadata.
    pub metadata: FileMetadata,
    /// Output file path.
    pub output_path: PathBuf,
    /// Current state.
    pub state: TransferState,
    /// Received chunks.
    pub received_chunks: HashMap<u32, Vec<u8>>,
    /// Total chunks expected.
    pub total_chunks: u32,
    /// Bytes received.
    pub bytes_received: u64,
}

/// Transfer event.
#[derive(Debug, Clone)]
pub enum TransferEvent {
    /// Transfer started.
    Started {
        /// Unique transfer identifier.
        transfer_id: [u8; 16],
        /// File metadata.
        metadata: FileMetadata,
        /// Peer's onion address.
        peer: String,
    },
    /// Progress update.
    Progress {
        /// Unique transfer identifier.
        transfer_id: [u8; 16],
        /// Bytes transferred so far.
        bytes_transferred: u64,
        /// Total file size in bytes.
        total_bytes: u64,
    },
    /// Transfer completed.
    Completed {
        /// Unique transfer identifier.
        transfer_id: [u8; 16],
        /// Path where file was saved.
        output_path: PathBuf,
    },
    /// Transfer failed.
    Failed {
        /// Unique transfer identifier.
        transfer_id: [u8; 16],
        /// Error description.
        error: String,
    },
}

/// File transfer manager.
pub struct FileTransferManager {
    /// Outgoing transfers.
    outgoing: Arc<RwLock<HashMap<[u8; 16], OutgoingTransfer>>>,
    /// Incoming transfers.
    incoming: Arc<RwLock<HashMap<[u8; 16], IncomingTransfer>>>,
    /// Event channel.
    event_tx: mpsc::Sender<TransferEvent>,
    event_rx: Arc<RwLock<mpsc::Receiver<TransferEvent>>>,
}

impl FileTransferManager {
    /// Create a new file transfer manager.
    pub fn new() -> Self {
        let (event_tx, event_rx) = mpsc::channel(100);

        Self {
            outgoing: Arc::new(RwLock::new(HashMap::new())),
            incoming: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            event_rx: Arc::new(RwLock::new(event_rx)),
        }
    }

    /// Subscribe to transfer events.
    pub fn event_receiver(&self) -> Arc<RwLock<mpsc::Receiver<TransferEvent>>> {
        self.event_rx.clone()
    }

    /// Initiate a file transfer.
    pub async fn send_file(
        &self,
        file_path: PathBuf,
        peer_address: String,
    ) -> Result<([u8; 16], FileMetadata)> {
        // Read file metadata
        let file = File::open(&file_path).await?;
        let metadata_std = file.metadata().await?;

        let size = metadata_std.len();
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();

        // Compute hash
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        let mut file_for_hash = File::open(&file_path).await?;
        let mut buffer = vec![0u8; 8192];
        loop {
            let n = file_for_hash.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        let hash: [u8; 32] = hasher.finalize().into();

        let metadata = FileMetadata {
            filename,
            size,
            mime_type: "application/octet-stream".to_string(), // Could use mime_guess crate
            hash,
        };

        // Generate transfer ID
        let transfer_id = crate::crypto::random_bytes::<16>();

        // Calculate total chunks
        let total_chunks = ((size + MAX_CHUNK_SIZE as u64 - 1) / MAX_CHUNK_SIZE as u64) as u32;

        // Create transfer
        let transfer = OutgoingTransfer {
            transfer_id,
            metadata: metadata.clone(),
            file_path: file_path.clone(),
            state: TransferState::Pending,
            chunks_sent: 0,
            total_chunks,
            bytes_sent: 0,
        };

        let mut outgoing = self.outgoing.write().await;
        outgoing.insert(transfer_id, transfer);

        // Send event
        let _ = self.event_tx.send(TransferEvent::Started {
            transfer_id,
            metadata: metadata.clone(),
            peer: peer_address,
        }).await;

        info!(
            transfer_id = ?transfer_id,
            filename = %metadata.filename,
            size = metadata.size,
            "File transfer initiated"
        );

        Ok((transfer_id, metadata))
    }

    /// Receive an incoming file transfer notification.
    pub async fn receive_file(
        &self,
        transfer_id: [u8; 16],
        metadata: FileMetadata,
        output_dir: PathBuf,
        peer_address: String,
    ) -> Result<PathBuf> {
        // Create output path
        let output_path = output_dir.join(&metadata.filename);

        // Calculate total chunks
        let total_chunks =
            ((metadata.size + MAX_CHUNK_SIZE as u64 - 1) / MAX_CHUNK_SIZE as u64) as u32;

        let transfer = IncomingTransfer {
            transfer_id,
            metadata: metadata.clone(),
            output_path: output_path.clone(),
            state: TransferState::Pending,
            received_chunks: HashMap::new(),
            total_chunks,
            bytes_received: 0,
        };

        let mut incoming = self.incoming.write().await;
        incoming.insert(transfer_id, transfer);

        // Send event
        let _ = self.event_tx.send(TransferEvent::Started {
            transfer_id,
            metadata,
            peer: peer_address,
        }).await;

        Ok(output_path)
    }

    /// Get chunk data for an outgoing transfer.
    pub async fn get_chunk(
        &self,
        transfer_id: &[u8; 16],
        chunk_index: u32,
    ) -> Result<Vec<u8>> {
        let outgoing = self.outgoing.read().await;
        let transfer = outgoing
            .get(transfer_id)
            .ok_or_else(|| Error::NotFound("Transfer not found".into()))?;

        let mut file = File::open(&transfer.file_path).await?;

        // Seek to chunk position
        let offset = (chunk_index as u64) * (MAX_CHUNK_SIZE as u64);
        file.seek(std::io::SeekFrom::Start(offset)).await?;

        // Read chunk
        let mut chunk = vec![0u8; MAX_CHUNK_SIZE];
        let n = file.read(&mut chunk).await?;
        chunk.truncate(n);

        Ok(chunk)
    }

    /// Process an incoming chunk.
    pub async fn process_chunk(
        &self,
        transfer_id: &[u8; 16],
        chunk_index: u32,
        chunk_data: Vec<u8>,
    ) -> Result<()> {
        let mut incoming = self.incoming.write().await;
        let transfer = incoming
            .get_mut(transfer_id)
            .ok_or_else(|| Error::NotFound("Transfer not found".into()))?;

        // Store chunk
        transfer.received_chunks.insert(chunk_index, chunk_data.clone());
        transfer.bytes_received += chunk_data.len() as u64;

        // Update state
        if transfer.state == TransferState::Pending {
            transfer.state = TransferState::Active;
        }

        // Send progress event
        let _ = self.event_tx.send(TransferEvent::Progress {
            transfer_id: *transfer_id,
            bytes_transferred: transfer.bytes_received,
            total_bytes: transfer.metadata.size,
        }).await;

        debug!(
            transfer_id = ?transfer_id,
            chunk = chunk_index,
            total = transfer.total_chunks,
            "Chunk received"
        );

        // Check if complete
        if transfer.received_chunks.len() as u32 == transfer.total_chunks {
            self.finalize_transfer(transfer_id).await?;
        }

        Ok(())
    }

    /// Finalize an incoming transfer.
    async fn finalize_transfer(&self, transfer_id: &[u8; 16]) -> Result<()> {
        // First, collect all data we need while holding the read lock
        let (output_path, _total_chunks, expected_hash, chunks_data) = {
            let incoming = self.incoming.read().await;
            let transfer = incoming
                .get(transfer_id)
                .ok_or_else(|| Error::NotFound("Transfer not found".into()))?;

            let chunks: Vec<Vec<u8>> = (0..transfer.total_chunks)
                .map(|i| {
                    transfer.received_chunks.get(&i)
                        .cloned()
                        .ok_or_else(|| Error::Protocol(format!("Missing chunk {}", i)))
                })
                .collect::<Result<Vec<_>>>()?;

            (
                transfer.output_path.clone(),
                transfer.total_chunks,
                transfer.metadata.hash,
                chunks,
            )
        };

        // Now we can do file I/O without holding the lock
        let mut output_file = File::create(&output_path).await?;

        for chunk in &chunks_data {
            output_file.write_all(chunk).await?;
        }

        output_file.flush().await?;

        // Verify hash
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        let mut verify_file = File::open(&output_path).await?;
        let mut buffer = vec![0u8; 8192];
        loop {
            let n = verify_file.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        let computed_hash: [u8; 32] = hasher.finalize().into();

        if computed_hash != expected_hash {
            return Err(Error::Protocol("File hash mismatch".into()));
        }

        // Update state
        let mut incoming = self.incoming.write().await;
        if let Some(transfer) = incoming.get_mut(transfer_id) {
            transfer.state = TransferState::Completed;
        }

        info!(
            transfer_id = ?transfer_id,
            path = ?output_path,
            "File transfer completed"
        );

        // Send completion event
        let _ = self.event_tx.send(TransferEvent::Completed {
            transfer_id: *transfer_id,
            output_path,
        }).await;

        Ok(())
    }

    /// Mark an outgoing transfer chunk as sent.
    pub async fn mark_chunk_sent(&self, transfer_id: &[u8; 16], chunk_index: u32) -> Result<()> {
        let mut outgoing = self.outgoing.write().await;
        let transfer = outgoing
            .get_mut(transfer_id)
            .ok_or_else(|| Error::NotFound("Transfer not found".into()))?;

        transfer.chunks_sent = transfer.chunks_sent.max(chunk_index + 1);

        // Update state
        if transfer.state == TransferState::Pending {
            transfer.state = TransferState::Active;
        }

        // Send progress event
        let bytes_sent = (chunk_index as u64 + 1) * (MAX_CHUNK_SIZE as u64);
        let bytes_sent = bytes_sent.min(transfer.metadata.size);
        transfer.bytes_sent = bytes_sent;

        let _ = self.event_tx.send(TransferEvent::Progress {
            transfer_id: *transfer_id,
            bytes_transferred: bytes_sent,
            total_bytes: transfer.metadata.size,
        }).await;

        // Check if complete
        if transfer.chunks_sent == transfer.total_chunks {
            transfer.state = TransferState::Completed;

            info!(
                transfer_id = ?transfer_id,
                "Outgoing file transfer completed"
            );
        }

        Ok(())
    }

    /// Cancel a transfer.
    pub async fn cancel_transfer(&self, transfer_id: &[u8; 16]) -> Result<()> {
        let mut outgoing = self.outgoing.write().await;
        if let Some(transfer) = outgoing.get_mut(transfer_id) {
            transfer.state = TransferState::Cancelled;
            return Ok(());
        }

        let mut incoming = self.incoming.write().await;
        if let Some(transfer) = incoming.get_mut(transfer_id) {
            transfer.state = TransferState::Cancelled;
            return Ok(());
        }

        Err(Error::NotFound("Transfer not found".into()))
    }

    /// Get transfer status.
    pub async fn get_transfer_status(
        &self,
        transfer_id: &[u8; 16],
    ) -> Result<(TransferState, u64, u64)> {
        let outgoing = self.outgoing.read().await;
        if let Some(transfer) = outgoing.get(transfer_id) {
            return Ok((
                transfer.state,
                transfer.bytes_sent,
                transfer.metadata.size,
            ));
        }

        let incoming = self.incoming.read().await;
        if let Some(transfer) = incoming.get(transfer_id) {
            return Ok((
                transfer.state,
                transfer.bytes_received,
                transfer.metadata.size,
            ));
        }

        Err(Error::NotFound("Transfer not found".into()))
    }

    /// Get outgoing transfer status with full details.
    /// Returns (filename, size, state, progress_percentage)
    pub async fn get_outgoing_status(
        &self,
        transfer_id: &[u8; 16],
    ) -> Option<(String, u64, TransferState, f64)> {
        let outgoing = self.outgoing.read().await;
        outgoing.get(transfer_id).map(|transfer| {
            let progress = if transfer.metadata.size > 0 {
                (transfer.bytes_sent as f64 / transfer.metadata.size as f64) * 100.0
            } else {
                100.0
            };
            (
                transfer.metadata.filename.clone(),
                transfer.metadata.size,
                transfer.state,
                progress,
            )
        })
    }
}

impl Default for FileTransferManager {
    fn default() -> Self {
        Self::new()
    }
}
