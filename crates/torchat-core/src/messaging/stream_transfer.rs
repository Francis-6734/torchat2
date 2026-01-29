//! TCP Stream-based file transfer over Tor.
//!
//! Uses persistent TCP connections for reliable bidirectional file transfer.

use crate::error::{Error, Result};
use crate::identity::OnionAddress;
use crate::tor::{TorConnection, TorConnectionConfig};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::fs::File;
use tracing::{debug, info, warn};

/// Magic bytes to identify file transfer streams.
const FILE_TRANSFER_MAGIC: &[u8; 8] = b"TCFT0001";

/// Maximum metadata size (64KB).
const MAX_METADATA_SIZE: usize = 65536;

/// Chunk size for streaming (64KB).
const STREAM_CHUNK_SIZE: usize = 65536;

/// File transfer metadata sent at start of stream.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StreamFileMetadata {
    /// Transfer ID.
    pub transfer_id: [u8; 16],
    /// Original filename.
    pub filename: String,
    /// File size in bytes.
    pub size: u64,
    /// SHA-256 hash of file content.
    pub hash: [u8; 32],
    /// Sender's onion address.
    pub sender_address: String,
}

/// Result of a file transfer.
#[derive(Debug)]
pub struct TransferResult {
    /// Transfer ID.
    pub transfer_id: [u8; 16],
    /// Whether transfer succeeded.
    pub success: bool,
    /// Output path (for receiver).
    pub output_path: Option<PathBuf>,
    /// Error message if failed.
    pub error: Option<String>,
}

/// Send a file to a peer via TCP stream over Tor.
pub async fn send_file_stream(
    file_path: PathBuf,
    peer_address: &str,
    sender_address: &str,
    tor_config: &TorConnectionConfig,
) -> Result<TransferResult> {
    let peer_addr = OnionAddress::from_string(peer_address)
        .map_err(|_| Error::Protocol("Invalid peer address".into()))?;

    info!(to = %peer_address, file = ?file_path, "Starting TCP stream file transfer");

    // Open and read file metadata
    let file = File::open(&file_path).await?;
    let file_metadata = file.metadata().await?;
    let file_size = file_metadata.len();

    let filename = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string();

    // Compute file hash
    let hash = compute_file_hash(&file_path).await?;

    // Generate transfer ID
    let transfer_id = crate::crypto::random_bytes::<16>();

    let metadata = StreamFileMetadata {
        transfer_id,
        filename: filename.clone(),
        size: file_size,
        hash,
        sender_address: sender_address.to_string(),
    };

    // Connect to peer via Tor
    info!(to = %peer_address, "Connecting via Tor...");
    let mut conn = TorConnection::connect(tor_config, &peer_addr).await?;
    let stream = conn.stream_mut();

    // Send magic bytes
    stream.write_all(FILE_TRANSFER_MAGIC).await
        .map_err(|e| Error::Tor(format!("Failed to write magic: {}", e)))?;

    // Serialize and send metadata
    let metadata_bytes = bincode::serialize(&metadata)
        .map_err(|e| Error::Encoding(format!("Failed to serialize metadata: {}", e)))?;

    if metadata_bytes.len() > MAX_METADATA_SIZE {
        return Err(Error::Protocol("Metadata too large".into()));
    }

    // Send metadata length (4 bytes, big-endian)
    let metadata_len = metadata_bytes.len() as u32;
    stream.write_all(&metadata_len.to_be_bytes()).await
        .map_err(|e| Error::Tor(format!("Failed to write metadata length: {}", e)))?;

    // Send metadata
    stream.write_all(&metadata_bytes).await
        .map_err(|e| Error::Tor(format!("Failed to write metadata: {}", e)))?;

    stream.flush().await
        .map_err(|e| Error::Tor(format!("Failed to flush: {}", e)))?;

    info!(to = %peer_address, filename = %filename, size = file_size, "Metadata sent, streaming file...");

    // Stream file data
    let mut file = File::open(&file_path).await?;
    let mut buffer = vec![0u8; STREAM_CHUNK_SIZE];
    let mut bytes_sent: u64 = 0;

    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }

        stream.write_all(&buffer[..n]).await
            .map_err(|e| Error::Tor(format!("Failed to write chunk: {}", e)))?;

        bytes_sent += n as u64;

        if bytes_sent % (1024 * 1024) == 0 || bytes_sent == file_size {
            debug!(
                transfer_id = ?transfer_id,
                sent = bytes_sent,
                total = file_size,
                percent = (bytes_sent * 100 / file_size),
                "Transfer progress"
            );
        }
    }

    stream.flush().await
        .map_err(|e| Error::Tor(format!("Failed to flush: {}", e)))?;

    info!(
        transfer_id = ?transfer_id,
        to = %peer_address,
        bytes = bytes_sent,
        "File transfer complete"
    );

    // Wait for acknowledgment (1 byte: 0x01 = success, 0x00 = failure)
    let mut ack = [0u8; 1];
    let ack_result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        stream.read_exact(&mut ack)
    ).await;

    match ack_result {
        Ok(Ok(_)) => {
            if ack[0] == 0x01 {
                info!(transfer_id = ?transfer_id, "Received success acknowledgment");
                Ok(TransferResult {
                    transfer_id,
                    success: true,
                    output_path: None,
                    error: None,
                })
            } else {
                warn!(transfer_id = ?transfer_id, "Received failure acknowledgment");
                Ok(TransferResult {
                    transfer_id,
                    success: false,
                    output_path: None,
                    error: Some("Receiver reported failure".into()),
                })
            }
        }
        Ok(Err(e)) => {
            warn!(transfer_id = ?transfer_id, error = %e, "Failed to read acknowledgment");
            Ok(TransferResult {
                transfer_id,
                success: true, // Assume success if we sent all data
                output_path: None,
                error: Some(format!("No acknowledgment: {}", e)),
            })
        }
        Err(_) => {
            warn!(transfer_id = ?transfer_id, "Acknowledgment timeout");
            Ok(TransferResult {
                transfer_id,
                success: true, // Assume success if we sent all data
                output_path: None,
                error: Some("Acknowledgment timeout".into()),
            })
        }
    }
}

/// Receive a file from a TCP stream.
/// Called when an incoming connection is detected with FILE_TRANSFER_MAGIC.
pub async fn receive_file_stream(
    stream: &mut tokio::net::TcpStream,
    output_dir: PathBuf,
) -> Result<TransferResult> {
    info!("Receiving file via TCP stream...");

    // Read metadata length
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await
        .map_err(|e| Error::Tor(format!("Failed to read metadata length: {}", e)))?;

    let metadata_len = u32::from_be_bytes(len_buf) as usize;

    if metadata_len > MAX_METADATA_SIZE {
        return Err(Error::Protocol("Metadata too large".into()));
    }

    // Read metadata
    let mut metadata_buf = vec![0u8; metadata_len];
    stream.read_exact(&mut metadata_buf).await
        .map_err(|e| Error::Tor(format!("Failed to read metadata: {}", e)))?;

    let metadata: StreamFileMetadata = bincode::deserialize(&metadata_buf)
        .map_err(|e| Error::Encoding(format!("Failed to parse metadata: {}", e)))?;

    info!(
        from = %metadata.sender_address,
        filename = %metadata.filename,
        size = metadata.size,
        "Receiving file"
    );

    // Create output path
    let safe_filename = sanitize_filename(&metadata.filename);
    let output_path = output_dir.join(&safe_filename);

    // Create output file
    let mut output_file = File::create(&output_path).await?;

    // Receive file data
    let mut buffer = vec![0u8; STREAM_CHUNK_SIZE];
    let mut bytes_received: u64 = 0;

    while bytes_received < metadata.size {
        let remaining = (metadata.size - bytes_received) as usize;
        let to_read = remaining.min(STREAM_CHUNK_SIZE);

        let n = stream.read(&mut buffer[..to_read]).await
            .map_err(|e| Error::Tor(format!("Failed to read chunk: {}", e)))?;

        if n == 0 {
            warn!(
                received = bytes_received,
                expected = metadata.size,
                "Connection closed before transfer complete"
            );
            break;
        }

        output_file.write_all(&buffer[..n]).await?;
        bytes_received += n as u64;

        if bytes_received % (1024 * 1024) == 0 || bytes_received == metadata.size {
            debug!(
                transfer_id = ?metadata.transfer_id,
                received = bytes_received,
                total = metadata.size,
                percent = (bytes_received * 100 / metadata.size),
                "Receive progress"
            );
        }
    }

    output_file.flush().await?;

    // Verify hash
    let received_hash = compute_file_hash(&output_path).await?;
    let hash_valid = received_hash == metadata.hash;

    if hash_valid {
        info!(
            transfer_id = ?metadata.transfer_id,
            from = %metadata.sender_address,
            path = ?output_path,
            "File received and verified"
        );

        // Send success acknowledgment
        if let Err(e) = stream.write_all(&[0x01]).await {
            warn!(error = %e, "Failed to send acknowledgment");
        }
        let _ = stream.flush().await;

        Ok(TransferResult {
            transfer_id: metadata.transfer_id,
            success: true,
            output_path: Some(output_path),
            error: None,
        })
    } else {
        warn!(
            transfer_id = ?metadata.transfer_id,
            "File hash mismatch"
        );

        // Clean up corrupted file
        let _ = tokio::fs::remove_file(&output_path).await;

        // Send failure acknowledgment
        if let Err(e) = stream.write_all(&[0x00]).await {
            warn!(error = %e, "Failed to send failure acknowledgment");
        }
        let _ = stream.flush().await;

        Ok(TransferResult {
            transfer_id: metadata.transfer_id,
            success: false,
            output_path: None,
            error: Some("Hash verification failed".into()),
        })
    }
}

/// Check if incoming data starts with file transfer magic.
pub fn is_file_transfer_magic(data: &[u8]) -> bool {
    data.len() >= 8 && &data[..8] == FILE_TRANSFER_MAGIC
}

/// Get the magic bytes for file transfer.
pub fn get_magic_bytes() -> &'static [u8; 8] {
    FILE_TRANSFER_MAGIC
}

/// Compute SHA-256 hash of a file.
async fn compute_file_hash(path: &PathBuf) -> Result<[u8; 32]> {
    use sha2::{Sha256, Digest};

    let mut file = File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 8192];

    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(hasher.finalize().into())
}

/// Sanitize filename to prevent path traversal.
fn sanitize_filename(name: &str) -> String {
    let name = name.replace(['/', '\\', '\0'], "_");
    let name = name.trim_start_matches('.');

    if name.is_empty() {
        format!("file_{}", chrono::Utc::now().timestamp())
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("test.txt"), "test.txt");
        // After replacing /, \, \0 with _ and trimming leading dots:
        // "../../../etc/passwd" -> ".._.._.._etc_passwd" -> "_.._.._etc_passwd"
        assert_eq!(sanitize_filename("../../../etc/passwd"), "_.._.._etc_passwd");
        assert_eq!(sanitize_filename(".hidden"), "hidden");
        assert_eq!(sanitize_filename("file/with/slashes"), "file_with_slashes");
    }

    #[test]
    fn test_magic_detection() {
        let magic = get_magic_bytes();
        assert!(is_file_transfer_magic(magic));
        assert!(!is_file_transfer_magic(b"NOTMAGIC"));
        assert!(!is_file_transfer_magic(&[1, 2, 3]));
    }

    #[test]
    fn test_metadata_serialization() {
        let metadata = StreamFileMetadata {
            transfer_id: [1u8; 16],
            filename: "test_file.txt".to_string(),
            size: 1024,
            hash: [2u8; 32],
            sender_address: "test.onion".to_string(),
        };

        // Serialize
        let bytes = bincode::serialize(&metadata).unwrap();
        assert!(bytes.len() < MAX_METADATA_SIZE);

        // Deserialize
        let decoded: StreamFileMetadata = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.filename, "test_file.txt");
        assert_eq!(decoded.size, 1024);
        assert_eq!(decoded.transfer_id, [1u8; 16]);
        assert_eq!(decoded.hash, [2u8; 32]);
        assert_eq!(decoded.sender_address, "test.onion");
    }

    #[tokio::test]
    async fn test_local_file_transfer() {
        use tokio::net::{TcpListener, TcpStream};
        use std::io::Write as _;

        // Create temp directory and test file
        let temp_dir = std::env::temp_dir().join("torchat_test");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let test_content = b"Hello, this is a test file for TorChat file transfer!";
        let test_file_path = temp_dir.join("test_input.txt");
        {
            let mut f = std::fs::File::create(&test_file_path).unwrap();
            f.write_all(test_content).unwrap();
        }

        // Compute expected hash
        let expected_hash = compute_file_hash(&test_file_path).await.unwrap();

        // Create metadata
        let metadata = StreamFileMetadata {
            transfer_id: [42u8; 16],
            filename: "test_input.txt".to_string(),
            size: test_content.len() as u64,
            hash: expected_hash,
            sender_address: "sender.onion".to_string(),
        };

        // Start a local TCP listener
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn receiver task
        let output_dir = temp_dir.join("received");
        std::fs::create_dir_all(&output_dir).unwrap();
        let output_dir_clone = output_dir.clone();

        let receiver_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read and verify magic bytes
            let mut magic_buf = [0u8; 8];
            stream.read_exact(&mut magic_buf).await.unwrap();
            assert!(is_file_transfer_magic(&magic_buf));

            // Receive file
            receive_file_stream(&mut stream, output_dir_clone).await
        });

        // Spawn sender task
        let metadata_bytes = bincode::serialize(&metadata).unwrap();
        let test_file_path_clone = test_file_path.clone();

        let sender_handle = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();

            // Send magic bytes
            stream.write_all(FILE_TRANSFER_MAGIC).await.unwrap();

            // Send metadata length
            let metadata_len = metadata_bytes.len() as u32;
            stream.write_all(&metadata_len.to_be_bytes()).await.unwrap();

            // Send metadata
            stream.write_all(&metadata_bytes).await.unwrap();

            // Send file content
            let content = tokio::fs::read(&test_file_path_clone).await.unwrap();
            stream.write_all(&content).await.unwrap();
            stream.flush().await.unwrap();

            // Wait for ack
            let mut ack = [0u8; 1];
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                stream.read_exact(&mut ack)
            ).await;

            ack[0]
        });

        // Wait for both tasks
        let (receiver_result, sender_ack) = tokio::join!(receiver_handle, sender_handle);

        let result = receiver_result.unwrap().unwrap();
        assert!(result.success, "Transfer should succeed");
        assert!(result.output_path.is_some());

        // Verify received file content
        let received_content = std::fs::read(result.output_path.unwrap()).unwrap();
        assert_eq!(received_content, test_content);

        // Verify ack
        assert_eq!(sender_ack.unwrap(), 0x01, "Should receive success ack");

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
