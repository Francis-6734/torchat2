//! TorChat 2.0 Relay Server
//!
//! Store-and-forward relay for offline message delivery.
//!
//! ## Relay Properties (Spec Section 8)
//!
//! - Relays never decrypt content
//! - Cannot identify senders
//! - Time-limited storage (TTL)
//! - Proof-of-work for spam resistance
//! - Replay detection
//! - Per-recipient rate limiting

use anyhow::Result;
use clap::Parser;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

/// TorChat 2.0 Relay - Offline message storage
#[derive(Parser)]
#[command(name = "torchat-relay")]
#[command(author, version, about)]
struct Args {
    /// Listen address
    #[arg(short, long, default_value = "127.0.0.1:9879")]
    listen: String,

    /// Maximum stored messages per recipient
    #[arg(long, default_value = "1000")]
    max_per_recipient: usize,

    /// Message TTL in hours
    #[arg(long, default_value = "168")]
    ttl_hours: u64,

    /// Proof-of-work difficulty (bits of leading zeros)
    #[arg(long, default_value = "16")]
    pow_difficulty: u8,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

/// A stored message.
#[derive(Clone)]
#[allow(dead_code)]
struct StoredMessage {
    /// Encrypted message data.
    data: Vec<u8>,
    /// Time when message was stored.
    stored_at: Instant,
    /// Proof-of-work nonce.
    pow_nonce: [u8; 8],
}

/// Relay state.
struct RelayState {
    /// Messages by recipient onion address hash.
    messages: HashMap<[u8; 32], Vec<StoredMessage>>,
    /// Seen proof-of-work nonces (for replay detection).
    seen_nonces: HashMap<[u8; 8], Instant>,
    /// Configuration.
    config: RelayConfig,
}

#[derive(Clone)]
#[allow(dead_code)]
struct RelayConfig {
    max_per_recipient: usize,
    ttl: Duration,
    pow_difficulty: u8,
}

impl RelayState {
    fn new(config: RelayConfig) -> Self {
        Self {
            messages: HashMap::new(),
            seen_nonces: HashMap::new(),
            config,
        }
    }

    /// Store a message.
    #[allow(dead_code)]
    fn store(&mut self, recipient_hash: [u8; 32], message: StoredMessage) -> Result<(), &'static str> {
        // Check replay
        if self.seen_nonces.contains_key(&message.pow_nonce) {
            return Err("replay detected");
        }

        // Check proof-of-work
        if !verify_pow(&message.data, &message.pow_nonce, self.config.pow_difficulty) {
            return Err("invalid proof-of-work");
        }

        // Store nonce
        self.seen_nonces.insert(message.pow_nonce, Instant::now());

        // Get or create recipient queue
        let queue = self.messages.entry(recipient_hash).or_insert_with(Vec::new);

        // Check rate limit
        if queue.len() >= self.config.max_per_recipient {
            // Remove oldest message
            queue.remove(0);
        }

        queue.push(message);
        Ok(())
    }

    /// Retrieve messages for a recipient.
    #[allow(dead_code)]
    fn retrieve(&mut self, recipient_hash: [u8; 32]) -> Vec<StoredMessage> {
        self.messages.remove(&recipient_hash).unwrap_or_default()
    }

    /// Clean up expired messages.
    fn cleanup(&mut self) {
        let now = Instant::now();
        let ttl = self.config.ttl;

        // Remove expired messages
        for queue in self.messages.values_mut() {
            queue.retain(|msg| now.duration_since(msg.stored_at) < ttl);
        }

        // Remove empty queues
        self.messages.retain(|_, queue| !queue.is_empty());

        // Remove old nonces
        self.seen_nonces.retain(|_, stored| now.duration_since(*stored) < ttl);
    }
}

/// Verify proof-of-work.
fn verify_pow(data: &[u8], nonce: &[u8; 8], difficulty: u8) -> bool {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.update(nonce);
    let hash = hasher.finalize();

    // Check leading zero bits
    let required_bytes = (difficulty / 8) as usize;
    let remaining_bits = difficulty % 8;

    // Check full zero bytes
    for byte in hash.iter().take(required_bytes) {
        if *byte != 0 {
            return false;
        }
    }

    // Check remaining bits
    if remaining_bits > 0 && required_bytes < hash.len() {
        let mask = 0xFF << (8 - remaining_bits);
        if hash[required_bytes] & mask != 0 {
            return false;
        }
    }

    true
}

/// Compute proof-of-work (for testing).
#[allow(dead_code)]
fn compute_pow(data: &[u8], difficulty: u8) -> [u8; 8] {
    use rand::RngCore;

    let mut nonce = [0u8; 8];
    loop {
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        if verify_pow(data, &nonce, difficulty) {
            return nonce;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let filter = if args.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let config = RelayConfig {
        max_per_recipient: args.max_per_recipient,
        ttl: Duration::from_secs(args.ttl_hours * 3600),
        pow_difficulty: args.pow_difficulty,
    };

    let state = Arc::new(RwLock::new(RelayState::new(config)));

    // Start cleanup task
    let cleanup_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
            let mut state = cleanup_state.write().await;
            state.cleanup();
            tracing::info!(
                messages = state.messages.values().map(|v| v.len()).sum::<usize>(),
                recipients = state.messages.len(),
                "Cleanup completed"
            );
        }
    });

    // Start listener
    let listener = TcpListener::bind(&args.listen).await?;

    tracing::info!(
        address = %args.listen,
        pow_difficulty = args.pow_difficulty,
        ttl_hours = args.ttl_hours,
        "TorChat relay started"
    );

    loop {
        let (socket, addr) = listener.accept().await?;
        let _state = Arc::clone(&state);

        tokio::spawn(async move {
            tracing::debug!(?addr, "New connection");

            // TODO: Handle relay protocol
            // - Receive STORE requests (with PoW)
            // - Receive RETRIEVE requests
            // - Send stored messages

            drop(socket);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_verification() {
        let data = b"test message";
        let difficulty = 8; // 1 byte of zeros

        let nonce = compute_pow(data, difficulty);
        assert!(verify_pow(data, &nonce, difficulty));
    }

    #[test]
    fn test_pow_invalid() {
        let data = b"test message";
        let nonce = [0u8; 8];

        // Random nonce is unlikely to pass difficulty 16
        assert!(!verify_pow(data, &nonce, 16));
    }

    #[test]
    fn test_relay_state() {
        let config = RelayConfig {
            max_per_recipient: 10,
            ttl: Duration::from_secs(3600),
            pow_difficulty: 0, // No PoW for testing
        };

        let mut state = RelayState::new(config);
        let recipient = [0u8; 32];

        let msg = StoredMessage {
            data: b"hello".to_vec(),
            stored_at: Instant::now(),
            pow_nonce: [1, 2, 3, 4, 5, 6, 7, 8],
        };

        state.store(recipient, msg).expect("should store");

        let retrieved = state.retrieve(recipient);
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].data, b"hello");

        // Second retrieve should be empty
        let retrieved = state.retrieve(recipient);
        assert!(retrieved.is_empty());
    }
}
