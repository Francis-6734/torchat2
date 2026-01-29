//! Voice calling support for TorChat 2.0.
//!
//! Implements encrypted voice calls over Tor using Opus codec.
//! Audio is encrypted end-to-end using the existing session keys.
//!
//! ## Design
//!
//! - Opus codec for efficient audio (48kHz, mono)
//! - 20ms audio frames
//! - Each frame encrypted with ChaCha20-Poly1305
//! - Call signaling via CallSignal packets
//! - Audio data sent as encrypted UDP-style datagrams over TCP

use crate::crypto::{encrypt, decrypt, random_bytes, Nonce, NONCE_SIZE};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use tokio::sync::mpsc;

/// Audio sample rate in Hz.
pub const SAMPLE_RATE: u32 = 48000;
/// Number of audio channels (1 = mono).
pub const CHANNELS: u16 = 1;
/// Audio frame duration in milliseconds.
pub const FRAME_SIZE_MS: u32 = 20;
/// Number of samples per audio frame.
pub const FRAME_SIZE_SAMPLES: usize = (SAMPLE_RATE * FRAME_SIZE_MS / 1000) as usize;

/// Maximum jitter buffer size in frames.
pub const JITTER_BUFFER_SIZE: usize = 10;

/// Call state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    /// No active call.
    Idle,
    /// Outgoing call, waiting for answer.
    Calling,
    /// Incoming call, ringing.
    Ringing,
    /// Call connected, audio active.
    Connected,
    /// Call ending.
    Ending,
}

/// Voice call session.
pub struct VoiceCall {
    /// Unique call ID.
    pub call_id: [u8; 16],
    /// Peer's onion address.
    pub peer_address: String,
    /// Current call state.
    state: CallState,
    /// Audio encryption key (derived from session).
    audio_key: [u8; 32],
    /// Sequence number for outgoing audio.
    send_seq: u64,
    /// Expected sequence number for incoming audio.
    recv_seq: u64,
    /// Jitter buffer for incoming audio.
    jitter_buffer: VecDeque<AudioFrame>,
    /// Call start time (for duration tracking).
    start_time: Option<std::time::Instant>,
    /// Call statistics.
    stats: CallStats,
}

/// Encrypted audio frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioFrame {
    /// Sequence number for ordering.
    pub sequence: u64,
    /// Timestamp (samples).
    pub timestamp: u32,
    /// Encrypted Opus-encoded audio data.
    pub data: Vec<u8>,
    /// Nonce used for encryption.
    pub nonce: [u8; 12],
}

/// Call offer data (sent in encrypted payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallOffer {
    /// Caller's audio capabilities.
    pub capabilities: AudioCapabilities,
    /// Session audio key component.
    pub audio_key_share: [u8; 32],
}

/// Call answer data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallAnswer {
    /// Responder's audio capabilities.
    pub capabilities: AudioCapabilities,
    /// Session audio key component.
    pub audio_key_share: [u8; 32],
}

/// Audio capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioCapabilities {
    /// Supported sample rates.
    pub sample_rates: Vec<u32>,
    /// Supported channel counts.
    pub channels: Vec<u16>,
    /// Maximum bitrate supported.
    pub max_bitrate: u32,
}

impl Default for AudioCapabilities {
    fn default() -> Self {
        Self {
            sample_rates: vec![48000, 24000, 16000],
            channels: vec![1, 2],
            max_bitrate: 64000,
        }
    }
}

/// Call statistics.
#[derive(Debug, Clone, Default)]
pub struct CallStats {
    /// Total packets sent.
    pub packets_sent: u64,
    /// Total packets received.
    pub packets_received: u64,
    /// Packets lost.
    pub packets_lost: u64,
    /// Average latency in milliseconds.
    pub avg_latency_ms: f64,
    /// Jitter in milliseconds.
    pub jitter_ms: f64,
}

impl VoiceCall {
    /// Create a new outgoing call.
    pub fn new_outgoing(peer_address: String) -> Self {
        Self {
            call_id: random_bytes(),
            peer_address,
            state: CallState::Idle,
            audio_key: [0u8; 32],
            send_seq: 0,
            recv_seq: 0,
            jitter_buffer: VecDeque::with_capacity(JITTER_BUFFER_SIZE),
            start_time: None,
            stats: CallStats::default(),
        }
    }

    /// Create a new incoming call.
    pub fn new_incoming(call_id: [u8; 16], peer_address: String) -> Self {
        Self {
            call_id,
            peer_address,
            state: CallState::Ringing,
            audio_key: [0u8; 32],
            send_seq: 0,
            recv_seq: 0,
            jitter_buffer: VecDeque::with_capacity(JITTER_BUFFER_SIZE),
            start_time: None,
            stats: CallStats::default(),
        }
    }

    /// Get current call state.
    pub fn state(&self) -> CallState {
        self.state
    }

    /// Get call duration in seconds.
    pub fn duration(&self) -> Option<f64> {
        self.start_time.map(|t| t.elapsed().as_secs_f64())
    }

    /// Get call statistics.
    pub fn stats(&self) -> &CallStats {
        &self.stats
    }

    /// Initiate the call (generate offer).
    pub fn initiate(&mut self) -> Result<CallOffer> {
        if self.state != CallState::Idle {
            return Err(Error::Protocol("call already in progress".into()));
        }

        self.state = CallState::Calling;

        // Generate our key share
        let key_share: [u8; 32] = random_bytes();

        Ok(CallOffer {
            capabilities: AudioCapabilities::default(),
            audio_key_share: key_share,
        })
    }

    /// Accept an incoming call (generate answer).
    pub fn accept(&mut self, offer: &CallOffer) -> Result<CallAnswer> {
        if self.state != CallState::Ringing {
            return Err(Error::Protocol("no incoming call to accept".into()));
        }

        // Generate our key share
        let our_key_share: [u8; 32] = random_bytes();

        // Derive shared audio key from both shares
        self.derive_audio_key(&offer.audio_key_share, &our_key_share);

        self.state = CallState::Connected;
        self.start_time = Some(std::time::Instant::now());

        Ok(CallAnswer {
            capabilities: AudioCapabilities::default(),
            audio_key_share: our_key_share,
        })
    }

    /// Complete call setup when answer received.
    pub fn on_answer(&mut self, answer: &CallAnswer, our_key_share: &[u8; 32]) -> Result<()> {
        if self.state != CallState::Calling {
            return Err(Error::Protocol("not in calling state".into()));
        }

        // Derive shared audio key
        self.derive_audio_key(our_key_share, &answer.audio_key_share);

        self.state = CallState::Connected;
        self.start_time = Some(std::time::Instant::now());

        Ok(())
    }

    /// Derive the audio encryption key from both key shares.
    fn derive_audio_key(&mut self, share1: &[u8; 32], share2: &[u8; 32]) {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(b"torchat-audio-key");
        hasher.update(share1);
        hasher.update(share2);
        let hash = hasher.finalize();

        self.audio_key.copy_from_slice(&hash);
    }

    /// Encrypt an audio frame for sending.
    pub fn encrypt_audio(&mut self, opus_data: &[u8]) -> Result<AudioFrame> {
        if self.state != CallState::Connected {
            return Err(Error::Protocol("call not connected".into()));
        }

        let nonce_bytes: [u8; NONCE_SIZE] = random_bytes();
        let nonce = Nonce::from(nonce_bytes);
        let aad = format!("audio:{}", self.send_seq);

        let encrypted = encrypt(&self.audio_key, &nonce, opus_data, aad.as_bytes())?;

        let frame = AudioFrame {
            sequence: self.send_seq,
            timestamp: (self.send_seq * FRAME_SIZE_SAMPLES as u64) as u32,
            data: encrypted,
            nonce: nonce_bytes,
        };

        self.send_seq += 1;
        self.stats.packets_sent += 1;

        Ok(frame)
    }

    /// Decrypt a received audio frame.
    pub fn decrypt_audio(&mut self, frame: &AudioFrame) -> Result<Vec<u8>> {
        if self.state != CallState::Connected {
            return Err(Error::Protocol("call not connected".into()));
        }

        let nonce = Nonce::from(frame.nonce);
        let aad = format!("audio:{}", frame.sequence);

        let decrypted = decrypt(&self.audio_key, &nonce, &frame.data, aad.as_bytes())?;

        self.stats.packets_received += 1;

        // Track packet loss
        if frame.sequence > self.recv_seq {
            self.stats.packets_lost += frame.sequence - self.recv_seq;
        }
        self.recv_seq = frame.sequence + 1;

        Ok(decrypted.to_vec())
    }

    /// Add frame to jitter buffer.
    pub fn buffer_frame(&mut self, frame: AudioFrame) {
        // Insert in order by sequence number
        let pos = self.jitter_buffer
            .iter()
            .position(|f| f.sequence > frame.sequence)
            .unwrap_or(self.jitter_buffer.len());

        self.jitter_buffer.insert(pos, frame);

        // Trim if too large
        while self.jitter_buffer.len() > JITTER_BUFFER_SIZE {
            self.jitter_buffer.pop_front();
        }
    }

    /// Get next frame from jitter buffer.
    pub fn get_buffered_frame(&mut self) -> Option<AudioFrame> {
        self.jitter_buffer.pop_front()
    }

    /// End the call.
    pub fn hangup(&mut self) {
        self.state = CallState::Ending;
    }

    /// Handle decline from peer.
    pub fn on_decline(&mut self) {
        self.state = CallState::Idle;
    }

    /// Handle hangup from peer.
    pub fn on_hangup(&mut self) {
        self.state = CallState::Idle;
    }
}

/// Voice call manager for handling multiple calls.
pub struct VoiceCallManager {
    /// Active calls by call ID.
    calls: std::collections::HashMap<[u8; 16], VoiceCall>,
    /// Incoming call handler.
    incoming_tx: Option<mpsc::Sender<VoiceCall>>,
}

impl VoiceCallManager {
    /// Create a new call manager.
    pub fn new() -> Self {
        Self {
            calls: std::collections::HashMap::new(),
            incoming_tx: None,
        }
    }

    /// Set the incoming call handler.
    pub fn set_incoming_handler(&mut self, tx: mpsc::Sender<VoiceCall>) {
        self.incoming_tx = Some(tx);
    }

    /// Start a new outgoing call.
    pub fn start_call(&mut self, peer_address: String) -> Result<([u8; 16], CallOffer)> {
        let mut call = VoiceCall::new_outgoing(peer_address);
        let offer = call.initiate()?;
        let call_id = call.call_id;
        self.calls.insert(call_id, call);
        Ok((call_id, offer))
    }

    /// Handle an incoming call offer.
    pub async fn handle_incoming(&mut self, call_id: [u8; 16], peer_address: String, _offer: CallOffer) -> Result<()> {
        let call = VoiceCall::new_incoming(call_id, peer_address);

        if let Some(tx) = &self.incoming_tx {
            tx.send(call).await.map_err(|_| Error::Protocol("failed to notify incoming call".into()))?;
        }

        Ok(())
    }

    /// Get a call by ID.
    pub fn get_call(&mut self, call_id: &[u8; 16]) -> Option<&mut VoiceCall> {
        self.calls.get_mut(call_id)
    }

    /// Remove a completed call.
    pub fn remove_call(&mut self, call_id: &[u8; 16]) -> Option<VoiceCall> {
        self.calls.remove(call_id)
    }
}

impl Default for VoiceCallManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_state_flow() {
        let mut caller = VoiceCall::new_outgoing("test.onion".to_string());
        assert_eq!(caller.state(), CallState::Idle);

        let offer = caller.initiate().unwrap();
        assert_eq!(caller.state(), CallState::Calling);

        let mut callee = VoiceCall::new_incoming(caller.call_id, "caller.onion".to_string());
        assert_eq!(callee.state(), CallState::Ringing);

        let answer = callee.accept(&offer).unwrap();
        assert_eq!(callee.state(), CallState::Connected);

        caller.on_answer(&answer, &offer.audio_key_share).unwrap();
        assert_eq!(caller.state(), CallState::Connected);
    }

    #[test]
    fn test_audio_encryption() {
        let mut caller = VoiceCall::new_outgoing("test.onion".to_string());
        let offer = caller.initiate().unwrap();

        let mut callee = VoiceCall::new_incoming(caller.call_id, "caller.onion".to_string());
        let answer = callee.accept(&offer).unwrap();
        caller.on_answer(&answer, &offer.audio_key_share).unwrap();

        // Encrypt some audio data
        let audio_data = vec![1u8, 2, 3, 4, 5];
        let frame = caller.encrypt_audio(&audio_data).unwrap();

        // Decrypt on the other side
        let decrypted = callee.decrypt_audio(&frame).unwrap();
        assert_eq!(audio_data, decrypted);
    }
}
