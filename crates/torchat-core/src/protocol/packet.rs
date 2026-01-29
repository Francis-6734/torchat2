//! Packet framing and parsing.
//!
//! Handles the binary packet format with strict validation.
//! Malformed packets result in silent drop (per spec).

use super::types::PacketType;
use super::PROTOCOL_VERSION;
use crate::error::{Error, Result};
use crate::MAX_MESSAGE_SIZE;

/// Maximum payload size (64 KiB).
pub const MAX_PAYLOAD_SIZE: usize = MAX_MESSAGE_SIZE;

/// Header size: version (1) + type (1) + length (4) = 6 bytes.
pub const HEADER_SIZE: usize = 6;

/// Packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    /// Protocol version.
    pub version: u8,
    /// Packet type.
    pub packet_type: PacketType,
    /// Payload length in bytes.
    pub length: u32,
}

impl PacketHeader {
    /// Create a new header.
    pub fn new(packet_type: PacketType, length: u32) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            packet_type,
            length,
        }
    }

    /// Serialize header to bytes.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0] = self.version;
        bytes[1] = self.packet_type.to_byte();
        bytes[2..6].copy_from_slice(&self.length.to_be_bytes());
        bytes
    }

    /// Parse header from bytes.
    ///
    /// Returns error for malformed headers (should trigger silent drop).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            return Err(Error::Protocol("header too short".into()));
        }

        let version = bytes[0];

        // Validate version
        super::validate_version(version)?;

        let packet_type = PacketType::from_byte(bytes[1])?;

        let length = u32::from_be_bytes(
            bytes[2..6]
                .try_into()
                .map_err(|_| Error::Protocol("invalid length field".into()))?,
        );

        // Validate length
        if length as usize > MAX_PAYLOAD_SIZE {
            return Err(Error::Protocol("payload too large".into()));
        }

        Ok(Self {
            version,
            packet_type,
            length,
        })
    }
}

/// A complete packet with header and payload.
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet header.
    pub header: PacketHeader,
    /// Packet payload (encrypted).
    pub payload: Vec<u8>,
}

impl Packet {
    /// Create a new packet.
    pub fn new(packet_type: PacketType, payload: Vec<u8>) -> Result<Self> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(Error::Protocol("payload too large".into()));
        }

        let header = PacketHeader::new(packet_type, payload.len() as u32);

        Ok(Self { header, payload })
    }

    /// Serialize packet to bytes for transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Parse a packet from bytes.
    ///
    /// Validates header and ensures payload matches declared length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let header = PacketHeader::from_bytes(bytes)?;

        let expected_len = HEADER_SIZE + header.length as usize;
        if bytes.len() < expected_len {
            return Err(Error::Protocol("incomplete packet".into()));
        }

        let payload = bytes[HEADER_SIZE..expected_len].to_vec();

        Ok(Self { header, payload })
    }

    /// Get the packet type.
    pub fn packet_type(&self) -> PacketType {
        self.header.packet_type
    }

    /// Get total packet size in bytes.
    pub fn total_size(&self) -> usize {
        HEADER_SIZE + self.payload.len()
    }
}

/// Packet reader for streaming data.
///
/// Accumulates bytes and extracts complete packets.
pub struct PacketReader {
    buffer: Vec<u8>,
}

#[allow(dead_code)]
impl PacketReader {
    /// Create a new packet reader.
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(HEADER_SIZE + MAX_PAYLOAD_SIZE),
        }
    }

    /// Add received bytes to the buffer.
    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Try to extract a complete packet.
    ///
    /// Returns `Ok(Some(packet))` if a complete packet is available,
    /// `Ok(None)` if more data is needed, or `Err` for protocol errors.
    ///
    /// On error, the buffer should be cleared and connection terminated
    /// (silent drop per spec - no error response sent).
    pub fn try_read(&mut self) -> Result<Option<Packet>> {
        // Need at least header
        if self.buffer.len() < HEADER_SIZE {
            return Ok(None);
        }

        // Parse header to get length
        let header = match PacketHeader::from_bytes(&self.buffer) {
            Ok(h) => h,
            Err(e) => {
                // Clear buffer on error (malformed packet)
                self.buffer.clear();
                return Err(e);
            }
        };

        let total_size = HEADER_SIZE + header.length as usize;

        // Need more data?
        if self.buffer.len() < total_size {
            return Ok(None);
        }

        // Extract packet
        let packet_bytes: Vec<u8> = self.buffer.drain(..total_size).collect();
        let packet = Packet::from_bytes(&packet_bytes)?;

        Ok(Some(packet))
    }

    /// Clear the buffer (e.g., after protocol error).
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    /// Get current buffer size.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }
}

impl Default for PacketReader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let header = PacketHeader::new(PacketType::Message, 1234);
        let bytes = header.to_bytes();
        let parsed = PacketHeader::from_bytes(&bytes).expect("should parse");

        assert_eq!(header, parsed);
    }

    #[test]
    fn test_packet_roundtrip() {
        let payload = b"Hello, TorChat!".to_vec();
        let packet = Packet::new(PacketType::Message, payload.clone()).expect("should create");
        let bytes = packet.to_bytes();
        let parsed = Packet::from_bytes(&bytes).expect("should parse");

        assert_eq!(parsed.packet_type(), PacketType::Message);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_packet_reader_streaming() {
        let payload = b"Test payload".to_vec();
        let packet = Packet::new(PacketType::Message, payload).expect("should create");
        let bytes = packet.to_bytes();

        let mut reader = PacketReader::new();

        // Feed bytes one at a time
        for (i, &byte) in bytes.iter().enumerate() {
            reader.push(&[byte]);

            if i < bytes.len() - 1 {
                // Should not have complete packet yet
                assert!(reader.try_read().expect("no error").is_none());
            }
        }

        // Now should have complete packet
        let parsed = reader.try_read().expect("no error").expect("should have packet");
        assert_eq!(parsed.packet_type(), PacketType::Message);
    }

    #[test]
    fn test_payload_too_large() {
        let payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        assert!(Packet::new(PacketType::Message, payload).is_err());
    }

    #[test]
    fn test_invalid_packet_type() {
        let mut bytes = PacketHeader::new(PacketType::Message, 0).to_bytes();
        bytes[1] = 0xFF; // Invalid type

        assert!(PacketHeader::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_invalid_version() {
        let mut bytes = PacketHeader::new(PacketType::Message, 0).to_bytes();
        bytes[0] = 0xFF; // Invalid version

        assert!(PacketHeader::from_bytes(&bytes).is_err());
    }
}
