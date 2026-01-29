//! Wire protocol for TorChat 2.0.
//!
//! A strict binary, versioned protocol transmitted over Tor TCP streams.
//! All payloads are encrypted; only minimal framing is visible.
//!
//! ## Protocol Rules (Spec Section 6)
//!
//! - Strict packet validation
//! - Silent drop on malformed input (no error responses)
//! - Versioned for forward compatibility
//! - Binary format (not JSON/text)
//!
//! ## Packet Structure
//!
//! ```text
//! ┌─────────┬─────────┬──────────┬───────────────────┐
//! │ Version │  Type   │  Length  │     Payload       │
//! │ (1 byte)│ (1 byte)│ (4 bytes)│   (variable)      │
//! └─────────┴─────────┴──────────┴───────────────────┘
//! ```
//!
//! Maximum payload size: 64 KiB

mod packet;
mod types;

pub use packet::{Packet, PacketHeader, HEADER_SIZE, MAX_PAYLOAD_SIZE};
pub use types::{
    AckPayload, AckType, CallSignalPayload, CallSignalType, DeletePayload, FileChunkPayload,
    HelloPayload, MessagePayload, PacketType, ReactionPayload, SessionInitPayload,
};

use crate::error::{Error, Result};

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// Minimum supported protocol version.
pub const MIN_PROTOCOL_VERSION: u8 = 1;

/// Validate that a protocol version is supported.
pub fn validate_version(version: u8) -> Result<()> {
    if version < MIN_PROTOCOL_VERSION || version > PROTOCOL_VERSION {
        return Err(Error::Protocol(format!(
            "unsupported protocol version: {}",
            version
        )));
    }
    Ok(())
}
