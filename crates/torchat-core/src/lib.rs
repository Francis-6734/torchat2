//! # TorChat 2.0 Core Library
//!
//! A decentralized, Tor-native communication system providing anonymous,
//! end-to-end encrypted messaging and voice calls without accounts,
//! centralized servers, or surveillance.
//!
//! ## Security Model
//!
//! TorChat 2.0 assumes a hostile environment with:
//! - Network observers (ISPs, state-level actors)
//! - Malicious Tor relay operators
//! - Compromised devices
//!
//! ## Core Guarantees
//!
//! - No IP address exposure at any layer
//! - No user accounts, emails, or phone numbers
//! - No central servers or message brokers
//! - End-to-end encryption with Perfect Forward Secrecy
//! - Tor v3 onion services only
//! - Fail-closed security model
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │              Application                │
//! ├─────────────────────────────────────────┤
//! │  messaging  │  storage  │     tor       │
//! ├─────────────────────────────────────────┤
//! │           protocol (wire)               │
//! ├─────────────────────────────────────────┤
//! │    crypto    │       identity           │
//! └─────────────────────────────────────────┘
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, clippy::all)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod crypto;
pub mod error;
pub mod identity;
pub mod logging;
pub mod messaging;
pub mod protocol;
pub mod storage;
pub mod tor;

#[cfg(feature = "voice")]
pub mod voice;

pub use error::{Error, Result};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Wire protocol version for compatibility checks
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum message size in bytes (64 KiB)
pub const MAX_MESSAGE_SIZE: usize = 65536;

/// Maximum number of skipped message keys to store
pub const MAX_SKIP: usize = 1000;
