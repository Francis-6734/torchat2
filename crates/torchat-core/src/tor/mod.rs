//! Tor integration for TorChat 2.0.
//!
//! Provides Tor v3 onion service management and circuit handling.
//!
//! ## Requirements (Spec Section 0.3)
//!
//! - Support v3 onion services
//! - Stream isolation
//! - Per-peer circuits
//! - ControlPort integration
//!
//! ## Design
//!
//! TorChat connects to a local Tor daemon via ControlPort or uses
//! an embedded Arti client. All connections go through Tor - there
//! is no clearnet fallback.

mod connection;
mod controller;
mod service;

pub use connection::{TorConnection, TorConnectionConfig};
pub use controller::{ProtocolInfo, TorAuth, TorController};
pub use service::{OnionService, OnionServiceConfig};


/// Default SOCKS5 proxy port for Tor.
pub const DEFAULT_SOCKS_PORT: u16 = 9050;

/// Default control port for Tor.
pub const DEFAULT_CONTROL_PORT: u16 = 9051;

/// Connection timeout for Tor circuits (seconds).
pub const CIRCUIT_TIMEOUT_SECS: u64 = 120;

/// Maximum retries for connection attempts.
pub const MAX_CONNECT_RETRIES: u32 = 3;
