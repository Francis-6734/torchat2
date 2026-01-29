//! Tor onion service management.
//!
//! Creates and manages a Tor v3 onion service for receiving connections.

use super::controller::TorController;
use crate::error::{Error, Result};
use crate::identity::TorIdentity;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// Configuration for onion service.
#[derive(Debug, Clone)]
pub struct OnionServiceConfig {
    /// Local port to listen on.
    pub local_port: u16,
    /// Tor control port address.
    pub control_addr: String,
    /// Virtual port exposed on the onion service.
    pub virtual_port: u16,
    /// Directory to store onion service keys (optional).
    pub data_dir: Option<PathBuf>,
}

impl Default for OnionServiceConfig {
    fn default() -> Self {
        Self {
            local_port: 9878,
            control_addr: format!("127.0.0.1:{}", super::DEFAULT_CONTROL_PORT),
            virtual_port: 443,
            data_dir: None,
        }
    }
}

/// A running onion service.
pub struct OnionService {
    /// Our identity (determines onion address).
    identity: TorIdentity,
    /// Service ID returned by Tor (hostname without .onion).
    service_id: String,
    /// Local TCP listener.
    listener: TcpListener,
    /// Configuration.
    config: OnionServiceConfig,
    /// Controller connection for cleanup.
    controller: Arc<Mutex<TorController>>,
}

impl OnionService {
    /// Create and start an onion service.
    ///
    /// This registers the onion service with Tor via ControlPort and starts
    /// listening for incoming connections.
    pub async fn start(identity: TorIdentity, config: OnionServiceConfig) -> Result<Self> {
        // Bind local listener first
        let addr = format!("127.0.0.1:{}", config.local_port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| Error::Tor(format!("failed to bind listener on {}: {}", addr, e)))?;

        tracing::info!(local_port = config.local_port, "Bound local listener");

        // Connect to Tor control port
        let mut controller = TorController::connect(&config.control_addr).await?;

        // Authenticate
        controller.authenticate_auto().await?;

        // Check Tor version
        match controller.get_version().await {
            Ok(version) => tracing::info!(version = %version, "Connected to Tor"),
            Err(e) => tracing::warn!("Could not get Tor version: {}", e),
        }

        // Wait for Tor to be ready (has circuits)
        tracing::info!("Waiting for Tor circuits...");
        controller
            .wait_ready(std::time::Duration::from_secs(60))
            .await
            .map_err(|_| Error::Tor("Tor not ready (no circuits) after 60s".into()))?;

        // Register onion service
        let service_id = controller
            .add_onion(&identity, config.virtual_port, config.local_port)
            .await?;

        tracing::info!(
            onion_address = %format!("{}.onion", service_id),
            local_port = config.local_port,
            virtual_port = config.virtual_port,
            "Onion service registered"
        );

        Ok(Self {
            identity,
            service_id,
            listener,
            config,
            controller: Arc::new(Mutex::new(controller)),
        })
    }

    /// Accept an incoming connection.
    pub async fn accept(&self) -> Result<tokio::net::TcpStream> {
        let (stream, addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| Error::Tor(format!("accept failed: {}", e)))?;

        tracing::debug!(?addr, "Accepted incoming connection");

        Ok(stream)
    }

    /// Get the onion address.
    pub fn onion_address(&self) -> &crate::identity::OnionAddress {
        self.identity.onion_address()
    }

    /// Get the service ID (hostname without .onion).
    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    /// Get the local port.
    pub fn local_port(&self) -> u16 {
        self.config.local_port
    }

    /// Get the virtual port (external port on .onion).
    pub fn virtual_port(&self) -> u16 {
        self.config.virtual_port
    }

    /// Stop the onion service.
    pub async fn stop(self) -> Result<()> {
        // Remove onion service from Tor
        let mut controller = self.controller.lock().await;
        if let Err(e) = controller.del_onion(&self.service_id).await {
            tracing::warn!(error = %e, "Failed to remove onion service");
        }

        drop(self.listener);
        tracing::info!("Onion service stopped");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = OnionServiceConfig::default();
        assert_eq!(config.local_port, 9878);
        assert_eq!(config.virtual_port, 443);
    }
}
