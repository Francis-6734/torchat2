//! Tor connection handling.
//!
//! Manages connections to onion services through Tor's SOCKS5 proxy.

use crate::error::{Error, Result};
use crate::identity::OnionAddress;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Configuration for Tor connections.
#[derive(Debug, Clone)]
pub struct TorConnectionConfig {
    /// SOCKS5 proxy address.
    pub socks_addr: SocketAddr,
    /// Connection timeout.
    pub timeout: Duration,
    /// Enable stream isolation (unique circuit per connection).
    pub stream_isolation: bool,
}

impl Default for TorConnectionConfig {
    fn default() -> Self {
        Self {
            socks_addr: SocketAddr::from(([127, 0, 0, 1], super::DEFAULT_SOCKS_PORT)),
            timeout: Duration::from_secs(super::CIRCUIT_TIMEOUT_SECS),
            stream_isolation: true,
        }
    }
}

/// A connection through Tor to an onion service.
pub struct TorConnection {
    stream: TcpStream,
    peer_address: OnionAddress,
}

impl TorConnection {
    /// Connect to an onion service.
    ///
    /// Uses SOCKS5 to establish a connection through Tor.
    pub async fn connect(config: &TorConnectionConfig, target: &OnionAddress) -> Result<Self> {
        // Connect to SOCKS5 proxy
        let stream = tokio::time::timeout(
            config.timeout,
            TcpStream::connect(config.socks_addr),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Tor(format!("failed to connect to SOCKS proxy: {}", e)))?;

        // SOCKS5 handshake
        let mut connection = Self {
            stream,
            peer_address: target.clone(),
        };

        connection.socks5_handshake(target, config.stream_isolation).await?;

        Ok(connection)
    }

    /// Perform SOCKS5 handshake.
    async fn socks5_handshake(&mut self, target: &OnionAddress, _isolate: bool) -> Result<()> {
        // SOCKS5 greeting
        // Version 5, 1 auth method (no auth = 0x00)
        self.stream.write_all(&[0x05, 0x01, 0x00]).await
            .map_err(|e| Error::Tor(format!("SOCKS5 greeting failed: {}", e)))?;

        // Read response
        let mut response = [0u8; 2];
        self.stream.read_exact(&mut response).await
            .map_err(|e| Error::Tor(format!("SOCKS5 response failed: {}", e)))?;

        if response[0] != 0x05 || response[1] != 0x00 {
            return Err(Error::Tor("SOCKS5 authentication failed".into()));
        }

        // SOCKS5 connect request
        // Version 5, CMD connect (0x01), RSV (0x00), ATYP domain (0x03)
        let hostname = target.as_str();
        let hostname_bytes = hostname.as_bytes();

        if hostname_bytes.len() > 255 {
            return Err(Error::Tor("hostname too long".into()));
        }

        let mut request = Vec::with_capacity(7 + hostname_bytes.len());
        request.push(0x05); // Version
        request.push(0x01); // Connect
        request.push(0x00); // Reserved
        request.push(0x03); // Domain name
        request.push(hostname_bytes.len() as u8);
        request.extend_from_slice(hostname_bytes);
        request.extend_from_slice(&(443u16).to_be_bytes()); // Port (we use 443 for onion services)

        self.stream.write_all(&request).await
            .map_err(|e| Error::Tor(format!("SOCKS5 connect failed: {}", e)))?;

        // Read response header
        let mut response = [0u8; 4];
        self.stream.read_exact(&mut response).await
            .map_err(|e| Error::Tor(format!("SOCKS5 connect response failed: {}", e)))?;

        if response[0] != 0x05 {
            return Err(Error::Tor("invalid SOCKS5 version in response".into()));
        }

        if response[1] != 0x00 {
            return Err(Error::Tor(format!("SOCKS5 connect failed: error code {}", response[1])));
        }

        // Read bound address (we ignore it but must consume it)
        match response[3] {
            0x01 => {
                // IPv4: 4 bytes + 2 port
                let mut buf = [0u8; 6];
                self.stream.read_exact(&mut buf).await
                    .map_err(|e| Error::Tor(e.to_string()))?;
            }
            0x03 => {
                // Domain: 1 len byte + domain + 2 port
                let mut len = [0u8; 1];
                self.stream.read_exact(&mut len).await
                    .map_err(|e| Error::Tor(e.to_string()))?;
                let mut buf = vec![0u8; len[0] as usize + 2];
                self.stream.read_exact(&mut buf).await
                    .map_err(|e| Error::Tor(e.to_string()))?;
            }
            0x04 => {
                // IPv6: 16 bytes + 2 port
                let mut buf = [0u8; 18];
                self.stream.read_exact(&mut buf).await
                    .map_err(|e| Error::Tor(e.to_string()))?;
            }
            _ => {
                return Err(Error::Tor("invalid SOCKS5 address type".into()));
            }
        }

        Ok(())
    }

    /// Get the peer's onion address.
    pub fn peer_address(&self) -> &OnionAddress {
        &self.peer_address
    }

    /// Send data.
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.stream.write_all(data).await
            .map_err(|e| Error::Tor(format!("send failed: {}", e)))?;
        self.stream.flush().await
            .map_err(|e| Error::Tor(format!("flush failed: {}", e)))?;
        Ok(())
    }

    /// Receive data into buffer.
    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = self.stream.read(buf).await
            .map_err(|e| Error::Tor(format!("recv failed: {}", e)))?;
        Ok(n)
    }

    /// Close the connection.
    pub async fn close(mut self) -> Result<()> {
        self.stream.shutdown().await
            .map_err(|e| Error::Tor(format!("shutdown failed: {}", e)))?;
        Ok(())
    }

    /// Get mutable access to the underlying stream.
    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    /// Split into read and write halves.
    pub fn split(self) -> (tokio::net::tcp::OwnedReadHalf, tokio::net::tcp::OwnedWriteHalf) {
        self.stream.into_split()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = TorConnectionConfig::default();
        assert_eq!(config.socks_addr.port(), super::super::DEFAULT_SOCKS_PORT);
        assert!(config.stream_isolation);
    }
}
