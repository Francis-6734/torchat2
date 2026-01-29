//! Tor ControlPort client implementation.
//!
//! Communicates with Tor via the ControlPort protocol (spec: control-spec.txt).
//! Supports cookie and password authentication, and ADD_ONION/DEL_ONION commands.

use crate::error::{Error, Result};
use crate::identity::TorIdentity;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Authentication method for Tor ControlPort.
#[derive(Debug, Clone)]
pub enum TorAuth {
    /// No authentication required.
    None,
    /// Cookie authentication (reads from file).
    Cookie(String),
    /// Password authentication.
    Password(String),
}

/// Tor ControlPort client.
pub struct TorController {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
    authenticated: bool,
}

impl TorController {
    /// Connect to Tor ControlPort.
    pub async fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| Error::Tor(format!("failed to connect to control port: {}", e)))?;

        let (read_half, write_half) = stream.into_split();
        let reader = BufReader::new(read_half);

        Ok(Self {
            reader,
            writer: write_half,
            authenticated: false,
        })
    }

    /// Connect to default Tor ControlPort (127.0.0.1:9051).
    pub async fn connect_default() -> Result<Self> {
        Self::connect("127.0.0.1:9051").await
    }

    /// Send a command and read the response.
    async fn command(&mut self, cmd: &str) -> Result<Vec<String>> {
        // Send command
        self.writer
            .write_all(format!("{}\r\n", cmd).as_bytes())
            .await
            .map_err(|e| Error::Tor(format!("failed to send command: {}", e)))?;
        self.writer
            .flush()
            .await
            .map_err(|e| Error::Tor(format!("failed to flush: {}", e)))?;

        // Read response lines
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            self.reader
                .read_line(&mut line)
                .await
                .map_err(|e| Error::Tor(format!("failed to read response: {}", e)))?;

            let line = line.trim_end().to_string();

            if line.is_empty() {
                continue;
            }

            // Response format: "250-..." for continuation, "250 ..." for final
            // Error responses: "5xx ..." or "4xx ..."
            let code = &line[..3];
            let separator = line.chars().nth(3).unwrap_or(' ');

            if code.starts_with('2') {
                lines.push(line[4..].to_string());
                if separator == ' ' {
                    // Final line of successful response
                    break;
                }
            } else {
                // Error response
                return Err(Error::Tor(format!("control port error: {}", line)));
            }
        }

        Ok(lines)
    }

    /// Get protocol info to determine authentication method.
    pub async fn get_protocol_info(&mut self) -> Result<ProtocolInfo> {
        let lines = self.command("PROTOCOLINFO 1").await?;

        let mut auth_methods = Vec::new();
        let mut cookie_file = None;

        for line in lines {
            // Parse: AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="/path"
            if let Some(auth_part) = line.strip_prefix("AUTH ") {
                // Find METHODS=
                if let Some(methods_start) = auth_part.find("METHODS=") {
                    let after_methods = &auth_part[methods_start + 8..];
                    // Methods end at space or end of string
                    let methods_end = after_methods.find(' ').unwrap_or(after_methods.len());
                    let methods_str = &after_methods[..methods_end];
                    auth_methods = methods_str.split(',').map(String::from).collect();
                }
                // Find COOKIEFILE=
                if let Some(cookie_start) = auth_part.find("COOKIEFILE=\"") {
                    let after_cookie = &auth_part[cookie_start + 12..];
                    if let Some(quote_end) = after_cookie.find('"') {
                        cookie_file = Some(after_cookie[..quote_end].to_string());
                    }
                }
            }
        }

        Ok(ProtocolInfo {
            auth_methods,
            cookie_file,
        })
    }

    /// Authenticate with the control port.
    pub async fn authenticate(&mut self, auth: TorAuth) -> Result<()> {
        let cmd = match auth {
            TorAuth::None => "AUTHENTICATE".to_string(),
            TorAuth::Cookie(path) => {
                let cookie = std::fs::read(&path)
                    .map_err(|e| Error::Tor(format!("failed to read cookie file: {}", e)))?;
                format!("AUTHENTICATE {}", hex::encode(cookie))
            }
            TorAuth::Password(password) => {
                format!("AUTHENTICATE \"{}\"", escape_tor_string(&password))
            }
        };

        self.command(&cmd).await?;
        self.authenticated = true;

        tracing::info!("Authenticated with Tor control port");
        Ok(())
    }

    /// Auto-authenticate using available methods.
    pub async fn authenticate_auto(&mut self) -> Result<()> {
        let info = self.get_protocol_info().await?;

        tracing::debug!("Tor auth methods: {:?}, cookie file: {:?}", info.auth_methods, info.cookie_file);

        // Try cookie auth first
        if info.auth_methods.contains(&"COOKIE".to_string())
            || info.auth_methods.contains(&"SAFECOOKIE".to_string())
        {
            // Try the path from PROTOCOLINFO first
            if let Some(cookie_path) = &info.cookie_file {
                match self.authenticate(TorAuth::Cookie(cookie_path.clone())).await {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        tracing::warn!(
                            "Cookie auth failed for {}: {}. \
                            You may need to add your user to the 'debian-tor' group: \
                            sudo usermod -a -G debian-tor $USER && newgrp debian-tor",
                            cookie_path, e
                        );
                    }
                }
            }
            // Try common cookie locations
            for path in &[
                "/run/tor/control.authcookie",
                "/var/run/tor/control.authcookie",
                "/var/lib/tor/control_auth_cookie",
            ] {
                if Path::new(path).exists() {
                    match self.authenticate(TorAuth::Cookie((*path).to_string())).await {
                        Ok(()) => return Ok(()),
                        Err(e) => {
                            tracing::debug!("Cookie auth failed for {}: {}", path, e);
                        }
                    }
                }
            }
        }

        // Try null auth
        if info.auth_methods.contains(&"NULL".to_string()) {
            return self.authenticate(TorAuth::None).await;
        }

        Err(Error::Tor(
            "Tor authentication failed. Run: sudo usermod -a -G debian-tor $USER && newgrp debian-tor".into(),
        ))
    }

    /// Add an ephemeral onion service using our Ed25519 identity.
    ///
    /// The key format for ADD_ONION with Ed25519-V3 is:
    /// ED25519-V3:<base64-encoded expanded secret key>
    ///
    /// Note: Tor expects the 64-byte expanded secret key, not the 32-byte seed.
    pub async fn add_onion(
        &mut self,
        identity: &TorIdentity,
        virtual_port: u16,
        target_port: u16,
    ) -> Result<String> {
        if !self.authenticated {
            return Err(Error::Tor("not authenticated".into()));
        }

        // Get the Ed25519 secret key bytes (seed)
        let secret_bytes = identity.secret_key_bytes();

        // Tor expects the expanded secret key (64 bytes) for ADD_ONION
        // We need to expand the 32-byte seed to 64 bytes using SHA-512
        let expanded = expand_ed25519_secret_key(&secret_bytes);
        let key_b64 = BASE64.encode(&expanded);

        let cmd = format!(
            "ADD_ONION ED25519-V3:{} Port={},127.0.0.1:{}",
            key_b64, virtual_port, target_port
        );

        let response = self.command(&cmd).await?;

        // Parse response for ServiceID
        let mut service_id = None;
        for line in &response {
            if let Some(id) = line.strip_prefix("ServiceID=") {
                service_id = Some(id.to_string());
            }
        }

        let service_id = service_id.ok_or_else(|| Error::Tor("no ServiceID in response".into()))?;

        // Verify it matches our expected onion address
        let expected_hostname = identity.onion_address().hostname();
        if service_id != expected_hostname {
            tracing::warn!(
                expected = %expected_hostname,
                got = %service_id,
                "Onion address mismatch - Tor generated different address"
            );
        }

        tracing::info!(
            service_id = %service_id,
            virtual_port = virtual_port,
            target_port = target_port,
            "Created onion service"
        );

        Ok(service_id)
    }

    /// Remove an onion service.
    pub async fn del_onion(&mut self, service_id: &str) -> Result<()> {
        if !self.authenticated {
            return Err(Error::Tor("not authenticated".into()));
        }

        self.command(&format!("DEL_ONION {}", service_id)).await?;

        tracing::info!(service_id = %service_id, "Removed onion service");
        Ok(())
    }

    /// Get Tor version and other info.
    pub async fn get_version(&mut self) -> Result<String> {
        let lines = self.command("GETINFO version").await?;
        for line in lines {
            if let Some(version) = line.strip_prefix("version=") {
                return Ok(version.to_string());
            }
        }
        Err(Error::Tor("version not found in response".into()))
    }

    /// Check if Tor has established circuits (is ready for connections).
    pub async fn is_ready(&mut self) -> Result<bool> {
        let lines = self
            .command("GETINFO status/circuit-established")
            .await?;
        for line in lines {
            if line.contains("circuit-established=1") {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Wait for Tor to be ready (circuits established).
    pub async fn wait_ready(&mut self, timeout: std::time::Duration) -> Result<()> {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if self.is_ready().await? {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        Err(Error::Timeout)
    }

    /// Signal Tor (e.g., NEWNYM for new circuit).
    pub async fn signal(&mut self, signal: &str) -> Result<()> {
        if !self.authenticated {
            return Err(Error::Tor("not authenticated".into()));
        }

        self.command(&format!("SIGNAL {}", signal)).await?;
        Ok(())
    }
}

/// Information from PROTOCOLINFO response.
#[derive(Debug)]
pub struct ProtocolInfo {
    /// Available authentication methods.
    pub auth_methods: Vec<String>,
    /// Path to control port cookie file for authentication.
    pub cookie_file: Option<String>,
}

/// Expand Ed25519 32-byte seed to 64-byte expanded secret key.
///
/// Tor's ADD_ONION expects the expanded key format:
/// - First 32 bytes: clamped scalar
/// - Last 32 bytes: prefix for signing
fn expand_ed25519_secret_key(seed: &[u8; 32]) -> [u8; 64] {
    use sha2::{Digest, Sha512};

    let hash = Sha512::digest(seed);
    let mut expanded = [0u8; 64];
    expanded.copy_from_slice(&hash);

    // Clamp the scalar (first 32 bytes) per Ed25519 spec
    expanded[0] &= 248;
    expanded[31] &= 127;
    expanded[31] |= 64;

    expanded
}

/// Escape a string for Tor control protocol.
fn escape_tor_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_tor_string() {
        assert_eq!(escape_tor_string("hello"), "hello");
        assert_eq!(escape_tor_string("hello\"world"), "hello\\\"world");
        assert_eq!(escape_tor_string("a\\b"), "a\\\\b");
    }

    #[test]
    fn test_expand_secret_key() {
        let seed = [0u8; 32];
        let expanded = expand_ed25519_secret_key(&seed);
        assert_eq!(expanded.len(), 64);
        // Check clamping
        assert_eq!(expanded[0] & 7, 0); // Low 3 bits cleared
        assert_eq!(expanded[31] & 128, 0); // High bit cleared
        assert_eq!(expanded[31] & 64, 64); // Bit 6 set
    }
}
