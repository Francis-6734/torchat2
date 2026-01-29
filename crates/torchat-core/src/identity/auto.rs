//! Automatic identity management.
//!
//! Generates and stores identity automatically on first run,
//! using device-specific entropy for the encryption key.

use crate::error::{Error, Result};
use crate::identity::{generate_identity, TorIdentity};
use crate::storage::{derive_db_key, Database, DatabaseConfig};
use std::path::Path;
use zeroize::Zeroizing;

/// Device key derivation salt.
const DEVICE_KEY_SALT: &[u8] = b"torchat2-device-key-v1";

/// Auto-identity manager for automatic setup.
pub struct AutoIdentity {
    /// Data directory path.
    data_dir: String,
    /// Database instance.
    db: Option<Database>,
    /// Loaded identity.
    identity: Option<TorIdentity>,
}

impl AutoIdentity {
    /// Create a new auto-identity manager.
    pub fn new(data_dir: impl Into<String>) -> Self {
        Self {
            data_dir: data_dir.into(),
            db: None,
            identity: None,
        }
    }

    /// Get or create identity automatically.
    ///
    /// On first run, generates a new identity and stores it.
    /// On subsequent runs, loads the existing identity.
    ///
    /// Uses device-specific key derivation (machine ID + data dir).
    pub fn get_or_create(&mut self) -> Result<&TorIdentity> {
        if self.identity.is_some() {
            return Ok(self.identity.as_ref().ok_or_else(|| Error::Identity("no identity".into()))?);
        }

        // Create data directory if needed
        std::fs::create_dir_all(&self.data_dir)
            .map_err(|e| Error::Storage(format!("failed to create data dir: {}", e)))?;

        let db_path = format!("{}/torchat.db", self.data_dir);
        let key = self.derive_device_key()?;

        let config = DatabaseConfig {
            path: db_path.clone(),
            in_memory: false,
        };

        // Check if identity exists
        let is_new = !Path::new(&db_path).exists();

        let db = Database::open(&config, &key[..])?;

        if is_new {
            // Generate new identity
            let identity = generate_identity()?;

            tracing::info!(
                onion_address = %identity.onion_address(),
                "Generated new TorChat identity"
            );

            db.store_identity(&identity)?;
            self.identity = Some(identity);
        } else {
            // Load existing identity
            let identity = db.load_identity()?
                .ok_or_else(|| Error::Identity("no identity in database".into()))?;

            tracing::info!(
                onion_address = %identity.onion_address(),
                "Loaded existing TorChat identity"
            );

            self.identity = Some(identity);
        }

        self.db = Some(db);

        Ok(self.identity.as_ref().ok_or_else(|| Error::Identity("no identity".into()))?)
    }

    /// Get the identity if loaded.
    pub fn identity(&self) -> Option<&TorIdentity> {
        self.identity.as_ref()
    }

    /// Get the database if opened.
    pub fn database(&self) -> Option<&Database> {
        self.db.as_ref()
    }

    /// Check if identity exists without loading.
    pub fn exists(&self) -> bool {
        let db_path = format!("{}/torchat.db", self.data_dir);
        Path::new(&db_path).exists()
    }

    /// Get the device-specific encryption key for this data directory.
    ///
    /// This can be used to open additional database connections with the same key.
    pub fn get_encryption_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        self.derive_device_key()
    }

    /// Derive device-specific encryption key.
    ///
    /// Uses machine ID + data directory as entropy sources.
    fn derive_device_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        let machine_id = self.get_machine_id()?;

        // Combine machine ID with data directory for uniqueness
        let mut input = Vec::new();
        input.extend_from_slice(&machine_id);
        input.extend_from_slice(self.data_dir.as_bytes());

        let key = derive_db_key(&input, DEVICE_KEY_SALT);

        Ok(key)
    }

    /// Get machine-specific identifier.
    fn get_machine_id(&self) -> Result<Vec<u8>> {
        // Try to read machine-id from various locations
        let paths = [
            "/etc/machine-id",
            "/var/lib/dbus/machine-id",
        ];

        for path in paths {
            if let Ok(id) = std::fs::read_to_string(path) {
                let id = id.trim();
                if !id.is_empty() {
                    return Ok(id.as_bytes().to_vec());
                }
            }
        }

        // Fallback: use hostname + data dir hash
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let mut fallback = Vec::new();
        fallback.extend_from_slice(hostname.as_bytes());
        fallback.extend_from_slice(self.data_dir.as_bytes());

        // Hash it for consistent length
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(&fallback);

        Ok(hash.to_vec())
    }

    /// Reset identity (delete and regenerate).
    ///
    /// WARNING: This destroys the existing identity permanently!
    pub fn reset(&mut self) -> Result<&TorIdentity> {
        let db_path = format!("{}/torchat.db", self.data_dir);

        // Close existing connection
        self.db = None;
        self.identity = None;

        // Delete database
        if Path::new(&db_path).exists() {
            std::fs::remove_file(&db_path)
                .map_err(|e| Error::Storage(format!("failed to delete database: {}", e)))?;
        }

        // Delete WAL and SHM files if they exist
        let _ = std::fs::remove_file(format!("{}-wal", db_path));
        let _ = std::fs::remove_file(format!("{}-shm", db_path));

        // Create new identity
        self.get_or_create()
    }
}

/// Initialize TorChat with automatic identity.
///
/// This is the simplest way to start using TorChat:
/// ```ignore
/// let identity = torchat_core::identity::auto_init("~/.torchat")?;
/// println!("Your address: {}", identity.onion_address());
/// ```
pub fn auto_init(data_dir: impl Into<String>) -> Result<AutoIdentity> {
    let mut auto = AutoIdentity::new(data_dir);
    auto.get_or_create()?;
    Ok(auto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_dir() -> String {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        format!("/tmp/torchat-auto-test-{}-{}", std::process::id(), id)
    }

    #[test]
    fn test_auto_identity_new() {
        let dir = temp_dir();
        let mut auto = AutoIdentity::new(&dir);

        // Should not exist yet
        assert!(!auto.exists());

        // Get or create
        let identity = auto.get_or_create().unwrap();
        let addr1 = identity.onion_address().to_string();

        // Should exist now
        assert!(auto.exists());

        // Load again - should be same identity
        let mut auto2 = AutoIdentity::new(&dir);
        let identity2 = auto2.get_or_create().unwrap();
        let addr2 = identity2.onion_address().to_string();

        assert_eq!(addr1, addr2);

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_auto_identity_reset() {
        let dir = temp_dir();
        let mut auto = AutoIdentity::new(&dir);

        let identity1 = auto.get_or_create().unwrap();
        let addr1 = identity1.onion_address().to_string();

        // Reset creates new identity
        let identity2 = auto.reset().unwrap();
        let addr2 = identity2.onion_address().to_string();

        // Should be different
        assert_ne!(addr1, addr2);

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }
}
