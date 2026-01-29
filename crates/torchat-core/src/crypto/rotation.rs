//! Key rotation mechanism for long-term security.
//!
//! This module provides time-based key rotation to limit the impact
//! of key compromise. Keys are rotated on a configurable schedule.

use crate::error::{Error, Result};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Default key rotation period (30 days).
pub const DEFAULT_ROTATION_PERIOD: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Minimum allowed rotation period (1 day).
#[allow(dead_code)]
pub const MIN_ROTATION_PERIOD: Duration = Duration::from_secs(24 * 60 * 60);

/// Key rotation configuration.
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// How often to rotate keys.
    pub rotation_period: Duration,
    /// How long to keep old keys for decryption (key overlap period).
    pub overlap_period: Duration,
    /// Maximum number of old keys to retain.
    pub max_retained_keys: usize,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            rotation_period: DEFAULT_ROTATION_PERIOD,
            overlap_period: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            max_retained_keys: 3,
        }
    }
}

/// A versioned key with rotation metadata.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VersionedKey {
    /// The key material.
    #[zeroize(skip)] // We'll manually handle this
    key: [u8; 32],
    /// Key version (monotonically increasing).
    version: u64,
    /// When this key was created (Unix timestamp).
    created_at: u64,
    /// When this key expires (Unix timestamp).
    expires_at: u64,
}

impl VersionedKey {
    /// Create a new versioned key.
    pub fn new(key: [u8; 32], version: u64, created_at: u64, lifetime: Duration) -> Self {
        Self {
            key,
            version,
            created_at,
            expires_at: created_at + lifetime.as_secs(),
        }
    }

    /// Get the key material.
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Get the key version.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Check if this key is still valid for encryption.
    pub fn is_valid_for_encryption(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now < self.expires_at
    }

    /// Check if this key is still valid for decryption (within overlap period).
    pub fn is_valid_for_decryption(&self, overlap: Duration) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now < self.expires_at + overlap.as_secs()
    }
}

/// Key rotation manager.
pub struct KeyRotationManager {
    /// Current active key for encryption.
    current_key: Option<VersionedKey>,
    /// Previous keys retained for decryption.
    previous_keys: Vec<VersionedKey>,
    /// Rotation configuration.
    config: RotationConfig,
    /// Key derivation function for generating new keys.
    derive_key: Box<dyn Fn(u64) -> [u8; 32] + Send + Sync>,
}

impl KeyRotationManager {
    /// Create a new key rotation manager.
    pub fn new<F>(config: RotationConfig, derive_key: F) -> Self
    where
        F: Fn(u64) -> [u8; 32] + Send + Sync + 'static,
    {
        Self {
            current_key: None,
            previous_keys: Vec::new(),
            config,
            derive_key: Box::new(derive_key),
        }
    }

    /// Initialize with the first key.
    pub fn initialize(&mut self) -> Result<&VersionedKey> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Crypto("system time error".into()))?
            .as_secs();

        let version = 1;
        let key_material = (self.derive_key)(version);
        let key = VersionedKey::new(
            key_material,
            version,
            now,
            self.config.rotation_period,
        );

        self.current_key = Some(key);
        self.current_key.as_ref().ok_or(Error::Crypto("failed to initialize key".into()))
    }

    /// Get the current key for encryption, rotating if necessary.
    pub fn get_current_key(&mut self) -> Result<&VersionedKey> {
        // Check if we need to rotate
        if let Some(ref key) = self.current_key {
            if !key.is_valid_for_encryption() {
                self.rotate()?;
            }
        } else {
            return self.initialize();
        }

        self.current_key.as_ref().ok_or(Error::Crypto("no current key".into()))
    }

    /// Get a key by version for decryption.
    pub fn get_key_by_version(&self, version: u64) -> Option<&VersionedKey> {
        // Check current key
        if let Some(ref key) = self.current_key {
            if key.version == version && key.is_valid_for_decryption(self.config.overlap_period) {
                return Some(key);
            }
        }

        // Check previous keys
        self.previous_keys
            .iter()
            .find(|k| k.version == version && k.is_valid_for_decryption(self.config.overlap_period))
    }

    /// Force a key rotation.
    pub fn rotate(&mut self) -> Result<&VersionedKey> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Crypto("system time error".into()))?
            .as_secs();

        // Move current key to previous
        if let Some(old_key) = self.current_key.take() {
            self.previous_keys.push(old_key);
        }

        // Clean up expired previous keys
        self.previous_keys.retain(|k| k.is_valid_for_decryption(self.config.overlap_period));

        // Limit number of retained keys
        while self.previous_keys.len() > self.config.max_retained_keys {
            self.previous_keys.remove(0);
        }

        // Generate new key
        let new_version = self.previous_keys
            .iter()
            .map(|k| k.version)
            .max()
            .unwrap_or(0) + 1;

        let key_material = (self.derive_key)(new_version);
        let new_key = VersionedKey::new(
            key_material,
            new_version,
            now,
            self.config.rotation_period,
        );

        self.current_key = Some(new_key);
        self.current_key.as_ref().ok_or(Error::Crypto("failed to create new key".into()))
    }

    /// Get the current key version.
    pub fn current_version(&self) -> Option<u64> {
        self.current_key.as_ref().map(|k| k.version)
    }

    /// Check if rotation is needed.
    pub fn needs_rotation(&self) -> bool {
        self.current_key
            .as_ref()
            .map(|k| !k.is_valid_for_encryption())
            .unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_derive(version: u64) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = version as u8;
        key
    }

    #[test]
    fn test_key_rotation_initialization() {
        let config = RotationConfig::default();
        let mut manager = KeyRotationManager::new(config, test_derive);

        let key = manager.initialize().unwrap();
        assert_eq!(key.version(), 1);
        assert!(key.is_valid_for_encryption());
    }

    #[test]
    fn test_key_rotation_manual() {
        let config = RotationConfig::default();
        let mut manager = KeyRotationManager::new(config, test_derive);

        manager.initialize().unwrap();
        assert_eq!(manager.current_version(), Some(1));

        manager.rotate().unwrap();
        assert_eq!(manager.current_version(), Some(2));

        // Old key should still be accessible
        assert!(manager.get_key_by_version(1).is_some());
    }

    #[test]
    fn test_versioned_key_validity() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let key = VersionedKey::new([0u8; 32], 1, now, Duration::from_secs(3600));
        assert!(key.is_valid_for_encryption());
        assert!(key.is_valid_for_decryption(Duration::from_secs(3600)));

        // Expired key
        let old_key = VersionedKey::new([0u8; 32], 1, now - 7200, Duration::from_secs(3600));
        assert!(!old_key.is_valid_for_encryption());
        // But still valid for decryption within overlap
        assert!(old_key.is_valid_for_decryption(Duration::from_secs(7200)));
    }
}
