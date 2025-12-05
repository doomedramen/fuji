//! Credential backup and recovery system
//!
//! This module provides secure backup and recovery capabilities for credentials,
//! supporting multiple backup strategies including encrypted local storage,
//! remote backup services, and recovery key generation.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{info, warn};

// Import encryption types and credential types
use super::encryption::{create_encryptor, EncryptedData, EncryptionAlgorithm};
use super::hardware_credential_provider::EnhancedCredential;

/// Backup strategy for credential storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupStrategy {
    /// Local encrypted file backup
    LocalEncrypted { path: PathBuf },
    /// Remote backup service
    RemoteService {
        endpoint: String,
        auth_token: String,
    },
    /// Cloud storage backup
    CloudStorage {
        provider: String,
        bucket: String,
        credentials: String,
    },
    /// Recovery key based backup
    RecoveryKey {
        key_id: String,
        encrypted_shares: Vec<String>,
    },
}

/// Backup metadata for tracking backup operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    /// Backup ID
    pub backup_id: String,
    /// Timestamp when backup was created
    pub created_at: SystemTime,
    /// Backup strategy used
    pub strategy: BackupStrategy,
    /// Number of credentials backed up
    pub credential_count: u32,
    /// Backup size in bytes
    pub backup_size: u64,
    /// Checksum for integrity verification
    pub checksum: String,
    /// Encryption algorithm used
    pub encryption_algorithm: String,
    /// Compression flag
    pub compressed: bool,
    /// Backup version
    pub version: u32,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Recovery key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryKey {
    /// Key ID
    pub key_id: String,
    /// Encrypted master key
    pub encrypted_master_key: String,
    /// Key generation timestamp
    pub generated_at: SystemTime,
    /// Key expiration
    pub expires_at: Option<SystemTime>,
    /// Shamir secret shares (if using Shamir secret sharing)
    pub secret_shares: Vec<SecretShare>,
    /// Key metadata
    pub metadata: HashMap<String, String>,
}

/// Shamir secret share for distributed recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretShare {
    /// Share ID
    pub share_id: u8,
    /// Total number of shares required
    pub threshold: u8,
    /// Total number of shares generated
    pub total_shares: u8,
    /// Share data
    pub share_data: String,
    /// Share creation timestamp
    pub created_at: SystemTime,
}

/// Credential backup manager
pub struct CredentialBackupManager {
    /// Default backup strategy
    default_strategy: BackupStrategy,
    /// Backup metadata storage
    backup_metadata: Arc<RwLock<HashMap<String, BackupMetadata>>>,
    /// Recovery key storage
    recovery_keys: Arc<RwLock<HashMap<String, RecoveryKey>>>,
    /// Encryption algorithm for backups
    encryption_algorithm: EncryptionAlgorithm,
    /// Maximum number of backup versions to keep
    max_backup_versions: u32,
    /// Compression enabled flag
    compression_enabled: bool,
}

#[allow(dead_code)]
impl CredentialBackupManager {
    /// Create a new backup manager with default strategy
    pub fn new(default_strategy: BackupStrategy) -> Self {
        Self {
            default_strategy,
            backup_metadata: Arc::new(RwLock::new(HashMap::new())),
            recovery_keys: Arc::new(RwLock::new(HashMap::new())),
            encryption_algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            max_backup_versions: 10,
            compression_enabled: true,
        }
    }

    /// Create backup of enhanced credentials
    pub async fn create_backup(
        &self,
        credentials: &HashMap<String, EnhancedCredential>,
        strategy: Option<BackupStrategy>,
    ) -> Result<String> {
        let backup_strategy = strategy.unwrap_or_else(|| self.default_strategy.clone());
        let backup_id = self.generate_backup_id();

        // Serialize credentials
        let serialized = serde_json::to_vec(credentials)?;

        // Compress if enabled
        let data = if self.compression_enabled {
            self.compress_data(&serialized)?
        } else {
            serialized
        };

        // Encrypt data
        let encrypted_data = self.encrypt_backup_data(&data, &backup_strategy).await?;

        // Store backup based on strategy
        let backup_size = match &backup_strategy {
            BackupStrategy::LocalEncrypted { path } => {
                self.store_local_encrypted_backup(path, &backup_id, &encrypted_data)
                    .await?
            }
            BackupStrategy::RemoteService {
                endpoint,
                auth_token,
            } => {
                self.store_remote_backup(endpoint, auth_token, &backup_id, &encrypted_data)
                    .await?
            }
            BackupStrategy::CloudStorage {
                provider,
                bucket,
                credentials,
            } => {
                self.store_cloud_backup(provider, bucket, credentials, &backup_id, &encrypted_data)
                    .await?
            }
            BackupStrategy::RecoveryKey {
                key_id,
                encrypted_shares,
            } => {
                self.store_recovery_key_backup(
                    key_id,
                    encrypted_shares,
                    &backup_id,
                    &encrypted_data,
                )
                .await?
            }
        };

        // Calculate checksum
        let checksum = self.calculate_checksum(&encrypted_data)?;

        // Create metadata
        let metadata = BackupMetadata {
            backup_id: backup_id.clone(),
            created_at: SystemTime::now(),
            strategy: backup_strategy.clone(),
            credential_count: credentials.len() as u32,
            backup_size,
            checksum,
            encryption_algorithm: self.encryption_algorithm.identifier().to_string(),
            compressed: self.compression_enabled,
            version: 1,
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("creator".to_string(), "fuji-credential-backup".to_string());
                meta.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
                meta
            },
        };

        // Store metadata
        {
            let mut metadata_store = self.backup_metadata.write().await;
            metadata_store.insert(backup_id.clone(), metadata.clone());
        }

        // Clean up old backups
        self.cleanup_old_backups().await?;

        info!(
            "Created backup {} with {} credentials",
            backup_id,
            credentials.len()
        );
        Ok(backup_id)
    }

    /// Restore credentials from backup
    pub async fn restore_backup(
        &self,
        backup_id: &str,
    ) -> Result<HashMap<String, EnhancedCredential>> {
        // Get backup metadata
        let metadata = {
            let metadata_store = self.backup_metadata.read().await;
            metadata_store
                .get(backup_id)
                .ok_or_else(|| anyhow!("Backup metadata not found: {}", backup_id))?
                .clone()
        };

        // Retrieve encrypted backup data
        let encrypted_data = match &metadata.strategy {
            BackupStrategy::LocalEncrypted { path } => {
                self.retrieve_local_encrypted_backup(path, backup_id)
                    .await?
            }
            BackupStrategy::RemoteService {
                endpoint,
                auth_token,
            } => {
                self.retrieve_remote_backup(endpoint, auth_token, backup_id)
                    .await?
            }
            BackupStrategy::CloudStorage {
                provider,
                bucket,
                credentials,
            } => {
                self.retrieve_cloud_backup(provider, bucket, credentials, backup_id)
                    .await?
            }
            BackupStrategy::RecoveryKey {
                key_id,
                encrypted_shares,
            } => {
                self.retrieve_recovery_key_backup(key_id, encrypted_shares, backup_id)
                    .await?
            }
        };

        // Verify checksum
        let expected_checksum = self.calculate_checksum(&encrypted_data)?;
        if expected_checksum != metadata.checksum {
            return Err(anyhow!("Backup checksum mismatch: possible corruption"));
        }

        // Decrypt data
        let decrypted_data = self
            .decrypt_backup_data(&encrypted_data, &metadata.strategy)
            .await?;

        // Decompress if needed
        let data = if metadata.compressed {
            self.decompress_data(&decrypted_data)?
        } else {
            decrypted_data
        };

        // Deserialize credentials
        let credentials: HashMap<String, EnhancedCredential> = serde_json::from_slice(&data)?;

        info!(
            "Restored {} credentials from backup {}",
            credentials.len(),
            backup_id
        );
        Ok(credentials)
    }

    /// Generate recovery key for backup restoration
    pub async fn generate_recovery_key(
        &self,
        threshold: u8,
        total_shares: u8,
    ) -> Result<RecoveryKey> {
        if threshold > total_shares {
            return Err(anyhow!("Threshold cannot be greater than total shares"));
        }

        let key_id = self.generate_key_id();

        // Generate master recovery key
        let master_key = self.generate_secure_key(32)?;

        // Split master key using Shamir's Secret Sharing
        let secret_shares = self.split_secret(&master_key, threshold, total_shares)?;

        // Encrypt master key for storage
        let encrypted_master_key = self.encrypt_recovery_key(&master_key).await?;

        let recovery_key = RecoveryKey {
            key_id: key_id.clone(),
            encrypted_master_key,
            generated_at: SystemTime::now(),
            expires_at: None, // Recovery keys don't expire by default
            secret_shares,
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("threshold".to_string(), threshold.to_string());
                meta.insert("total_shares".to_string(), total_shares.to_string());
                meta.insert("algorithm".to_string(), "shamir-secret-sharing".to_string());
                meta
            },
        };

        // Store recovery key
        {
            let mut recovery_key_store = self.recovery_keys.write().await;
            recovery_key_store.insert(key_id.clone(), recovery_key.clone());
        }

        info!(
            "Generated recovery key {} with {} of {} shares",
            key_id, threshold, total_shares
        );
        Ok(recovery_key)
    }

    /// Restore from recovery key shares
    pub async fn restore_from_recovery_shares(&self, shares: &[SecretShare]) -> Result<Vec<u8>> {
        if shares.is_empty() {
            return Err(anyhow!("No shares provided for recovery"));
        }

        let threshold = shares[0].threshold;
        if shares.len() < threshold as usize {
            return Err(anyhow!(
                "Insufficient shares: need {}, got {}",
                threshold,
                shares.len()
            ));
        }

        // Reconstruct master key from shares
        let master_key = self.reconstruct_secret(shares)?;

        // Find and decrypt backup using master key
        // Implementation would locate the backup encrypted with this recovery key
        info!(
            "Successfully reconstructed master key from {} shares",
            shares.len()
        );
        Ok(master_key)
    }

    /// List all available backups
    pub async fn list_backups(&self) -> Vec<BackupMetadata> {
        let metadata_store = self.backup_metadata.read().await;
        metadata_store.values().cloned().collect()
    }

    /// Delete a backup
    pub async fn delete_backup(&self, backup_id: &str) -> Result<()> {
        // Get backup metadata
        let metadata = {
            let metadata_store = self.backup_metadata.read().await;
            match metadata_store.get(backup_id) {
                Some(meta) => meta.clone(),
                None => return Err(anyhow!("Backup not found: {}", backup_id)),
            }
        };

        // Delete backup data based on strategy
        match &metadata.strategy {
            BackupStrategy::LocalEncrypted { path } => {
                self.delete_local_encrypted_backup(path, backup_id).await?;
            }
            BackupStrategy::RemoteService {
                endpoint,
                auth_token,
            } => {
                self.delete_remote_backup(endpoint, auth_token, backup_id)
                    .await?;
            }
            BackupStrategy::CloudStorage {
                provider,
                bucket,
                credentials,
            } => {
                self.delete_cloud_backup(provider, bucket, credentials, backup_id)
                    .await?;
            }
            BackupStrategy::RecoveryKey {
                key_id,
                encrypted_shares,
            } => {
                self.delete_recovery_key_backup(key_id, encrypted_shares, backup_id)
                    .await?;
            }
        }

        // Remove metadata
        {
            let mut metadata_store = self.backup_metadata.write().await;
            metadata_store.remove(backup_id);
        }

        info!("Deleted backup: {}", backup_id);
        Ok(())
    }

    /// Validate backup integrity
    pub async fn validate_backup(&self, backup_id: &str) -> Result<bool> {
        // Get backup metadata
        let metadata = {
            let metadata_store = self.backup_metadata.read().await;
            match metadata_store.get(backup_id) {
                Some(meta) => meta.clone(),
                None => return Err(anyhow!("Backup not found: {}", backup_id)),
            }
        };

        // Retrieve backup data
        let encrypted_data = match &metadata.strategy {
            BackupStrategy::LocalEncrypted { path } => {
                self.retrieve_local_encrypted_backup(path, backup_id)
                    .await?
            }
            _ => {
                warn!("Backup validation only supported for local encrypted backups");
                return Ok(false);
            }
        };

        // Verify checksum
        let expected_checksum = self.calculate_checksum(&encrypted_data)?;
        Ok(expected_checksum == metadata.checksum)
    }

    // Private helper methods

    fn generate_backup_id(&self) -> String {
        use uuid::Uuid;
        format!("backup_{}", Uuid::new_v4())
    }

    fn generate_key_id(&self) -> String {
        use uuid::Uuid;
        format!("recovery_key_{}", Uuid::new_v4())
    }

    fn compress_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Use flate2 or other compression library
        // For now, return data uncompressed
        Ok(data.to_vec())
    }

    fn decompress_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Decompress data using appropriate algorithm
        // For now, return data as-is
        Ok(data.to_vec())
    }

    async fn encrypt_backup_data(&self, data: &[u8], strategy: &BackupStrategy) -> Result<Vec<u8>> {
        let encryptor = create_encryptor(self.encryption_algorithm);
        let key = self.get_backup_encryption_key(strategy).await?;
        let encrypted = encryptor.encrypt(data, &key)?;
        Ok(serde_json::to_vec(&encrypted)?)
    }

    async fn decrypt_backup_data(&self, data: &[u8], strategy: &BackupStrategy) -> Result<Vec<u8>> {
        let encrypted: EncryptedData = serde_json::from_slice(data)?;
        let encryptor = create_encryptor(self.encryption_algorithm);
        let key = self.get_backup_encryption_key(strategy).await?;
        encryptor.decrypt(&encrypted, &key).map_err(|e| e.into())
    }

    async fn get_backup_encryption_key(&self, strategy: &BackupStrategy) -> Result<Vec<u8>> {
        match strategy {
            BackupStrategy::LocalEncrypted { .. } => {
                // Derive key from system-specific data
                self.derive_system_key()
            }
            BackupStrategy::RemoteService { auth_token, .. } => {
                // Derive key from auth token
                self.derive_key_from_token(auth_token)
            }
            BackupStrategy::CloudStorage { credentials, .. } => {
                // Derive key from cloud credentials
                self.derive_key_from_token(credentials)
            }
            BackupStrategy::RecoveryKey { key_id, .. } => {
                // Get recovery key
                let recovery_key_store = self.recovery_keys.read().await;
                if let Some(recovery_key) = recovery_key_store.get(key_id) {
                    self.decrypt_recovery_key(&recovery_key.encrypted_master_key)
                        .await
                } else {
                    Err(anyhow!("Recovery key not found: {}", key_id))
                }
            }
        }
    }

    fn calculate_checksum(&self, data: &[u8]) -> Result<String> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        Ok(hex::encode(hasher.finalize()))
    }

    async fn cleanup_old_backups(&self) -> Result<()> {
        let metadata_store = self.backup_metadata.read().await;
        let mut backups_by_strategy: HashMap<String, Vec<_>> = HashMap::new();

        // Group backups by strategy
        for (backup_id, metadata) in metadata_store.iter() {
            let strategy_key = match &metadata.strategy {
                BackupStrategy::LocalEncrypted { path } => format!("local:{}", path.display()),
                BackupStrategy::RemoteService { endpoint, .. } => format!("remote:{}", endpoint),
                BackupStrategy::CloudStorage {
                    provider, bucket, ..
                } => format!("cloud:{}:{}", provider, bucket),
                BackupStrategy::RecoveryKey { key_id, .. } => format!("recovery:{}", key_id),
            };

            backups_by_strategy
                .entry(strategy_key)
                .or_insert_with(Vec::new)
                .push((backup_id.clone(), metadata.created_at));
        }

        drop(metadata_store);

        // Clean up old backups per strategy
        for (_strategy_key, backups) in backups_by_strategy {
            if backups.len() > self.max_backup_versions as usize {
                // Sort by creation time (oldest first)
                let mut sorted_backups = backups;
                sorted_backups.sort_by(|a, b| a.1.cmp(&b.1));

                // Delete oldest backups
                let to_delete = sorted_backups.len() - self.max_backup_versions as usize;
                for (backup_id, _) in sorted_backups.into_iter().take(to_delete) {
                    if let Err(e) = self.delete_backup(&backup_id).await {
                        warn!("Failed to delete old backup {}: {}", backup_id, e);
                    }
                }
            }
        }

        Ok(())
    }

    // Placeholder methods for actual implementations
    async fn store_local_encrypted_backup(
        &self,
        _path: &PathBuf,
        backup_id: &str,
        data: &[u8],
    ) -> Result<u64> {
        // Ensure the backup directory exists
        fs::create_dir_all(_path).await?;

        let backup_path = _path.join(format!("{}.backup", backup_id));
        fs::write(&backup_path, data).await?;
        Ok(data.len() as u64)
    }

    async fn retrieve_local_encrypted_backup(
        &self,
        path: &PathBuf,
        backup_id: &str,
    ) -> Result<Vec<u8>> {
        let backup_path = path.join(format!("{}.backup", backup_id));
        Ok(fs::read(&backup_path).await?)
    }

    async fn delete_local_encrypted_backup(&self, path: &PathBuf, _backup_id: &str) -> Result<()> {
        let backup_path = path.join(format!("{}.backup", _backup_id));
        fs::remove_file(&backup_path).await?;
        Ok(())
    }

    async fn store_remote_backup(
        &self,
        _endpoint: &str,
        _auth_token: &str,
        _backup_id: &str,
        data: &[u8],
    ) -> Result<u64> {
        warn!("Remote backup storage not implemented");
        Ok(data.len() as u64)
    }

    async fn retrieve_remote_backup(
        &self,
        _endpoint: &str,
        _auth_token: &str,
        _backup_id: &str,
    ) -> Result<Vec<u8>> {
        Err(anyhow!("Remote backup retrieval not implemented"))
    }

    async fn delete_remote_backup(
        &self,
        _endpoint: &str,
        _auth_token: &str,
        _backup_id: &str,
    ) -> Result<()> {
        warn!("Remote backup deletion not implemented");
        Ok(())
    }

    async fn store_cloud_backup(
        &self,
        _provider: &str,
        _bucket: &str,
        _credentials: &str,
        _backup_id: &str,
        data: &[u8],
    ) -> Result<u64> {
        warn!("Cloud backup storage not implemented");
        Ok(data.len() as u64)
    }

    async fn retrieve_cloud_backup(
        &self,
        _provider: &str,
        _bucket: &str,
        _credentials: &str,
        _backup_id: &str,
    ) -> Result<Vec<u8>> {
        Err(anyhow!("Cloud backup retrieval not implemented"))
    }

    async fn delete_cloud_backup(
        &self,
        _provider: &str,
        _bucket: &str,
        _credentials: &str,
        _backup_id: &str,
    ) -> Result<()> {
        warn!("Cloud backup deletion not implemented");
        Ok(())
    }

    async fn store_recovery_key_backup(
        &self,
        __key_id: &str,
        _encrypted_shares: &[String],
        _backup_id: &str,
        data: &[u8],
    ) -> Result<u64> {
        warn!("Recovery key backup storage not implemented");
        Ok(data.len() as u64)
    }

    async fn retrieve_recovery_key_backup(
        &self,
        __key_id: &str,
        _encrypted_shares: &[String],
        _backup_id: &str,
    ) -> Result<Vec<u8>> {
        Err(anyhow!("Recovery key backup retrieval not implemented"))
    }

    async fn delete_recovery_key_backup(
        &self,
        __key_id: &str,
        _encrypted_shares: &[String],
        _backup_id: &str,
    ) -> Result<()> {
        warn!("Recovery key backup deletion not implemented");
        Ok(())
    }

    fn derive_system_key(&self) -> Result<Vec<u8>> {
        use std::env;
        let hostname = hostname::get().unwrap_or_else(|_| "localhost".into());
        let username = env::var("USER").unwrap_or_else(|_| "user".to_string());
        let combined = format!("{}:{}:fuji-backup", hostname.to_string_lossy(), username);

        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
            combined.as_bytes(),
            b"fuji-backup-salt",
            100_000,
            &mut key,
        );
        Ok(key.to_vec())
    }

    fn derive_key_from_token(&self, token: &str) -> Result<Vec<u8>> {
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
            token.as_bytes(),
            b"fuji-backup-token",
            100_000,
            &mut key,
        );
        Ok(key.to_vec())
    }

    fn generate_secure_key(&self, length: usize) -> Result<Vec<u8>> {
        let mut key = vec![0u8; length];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Ok(key)
    }

    fn split_secret(
        &self,
        secret: &[u8],
        threshold: u8,
        total_shares: u8,
    ) -> Result<Vec<SecretShare>> {
        // Placeholder for Shamir's Secret Sharing implementation
        let mut shares = Vec::new();
        for i in 1..=total_shares {
            shares.push(SecretShare {
                share_id: i,
                threshold,
                total_shares,
                share_data: hex::encode(secret), // Simplified - should actually split the secret
                created_at: SystemTime::now(),
            });
        }
        Ok(shares)
    }

    fn reconstruct_secret(&self, shares: &[SecretShare]) -> Result<Vec<u8>> {
        // Placeholder for Shamir's Secret Sharing reconstruction
        if shares.is_empty() {
            return Err(anyhow!("No shares provided"));
        }
        hex::decode(&shares[0].share_data).map_err(|e| anyhow!("Failed to decode share: {}", e))
    }

    async fn encrypt_recovery_key(&self, key: &[u8]) -> Result<String> {
        // Simple base64 encoding for now - should be properly encrypted
        Ok(general_purpose::STANDARD.encode(key))
    }

    async fn decrypt_recovery_key(&self, encrypted_key: &str) -> Result<Vec<u8>> {
        // Simple base64 decoding for now - should be properly decrypted
        general_purpose::STANDARD
            .decode(encrypted_key)
            .map_err(|e| anyhow!("Failed to decode recovery key: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{
        hardware_credential_provider::{EnhancedCredential, KeyDerivationParams, SecurityMetadata},
        Credential,
    };
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_backup_creation() {
        let strategy = BackupStrategy::LocalEncrypted {
            path: PathBuf::from("/tmp/test_backups"),
        };
        let manager = CredentialBackupManager::new(strategy);

        // Create test credentials
        let mut credentials = HashMap::new();
        credentials.insert(
            "test_mount".to_string(),
            EnhancedCredential {
                credential: Credential {
                    username: "testuser".to_string(),
                    password: "testpass".to_string(),
                    domain: Some("TESTDOMAIN".to_string()),
                    metadata: HashMap::new(),
                },
                version: 1,
                created_at: SystemTime::now(),
                expires_at: None,
                last_rotated: Some(SystemTime::now()),
                security_metadata: SecurityMetadata {
                    integrity_hash: "test_hash".to_string(),
                    kdf_params: KeyDerivationParams {
                        iterations: 100_000,
                        salt: vec![1, 2, 3, 4],
                        key_length: 32,
                        memory_cost: None,
                        parallelism: Some(4),
                    },
                    encryption_algorithm: "chacha20-poly1305".to_string(),
                    mfa_required: false,
                    access_restrictions: HashMap::new(),
                    audit_log_ids: vec![],
                },
            },
        );

        // Create backup
        let backup_id = manager.create_backup(&credentials, None).await.unwrap();
        assert!(!backup_id.is_empty());

        // Verify backup exists
        let backups = manager.list_backups().await;
        assert_eq!(backups.len(), 1);
        assert_eq!(backups[0].backup_id, backup_id);
    }

    #[tokio::test]
    async fn test_recovery_key_generation() {
        let strategy = BackupStrategy::LocalEncrypted {
            path: PathBuf::from("/tmp/test_backups"),
        };
        let manager = CredentialBackupManager::new(strategy);

        // Generate recovery key
        let recovery_key = manager.generate_recovery_key(3, 5).await.unwrap();
        assert_eq!(recovery_key.secret_shares.len(), 5);
        assert_eq!(recovery_key.secret_shares[0].threshold, 3);
    }

    #[tokio::test]
    async fn test_backup_validation() {
        let strategy = BackupStrategy::LocalEncrypted {
            path: PathBuf::from("/tmp/test_backups"),
        };
        let manager = CredentialBackupManager::new(strategy);

        let credentials = HashMap::new();
        let backup_id = manager.create_backup(&credentials, None).await.unwrap();

        // Validate backup
        let is_valid = manager.validate_backup(&backup_id).await.unwrap();
        assert!(is_valid);

        // Cleanup
        manager.delete_backup(&backup_id).await.unwrap();
    }
}
