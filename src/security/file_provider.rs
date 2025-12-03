//! Encrypted file credential provider
//!
//! Stores credentials in an encrypted file using AES-256-GCM encryption
//! with PBKDF2 key derivation for secure local storage.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, OsRng};
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use sha2::Sha256;
use serde_json;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn, error};

use super::{Credential, CredentialProvider};
use base64::{Engine as _, engine::general_purpose};

/// Encrypted credential storage format
#[derive(serde::Serialize, serde::Deserialize)]
struct EncryptedCredentialStore {
    /// Version of the encryption format
    version: u32,
    /// PBKDF2 salt (base64 encoded)
    salt: String,
    /// Nonce used for encryption (base64 encoded)
    nonce: String,
    /// Encrypted credential data (base64 encoded)
    data: String,
    /// Metadata about encryption
    metadata: HashMap<String, String>,
}

/// File-based credential provider with AES-256-GCM encryption
pub struct FileCredentialProvider {
    file_path: PathBuf,
    encryption_key: [u8; 32],
}

impl FileCredentialProvider {
    /// Create a new file credential provider
    pub fn new() -> Self {
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from(".config"))
            .join("fuji");

        Self::with_path(config_dir.join("credentials.enc"))
    }

    /// Create a file credential provider with custom path
    pub fn with_path(path: PathBuf) -> Self {
        // Generate encryption key from system-specific source
        // In production, this should be derived from user password or system key
        let encryption_key = Self::derive_encryption_key();

        Self {
            file_path: path,
            encryption_key,
        }
    }

    /// Derive encryption key from system sources
    fn derive_encryption_key() -> [u8; 32] {
        // For now, use a simple hash of system info
        // In production, this should be more secure
        let mut key = [0u8; 32];
        let input = format!("{}-{}-{}",
            std::env::var("USER").unwrap_or_default(),
            std::env::var("HOME").unwrap_or_default(),
            std::env::var("HOSTNAME").unwrap_or_default()
        );

        pbkdf2_hmac::<Sha256>(
            input.as_bytes(),
            b"fuji-credential-salt",
            10000,
            &mut key,
        );

        key
    }

    /// Load the credential store from file
    async fn load_store(&self) -> Result<HashMap<String, Credential>> {
        if !self.file_path.exists() {
            return Ok(HashMap::new());
        }

        let mut file = File::open(&self.file_path).await
            .map_err(|e| anyhow!("Failed to open credential file: {}", e))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents).await
            .map_err(|e| anyhow!("Failed to read credential file: {}", e))?;

        // Parse encrypted store
        let store: EncryptedCredentialStore = serde_json::from_str(&contents)
            .map_err(|e| anyhow!("Failed to parse credential store: {}", e))?;

        // Decrypt the data
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        let salt = general_purpose::STANDARD.decode(&store.salt)
            .map_err(|e| anyhow!("Failed to decode salt: {}", e))?;
        let nonce = general_purpose::STANDARD.decode(&store.nonce)
            .map_err(|e| anyhow!("Failed to decode nonce: {}", e))?;
        let data = general_purpose::STANDARD.decode(&store.data)
            .map_err(|e| anyhow!("Failed to decode data: {}", e))?;

        let nonce = Nonce::from_slice(&nonce);
        let decrypted = cipher.decrypt(nonce, &data[..])
            .map_err(|e| anyhow!("Failed to decrypt credentials: {}", e))?;

        let json = String::from_utf8(decrypted)
            .map_err(|e| anyhow!("Failed to decode decrypted data: {}", e))?;

        serde_json::from_str(&json)
            .map_err(|e| anyhow!("Failed to parse decrypted credentials: {}", e))
    }

    /// Save the credential store to file
    async fn save_store(&self, credentials: &HashMap<String, Credential>) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = self.file_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| anyhow!("Failed to create credential directory: {}", e))?;
        }

        // Serialize credentials
        let json = serde_json::to_string(credentials)
            .map_err(|e| anyhow!("Failed to serialize credentials: {}", e))?;

        // Generate random salt and nonce
        let salt = rand::thread_rng().gen::<[u8; 32]>();
        let nonce_bytes = rand::thread_rng().gen::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the data
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        let encrypted = cipher.encrypt(nonce, json.as_bytes())
            .map_err(|e| anyhow!("Failed to encrypt credentials: {}", e))?;

        // Create encrypted store
        let store = EncryptedCredentialStore {
            version: 1,
            salt: general_purpose::STANDARD.encode(salt),
            nonce: general_purpose::STANDARD.encode(nonce_bytes),
            data: general_purpose::STANDARD.encode(encrypted),
            metadata: HashMap::new(),
        };

        // Write to temporary file first
        let temp_path = self.file_path.with_extension("tmp");
        let json = serde_json::to_string_pretty(&store)
            .map_err(|e| anyhow!("Failed to serialize store: {}", e))?;

        // Write with atomic operation
        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600) // Secure file permissions
                .open(&temp_path).await
                .map_err(|e| anyhow!("Failed to create temporary file: {}", e))?;

            file.write_all(json.as_bytes()).await
                .map_err(|e| anyhow!("Failed to write temporary file: {}", e))?;

            file.sync_all().await
                .map_err(|e| anyhow!("Failed to sync temporary file: {}", e))?;
        }

        // Atomic rename
        tokio::fs::rename(&temp_path, &self.file_path).await
            .map_err(|e| anyhow!("Failed to rename credential file: {}", e))?;

        debug!("Saved {} credentials to encrypted file", credentials.len());
        Ok(())
    }
}

#[async_trait]
impl CredentialProvider for FileCredentialProvider {
    async fn store_credential(&self, mount_id: &str, credential: &Credential) -> Result<()> {
        let mut credentials = self.load_store().await?;
        credentials.insert(mount_id.to_string(), credential.clone());
        self.save_store(&credentials).await?;
        debug!("Stored credential for {} in encrypted file", mount_id);
        Ok(())
    }

    async fn get_credential(&self, mount_id: &str) -> Result<Option<Credential>> {
        let credentials = self.load_store().await?;
        let credential = credentials.get(mount_id).cloned();
        debug!("Retrieved credential for {} from encrypted file: {}",
               mount_id, credential.is_some());
        Ok(credential)
    }

    async fn delete_credential(&self, mount_id: &str) -> Result<()> {
        let mut credentials = self.load_store().await?;
        credentials.remove(mount_id);
        self.save_store(&credentials).await?;
        debug!("Deleted credential for {} from encrypted file", mount_id);
        Ok(())
    }

    async fn list_credentials(&self) -> Result<Vec<String>> {
        let credentials = self.load_store().await?;
        Ok(credentials.into_keys().collect())
    }

    async fn has_credential(&self, mount_id: &str) -> Result<bool> {
        let credentials = self.load_store().await?;
        Ok(credentials.contains_key(mount_id))
    }

    fn provider_name(&self) -> &'static str {
        "file"
    }
}

impl Default for FileCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_file_provider_encryption() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_credentials.enc");
        let provider = FileCredentialProvider::with_path(file_path);

        let credential = Credential {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            domain: Some("TESTDOMAIN".to_string()),
            metadata: Default::default(),
        };

        // Store credential
        provider.store_credential("test-mount", &credential).await.unwrap();

        // Retrieve credential
        let retrieved = provider.get_credential("test-mount").await.unwrap();
        assert!(retrieved.is_some());

        let retrieved = retrieved.unwrap();
        assert_eq!(credential.username, retrieved.username);
        assert_eq!(credential.password, retrieved.password);
        assert_eq!(credential.domain, retrieved.domain);

        // List credentials
        let list = provider.list_credentials().await.unwrap();
        assert_eq!(list.len(), 1);
        assert!(list.contains(&"test-mount".to_string()));

        // Delete credential
        provider.delete_credential("test-mount").await.unwrap();

        // Check that it's gone
        assert!(!provider.has_credential("test-mount").await.unwrap());
        let list = provider.list_credentials().await.unwrap();
        assert_eq!(list.len(), 0);
    }
}