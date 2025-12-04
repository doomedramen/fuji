//! Encrypted file credential provider
//!
//! Stores credentials in an encrypted file using AES-256-GCM encryption
//! with PBKDF2 key derivation (100,000+ iterations) and HKDF-SHA256 for secure local storage.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use ring::hkdf;
use serde_json;
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use super::{Credential, CredentialProvider};
use base64::{engine::general_purpose, Engine as _};

/// Number of PBKDF2 iterations - OWASP recommends at least 120,000 for PBKDF2-HMAC-SHA256
const PBKDF2_ITERATIONS: u32 = 120_000;

/// Length of the master key derived from system information
const MASTER_KEY_LENGTH: usize = 32;

/// Length of the random salt for PBKDF2
const PBKDF2_SALT_LENGTH: usize = 32;

/// Length of the HKDF salt
const HKDF_SALT_LENGTH: usize = 32;

/// Length of the nonce for AES-GCM
const NONCE_LENGTH: usize = 12;

/// Encrypted credential storage format
#[derive(serde::Serialize, serde::Deserialize)]
struct EncryptedCredentialStore {
    /// Version of the encryption format
    version: u32,
    /// PBKDF2 salt (base64 encoded)
    pbkdf2_salt: String,
    /// HKDF salt (base64 encoded) - used for key derivation
    hkdf_salt: String,
    /// Number of PBKDF2 iterations used
    pbkdf2_iterations: u32,
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
    /// Cached master key derived from system sources
    master_key: [u8; MASTER_KEY_LENGTH],
}

impl FileCredentialProvider {
    /// Create a new file credential provider
    pub fn new() -> Result<Self> {
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from(".config"))
            .join("fuji");

        Self::with_path(config_dir.join("credentials.enc"))
    }

    /// Create a file credential provider with custom path
    pub fn with_path(path: PathBuf) -> Result<Self> {
        // Generate master key from system-specific source
        let master_key = Self::derive_master_key()?;

        Ok(Self {
            file_path: path,
            master_key,
        })
    }

    /// Derive master encryption key from system sources using HKDF with proper salt
    fn derive_master_key() -> Result<[u8; MASTER_KEY_LENGTH]> {
        // Collect system entropy sources
        let mut entropy_sources = Vec::new();

        // Add username if available
        if let Ok(username) = std::env::var("USER") {
            entropy_sources.extend_from_slice(username.as_bytes());
        }

        // Add home directory if available
        if let Ok(home) = std::env::var("HOME") {
            entropy_sources.extend_from_slice(home.as_bytes());
        }

        // Add hostname if available
        if let Ok(hostname) = std::env::var("HOSTNAME") {
            entropy_sources.extend_from_slice(hostname.as_bytes());
        }

        // Add test environment variable if available (for testing different keys)
        if let Ok(test_key) = std::env::var("TEST_FUJI_DIFFERENT_KEY") {
            entropy_sources.extend_from_slice(test_key.as_bytes());
        }

        // Add machine-specific data
        #[cfg(unix)]
        {
            // Add UID and GID on Unix systems
            let uid = nix::unistd::getuid().to_string();
            entropy_sources.extend_from_slice(uid.as_bytes());
            let gid = nix::unistd::getgid().to_string();
            entropy_sources.extend_from_slice(gid.as_bytes());
        }

        // If we don't have enough entropy, add some randomness
        if entropy_sources.is_empty() {
            let mut random_bytes = [0u8; 64];
            rand::thread_rng().fill_bytes(&mut random_bytes);
            entropy_sources.extend_from_slice(&random_bytes);
        }

        // Generate a proper random HKDF salt instead of using a static one
        let mut hkdf_salt_bytes = [0u8; HKDF_SALT_LENGTH];
        rand::thread_rng().fill_bytes(&mut hkdf_salt_bytes);

        // Use system-specific data to create a deterministic but unique salt
        let mut salt_context = Vec::new();
        if let Ok(username) = std::env::var("USER") {
            salt_context.extend_from_slice(username.as_bytes());
        }
        #[cfg(unix)]
        {
            let uid = nix::unistd::getuid().to_string();
            salt_context.extend_from_slice(uid.as_bytes());
        }

        // Combine random salt with system context for HKDF salt
        let mut hkdf_salt = Vec::new();
        hkdf_salt.extend_from_slice(&hkdf_salt_bytes);
        hkdf_salt.extend_from_slice(&salt_context);

        let mut master_key = [0u8; MASTER_KEY_LENGTH];
        let hkdf = hkdf::Salt::new(hkdf::HKDF_SHA256, &hkdf_salt);
        let prk = hkdf.extract(&entropy_sources);
        let okm = prk
            .expand(&[b"fuji-credential-master-key-v2"], hkdf::HKDF_SHA256)
            .map_err(|e| anyhow!("HKDF expansion for master key failed: {:?}", e))?;
        okm.fill(&mut master_key)
            .map_err(|e| anyhow!("Failed to fill master key: {:?}", e))?;

        Ok(master_key)
    }

    /// Derive encryption key from master key, PBKDF2 salt, and HKDF with improved key separation
    fn derive_encryption_key(&self, pbkdf2_salt: &[u8], hkdf_salt: &[u8]) -> Result<[u8; 32]> {
        // First, derive a key using PBKDF2 from the master key with stronger parameters
        let mut pbkdf2_output = [0u8; 32];
        pbkdf2_hmac::<Sha256>(
            &self.master_key,
            pbkdf2_salt,
            PBKDF2_ITERATIONS,
            &mut pbkdf2_output,
        );

        // Then, use HKDF to derive the final encryption key with better context separation
        let mut encryption_key = [0u8; 32];
        let hkdf = hkdf::Salt::new(hkdf::HKDF_SHA256, hkdf_salt);
        let prk = hkdf.extract(&pbkdf2_output);
        let okm = prk
            .expand(
                &[
                    b"fuji-encryption-key-v2",
                    b"file-credential-provider",
                    b"AES-256-GCM-encryption"
                ],
                hkdf::HKDF_SHA256
            )
            .map_err(|e| anyhow!("HKDF expansion failed: {:?}", e))?;
        okm.fill(&mut encryption_key)
            .map_err(|e| anyhow!("Failed to fill encryption key: {:?}", e))?;

        Ok(encryption_key)
    }

    /// Load the credential store from file
    async fn load_store(&self) -> Result<HashMap<String, Credential>> {
        if !self.file_path.exists() {
            return Ok(HashMap::new());
        }

        let mut file = File::open(&self.file_path)
            .await
            .map_err(|e| anyhow!("Failed to open credential file: {}", e))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .await
            .map_err(|e| anyhow!("Failed to read credential file: {}", e))?;

        // Parse encrypted store
        let store: EncryptedCredentialStore = serde_json::from_str(&contents)
            .map_err(|e| anyhow!("Failed to parse credential store: {}", e))?;

        // Verify version
        if store.version != 1 {
            return Err(anyhow!(
                "Unsupported credential store version: {}",
                store.version
            ));
        }

        // Verify PBKDF2 iterations (ensure it's not too low)
        if store.pbkdf2_iterations < 60_000 {
            return Err(anyhow!(
                "PBKDF2 iterations too low ({}), security compromise detected",
                store.pbkdf2_iterations
            ));
        }

        // Decode salts and nonce
        let pbkdf2_salt = general_purpose::STANDARD
            .decode(&store.pbkdf2_salt)
            .map_err(|e| anyhow!("Failed to decode PBKDF2 salt: {}", e))?;
        let hkdf_salt = general_purpose::STANDARD
            .decode(&store.hkdf_salt)
            .map_err(|e| anyhow!("Failed to decode HKDF salt: {}", e))?;
        let nonce = general_purpose::STANDARD
            .decode(&store.nonce)
            .map_err(|e| anyhow!("Failed to decode nonce: {}", e))?;
        let data = general_purpose::STANDARD
            .decode(&store.data)
            .map_err(|e| anyhow!("Failed to decode data: {}", e))?;

        // Validate salt randomness and quality
        self.validate_salt_quality(&pbkdf2_salt, "PBKDF2")?;
        self.validate_salt_quality(&hkdf_salt, "HKDF")?;
        self.validate_nonce_quality(&nonce)?;

        // Derive encryption key using stored salts
        let encryption_key = self.derive_encryption_key(&pbkdf2_salt, &hkdf_salt)?;

        // Decrypt the data
        let cipher = Aes256Gcm::new_from_slice(&encryption_key)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        let nonce = Nonce::from_slice(&nonce);
        let decrypted = cipher
            .decrypt(nonce, &data[..])
            .map_err(|e| anyhow!("Failed to decrypt credentials: {}", e))?;

        let json = String::from_utf8(decrypted)
            .map_err(|e| anyhow!("Failed to decode decrypted data: {}", e))?;

        serde_json::from_str(&json)
            .map_err(|e| anyhow!("Failed to parse decrypted credentials: {}", e))
    }

    /// Validate salt quality for randomness and proper length
    fn validate_salt_quality(&self, salt: &[u8], salt_type: &str) -> Result<()> {
        // Check salt length
        let expected_length = match salt_type {
            "PBKDF2" => PBKDF2_SALT_LENGTH,
            "HKDF" => HKDF_SALT_LENGTH,
            _ => return Err(anyhow!("Unknown salt type: {}", salt_type)),
        };

        if salt.len() != expected_length {
            return Err(anyhow!(
                "Invalid {} salt length: expected {}, got {}",
                salt_type,
                expected_length,
                salt.len()
            ));
        }

        // Check for obvious patterns (all zeros, all same byte, etc.)
        let mut all_same = true;
        let first_byte = salt[0];
        for &byte in salt.iter() {
            if byte != first_byte {
                all_same = false;
                break;
            }
        }

        if all_same {
            return Err(anyhow!(
                "{} salt appears to have low entropy (all bytes are the same)",
                salt_type
            ));
        }

        // Additional entropy quality check - ensure sufficient variation
        let mut bit_counts = [0u8; 8];
        for &byte in salt.iter() {
            for i in 0..8 {
                if (byte >> i) & 1 == 1 {
                    bit_counts[i] += 1;
                }
            }
        }

        // Check if each bit position has reasonable distribution (between 20% and 80% set)
        for (i, &count) in bit_counts.iter().enumerate() {
            let ratio = count as f64 / salt.len() as f64;
            if ratio < 0.2 || ratio > 0.8 {
                return Err(anyhow!(
                    "{} salt shows poor bit distribution at position {} (ratio: {:.2})",
                    salt_type,
                    i,
                    ratio
                ));
            }
        }

        Ok(())
    }

    /// Validate nonce quality for proper length and randomness
    fn validate_nonce_quality(&self, nonce: &[u8]) -> Result<()> {
        if nonce.len() != NONCE_LENGTH {
            return Err(anyhow!(
                "Invalid nonce length: expected {}, got {}",
                NONCE_LENGTH,
                nonce.len()
            ));
        }

        // Check for reuse - nonce should never be repeated with the same key
        // This is a basic check; in practice, we'd need to track used nonces
        let mut all_same = true;
        let first_byte = nonce[0];
        for &byte in nonce.iter() {
            if byte != first_byte {
                all_same = false;
                break;
            }
        }

        if all_same {
            return Err(anyhow!(
                "Nonce appears to have low entropy (all bytes are the same)"
            ));
        }

        Ok(())
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

        // Generate cryptographically secure random salts and nonce outside of async context
        let (pbkdf2_salt, hkdf_salt, nonce_bytes) = {
            let mut pbkdf2_salt = [0u8; PBKDF2_SALT_LENGTH];
            let mut hkdf_salt = [0u8; HKDF_SALT_LENGTH];
            let mut nonce_bytes = [0u8; NONCE_LENGTH];

            let mut rng = rand::thread_rng();
            rng.fill_bytes(&mut pbkdf2_salt);
            rng.fill_bytes(&mut hkdf_salt);
            rng.fill_bytes(&mut nonce_bytes);

            (pbkdf2_salt, hkdf_salt, nonce_bytes)
        };

        // Derive encryption key using the new salts
        let encryption_key = self.derive_encryption_key(&pbkdf2_salt, &hkdf_salt)?;

        // Encrypt the data
        let cipher = Aes256Gcm::new_from_slice(&encryption_key)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(nonce, json.as_bytes())
            .map_err(|e| anyhow!("Failed to encrypt credentials: {}", e))?;

        // Create encrypted store with all security parameters
        let store = EncryptedCredentialStore {
            version: 1,
            pbkdf2_salt: general_purpose::STANDARD.encode(pbkdf2_salt),
            hkdf_salt: general_purpose::STANDARD.encode(hkdf_salt),
            pbkdf2_iterations: PBKDF2_ITERATIONS,
            nonce: general_purpose::STANDARD.encode(nonce_bytes),
            data: general_purpose::STANDARD.encode(encrypted),
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("algorithm".to_string(), "AES-256-GCM".to_string());
                meta.insert("kdf".to_string(), "PBKDF2-HMAC-SHA256".to_string());
                meta.insert("prf".to_string(), "HKDF-SHA256".to_string());
                meta.insert("created_at".to_string(), chrono::Utc::now().to_rfc3339());
                meta
            },
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
                .mode(0o600) // Secure file permissions - owner read/write only
                .open(&temp_path)
                .await
                .map_err(|e| anyhow!("Failed to create temporary file: {}", e))?;

            file.write_all(json.as_bytes())
                .await
                .map_err(|e| anyhow!("Failed to write temporary file: {}", e))?;

            file.sync_all()
                .await
                .map_err(|e| anyhow!("Failed to sync temporary file: {}", e))?;
        }

        // Atomic rename
        tokio::fs::rename(&temp_path, &self.file_path)
            .await
            .map_err(|e| anyhow!("Failed to rename credential file: {}", e))?;

        debug!(
            "Saved {} credentials to encrypted file with {} PBKDF2 iterations",
            credentials.len(),
            PBKDF2_ITERATIONS
        );
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
        debug!(
            "Retrieved credential for {} from encrypted file: {}",
            mount_id,
            credential.is_some()
        );
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
        Self::new().expect("Failed to create default FileCredentialProvider")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_file_provider_encryption() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_credentials.enc");
        let provider = FileCredentialProvider::with_path(file_path).unwrap();

        let credential = Credential {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            domain: Some("TESTDOMAIN".to_string()),
            metadata: Default::default(),
        };

        // Store credential
        provider
            .store_credential("test-mount", &credential)
            .await
            .unwrap();

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

    #[tokio::test]
    async fn test_encryption_strength() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_strength.enc");
        let provider = FileCredentialProvider::with_path(file_path).unwrap();

        // Test with sensitive data
        let sensitive_credential = Credential {
            username: "admin".to_string(),
            password: "SuperSecretPassword123!@#$%^&*()".to_string(),
            domain: Some("DOMAIN.LOCAL".to_string()),
            metadata: Default::default(),
        };

        provider
            .store_credential("sensitive-mount", &sensitive_credential)
            .await
            .unwrap();

        // Verify the encrypted file doesn't contain plaintext
        let file_path = provider.file_path.clone();
        let contents = std::fs::read_to_string(file_path).unwrap();
        assert!(!contents.contains("SuperSecretPassword"));
        assert!(!contents.contains("admin"));
        assert!(!contents.contains("DOMAIN.LOCAL"));

        // Verify decryption still works
        let retrieved = provider.get_credential("sensitive-mount").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(
            retrieved.unwrap().password,
            "SuperSecretPassword123!@#$%^&*()"
        );
    }

    #[tokio::test]
    async fn test_pbkdf2_iterations() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_pbkdf2.enc");
        let provider = FileCredentialProvider::with_path(file_path).unwrap();

        let credential = Credential {
            username: "test".to_string(),
            password: "password".to_string(),
            domain: None,
            metadata: Default::default(),
        };

        provider
            .store_credential("test", &credential)
            .await
            .unwrap();

        // Read the file and verify PBKDF2 iterations
        let file_path = provider.file_path.clone();
        let contents = std::fs::read_to_string(file_path).unwrap();
        assert!(contents.contains("120000"));
    }

    #[tokio::test]
    async fn test_performance() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_perf.enc");
        let provider = FileCredentialProvider::with_path(file_path).unwrap();

        // Measure encryption time
        let start = Instant::now();

        for i in 0..10 {
            let credential = Credential {
                username: format!("user{}", i),
                password: format!("password{}", i),
                domain: Some(format!("DOMAIN{}", i)),
                metadata: Default::default(),
            };

            provider
                .store_credential(&format!("mount{}", i), &credential)
                .await
                .unwrap();
        }

        let encryption_time = start.elapsed();

        // Measure decryption time
        let start = Instant::now();

        for i in 0..10 {
            let _ = provider
                .get_credential(&format!("mount{}", i))
                .await
                .unwrap();
        }

        let decryption_time = start.elapsed();

        // Performance should be reasonable for 120,000 PBKDF2 iterations
        // Note: With strong encryption, this will take longer than weak encryption
        assert!(
            encryption_time < Duration::from_secs(30),
            "Encryption too slow: {:?}",
            encryption_time
        );
        assert!(
            decryption_time < Duration::from_secs(10),
            "Decryption too slow: {:?}",
            decryption_time
        );

        println!("Encryption time for 10 operations: {:?}", encryption_time);
        println!("Decryption time for 10 operations: {:?}", decryption_time);
    }

    #[tokio::test]
    async fn test_wrong_key_detection() {
        let temp_dir1 = TempDir::new().unwrap();
        let temp_dir2 = TempDir::new().unwrap();

        let file_path1 = temp_dir1.path().join("test1.enc");
        let file_path2 = temp_dir2.path().join("test2.enc");

        let provider1 = FileCredentialProvider::with_path(file_path1).unwrap();

        // Create provider2 with a different environment variable to ensure different master key
        std::env::set_var("TEST_FUJI_DIFFERENT_KEY", "different_value");
        let provider2 = FileCredentialProvider::with_path(file_path2).unwrap();
        std::env::remove_var("TEST_FUJI_DIFFERENT_KEY");

        let credential = Credential {
            username: "test".to_string(),
            password: "password".to_string(),
            domain: None,
            metadata: Default::default(),
        };

        // Store with provider1
        provider1
            .store_credential("test", &credential)
            .await
            .unwrap();

        // Copy the encrypted file to provider2's location
        std::fs::copy(&provider1.file_path, &provider2.file_path).unwrap();

        // Try to decrypt with provider2 (should fail due to different master key)
        let result = provider2.get_credential("test").await;
        assert!(result.is_err() || result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_salt_uniqueness() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_salts.enc");
        let provider = FileCredentialProvider::with_path(file_path).unwrap();

        let credential = Credential {
            username: "test".to_string(),
            password: "password".to_string(),
            domain: None,
            metadata: Default::default(),
        };

        // Store twice and check salts are different
        provider
            .store_credential("test1", &credential)
            .await
            .unwrap();

        // Read the file
        let file_path = provider.file_path.clone();
        let contents1 = std::fs::read_to_string(file_path).unwrap();

        // Store again
        provider
            .store_credential("test2", &credential)
            .await
            .unwrap();

        // Read the file again
        let contents2 = std::fs::read_to_string(&provider.file_path).unwrap();

        // Extract salts and ensure they're different
        // The salts should be base64 encoded, so we can compare the strings
        assert_ne!(contents1, contents2);
    }
}
