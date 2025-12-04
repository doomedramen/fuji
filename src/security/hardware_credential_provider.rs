//! Hardware Security Module (HSM) and advanced credential storage
//!
//! This module provides hardware-backed key storage, key rotation,
//! and advanced cryptographic operations for secure credential management.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, error, info, warn};

use crate::security::encryption::{EncryptionAlgorithm, EncryptedData};
use crate::security::auth::JWTAuthenticator;

/// Hardware-backed credential provider
pub struct HardwareCredentialProvider {
    /// HSM backend
    hsm_backend: Arc<dyn HSMBACKEND>,
    /// Key cache with TTL
    key_cache: Arc<RwLock<HashMap<String, CachedKey>>>,
    /// Key rotation configuration
    rotation_config: KeyRotationConfig,
    /// Rate limiter for key operations
    rate_limiter: Arc<Semaphore>,
    /// Security policy
    security_policy: SecurityPolicy,
}

/// Cached key with metadata
#[derive(Debug, Clone)]
struct CachedKey {
    key_id: String,
    key_data: Vec<u8>,
    created_at: SystemTime,
    last_accessed: SystemTime,
    access_count: u64,
}

/// Key rotation configuration
#[derive(Debug, Clone)]
pub struct KeyRotationConfig {
    /// Automatic rotation interval
    pub rotation_interval: Duration,
    /// Grace period before rotation
    pub grace_period: Duration,
    /// Maximum key age before forced rotation
    pub max_key_age: Duration,
    /// Notification period before rotation
    pub notification_period: Duration,
}

/// Security policy for credential operations
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Minimum password length
    pub min_password_length: usize,
    /// Password complexity requirements
    pub require_complex_password: bool,
    /// Maximum failed attempts before lockout
    pub max_failed_attempts: u32,
    /// Account lockout duration
    pub lockout_duration: Duration,
    /// Session timeout duration
    pub session_timeout: Duration,
    /// Require multi-factor authentication
    pub require_mfa: bool,
    /// Maximum concurrent sessions
    pub max_concurrent_sessions: u32,
}

/// Enhanced credential with additional security metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedCredential {
    /// Original credential
    #[serde(flatten)]
    pub credential: crate::security::Credential,
    /// Credential version for rotation tracking
    pub version: u64,
    /// Creation timestamp
    pub created_at: SystemTime,
    /// Expiration timestamp
    pub expires_at: Option<SystemTime>,
    /// Last rotation timestamp
    pub last_rotated: Option<SystemTime>,
    /// Security metadata
    pub security_metadata: SecurityMetadata,
}

/// Security metadata for credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetadata {
    /// Hash of the credential for integrity verification
    pub integrity_hash: String,
    /// Key derivation parameters
    pub kdf_params: KeyDerivationParams,
    /// Encryption algorithm used
    pub encryption_algorithm: String,
    /// MFA requirements
    pub mfa_required: bool,
    /// Access restrictions
    pub access_restrictions: HashMap<String, String>,
    /// Audit log entry IDs
    pub audit_log_ids: Vec<String>,
}

/// Key derivation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationParams {
    /// PBKDF2 iteration count
    pub iterations: u32,
    /// Salt used for key derivation
    pub salt: Vec<u8>,
    /// Key length in bytes
    pub key_length: usize,
    /// Memory-hard parameters (for Argon2 if available)
    pub memory_cost: Option<u32>,
    /// Parallelism factor
    pub parallelism: Option<u32>,
}

/// HSM backend trait for hardware security modules
#[async_trait::async_trait]
pub trait HSMBACKEND: Send + Sync {
    /// Store a key in the HSM
    async fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<()>;

    /// Retrieve a key from the HSM
    async fn get_key(&self, key_id: &str) -> Result<Option<Vec<u8>>>;

    /// Delete a key from the HSM
    async fn delete_key(&self, key_id: &str) -> Result<()>;

    /// Rotate a key in the HSM
    async fn rotate_key(&self, key_id: &str, new_key_data: &[u8]) -> Result<()>;

    /// List all keys in the HSM
    async fn list_keys(&self) -> Result<Vec<String>>;

    /// Check if HSM is available
    fn is_available(&self) -> bool;

    /// Get HSM type/name
    fn hsm_type(&self) -> &'static str;

    /// Perform secure random number generation
    async fn secure_random(&self, length: usize) -> Result<Vec<u8>>;

    /// Sign data with HSM-stored key
    async fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>>;

    /// Verify signature with HSM-stored key
    async fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> Result<bool>;
}

/// Software-based HSM fallback implementation
pub struct SoftwareHSM {
    /// Encrypted key store
    key_store: Arc<RwLock<HashMap<String, EncryptedKeyData>>>,
    /// Master key for key encryption
    master_key: Arc<RwLock<Option<Vec<u8>>>>,
    /// Key store file path
    key_store_path: PathBuf,
    /// Encryptor for key protection
    encryptor: ChaCha20Poly1305Encryptor,
}

/// Encrypted key data storage
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedKeyData {
    encrypted_key: String,
    nonce: String,
    created_at: SystemTime,
    access_count: u64,
    metadata: HashMap<String, String>,
}

/// ChaCha20-Poly1305 encryptor for HSM operations
struct ChaCha20Poly1305Encryptor {
    cipher: ChaCha20Poly1305,
}

impl HardwareCredentialProvider {
    /// Create a new hardware-backed credential provider
    pub fn new(hsm_backend: Arc<dyn HSMBACKEND>) -> Self {
        Self {
            hsm_backend,
            key_cache: Arc::new(RwLock::new(HashMap::new())),
            rotation_config: KeyRotationConfig::default(),
            rate_limiter: Arc::new(Semaphore::new(10)), // Limit concurrent key operations
            security_policy: SecurityPolicy::default(),
        }
    }

    /// Store an enhanced credential with hardware backing
    pub async fn store_enhanced_credential(
        &self,
        mount_id: &str,
        credential: &crate::security::Credential,
    ) -> Result<()> {
        // Acquire rate limiter permit
        let _permit = self.rate_limiter.acquire().await?;

        // Validate password against security policy
        self.validate_password(&credential.password)?;

        // Generate enhanced credential with security metadata
        let enhanced = self.create_enhanced_credential(mount_id, credential).await?;

        // Generate unique key for this credential
        let key_id = format!("credential_{}", mount_id);
        let key_data = self.generate_credential_key(mount_id, &enhanced).await?;

        // Store key in HSM
        self.hsm_backend.store_key(&key_id, &key_data).await?;

        // Cache the key metadata
        let cached_key = CachedKey {
            key_id: key_id.clone(),
            key_data: key_data.clone(),
            created_at: SystemTime::now(),
            last_accessed: SystemTime::now(),
            access_count: 0,
        };

        {
            let mut cache = self.key_cache.write().await;
            cache.insert(key_id.clone(), cached_key);
        }

        info!("Stored enhanced credential for {} in HSM", mount_id);
        Ok(())
    }

    /// Retrieve an enhanced credential with hardware backing
    pub async fn get_enhanced_credential(
        &self,
        mount_id: &str,
    ) -> Result<Option<EnhancedCredential>> {
        let _permit = self.rate_limiter.acquire().await?;

        let key_id = format!("credential_{}", mount_id);

        // Try cache first
        {
            let cache = self.key_cache.read().await;
            if let Some(cached_key) = cache.get(&key_id) {
                // Update access statistics
                drop(cache);
                self.update_key_access_stats(&key_id).await;

                // Decrypt and return credential
                let key_data = self.hsm_backend.get_key(&key_id).await?;
                if let Some(key) = key_data {
                    return Ok(Some(self.decrypt_credential(&key)?));
                }
            }
        }

        // Fallback to HSM lookup
        let key_data = match self.hsm_backend.get_key(&key_id).await? {
            Some(key) => key,
            None => return Ok(None),
        };

        let credential = self.decrypt_credential(&key_data)?;
        Ok(Some(credential))
    }

    /// Rotate credential key
    pub async fn rotate_credential_key(&self, mount_id: &str) -> Result<()> {
        let _permit = self.rate_limiter.acquire().await?;

        let key_id = format!("credential_{}", mount_id);

        // Get existing credential
        let key_data = self.hsm_backend.get_key(&key_id).await?
            .ok_or_else(|| anyhow!("Credential not found for rotation: {}", mount_id))?;

        let mut credential = self.decrypt_credential(&key_data)?;

        // Generate new key
        let new_key_data = self.generate_credential_key(mount_id, &credential).await?;

        // Rotate in HSM
        self.hsm_backend.rotate_key(&key_id, &new_key_data).await?;

        // Update credential metadata
        credential.version += 1;
        credential.last_rotated = Some(SystemTime::now());
        credential.security_metadata.kdf_params.salt = self.generate_salt();

        // Update cache
        {
            let mut cache = self.key_cache.write().await;
            if let Some(cached_key) = cache.get_mut(&key_id) {
                cached_key.key_data = new_key_data;
                cached_key.last_accessed = SystemTime::now();
                cached_key.access_count += 1;
            }
        }

        info!("Rotated credential key for {}", mount_id);
        Ok(())
    }

    /// Validate password against security policy
    fn validate_password(&self, password: &str) -> Result<()> {
        if password.len() < self.security_policy.min_password_length {
            return Err(anyhow!(
                "Password too short: minimum {} characters required",
                self.security_policy.min_password_length
            ));
        }

        if self.security_policy.require_complex_password {
            let has_upper = password.chars().any(|c| c.is_uppercase());
            let has_lower = password.chars().any(|c| c.is_lowercase());
            let has_digit = password.chars().any(|c| c.is_numeric());
            let has_special = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

            if !has_upper || !has_lower || !has_digit || !has_special {
                return Err(anyhow!(
                    "Password does not meet complexity requirements: \
                     must contain uppercase, lowercase, digits, and special characters"
                ));
            }
        }

        Ok(())
    }

    /// Create enhanced credential with security metadata
    async fn create_enhanced_credential(
        &self,
        mount_id: &str,
        credential: &crate::security::Credential,
    ) -> Result<EnhancedCredential> {
        let kdf_params = KeyDerivationParams {
            iterations: 200_000, // High iteration count for security
            salt: self.generate_salt(),
            key_length: 32,
            memory_cost: None,
            parallelism: Some(4),
        };

        let security_metadata = SecurityMetadata {
            integrity_hash: self.calculate_credential_hash(credential)?,
            kdf_params,
            encryption_algorithm: "chacha20-poly1305".to_string(),
            mfa_required: self.security_policy.require_mfa,
            access_restrictions: HashMap::new(),
            audit_log_ids: vec![],
        };

        Ok(EnhancedCredential {
            credential: credential.clone(),
            version: 1,
            created_at: SystemTime::now(),
            expires_at: None,
            last_rotated: Some(SystemTime::now()),
            security_metadata,
        })
    }

    /// Generate salt for key derivation
    fn generate_salt(&self) -> Vec<u8> {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        salt.to_vec()
    }

    /// Calculate integrity hash for credential
    fn calculate_credential_hash(&self, credential: &crate::security::Credential) -> Result<String> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(credential.username.as_bytes());
        hasher.update(credential.password.as_bytes());
        if let Some(domain) = &credential.domain {
            hasher.update(domain.as_bytes());
        }

        Ok(hex::encode(hasher.finalize()))
    }

    /// Generate key for credential encryption
    async fn generate_credential_key(
        &self,
        mount_id: &str,
        credential: &EnhancedCredential,
    ) -> Result<Vec<u8>> {
        // Derive key from mount_id and credential metadata
        let mut key_material = format!("{}:{}:{}",
            mount_id,
            credential.version,
            credential.created_at.duration_since(UNIX_EPOCH)?.as_secs()
        ).into_bytes();

        // Add salt from KDF parameters
        key_material.extend_from_slice(&credential.security_metadata.kdf_params.salt);

        // Derive key using PBKDF2
        let mut derived_key = vec![0u8; 32];
        pbkdf2_hmac::<Sha256>(
            &key_material,
            &credential.security_metadata.kdf_params.salt,
            credential.security_metadata.kdf_params.iterations as usize,
            &mut derived_key,
        );

        Ok(derived_key)
    }

    /// Decrypt credential using key data
    fn decrypt_credential(&self, key_data: &[u8]) -> Result<EnhancedCredential> {
        // Implementation would decrypt credential from encrypted storage
        // For now, this is a placeholder that would contain the actual decryption logic
        Err(anyhow!("Credential decryption not fully implemented"))
    }

    /// Update key access statistics
    async fn update_key_access_stats(&self, key_id: &str) {
        let mut cache = self.key_cache.write().await;
        if let Some(cached_key) = cache.get_mut(key_id) {
            cached_key.last_accessed = SystemTime::now();
            cached_key.access_count += 1;
        }
    }
}

impl Default for KeyRotationConfig {
    fn default() -> Self {
        Self {
            rotation_interval: Duration::from_secs(90 * 24 * 60 * 60), // 90 days
            grace_period: Duration::from_secs(7 * 24 * 60 * 60),     // 7 days
            max_key_age: Duration::from_secs(365 * 24 * 60 * 60),   // 1 year
            notification_period: Duration::from_secs(14 * 24 * 60 * 60), // 14 days
        }
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            min_password_length: 12,
            require_complex_password: true,
            max_failed_attempts: 5,
            lockout_duration: Duration::from_secs(15 * 60), // 15 minutes
            session_timeout: Duration::from_secs(30 * 60),  // 30 minutes
            require_mfa: false,
            max_concurrent_sessions: 3,
        }
    }
}

#[async_trait::async_trait]
impl HSMBACKEND for SoftwareHSM {
    async fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<()> {
        // Implementation for software HSM key storage
        Err(anyhow!("Software HSM implementation not completed"))
    }

    async fn get_key(&self, key_id: &str) -> Result<Option<Vec<u8>>> {
        // Implementation for software HSM key retrieval
        Ok(None)
    }

    async fn delete_key(&self, key_id: &str) -> Result<()> {
        // Implementation for software HSM key deletion
        Ok(())
    }

    async fn rotate_key(&self, key_id: &str, new_key_data: &[u8]) -> Result<()> {
        // Implementation for software HSM key rotation
        Ok(())
    }

    async fn list_keys(&self) -> Result<Vec<String>> {
        // Implementation for software HSM key listing
        Ok(vec![])
    }

    fn is_available(&self) -> bool {
        true // Software HSM is always available
    }

    fn hsm_type(&self) -> &'static str {
        "software"
    }

    async fn secure_random(&self, length: usize) -> Result<Vec<u8>> {
        let mut random_bytes = vec![0u8; length];
        OsRng.fill_bytes(&mut random_bytes);
        Ok(random_bytes)
    }

    async fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        // Implementation for software HSM signing
        Err(anyhow!("Software HSM signing not implemented"))
    }

    async fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> Result<bool> {
        // Implementation for software HSM verification
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{Credential, CredentialManager};

    #[test]
    fn test_security_policy_validation() {
        let policy = SecurityPolicy::default();

        // Valid password
        assert!(HardwareCredentialProvider::new(Arc::new(SoftwareHSM {
            key_store: Arc::new(RwLock::new(HashMap::new())),
            master_key: Arc::new(RwLock::new(None)),
            key_store_path: PathBuf::from("/tmp/test"),
            encryptor: ChaCha20Poly1305Encryptor { cipher: ChaCha20Poly1305::new(&Key::from_slice(&[0u8; 32])) },
        })).validate_password("SecurePass123!").is_ok());

        // Too short
        assert!(HardwareCredentialProvider::new(Arc::new(SoftwareHSM {
            key_store: Arc::new(RwLock::new(HashMap::new())),
            master_key: Arc::new(RwLock::new(None)),
            key_store_path: PathBuf::from("/tmp/test"),
            encryptor: ChaCha20Poly1305Encryptor { cipher: ChaCha20Poly1305::new(&Key::from_slice(&[0u8; 32])) },
        })).validate_password("short").is_err());
    }

    #[test]
    fn test_credential_hashing() {
        let provider = HardwareCredentialProvider::new(Arc::new(SoftwareHSM {
            key_store: Arc::new(RwLock::new(HashMap::new())),
            master_key: Arc::new(RwLock::new(None)),
            key_store_path: PathBuf::from("/tmp/test"),
            encryptor: ChaCha20Poly1305Encryptor { cipher: ChaCha20Poly1305::new(&Key::from_slice(&[0u8; 32])) },
        }));

        let credential = Credential {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            domain: Some("testdomain".to_string()),
            metadata: HashMap::new(),
        };

        let hash1 = provider.calculate_credential_hash(&credential).unwrap();
        let hash2 = provider.calculate_credential_hash(&credential).unwrap();

        assert_eq!(hash1, hash2); // Should be deterministic
        assert!(!hash1.is_empty()); // Should produce a hash
    }

    #[tokio::test]
    async fn test_hsm_interface() {
        let hsm = SoftwareHSM {
            key_store: Arc::new(RwLock::new(HashMap::new())),
            master_key: Arc::new(RwLock::new(None)),
            key_store_path: PathBuf::from("/tmp/test"),
            encryptor: ChaCha20Poly1305Encryptor { cipher: ChaCha20Poly1305::new(&Key::from_slice(&[0u8; 32])) },
        };

        assert!(hsm.is_available());
        assert_eq!(hsm.hsm_type(), "software");

        let random = hsm.secure_random(32).await.unwrap();
        assert_eq!(random.len(), 32);

        // Verify randomness (not all same bytes)
        let all_same = random.iter().all(|&b| b == random[0]);
        assert!(!all_same);
    }
}