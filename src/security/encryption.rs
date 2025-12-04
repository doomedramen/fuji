//! Enhanced encryption module supporting multiple cipher suites
//!
//! This module provides support for both AES-256-GCM and ChaCha20-Poly1305 encryption
//! algorithms with configurable security parameters and key derivation.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use base64::{engine::general_purpose, Engine as _};

/// Supported encryption algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    /// AES-256-GCM - Hardware-accelerated on most platforms
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    /// ChaCha20-Poly1305 - Software-based, resistant to timing attacks
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
}

impl EncryptionAlgorithm {
    /// Get the display name for the algorithm
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Aes256Gcm => "AES-256-GCM",
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        }
    }

    /// Get the algorithm identifier used in metadata
    pub fn identifier(&self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }

    /// Get the key size in bytes
    pub fn key_size(&self) -> usize {
        match self {
            Self::Aes256Gcm => 32,        // 256 bits
            Self::ChaCha20Poly1305 => 32, // 256 bits
        }
    }

    /// Get the nonce size in bytes
    pub fn nonce_size(&self) -> usize {
        match self {
            Self::Aes256Gcm => 12,        // 96 bits
            Self::ChaCha20Poly1305 => 12, // 96 bits
        }
    }

    /// Check if the algorithm is recommended for current security standards
    pub fn is_recommended(&self) -> bool {
        match self {
            Self::Aes256Gcm => true,
            Self::ChaCha20Poly1305 => true,
        }
    }

    /// Get performance characteristics
    pub fn performance_characteristics(&self) -> AlgorithmCharacteristics {
        match self {
            Self::Aes256Gcm => AlgorithmCharacteristics {
                hardware_acceleration: true,
                constant_time_operations: true,
                side_channel_resistance: "High (with constant-time implementations)",
                best_for: "High-throughput environments with hardware acceleration",
            },
            Self::ChaCha20Poly1305 => AlgorithmCharacteristics {
                hardware_acceleration: false,
                constant_time_operations: true,
                side_channel_resistance: "Very High (designed for side-channel resistance)",
                best_for: "Software-only environments and side-channel resistance",
            },
        }
    }
}

/// Performance characteristics of encryption algorithms
#[derive(Debug, Clone)]
pub struct AlgorithmCharacteristics {
    pub hardware_acceleration: bool,
    pub constant_time_operations: bool,
    pub side_channel_resistance: &'static str,
    pub best_for: &'static str,
}

/// Encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Encryption algorithm to use
    pub algorithm: EncryptionAlgorithm,
    /// Number of PBKDF2 iterations (minimum recommended: 120,000)
    pub pbkdf2_iterations: u32,
    /// Additional algorithm-specific parameters
    pub parameters: HashMap<String, String>,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            pbkdf2_iterations: 120_000,
            parameters: HashMap::new(),
        }
    }
}

impl EncryptionConfig {
    /// Create a new configuration with the specified algorithm
    pub fn new(algorithm: EncryptionAlgorithm) -> Self {
        Self {
            algorithm,
            pbkdf2_iterations: 120_000,
            parameters: HashMap::new(),
        }
    }

    /// Create a configuration optimized for security
    pub fn security_optimized() -> Self {
        Self {
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305, // Most resistant to timing attacks
            pbkdf2_iterations: 200_000, // Higher iteration count for better security
            parameters: {
                let mut params = HashMap::new();
                params.insert("security_level".to_string(), "high".to_string());
                params.insert("constant_time_ops".to_string(), "true".to_string());
                params
            },
        }
    }

    /// Create a configuration optimized for performance
    pub fn performance_optimized() -> Self {
        Self {
            algorithm: EncryptionAlgorithm::Aes256Gcm, // Usually faster with hardware acceleration
            pbkdf2_iterations: 120_000,                // OWASP minimum recommendation
            parameters: {
                let mut params = HashMap::new();
                params.insert("security_level".to_string(), "standard".to_string());
                params
            },
        }
    }

    /// Create a configuration with custom iteration count
    pub fn with_iterations(mut self, iterations: u32) -> Self {
        if iterations < 60_000 {
            tracing::warn!(
                "PBKDF2 iterations ({}) below recommended minimum (60,000)",
                iterations
            );
        }
        self.pbkdf2_iterations = iterations;
        self
    }

    /// Add a custom parameter
    pub fn with_parameter(mut self, key: String, value: String) -> Self {
        self.parameters.insert(key, value);
        self
    }
}

/// Generic encryption interface
pub trait Encryptor: Send + Sync {
    /// Encrypt data using the configured algorithm
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<EncryptedData>;

    /// Decrypt data using the configured algorithm
    fn decrypt(&self, encrypted: &EncryptedData, key: &[u8]) -> Result<Vec<u8>>;

    /// Get the algorithm used by this encryptor
    fn algorithm(&self) -> EncryptionAlgorithm;
}

/// Encrypted data container with algorithm metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Algorithm used for encryption
    pub algorithm: EncryptionAlgorithm,
    /// Nonce used for encryption (base64 encoded)
    pub nonce: String,
    /// Encrypted data (base64 encoded)
    pub ciphertext: String,
    /// Authentication tag (base64 encoded) - for algorithms with separate authentication
    pub tag: Option<String>,
    /// Encryption metadata
    pub metadata: HashMap<String, String>,
}

impl EncryptedData {
    /// Create new encrypted data with separate authentication tag
    pub fn new(
        algorithm: EncryptionAlgorithm,
        nonce: &[u8],
        ciphertext: &[u8],
        tag: Option<&[u8]>,
        metadata: HashMap<String, String>,
    ) -> Self {
        Self {
            algorithm,
            nonce: general_purpose::STANDARD.encode(nonce),
            ciphertext: general_purpose::STANDARD.encode(ciphertext),
            tag: tag.map(|t| general_purpose::STANDARD.encode(t)),
            metadata,
        }
    }

    /// Create new encrypted data for algorithms where tag is included in ciphertext
    pub fn new_with_combined_tag(
        algorithm: EncryptionAlgorithm,
        nonce: &[u8],
        combined_data: &[u8],
        metadata: HashMap<String, String>,
    ) -> Self {
        let (nonce, ciphertext) = combined_data.split_at(algorithm.nonce_size());
        Self {
            algorithm,
            nonce: general_purpose::STANDARD.encode(nonce),
            ciphertext: general_purpose::STANDARD.encode(ciphertext),
            tag: None,
            metadata,
        }
    }

    /// Decode nonce and ciphertext from base64
    pub fn decode_components(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let nonce = general_purpose::STANDARD
            .decode(&self.nonce)
            .map_err(|e| anyhow!("Failed to decode nonce: {}", e))?;
        let ciphertext = general_purpose::STANDARD
            .decode(&self.ciphertext)
            .map_err(|e| anyhow!("Failed to decode ciphertext: {}", e))?;

        Ok((nonce, ciphertext))
    }

    /// Decode authentication tag if present
    pub fn decode_tag(&self) -> Result<Option<Vec<u8>>> {
        match &self.tag {
            Some(tag) => {
                let decoded = general_purpose::STANDARD
                    .decode(tag)
                    .map_err(|e| anyhow!("Failed to decode authentication tag: {}", e))?;
                Ok(Some(decoded))
            }
            None => Ok(None),
        }
    }
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// ChaCha20-Poly1305 encryptor implementation
#[derive(Debug)]
pub struct ChaCha20Poly1305Encryptor {
    algorithm: EncryptionAlgorithm,
}

impl ChaCha20Poly1305Encryptor {
    pub fn new() -> Self {
        Self {
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
        }
    }
}

impl Encryptor for ChaCha20Poly1305Encryptor {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<EncryptedData> {
        let key = Key::from_slice(key);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = ChaCha20Poly1305::new(&key);
        let encrypted = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("ChaCha20-Poly1305 encryption failed: {}", e))?;

        // ChaCha20-Poly1305 includes the tag in the ciphertext
        let metadata = {
            let mut meta = HashMap::new();
            meta.insert(
                "algorithm".to_string(),
                self.algorithm.identifier().to_string(),
            );
            meta.insert("key_derivation".to_string(), "pbkdf2-sha256".to_string());
            meta.insert("created_at".to_string(), chrono::Utc::now().to_rfc3339());
            meta
        };

        Ok(EncryptedData::new_with_combined_tag(
            self.algorithm,
            &nonce_bytes,
            &encrypted,
            metadata,
        ))
    }

    fn decrypt(&self, encrypted: &EncryptedData, key: &[u8]) -> Result<Vec<u8>> {
        if encrypted.algorithm != EncryptionAlgorithm::ChaCha20Poly1305 {
            return Err(anyhow!(
                "Algorithm mismatch: expected {:?}, got {:?}",
                EncryptionAlgorithm::ChaCha20Poly1305,
                encrypted.algorithm
            ));
        }

        let key = Key::from_slice(key);

        let (nonce_bytes, ciphertext) = encrypted.decode_components()?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = ChaCha20Poly1305::new(&key);

        cipher
            .decrypt(nonce, &ciphertext[..])
            .map_err(|e| anyhow!("ChaCha20-Poly1305 decryption failed: {}", e))
    }

    fn algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }
}

/// Factory function to create appropriate encryptor
pub fn create_encryptor(algorithm: EncryptionAlgorithm) -> Box<dyn Encryptor> {
    match algorithm {
        EncryptionAlgorithm::ChaCha20Poly1305 => Box::new(ChaCha20Poly1305Encryptor::new()),
        EncryptionAlgorithm::Aes256Gcm => {
            // TODO: Implement AES-256-GCM encryptor
            panic!("AES-256-GCM encryptor not yet implemented");
        }
    }
}

/// Generate cryptographically secure random nonce
pub fn generate_nonce(size: usize) -> Vec<u8> {
    let mut nonce = vec![0u8; size];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Validate encryption security parameters
pub fn validate_security_params(config: &EncryptionConfig) -> Result<()> {
    // Check PBKDF2 iterations
    if config.pbkdf2_iterations < 60_000 {
        return Err(anyhow!(
            "PBKDF2 iterations ({}) below minimum recommended value (60,000)",
            config.pbkdf2_iterations
        ));
    }

    // Check algorithm is supported
    if !config.algorithm.is_recommended() {
        return Err(anyhow!(
            "Encryption algorithm {:?} is not recommended",
            config.algorithm
        ));
    }

    // Warn if iterations are very high (performance impact)
    if config.pbkdf2_iterations > 500_000 {
        tracing::warn!(
            "High PBKDF2 iteration count ({}) may impact performance significantly",
            config.pbkdf2_iterations
        );
    }

    Ok(())
}

/// Get security recommendations based on algorithm
pub fn get_security_recommendations(algorithm: EncryptionAlgorithm) -> Vec<String> {
    let mut recommendations = Vec::new();

    recommendations.push(format!(
        "Use {} as primary encryption algorithm",
        algorithm.display_name()
    ));

    match algorithm {
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            recommendations.push(
                "ChaCha20-Poly1305 provides excellent resistance to timing attacks".to_string(),
            );
            recommendations.push(
                "Consider using 200,000+ PBKDF2 iterations for enhanced security".to_string(),
            );
        }
        EncryptionAlgorithm::Aes256Gcm => {
            recommendations.push("AES-256-GCM may benefit from hardware acceleration".to_string());
            recommendations.push("Ensure constant-time implementations are used".to_string());
        }
    }

    recommendations.push("Store encryption salts and nonces securely".to_string());
    recommendations.push("Use unique nonces for each encryption".to_string());
    recommendations.push("Never reuse keys with the same nonce".to_string());

    recommendations
}

/// Compare two encryption algorithms and return security assessment
pub fn compare_algorithms(
    algo1: EncryptionAlgorithm,
    algo2: EncryptionAlgorithm,
) -> AlgorithmComparison {
    AlgorithmComparison {
        algorithm1: algo1,
        algorithm2: algo2,
        security_level1: algo1.is_recommended(),
        security_level2: algo2.is_recommended(),
        hardware_acceleration1: algo1.performance_characteristics().hardware_acceleration,
        hardware_acceleration2: algo2.performance_characteristics().hardware_acceleration,
        recommendation: match (algo1, algo2) {
            (EncryptionAlgorithm::ChaCha20Poly1305, EncryptionAlgorithm::Aes256Gcm) => {
                "ChaCha20-Poly1305 recommended for enhanced side-channel resistance"
            }
            (EncryptionAlgorithm::Aes256Gcm, EncryptionAlgorithm::ChaCha20Poly1305) => {
                "ChaCha20-Poly1305 recommended for enhanced side-channel resistance"
            }
            _ => "Both algorithms provide strong security",
        },
    }
}

/// Comparison between two encryption algorithms
#[derive(Debug)]
pub struct AlgorithmComparison {
    pub algorithm1: EncryptionAlgorithm,
    pub algorithm2: EncryptionAlgorithm,
    pub security_level1: bool,
    pub security_level2: bool,
    pub hardware_acceleration1: bool,
    pub hardware_acceleration2: bool,
    pub recommendation: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_properties() {
        assert_eq!(EncryptionAlgorithm::Aes256Gcm.key_size(), 32);
        assert_eq!(EncryptionAlgorithm::Aes256Gcm.nonce_size(), 12);
        assert_eq!(EncryptionAlgorithm::ChaCha20Poly1305.key_size(), 32);
        assert_eq!(EncryptionAlgorithm::ChaCha20Poly1305.nonce_size(), 12);
    }

    #[test]
    fn test_encryption_config() {
        let config = EncryptionConfig::security_optimized();
        assert_eq!(config.algorithm, EncryptionAlgorithm::ChaCha20Poly1305);
        assert_eq!(config.pbkdf2_iterations, 200_000);

        let config = EncryptionConfig::performance_optimized();
        assert_eq!(config.algorithm, EncryptionAlgorithm::Aes256Gcm);
        assert_eq!(config.pbkdf2_iterations, 120_000);
    }

    #[test]
    fn test_chacha20_encryptor() {
        let encryptor = ChaCha20Poly1305Encryptor::new();
        let plaintext = b"Hello, ChaCha20-Poly1305!";
        let key = [0u8; 32]; // 256-bit key

        let encrypted = encryptor.encrypt(plaintext, &key).unwrap();
        assert_eq!(encrypted.algorithm, EncryptionAlgorithm::ChaCha20Poly1305);

        let decrypted = encryptor.decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = generate_nonce(12);
        let nonce2 = generate_nonce(12);

        assert_eq!(nonce1.len(), 12);
        assert_eq!(nonce2.len(), 12);
        assert_ne!(nonce1, nonce2); // Should be random

        // Check for reasonable randomness (not all same bytes)
        let all_same = nonce1.iter().all(|&b| b == nonce1[0]);
        assert!(!all_same);
    }

    #[test]
    fn test_security_validation() {
        let config =
            EncryptionConfig::new(EncryptionAlgorithm::ChaCha20Poly1305).with_iterations(120_000);
        assert!(validate_security_params(&config).is_ok());

        let bad_config =
            EncryptionConfig::new(EncryptionAlgorithm::ChaCha20Poly1305).with_iterations(30_000);
        assert!(validate_security_params(&bad_config).is_err());
    }

    #[test]
    fn test_algorithm_comparison() {
        let comparison = compare_algorithms(
            EncryptionAlgorithm::Aes256Gcm,
            EncryptionAlgorithm::ChaCha20Poly1305,
        );

        assert!(comparison.security_level1);
        assert!(comparison.security_level2);
        assert!(comparison.hardware_acceleration1);
        assert!(!comparison.hardware_acceleration2);
    }
}
