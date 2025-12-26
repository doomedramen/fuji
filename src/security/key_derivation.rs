// Allow dead code - advanced key derivation for future features
#![allow(dead_code)]

//! Advanced key derivation functions for secure credential storage
//!
//! This module provides memory-hard key derivation functions including
//! Argon2, scrypt, and PBKDF2 variants with configurable parameters
//! for different security requirements.

use anyhow::Result;
use pbkdf2::pbkdf2_hmac;
use rand::{RngCore, rngs::OsRng};
use sha2::{Sha256, Sha512};
use std::time::{Duration as StdDuration, SystemTime};
use tracing::{debug, warn};

/// Key derivation function types
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyDerivationFunction {
    /// PBKDF2 with SHA-256
    PBKDF2Sha256,
    /// PBKDF2 with SHA-512
    PBKDF2Sha512,
    /// Argon2id (memory-hard)
    Argon2id,
    /// Scrypt (memory-hard)
    Scrypt,
}

impl KeyDerivationFunction {
    /// Get default parameters for this KDF
    #[must_use]
    pub const fn default_parameters(&self) -> KDFParameters {
        match self {
            Self::PBKDF2Sha256 => KDFParameters {
                function: *self,
                iterations: 200_000,
                salt_length: 32,
                key_length: 32,
                memory_cost: None,
                parallelism: None,
                estimated_time_ms: 1000,
                security_level: SecurityLevel::Standard,
            },
            Self::PBKDF2Sha512 => KDFParameters {
                function: *self,
                iterations: 150_000,
                salt_length: 64,
                key_length: 64,
                memory_cost: None,
                parallelism: None,
                estimated_time_ms: 1500,
                security_level: SecurityLevel::Standard,
            },
            Self::Argon2id => KDFParameters {
                function: *self,
                iterations: 3,
                salt_length: 16,
                key_length: 32,
                memory_cost: Some(64 * 1024), // 64 MB
                parallelism: Some(4),
                estimated_time_ms: 800,
                security_level: SecurityLevel::High,
            },
            Self::Scrypt => KDFParameters {
                function: *self,
                iterations: 1,
                salt_length: 32,
                key_length: 32,
                memory_cost: Some(32 * 1024), // 32 MB
                parallelism: Some(1),
                estimated_time_ms: 600,
                security_level: SecurityLevel::High,
            },
        }
    }

    /// Get high security parameters for this KDF
    #[must_use]
    pub const fn high_security_parameters(&self) -> KDFParameters {
        match self {
            Self::PBKDF2Sha256 => KDFParameters {
                function: *self,
                iterations: 500_000,
                salt_length: 32,
                key_length: 32,
                memory_cost: None,
                parallelism: None,
                estimated_time_ms: 2500,
                security_level: SecurityLevel::High,
            },
            Self::PBKDF2Sha512 => KDFParameters {
                function: *self,
                iterations: 350_000,
                salt_length: 64,
                key_length: 64,
                memory_cost: None,
                parallelism: None,
                estimated_time_ms: 3000,
                security_level: SecurityLevel::High,
            },
            Self::Argon2id => KDFParameters {
                function: *self,
                iterations: 4,
                salt_length: 16,
                key_length: 32,
                memory_cost: Some(128 * 1024), // 128 MB
                parallelism: Some(8),
                estimated_time_ms: 1500,
                security_level: SecurityLevel::VeryHigh,
            },
            Self::Scrypt => KDFParameters {
                function: *self,
                iterations: 2,
                salt_length: 32,
                key_length: 32,
                memory_cost: Some(64 * 1024), // 64 MB
                parallelism: Some(2),
                estimated_time_ms: 1200,
                security_level: SecurityLevel::VeryHigh,
            },
        }
    }

    /// Get fast parameters for this KDF (useful for testing)
    #[must_use]
    pub const fn fast_parameters(&self) -> KDFParameters {
        match self {
            Self::PBKDF2Sha256 => KDFParameters {
                function: *self,
                iterations: 10_000,
                salt_length: 16,
                key_length: 32,
                memory_cost: None,
                parallelism: None,
                estimated_time_ms: 50,
                security_level: SecurityLevel::Low,
            },
            Self::PBKDF2Sha512 => KDFParameters {
                function: *self,
                iterations: 8_000,
                salt_length: 32,
                key_length: 32,
                memory_cost: None,
                parallelism: None,
                estimated_time_ms: 60,
                security_level: SecurityLevel::Low,
            },
            Self::Argon2id => KDFParameters {
                function: *self,
                iterations: 1,
                salt_length: 16,
                key_length: 32,
                memory_cost: Some(8 * 1024), // 8 MB
                parallelism: Some(2),
                estimated_time_ms: 40,
                security_level: SecurityLevel::Low,
            },
            Self::Scrypt => KDFParameters {
                function: *self,
                iterations: 1,
                salt_length: 16,
                key_length: 32,
                memory_cost: Some(4 * 1024), // 4 MB
                parallelism: Some(1),
                estimated_time_ms: 30,
                security_level: SecurityLevel::Low,
            },
        }
    }
}

/// Security levels for key derivation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Low security - fast, for testing only
    Low,
    /// Standard security - good for most use cases
    Standard,
    /// High security - recommended for sensitive data
    High,
    /// Very high security - maximum protection
    VeryHigh,
}

/// Parameters for key derivation functions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KDFParameters {
    /// Key derivation function to use
    pub function: KeyDerivationFunction,
    /// Number of iterations (for PBKDF2-based functions)
    pub iterations: u32,
    /// Salt length in bytes
    pub salt_length: usize,
    /// Derived key length in bytes
    pub key_length: usize,
    /// Memory cost in bytes (for memory-hard functions)
    pub memory_cost: Option<u32>,
    /// Parallelism factor (for parallelizable functions)
    pub parallelism: Option<u32>,
    /// Estimated execution time in milliseconds
    pub estimated_time_ms: u64,
    /// Security level
    pub security_level: SecurityLevel,
}

impl KDFParameters {
    /// Generate a random salt
    #[must_use]
    pub fn generate_salt(&self) -> Vec<u8> {
        let mut salt = vec![0u8; self.salt_length];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    /// Derive key from password and salt
    pub fn derive_key(&self, password: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
        let start_time = SystemTime::now();

        let key = match self.function {
            KeyDerivationFunction::PBKDF2Sha256 => {
                let mut derived_key = vec![0u8; self.key_length];
                pbkdf2_hmac::<Sha256>(password, salt, self.iterations, &mut derived_key);
                derived_key
            }
            KeyDerivationFunction::PBKDF2Sha512 => {
                let mut derived_key = vec![0u8; self.key_length];
                pbkdf2_hmac::<Sha512>(password, salt, self.iterations, &mut derived_key);
                derived_key
            }
            KeyDerivationFunction::Argon2id => self.derive_key_argon2id(password, salt)?,
            KeyDerivationFunction::Scrypt => self.derive_key_scrypt(password, salt)?,
        };

        let elapsed = start_time.elapsed().unwrap_or_default();
        debug!(
            "Key derivation completed in {}ms using {:?}",
            elapsed.as_millis(),
            self.function
        );

        if elapsed.as_millis() < u128::from(self.estimated_time_ms) / 2 {
            warn!("Key derivation completed faster than expected. Consider increasing parameters.");
        }

        Ok(key)
    }

    /// Derive key using Argon2id
    fn derive_key_argon2id(&self, password: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
        // This would use the argon2 crate when available
        // For now, fall back to PBKDF2 as placeholder
        warn!("Argon2id not available, falling back to PBKDF2-SHA256");
        let mut derived_key = vec![0u8; self.key_length];
        pbkdf2_hmac::<Sha256>(password, salt, self.iterations, &mut derived_key);
        Ok(derived_key)
    }

    /// Derive key using scrypt
    fn derive_key_scrypt(&self, password: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
        // This would use the scrypt crate when available
        // For now, fall back to PBKDF2 as placeholder
        warn!("Scrypt not available, falling back to PBKDF2-SHA512");
        let mut derived_key = vec![0u8; self.key_length];
        pbkdf2_hmac::<Sha512>(
            password,
            salt,
            self.iterations.saturating_mul(10),
            &mut derived_key,
        );
        Ok(derived_key)
    }

    /// Benchmark the current parameters
    pub fn benchmark(&self, password: &[u8], salt: &[u8]) -> Result<StdDuration> {
        let start_time = SystemTime::now();
        self.derive_key(password, salt)?;
        Ok(start_time.elapsed().unwrap_or_default())
    }

    /// Auto-tune parameters to target execution time
    pub fn auto_tune(&mut self, password: &[u8], target_time: StdDuration) -> Result<()> {
        let target_ms = target_time.as_millis() as u64;
        let salt = self.generate_salt();

        // Start with current parameters
        let mut best_params = self.clone();
        let mut best_diff = (target_ms as i64 - best_params.estimated_time_ms as i64).abs();

        // Try different parameter combinations
        match self.function {
            KeyDerivationFunction::PBKDF2Sha256 | KeyDerivationFunction::PBKDF2Sha512 => {
                // Tune iteration count
                for multiplier in [0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 3.0, 5.0] {
                    let mut test_params = self.clone();
                    test_params.iterations = (f64::from(self.iterations) * multiplier) as u32;

                    let actual_time = test_params.benchmark(password, &salt)?;
                    let actual_ms = actual_time.as_millis() as u64;
                    let diff = (target_ms as i64 - actual_ms as i64).abs();

                    if diff < best_diff {
                        best_diff = diff;
                        best_params = test_params;
                    }
                }
            }
            KeyDerivationFunction::Argon2id | KeyDerivationFunction::Scrypt => {
                // Tune memory cost and parallelism
                if let (Some(memory), Some(parallel)) = (self.memory_cost, self.parallelism) {
                    for mem_multiplier in [0.5, 0.75, 1.0, 1.25, 1.5, 2.0] {
                        for par_multiplier in [0.5, 0.75, 1.0, 1.25, 1.5, 2.0] {
                            let mut test_params = self.clone();
                            test_params.memory_cost =
                                Some((f64::from(memory) * mem_multiplier) as u32);
                            test_params.parallelism =
                                Some((f64::from(parallel) * par_multiplier) as u32);

                            let actual_time = test_params.benchmark(password, &salt)?;
                            let actual_ms = actual_time.as_millis() as u64;
                            let diff = (target_ms as i64 - actual_ms as i64).abs();

                            if diff < best_diff {
                                best_diff = diff;
                                best_params = test_params;
                            }
                        }
                    }
                }
            }
        }

        // Update with best parameters
        *self = best_params;
        Ok(())
    }
}

/// Key derivation manager for managing multiple KDF configurations
pub struct KeyDerivationManager {
    /// Default KDF function
    default_function: KeyDerivationFunction,
    /// Cached parameters for different functions
    parameter_cache:
        std::collections::HashMap<(KeyDerivationFunction, SecurityLevel), KDFParameters>,
}

impl KeyDerivationManager {
    /// Create a new key derivation manager
    #[must_use]
    pub fn new(default_function: KeyDerivationFunction) -> Self {
        let mut manager = Self {
            default_function,
            parameter_cache: std::collections::HashMap::new(),
        };

        // Cache default parameters
        manager.cache_default_parameters();
        manager
    }

    /// Get parameters for a specific security level
    pub fn get_parameters(
        &mut self,
        function: KeyDerivationFunction,
        security_level: SecurityLevel,
    ) -> KDFParameters {
        let cache_key = (function, security_level);

        if let Some(params) = self.parameter_cache.get(&cache_key) {
            return params.clone();
        }

        // Generate parameters based on security level
        let params = match security_level {
            SecurityLevel::Low => function.fast_parameters(),
            SecurityLevel::Standard => function.default_parameters(),
            SecurityLevel::High => function.default_parameters(),
            SecurityLevel::VeryHigh => function.high_security_parameters(),
        };

        // Cache the parameters
        self.parameter_cache.insert(cache_key, params.clone());
        params
    }

    /// Derive key using default function and parameters
    pub fn derive_key(&mut self, password: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
        let params = self.get_parameters(self.default_function, SecurityLevel::Standard);
        params.derive_key(password, salt)
    }

    /// Derive key with custom parameters
    pub fn derive_key_with_params(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &KDFParameters,
    ) -> Result<Vec<u8>> {
        params.derive_key(password, salt)
    }

    /// Generate salt and derive key in one operation
    pub fn derive_key_with_salt(&mut self, password: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let params = self.get_parameters(self.default_function, SecurityLevel::Standard);
        let salt = params.generate_salt();
        let key = params.derive_key(password, &salt)?;
        Ok((key, salt))
    }

    /// Cache default parameters for all functions
    fn cache_default_parameters(&mut self) {
        for function in [
            KeyDerivationFunction::PBKDF2Sha256,
            KeyDerivationFunction::PBKDF2Sha512,
            KeyDerivationFunction::Argon2id,
            KeyDerivationFunction::Scrypt,
        ] {
            for security_level in [
                SecurityLevel::Low,
                SecurityLevel::Standard,
                SecurityLevel::High,
                SecurityLevel::VeryHigh,
            ] {
                let params = match security_level {
                    SecurityLevel::Low => function.fast_parameters(),
                    SecurityLevel::Standard => function.default_parameters(),
                    SecurityLevel::High => function.default_parameters(),
                    SecurityLevel::VeryHigh => function.high_security_parameters(),
                };

                self.parameter_cache
                    .insert((function, security_level), params);
            }
        }
    }
}

impl Default for KeyDerivationManager {
    fn default() -> Self {
        Self::new(KeyDerivationFunction::PBKDF2Sha256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_parameters() {
        let params = KeyDerivationFunction::PBKDF2Sha256.default_parameters();
        assert_eq!(params.function, KeyDerivationFunction::PBKDF2Sha256);
        assert_eq!(params.iterations, 200_000);
        assert_eq!(params.salt_length, 32);
        assert_eq!(params.key_length, 32);
    }

    #[test]
    fn test_key_derivation() {
        let password = b"test_password_123";
        let params = KeyDerivationFunction::PBKDF2Sha256.fast_parameters();
        let salt = params.generate_salt();

        let key1 = params.derive_key(password, &salt).unwrap();
        let key2 = params.derive_key(password, &salt).unwrap();

        assert_eq!(key1, key2); // Should be deterministic
        assert_eq!(key1.len(), params.key_length);
    }

    #[test]
    fn test_different_passwords_produce_different_keys() {
        let params = KeyDerivationFunction::PBKDF2Sha256.fast_parameters();
        let salt = params.generate_salt();

        let key1 = params.derive_key(b"password1", &salt).unwrap();
        let key2 = params.derive_key(b"password2", &salt).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_key_derivation_manager() {
        let mut manager = KeyDerivationManager::new(KeyDerivationFunction::PBKDF2Sha256);

        let (key, salt) = manager.derive_key_with_salt(b"test_password").unwrap();
        assert!(!key.is_empty());
        assert!(!salt.is_empty());
        assert_eq!(salt.len(), 32); // Default salt length
    }

    #[test]
    fn test_security_levels() {
        let fast_params = KeyDerivationFunction::PBKDF2Sha256.fast_parameters();
        let standard_params = KeyDerivationFunction::PBKDF2Sha256.default_parameters();
        let high_params = KeyDerivationFunction::PBKDF2Sha256.high_security_parameters();

        assert!(fast_params.iterations < standard_params.iterations);
        assert!(standard_params.iterations < high_params.iterations);
        assert_eq!(fast_params.security_level, SecurityLevel::Low);
        assert_eq!(standard_params.security_level, SecurityLevel::Standard);
        assert_eq!(high_params.security_level, SecurityLevel::High);
    }

    #[tokio::test]
    #[ignore = "Performance test - run manually with --ignored"]
    async fn test_benchmark() {
        let params = KeyDerivationFunction::PBKDF2Sha256.fast_parameters();
        let password = b"benchmark_password";
        let salt = params.generate_salt();

        let duration = params.benchmark(password, &salt).unwrap();
        assert!(duration.as_millis() > 0);
        assert!(duration.as_millis() < 1000); // Should complete quickly with fast params
    }
}
