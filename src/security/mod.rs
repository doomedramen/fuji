//! # Comprehensive Security and Credential Management Module
//!
//! This module provides enterprise-grade security capabilities for the Fuji network filesystem,
//! implementing defense-in-depth principles across multiple security domains.
//!
//! ## Core Security Features
//!
//! ### 🔐 Credential Management
//! - **Platform-specific secure storage** (keyring/credential manager integration)
//! - **Encrypted credential files** with AES-256-GCM and ChaCha20-Poly1305 support
//! - **Hardware security module (HSM)** integration for critical credentials
//! - **Environment variable providers** for containerized deployments
//! - **Credential backup and recovery** with encrypted export capabilities
//!
//! ### 🛡️ Authentication & Authorization
//! - **Multi-factor authentication** support
//! - **JWT-based token authentication** for service-to-service communication
//! - **Unix socket authentication** with peer verification
//! - **Role-based access control (RBAC)** for administrative operations
//! - **Session management** with automatic timeout and renewal
//!
//! ### 🔍 Audit & Monitoring
//! - **Real-time audit logging** with tamper-evident storage
//! - **Security event monitoring** with configurable alerting
//! - **Intrusion detection system** with behavioral analysis
//! - **Security dashboard** with comprehensive metrics visualization
//! - **Compliance reporting** for security audits
//!
//! ### 🔒 System Hardening
//! - **Process isolation** using Linux namespaces and seccomp filters
//! - **Resource limits** to prevent denial-of-service attacks
//! - **Secure update mechanism** with cryptographic signature verification
//! - **Runtime integrity verification** to detect tampering
//! - **Path security enforcement** to prevent directory traversal
//!
//! ### 🚨 Advanced Protection
//! - **Memory protection** with secure allocation and wiping
//! - **Key derivation** using PBKDF2 with configurable iteration counts
//! - **Secure random number generation** using system entropy sources
//! - **Side-channel attack mitigation** through constant-time operations
//! - **Forward secrecy** for network communications
//!
//! ## Configuration
//!
//! Security features can be configured through:
//! - Configuration files (`security:` section)
//! - Environment variables (`FUJI_SECURITY_*`)
//! - Runtime configuration via CLI commands
//! - Hardware security module integration
//!
//! ## Examples
//!
//! ```rust,no_run
//! use fuji::security::{CredentialProvider, SecurityConfig};
//!
//! // Initialize secure credential manager
//! let provider = SecurityManager::new()
//!     .with_hardware_backing()
//!     .with_encrypted_storage("/secure/creds.enc")
//!     .build()?;
//!
//! // Store credentials securely
//! let credential = Credential::new("user", "password", Some("domain"));
//! provider.store_credential("nfs-server", &credential).await?;
//!
//! // Retrieve with authentication
//! let retrieved = provider.get_credential("nfs-server").await?;
//! ```
//!
//! ## Security Compliance
//!
//! This module implements security controls aligned with:
//! - **NIST Cybersecurity Framework** (CSF)
//! - **CIS Controls** version 8
//! - **OWASP Application Security Verification Standard**
//! - **ISO 27001** information security management
//!
//! ## Threat Model
//!
//! The security implementation protects against:
//! - **Credential theft** through encryption at rest and in transit
//! - **Privilege escalation** via process isolation and least-privilege principles
//! - **Tampering** through integrity verification and audit logging
//! - **Information disclosure** via access controls and encryption
//! - **Denial of service** through resource limits and monitoring
//!
//! ## Performance Considerations
//!
//! Security features are designed for minimal performance impact:
//! - **Lazy loading** of security modules
//! - **Asynchronous operations** for non-blocking security checks
//! - **Caching** of frequently accessed credentials
//! - **Configurable security levels** for performance-critical environments
//!
//! ## Migration Guide
//!
//! For migrating from previous versions:
//! 1. Backup existing credential stores
//! 2. Update configuration format (see breaking changes)
//! 3. Run migration utilities for credential format upgrades
//! 4. Validate security configuration
//! 5. Monitor audit logs for anomalies during transition

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod audit_logging;
pub mod audit_monitoring;
pub mod audit_monitoring_simple;
pub mod auth;
pub mod config_security;
pub mod credential_backup;
pub mod encryption;
pub mod env_provider;
pub mod error;
pub mod file_provider;
pub mod hardware_credential_provider;
pub mod integrity;
pub mod intrusion_detection;
pub mod key_derivation;
pub mod keyring_provider;
pub mod path_security;
pub mod permissions;
pub mod process_isolation;
pub mod resource_limits;
pub mod seccomp;
pub mod secure_socket;
pub mod secure_updates;
pub mod security_dashboard;
pub mod socket;

// Re-export commonly used error types for convenience
pub use error::{IntoSecurityError, SecurityError, SecurityResult, SecurityResultExt};

/// Credential information for network mounts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// Username for authentication
    pub username: String,
    /// Password or secret
    pub password: String,
    /// Domain for SMB authentication (optional)
    pub domain: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Trait for credential providers
#[async_trait]
pub trait CredentialProvider: Send + Sync {
    /// Store credentials for a given mount
    async fn store_credential(&self, mount_id: &str, credential: &Credential) -> Result<()>;

    /// Retrieve credentials for a given mount
    async fn get_credential(&self, mount_id: &str) -> Result<Option<Credential>>;

    /// Delete credentials for a given mount
    async fn delete_credential(&self, mount_id: &str) -> Result<()>;

    /// List all stored credential IDs
    async fn list_credentials(&self) -> Result<Vec<String>>;

    /// Check if credentials exist for a given mount
    async fn has_credential(&self, mount_id: &str) -> Result<bool>;

    /// Get provider name
    fn provider_name(&self) -> &'static str;
}

/// Manager for multiple credential providers
pub struct CredentialManager {
    providers: Vec<Box<dyn CredentialProvider>>,
}

#[allow(dead_code)]
impl CredentialManager {
    /// Create a new credential manager with default providers
    pub fn new() -> Self {
        let mut providers: Vec<Box<dyn CredentialProvider>> = Vec::new();

        // Add environment provider (highest priority)
        providers.push(Box::new(env_provider::EnvironmentCredentialProvider::new()));

        // Add file provider
        match file_provider::FileCredentialProvider::new() {
            Ok(provider) => providers.push(Box::new(provider)),
            Err(e) => {
                tracing::warn!("Failed to initialize file credential provider: {}", e);
                // Continue without file provider
            }
        }

        // Add keyring provider (lowest priority, but most secure)
        providers.push(Box::new(keyring_provider::KeyringCredentialProvider::new()));

        Self { providers }
    }

    /// Add a custom credential provider
    pub fn add_provider(&mut self, provider: Box<dyn CredentialProvider>) {
        self.providers.push(provider);
    }

    /// Store credentials using the first available provider
    pub async fn store_credential(&self, mount_id: &str, credential: &Credential) -> Result<()> {
        for provider in &self.providers {
            if let Ok(()) = provider.store_credential(mount_id, credential).await {
                tracing::info!(
                    "Stored credential for {} using {}",
                    mount_id,
                    provider.provider_name()
                );
                return Ok(());
            }
        }
        Err(anyhow::anyhow!(
            "No credential provider available for storage"
        ))
    }

    /// Retrieve credentials, checking all providers in order
    pub async fn get_credential(&self, mount_id: &str) -> Result<Option<Credential>> {
        for provider in &self.providers {
            if let Ok(Some(credential)) = provider.get_credential(mount_id).await {
                tracing::info!(
                    "Retrieved credential for {} from {}",
                    mount_id,
                    provider.provider_name()
                );
                return Ok(Some(credential));
            }
        }
        Ok(None)
    }

    /// Delete credentials from all providers
    pub async fn delete_credential(&self, mount_id: &str) -> Result<()> {
        let mut any_success = false;
        for provider in &self.providers {
            if provider.delete_credential(mount_id).await.is_ok() {
                any_success = true;
                tracing::info!(
                    "Deleted credential for {} from {}",
                    mount_id,
                    provider.provider_name()
                );
            }
        }
        if any_success {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Failed to delete credential from any provider"
            ))
        }
    }

    /// List all credentials from all providers
    pub async fn list_credentials(&self) -> Result<Vec<String>> {
        let mut all_ids = std::collections::HashSet::new();
        for provider in &self.providers {
            if let Ok(ids) = provider.list_credentials().await {
                all_ids.extend(ids);
            }
        }
        Ok(all_ids.into_iter().collect())
    }

    /// Check if any provider has credentials for the mount
    pub async fn has_credential(&self, mount_id: &str) -> Result<bool> {
        for provider in &self.providers {
            if provider.has_credential(mount_id).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl Default for CredentialManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_serialization() {
        let credential = Credential {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            domain: Some("TESTDOMAIN".to_string()),
            metadata: HashMap::new(),
        };

        let json = serde_json::to_string(&credential).unwrap();
        let deserialized: Credential = serde_json::from_str(&json).unwrap();

        assert_eq!(credential.username, deserialized.username);
        assert_eq!(credential.password, deserialized.password);
        assert_eq!(credential.domain, deserialized.domain);
    }
}
