//! Security and credential management module
//!
//! This module provides secure credential handling for network mounts with support for:
//! - Platform-specific secure storage (keyring)
//! - Encrypted credential files
//! - Environment variable providers
//! - Unix socket authentication
//! - Mount point permission management

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod auth;
pub mod env_provider;
pub mod file_provider;
pub mod keyring_provider;
pub mod permissions;
pub mod socket;

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

impl CredentialManager {
    /// Create a new credential manager with default providers
    pub fn new() -> Self {
        let mut providers: Vec<Box<dyn CredentialProvider>> = Vec::new();

        // Add environment provider (highest priority)
        providers.push(Box::new(env_provider::EnvironmentCredentialProvider::new()));

        // Add file provider
        providers.push(Box::new(file_provider::FileCredentialProvider::new()));

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
