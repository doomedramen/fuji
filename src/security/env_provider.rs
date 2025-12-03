//! Environment variable credential provider
//!
//! Reads credentials from environment variables with the FUJI_MOUNT_ prefix.
//! Supports both simple format and JSON format for complex credentials.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json;
use std::collections::HashMap;
use std::env;
use tracing::{debug, warn};

use super::{Credential, CredentialProvider};

/// Environment variable credential provider
pub struct EnvironmentCredentialProvider {
    cache: HashMap<String, Option<Credential>>,
    prefix: String,
}

impl EnvironmentCredentialProvider {
    /// Create a new environment variable credential provider
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            prefix: "FUJI_MOUNT_".to_string(),
        }
    }

    /// Sanitize mount ID for environment variable usage
    fn sanitize_mount_id(&self, mount_id: &str) -> String {
        mount_id
            .chars()
            .map(|c| match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' => c.to_uppercase(),
                '-' | '.' | '_' => '_',
                _ => '_',
            })
            .collect::<String>()
    }

    /// Parse credential from environment variable value
    fn parse_credential(&self, value: &str) -> Result<Credential> {
        // Try to parse as JSON first
        if value.trim_start().starts_with('{') {
            match serde_json::from_str::<Credential>(value) {
                Ok(credential) => return Ok(credential),
                Err(e) => {
                    warn!("Failed to parse credential as JSON: {}", e);
                    // Fall through to simple format
                }
            }
        }

        // Simple format: username:password[:domain]
        let parts: Vec<&str> = value.split(':').collect();
        if parts.len() < 2 {
            return Err(anyhow!("Invalid credential format: expected username:password"));
        }

        let username = parts[0].to_string();
        let password = parts[1].to_string();
        let domain = if parts.len() > 2 {
            Some(parts[2..].join(":"))
        } else {
            None
        };

        Ok(Credential {
            username,
            password,
            domain,
            metadata: HashMap::new(),
        })
    }

    /// Get credential from environment (with caching)
    fn get_from_env(&mut self, mount_id: &str) -> Option<Credential> {
        let sanitized = self.sanitize_mount_id(mount_id);
        let var_name = format!("{}{}", self.prefix, sanitized);

        match env::var(&var_name) {
            Ok(value) => {
                match self.parse_credential(&value) {
                    Ok(credential) => {
                        debug!("Loaded credential for {} from environment variable {}",
                               mount_id, var_name);
                        Some(credential)
                    }
                    Err(e) => {
                        warn!("Failed to parse credential from {}: {}", var_name, e);
                        None
                    }
                }
            }
            Err(env::VarError::NotPresent) => {
                None
            }
            Err(e) => {
                warn!("Error reading environment variable {}: {}", var_name, e);
                None
            }
        }
    }

    /// Check if any FUJI_MOUNT_ environment variables are set
    pub fn has_credentials(&self) -> bool {
        env::vars()
            .any(|(key, _)| key.starts_with(&self.prefix))
    }

    /// List all available credential mount IDs from environment
    pub fn list_env_credential_ids(&self) -> Vec<String> {
        env::vars()
            .filter_map(|(key, _)| {
                if key.starts_with(&self.prefix) {
                    Some(key[self.prefix.len()..].to_lowercase())
                } else {
                    None
                }
            })
            .collect()
    }
}

#[async_trait]
impl CredentialProvider for EnvironmentCredentialProvider {
    async fn store_credential(&self, _mount_id: &str, _credential: &Credential) -> Result<()> {
        // Environment variables are read-only
        Err(anyhow!("Environment variable provider is read-only"))
    }

    async fn get_credential(&self, mount_id: &str) -> Result<Option<Credential>> {
        // Note: In a real async implementation, we'd need interior mutability
        // For simplicity, we'll read directly from environment each time
        let mut provider = EnvironmentCredentialProvider::new();
        Ok(provider.get_from_env(mount_id))
    }

    async fn delete_credential(&self, _mount_id: &str) -> Result<()> {
        // Environment variables are read-only
        Err(anyhow!("Environment variable provider is read-only"))
    }

    async fn list_credentials(&self) -> Result<Vec<String>> {
        Ok(self.list_env_credential_ids())
    }

    async fn has_credential(&self, mount_id: &str) -> Result<bool> {
        let sanitized = self.sanitize_mount_id(mount_id);
        let var_name = format!("{}{}", self.prefix, sanitized);
        Ok(env::var(&var_name).is_ok())
    }

    fn provider_name(&self) -> &'static str {
        "environment"
    }
}

impl Default for EnvironmentCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_sanitize_mount_id() {
        let provider = EnvironmentCredentialProvider::new();

        assert_eq!(provider.sanitize_mount_id("test-mount"), "TEST_MOUNT");
        assert_eq!(provider.sanitize_mount_id("test.mount.id"), "TEST_MOUNT_ID");
        assert_eq!(provider.sanitize_mount_id("test@mount#id"), "TEST_MOUNT_ID");
    }

    #[test]
    fn test_parse_credential_simple() {
        let provider = EnvironmentCredentialProvider::new();

        let credential = provider.parse_credential("user:pass").unwrap();
        assert_eq!(credential.username, "user");
        assert_eq!(credential.password, "pass");
        assert_eq!(credential.domain, None);

        let credential = provider.parse_credential("user:pass:domain").unwrap();
        assert_eq!(credential.username, "user");
        assert_eq!(credential.password, "pass");
        assert_eq!(credential.domain, Some("domain".to_string()));

        let credential = provider.parse_credential("user:pass:domain:extra").unwrap();
        assert_eq!(credential.username, "user");
        assert_eq!(credential.password, "pass");
        assert_eq!(credential.domain, Some("domain:extra".to_string()));
    }

    #[test]
    fn test_parse_credential_json() {
        let provider = EnvironmentCredentialProvider::new();

        let json = r#"{
            "username": "testuser",
            "password": "testpass",
            "domain": "TESTDOMAIN",
            "metadata": {"key": "value"}
        }"#;

        let credential = provider.parse_credential(json).unwrap();
        assert_eq!(credential.username, "testuser");
        assert_eq!(credential.password, "testpass");
        assert_eq!(credential.domain, Some("TESTDOMAIN".to_string()));
        assert_eq!(credential.metadata.get("key"), Some(&"value".to_string()));
    }

    #[tokio::test]
    async fn test_env_provider() {
        let provider = EnvironmentCredentialProvider::new();

        // Set test environment variable
        env::set_var("FUJI_MOUNT_TEST_MOUNT", "testuser:testpass");

        // Test get_credential
        let credential = provider.get_credential("test-mount").await.unwrap();
        assert!(credential.is_some());

        let credential = credential.unwrap();
        assert_eq!(credential.username, "testuser");
        assert_eq!(credential.password, "testpass");

        // Test has_credential
        assert!(provider.has_credential("test-mount").await.unwrap());
        assert!(!provider.has_credential("nonexistent").await.unwrap());

        // Test list_credentials
        let list = provider.list_credentials().await.unwrap();
        assert!(list.contains(&"test_mount".to_string()));

        // Clean up
        env::remove_var("FUJI_MOUNT_TEST_MOUNT");
    }
}