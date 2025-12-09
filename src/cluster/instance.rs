//! Instance identification and management for cluster nodes
//!
//! This module provides utilities for generating and managing unique instance IDs
//! for Fuji daemon instances in a cluster.

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use toml;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Information about a Fuji instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceInfo {
    /// Unique identifier for this instance
    pub id: String,
    /// Hostname of the machine
    pub hostname: String,
    /// IP address(es) of the machine
    pub ip_addresses: Vec<String>,
    /// When this instance was first created
    pub created_at: DateTime<Utc>,
    /// When this instance was last started
    pub started_at: DateTime<Utc>,
    /// Fuji version
    pub version: String,
}

impl Default for InstanceInfo {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            hostname: gethostname::gethostname().to_string_lossy().to_string(),
            ip_addresses: get_local_ip_addresses(),
            created_at: Utc::now(),
            started_at: Utc::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Instance manager for handling instance identification
pub struct InstanceManager {
    /// Current instance information
    instance_info: InstanceInfo,
}

impl InstanceManager {
    /// Create a new instance manager
    pub fn new(config_dir: PathBuf) -> Self {
        // Try to load from existing config or create new
        let instance_info = Self::load_or_create(&config_dir);

        Self {
            instance_info,
        }
    }

    /// Get the current instance ID
    pub fn get_instance_id(&self) -> &str {
        &self.instance_info.id
    }

    /// Get the current instance information
    pub fn get_instance_info(&self) -> &InstanceInfo {
        &self.instance_info
    }

    /// Load existing instance info or create new
    fn load_or_create(config_dir: &PathBuf) -> InstanceInfo {
        // Try to load from existing config file
        let config_path = config_dir.join("mounts.toml");

        if config_path.exists() {
            match fs::read_to_string(&config_path) {
                Ok(content) => {
                    match toml::from_str::<crate::config::Config>(&content) {
                        Ok(config) => {
                            if let Some(cluster_config) = config.cluster {
                                debug!(
                                    "Loaded existing instance ID: {}",
                                    cluster_config.instance_id
                                );
                                // Create instance info with existing ID
                                let mut info = InstanceInfo::default();
                                info.id = cluster_config.instance_id;
                                info.started_at = Utc::now();
                                return info;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse config file: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read config file: {}", e);
                }
            }
        }

        // Create new instance info
        let info = InstanceInfo::default();
        info!("Creating new instance with ID: {}", info.id);
        info
    }

    /// Update instance information (returns new instance info)
    pub fn update_info<F>(&self, updater: F) -> InstanceInfo
    where
        F: FnOnce(&mut InstanceInfo),
    {
        let mut info = self.instance_info.clone();
        updater(&mut info);
        info
    }

    /// Generate a new instance ID (for recovery situations)
    pub fn regenerate_id() -> InstanceInfo {
        let mut info = InstanceInfo::default();
        info.id = Uuid::new_v4().to_string();
        info.created_at = Utc::now();

        info!("Generated new instance ID: {}", info.id);
        info
    }

    /// Check if this instance has been running for longer than the specified duration
    pub fn uptime(&self) -> chrono::Duration {
        Utc::now() - self.instance_info.started_at
    }
}

/// Get local IP addresses
fn get_local_ip_addresses() -> Vec<String> {
    let mut ips = Vec::new();

    // Get localhost
    ips.push("127.0.0.1".to_string());
    ips.push("::1".to_string());

    // Try to get actual network interfaces
    if let Ok(interfaces) = get_if_addrs::get_if_addrs() {
        for iface in interfaces {
            if iface.is_loopback() {
                continue;
            }

            match iface.addr {
                get_if_addrs::IfAddr::V4(addr) => {
                    ips.push(addr.ip.to_string());
                }
                get_if_addrs::IfAddr::V6(addr) => {
                    ips.push(addr.ip.to_string());
                }
            }
        }
    }

    ips
}

/// Generate a pre-shared key for cluster authentication
pub fn generate_psk() -> Result<String> {
    use rand::distributions::Alphanumeric;
    use rand::{Rng, thread_rng};

    let psk: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    Ok(psk)
}

/// Sign data with HMAC-SHA256 using the provided key
pub fn sign_data(key: &str, data: &str) -> Result<String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .map_err(|e| anyhow!("Failed to create HMAC: {}", e))?;
    mac.update(data.as_bytes());

    Ok(format!("{:x}", mac.finalize().into_bytes()))
}

/// Verify HMAC signature
pub fn verify_signature(key: &str, data: &str, signature: &str) -> Result<bool> {
    let expected_signature = sign_data(key, data)?;
    Ok(expected_signature == signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::TempDir;

    #[test]
    fn test_instance_manager() {
        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path().to_path_buf();

        // Create instance manager
        let manager = InstanceManager::new(config_dir.clone());

        // Check instance ID
        let id1 = manager.get_instance_id().to_string();
        assert!(!id1.is_empty());

        // Reload and check persistence
        let manager2 = InstanceManager::new(config_dir);
        assert_eq!(manager2.get_instance_id(), id1);
    }

    #[test]
    fn test_psk_generation() {
        let psk1 = generate_psk().unwrap();
        let psk2 = generate_psk().unwrap();

        assert_eq!(psk1.len(), 32);
        assert_eq!(psk2.len(), 32);
        assert_ne!(psk1, psk2);
    }

    #[test]
    fn test_signing() {
        let key = "test_key";
        let data = "test_data";

        let signature = sign_data(key, data).unwrap();
        assert!(!signature.is_empty());

        assert!(verify_signature(key, data, &signature).unwrap());
        assert!(!verify_signature("wrong_key", data, &signature).unwrap());
        assert!(!verify_signature(key, "wrong_data", &signature).unwrap());
    }

    #[test]
    fn test_get_local_ips() {
        let ips = get_local_ip_addresses();
        assert!(!ips.is_empty());
        assert!(ips.contains(&"127.0.0.1".to_string()));
    }
}
