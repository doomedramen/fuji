//! Mount type abstraction
//!
//! This module provides an interface for different types of network file systems.

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use url::Url;

pub mod drivers;
pub mod options;
pub mod point;
pub mod state_machine;

/// Mount types supported by Fuji
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MountType {
    /// NFS (Network File System)
    Nfs {
        host: String,
        share: String,
        options: Vec<String>,
    },
    /// SMB/CIFS (Windows file sharing)
    Smb {
        host: String,
        share: String,
        username: Option<String>,
        password: Option<String>,
        domain: Option<String>,
        options: Vec<String>,
    },
    /// SSHFS (SSH File System)
    Sshfs {
        host: String,
        username: Option<String>,
        path: String,
        private_key: Option<String>,
        password: Option<String>,
        options: Vec<String>,
    },
}

/// Mount status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MountStatus {
    /// Mount is active and accessible
    Active,
    /// Mount is attempting to reconnect
    Reconnecting,
    /// Mount has failed and is not accessible
    Failed,
    /// Mount is disabled in configuration
    Disabled,
    /// Mount is in progress (being set up or checked)
    InProgress,
    /// Mount encountered an error
    Error(String),
}

impl std::fmt::Display for MountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MountStatus::Active => write!(f, "Active"),
            MountStatus::Reconnecting => write!(f, "Reconnecting"),
            MountStatus::Failed => write!(f, "Failed"),
            MountStatus::Disabled => write!(f, "Disabled"),
            MountStatus::InProgress => write!(f, "InProgress"),
            MountStatus::Error(msg) => write!(f, "Error: {}", msg),
        }
    }
}

/// Mount configuration entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MountConfig {
    /// Unique identifier for this mount
    pub id: String,
    /// URL of the network share
    pub url: String,
    /// Where it's mounted
    pub mount_point: PathBuf,
    /// Mount type and configuration
    pub mount_type: MountType,
    /// Whether this mount is enabled
    pub enabled: bool,
    /// Current status
    pub status: MountStatus,
    /// When this mount was first configured
    pub created_at: DateTime<Utc>,
    /// When this mount was last updated
    pub updated_at: DateTime<Utc>,
    /// Last successful connection time
    pub last_connected: Option<DateTime<Utc>>,
    /// Number of reconnection attempts
    pub reconnect_attempts: u32,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

/// Mount state information
#[derive(Debug, Clone)]
pub struct MountState {
    /// Whether the mount is currently accessible
    pub accessible: bool,
    /// Last error (if any)
    pub last_error: Option<String>,
    /// Time of last health check
    #[allow(dead_code)] // Set by health monitoring, useful for debugging
    pub last_health_check: DateTime<Utc>,
    /// Connection health score (0-100)
    pub health_score: u8,
}

/// Interface for mount type implementations
#[async_trait]
pub trait MountHandler: Send + Sync {
    /// Get the protocol name
    #[allow(dead_code)] // Part of trait interface, useful for debugging
    fn protocol(&self) -> &'static str;

    /// Parse a URL into a mount configuration
    fn parse_url(&self, url: &str) -> Result<MountType>;

    /// Validate a mount configuration
    fn validate_config(&self, config: &MountConfig) -> Result<()>;

    /// Discover available shares from a server
    async fn discover_shares(&self, host: &str) -> Result<Vec<String>>;

    /// Mount a share
    async fn mount(&self, config: &MountConfig, mount_point: &Path) -> Result<()>;

    /// Unmount a share
    async fn unmount(&self, mount_point: &Path) -> Result<()>;

    /// Check if a mount is healthy
    async fn check_health(&self, mount_point: &Path) -> Result<MountState>;

    /// Get default mount options for this type
    fn get_default_options(&self) -> Vec<String>;

    /// Generate a mount ID for a given URL
    fn generate_mount_id(&self, url: &str) -> Result<String>;

    /// Generate mount point path from URL (preserving directory structure)
    fn generate_mount_point(&self, url: &str) -> Result<PathBuf>;

    /// Get the base mount directory
    fn get_mount_base_dir(&self) -> PathBuf {
        PathBuf::from("/mnt/fuji")
    }
}

impl MountConfig {
    /// Create a new mount configuration
    pub fn new(url: String, mount_type: MountType, mount_point: PathBuf) -> Self {
        let now = Utc::now();
        Self {
            id: Self::generate_id(&url),
            url,
            mount_point,
            mount_type,
            enabled: true,
            status: MountStatus::Disabled,
            created_at: now,
            updated_at: now,
            last_connected: None,
            reconnect_attempts: 0,
            metadata: HashMap::new(),
        }
    }

    /// Generate a unique ID from a URL
    fn generate_id(url: &str) -> String {
        if let Ok(parsed) = Url::parse(url) {
            let host = parsed.host_str().unwrap_or("unknown");
            let mut id = format!("{}_{}", host, parsed.scheme());

            // Add path if present
            if !parsed.path().is_empty() && parsed.path() != "/" {
                id.push('_');
                id.push_str(&parsed.path().trim_start_matches('/').replace('/', "_"));
            }

            id
        } else {
            // Fallback for invalid URLs
            url.replace("://", "_").replace(
                [
                    '/', ':', '?', '#', '[', ']', '@', '!', '$', '&', '\'', '(', ')', '*', '+',
                    ',', ';', '=',
                ],
                "_",
            )
        }
    }

    /// Update the mount status
    pub fn update_status(&mut self, status: MountStatus) {
        let is_active = status == MountStatus::Active;
        self.status = status;
        self.updated_at = Utc::now();

        if is_active {
            self.last_connected = Some(Utc::now());
            self.reconnect_attempts = 0;
        }
    }

    /// Increment reconnection attempts
    pub fn increment_reconnect_attempts(&mut self) {
        self.reconnect_attempts += 1;
        self.updated_at = Utc::now();
    }

    /// Check if the mount is active
    pub fn is_active(&self) -> bool {
        matches!(self.status, MountStatus::Active)
    }

    /// Enable the mount
    pub fn enable(&mut self) {
        self.enabled = true;
        self.update_status(MountStatus::Disabled);
    }

    /// Disable the mount
    pub fn disable(&mut self) {
        self.enabled = false;
        self.update_status(MountStatus::Disabled);
    }
}

/// Factory function to get the appropriate mount handler
pub fn get_mount_handler(protocol: &str) -> Result<Box<dyn MountHandler>> {
    match protocol.to_lowercase().as_str() {
        "nfs" => Ok(Box::new(drivers::NfsHandler::new())),
        "smb" | "cifs" => Ok(Box::new(drivers::SmbHandler::new())),
        "sshfs" | "ssh" => Ok(Box::new(drivers::SshfsHandler::new())),
        _ => Err(anyhow::anyhow!("Unsupported protocol: {}", protocol)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mount_type_nfs_serialization() {
        let mount_type = MountType::Nfs {
            host: "nfs-server.local".to_string(),
            share: "/export/data".to_string(),
            options: vec!["rw".to_string(), "noatime".to_string()],
        };

        let json = serde_json::to_string(&mount_type).unwrap();
        let parsed: MountType = serde_json::from_str(&json).unwrap();

        assert_eq!(mount_type, parsed);
    }

    #[test]
    fn test_mount_type_smb_serialization() {
        let mount_type = MountType::Smb {
            host: "fileserver".to_string(),
            share: "shared".to_string(),
            username: Some("user1".to_string()),
            password: Some("secret".to_string()),
            domain: Some("CORP".to_string()),
            options: vec![],
        };

        let json = serde_json::to_string(&mount_type).unwrap();
        let parsed: MountType = serde_json::from_str(&json).unwrap();

        assert_eq!(mount_type, parsed);
    }

    #[test]
    fn test_mount_type_sshfs_serialization() {
        let mount_type = MountType::Sshfs {
            host: "dev-server.example.com".to_string(),
            username: Some("devuser".to_string()),
            path: "/home/devuser/projects".to_string(),
            private_key: Some("/home/user/.ssh/id_rsa".to_string()),
            password: None,
            options: vec!["reconnect".to_string()],
        };

        let json = serde_json::to_string(&mount_type).unwrap();
        let parsed: MountType = serde_json::from_str(&json).unwrap();

        assert_eq!(mount_type, parsed);
    }

    #[test]
    fn test_mount_status_display() {
        assert_eq!(format!("{}", MountStatus::Active), "Active");
        assert_eq!(format!("{}", MountStatus::Reconnecting), "Reconnecting");
        assert_eq!(format!("{}", MountStatus::Failed), "Failed");
        assert_eq!(format!("{}", MountStatus::Disabled), "Disabled");
        assert_eq!(format!("{}", MountStatus::InProgress), "InProgress");
        assert_eq!(
            format!("{}", MountStatus::Error("test error".to_string())),
            "Error: test error"
        );
    }

    #[test]
    fn test_mount_status_serialization() {
        let statuses = vec![
            MountStatus::Active,
            MountStatus::Reconnecting,
            MountStatus::Failed,
            MountStatus::Disabled,
            MountStatus::InProgress,
            MountStatus::Error("Network timeout".to_string()),
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: MountStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, parsed);
        }
    }

    #[test]
    fn test_mount_config_new() {
        let mount_type = MountType::Nfs {
            host: "server".to_string(),
            share: "/data".to_string(),
            options: vec![],
        };
        let mount_point = PathBuf::from("/mnt/data");

        let config = MountConfig::new(
            "nfs://server/data".to_string(),
            mount_type.clone(),
            mount_point.clone(),
        );

        assert_eq!(config.url, "nfs://server/data");
        assert_eq!(config.mount_point, mount_point);
        assert_eq!(config.mount_type, mount_type);
        assert!(config.enabled);
        assert_eq!(config.status, MountStatus::Disabled);
        assert_eq!(config.reconnect_attempts, 0);
        assert!(config.last_connected.is_none());
    }

    #[test]
    fn test_mount_config_generate_id_nfs() {
        let id = MountConfig::generate_id("nfs://server.local/export/data");
        assert_eq!(id, "server.local_nfs_export_data");
    }

    #[test]
    fn test_mount_config_generate_id_smb() {
        let id = MountConfig::generate_id("smb://fileserver/shared");
        assert_eq!(id, "fileserver_smb_shared");
    }

    #[test]
    fn test_mount_config_generate_id_sshfs() {
        let id = MountConfig::generate_id("sshfs://user@host/path/to/dir");
        assert_eq!(id, "host_sshfs_path_to_dir");
    }

    #[test]
    fn test_mount_config_generate_id_root_path() {
        let id = MountConfig::generate_id("nfs://server/");
        // Root path should not add extra underscore
        assert_eq!(id, "server_nfs");
    }

    #[test]
    fn test_mount_config_generate_id_invalid_url() {
        let id = MountConfig::generate_id("not a valid url");
        // Should fallback to character replacement
        assert!(!id.contains(':'));
        assert!(!id.contains('/'));
    }

    #[test]
    fn test_mount_config_update_status_active() {
        let mount_type = MountType::Nfs {
            host: "server".to_string(),
            share: "/data".to_string(),
            options: vec![],
        };
        let mut config = MountConfig::new(
            "nfs://server/data".to_string(),
            mount_type,
            PathBuf::from("/mnt/data"),
        );

        // Simulate some reconnect attempts
        config.reconnect_attempts = 5;
        config.last_connected = None;

        // Update to Active should reset reconnect_attempts and set last_connected
        config.update_status(MountStatus::Active);

        assert_eq!(config.status, MountStatus::Active);
        assert_eq!(config.reconnect_attempts, 0);
        assert!(config.last_connected.is_some());
    }

    #[test]
    fn test_mount_config_update_status_failed() {
        let mount_type = MountType::Nfs {
            host: "server".to_string(),
            share: "/data".to_string(),
            options: vec![],
        };
        let mut config = MountConfig::new(
            "nfs://server/data".to_string(),
            mount_type,
            PathBuf::from("/mnt/data"),
        );

        let original_reconnect_attempts = config.reconnect_attempts;

        // Update to Failed should NOT reset reconnect_attempts
        config.update_status(MountStatus::Failed);

        assert_eq!(config.status, MountStatus::Failed);
        assert_eq!(config.reconnect_attempts, original_reconnect_attempts);
    }

    #[test]
    fn test_mount_config_increment_reconnect_attempts() {
        let mount_type = MountType::Nfs {
            host: "server".to_string(),
            share: "/data".to_string(),
            options: vec![],
        };
        let mut config = MountConfig::new(
            "nfs://server/data".to_string(),
            mount_type,
            PathBuf::from("/mnt/data"),
        );

        assert_eq!(config.reconnect_attempts, 0);

        config.increment_reconnect_attempts();
        assert_eq!(config.reconnect_attempts, 1);

        config.increment_reconnect_attempts();
        assert_eq!(config.reconnect_attempts, 2);

        config.increment_reconnect_attempts();
        assert_eq!(config.reconnect_attempts, 3);
    }

    #[test]
    fn test_mount_config_is_active() {
        let mount_type = MountType::Nfs {
            host: "server".to_string(),
            share: "/data".to_string(),
            options: vec![],
        };
        let mut config = MountConfig::new(
            "nfs://server/data".to_string(),
            mount_type,
            PathBuf::from("/mnt/data"),
        );

        // Initially disabled, not active
        assert!(!config.is_active());

        config.update_status(MountStatus::Active);
        assert!(config.is_active());

        config.update_status(MountStatus::Reconnecting);
        assert!(!config.is_active());

        config.update_status(MountStatus::Failed);
        assert!(!config.is_active());

        config.update_status(MountStatus::InProgress);
        assert!(!config.is_active());

        config.update_status(MountStatus::Error("test".to_string()));
        assert!(!config.is_active());
    }

    #[test]
    fn test_mount_config_enable_disable() {
        let mount_type = MountType::Nfs {
            host: "server".to_string(),
            share: "/data".to_string(),
            options: vec![],
        };
        let mut config = MountConfig::new(
            "nfs://server/data".to_string(),
            mount_type,
            PathBuf::from("/mnt/data"),
        );

        assert!(config.enabled);

        config.disable();
        assert!(!config.enabled);
        assert_eq!(config.status, MountStatus::Disabled);

        config.enable();
        assert!(config.enabled);
    }

    #[test]
    fn test_mount_config_serialization() {
        let mount_type = MountType::Nfs {
            host: "server".to_string(),
            share: "/data".to_string(),
            options: vec!["rw".to_string()],
        };
        let config = MountConfig::new(
            "nfs://server/data".to_string(),
            mount_type,
            PathBuf::from("/mnt/data"),
        );

        let json = serde_json::to_string(&config).unwrap();
        let parsed: MountConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.id, parsed.id);
        assert_eq!(config.url, parsed.url);
        assert_eq!(config.mount_point, parsed.mount_point);
        assert_eq!(config.mount_type, parsed.mount_type);
        assert_eq!(config.enabled, parsed.enabled);
        assert_eq!(config.status, parsed.status);
    }

    #[test]
    fn test_get_mount_handler_nfs() {
        let handler = get_mount_handler("nfs").unwrap();
        assert_eq!(handler.protocol(), "nfs");
    }

    #[test]
    fn test_get_mount_handler_smb() {
        let handler = get_mount_handler("smb").unwrap();
        assert_eq!(handler.protocol(), "smb");

        let handler = get_mount_handler("cifs").unwrap();
        assert_eq!(handler.protocol(), "smb");
    }

    #[test]
    fn test_get_mount_handler_sshfs() {
        let handler = get_mount_handler("sshfs").unwrap();
        assert_eq!(handler.protocol(), "sshfs");

        let handler = get_mount_handler("ssh").unwrap();
        assert_eq!(handler.protocol(), "sshfs");
    }

    #[test]
    fn test_get_mount_handler_case_insensitive() {
        assert!(get_mount_handler("NFS").is_ok());
        assert!(get_mount_handler("Nfs").is_ok());
        assert!(get_mount_handler("SMB").is_ok());
        assert!(get_mount_handler("SSHFS").is_ok());
    }

    #[test]
    fn test_get_mount_handler_unsupported() {
        let result = get_mount_handler("ftp");
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("Unsupported protocol"));

        let result = get_mount_handler("webdav");
        assert!(result.is_err());

        let result = get_mount_handler("");
        assert!(result.is_err());
    }

    #[test]
    fn test_mount_state_creation() {
        let state = MountState {
            accessible: true,
            last_error: None,
            last_health_check: Utc::now(),
            health_score: 100,
        };

        assert!(state.accessible);
        assert!(state.last_error.is_none());
        assert_eq!(state.health_score, 100);
    }

    #[test]
    fn test_mount_state_with_error() {
        let state = MountState {
            accessible: false,
            last_error: Some("Connection timed out".to_string()),
            last_health_check: Utc::now(),
            health_score: 0,
        };

        assert!(!state.accessible);
        assert_eq!(state.last_error, Some("Connection timed out".to_string()));
        assert_eq!(state.health_score, 0);
    }

    #[test]
    fn test_mount_config_metadata() {
        let mount_type = MountType::Nfs {
            host: "server".to_string(),
            share: "/data".to_string(),
            options: vec![],
        };
        let mut config = MountConfig::new(
            "nfs://server/data".to_string(),
            mount_type,
            PathBuf::from("/mnt/data"),
        );

        // Initially empty
        assert!(config.metadata.is_empty());

        // Add metadata
        config
            .metadata
            .insert("label".to_string(), "Production".to_string());
        config
            .metadata
            .insert("owner".to_string(), "admin".to_string());

        assert_eq!(config.metadata.len(), 2);
        assert_eq!(
            config.metadata.get("label"),
            Some(&"Production".to_string())
        );
        assert_eq!(config.metadata.get("owner"), Some(&"admin".to_string()));
    }

    #[test]
    fn test_mount_type_equality() {
        let nfs1 = MountType::Nfs {
            host: "server".to_string(),
            share: "/data".to_string(),
            options: vec![],
        };
        let nfs2 = MountType::Nfs {
            host: "server".to_string(),
            share: "/data".to_string(),
            options: vec![],
        };
        let nfs3 = MountType::Nfs {
            host: "other-server".to_string(),
            share: "/data".to_string(),
            options: vec![],
        };

        assert_eq!(nfs1, nfs2);
        assert_ne!(nfs1, nfs3);
    }

    #[test]
    fn test_mount_status_equality() {
        assert_eq!(MountStatus::Active, MountStatus::Active);
        assert_ne!(MountStatus::Active, MountStatus::Failed);
        assert_eq!(
            MountStatus::Error("test".to_string()),
            MountStatus::Error("test".to_string())
        );
        assert_ne!(
            MountStatus::Error("test".to_string()),
            MountStatus::Error("other".to_string())
        );
    }
}
