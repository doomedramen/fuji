//! Mount type abstraction
//!
//! This module provides an interface for different types of network file systems.

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use url::Url;

pub mod drivers;
pub mod options;
pub mod point;
pub mod state_machine;

/// Mount types supported by Fuji
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MountType {
    /// NFS (Network File System)
    NFS {
        host: String,
        share: String,
        options: Vec<String>,
    },
    /// SMB/CIFS (Windows file sharing)
    SMB {
        host: String,
        share: String,
        username: Option<String>,
        password: Option<String>,
        domain: Option<String>,
        options: Vec<String>,
    },
}

/// Mount status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Copy)]
pub enum MountStatus {
    /// Mount is active and accessible
    Active,
    /// Mount is attempting to reconnect
    Reconnecting,
    /// Mount has failed and is not accessible
    Failed,
    /// Mount is disabled in configuration
    Disabled,
}

impl std::fmt::Display for MountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MountStatus::Active => write!(f, "Active"),
            MountStatus::Reconnecting => write!(f, "Reconnecting"),
            MountStatus::Failed => write!(f, "Failed"),
            MountStatus::Disabled => write!(f, "Disabled"),
        }
    }
}

/// Mount configuration entry
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub last_health_check: DateTime<Utc>,
    /// Connection health score (0-100)
    pub health_score: u8,
}

/// Interface for mount type implementations
#[async_trait]
pub trait MountHandler: Send + Sync {
    /// Get the protocol name
    fn protocol(&self) -> &'static str;

    /// Parse a URL into a mount configuration
    fn parse_url(&self, url: &str) -> Result<MountType>;

    /// Validate a mount configuration
    fn validate_config(&self, config: &MountConfig) -> Result<()>;

    /// Discover available shares from a server
    async fn discover_shares(&self, host: &str) -> Result<Vec<String>>;

    /// Mount a share
    async fn mount(&self, config: &MountConfig, mount_point: &PathBuf) -> Result<()>;

    /// Unmount a share
    async fn unmount(&self, mount_point: &PathBuf) -> Result<()>;

    /// Check if a mount is healthy
    async fn check_health(&self, mount_point: &PathBuf) -> Result<MountState>;

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
        self.status = status;
        self.updated_at = Utc::now();

        if status == MountStatus::Active {
            self.last_connected = Some(Utc::now());
            self.reconnect_attempts = 0;
        }
    }

    /// Increment reconnection attempts
    pub fn increment_reconnect_attempts(&mut self) {
        self.reconnect_attempts += 1;
        self.updated_at = Utc::now();
    }

    /// Reset reconnection attempts
    pub fn reset_reconnect_attempts(&mut self) {
        self.reconnect_attempts = 0;
        self.updated_at = Utc::now();
    }

    /// Check if the mount is in a failure state
    pub fn is_failed(&self) -> bool {
        matches!(self.status, MountStatus::Failed)
    }

    /// Check if the mount is active
    pub fn is_active(&self) -> bool {
        matches!(self.status, MountStatus::Active)
    }

    /// Check if the mount is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
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
