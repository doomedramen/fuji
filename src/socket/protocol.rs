//! Protocol definitions for socket communication

use crate::mount::{MountConfig, MountStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Request from CLI to daemon
#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    /// Ping the daemon
    Ping,

    /// Mount a network share
    Mount {
        url: String,
        mount_point: Option<String>,
        options: Option<Vec<String>>,
        disable: bool,
        dry_run: bool,
        progress: bool,
    },

    /// Unmount a share
    Unmount {
        mount_id: String,
        force: bool,
    },

    /// Get current status
    Status {
        verbose: bool,
        watch: bool,
        json: bool,
        filter_url: Option<String>,
        filter_type: Option<String>,
        filter_point: Option<String>,
        filter_status: Option<String>,
    },

    /// List all configured mounts
    List {
        enabled_only: bool,
        disabled_only: bool,
        json: bool,
        filter_url: Option<String>,
        filter_type: Option<String>,
        filter_point: Option<String>,
    },

    /// Stop the daemon
    StopDaemon,

    /// Get daemon logs
    GetLogs {
        lines: Option<usize>,
    },

    /// Discover shares on a server
    Discover {
        url: String,
    },

    /// Enable a mount
    Enable {
        mount_id: String,
    },

    /// Disable a mount
    Disable {
        mount_id: String,
    },

    /// Remove a mount completely
    Remove {
        mount_id: String,
    },

    /// Force reconnection of a mount
    Remount {
        mount_id: String,
    },

    /// Get configuration
    GetConfig,

    /// Check system for issues
    Doctor,

    /// Force cluster synchronization
    ForceSync {
        reason: Option<String>,
    },
}

/// Response from daemon to CLI
#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    /// Successful response
    Success,

    /// Ping response
    Pong,

    /// Mount response with mount ID
    MountSuccess {
        mount_id: String,
        mount_point: PathBuf,
    },

    /// Unmount response
    UnmountSuccess,

    /// Status information
    Status {
        mounts: Vec<MountStatusInfo>,
        daemon_running: bool,
        daemon_health: Option<DaemonHealthInfo>,
    },

    /// List of mounts
    MountList {
        mounts: Vec<MountConfig>,
    },

    /// Log lines
    Logs {
        lines: Vec<String>,
    },

    /// Discovered shares
    DiscoveredShares {
        url: String,
        shares: Vec<String>,
    },

    /// Configuration data
    Config {
        config: String, // TOML formatted
    },

    /// Doctor report
    DoctorReport {
        issues: Vec<Issue>,
        suggestions: Vec<String>,
    },

    /// Error response
    Error(String),
}

/// Information about a mount's status
#[derive(Debug, Serialize, Deserialize)]
pub struct MountStatusInfo {
    pub id: String,
    pub url: String,
    pub mount_point: PathBuf,
    pub status: MountStatus,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_connected: Option<DateTime<Utc>>,
    pub reconnect_attempts: u32,
    pub health_score: Option<u8>,
}

/// Information about daemon health
#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonHealthInfo {
    pub healthy: bool,
    pub uptime: Option<std::time::Duration>,
    pub last_check: Option<DateTime<Utc>>,
    pub issues: Vec<String>,
    pub cluster_info: Option<ClusterInfo>,
}

/// Cluster information for daemon status
#[derive(Debug, Serialize, Deserialize)]
pub struct ClusterInfo {
    pub instance_id: String,
    pub cluster_enabled: bool,
    pub peers_connected: usize,
    pub last_sync: Option<DateTime<Utc>>,
    pub force_sync_info: Option<ForceSyncInfo>,
}

/// Force sync information
#[derive(Debug, Serialize, Deserialize)]
pub struct ForceSyncInfo {
    pub in_progress: bool,
    pub last_initiated: Option<DateTime<Utc>>,
    pub initiated_by: Option<String>,
    pub reason: Option<String>,
    pub attempt_count: u32,
    pub last_result: Option<crate::config::ForceSyncResult>,
}

/// System issue identified by doctor
#[derive(Debug, Serialize, Deserialize)]
pub struct Issue {
    pub severity: IssueSeverity,
    pub message: String,
    pub component: String,
}

/// Issue severity levels
#[derive(Debug, Serialize, Deserialize)]
pub enum IssueSeverity {
    Error,
    Warning,
    Info,
}

/// Trait for serializing to JSON with error handling
pub trait ToJson {
    fn to_json(&self) -> Result<String, serde_json::Error>;
}

impl ToJson for Request {
    fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

impl ToJson for Response {
    fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}
