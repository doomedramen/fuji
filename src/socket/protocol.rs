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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_request_ping_serialization() {
        let request = Request::Ping;
        let json = request.to_json().unwrap();
        assert!(json.contains("Ping"));

        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Request::Ping));
    }

    #[test]
    fn test_request_mount_serialization() {
        let request = Request::Mount {
            url: "nfs://server/share".to_string(),
            mount_point: Some("/mnt/test".to_string()),
            options: Some(vec!["ro".to_string(), "noatime".to_string()]),
            disable: false,
            dry_run: true,
            progress: false,
        };

        let json = request.to_json().unwrap();
        assert!(json.contains("nfs://server/share"));
        assert!(json.contains("/mnt/test"));
        assert!(json.contains("noatime"));

        let parsed: Request = serde_json::from_str(&json).unwrap();
        if let Request::Mount {
            url,
            mount_point,
            options,
            dry_run,
            ..
        } = parsed
        {
            assert_eq!(url, "nfs://server/share");
            assert_eq!(mount_point, Some("/mnt/test".to_string()));
            assert_eq!(options, Some(vec!["ro".to_string(), "noatime".to_string()]));
            assert!(dry_run);
        } else {
            panic!("Expected Mount request");
        }
    }

    #[test]
    fn test_request_unmount_serialization() {
        let request = Request::Unmount {
            mount_id: "test-mount".to_string(),
            force: true,
        };

        let json = request.to_json().unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();

        if let Request::Unmount {
            mount_id,
            force,
        } = parsed
        {
            assert_eq!(mount_id, "test-mount");
            assert!(force);
        } else {
            panic!("Expected Unmount request");
        }
    }

    #[test]
    fn test_request_status_serialization() {
        let request = Request::Status {
            verbose: true,
            watch: false,
            json: true,
            filter_url: Some("nfs://".to_string()),
            filter_type: None,
            filter_point: None,
            filter_status: Some("active".to_string()),
        };

        let json = request.to_json().unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();

        if let Request::Status {
            verbose,
            watch,
            json: json_flag,
            filter_url,
            filter_status,
            ..
        } = parsed
        {
            assert!(verbose);
            assert!(!watch);
            assert!(json_flag);
            assert_eq!(filter_url, Some("nfs://".to_string()));
            assert_eq!(filter_status, Some("active".to_string()));
        } else {
            panic!("Expected Status request");
        }
    }

    #[test]
    fn test_request_list_serialization() {
        let request = Request::List {
            enabled_only: true,
            disabled_only: false,
            json: true,
            filter_url: None,
            filter_type: Some("nfs".to_string()),
            filter_point: None,
        };

        let json = request.to_json().unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();

        if let Request::List {
            enabled_only,
            disabled_only,
            json: json_flag,
            filter_type,
            ..
        } = parsed
        {
            assert!(enabled_only);
            assert!(!disabled_only);
            assert!(json_flag);
            assert_eq!(filter_type, Some("nfs".to_string()));
        } else {
            panic!("Expected List request");
        }
    }

    #[test]
    fn test_request_stop_daemon_serialization() {
        let request = Request::StopDaemon;
        let json = request.to_json().unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Request::StopDaemon));
    }

    #[test]
    fn test_request_get_logs_serialization() {
        let request = Request::GetLogs {
            lines: Some(100),
        };
        let json = request.to_json().unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();

        if let Request::GetLogs {
            lines,
        } = parsed
        {
            assert_eq!(lines, Some(100));
        } else {
            panic!("Expected GetLogs request");
        }
    }

    #[test]
    fn test_request_discover_serialization() {
        let request = Request::Discover {
            url: "smb://fileserver".to_string(),
        };
        let json = request.to_json().unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();

        if let Request::Discover {
            url,
        } = parsed
        {
            assert_eq!(url, "smb://fileserver");
        } else {
            panic!("Expected Discover request");
        }
    }

    #[test]
    fn test_request_enable_disable_serialization() {
        let enable = Request::Enable {
            mount_id: "mount1".to_string(),
        };
        let disable = Request::Disable {
            mount_id: "mount2".to_string(),
        };

        let enable_json = enable.to_json().unwrap();
        let disable_json = disable.to_json().unwrap();

        let enable_parsed: Request = serde_json::from_str(&enable_json).unwrap();
        let disable_parsed: Request = serde_json::from_str(&disable_json).unwrap();

        if let Request::Enable {
            mount_id,
        } = enable_parsed
        {
            assert_eq!(mount_id, "mount1");
        } else {
            panic!("Expected Enable request");
        }

        if let Request::Disable {
            mount_id,
        } = disable_parsed
        {
            assert_eq!(mount_id, "mount2");
        } else {
            panic!("Expected Disable request");
        }
    }

    #[test]
    fn test_request_remove_remount_serialization() {
        let remove = Request::Remove {
            mount_id: "old-mount".to_string(),
        };
        let remount = Request::Remount {
            mount_id: "flaky-mount".to_string(),
        };

        let remove_parsed: Request = serde_json::from_str(&remove.to_json().unwrap()).unwrap();
        let remount_parsed: Request = serde_json::from_str(&remount.to_json().unwrap()).unwrap();

        assert!(matches!(remove_parsed, Request::Remove { mount_id } if mount_id == "old-mount"));
        assert!(
            matches!(remount_parsed, Request::Remount { mount_id } if mount_id == "flaky-mount")
        );
    }

    #[test]
    fn test_request_get_config_doctor_serialization() {
        let get_config = Request::GetConfig;
        let doctor = Request::Doctor;

        assert!(matches!(
            serde_json::from_str::<Request>(&get_config.to_json().unwrap()).unwrap(),
            Request::GetConfig
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(&doctor.to_json().unwrap()).unwrap(),
            Request::Doctor
        ));
    }

    #[test]
    fn test_request_force_sync_serialization() {
        let force_sync = Request::ForceSync {
            reason: Some("Manual trigger".to_string()),
        };

        let json = force_sync.to_json().unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();

        if let Request::ForceSync {
            reason,
        } = parsed
        {
            assert_eq!(reason, Some("Manual trigger".to_string()));
        } else {
            panic!("Expected ForceSync request");
        }
    }

    #[test]
    fn test_response_success_serialization() {
        let response = Response::Success;
        let json = response.to_json().unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Response::Success));
    }

    #[test]
    fn test_response_pong_serialization() {
        let response = Response::Pong;
        let json = response.to_json().unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Response::Pong));
    }

    #[test]
    fn test_response_mount_success_serialization() {
        let response = Response::MountSuccess {
            mount_id: "new-mount".to_string(),
            mount_point: PathBuf::from("/mnt/shares/new"),
        };

        let json = response.to_json().unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();

        if let Response::MountSuccess {
            mount_id,
            mount_point,
        } = parsed
        {
            assert_eq!(mount_id, "new-mount");
            assert_eq!(mount_point, PathBuf::from("/mnt/shares/new"));
        } else {
            panic!("Expected MountSuccess response");
        }
    }

    #[test]
    fn test_response_error_serialization() {
        let response = Response::Error("Connection refused".to_string());
        let json = response.to_json().unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();

        if let Response::Error(msg) = parsed {
            assert_eq!(msg, "Connection refused");
        } else {
            panic!("Expected Error response");
        }
    }

    #[test]
    fn test_response_logs_serialization() {
        let response = Response::Logs {
            lines: vec![
                "2024-01-01 INFO Started".to_string(),
                "2024-01-01 INFO Mount successful".to_string(),
            ],
        };

        let json = response.to_json().unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();

        if let Response::Logs {
            lines,
        } = parsed
        {
            assert_eq!(lines.len(), 2);
            assert!(lines[0].contains("Started"));
        } else {
            panic!("Expected Logs response");
        }
    }

    #[test]
    fn test_response_discovered_shares_serialization() {
        let response = Response::DiscoveredShares {
            url: "nfs://server".to_string(),
            shares: vec![
                "/data".to_string(),
                "/media".to_string(),
                "/backup".to_string(),
            ],
        };

        let json = response.to_json().unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();

        if let Response::DiscoveredShares {
            url,
            shares,
        } = parsed
        {
            assert_eq!(url, "nfs://server");
            assert_eq!(shares.len(), 3);
            assert!(shares.contains(&"/data".to_string()));
        } else {
            panic!("Expected DiscoveredShares response");
        }
    }

    #[test]
    fn test_response_config_serialization() {
        let config_toml = r#"[mounts]
enabled = true
url = "nfs://server/share"
"#;
        let response = Response::Config {
            config: config_toml.to_string(),
        };

        let json = response.to_json().unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();

        if let Response::Config {
            config,
        } = parsed
        {
            assert!(config.contains("nfs://server/share"));
        } else {
            panic!("Expected Config response");
        }
    }

    #[test]
    fn test_response_doctor_report_serialization() {
        let response = Response::DoctorReport {
            issues: vec![
                Issue {
                    severity: IssueSeverity::Error,
                    message: "NFS server unreachable".to_string(),
                    component: "mount".to_string(),
                },
                Issue {
                    severity: IssueSeverity::Warning,
                    message: "Low disk space".to_string(),
                    component: "system".to_string(),
                },
            ],
            suggestions: vec![
                "Check network connectivity".to_string(),
                "Free up disk space".to_string(),
            ],
        };

        let json = response.to_json().unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();

        if let Response::DoctorReport {
            issues,
            suggestions,
        } = parsed
        {
            assert_eq!(issues.len(), 2);
            assert_eq!(suggestions.len(), 2);
            assert!(matches!(issues[0].severity, IssueSeverity::Error));
            assert!(matches!(issues[1].severity, IssueSeverity::Warning));
        } else {
            panic!("Expected DoctorReport response");
        }
    }

    #[test]
    fn test_issue_severity_serialization() {
        let error = IssueSeverity::Error;
        let warning = IssueSeverity::Warning;
        let info = IssueSeverity::Info;

        let error_json = serde_json::to_string(&error).unwrap();
        let warning_json = serde_json::to_string(&warning).unwrap();
        let info_json = serde_json::to_string(&info).unwrap();

        assert_eq!(
            serde_json::from_str::<IssueSeverity>(&error_json).unwrap(),
            IssueSeverity::Error
        );
        assert_eq!(
            serde_json::from_str::<IssueSeverity>(&warning_json).unwrap(),
            IssueSeverity::Warning
        );
        assert_eq!(
            serde_json::from_str::<IssueSeverity>(&info_json).unwrap(),
            IssueSeverity::Info
        );
    }

    #[test]
    fn test_daemon_health_info_serialization() {
        let health_info = DaemonHealthInfo {
            healthy: true,
            uptime: Some(std::time::Duration::from_secs(3600)),
            last_check: Some(Utc::now()),
            issues: vec!["Minor: Connection timeout".to_string()],
            cluster_info: None,
        };

        let json = serde_json::to_string(&health_info).unwrap();
        let parsed: DaemonHealthInfo = serde_json::from_str(&json).unwrap();

        assert!(parsed.healthy);
        assert_eq!(parsed.uptime, Some(std::time::Duration::from_secs(3600)));
        assert_eq!(parsed.issues.len(), 1);
    }

    #[test]
    fn test_cluster_info_serialization() {
        let cluster_info = ClusterInfo {
            instance_id: "node-001".to_string(),
            cluster_enabled: true,
            peers_connected: 3,
            last_sync: Some(Utc::now()),
            force_sync_info: None,
        };

        let json = serde_json::to_string(&cluster_info).unwrap();
        let parsed: ClusterInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.instance_id, "node-001");
        assert!(parsed.cluster_enabled);
        assert_eq!(parsed.peers_connected, 3);
    }

    #[test]
    fn test_force_sync_info_serialization() {
        let sync_info = ForceSyncInfo {
            in_progress: true,
            last_initiated: Some(Utc::now()),
            initiated_by: Some("admin".to_string()),
            reason: Some("Config drift detected".to_string()),
            attempt_count: 2,
            last_result: None,
        };

        let json = serde_json::to_string(&sync_info).unwrap();
        let parsed: ForceSyncInfo = serde_json::from_str(&json).unwrap();

        assert!(parsed.in_progress);
        assert_eq!(parsed.initiated_by, Some("admin".to_string()));
        assert_eq!(parsed.attempt_count, 2);
    }
}

impl PartialEq for IssueSeverity {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::Error, Self::Error) | (Self::Warning, Self::Warning) | (Self::Info, Self::Info)
        )
    }
}
