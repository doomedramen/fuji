//! Synchronization protocol for Fuji cluster
//!
//! Defines the message types and protocol for configuration synchronization
//! between cluster nodes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::Config;

/// Synchronization message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SyncMessage {
    /// Request for configuration synchronization
    SyncRequest(SyncRequest),
    /// Response with configuration data
    SyncResponse(SyncResponse),
    /// Configuration update notification
    ConfigUpdate(ConfigUpdate),
    /// Synchronization complete notification
    SyncComplete(SyncComplete),
    /// Heartbeat message
    Heartbeat(Heartbeat),
}

/// Request to synchronize configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    /// Unique request identifier
    pub request_id: String,
    /// ID of the requesting instance
    pub requester_id: String,
    /// Sync version requester knows about
    pub known_version: u64,
    /// Types of mounts to sync (optional filter)
    pub mount_filter: Option<Vec<String>>,
}

/// Response to a sync request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    /// Corresponding request ID
    pub request_id: String,
    /// The configuration data
    pub config: Config,
    /// Current sync version
    pub sync_version: u64,
    /// List of conflicting mounts (if any)
    pub conflicts: Vec<MountConflict>,
}

/// Configuration update notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigUpdate {
    /// Updated configuration
    pub config: Config,
    /// Sync version of this update
    pub sync_version: u64,
    /// ID of the instance that made the change
    pub updated_by: String,
    /// When the change was made
    pub updated_at: DateTime<Utc>,
    /// List of affected mount IDs
    pub affected_mounts: Vec<String>,
}

/// Sync completion notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncComplete {
    /// Sync version that was completed
    pub sync_version: u64,
    /// ID of the instance that initiated the sync
    pub initiator_id: String,
    /// Result of the sync operation
    pub result: SyncResult,
    /// Number of conflicts resolved
    pub conflicts_resolved: u32,
    /// List of peers that participated
    pub participants: Vec<String>,
}

/// Heartbeat message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    /// ID of the sending instance
    pub instance_id: String,
    /// Current timestamp
    pub timestamp: DateTime<Utc>,
    /// Current sync version
    pub sync_version: u64,
    /// Current status
    pub status: NodeStatus,
    /// Number of connected peers
    pub peer_count: usize,
}

/// Result of a sync operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncResult {
    /// Sync completed successfully
    Success,
    /// Sync failed with error
    Failed(String),
    /// Sync completed with conflicts
    Conflict(Vec<MountConflict>),
    /// Sync was aborted
    Aborted,
}

/// Status of a cluster node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeStatus {
    /// Node is healthy and active
    Healthy,
    /// Node is syncing
    Syncing,
    /// Node has encountered errors
    Error(String),
    /// Node is shutting down
    ShuttingDown,
}

/// Information about a mount conflict
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountConflict {
    /// ID of the mount with conflict
    pub mount_id: String,
    /// Type of conflict
    pub conflict_type: ConflictType,
    /// Local version of the mount
    pub local_version: MountVersion,
    /// Remote version(s) of the mount
    pub remote_versions: Vec<MountVersion>,
    /// Suggested resolution
    pub suggested_resolution: ConflictResolution,
}

/// Version information for a mount
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountVersion {
    /// Instance ID that owns this version
    pub instance_id: String,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
    /// Mount configuration data
    pub mount_data: serde_json::Value,
}

/// Type of conflict
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictType {
    /// Same mount modified concurrently
    ConcurrentModification,
    /// Mount deleted locally but modified remotely
    DeleteModifyConflict,
    /// Mount created with conflicting mount points
    MountPointConflict,
    /// Different mount types for same location
    TypeMismatch,
}

/// How to resolve a conflict
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictResolution {
    /// Use the latest version (by timestamp)
    UseLatest,
    /// Use version from specific instance
    UseInstance(String),
    /// Delete the mount
    Delete,
    /// Require manual intervention
    Manual,
}

impl SyncMessage {
    /// Create a new sync request
    #[must_use]
    pub const fn sync_request(
        request_id: String,
        requester_id: String,
        known_version: u64,
    ) -> Self {
        Self::SyncRequest(SyncRequest {
            request_id,
            requester_id,
            known_version,
            mount_filter: None,
        })
    }

    /// Create a sync response
    #[must_use]
    pub const fn sync_response(
        request_id: String,
        config: Config,
        sync_version: u64,
        conflicts: Vec<MountConflict>,
    ) -> Self {
        Self::SyncResponse(SyncResponse {
            request_id,
            config,
            sync_version,
            conflicts,
        })
    }

    /// Create a config update notification
    #[must_use]
    pub fn config_update(
        config: Config,
        sync_version: u64,
        updated_by: String,
        affected_mounts: Vec<String>,
    ) -> Self {
        Self::ConfigUpdate(ConfigUpdate {
            config,
            sync_version,
            updated_by,
            updated_at: Utc::now(),
            affected_mounts,
        })
    }

    /// Create a sync complete notification
    #[must_use]
    pub const fn sync_complete(
        sync_version: u64,
        initiator_id: String,
        result: SyncResult,
        conflicts_resolved: u32,
        participants: Vec<String>,
    ) -> Self {
        Self::SyncComplete(SyncComplete {
            sync_version,
            initiator_id,
            result,
            conflicts_resolved,
            participants,
        })
    }

    /// Create a heartbeat message
    #[must_use]
    pub fn heartbeat(
        instance_id: String,
        sync_version: u64,
        status: NodeStatus,
        peer_count: usize,
    ) -> Self {
        Self::Heartbeat(Heartbeat {
            instance_id,
            timestamp: Utc::now(),
            sync_version,
            status,
            peer_count,
        })
    }

    /// Get the message type as a string
    #[must_use]
    pub const fn message_type(&self) -> &'static str {
        match self {
            Self::SyncRequest(_) => "SyncRequest",
            Self::SyncResponse(_) => "SyncResponse",
            Self::ConfigUpdate(_) => "ConfigUpdate",
            Self::SyncComplete(_) => "SyncComplete",
            Self::Heartbeat(_) => "Heartbeat",
        }
    }

    /// Get a unique identifier for the message
    #[must_use]
    pub fn message_id(&self) -> String {
        match self {
            Self::SyncRequest(req) => format!("req-{}", req.request_id),
            Self::SyncResponse(resp) => format!("resp-{}", resp.request_id),
            Self::ConfigUpdate(_) => {
                format!("update-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0))
            }
            Self::SyncComplete(comp) => {
                format!("complete-{}-{}", comp.sync_version, comp.initiator_id)
            }
            Self::Heartbeat(hb) => format!(
                "hb-{}-{}",
                hb.instance_id,
                hb.timestamp.timestamp_nanos_opt().unwrap_or(0)
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_sync_message_serialization() {
        let message = SyncMessage::sync_request("req-123".to_string(), "instance-1".to_string(), 5);

        let serialized = serde_json::to_string(&message).unwrap();
        let deserialized: SyncMessage = serde_json::from_str(&serialized).unwrap();

        match (message, deserialized) {
            (SyncMessage::SyncRequest(orig), SyncMessage::SyncRequest(de)) => {
                assert_eq!(orig.request_id, de.request_id);
                assert_eq!(orig.requester_id, de.requester_id);
                assert_eq!(orig.known_version, de.known_version);
            }
            _ => panic!("Serialization/deserialization failed"),
        }
    }

    #[test]
    fn test_message_id() {
        let req = SyncMessage::sync_request("test-123".to_string(), "node-1".to_string(), 10);
        assert_eq!(req.message_id(), "req-test-123");

        let update = SyncMessage::config_update(
            Config::default(),
            15,
            "node-1".to_string(),
            vec!["mount-1".to_string()],
        );
        assert!(update.message_id().starts_with("update-"));
    }

    #[test]
    fn test_conflict_resolution() {
        let conflict = MountConflict {
            mount_id: "test-mount".to_string(),
            conflict_type: ConflictType::ConcurrentModification,
            local_version: MountVersion {
                instance_id: "node-1".to_string(),
                updated_at: Utc::now(),
                mount_data: serde_json::json!({"test": "data"}),
            },
            remote_versions: vec![],
            suggested_resolution: ConflictResolution::UseLatest,
        };

        assert_eq!(conflict.mount_id, "test-mount");
        matches!(conflict.conflict_type, ConflictType::ConcurrentModification);
        matches!(conflict.suggested_resolution, ConflictResolution::UseLatest);
    }
}
