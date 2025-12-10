//! Synchronization coordinator for Fuji cluster
//!
//! Manages the coordination of configuration synchronization between
//! cluster nodes using the algorithm described in the plan.

use anyhow::Result;
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use serde_json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration as StdDuration, sleep};
use tracing::{debug, error, info, warn};

use crate::cluster::{ClusterInvitation, ClusterState};
use crate::config::{Config, PeerInfo, PeerStatus};
use crate::network::tcp::TcpTransport;
use crate::sync::merge::ConfigMerger;
use crate::sync::protocol::{
    ConfigUpdate, ConflictResolution as ProtocolConflictResolution,
    ConflictType as ProtocolConflictType, MountConflict, MountVersion, SyncComplete, SyncMessage,
    SyncRequest, SyncResponse,
};

/// Synchronization coordinator
pub struct SyncCoordinator {
    /// Instance ID
    instance_id: String,
    /// Cluster state
    cluster_state: Arc<ClusterState>,
    /// TCP transport layer
    transport: Arc<TcpTransport>,
    /// Current configuration
    config: Arc<RwLock<Config>>,
    /// Pending sync operations
    pending_syncs: Arc<RwLock<HashMap<String, PendingSync>>>,
}

/// Information about a pending sync operation
#[derive(Debug)]
#[allow(dead_code)]
pub struct PendingSync {
    /// Sync request ID
    request_id: String,
    /// When the sync was initiated
    initiated_at: DateTime<Utc>,
    /// Peers that have responded
    responded_peers: Vec<String>,
    /// Configs received from peers
    peer_configs: HashMap<String, Config>,
    /// Total number of peers expected
    total_peers: usize,
}

impl SyncCoordinator {
    /// Create a new sync coordinator
    pub fn new(
        instance_id: String,
        cluster_state: Arc<ClusterState>,
        transport: Arc<TcpTransport>,
        config: Arc<RwLock<Config>>,
    ) -> Self {
        Self {
            instance_id,
            cluster_state,
            transport,
            config,
            pending_syncs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize the coordinator
    pub async fn initialize(&self) -> Result<()> {
        info!(
            "Initializing sync coordinator for instance {}",
            self.instance_id
        );

        // Start the periodic sync checker
        self.start_sync_checker().await;

        // Start the TCP server
        self.transport.start_server().await?;

        Ok(())
    }

    /// Join a cluster using an invitation
    pub async fn join_cluster(&self, invitation: &ClusterInvitation) -> Result<()> {
        info!(
            "Joining cluster with invitation from {}",
            invitation.instance_id
        );

        // Verify the invitation
        if !invitation.verify()? {
            return Err(anyhow!("Invalid invitation signature"));
        }

        if invitation.is_expired() {
            return Err(anyhow!("Invitation has expired"));
        }

        // Add the inviting peer to our cluster state
        let inviting_peer = PeerInfo {
            id: invitation.instance_id.clone(),
            address: invitation.address.clone(),
            psk: invitation.psk.clone(),
            last_seen: Utc::now(),
            status: PeerStatus::Disconnected,
        };

        let inviting_peer_id = inviting_peer.id.clone();
        self.cluster_state.update_peer(inviting_peer).await;

        // Update our configuration with cluster info
        {
            let mut config = self.config.write().await;
            if config.cluster.is_none() {
                config.initialize_cluster(self.instance_id.clone());
            }

            if let Some(cluster) = config.get_cluster_config_mut() {
                // Get the peer from cluster state to avoid clone issue
                if let Some(peer) = self.cluster_state.get_peer(&inviting_peer_id).await {
                    cluster.peers.push(peer);
                }
            }
        }

        // Connect to the inviting peer
        if let Some(peer) = self.cluster_state.get_peer(&inviting_peer_id).await {
            self.transport.connect_to_peer(&peer).await?;
        }

        info!(
            "Successfully joined cluster with instance {}",
            invitation.instance_id
        );
        Ok(())
    }

    /// Process incoming sync message
    pub async fn handle_sync_message(
        &self,
        sender_id: &str,
        message: SyncMessage,
    ) -> Result<SyncMessage> {
        debug!(
            "Processing sync message from {}: {} (id: {})",
            sender_id,
            message.message_type(),
            message.message_id()
        );

        // Update peer's last seen time
        self.cluster_state.mark_peer_seen(sender_id).await;

        match message {
            SyncMessage::SyncRequest(req) => self.handle_sync_request(sender_id, req).await,
            SyncMessage::SyncResponse(resp) => {
                self.handle_sync_response(sender_id, resp).await?;
                Ok(self.create_heartbeat().await)
            }
            SyncMessage::ConfigUpdate(update) => {
                self.handle_config_update(sender_id, update).await?;
                Ok(self.create_heartbeat().await)
            }
            SyncMessage::SyncComplete(comp) => {
                self.handle_sync_complete(sender_id, comp).await?;
                Ok(self.create_heartbeat().await)
            }
            SyncMessage::Heartbeat(_) => {
                // Respond with our own heartbeat
                Ok(self.create_heartbeat().await)
            }
        }
    }

    /// Handle a sync request from another node
    async fn handle_sync_request(
        &self,
        sender_id: &str,
        request: SyncRequest,
    ) -> Result<SyncMessage> {
        debug!(
            "Handling sync request {} from {}",
            request.request_id, sender_id
        );

        // Reset our timer to prevent us from initiating our own sync
        self.cluster_state.mark_peer_request().await;

        // Get our current config
        let config = self.config.read().await.clone();

        // Check for conflicts
        let mut merger = ConfigMerger::new();
        let merged_config = merger
            .merge_configs(&[(self.instance_id.clone(), config.clone())])
            .await?;

        // Convert SyncConflicts to MountConflicts
        let mount_conflicts = self.convert_sync_to_mount_conflicts(
            &merged_config.sync_metadata.pending_conflicts,
            &config,
            &config, // Local and remote are the same here
        )?;

        // Create response
        Ok(SyncMessage::sync_response(
            request.request_id.clone(),
            merged_config.config,
            merged_config.sync_metadata.sync_version,
            mount_conflicts,
        ))
    }

    /// Handle a sync response from another node
    async fn handle_sync_response(&self, sender_id: &str, response: SyncResponse) -> Result<()> {
        debug!("Handling sync response from {}", sender_id);

        // Find the pending sync
        let mut pending = self.pending_syncs.write().await;
        if let Some(sync) = pending.get_mut(&response.request_id) {
            // Record the response
            sync.responded_peers.push(sender_id.to_string());
            sync.peer_configs
                .insert(sender_id.to_string(), response.config);

            // Check if we have all responses
            if sync.responded_peers.len() == sync.total_peers {
                info!("All peers responded to sync {}", response.request_id);

                // Extract all configs for merging
                let mut configs: Vec<(String, Config)> = sync.peer_configs.drain().collect();

                // Add our own config
                let our_config = self.config.read().await.clone();
                configs.push((self.instance_id.clone(), our_config));

                // Perform the merge
                if let Err(e) = self.perform_merge(sync.request_id.clone(), configs).await {
                    error!("Failed to perform merge: {}", e);
                }

                // Remove the completed sync
                pending.remove(&response.request_id);
            }
        } else {
            warn!(
                "Received response for unknown sync request: {}",
                response.request_id
            );
        }

        Ok(())
    }

    /// Handle a config update notification
    async fn handle_config_update(&self, sender_id: &str, update: ConfigUpdate) -> Result<()> {
        info!(
            "Received config update from {} with sync version {}",
            sender_id, update.sync_version
        );

        // Check if this is newer than our current version
        let current_version = {
            let config = self.config.read().await;
            config
                .cluster
                .as_ref()
                .map(|c| c.sync_metadata.sync_version)
                .unwrap_or(0)
        };

        if update.sync_version > current_version {
            // Apply the update
            {
                let mut config = self.config.write().await;
                *config = update.config;

                // Update sync metadata
                if let Some(cluster) = config.get_cluster_config_mut() {
                    cluster.sync_metadata.sync_version = update.sync_version;
                    cluster.sync_metadata.last_sync_at = Some(Utc::now());
                    cluster.sync_metadata.last_modified_by = Some(update.updated_by);
                }
            }

            info!("Applied config update from {}", sender_id);
        } else {
            debug!(
                "Ignoring outdated config update (version {} <= {})",
                update.sync_version, current_version
            );
        }

        Ok(())
    }

    /// Handle a sync complete notification
    async fn handle_sync_complete(&self, sender_id: &str, complete: SyncComplete) -> Result<()> {
        info!(
            "Sync complete notification from {} for version {}",
            sender_id, complete.sync_version
        );

        // Update our known sync version if it's newer
        let current_version = {
            let config = self.config.read().await;
            config
                .cluster
                .as_ref()
                .map(|c| c.sync_metadata.sync_version)
                .unwrap_or(0)
        };

        if complete.sync_version > current_version {
            // We might need to request the updated config
            info!("Sync version mismatch, may need to request updated config");
        }

        Ok(())
    }

    /// Perform configuration merging
    async fn perform_merge(
        &self,
        request_id: String,
        configs: Vec<(String, Config)>,
    ) -> Result<()> {
        info!("Performing merge for sync {}", request_id);

        // Create and run the merger
        let mut merger = ConfigMerger::new();
        let merged = merger.merge_configs(&configs).await?;

        // Extract values before moving
        let sync_version = merged.sync_metadata.sync_version;
        let mount_ids = merged.config.mounts.keys().cloned().collect();

        // Apply the merged configuration
        {
            let mut config = self.config.write().await;
            *config = merged.config.clone();

            // Update sync metadata
            if let Some(cluster) = config.get_cluster_config_mut() {
                cluster.sync_metadata = merged.sync_metadata.clone();
            }

            // Mark as modified by us
            config.mark_modified(&self.instance_id);
        }

        // Save the updated configuration
        // Note: In a real implementation, this would use the platform to save
        debug!("Merged configuration applied");

        // Notify all peers of the update
        let update = SyncMessage::config_update(
            self.config.read().await.clone(),
            sync_version,
            self.instance_id.clone(),
            mount_ids,
        );

        if let Err(failed_peers) = self.transport.broadcast_message(&update).await {
            warn!(
                "Failed to notify some peers of config update: {:?}",
                failed_peers
            );
        }

        // Send sync complete notification to all peers
        let participants: Vec<String> = configs.iter().map(|(id, _)| id.clone()).collect();
        let complete = SyncMessage::sync_complete(
            sync_version,
            self.instance_id.clone(),
            crate::sync::protocol::SyncResult::Success,
            merged.resolved_conflicts.len() as u32,
            participants,
        );

        if let Err(failed_peers) = self.transport.broadcast_message(&complete).await {
            warn!(
                "Failed to notify some peers of sync complete: {:?}",
                failed_peers
            );
        }

        info!(
            "Merge completed for sync {} with version {}",
            request_id, merged.sync_metadata.sync_version
        );
        Ok(())
    }

    /// Start the periodic sync checker
    async fn start_sync_checker(&self) {
        let coordinator = self.clone(); // Arc clone

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(StdDuration::from_secs(60));

            loop {
                interval.tick().await;

                if let Err(e) = coordinator.check_and_initiate_sync().await {
                    error!("Error in sync checker: {}", e);
                }
            }
        });
    }

    /// Check if we should initiate a sync and do so if needed
    async fn check_and_initiate_sync(&self) -> Result<()> {
        if !self.cluster_state.should_initiate_sync().await {
            return Ok(());
        }

        // Get healthy peers
        let sync_config = self.cluster_state.get_sync_config().await;
        let (sync_interval, _) =
            sync_config.unwrap_or((chrono::Duration::minutes(5), chrono::Duration::minutes(10)));

        let peers = self
            .cluster_state
            .get_healthy_peers(
                sync_interval + chrono::Duration::minutes(2), // Add some buffer
            )
            .await;

        if peers.is_empty() {
            debug!("No healthy peers available for sync");
            return Ok(());
        }

        info!("Initiating sync with {} peers", peers.len());

        // Generate a unique request ID
        let request_id = format!(
            "{}-{}",
            self.instance_id,
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );

        // Create pending sync record
        {
            let mut pending = self.pending_syncs.write().await;
            pending.insert(
                request_id.clone(),
                PendingSync {
                    request_id: request_id.clone(),
                    initiated_at: Utc::now(),
                    responded_peers: Vec::new(),
                    peer_configs: HashMap::new(),
                    total_peers: peers.len(),
                },
            );
        }

        // Mark that we initiated a sync
        self.cluster_state.mark_sync_initiated().await;

        // Send sync requests to all peers
        let message = SyncMessage::sync_request(
            request_id.clone(),
            self.instance_id.clone(),
            self.config
                .read()
                .await
                .cluster
                .as_ref()
                .map(|c| c.sync_metadata.sync_version)
                .unwrap_or(0),
        );

        let mut failed_peers = Vec::new();
        for peer in peers {
            if let Err(e) = self.transport.send_message(&peer.id, &message).await {
                warn!("Failed to send sync request to {}: {}", peer.id, e);
                failed_peers.push(peer.id);
            }
        }

        if failed_peers.is_empty() {
            info!("Sent sync requests to all peers");
        } else {
            warn!("Failed to send sync requests to: {:?}", failed_peers);
        }

        // Set a timeout for the sync
        let coordinator = self.clone();
        tokio::spawn(async move {
            sleep(StdDuration::from_secs(60)).await;

            let mut pending = coordinator.pending_syncs.write().await;
            if pending.remove(&request_id).is_some() {
                warn!("Sync request {} timed out", request_id);
            }
        });

        Ok(())
    }

    /// Create a heartbeat message
    async fn create_heartbeat(&self) -> SyncMessage {
        let peer_count = self.cluster_state.get_peers().await.len();
        let sync_version = self
            .config
            .read()
            .await
            .cluster
            .as_ref()
            .map(|c| c.sync_metadata.sync_version)
            .unwrap_or(0);

        SyncMessage::heartbeat(
            self.instance_id.clone(),
            sync_version,
            crate::sync::protocol::NodeStatus::Healthy,
            peer_count,
        )
    }

    /// Convert SyncConflict to MountConflict for protocol communication
    fn convert_sync_to_mount_conflicts(
        &self,
        sync_conflicts: &[crate::config::SyncConflict],
        local_config: &Config,
        remote_config: &Config,
    ) -> Result<Vec<MountConflict>> {
        let mut mount_conflicts = Vec::new();

        for sync_conflict in sync_conflicts {
            // Convert conflict type
            let conflict_type = match sync_conflict.conflict_type {
                crate::config::ConflictType::ConcurrentModification => {
                    ProtocolConflictType::ConcurrentModification
                }
                crate::config::ConflictType::DeleteModifyConflict => {
                    ProtocolConflictType::DeleteModifyConflict
                }
                crate::config::ConflictType::MountPointConflict => {
                    ProtocolConflictType::MountPointConflict
                }
            };

            // Convert resolution
            let suggested_resolution = match sync_conflict.resolution {
                crate::config::ConflictResolution::UsedLatest => {
                    ProtocolConflictResolution::UseLatest
                }
                crate::config::ConflictResolution::UsedInstance(ref instance_id) => {
                    ProtocolConflictResolution::UseInstance(instance_id.clone())
                }
                crate::config::ConflictResolution::RequiresManualIntervention => {
                    ProtocolConflictResolution::Manual
                }
            };

            // Create local version
            let local_version = MountVersion {
                instance_id: self.instance_id.clone(),
                updated_at: local_config
                    .mounts
                    .get(&sync_conflict.mount_id)
                    .map(|w| w.config.updated_at)
                    .unwrap_or_else(|| chrono::Utc::now()),
                mount_data: local_config
                    .mounts
                    .get(&sync_conflict.mount_id)
                    .and_then(|w| serde_json::to_value(&w.config).ok())
                    .unwrap_or(serde_json::Value::Null),
            };

            // Create remote versions for each conflicting instance
            let mut remote_versions = Vec::new();
            for instance_id in &sync_conflict.conflicting_instances {
                if instance_id != &self.instance_id {
                    let mount_data = remote_config
                        .mounts
                        .get(&sync_conflict.mount_id)
                        .and_then(|w| serde_json::to_value(&w.config).ok())
                        .unwrap_or(serde_json::Value::Null);

                    let updated_at = remote_config
                        .mounts
                        .get(&sync_conflict.mount_id)
                        .map(|w| w.config.updated_at)
                        .unwrap_or_else(|| chrono::Utc::now());

                    remote_versions.push(MountVersion {
                        instance_id: instance_id.clone(),
                        updated_at,
                        mount_data,
                    });
                }
            }

            mount_conflicts.push(MountConflict {
                mount_id: sync_conflict.mount_id.clone(),
                conflict_type,
                local_version,
                remote_versions,
                suggested_resolution,
            });
        }

        Ok(mount_conflicts)
    }

    /// Get cluster statistics
    pub async fn get_stats(&self) -> crate::cluster::ClusterStats {
        self.cluster_state.get_stats().await
    }
}

// Implement Clone for SyncCoordinator
impl Clone for SyncCoordinator {
    fn clone(&self) -> Self {
        Self {
            instance_id: self.instance_id.clone(),
            cluster_state: Arc::clone(&self.cluster_state),
            transport: Arc::clone(&self.transport),
            config: Arc::clone(&self.config),
            pending_syncs: Arc::clone(&self.pending_syncs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MountConfigWrapper, MountSyncMetadata};
    use crate::mount::{MountConfig, MountStatus, MountType};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_coordinator_creation() {
        let cluster_state = Arc::new(ClusterState::new());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let transport = Arc::new(TcpTransport::new(addr));
        let config = Arc::new(RwLock::new(Config::default()));

        let coordinator = SyncCoordinator::new(
            "test-instance".to_string(),
            cluster_state,
            transport,
            config,
        );

        assert_eq!(coordinator.instance_id, "test-instance");
    }

    #[tokio::test]
    async fn test_pending_sync() {
        let sync = PendingSync {
            request_id: "test-123".to_string(),
            initiated_at: Utc::now(),
            responded_peers: vec!["peer1".to_string()],
            peer_configs: HashMap::new(),
            total_peers: 2,
        };

        assert_eq!(sync.request_id, "test-123");
        assert_eq!(sync.responded_peers.len(), 1);
        assert_eq!(sync.total_peers, 2);
    }

    #[tokio::test]
    async fn test_sync_to_mount_conflict_conversion() {
        // Create a coordinator
        let cluster_state = Arc::new(ClusterState::new());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let transport = Arc::new(TcpTransport::new(addr));
        let config = Arc::new(RwLock::new(Config::default()));

        let coordinator =
            SyncCoordinator::new("instance-1".to_string(), cluster_state, transport, config);

        // Create test configs with mount data
        let mut local_config = Config::default();
        let remote_config = Config::default();

        let test_mount = MountConfig {
            id: "test-mount".to_string(),
            url: "nfs://server.example.com/share".to_string(),
            mount_type: MountType::Nfs {
                host: "server.example.com".to_string(),
                share: "/share".to_string(),
                options: vec!["rw".to_string()],
            },
            mount_point: PathBuf::from("/mnt/test"),
            enabled: true,
            status: MountStatus::Active,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_connected: None,
            reconnect_attempts: 0,
            metadata: HashMap::new(),
        };

        local_config.mounts.insert(
            "test-mount".to_string(),
            MountConfigWrapper {
                config: test_mount.clone(),
                sync_metadata: Some(MountSyncMetadata {
                    last_modified_by: Some("instance-1".to_string()),
                    version: 1,
                }),
            },
        );

        // Create a sync conflict
        let sync_conflict = crate::config::SyncConflict {
            mount_id: "test-mount".to_string(),
            conflict_type: crate::config::ConflictType::ConcurrentModification,
            conflicting_instances: vec!["instance-2".to_string()],
            resolution: crate::config::ConflictResolution::UsedLatest,
        };

        // Convert to mount conflict
        let mount_conflicts = coordinator
            .convert_sync_to_mount_conflicts(&[sync_conflict], &local_config, &remote_config)
            .unwrap();

        assert_eq!(mount_conflicts.len(), 1);
        let conflict = &mount_conflicts[0];
        assert_eq!(conflict.mount_id, "test-mount");
        assert!(matches!(
            conflict.conflict_type,
            ProtocolConflictType::ConcurrentModification
        ));
        assert!(matches!(
            conflict.suggested_resolution,
            ProtocolConflictResolution::UseLatest
        ));
        assert_eq!(conflict.local_version.instance_id, "instance-1");
        assert_eq!(conflict.remote_versions.len(), 1);
        assert_eq!(conflict.remote_versions[0].instance_id, "instance-2");
    }
}
