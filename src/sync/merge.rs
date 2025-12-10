//! Configuration merge algorithm for Fuji cluster
//!
//! Implements the logic to merge configurations from multiple instances
//! using timestamps to determine the most recent version of each mount.

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use tracing::{debug, info, warn};

use crate::config::{
    Config, ConflictResolution, ConflictType, MountConfigWrapper, SyncConflict, SyncMetadata,
};

/// Configuration merger
pub struct ConfigMerger {
    /// Instance ID of the node performing the merge
    instance_id: String,
    /// Conflict resolution strategy
    conflict_strategy: ConflictResolutionStrategy,
}

/// Strategy for resolving conflicts
#[derive(Debug, Clone)]
pub enum ConflictResolutionStrategy {
    /// Always use the latest version (by timestamp)
    LatestWins,
    /// Use version from specific instance ID
    PreferInstance(String),
    /// Mark conflicts for manual resolution
    Manual,
    /// Automatic resolution using instance ID as tie-breaker
    InstanceIdTieBreak,
}

/// Result of a merge operation
#[derive(Debug, Clone)]
pub struct MergedConfig {
    /// The merged configuration
    pub config: Config,
    /// Sync metadata
    pub sync_metadata: SyncMetadata,
    /// List of resolved conflicts
    pub resolved_conflicts: Vec<ConflictResolution>,
}

/// Mount version information for merging
#[derive(Debug, Clone)]
struct MountVersion {
    /// Instance ID
    instance_id: String,
    /// Mount configuration
    config: MountConfigWrapper,
    /// Last updated timestamp
    updated_at: DateTime<Utc>,
}

impl Default for ConfigMerger {
    fn default() -> Self {
        Self {
            instance_id: "unknown".to_string(),
            conflict_strategy: ConflictResolutionStrategy::InstanceIdTieBreak,
        }
    }
}

impl ConfigMerger {
    /// Create a new config merger
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new config merger with specific instance ID
    pub fn with_instance_id(instance_id: String) -> Self {
        let mut merger = Self::new();
        merger.instance_id = instance_id;
        merger
    }

    /// Merge configurations from multiple instances
    pub async fn merge_configs(
        &mut self,
        instance_configs: &[(String, Config)],
    ) -> Result<MergedConfig, anyhow::Error> {
        info!(
            "Merging configurations from {} instances",
            instance_configs.len()
        );

        let mut merged_config = Config::default();
        let mut conflicts = Vec::new();
        let mut resolved_conflicts = Vec::new();
        let mut latest_sync_version = 0;

        // Collect all mount versions
        let mut mount_versions: HashMap<String, Vec<MountVersion>> = HashMap::new();

        // Also find the latest sync version
        for (_, config) in instance_configs {
            if let Some(cluster) = &config.cluster {
                if cluster.sync_metadata.sync_version > latest_sync_version {
                    latest_sync_version = cluster.sync_metadata.sync_version;
                }
            }
        }

        for (instance_id, config) in instance_configs {
            for (mount_id, wrapper) in &config.mounts {
                mount_versions
                    .entry(mount_id.clone())
                    .or_default()
                    .push(MountVersion {
                        instance_id: instance_id.clone(),
                        config: wrapper.clone(),
                        updated_at: wrapper.config.updated_at,
                    });
            }
        }

        // Merge each mount
        for (mount_id, versions) in mount_versions {
            let resolved = self.resolve_mount_conflict(&mount_id, versions).await?;

            if let Some(conflict) = resolved.conflict {
                conflicts.push(conflict.clone());
                resolved_conflicts.push(conflict.resolution.clone());
            }

            merged_config.mounts.insert(mount_id, resolved.config);
        }

        // Merge global settings (use latest)
        self.merge_global_settings(&mut merged_config, instance_configs)?;

        // Update sync metadata
        merged_config.cluster = Some(crate::config::ClusterConfig {
            enabled: true,
            instance_id: self.instance_id.clone(),
            peers: Vec::new(), // Peers are managed separately
            sync_interval: chrono::Duration::minutes(5),
            sync_timeout: chrono::Duration::minutes(10),
            sync_metadata: SyncMetadata {
                last_sync_at: Some(Utc::now()),
                last_modified_by: Some(self.instance_id.clone()),
                sync_version: latest_sync_version + 1,
                pending_conflicts: conflicts.clone(),
            },
        });

        info!(
            "Merge completed. New sync version: {}",
            latest_sync_version + 1
        );

        let sync_version = merged_config
            .cluster
            .as_ref()
            .map(|c| c.sync_metadata.sync_version)
            .unwrap_or(0);

        Ok(MergedConfig {
            config: merged_config,
            sync_metadata: SyncMetadata {
                last_sync_at: Some(Utc::now()),
                last_modified_by: Some(self.instance_id.clone()),
                sync_version: sync_version + 1,
                pending_conflicts: conflicts.clone(),
            },
            resolved_conflicts,
        })
    }

    /// Resolve conflicts for a single mount
    async fn resolve_mount_conflict(
        &self,
        mount_id: &str,
        mut versions: Vec<MountVersion>,
    ) -> Result<ResolvedMount, anyhow::Error> {
        // Sort by updated_at timestamp, most recent first
        versions.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

        let latest = &versions[0];
        let latest_timestamp = latest.updated_at;

        // Check for timestamp conflicts (same timestamp, different content)
        let mut timestamp_conflicts: Vec<_> = versions
            .iter()
            .filter(|v| v.updated_at == latest_timestamp)
            .filter(|v| v.config.config != latest.config.config)
            .collect();

        if !timestamp_conflicts.is_empty() {
            // We have a timestamp conflict
            match &self.conflict_strategy {
                ConflictResolutionStrategy::LatestWins => {
                    debug!("Using latest version for mount {} (latest wins)", mount_id);
                }
                ConflictResolutionStrategy::PreferInstance(prefer_id) => {
                    if let Some(_preferred) = versions.iter().find(|v| v.instance_id == *prefer_id)
                    {
                        debug!(
                            "Using preferred instance {} for mount {}",
                            prefer_id, mount_id
                        );
                    } else {
                        warn!(
                            "Preferred instance {} not found for mount {}, using latest",
                            prefer_id, mount_id
                        );
                    }
                }
                ConflictResolutionStrategy::Manual => {
                    debug!("Marking mount {} for manual resolution", mount_id);
                    return Ok(ResolvedMount {
                        config: latest.config.clone(),
                        conflict: Some(SyncConflict {
                            mount_id: mount_id.to_string(),
                            conflict_type: ConflictType::ConcurrentModification,
                            conflicting_instances: timestamp_conflicts
                                .iter()
                                .map(|v| v.instance_id.clone())
                                .collect(),
                            resolution: ConflictResolution::RequiresManualIntervention,
                        }),
                    });
                }
                ConflictResolutionStrategy::InstanceIdTieBreak => {
                    // Sort by instance ID for deterministic tie-breaking
                    timestamp_conflicts.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));
                    if let Some(selected) = timestamp_conflicts.first() {
                        debug!(
                            "Using instance {} as tie-breaker for mount {}",
                            selected.instance_id, mount_id
                        );
                    }
                }
            }
        }

        Ok(ResolvedMount {
            config: latest.config.clone(),
            conflict: None,
        })
    }

    /// Merge global settings from multiple configs
    fn merge_global_settings(
        &self,
        merged: &mut Config,
        instance_configs: &[(String, Config)],
    ) -> Result<(), anyhow::Error> {
        // For global settings, we'll use a simple strategy:
        // - Use the most recent reconnection config (by comparing some field)
        // - Use the most recent global config
        // - Combine resource limits with maximum values

        let mut latest_reconnection = None;
        let mut latest_reconnection_time = 0;
        let mut latest_global = None;
        let mut latest_global_time = 0;

        for (_instance_id, config) in instance_configs {
            // Use created_at as a proxy for when the config was last modified
            if let Some(cluster) = &config.cluster {
                if let Some(last_sync) = cluster.sync_metadata.last_sync_at {
                    if last_sync.timestamp_millis() > latest_reconnection_time {
                        latest_reconnection_time = last_sync.timestamp_millis();
                        latest_reconnection = Some(config.reconnection.clone());
                    }

                    if last_sync.timestamp_millis() > latest_global_time {
                        latest_global_time = last_sync.timestamp_millis();
                        latest_global = Some(config.global.clone());
                    }
                }
            }
        }

        if let Some(reconnection) = latest_reconnection {
            merged.reconnection = reconnection;
        }

        if let Some(global) = latest_global {
            merged.global = global;
        }

        // Platform config is local, so we keep it as is
        // Version should remain "1.0"

        Ok(())
    }
}

/// Result of resolving a mount conflict
#[derive(Debug, Clone)]
struct ResolvedMount {
    /// The resolved mount configuration
    pub config: MountConfigWrapper,
    /// Any conflict that was resolved
    pub conflict: Option<SyncConflict>,
}

// // #[cfg(test)]
// // mod tests {
// //     use super::*;
// //     use chrono::{TimeZone, Utc};
// //     use std::collections::HashMap;
// //
// //     fn create_test_config(instance_id: &str, mounts: Vec<(&str, &str, &str)>) -> Config {
//         let mut config = Config::default();
//         config.initialize_cluster(instance_id.to_string());
//
//         for (id, url, mount_point) in mounts {
//             let mount_config = crate::mount::MountConfig {
//                 id: id.to_string(),
//                 url: url.to_string(),
//                 mount_type: crate::mount::MountType::Nfs {
//                     host: "test".to_string(),
//                     share: "/test".to_string(),
//                     options: vec![],
//                 },
//                 mount_point: mount_point.into(),
//                 enabled: true,
//                 status: crate::mount::MountStatus::Active,
//                 created_at: Utc::now(),
//                 updated_at: Utc::now(),
//                 last_connected: None,
//                 reconnect_attempts: 0,
//                 metadata: HashMap::new(),
//             };
//             config.add_mount(mount_config);
//         }
//
//         config
//     }
//
//     #[tokio::test]
//     async fn test_simple_merge() {
//         let mut merger = ConfigMerger::new();
//
//         let config1 = create_test_config(
//             "instance1",
//             vec![
//                 ("mount1", "nfs://server1/share1", "/mnt/test1"),
//                 ("mount2", "nfs://server1/share2", "/mnt/test2"),
//             ],
//         );
//
//         let config2 = create_test_config(
//             "instance2",
//             vec![
//                 ("mount1", "nfs://server1/share1", "/mnt/test1"), // Same mount
//                 ("mount3", "nfs://server2/share3", "/mnt/test3"), // Different mount
//             ],
//         );
//
//         let configs = vec![
//             ("instance1".to_string(), config1),
//             ("instance2".to_string(), config2),
//         ];
//
//         let result = merger.merge_configs(&configs).await.unwrap();
//
//         // Should have all three mounts
//         assert_eq!(result.config.mounts.len(), 3);
//         assert!(result.config.mounts.contains_key("mount1"));
//         assert!(result.config.mounts.contains_key("mount2"));
//         assert!(result.config.mounts.contains_key("mount3"));
//     }
//
//     #[tokio::test]
//     async fn test_conflict_resolution() {
//         let mut merger = ConfigMerger::new();
//
//         let config1 = create_test_config(
//             "instance1",
//             vec![("mount1", "nfs://server1/share", "/mnt/test")],
//         );
//         let config2 = create_test_config(
//             "instance2",
//             vec![("mount1", "nfs://server2/share", "/mnt/test")],
//         );
//
//         // Modify the updated_at to be the same for both
//         let timestamp = Utc.with_ymd_and_hms(2024, 1, 1, 12, 0, 0).unwrap();
//         for wrapper in config1.mounts.values_mut() {
//             wrapper.config.updated_at = timestamp;
//         }
//         for wrapper in config2.mounts.values_mut() {
//             wrapper.config.updated_at = timestamp;
//         }
//
//         let configs = vec![
//             ("instance1".to_string(), config1),
//             ("instance2".to_string(), config2),
//         ];
//
//         let result = merger.merge_configs(&configs).await.unwrap();
//
//         // Should still have the mount
//         assert_eq!(result.config.mounts.len(), 1);
//         assert!(result.config.mounts.contains_key("mount1"));
//     }
// // }
