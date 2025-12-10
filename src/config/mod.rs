//! Configuration management for Fuji
//!
//! This module handles loading, saving, and managing configuration using TOML format.
//! Provides atomic writes, validation, and conflict detection.

use crate::mount::{MountConfig, MountStatus};
use crate::platform::Platform;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, info, warn};
use validator::Validate;

/// Global configuration structure
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct Config {
    /// Version of the configuration file format
    #[validate(length(min = 1, max = 10))]
    pub version: String,
    /// Mount configurations indexed by ID
    #[serde(flatten)]
    #[validate(custom(function = "crate::config::validate_mounts"))]
    pub mounts: HashMap<String, MountConfigWrapper>,
    /// Reconnection settings
    pub reconnection: ReconnectionConfig,
    /// Global settings
    pub global: GlobalConfig,
    /// Platform-specific settings
    pub platform: PlatformConfig,
    /// Cluster configuration (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster: Option<ClusterConfig>,
}

/// Wrapper for mount config to handle serialization and sync metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountConfigWrapper {
    /// The actual mount configuration
    #[serde(flatten)]
    pub config: MountConfig,
    /// Sync metadata for this mount
    #[serde(default)]
    pub sync_metadata: Option<MountSyncMetadata>,
}

/// Sync metadata for individual mounts
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MountSyncMetadata {
    /// Which instance last modified this mount
    pub last_modified_by: Option<String>,
    /// Version of this mount configuration
    pub version: u64,
}

impl MountConfigWrapper {
    /// Create a new wrapper from a mount config
    pub fn new(mount: MountConfig, instance_id: Option<&str>) -> Self {
        Self {
            config: mount.clone(),
            sync_metadata: instance_id.map(|id| MountSyncMetadata {
                last_modified_by: Some(id.to_string()),
                version: 1,
            }),
        }
    }

    /// Get a reference to the mount config
    #[allow(dead_code)]
    pub fn mount(&self) -> &MountConfig {
        &self.config
    }

    /// Get a mutable reference to the mount config
    #[allow(dead_code)]
    pub fn mount_mut(&mut self) -> &mut MountConfig {
        &mut self.config
    }

    /// Update the mount and increment version
    pub fn update_mount(&mut self, mount: MountConfig, instance_id: &str) {
        self.config = mount;
        self.config.updated_at = Utc::now();

        let metadata = self
            .sync_metadata
            .get_or_insert_with(MountSyncMetadata::default);
        metadata.last_modified_by = Some(instance_id.to_string());
        metadata.version += 1;
    }
}

/// Reconnection configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ReconnectionConfig {
    /// Maximum number of reconnection attempts
    #[validate(range(min = 1, max = 100))]
    pub max_retries: u32,
    /// Initial delay between reconnection attempts (in milliseconds)
    #[validate(range(min = 100, max = 300_000))]
    pub initial_delay_ms: u64,
    /// Maximum delay between reconnection attempts (in milliseconds)
    #[validate(range(min = 1000, max = 3_600_000))]
    pub max_delay_ms: u64,
    /// Backoff multiplier
    #[validate(range(min = 1.0, max = 10.0))]
    pub backoff_multiplier: f64,
}

/// Global configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct GlobalConfig {
    /// Health check interval (in seconds)
    #[validate(range(min = 5, max = 3600))]
    pub health_check_interval_secs: u64,
    /// Log level
    #[validate(custom(function = "crate::config::validate_log_level"))]
    pub log_level: String,
    /// Whether to automatically mount enabled shares on startup
    pub auto_mount: bool,
    /// Resource limits configuration
    pub resource_limits: ResourceLimitsConfig,
}

/// Platform-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PlatformConfig {
    /// Custom socket path (overrides default)
    pub socket_path: Option<PathBuf>,
    /// Custom configuration directory
    pub config_dir: Option<PathBuf>,
    /// Custom mount directory
    pub mount_dir: Option<PathBuf>,
}

/// Resource limits configuration for the global config
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ResourceLimitsConfig {
    /// Maximum memory usage in MB (0 = no limit)
    #[validate(range(min = 0, max = 16384))] // 16GB max in MB
    pub max_memory_mb: u32,
    /// Maximum CPU usage percentage (0-100, 0 = no limit)
    #[validate(range(min = 0, max = 100))]
    pub max_cpu_percent: u8,
    /// Maximum number of concurrent mount operations
    #[validate(range(min = 1, max = 100))]
    pub max_concurrent_mounts: u32,
    /// Maximum number of file descriptors
    #[validate(range(min = 64, max = 65536))]
    pub max_file_descriptors: u32,
    /// Maximum number of network connections
    #[validate(range(min = 10, max = 10000))]
    pub max_connections: u32,
    /// Enable resource limits enforcement
    pub enable_enforcement: bool,
    /// Violation action when limits exceeded: 'warn', 'throttle', 'reject', 'terminate'
    pub violation_action: String,
    /// Resource monitoring interval in seconds
    #[validate(range(min = 1, max = 3600))]
    pub monitoring_interval_secs: u64,
}

/// Cluster configuration for multi-instance synchronization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Whether clustering is enabled
    pub enabled: bool,
    /// Unique identifier for this instance
    pub instance_id: String,
    /// List of cluster peers
    pub peers: Vec<PeerInfo>,
    /// TCP port for cluster communication
    #[serde(default = "default_cluster_port")]
    pub port: u16,
    /// Sync interval (how often to check if we should initiate)
    #[serde(with = "duration_serde")]
    pub sync_interval: Duration,
    /// How long to wait after being asked before we can initiate
    #[serde(with = "duration_serde")]
    pub sync_timeout: Duration,
    /// Metadata for synchronization
    pub sync_metadata: SyncMetadata,
}

/// Information about a cluster peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Unique identifier of the peer
    pub id: String,
    /// Network address of the peer
    pub address: String,
    /// Pre-shared key for authentication
    pub psk: String,
    /// Last time we heard from this peer
    pub last_seen: DateTime<Utc>,
    /// Peer status
    pub status: PeerStatus,
}

/// Peer connection status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PeerStatus {
    /// Peer is connected and healthy
    Connected,
    /// Peer is temporarily unreachable
    Disconnected,
    /// Peer has not been seen for a long time
    Suspended,
    /// Peer is being removed from cluster
    Leaving,
}

/// Synchronization metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncMetadata {
    /// Last successful sync time
    pub last_sync_at: Option<DateTime<Utc>>,
    /// Which instance last modified the config
    pub last_modified_by: Option<String>,
    /// Monotonically increasing version number
    pub sync_version: u64,
    /// Pending conflicts to resolve
    pub pending_conflicts: Vec<SyncConflict>,
    /// Force sync state tracking
    #[serde(default)]
    pub force_sync_state: ForceSyncState,
}

impl Default for SyncMetadata {
    fn default() -> Self {
        Self {
            last_sync_at: None,
            last_modified_by: None,
            sync_version: 0,
            pending_conflicts: Vec::new(),
            force_sync_state: ForceSyncState::default(),
        }
    }
}

/// Configuration sync conflict information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConflict {
    /// ID of the mount with conflict
    pub mount_id: String,
    /// Type of conflict
    pub conflict_type: ConflictType,
    /// Instances involved in the conflict
    pub conflicting_instances: Vec<String>,
    /// How the conflict was resolved
    pub resolution: ConflictResolution,
}

/// Types of configuration conflicts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictType {
    /// Same mount modified concurrently
    ConcurrentModification,
    /// Mount deleted on one instance, modified on another
    DeleteModifyConflict,
    /// Same mount point used by different mounts
    MountPointConflict,
}

/// How a conflict was resolved
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictResolution {
    /// Used the most recent version
    UsedLatest,
    /// Used the version from the specified instance
    UsedInstance(String),
    /// Manual resolution required
    RequiresManualIntervention,
}

/// Force sync state tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForceSyncState {
    /// Last time a force sync was initiated
    pub last_force_sync_at: Option<DateTime<Utc>>,
    /// Whether a force sync is currently in progress
    pub sync_in_progress: bool,
    /// Reason for the last force sync
    pub last_force_sync_reason: Option<String>,
    /// Instance that initiated the last force sync
    pub initiated_by: Option<String>,
    /// Force sync attempts count
    pub attempt_count: u32,
    /// Last force sync result
    pub last_result: Option<ForceSyncResult>,
}

/// Result of a force sync operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForceSyncResult {
    /// Sync completed successfully
    Success {
        completed_at: DateTime<Utc>,
        peers_synced: usize,
        conflicts_resolved: usize,
    },
    /// Sync failed
    Failed {
        failed_at: DateTime<Utc>,
        error: String,
        peers_attempted: usize,
    },
    /// Sync is in progress
    InProgress {
        started_at: DateTime<Utc>,
        peers_attempted: usize,
        peers_completed: usize,
    },
}

impl Default for ForceSyncState {
    fn default() -> Self {
        Self {
            last_force_sync_at: None,
            sync_in_progress: false,
            last_force_sync_reason: None,
            initiated_by: None,
            attempt_count: 0,
            last_result: None,
        }
    }
}

/// Serialization helper for Duration
mod duration_serde {
    use chrono::Duration;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(duration.num_seconds())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let seconds = i64::deserialize(deserializer)?;
        Ok(Duration::seconds(seconds))
    }
}

impl Default for ResourceLimitsConfig {
    fn default() -> Self {
        Self {
            max_memory_mb: 1024, // 1GB
            max_cpu_percent: 80,
            max_concurrent_mounts: 10,
            max_file_descriptors: 1024,
            max_connections: 100,
            enable_enforcement: true,
            violation_action: "throttle".to_string(),
            monitoring_interval_secs: 30,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: "1.0".to_string(),
            mounts: HashMap::new(),
            reconnection: ReconnectionConfig::default(),
            global: GlobalConfig::default(),
            platform: PlatformConfig::default(),
            cluster: None, // Disabled by default
        }
    }
}

impl Default for ReconnectionConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            initial_delay_ms: 1000,
            max_delay_ms: 60000,
            backoff_multiplier: 2.0,
        }
    }
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            health_check_interval_secs: 30,
            log_level: "info".to_string(),
            auto_mount: true,
            resource_limits: ResourceLimitsConfig::default(),
        }
    }
}

/// Default cluster port
fn default_cluster_port() -> u16 {
    10080
}

#[allow(dead_code)]
impl Config {
    /// Load configuration from various possible locations
    pub async fn load(platform: &dyn Platform) -> Result<Self> {
        let config_paths = Self::get_config_paths(platform);

        for path in config_paths {
            debug!("Trying to load config from: {:?}", path);

            if !platform.path_exists(&path) {
                continue;
            }

            match fs::read_to_string(&path).await {
                Ok(content) => {
                    match toml::from_str::<Config>(&content) {
                        Ok(mut config) => {
                            info!("Loaded configuration from {:?}", path);
                            // Migrate old configurations if needed
                            Self::migrate(&mut config)?;
                            return Ok(config);
                        }
                        Err(e) => {
                            warn!("Failed to parse config from {:?}: {}", path, e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read config from {:?}: {}", path, e);
                }
            }
        }

        warn!("No configuration file found, using defaults");
        Ok(Config::default())
    }

    /// Save configuration to the preferred location
    pub async fn save(&self, platform: &dyn Platform) -> Result<()> {
        let config_path = Self::get_preferred_config_path(platform);

        // Ensure config directory exists
        if let Some(parent) = config_path.parent() {
            platform.ensure_dir_exists(parent)?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|e| anyhow!("Failed to serialize configuration: {}", e))?;

        fs::write(&config_path, content)
            .await
            .map_err(|e| anyhow!("Failed to write configuration to {:?}: {}", config_path, e))?;

        info!("Saved configuration to {:?}", config_path);
        Ok(())
    }

    /// Load configuration from a specific directory
    pub async fn load_with_dir(config_dir: &Path) -> Result<Self> {
        let config_path = config_dir.join("mounts.toml");

        if !config_path.exists() {
            info!("No existing configuration found, using defaults");
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&config_path)
            .await
            .map_err(|e| anyhow!("Failed to read config from {:?}: {}", config_path, e))?;

        let mut config = toml::from_str::<Config>(&content)
            .map_err(|e| anyhow!("Failed to parse config from {:?}: {}", config_path, e))?;

        // Migrate old configurations if needed
        Self::migrate(&mut config)?;
        Ok(config)
    }

    /// Save configuration to a specific directory
    pub async fn save_to_dir(&self, config_dir: &Path) -> Result<()> {
        let config_path = config_dir.join("mounts.toml");

        // Ensure config directory exists
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow!("Failed to create config directory: {}", e))?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|e| anyhow!("Failed to serialize configuration: {}", e))?;

        fs::write(&config_path, content)
            .await
            .map_err(|e| anyhow!("Failed to write configuration to {:?}: {}", config_path, e))?;

        info!("Saved configuration to {:?}", config_path);
        Ok(())
    }

    /// Get all possible configuration paths in order of preference
    fn get_config_paths(platform: &dyn Platform) -> Vec<PathBuf> {
        let config_dir = platform.get_config_dir();
        vec![config_dir.join("mounts.toml")]
    }

    /// Get the preferred configuration path
    fn get_preferred_config_path(platform: &dyn Platform) -> PathBuf {
        platform.get_config_dir().join("mounts.toml")
    }

    /// Migrate old configuration formats
    fn migrate(config: &mut Config) -> Result<()> {
        // Add migrations here as needed
        if config.version != "1.0" {
            warn!("Migrating configuration from version {}", config.version);
            config.version = "1.0".to_string();
        }

        Ok(())
    }

    /// Add or update a mount configuration
    pub fn add_mount(&mut self, mount: MountConfig) {
        let instance_id = self.get_instance_id();
        let wrapper = MountConfigWrapper::new(mount.clone(), instance_id);
        self.mounts.insert(mount.id.clone(), wrapper);
    }

    /// Remove a mount configuration
    pub fn remove_mount(&mut self, id: &str) -> Option<MountConfig> {
        self.mounts.remove(id).map(|w| w.config)
    }

    /// Get a mount configuration by ID
    pub fn get_mount(&self, id: &str) -> Option<&MountConfig> {
        self.mounts.get(id).map(|w| &w.config)
    }

    /// Get a mutable mount configuration by ID
    pub fn get_mount_mut(&mut self, id: &str) -> Option<&mut MountConfig> {
        self.mounts.get_mut(id).map(|w| &mut w.config)
    }

    /// Get all mount configurations
    pub fn get_all_mounts(&self) -> impl Iterator<Item = &MountConfig> {
        self.mounts.values().map(|w| &w.config)
    }

    /// Get all enabled mount configurations
    pub fn get_enabled_mounts(&self) -> impl Iterator<Item = &MountConfig> {
        self.mounts.values().filter_map(|w| {
            if w.config.enabled {
                Some(&w.config)
            } else {
                None
            }
        })
    }

    /// Get all active mount configurations
    pub fn get_active_mounts(&self) -> impl Iterator<Item = &MountConfig> {
        self.mounts.values().filter_map(|w| {
            if w.config.status == MountStatus::Active {
                Some(&w.config)
            } else {
                None
            }
        })
    }

    /// Get mounts that need to be attempted for reconnection
    pub fn get_failed_mounts(&self) -> impl Iterator<Item = &MountConfig> {
        self.mounts.values().filter_map(|w| {
            if w.config.status == MountStatus::Failed && w.config.enabled {
                Some(&w.config)
            } else {
                None
            }
        })
    }

    /// Update a mount configuration with sync tracking
    pub fn update_mount(&mut self, id: &str, mount: MountConfig) {
        let instance_id = self.get_instance_id().unwrap_or("unknown").to_string();
        if let Some(wrapper) = self.mounts.get_mut(id) {
            wrapper.update_mount(mount, &instance_id);
        }
    }

    /// Calculate next reconnection delay based on attempts
    pub fn get_reconnection_delay(&self, attempts: u32) -> Duration {
        let base_delay = Duration::milliseconds(self.reconnection.initial_delay_ms as i64);
        let max_delay = Duration::milliseconds(self.reconnection.max_delay_ms as i64);

        if attempts == 0 {
            return base_delay;
        }

        let multiplier = self.reconnection.backoff_multiplier.powi(attempts as i32);
        let delay_ms = (self.reconnection.initial_delay_ms as f64 * multiplier) as i64;
        let delay = Duration::milliseconds(delay_ms);
        std::cmp::min(delay, max_delay)
    }

    /// Get socket path based on configuration and platform defaults
    pub fn get_socket_path(&self, platform: &dyn Platform) -> Result<PathBuf> {
        // Pass the custom path from config to platform (or None if not set)
        let config_path = self.platform.socket_path.as_deref();
        Ok(platform.get_socket_path(config_path))
    }

    /// Get mount directory based on configuration and platform defaults
    pub fn get_mount_dir(&self, platform: &dyn Platform) -> PathBuf {
        self.platform
            .mount_dir
            .clone()
            .unwrap_or_else(|| platform.get_mount_dir())
    }

    /// Save configuration atomically to prevent corruption
    pub async fn save_atomic(&self, platform: &dyn Platform) -> Result<()> {
        let config_path = Self::get_preferred_config_path(platform);

        // Ensure config directory exists
        if let Some(parent) = config_path.parent() {
            platform.ensure_dir_exists(parent)?;
        }

        // Validate configuration before saving
        self.validate_config()
            .map_err(|e| anyhow!("Configuration validation failed: {}", e))?;

        // Write to temporary file first
        let temp_path = config_path.with_extension("tmp");
        let content = toml::to_string_pretty(self)
            .map_err(|e| anyhow!("Failed to serialize configuration: {}", e))?;

        fs::write(&temp_path, content)
            .await
            .map_err(|e| anyhow!("Failed to write temporary configuration: {}", e))?;

        // Atomic rename
        fs::rename(&temp_path, &config_path)
            .await
            .map_err(|e| anyhow!("Failed to rename temporary configuration: {}", e))?;

        info!("Configuration saved atomically to {:?}", config_path);
        Ok(())
    }

    /// Validate the entire configuration
    pub fn validate_config(&self) -> Result<(), validator::ValidationErrors> {
        use validator::Validate;
        self.validate()
    }

    /// Check for mount conflicts with system
    pub async fn detect_mount_conflicts(&self, platform: &dyn Platform) -> Result<Vec<String>> {
        let mut conflicts = Vec::new();

        for mount_config in self.get_all_mounts() {
            if platform.path_exists(&mount_config.mount_point) {
                // Check if there's already something mounted at this point
                if let Ok(Some(existing_mount)) = platform.get_mount_info(&mount_config.mount_point)
                {
                    conflicts.push(format!(
                        "Mount point {} already has {} mounted",
                        mount_config.mount_point.display(),
                        existing_mount.device
                    ));
                }
            }
        }

        Ok(conflicts)
    }

    /// Sync configuration with actual system state
    pub async fn sync_with_system(&mut self, platform: &dyn Platform) -> Result<()> {
        info!("Syncing configuration with system state...");

        // Get all active mounts from the system
        let system_mounts = platform.list_system_mounts()?;

        // Update mount status based on system state
        for (_, wrapper) in self.mounts.iter_mut() {
            let is_mounted = system_mounts
                .iter()
                .any(|(point, _)| point == &wrapper.config.mount_point);

            if is_mounted && wrapper.config.enabled {
                wrapper.config.update_status(MountStatus::Active);
            } else if !is_mounted && wrapper.config.status == MountStatus::Active {
                wrapper.config.update_status(MountStatus::Failed);
            }
        }

        info!("Configuration sync complete");
        Ok(())
    }

    /// Check if clustering is enabled
    pub fn is_cluster_enabled(&self) -> bool {
        self.cluster.as_ref().map(|c| c.enabled).unwrap_or(false)
    }

    /// Get instance ID if clustering is enabled
    pub fn get_instance_id(&self) -> Option<&str> {
        self.cluster.as_ref().map(|c| c.instance_id.as_str())
    }

    /// Initialize cluster configuration with generated instance ID
    pub fn initialize_cluster(&mut self, instance_id: String) {
        self.cluster = Some(ClusterConfig {
            enabled: true,
            instance_id: instance_id.clone(),
            peers: Vec::new(),
            port: 10080,                         // Default cluster port
            sync_interval: Duration::minutes(5), // Default 5 minutes
            sync_timeout: Duration::minutes(10), // Default 10 minutes
            sync_metadata: SyncMetadata {
                last_sync_at: None,
                last_modified_by: Some(instance_id),
                sync_version: 0,
                pending_conflicts: Vec::new(),
                force_sync_state: ForceSyncState::default(),
            },
        });
    }

    /// Update sync metadata when configuration is modified
    pub fn mark_modified(&mut self, instance_id: &str) {
        if let Some(cluster) = &mut self.cluster {
            cluster.sync_metadata.last_modified_by = Some(instance_id.to_string());
            cluster.sync_metadata.sync_version += 1;
        }

        // Update mount timestamps
        for wrapper in self.mounts.values_mut() {
            wrapper.config.updated_at = Utc::now();
        }
    }

    /// Add a peer to the cluster configuration
    pub fn add_cluster_peer(&mut self, peer: PeerInfo) {
        if let Some(cluster) = &mut self.cluster {
            // Check if peer already exists
            if !cluster.peers.iter().any(|p| p.id == peer.id) {
                cluster.peers.push(peer);
            }
        }
    }

    /// Remove a peer from the cluster configuration
    pub fn remove_cluster_peer(&mut self, peer_id: &str) -> bool {
        if let Some(cluster) = &mut self.cluster {
            if let Some(pos) = cluster.peers.iter().position(|p| p.id == peer_id) {
                cluster.peers.remove(pos);
                return true;
            }
        }
        false
    }

    /// Get cluster configuration
    pub fn get_cluster_config(&self) -> Option<&ClusterConfig> {
        self.cluster.as_ref()
    }

    /// Get mutable cluster configuration
    pub fn get_cluster_config_mut(&mut self) -> Option<&mut ClusterConfig> {
        self.cluster.as_mut()
    }

    /// Initiate a force sync operation
    pub fn initiate_force_sync(&mut self, reason: String, initiated_by: String) -> Result<()> {
        if let Some(cluster) = self.get_cluster_config_mut() {
            let force_sync = &mut cluster.sync_metadata.force_sync_state;

            // Update force sync state
            force_sync.last_force_sync_at = Some(Utc::now());
            force_sync.sync_in_progress = true;
            force_sync.last_force_sync_reason = Some(reason);
            force_sync.initiated_by = Some(initiated_by);
            force_sync.attempt_count += 1;

            // Set current result to in-progress
            force_sync.last_result = Some(ForceSyncResult::InProgress {
                started_at: Utc::now(),
                peers_attempted: cluster.peers.len(),
                peers_completed: 0,
            });

            info!(
                "Force sync initiated by {} (attempt #{})",
                force_sync.initiated_by.as_ref().unwrap(),
                force_sync.attempt_count
            );

            Ok(())
        } else {
            Err(anyhow!("Clustering is not enabled"))
        }
    }

    /// Mark force sync as completed
    pub fn complete_force_sync(
        &mut self,
        peers_synced: usize,
        conflicts_resolved: usize,
    ) -> Result<()> {
        if let Some(cluster) = self.get_cluster_config_mut() {
            let force_sync = &mut cluster.sync_metadata.force_sync_state;

            if !force_sync.sync_in_progress {
                return Err(anyhow!("No force sync in progress"));
            }

            force_sync.sync_in_progress = false;
            force_sync.last_result = Some(ForceSyncResult::Success {
                completed_at: Utc::now(),
                peers_synced,
                conflicts_resolved,
            });

            info!(
                "Force sync completed successfully: {} peers synced, {} conflicts resolved",
                peers_synced, conflicts_resolved
            );

            Ok(())
        } else {
            Err(anyhow!("Clustering is not enabled"))
        }
    }

    /// Mark force sync as failed
    pub fn fail_force_sync(&mut self, error: String, peers_attempted: usize) -> Result<()> {
        if let Some(cluster) = self.get_cluster_config_mut() {
            let force_sync = &mut cluster.sync_metadata.force_sync_state;

            if !force_sync.sync_in_progress {
                return Err(anyhow!("No force sync in progress"));
            }

            force_sync.sync_in_progress = false;
            force_sync.last_result = Some(ForceSyncResult::Failed {
                failed_at: Utc::now(),
                error,
                peers_attempted,
            });

            warn!("Force sync failed");

            Ok(())
        } else {
            Err(anyhow!("Clustering is not enabled"))
        }
    }

    /// Get current force sync state
    pub fn get_force_sync_state(&self) -> Option<&ForceSyncState> {
        self.cluster
            .as_ref()
            .map(|c| &c.sync_metadata.force_sync_state)
    }
}

// Validation functions
fn validate_mounts(
    mounts: &HashMap<String, MountConfigWrapper>,
) -> Result<(), validator::ValidationError> {
    // Check for duplicate mount points
    let mut mount_points = std::collections::HashSet::new();
    for wrapper in mounts.values() {
        if !mount_points.insert(&wrapper.config.mount_point) {
            return Err(validator::ValidationError::new("duplicate_mount_point"));
        }
    }

    // Check each mount configuration
    for (id, wrapper) in mounts {
        if id != &wrapper.config.id {
            return Err(validator::ValidationError::new("id_mismatch"));
        }

        // Validate URL format
        if wrapper.config.url.is_empty() {
            return Err(validator::ValidationError::new("empty_url"));
        }

        // Check mount point is absolute
        if !wrapper.config.mount_point.is_absolute() {
            return Err(validator::ValidationError::new("relative_mount_point"));
        }
    }

    Ok(())
}

fn validate_log_level(log_level: &str) -> Result<(), validator::ValidationError> {
    let valid_levels = ["trace", "debug", "info", "warn", "error"];
    if !valid_levels.contains(&log_level) {
        return Err(validator::ValidationError::new("invalid_log_level"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_config_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test.toml");

        let mut config = Config::default();
        config.global.log_level = "debug".to_string();

        // Write config
        let content = toml::to_string_pretty(&config).unwrap();
        fs::write(&config_path, content).await.unwrap();

        // Read config
        let loaded_content = fs::read_to_string(&config_path).await.unwrap();
        let loaded_config: Config = toml::from_str(&loaded_content).unwrap();

        assert_eq!(loaded_config.global.log_level, "debug");
    }
}
