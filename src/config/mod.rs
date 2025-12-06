//! Configuration management for Fuji
//!
//! This module handles loading, saving, and managing configuration using TOML format.
//! Provides atomic writes, validation, and conflict detection.

use crate::mount::{MountConfig, MountStatus};
use crate::platform::Platform;
use anyhow::{Result, anyhow};
use chrono::Duration;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
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
    #[validate(custom = "validate_mounts")]
    pub mounts: HashMap<String, MountConfigWrapper>,
    /// Reconnection settings
    pub reconnection: ReconnectionConfig,
    /// Global settings
    pub global: GlobalConfig,
    /// Platform-specific settings
    pub platform: PlatformConfig,
}

/// Wrapper for mount config to handle serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountConfigWrapper {
    /// The actual mount configuration
    #[serde(flatten)]
    pub mount: MountConfig,
}

/// Reconnection configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ReconnectionConfig {
    /// Maximum number of reconnection attempts
    #[validate(range(min = 1, max = 100))]
    pub max_retries: u32,
    /// Initial delay between reconnection attempts (in milliseconds)
    #[validate(range(min = 100, max = 300000))]
    pub initial_delay_ms: u64,
    /// Maximum delay between reconnection attempts (in milliseconds)
    #[validate(range(min = 1000, max = 3600000))]
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
    #[validate(custom = "validate_log_level")]
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
    /// Maximum memory usage in bytes (0 = no limit)
    #[validate(range(min = 0, max = 17179869184))] // 16GB max
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
        let wrapper = MountConfigWrapper {
            mount: mount.clone(),
        };
        self.mounts.insert(mount.id.clone(), wrapper);
    }

    /// Remove a mount configuration
    pub fn remove_mount(&mut self, id: &str) -> Option<MountConfig> {
        self.mounts.remove(id).map(|w| w.mount)
    }

    /// Get a mount configuration by ID
    pub fn get_mount(&self, id: &str) -> Option<&MountConfig> {
        self.mounts.get(id).map(|w| &w.mount)
    }

    /// Get a mutable mount configuration by ID
    pub fn get_mount_mut(&mut self, id: &str) -> Option<&mut MountConfig> {
        self.mounts.get_mut(id).map(|w| &mut w.mount)
    }

    /// Get all mount configurations
    pub fn get_all_mounts(&self) -> impl Iterator<Item = &MountConfig> {
        self.mounts.values().map(|w| &w.mount)
    }

    /// Get all enabled mount configurations
    pub fn get_enabled_mounts(&self) -> impl Iterator<Item = &MountConfig> {
        self.mounts.values().filter_map(|w| {
            if w.mount.enabled {
                Some(&w.mount)
            } else {
                None
            }
        })
    }

    /// Get all active mount configurations
    pub fn get_active_mounts(&self) -> impl Iterator<Item = &MountConfig> {
        self.mounts.values().filter_map(|w| {
            if w.mount.status == MountStatus::Active {
                Some(&w.mount)
            } else {
                None
            }
        })
    }

    /// Get mounts that need to be attempted for reconnection
    pub fn get_failed_mounts(&self) -> impl Iterator<Item = &MountConfig> {
        self.mounts.values().filter_map(|w| {
            if w.mount.status == MountStatus::Failed && w.mount.enabled {
                Some(&w.mount)
            } else {
                None
            }
        })
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
                .any(|(point, _)| point == &wrapper.mount.mount_point);

            if is_mounted && wrapper.mount.enabled {
                wrapper.mount.update_status(MountStatus::Active);
            } else if !is_mounted && wrapper.mount.status == MountStatus::Active {
                wrapper.mount.update_status(MountStatus::Failed);
            }
        }

        info!("Configuration sync complete");
        Ok(())
    }
}

// Validation functions
fn validate_mounts(
    mounts: &HashMap<String, MountConfigWrapper>,
) -> Result<(), validator::ValidationError> {
    // Check for duplicate mount points
    let mut mount_points = std::collections::HashSet::new();
    for wrapper in mounts.values() {
        if !mount_points.insert(&wrapper.mount.mount_point) {
            return Err(validator::ValidationError::new("duplicate_mount_point"));
        }
    }

    // Check each mount configuration
    for (id, wrapper) in mounts {
        if id != &wrapper.mount.id {
            return Err(validator::ValidationError::new("id_mismatch"));
        }

        // Validate URL format
        if wrapper.mount.url.is_empty() {
            return Err(validator::ValidationError::new("empty_url"));
        }

        // Check mount point is absolute
        if !wrapper.mount.mount_point.is_absolute() {
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
