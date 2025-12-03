use crate::error::{FujiError, Result};
use crate::platform::{get_platform, Platform};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountConfig {
    pub id: String,
    pub url: String,
    pub mount_point: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub mounts: HashMap<String, MountConfig>,
    pub reconnection: ReconnectionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconnectionConfig {
    pub max_retries: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_multiplier: f64,
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

#[derive(Debug, Clone)]
pub struct Config {
    socket_path: PathBuf,
    config_path: PathBuf,
    mounts_path: PathBuf,
    app_config: AppConfig,
}

impl Config {
    pub fn load() -> Result<Self> {
        tracing::info!("Loading Fuji configuration...");

        let config_path = Self::get_config_path()?;
        let socket_path = Self::get_socket_path()?;
        let mounts_path = Self::get_mounts_path()?;

        tracing::info!("Configuration paths resolved:");
        tracing::info!("  - Socket: {}", socket_path.display());
        tracing::info!("  - Config: {}", config_path.display());
        tracing::info!("  - Mounts: {}", mounts_path.display());

        // Load app config or create default
        let app_config = if mounts_path.exists() {
            tracing::info!("Loading existing mounts configuration from: {}", mounts_path.display());
            let content = std::fs::read_to_string(&mounts_path)
                .map_err(|e| FujiError::Config(format!("Failed to read mounts config: {}", e)))?;

            // If file is empty or contains invalid TOML, create default config
            if content.trim().is_empty() {
                tracing::warn!("Mounts config file is empty, creating default configuration");
                AppConfig {
                    mounts: HashMap::new(),
                    reconnection: ReconnectionConfig::default(),
                }
            } else {
                tracing::debug!("Parsing TOML configuration from file");
                match toml::from_str::<AppConfig>(&content) {
                    Ok(config) => {
                        tracing::info!("Successfully loaded configuration with {} mounts", config.mounts.len());
                        config
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse configuration TOML: {}. Creating default config.", e);
                        AppConfig {
                            mounts: HashMap::new(),
                            reconnection: ReconnectionConfig::default(),
                        }
                    }
                }
            }
        } else {
            tracing::info!("No mounts configuration found, creating default configuration");
            AppConfig {
                mounts: HashMap::new(),
                reconnection: ReconnectionConfig::default(),
            }
        };

        let config = Config {
            socket_path,
            config_path,
            mounts_path,
            app_config,
        };

        tracing::info!("Configuration loaded successfully");
        Ok(config)
    }

    pub fn load_from_path(config_path: PathBuf) -> Result<Self> {
        let socket_path = Self::get_socket_path()?;
        let mounts_path = Self::get_mounts_path()?;

        // Load app config or create default
        let app_config = if mounts_path.exists() {
            let content = std::fs::read_to_string(&mounts_path)
                .map_err(|e| FujiError::Config(format!("Failed to read mounts config: {}", e)))?;

            // If file is empty or contains invalid TOML, create default config
            if content.trim().is_empty() {
                AppConfig {
                    mounts: HashMap::new(),
                    reconnection: ReconnectionConfig::default(),
                }
            } else {
                toml::from_str(&content).unwrap_or_else(|_| AppConfig {
                    mounts: HashMap::new(),
                    reconnection: ReconnectionConfig::default(),
                })
            }
        } else {
            AppConfig {
                mounts: HashMap::new(),
                reconnection: ReconnectionConfig::default(),
            }
        };

        Ok(Config {
            socket_path,
            config_path,
            mounts_path,
            app_config,
        })
    }

    /// Helper function to expand $HOME in path strings
    fn expand_home_dir(path: &str) -> PathBuf {
        if path.starts_with("$HOME/") {
            if let Ok(home) = std::env::var("HOME") {
                return PathBuf::from(path.replace("$HOME", &home));
            }
        }
        PathBuf::from(path)
    }

    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }

    pub fn config_path(&self) -> &PathBuf {
        &self.config_path
    }

    pub fn mounts_path(&self) -> &PathBuf {
        &self.mounts_path
    }

    pub fn app_config(&self) -> &AppConfig {
        &self.app_config
    }

    pub fn app_config_mut(&mut self) -> &mut AppConfig {
        &mut self.app_config
    }

    pub fn save(&self) -> Result<()> {
        let content = toml::to_string_pretty(&self.app_config)
            .map_err(|e| FujiError::Config(format!("Failed to serialize config: {}", e)))?;

        // Ensure parent directory exists
        if let Some(parent) = self.mounts_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    FujiError::Config(format!("Failed to create config directory: {}", e))
                })?;
            }
        }

        std::fs::write(&self.mounts_path, content)
            .map_err(|e| FujiError::Config(format!("Failed to write config file: {}", e)))?;

        Ok(())
    }

    pub fn add_mount(&mut self, mount: MountConfig) -> Result<()> {
        self.app_config.mounts.insert(mount.id.clone(), mount);
        self.save()
    }

    pub fn remove_mount(&mut self, mount_id: &str) -> Result<()> {
        self.app_config.mounts.remove(mount_id);
        self.save()
    }

    pub fn get_mount(&self, mount_id: &str) -> Option<&MountConfig> {
        self.app_config.mounts.get(mount_id)
    }

    pub fn get_mounts(&self) -> &HashMap<String, MountConfig> {
        &self.app_config.mounts
    }

    pub fn get_enabled_mounts(&self) -> Vec<&MountConfig> {
        self.app_config
            .mounts
            .values()
            .filter(|m| m.enabled)
            .collect()
    }

    fn get_config_path() -> Result<PathBuf> {
        tracing::debug!("Resolving configuration path...");
        let platform = get_platform()?;
        let config_dir = platform.default_config_dir();

        // Try different paths in order of preference
        let paths = vec![
            std::env::var("HOME").ok().map(|h| {
                PathBuf::from(h)
                    .join(".config")
                    .join("fuji")
                    .join("config.toml")
            }),
            Some(Self::expand_home_dir(config_dir).join("config.toml")),
            Some(PathBuf::from("/tmp/fuji/config.toml")),
        ];

        for (index, path) in paths.iter().enumerate() {
            if let Some(path) = path {
                tracing::debug!("Trying config path {}: {:?}", index + 1, path.display());
                if let Some(parent) = path.parent() {
                    if !parent.exists() {
                        tracing::debug!("Creating parent directory: {:?}", parent.display());
                        if let Err(e) = std::fs::create_dir_all(parent) {
                            tracing::warn!("Failed to create directory {:?}: {}", parent, e);
                            continue;
                        }
                    }
                }

                // Check if we can write to the path or create it
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(&path)
                {
                    Ok(_) => {
                        tracing::info!("✓ Using config path: {:?}", path.display());
                        return Ok(path.to_path_buf());
                    }
                    Err(e) => {
                        tracing::warn!("✗ Cannot use config path {:?}: {}", path.display(), e);
                    }
                }
            }
        }

        Err(FujiError::Config(
            "Cannot find writable configuration path".to_string(),
        ))
    }

    fn get_socket_path() -> Result<PathBuf> {
        let platform = get_platform()?;
        let default_socket = platform.default_socket_path();

        // Try different socket paths in order of preference
        let paths = vec![
            // Prefer user's home directory to avoid macOS /tmp cleanup
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join("fuji_tmp").join("fuji.sock")),
            Some(PathBuf::from(default_socket)),
            Some(PathBuf::from("/tmp/fuji.sock")),
            std::env::var("XDG_RUNTIME_DIR")
                .ok()
                .map(|r| PathBuf::from(r).join("fuji.sock")),
        ];

        for path in paths {
            if let Some(path) = path {
                if let Some(parent) = path.parent() {
                    if !parent.exists() {
                        if let Err(e) = std::fs::create_dir_all(parent) {
                            tracing::warn!("Failed to create directory {:?}: {}", parent, e);
                            continue;
                        }
                    }
                }

                // Check if we can create the socket
                if path.exists() {
                    if let Err(e) = std::fs::remove_file(&path) {
                        tracing::warn!("Cannot remove existing socket {:?}: {}", path, e);
                        continue;
                    }
                }

                tracing::info!("Using socket path: {:?}", path);
                return Ok(path);
            }
        }

        Err(FujiError::Config(
            "Cannot find writable socket path".to_string(),
        ))
    }

    fn get_mounts_path() -> Result<PathBuf> {
        let platform = get_platform()?;
        let config_dir = platform.default_config_dir();

        // Try different mounts paths in order of preference
        let paths = vec![
            std::env::var("HOME").ok().map(|h| {
                PathBuf::from(h)
                    .join(".config")
                    .join("fuji")
                    .join("mounts.toml")
            }),
            Some(Self::expand_home_dir(config_dir).join("mounts.toml")),
            Some(PathBuf::from("/tmp/fuji/mounts.toml")),
        ];

        for path in paths {
            if let Some(path) = path {
                if let Some(parent) = path.parent() {
                    if !parent.exists() {
                        if let Err(e) = std::fs::create_dir_all(parent) {
                            tracing::warn!("Failed to create directory {:?}: {}", parent, e);
                            continue;
                        }
                    }
                }

                // Check if we can write to path or create it
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(&path)
                {
                    Ok(_) => {
                        tracing::info!("Using mounts path: {:?}", path);
                        return Ok(path);
                    }
                    Err(e) => {
                        tracing::warn!("Cannot use mounts path {:?}: {}", path, e);
                    }
                }
            }
        }

        Err(FujiError::Config(
            "Cannot find writable mounts path".to_string(),
        ))
    }
}
