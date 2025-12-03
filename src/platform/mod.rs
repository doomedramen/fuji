use crate::error::{FujiError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

pub mod common;
pub mod linux;
pub mod macos;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountInfo {
    pub id: String,
    pub url: String,
    pub mount_point: String,
    pub mount_type: MountType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MountType {
    Nfs,
    Smb,
}

pub trait Platform : Send + Sync {
    fn mount(&self, url: &str, mount_point: &str) -> Result<MountInfo>;
    fn unmount(&self, mount_id: &str) -> Result<()>;  // Changed from &mut self to &self
    fn list_mounts(&self) -> Result<Vec<MountInfo>>;
    fn is_supported(&self) -> bool;

    // Platform-specific path configurations
    fn default_socket_path(&self) -> &'static str;
    fn default_config_dir(&self) -> &'static str;
    fn default_mount_root(&self) -> &'static str;
}

pub fn get_platform() -> Result<Box<dyn Platform + Send + Sync>> {
    // Check runtime OS instead of compile-time target
    match std::env::consts::OS {
        "linux" => Ok(Box::new(linux::LinuxPlatform::new()) as Box<dyn Platform + Send + Sync>),
        "macos" => Ok(Box::new(macos::MacOSPlatform::new()) as Box<dyn Platform + Send + Sync>),
        _ => Err(FujiError::PlatformNotSupported),
    }
}
