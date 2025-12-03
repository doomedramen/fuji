use crate::error::{FujiError, Result};
use crate::platform::{MountInfo, MountType};
use std::collections::HashMap;
use std::path::Path;
use std::sync::RwLock;

pub struct UnixPlatformBase {
    pub mounts: RwLock<HashMap<String, MountInfo>>,
}

impl UnixPlatformBase {
    pub fn new() -> Self {
        tracing::debug!("Initializing new UnixPlatformBase");
        let base = Self {
            mounts: RwLock::new(HashMap::new()),
        };
        tracing::debug!("UnixPlatformBase initialized with empty mount tracking");
        base
    }

    pub fn create_mount_point(&self, url: &url::Url, mount_root: &str) -> Result<String> {
        tracing::info!("Creating mount point for URL: {} using root: {}", url, mount_root);

        let host = url
            .host_str()
            .ok_or_else(|| FujiError::MountFailed("Invalid URL: missing host".to_string()))?;
        let scheme = url.scheme();

        tracing::debug!("Parsed URL - host: {}, scheme: {}", host, scheme);

        // Sanitize hostname to remove special characters
        let sanitized_host = host.replace(['.', '-'], "_");
        tracing::debug!("Sanitized hostname: {} -> {}", host, sanitized_host);

        // Create base directory using platform-specific mount root
        let base_dir = mount_root;
        tracing::debug!("Creating base mount directory: {}", base_dir);
        if !std::path::Path::new(base_dir).exists() {
            tracing::info!("Base mount directory does not exist, creating: {}", base_dir);
            std::fs::create_dir_all(base_dir).map_err(|e| {
                tracing::error!("Failed to create base mount directory {}: {}", base_dir, e);
                FujiError::MountFailed(format!("Failed to create base mount directory: {}", e))
            })?;
            tracing::info!("Successfully created base mount directory: {}", base_dir);
        } else {
            tracing::debug!("Base mount directory already exists: {}", base_dir);
        }

        // Create host directory
        let host_dir = format!("{}/{}", base_dir, sanitized_host);
        tracing::debug!("Creating host mount directory: {}", host_dir);
        if !std::path::Path::new(&host_dir).exists() {
            tracing::info!("Host mount directory does not exist, creating: {}", host_dir);
            std::fs::create_dir_all(&host_dir).map_err(|e| {
                tracing::error!("Failed to create host mount directory {}: {}", host_dir, e);
                FujiError::MountFailed(format!("Failed to create host mount directory: {}", e))
            })?;
            tracing::info!("Successfully created host mount directory: {}", host_dir);
        } else {
            tracing::debug!("Host mount directory already exists: {}", host_dir);
        }

        // Determine mount name based on URL scheme and path
        let mount_name = match scheme {
            "nfs" => {
                let path = url.path();
                tracing::debug!("Processing NFS export path: '{}'", path);
                if path.is_empty() || path == "/" {
                    tracing::debug!("NFS path is root, using mount name: 'root'");
                    "root".to_string()
                } else {
                    // Remove leading slash and replace other slashes with underscores
                    let clean_path = path.trim_start_matches('/').replace('/', "_");
                    tracing::debug!("NFS path cleaned to mount name: '{}'", clean_path);
                    clean_path
                }
            }
            "smb" | "cifs" => {
                let share = url.path().trim_start_matches('/');
                tracing::debug!("Processing SMB share name: '{}'", share);
                if share.is_empty() {
                    tracing::debug!("SMB share is empty, using mount name: 'public'");
                    "public".to_string()
                } else {
                    // Sanitize share name
                    let clean_share = share.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
                    tracing::debug!("SMB share sanitized to mount name: '{}'", clean_share);
                    clean_share
                }
            }
            _ => {
                tracing::error!("Unsupported URL scheme: {}", scheme);
                return Err(FujiError::MountFailed(format!(
                    "Unsupported URL scheme: {}",
                    scheme
                )));
            }
        };

        let mount_point = format!("{}/{}", host_dir, mount_name);
        tracing::info!("Final mount point: {}", mount_point);

        // Create the final mount point directory
        tracing::debug!("Creating final mount point directory: {}", mount_point);
        if !std::path::Path::new(&mount_point).exists() {
            tracing::info!("Mount point directory does not exist, creating: {}", mount_point);
            std::fs::create_dir_all(&mount_point).map_err(|e| {
                tracing::error!("Failed to create mount point directory {}: {}", mount_point, e);
                FujiError::MountFailed(format!("Failed to create mount point: {}", e))
            })?;
            tracing::info!("Successfully created mount point directory: {}", mount_point);
        } else {
            tracing::debug!("Mount point directory already exists: {}", mount_point);
        }

        tracing::info!("Successfully created mount point: {}", mount_point);
        Ok(mount_point)
    }

    pub fn parse_nfs_url(&self, url: &url::Url) -> Result<(String, String)> {
        tracing::debug!("Parsing NFS URL: {}", url);

        let host = url
            .host_str()
            .ok_or_else(|| {
                tracing::error!("NFS URL missing host: {}", url);
                FujiError::MountFailed("Invalid NFS URL: missing host".to_string())
            })?;
        let path = url.path();

        tracing::debug!("Extracted NFS host: '{}', path: '{}'", host, path);

        if path.is_empty() || path == "/" {
            tracing::error!("NFS URL missing export path: {}", url);
            return Err(FujiError::MountFailed(
                "Invalid NFS URL: missing export path".to_string(),
            ));
        }

        tracing::info!("Successfully parsed NFS URL - host: {}, export path: {}", host, path);
        Ok((host.to_string(), path.to_string()))
    }

    pub fn parse_smb_url(&self, url: &url::Url) -> Result<(String, String)> {
        tracing::debug!("Parsing SMB URL: {}", url);

        let host = url
            .host_str()
            .ok_or_else(|| {
                tracing::error!("SMB URL missing host: {}", url);
                FujiError::MountFailed("Invalid SMB URL: missing host".to_string())
            })?;
        let share = url.path().trim_start_matches('/');

        tracing::debug!("Extracted SMB host: '{}', share: '{}'", host, share);

        if share.is_empty() {
            tracing::error!("SMB URL missing share name: {}", url);
            return Err(FujiError::MountFailed(
                "Invalid SMB URL: missing share name".to_string(),
            ));
        }

        tracing::info!("Successfully parsed SMB URL - host: {}, share: {}", host, share);
        Ok((host.to_string(), share.to_string()))
    }

    pub fn command_exists(&self, command: &str) -> bool {
        tracing::debug!("Checking if command exists in PATH: {}", command);

        // Check if command exists in PATH
        if let Ok(path) = std::env::var("PATH") {
            tracing::debug!("Searching PATH: {}", path);
            for dir in path.split(':') {
                let cmd_path = Path::new(dir).join(command);
                if cmd_path.exists() {
                    tracing::debug!("Found command at: {}", cmd_path.display());
                    return true;
                } else {
                    tracing::debug!("Command not found at: {}", cmd_path.display());
                }
            }
        } else {
            tracing::warn!("Failed to get PATH environment variable");
        }

        tracing::debug!("Command '{}' not found in PATH", command);
        false
    }

    pub fn generate_mount_id(&self, host: &str, scheme: &str) -> String {
        tracing::debug!("Generating mount ID for host: '{}', scheme: '{}'", host, scheme);
        let sanitized_host = host.replace(['.', '-'], "_");
        let mount_id = format!("{}_{}", sanitized_host, scheme);
        tracing::debug!("Generated mount ID: '{}'", mount_id);
        mount_id
    }

    pub fn create_mount_info(&self, id: String, url: String, mount_point: String, scheme: &str) -> Result<MountInfo> {
        tracing::debug!("Creating mount info - ID: '{}', URL: '{}', mount point: '{}', scheme: '{}'",
                       id, url, mount_point, scheme);

        let mount_type = match scheme {
            "nfs" => MountType::Nfs,
            "smb" | "cifs" => MountType::Smb,
            _ => {
                tracing::error!("Unsupported scheme for mount info creation: {}", scheme);
                return Err(FujiError::MountFailed(format!("Unsupported scheme: {}", scheme)));
            }
        };

        let mount_info = MountInfo {
            id: id.clone(),
            url: url.clone(),
            mount_point: mount_point.clone(),
            mount_type: mount_type.clone(),
        };

        tracing::info!("Successfully created mount info: {} -> {} ({:?})", id, mount_point, mount_type);
        Ok(mount_info)
    }

    pub fn unmount_by_mount_point(&self, mount_point: &str) -> Result<()> {
        tracing::info!("Attempting to unmount mount point: {}", mount_point);

        let output = std::process::Command::new("umount")
            .args([mount_point])
            .output()
            .map_err(|e| {
                tracing::error!("Failed to execute umount command for {}: {}", mount_point, e);
                FujiError::UnmountFailed(format!("Failed to execute umount command: {}", e))
            })?;

        tracing::debug!("umount command exit code: {}", output.status);
        if !output.stdout.is_empty() {
            tracing::debug!("umount stdout: {}", String::from_utf8_lossy(&output.stdout));
        }
        if !output.stderr.is_empty() {
            tracing::debug!("umount stderr: {}", String::from_utf8_lossy(&output.stderr));
        }

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!("Unmount failed for {}: {}", mount_point, stderr);
            return Err(FujiError::UnmountFailed(format!(
                "Unmount failed: {}",
                stderr
            )));
        }

        tracing::info!("Successfully unmounted: {}", mount_point);

        // Remove mount point directory
        tracing::debug!("Attempting to remove mount point directory: {}", mount_point);
        if let Err(e) = std::fs::remove_dir(mount_point) {
            tracing::warn!(
                "Failed to remove mount point directory {}: {}",
                mount_point,
                e
            );
        } else {
            tracing::info!("Successfully removed mount point directory: {}", mount_point);
        }

        Ok(())
    }

    pub fn remove_from_tracking(&self, mount_id: &str) -> Option<MountInfo> {
        tracing::debug!("Removing mount from tracking: {}", mount_id);
        let mut mounts = self.mounts.write().unwrap();
        let removed = mounts.remove(mount_id);
        if removed.is_some() {
            tracing::info!("Successfully removed mount from tracking: {}", mount_id);
        } else {
            tracing::warn!("Mount '{}' not found in tracking", mount_id);
        }
        removed
    }

    pub fn get_tracked_mount(&self, mount_id: &str) -> Option<MountInfo> {  // Changed to return owned value instead of reference
        tracing::debug!("Looking up mount in tracking: {}", mount_id);
        let mounts = self.mounts.read().unwrap();
        let mount = mounts.get(mount_id).cloned();  // Cloned to return owned value
        if mount.is_some() {
            tracing::debug!("Found mount in tracking: {}", mount_id);
        } else {
            tracing::debug!("Mount '{}' not found in tracking", mount_id);
        }
        mount
    }

    pub fn add_to_tracking(&self, mount_info: MountInfo) {
        tracing::debug!("Adding mount to tracking: {} -> {}", mount_info.id, mount_info.mount_point);
        let mut mounts = self.mounts.write().unwrap();
        mounts.insert(mount_info.id.clone(), mount_info.clone());
        tracing::info!("Successfully added mount to tracking: {} -> {}", mount_info.id, mount_info.mount_point);
    }
}