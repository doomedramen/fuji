use crate::error::{FujiError, Result};
use crate::platform::{common::UnixPlatformBase, MountInfo, Platform};
use std::collections::HashMap;

pub struct LinuxPlatform {
    base: UnixPlatformBase,
}

impl LinuxPlatform {
    pub fn new() -> Self {
        tracing::info!("Initializing Linux platform");
        let platform = Self {
            base: UnixPlatformBase::new(),
        };
        tracing::info!("Linux platform initialized successfully");
        platform
    }

    fn mount_nfs(&self, host: &str, export_path: &str, mount_point: &str) -> Result<()> {
        tracing::info!("Mounting NFS share - host: {}, export: {}, mount point: {}", host, export_path, mount_point);

        // Check if nfs-common is installed
        if !self.base.command_exists("mount.nfs") {
            tracing::error!("mount.nfs command not found - nfs-common package not installed");
            return Err(FujiError::MountFailed("nfs-common package not installed. Please install it with: sudo apt-get install nfs-common".to_string()));
        }
        tracing::debug!("nfs-common package is available");

        // Create mount point if it doesn't exist
        if !std::path::Path::new(mount_point).exists() {
            tracing::info!("Mount point does not exist, creating: {}", mount_point);
            std::fs::create_dir_all(mount_point).map_err(|e| {
                tracing::error!("Failed to create mount point {}: {}", mount_point, e);
                FujiError::MountFailed(format!("Failed to create mount point: {}", e))
            })?;
            tracing::info!("Successfully created mount point: {}", mount_point);
        } else {
            tracing::debug!("Mount point already exists: {}", mount_point);
        }

        // Build mount command
        let source = format!("{}:{}", host, export_path);
        tracing::debug!("Executing NFS mount command: mount -t nfs -o nolock {} {}", source, mount_point);

        let output = std::process::Command::new("mount")
            .args(["-t", "nfs", "-o", "nolock", &source, mount_point])
            .output()
            .map_err(|e| {
                tracing::error!("Failed to execute mount command: {}", e);
                FujiError::MountFailed(format!("Failed to execute mount command: {}", e))
            })?;

        tracing::debug!("NFS mount command exit code: {}", output.status);
        if !output.stdout.is_empty() {
            tracing::debug!("NFS mount stdout: {}", String::from_utf8_lossy(&output.stdout));
        }
        if !output.stderr.is_empty() {
            tracing::debug!("NFS mount stderr: {}", String::from_utf8_lossy(&output.stderr));
        }

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!("NFS mount failed for {}:{} -> {}: {}", host, export_path, mount_point, stderr);
            return Err(FujiError::MountFailed(format!("Mount failed: {}", stderr)));
        }

        tracing::info!("Successfully mounted NFS share {}:{} -> {}", host, export_path, mount_point);
        Ok(())
    }

    fn mount_smb(&self, host: &str, share: &str, mount_point: &str) -> Result<()> {
        tracing::info!("Mounting SMB/CIFS share - host: {}, share: {}, mount point: {}", host, share, mount_point);

        // Check if cifs-utils is installed
        if !self.base.command_exists("mount.cifs") {
            tracing::error!("mount.cifs command not found - cifs-utils package not installed");
            return Err(FujiError::MountFailed("cifs-utils package not installed. Please install it with: sudo apt-get install cifs-utils".to_string()));
        }
        tracing::debug!("cifs-utils package is available");

        // Create mount point if it doesn't exist
        if !std::path::Path::new(mount_point).exists() {
            tracing::info!("Mount point does not exist, creating: {}", mount_point);
            std::fs::create_dir_all(mount_point).map_err(|e| {
                tracing::error!("Failed to create mount point {}: {}", mount_point, e);
                FujiError::MountFailed(format!("Failed to create mount point: {}", e))
            })?;
            tracing::info!("Successfully created mount point: {}", mount_point);
        } else {
            tracing::debug!("Mount point already exists: {}", mount_point);
        }

        // Build mount command (guest access for simplicity)
        let source = format!("//{}/{}", host, share);
        tracing::debug!("Executing SMB/CIFS mount command: mount -t cifs -o guest {} {}", source, mount_point);

        let output = std::process::Command::new("mount")
            .args(["-t", "cifs", &source, mount_point, "-o", "guest"])
            .output()
            .map_err(|e| {
                tracing::error!("Failed to execute mount command: {}", e);
                FujiError::MountFailed(format!("Failed to execute mount command: {}", e))
            })?;

        tracing::debug!("SMB/CIFS mount command exit code: {}", output.status);
        if !output.stdout.is_empty() {
            tracing::debug!("SMB/CIFS mount stdout: {}", String::from_utf8_lossy(&output.stdout));
        }
        if !output.stderr.is_empty() {
            tracing::debug!("SMB/CIFS mount stderr: {}", String::from_utf8_lossy(&output.stderr));
        }

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!("SMB/CIFS mount failed for //{}/{} -> {}: {}", host, share, mount_point, stderr);
            return Err(FujiError::MountFailed(format!("Mount failed: {}", stderr)));
        }

        tracing::info!("Successfully mounted SMB/CIFS share //{}/{} -> {}", host, share, mount_point);
        Ok(())
    }
}

impl Platform for LinuxPlatform {
    fn mount(&self, url: &str, mount_point: &str) -> Result<MountInfo> {
        let parsed_url = url::Url::parse(url)?;
        let host = parsed_url
            .host_str()
            .ok_or_else(|| FujiError::MountFailed("Invalid URL: missing host".to_string()))?;
        let scheme = parsed_url.scheme();

        // Generate mount ID using hostname_protocol format with sanitized hostname
        let mount_id = self.base.generate_mount_id(host, scheme);

        // Check if mount already exists in tracking
        if let Some(existing) = self.base.get_tracked_mount(&mount_id) {
            return Ok(existing.clone());
        }

        // Create mount info
        let mount_info = self.base.create_mount_info(mount_id.clone(), url.to_string(), mount_point.to_string(), scheme)?;

        // Perform actual mount operation
        match scheme {
            "nfs" => {
                let (nfs_host, export_path) = self.base.parse_nfs_url(&parsed_url)?;
                self.mount_nfs(&nfs_host, &export_path, mount_point)?;
            }
            "smb" | "cifs" => {
                let (smb_host, share) = self.base.parse_smb_url(&parsed_url)?;
                self.mount_smb(&smb_host, &share, mount_point)?;
            }
            _ => return Err(FujiError::MountFailed(format!("Unsupported scheme: {}", scheme))),
        }

        Ok(mount_info)
    }

    fn unmount(&self, mount_id: &str) -> Result<()> {
        // Remove from internal tracking
        if let Some(mount_info) = self.base.remove_from_tracking(mount_id) {
            return self.base.unmount_by_mount_point(&mount_info.mount_point);
        }

        // If not found in internal tracking, try to find it from /proc/mounts
        let current_mounts = self.list_mounts()?;
        if let Some(mount_info) = current_mounts.iter().find(|m| m.id == mount_id) {
            return self.base.unmount_by_mount_point(&mount_info.mount_point);
        }

        Err(FujiError::UnmountFailed(format!(
            "Mount with ID {} not found",
            mount_id
        )))
    }

    fn list_mounts(&self) -> Result<Vec<MountInfo>> {
        // Read /proc/mounts to get current mounts
        let mounts_content = std::fs::read_to_string("/proc/mounts")
            .map_err(|e| FujiError::MountFailed(format!("Failed to read /proc/mounts: {}", e)))?;

        let mut mounts = Vec::new();
        for line in mounts_content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let device = parts[0];
                let mount_point = parts[1];
                let fs_type = parts[2];

                if fs_type == "nfs" || fs_type == "cifs" {
                    // Extract URL and generate consistent mount ID
                    let (url, mount_id) = if fs_type == "nfs" {
                        // Parse NFS device format: hostname:/export/path
                        if let Some(colon_pos) = device.find(':') {
                            let hostname = &device[..colon_pos];
                            let mount_id = format!("{}_nfs", hostname);
                            (format!("nfs://{}", device), mount_id)
                        } else {
                            continue; // Skip invalid NFS device format
                        }
                    } else {
                        // Parse CIFS device format: //hostname/share
                        let device_clean = device.replace("//", "");
                        if let Some(slash_pos) = device_clean.find('/') {
                            let hostname = &device_clean[..slash_pos];
                            let mount_id = format!("{}_smb", hostname);
                            (format!("smb://{}", device_clean), mount_id)
                        } else {
                            continue; // Skip invalid CIFS device format
                        }
                    };

                    mounts.push(MountInfo {
                        id: mount_id,
                        url,
                        mount_point: mount_point.to_string(),
                        mount_type: if fs_type == "nfs" {
                            crate::platform::MountType::Nfs
                        } else {
                            crate::platform::MountType::Smb
                        },
                    });
                }
            }
        }

        Ok(mounts)
    }

    fn is_supported(&self) -> bool {
        cfg!(target_os = "linux")
    }

    fn default_socket_path(&self) -> &'static str {
        "/run/fuji.sock"
    }

    fn default_config_dir(&self) -> &'static str {
        "/etc/fuji"
    }

    fn default_mount_root(&self) -> &'static str {
        "/mnt/fuji"
    }
}