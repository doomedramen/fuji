use crate::error::{FujiError, Result};
use crate::platform::{common::UnixPlatformBase, MountInfo, Platform};

pub struct MacOSPlatform {
    base: UnixPlatformBase,
}

impl MacOSPlatform {
    pub fn new() -> Self {
        Self {
            base: UnixPlatformBase::new(),
        }
    }

    fn mount_nfs(&self, host: &str, export_path: &str, mount_point: &str) -> Result<()> {
        // Check if mount command exists (macOS has built-in NFS support)
        if !self.base.command_exists("mount") {
            return Err(FujiError::MountFailed("mount command not found".to_string()));
        }

        // Create mount point if it doesn't exist
        if !std::path::Path::new(mount_point).exists() {
            std::fs::create_dir_all(mount_point).map_err(|e| {
                FujiError::MountFailed(format!("Failed to create mount point: {}", e))
            })?;
        }

        // Build mount command for macOS (nfs://host/path format)
        let source = format!("{}:{}", host, export_path);
        let output = std::process::Command::new("mount")
            .args(["-t", "nfs", "-o", "resvport,nolock", &source, mount_point])
            .output()
            .map_err(|e| {
                FujiError::MountFailed(format!("Failed to execute mount command: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FujiError::MountFailed(format!("Mount failed: {}", stderr)));
        }

        Ok(())
    }

    fn mount_smb(&self, host: &str, _share: &str, mount_point: &str) -> Result<()> {
        // Check if mount_smbfs command exists (macOS built-in)
        if !self.base.command_exists("mount_smbfs") {
            return Err(FujiError::MountFailed("mount_smbfs command not found. Install SMB support or use a newer macOS version".to_string()));
        }

        // Create mount point if it doesn't exist
        if !std::path::Path::new(mount_point).exists() {
            std::fs::create_dir_all(mount_point).map_err(|e| {
                FujiError::MountFailed(format!("Failed to create mount point: {}", e))
            })?;
        }

        // Build mount command for macOS (mount_smbfs)
        let source = format!("//{}@{}", "guest", host);
        let output = std::process::Command::new("mount_smbfs")
            .args([&source, mount_point])
            .output()
            .map_err(|e| {
                FujiError::MountFailed(format!("Failed to execute mount_smbfs command: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FujiError::MountFailed(format!("Mount failed: {}", stderr)));
        }

        Ok(())
    }
}

impl Platform for MacOSPlatform {
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

        // Try to find mount from system
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
        // Use mount command to list mounts on macOS
        let output = std::process::Command::new("mount")
            .output()
            .map_err(|e| FujiError::MountFailed(format!("Failed to execute mount command: {}", e)))?;

        let mounts_output = String::from_utf8_lossy(&output.stdout);
        let mut mounts = Vec::new();

        for line in mounts_output.lines() {
            // Parse macOS mount format: host:/export/path on /mount_point (nfs)
            if line.contains(" on ") && (line.contains("(nfs)") || line.contains("(smbfs)")) {
                let parts: Vec<&str> = line.split(" on ").collect();
                if parts.len() == 2 {
                    let device = parts[0].trim();
                    let mount_part = parts[1].trim();

                    let mount_point_end = mount_part.find(' ').unwrap_or(mount_part.len());
                    let mount_point = &mount_part[..mount_point_end];

                    let (url, mount_id, mount_type) = if line.contains("(nfs)") {
                        // Parse NFS device format: hostname:/export/path
                        if let Some(colon_pos) = device.find(':') {
                            let hostname = &device[..colon_pos];
                            let mount_id = format!("{}_nfs", hostname.replace(['.', '-'], "_"));
                            (format!("nfs://{}", device), mount_id, crate::platform::MountType::Nfs)
                        } else {
                            continue;
                        }
                    } else {
                        // Parse SMBFS device format: //user@host/share
                        let device_clean = device.replace("//", "");
                        if let Some(at_pos) = device_clean.find('@') {
                            let host_share = &device_clean[at_pos + 1..];
                            if let Some(slash_pos) = host_share.find('/') {
                                let hostname = &host_share[..slash_pos];
                                let mount_id = format!("{}_smb", hostname.replace(['.', '-'], "_"));
                                (format!("smb://{}", host_share), mount_id, crate::platform::MountType::Smb)
                            } else {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    };

                    mounts.push(MountInfo {
                        id: mount_id,
                        url,
                        mount_point: mount_point.to_string(),
                        mount_type,
                    });
                }
            }
        }

        Ok(mounts)
    }

    fn is_supported(&self) -> bool {
        cfg!(target_os = "macos")
    }

    fn default_socket_path(&self) -> &'static str {
        // Use user-accessible temp directory by default on macOS
        // /var/run requires root permissions, so prefer /tmp
        "/tmp/fuji.sock"
    }

    fn default_config_dir(&self) -> &'static str {
        // Use user's Library directory to avoid requiring admin access
        // The config module will expand $HOME if needed
        "$HOME/Library/Application Support/fuji"
    }

    fn default_mount_root(&self) -> &'static str {
        // macOS doesn't have /mnt convention, use /Volumes
        "/Volumes/fuji"
    }
}