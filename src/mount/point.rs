//! Mount point validation and creation
//!
//! Provides functionality for validating mount points, creating directories,
//! and managing permissions.

use anyhow::{anyhow, Context, Result};
use nix::unistd::{getuid, getgid};
use std::path::Path;
use tracing::{debug, info, warn};

use crate::platform::Platform;
use crate::security::permissions::{PermissionManager, PermissionConfig};

/// Mount point validator and manager
pub struct MountPointValidator {
    platform: Box<dyn Platform>,
    permission_manager: PermissionManager,
}

impl MountPointValidator {
    /// Create a new mount point validator
    pub fn new(platform: Box<dyn Platform>) -> Self {
        Self {
            platform,
            permission_manager: PermissionManager::new(),
        }
    }

    /// Validate a mount point path
    pub fn validate_path(&self, mount_point: &Path) -> Result<()> {
        // Path must be absolute
        if !mount_point.is_absolute() {
            return Err(anyhow!(
                "Mount point must be absolute path: {}",
                mount_point.display()
            ));
        }

        // Check for dangerous paths
        self.check_dangerous_paths(mount_point)?;

        // Check path length limits
        self.check_path_length(mount_point)?;

        debug!("Mount point path validation passed: {}", mount_point.display());
        Ok(())
    }

    /// Check for dangerous or prohibited paths
    fn check_dangerous_paths(&self, mount_point: &Path) -> Result<()> {
        let path_str = mount_point.to_string_lossy();

        // Prohibited system directories
        let prohibited = [
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin",
            "/etc",
            "/boot",
            "/sys",
            "/proc",
            "/dev",
        ];

        for prohibited_path in &prohibited {
            if path_str.starts_with(*prohibited_path) {
                return Err(anyhow!(
                    "Cannot mount under system directory: {}",
                    *prohibited_path
                ));
            }
        }

        // Check for parent directory traversal attempts
        if path_str.contains("..") {
            return Err(anyhow!("Path contains parent directory traversal"));
        }

        // Check for empty path segments
        if path_str.contains("//") {
            return Err(anyhow!("Path contains empty segments"));
        }

        Ok(())
    }

    /// Check path length limits
    fn check_path_length(&self, mount_point: &Path) -> Result<()> {
        // Most filesystems have 255 byte limit for path components
        for component in mount_point.components() {
            if let Some(name) = component.as_os_str().to_str() {
                if name.len() > 255 {
                    return Err(anyhow!(
                        "Path component too long: {} (max 255 bytes)",
                        name
                    ));
                }
            }
        }

        // Check total path length (typical limit is 4096 bytes)
        let path_str = mount_point.to_string_lossy();
        if path_str.len() > 4096 {
            return Err(anyhow!(
                "Mount path too long: {} bytes (max 4096)",
                path_str.len()
            ));
        }

        Ok(())
    }

    /// Check if mount point already exists and is a mount
    pub async fn check_existing_mount(&self, mount_point: &Path) -> Result<bool> {
        if !self.platform.path_exists(mount_point) {
            return Ok(false);
        }

        // Check if it's already a mount point
        match self.platform.is_mounted(mount_point) {
            Ok(is_mounted) => {
                if is_mounted {
                    warn!(
                        "Mount point already mounted: {}",
                        mount_point.display()
                    );
                }
                Ok(is_mounted)
            }
            Err(e) => {
                warn!("Failed to check if {} is mounted: {}", mount_point.display(), e);
                // Assume it's not mounted if we can't check
                Ok(false)
            }
        }
    }

    /// Check for conflicts with existing mounts
    pub async fn check_mount_conflicts(&self, mount_point: &Path) -> Result<Vec<String>> {
        let mut conflicts = Vec::new();

        // Get all system mounts
        let system_mounts = self.platform.list_system_mounts()
            .unwrap_or_default();

        // Check if our mount point is already used
        for (mount_path, mount_info) in system_mounts {
            if mount_path == mount_point {
                conflicts.push(format!(
                    "Path {} already has {} mounted",
                    mount_point.display(),
                    mount_info.device
                ));
            }

            // Check for nested mounts (e.g., trying to mount on /mnt/foo when /mnt is already mounted)
            if mount_point.starts_with(&mount_path) && mount_path != Path::new("/") {
                conflicts.push(format!(
                    "Cannot mount on {} as it's under existing mount {}",
                    mount_point.display(),
                    mount_path.display()
                ));
            }
        }

        Ok(conflicts)
    }

    /// Create mount point directory if it doesn't exist
    pub async fn create_mount_point(
        &mut self,
        mount_point: &Path,
        owner: Option<&str>,
        mode: Option<u32>,
    ) -> Result<()> {
        // Create parent directories if needed
        if let Some(parent) = mount_point.parent() {
            self.platform.ensure_dir_exists(parent)
                .with_context(|| {
                    format!("Failed to create parent directory: {}", parent.display())
                })?;
        }

        // Create the mount point directory
        if !self.platform.path_exists(mount_point) {
            self.platform.create_dir(mount_point)
                .with_context(|| {
                    format!("Failed to create mount point: {}", mount_point.display())
                })?;
            info!("Created mount point: {}", mount_point.display());
        }

        // Set permissions
        let config = if let Some(mode) = mode {
            PermissionConfig {
                owner_uid: None,
                owner_gid: None,
                mode,
                umask: 0o022,
                inherit: false,
            }
        } else {
            PermissionConfig::default()
        };

        self.permission_manager
            .set_permissions(mount_point, owner, Some(&config))
            .with_context(|| {
                format!("Failed to set permissions for: {}", mount_point.display())
            })?;

        debug!("Mount point created and configured: {}", mount_point.display());
        Ok(())
    }

    /// Validate mount point is ready for mounting
    pub async fn validate_for_mount(&self, mount_point: &Path) -> Result<()> {
        // Check if path exists
        if !self.platform.path_exists(mount_point) {
            return Err(anyhow!(
                "Mount point does not exist: {}",
                mount_point.display()
            ));
        }

        // Check if it's a directory
        if !mount_point.is_dir() {
            return Err(anyhow!(
                "Mount point is not a directory: {}",
                mount_point.display()
            ));
        }

        // Check if it's already mounted
        if self.platform.is_mounted(mount_point)? {
            return Err(anyhow!(
                "Mount point is already mounted: {}",
                mount_point.display()
            ));
        }

        // Check permissions
        if !self.platform.can_access_path(mount_point)? {
            return Err(anyhow!(
                "No permission to access mount point: {}",
                mount_point.display()
            ));
        }

        // Check if directory is empty (not strictly necessary but good practice)
        let mut entries = match std::fs::read_dir(mount_point) {
            Ok(entries) => entries,
            Err(e) => {
                warn!("Failed to read mount point directory: {}", e);
                return Ok(()); // Don't fail if we can't read the directory
            }
        };

        if entries.next().is_some() {
            warn!(
                "Mount point directory is not empty: {}",
                mount_point.display()
            );
        }

        Ok(())
    }

    /// Clean up mount point after unmount (optional)
    pub async fn cleanup_mount_point(&self, mount_point: &Path, remove_empty: bool) -> Result<()> {
        if !self.platform.path_exists(mount_point) {
            return Ok(());
        }

        // Check if it's still mounted
        if self.platform.is_mounted(mount_point)? {
            warn!("Cannot clean up still-mounted mount point: {}", mount_point.display());
            return Ok(());
        }

        // Optionally remove if empty
        if remove_empty {
            match std::fs::read_dir(mount_point) {
                Ok(mut entries) => {
                    if entries.next().is_none() {
                        if let Err(e) = std::fs::remove_dir(mount_point) {
                            warn!("Failed to remove empty mount point {}: {}", mount_point.display(), e);
                        } else {
                            info!("Removed empty mount point: {}", mount_point.display());
                        }
                    } else {
                        debug!("Mount point not empty, keeping: {}", mount_point.display());
                    }
                }
                Err(e) => {
                    warn!("Failed to check mount point for cleanup: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Get recommended permissions for mount point
    pub fn get_recommended_permissions(&self) -> u32 {
        // Use current user's umask but ensure at least owner rwx
        let current_uid = getuid().as_raw();
        let current_gid = getgid().as_raw();

        // Default to 755 (owner rwx, group rx, other rx)
        0o755
    }
}

impl Default for MountPointValidator {
    fn default() -> Self {
        Self::new(crate::platform::get_platform())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::platform::linux::LinuxPlatform;

    #[tokio::test]
    async fn test_validate_absolute_path() {
        let validator = MountPointValidator::new(Box::new(LinuxPlatform));

        // Valid absolute path
        assert!(validator.validate_path(Path::new("/mnt/test")).is_ok());

        // Invalid relative path
        assert!(validator.validate_path(Path::new("mnt/test")).is_err());

        // Valid absolute path with subdirectories
        assert!(validator.validate_path(Path::new("/mnt/fuji/share")).is_ok());
    }

    #[tokio::test]
    async fn test_dangerous_paths() {
        let validator = MountPointValidator::new(Box::new(LinuxPlatform));

        // Should not allow mounting under /bin
        assert!(validator.validate_path(Path::new("/bin/test")).is_err());

        // Should not allow mounting under /etc
        assert!(validator.validate_path(Path::new("/etc/test")).is_err());

        // Should not allow parent directory traversal
        assert!(validator.validate_path(Path::new("/mnt/../etc")).is_err());

        // Regular path should be allowed
        assert!(validator.validate_path(Path::new("/mnt/test")).is_ok());
    }

    #[tokio::test]
    async fn test_create_mount_point() {
        let temp_dir = TempDir::new().unwrap();
        let mount_point = temp_dir.path().join("test_mount");

        let mut validator = MountPointValidator::new(Box::new(LinuxPlatform));

        // Create mount point
        validator
            .create_mount_point(&mount_point, None, Some(0o755))
            .await
            .unwrap();

        assert!(mount_point.exists());
        assert!(mount_point.is_dir());

        // Validate for mounting
        validator.validate_for_mount(&mount_point).await.unwrap();
    }

    #[tokio::test]
    async fn test_mount_conflicts() {
        let temp_dir = TempDir::new().unwrap();
        let validator = MountPointValidator::new(Box::new(LinuxPlatform));

        // Create a mock existing mount point
        let mount_point = temp_dir.path().join("existing_mount");
        std::fs::create_dir_all(&mount_point).unwrap();

        // Should not find conflicts if nothing is mounted
        let conflicts = validator.check_mount_conflicts(&mount_point).await.unwrap();
        assert_eq!(conflicts.len(), 0);
    }
}