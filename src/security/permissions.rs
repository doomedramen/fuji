// Allow dead code - permission utilities for future features
#![allow(dead_code)]

//! Mount point permission management
//!
//! Manages permissions and ownership of mount points with proper UID/GID mapping.

use anyhow::{Result, anyhow};
use nix::unistd::{Gid, Uid, chown};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use tracing::{debug, info};

/// User and group mapping configuration
#[derive(Debug, Clone)]
pub struct UserMapping {
    pub username: String,
    pub uid: Uid,
    pub gid: Gid,
    pub groups: Vec<Gid>,
}

/// Permission configuration for mount points
#[derive(Debug, Clone)]
pub struct PermissionConfig {
    pub owner_uid: Option<Uid>,
    pub owner_gid: Option<Gid>,
    pub mode: u32,     // File mode bits (e.g., 0o755)
    pub umask: u32,    // Process umask to apply
    pub inherit: bool, // Inherit from parent directory
}

impl Default for PermissionConfig {
    fn default() -> Self {
        Self {
            owner_uid: None,
            owner_gid: None,
            mode: 0o755,
            umask: 0o022,
            inherit: true,
        }
    }
}

/// Permission manager for mount points
pub struct PermissionManager {
    user_cache: HashMap<String, UserMapping>,
    default_config: PermissionConfig,
}

impl PermissionManager {
    /// Create a new permission manager
    pub fn new() -> Self {
        Self {
            user_cache: HashMap::new(),
            default_config: PermissionConfig::default(),
        }
    }

    /// Set default permission configuration
    pub fn with_default_config(mut self, config: PermissionConfig) -> Self {
        self.default_config = config;
        self
    }

    /// Get user mapping for username
    pub fn get_user_mapping(&mut self, username: &str) -> Result<UserMapping> {
        // Check cache first
        if let Some(mapping) = self.user_cache.get(username) {
            return Ok(mapping.clone());
        }

        // Look up user from system
        let mapping = self.lookup_user(username)?;
        self.user_cache
            .insert(username.to_string(), mapping.clone());
        Ok(mapping)
    }

    /// Look up user from system (/etc/passwd)
    fn lookup_user(&self, username: &str) -> Result<UserMapping> {
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        let passwd_file =
            File::open("/etc/passwd").map_err(|e| anyhow!("Failed to open /etc/passwd: {}", e))?;
        let reader = BufReader::new(passwd_file);

        for line in reader.lines() {
            let line = line.map_err(|e| anyhow!("Failed to read /etc/passwd: {}", e))?;
            let parts: Vec<&str> = line.split(':').collect();

            if parts.len() >= 7 && parts[0] == username {
                let uid = parts[2]
                    .parse::<u32>()
                    .map_err(|_| anyhow!("Invalid UID for user {}", username))?;
                let gid = parts[3]
                    .parse::<u32>()
                    .map_err(|_| anyhow!("Invalid GID for user {}", username))?;

                // Get supplementary groups
                let groups = self.get_user_groups(username)?;

                return Ok(UserMapping {
                    username: username.to_string(),
                    uid: Uid::from_raw(uid),
                    gid: Gid::from_raw(gid),
                    groups,
                });
            }
        }

        Err(anyhow!("User {} not found", username))
    }

    /// Get supplementary groups for user
    fn get_user_groups(&self, username: &str) -> Result<Vec<Gid>> {
        use std::process::Command;

        let output = Command::new("id")
            .arg("-G")
            .arg(username)
            .output()
            .map_err(|e| anyhow!("Failed to execute id command: {}", e))?;

        if !output.status.success() {
            return Err(anyhow!("id command failed"));
        }

        let output_str = String::from_utf8(output.stdout)
            .map_err(|e| anyhow!("Failed to parse id output: {}", e))?;

        let groups: Result<Vec<Gid>, _> = output_str
            .split_whitespace()
            .map(|g| g.parse::<u32>().map(Gid::from_raw))
            .collect();

        groups.map_err(|e| anyhow!("Failed to parse group IDs: {}", e))
    }

    /// Create mount point with proper permissions
    pub fn create_mount_point<P: AsRef<Path>>(
        &mut self,
        path: P,
        config: Option<&PermissionConfig>,
    ) -> Result<()> {
        let path = path.as_ref();
        let config = config.unwrap_or(&self.default_config);

        // Create directory
        fs::create_dir_all(path)
            .map_err(|e| anyhow!("Failed to create mount point {}: {}", path.display(), e))?;

        // Determine final permissions
        let (final_uid, final_gid, final_mode) = if config.inherit {
            if let Some(parent) = path.parent() {
                if parent.exists() {
                    let metadata = fs::metadata(parent)?;
                    let uid = config
                        .owner_uid
                        .unwrap_or_else(|| Uid::from_raw(metadata.uid()));
                    let gid = config
                        .owner_gid
                        .unwrap_or_else(|| Gid::from_raw(metadata.gid()));
                    let mode = if config.mode == 0 {
                        metadata.mode() & !config.umask
                    } else {
                        config.mode
                    };
                    (uid, gid, mode)
                } else {
                    (
                        config.owner_uid.unwrap_or_else(Uid::current),
                        config.owner_gid.unwrap_or_else(Gid::current),
                        config.mode,
                    )
                }
            } else {
                (
                    config.owner_uid.unwrap_or_else(Uid::current),
                    config.owner_gid.unwrap_or_else(Gid::current),
                    config.mode,
                )
            }
        } else {
            (
                config.owner_uid.unwrap_or_else(Uid::current),
                config.owner_gid.unwrap_or_else(Gid::current),
                config.mode,
            )
        };

        // Set ownership
        chown(path, Some(final_uid), Some(final_gid))
            .map_err(|e| anyhow!("Failed to set ownership for {}: {}", path.display(), e))?;

        // Set permissions
        fs::set_permissions(path, fs::Permissions::from_mode(final_mode))
            .map_err(|e| anyhow!("Failed to set permissions for {}: {}", path.display(), e))?;

        info!(
            "Created mount point {} with uid:{} gid:{} mode:{:o}",
            path.display(),
            final_uid,
            final_gid,
            final_mode
        );

        Ok(())
    }

    /// Set permissions for existing mount point
    pub fn set_permissions<P: AsRef<Path>>(
        &mut self,
        path: P,
        username: Option<&str>,
        config: Option<&PermissionConfig>,
    ) -> Result<()> {
        let path = path.as_ref();

        // Clone the config we need
        let config = config
            .cloned()
            .unwrap_or_else(|| self.default_config.clone());

        if !path.exists() {
            return Err(anyhow!("Path {} does not exist", path.display()));
        }

        // Get user mapping and owner info before we need to borrow for metadata
        let user_mapping = if let Some(username) = username {
            Some(self.get_user_mapping(username)?)
        } else {
            None
        };

        let owner_uid = config.owner_uid;
        let owner_gid = config.owner_gid;

        let (uid, gid) = if let Some(ref mapping) = user_mapping {
            (Some(mapping.uid), Some(mapping.gid))
        } else {
            (owner_uid, owner_gid)
        };

        // Set ownership if specified
        if let (Some(uid), Some(gid)) = (uid, gid) {
            chown(path, Some(uid), Some(gid))
                .map_err(|e| anyhow!("Failed to set ownership: {}", e))?;
            debug!("Set ownership for {} to {}:{}", path.display(), uid, gid);
        }

        // Set permissions
        let mode = if config.mode == 0 {
            // Keep existing permissions but apply umask
            let metadata = fs::metadata(path)?;
            metadata.mode() & !config.umask
        } else {
            config.mode
        };

        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|e| anyhow!("Failed to set permissions: {}", e))?;

        debug!("Set permissions for {} to {:o}", path.display(), mode);
        Ok(())
    }

    /// Check if current user can access path
    pub fn can_access<P: AsRef<Path>>(&mut self, path: P, write: bool) -> bool {
        let path = path.as_ref();

        if !path.exists() {
            return false;
        }

        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return false,
        };

        let uid = Uid::current();
        let gid = Gid::current();

        // Check if owner
        let is_owner = uid.as_raw() == metadata.uid();
        let is_group = gid.as_raw() == metadata.gid();

        let mode = metadata.mode();

        // Check permissions
        if is_owner {
            if write {
                (mode & 0o200) != 0
            } else {
                (mode & 0o400) != 0
            }
        } else if is_group {
            if write {
                (mode & 0o020) != 0
            } else {
                (mode & 0o040) != 0
            }
        } else if write {
            (mode & 0o002) != 0
        } else {
            (mode & 0o004) != 0
        }
    }

    /// Get effective permissions for a path
    pub fn get_effective_permissions<P: AsRef<Path>>(&self, path: P) -> Result<(u32, u32, u32)> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(anyhow!("Path {} does not exist", path.display()));
        }

        let metadata = fs::metadata(path)?;
        Ok((metadata.uid(), metadata.gid(), metadata.mode()))
    }
}

impl Default for PermissionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_mount_point() {
        let temp_dir = TempDir::new().unwrap();
        let mount_path = temp_dir.path().join("test_mount");

        let mut manager = PermissionManager::new();
        let config = PermissionConfig {
            owner_uid: Some(Uid::from_raw(1000)),
            owner_gid: Some(Gid::from_raw(1000)),
            mode: 0o750,
            umask: 0o022,
            inherit: false,
        };

        // On macOS, non-root users can't change ownership, so we expect this to fail
        // This tests that the function correctly handles permission errors
        #[cfg(target_os = "macos")]
        {
            let result = manager.create_mount_point(&mount_path, Some(&config));
            assert!(result.is_err());
            // The directory should still be created
            assert!(mount_path.exists());
        }

        #[cfg(not(target_os = "macos"))]
        {
            manager
                .create_mount_point(&mount_path, Some(&config))
                .unwrap();
            assert!(mount_path.exists());

            #[cfg(unix)]
            {
                let metadata = fs::metadata(&mount_path).unwrap();
                // We can't reliably test UID/GID changes as they require root privileges
                // but we can test the mode
                assert_eq!(metadata.mode() & 0o777, 0o750);
            }
        }
    }

    #[test]
    fn test_permission_inheritance() {
        let temp_dir = TempDir::new().unwrap();

        // Create parent directory with specific permissions
        let parent_path = temp_dir.path().join("parent");
        fs::create_dir(&parent_path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&parent_path, fs::Permissions::from_mode(0o750)).unwrap();
        }

        let mount_path = parent_path.join("child");

        let mut manager = PermissionManager::new();
        let config = PermissionConfig {
            owner_uid: None,
            owner_gid: None,
            mode: 0, // Use inherited
            umask: 0o022,
            inherit: true,
        };

        manager
            .create_mount_point(&mount_path, Some(&config))
            .unwrap();

        // Child should inherit from parent
        let parent_meta = fs::metadata(&parent_path).unwrap();
        let child_meta = fs::metadata(&mount_path).unwrap();

        assert_eq!(parent_meta.uid(), child_meta.uid());
        assert_eq!(parent_meta.gid(), child_meta.gid());
    }

    #[test]
    fn test_access_check() {
        let temp_dir = TempDir::new().unwrap();
        let test_path = temp_dir.path().join("test_file");

        fs::write(&test_path, "test").unwrap();

        let mut manager = PermissionManager::new();

        // Should be able to read our own file
        assert!(manager.can_access(&test_path, false));

        // Should be able to write our own file
        assert!(manager.can_access(&test_path, true));
    }
}
