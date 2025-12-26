// Allow dead code - socket security utilities
#![allow(dead_code)]

//! Unix socket security manager
//!
//! Manages Unix domain socket creation with proper permissions and ownership.

use anyhow::{Result, anyhow};
use libc::{chmod, chown, gid_t, uid_t};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tokio::net::UnixListener;
use tracing::{debug, error, info};

/// Socket security manager for Unix domain sockets
pub struct SocketManager {
    socket_path: PathBuf,
    owner_uid: Option<uid_t>,
    owner_gid: Option<gid_t>,
    permissions: u32,
}

#[allow(dead_code)]
impl SocketManager {
    /// Create a new socket manager
    #[must_use]
    pub const fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            owner_uid: None,
            owner_gid: None,
            permissions: 0o600, // Only owner can read/write
        }
    }

    /// Set socket owner
    #[must_use]
    pub const fn with_owner(mut self, uid: uid_t, gid: gid_t) -> Self {
        self.owner_uid = Some(uid);
        self.owner_gid = Some(gid);
        self
    }

    /// Set socket permissions (default: 0o600)
    #[must_use]
    pub const fn with_permissions(mut self, permissions: u32) -> Self {
        self.permissions = permissions;
        self
    }

    /// Create Unix socket with proper permissions
    pub async fn create_socket(&self) -> Result<UnixListener> {
        // Remove existing socket if it exists
        if self.socket_path.exists() {
            fs::remove_file(&self.socket_path)?;
            info!("Removed existing socket file: {:?}", self.socket_path);
        }

        // Ensure parent directory exists
        if let Some(parent) = self.socket_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| anyhow!("Failed to create socket directory: {e}"))?;
        }

        // Create the socket
        let listener = UnixListener::bind(&self.socket_path)
            .map_err(|e| anyhow!("Failed to bind socket: {e}"))?;

        // Set permissions
        self.set_socket_permissions()?;

        info!(
            "Created socket at {:?} with permissions {:o}",
            self.socket_path, self.permissions
        );

        Ok(listener)
    }

    /// Set socket file permissions and ownership
    fn set_socket_permissions(&self) -> Result<()> {
        // Convert path to C string
        let path_cstr = std::ffi::CString::new(self.socket_path.to_string_lossy().as_bytes())
            .map_err(|e| anyhow!("Failed to create path CString: {e}"))?;

        // Set ownership if specified
        if let (Some(uid), Some(gid)) = (self.owner_uid, self.owner_gid) {
            unsafe {
                if chown(path_cstr.as_ptr(), uid, gid) != 0 {
                    let error = std::io::Error::last_os_error();
                    error!("Failed to set socket ownership: {}", error);
                    return Err(anyhow!("Failed to set socket ownership: {error}"));
                }
            }
            debug!("Set socket ownership to uid:{} gid:{}", uid, gid);
        }

        // Set permissions
        unsafe {
            if chmod(path_cstr.as_ptr(), self.permissions as libc::mode_t) != 0 {
                let error = std::io::Error::last_os_error();
                error!("Failed to set socket permissions: {}", error);
                return Err(anyhow!("Failed to set socket permissions: {error}"));
            }
        }

        debug!("Set socket permissions to {:o}", self.permissions);
        Ok(())
    }

    /// Check if socket has correct permissions
    pub fn verify_permissions(&self) -> Result<bool> {
        if !self.socket_path.exists() {
            return Ok(false);
        }

        let metadata = fs::metadata(&self.socket_path)?;
        let mode = metadata.permissions().mode();

        // Check file permissions
        if (mode & 0o777) != self.permissions {
            debug!(
                "Socket permissions mismatch: expected {:o}, found {:o}",
                self.permissions,
                mode & 0o777
            );
            return Ok(false);
        }

        // Check ownership if specified
        if let (Some(uid), Some(gid)) = (self.owner_uid, self.owner_gid) {
            use std::os::unix::fs::MetadataExt;
            let file_uid = metadata.uid();
            let file_gid = metadata.gid();

            if file_uid != uid || file_gid != gid {
                debug!(
                    "Socket ownership mismatch: expected uid:{} gid:{}, found uid:{} gid:{}",
                    uid, gid, file_uid, file_gid
                );
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Get socket path
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Clean up socket file
    pub fn cleanup(&self) -> Result<()> {
        if self.socket_path.exists() {
            fs::remove_file(&self.socket_path)?;
            info!("Removed socket file: {:?}", self.socket_path);
        }
        Ok(())
    }
}

impl Drop for SocketManager {
    fn drop(&mut self) {
        // Try to clean up on drop
        if let Err(e) = self.cleanup() {
            error!("Failed to cleanup socket: {}", e);
        }
    }
}

/// Default socket manager with secure settings
pub fn create_secure_socket(socket_path: PathBuf) -> Result<SocketManager> {
    let manager = SocketManager::new(socket_path);

    // Try to get current user info for ownership
    #[cfg(unix)]
    {
        use nix::unistd::{getgid, getuid};
        Ok(manager.with_owner(getuid().as_raw(), getgid().as_raw()))
    }

    #[cfg(not(unix))]
    {
        Ok(manager)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_socket_creation() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let manager = SocketManager::new(socket_path.clone());
        let listener = manager.create_socket().await.unwrap();

        // Verify socket exists
        assert!(socket_path.exists());

        // Verify permissions
        assert!(manager.verify_permissions().unwrap());

        drop(listener);

        // Clean up
        manager.cleanup().unwrap();
        assert!(!socket_path.exists());
    }

    #[tokio::test]
    async fn test_socket_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let manager = SocketManager::new(socket_path.clone()).with_permissions(0o640); // Owner rw, group r

        let listener = manager.create_socket().await.unwrap();

        // Check actual file permissions
        let metadata = fs::metadata(&socket_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;

        assert_eq!(mode, 0o640);

        drop(listener);
    }

    #[test]
    fn test_permission_verification() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        // Create a regular file with wrong permissions
        fs::write(&socket_path, "test").unwrap();

        let manager = SocketManager::new(socket_path.clone()).with_permissions(0o600);

        // Should fail because permissions don't match
        assert!(!manager.verify_permissions().unwrap());

        // Clean up
        fs::remove_file(&socket_path).unwrap();
    }
}
