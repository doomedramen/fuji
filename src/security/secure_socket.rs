//! Secure socket operations with seccomp filtering
//!
//! This module provides secure Unix socket operations with system call
//! filtering and privilege restrictions.

// use crate::error::DaemonError; // Commented out since we don't need it for validation
use crate::security::seccomp::{SeccompProfile, SecureExecutor};
use anyhow::{anyhow, Result};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener as TokioUnixListener, UnixStream as TokioUnixStream};
use tracing::{debug, info, warn};

/// Secure Unix socket server with seccomp filtering
pub struct SecureSocketServer {
    listener: TokioUnixListener,
    seccomp_profile: Option<SeccompProfile>,
    executor: Option<SecureExecutor>,
}

impl SecureSocketServer {
    /// Create a new secure socket server
    pub async fn new<P: AsRef<Path>>(
        socket_path: P,
        seccomp_profile: Option<SeccompProfile>,
    ) -> Result<Self> {
        let path = socket_path.as_ref();

        // Remove existing socket file if it exists
        if path.exists() {
            tokio::fs::remove_file(path)
                .await
                .map_err(|e| anyhow!("Failed to remove existing socket {:?}: {}", path, e))?;
        }

        let listener = TokioUnixListener::bind(path)
            .map_err(|e| anyhow!("Failed to bind to socket {:?}: {}", path, e))?;

        info!("Secure socket server listening on {:?}", path);

        let mut server = Self {
            listener,
            seccomp_profile,
            executor: None,
        };

        // Initialize seccomp if profile is provided
        if let Some(profile) = seccomp_profile {
            let mut executor = SecureExecutor::new(profile)?;
            executor.initialize()?;
            server.executor = Some(executor);
            info!(
                "Initialized seccomp filter for socket server: {:?}",
                profile
            );
        }

        Ok(server)
    }

    /// Accept a new connection with security validation
    pub async fn accept(&mut self) -> Result<SecureSocketConnection> {
        let (stream, addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| anyhow!("Failed to accept socket connection: {}", e))?;

        debug!("Accepted connection from {:?}", addr);

        // Validate connection security
        self.validate_connection(&stream).await?;

        Ok(SecureSocketConnection {
            stream,
            executor: self.executor.clone(),
        })
    }

    /// Validate the connection for security
    async fn validate_connection(&self, stream: &TokioUnixStream) -> Result<()> {
        // Check if the socket is from a trusted source
        let peer_addr = stream
            .peer_addr()
            .map_err(|e| anyhow!("Failed to get peer address: {}", e))?;

        // For Unix sockets, we can check the path
        if let Some(path) = peer_addr.as_pathname() {
            self.validate_socket_path(path)?;
        }

        // Additional security checks can be added here
        // - Check process credentials
        // - Verify connection origin
        // - Rate limiting
        // - Connection timeout

        Ok(())
    }

    /// Validate that a socket path is safe
    fn validate_socket_path(&self, path: &Path) -> Result<()> {
        // Check for path traversal attempts
        if path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
        {
            return Err(anyhow!(
                "Socket path contains parent directory reference: {:?}",
                path
            ));
        }

        // Check for absolute paths (should be relative to /tmp or /var/run)
        if path.is_absolute() && !path.starts_with("/tmp/") && !path.starts_with("/var/run/") {
            return Err(anyhow!(
                "Socket path is not in allowed directory: {:?}",
                path
            ));
        }

        // Check path length
        if path.to_string_lossy().len() > 255 {
            return Err(anyhow!("Socket path too long: {:?}", path));
        }

        Ok(())
    }

    /// Get the local socket address
    pub fn local_addr(&self) -> Result<tokio::net::unix::SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|e| anyhow!("Failed to get local address: {}", e))
    }
}

/// Secure socket connection with seccomp protection
pub struct SecureSocketConnection {
    stream: TokioUnixStream,
    executor: Option<SecureExecutor>,
}

impl SecureSocketConnection {
    /// Send data with security validation
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.validate_data_size(data)?;

        if let Some(ref mut executor) = self.executor {
            executor.validate_operation("socket_write")?;
            executor.execute_in_sandbox(|| Ok(()))?;
        }

        self.stream
            .write_all(data)
            .await
            .map_err(|e| anyhow!("Failed to send data: {}", e))?;
        Ok(())
    }

    /// Receive data with security validation
    pub async fn receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.validate_buffer_size(buf)?;

        if let Some(ref mut executor) = self.executor {
            executor.validate_operation("socket_read")?;
            executor.execute_in_sandbox(|| Ok(()))?;
        }

        let n = self
            .stream
            .read(buf)
            .await
            .map_err(|e| anyhow!("Failed to receive data: {}", e))?;
        Ok(n)
    }

    /// Send a string message
    pub async fn send_message(&mut self, message: &str) -> Result<()> {
        let data = message.as_bytes();
        let len = data.len() as u32;

        // Send length prefix
        self.stream
            .write_u32(len)
            .await
            .map_err(|e| anyhow!("Failed to send message length: {}", e))?;

        // Send message data
        self.stream
            .write_all(data)
            .await
            .map_err(|e| anyhow!("Failed to send message data: {}", e))?;

        debug!("Sent message: {} bytes", len);
        Ok(())
    }

    /// Receive a string message
    pub async fn receive_message(&mut self) -> Result<String> {
        // Read length prefix
        let len = self
            .stream
            .read_u32()
            .await
            .map_err(|e| anyhow!("Failed to read message length: {}", e))?;

        // Validate length
        if len > 1024 * 1024 {
            // 1MB limit
            return Err(anyhow!("Message too large: {} bytes", len));
        }

        // Read message data
        let mut buf = vec![0u8; len as usize];
        self.stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| anyhow!("Failed to read message data: {}", e))?;

        let message =
            String::from_utf8(buf).map_err(|e| anyhow!("Invalid UTF-8 in message: {}", e))?;

        debug!("Received message: {} bytes", len);
        Ok(message)
    }

    /// Validate data size for sending
    fn validate_data_size(&self, data: &[u8]) -> Result<()> {
        const MAX_DATA_SIZE: usize = 10 * 1024 * 1024; // 10MB

        if data.len() > MAX_DATA_SIZE {
            return Err(anyhow!(
                "Data too large: {} bytes (max: {})",
                data.len(),
                MAX_DATA_SIZE
            ));
        }

        Ok(())
    }

    /// Validate buffer size for receiving
    fn validate_buffer_size(&self, buf: &[u8]) -> Result<()> {
        const MAX_BUFFER_SIZE: usize = 10 * 1024 * 1024; // 10MB

        if buf.len() > MAX_BUFFER_SIZE {
            return Err(anyhow!(
                "Buffer too large: {} bytes (max: {})",
                buf.len(),
                MAX_BUFFER_SIZE
            ));
        }

        Ok(())
    }

    /// Get peer address
    pub fn peer_addr(&self) -> Result<tokio::net::unix::SocketAddr> {
        self.stream
            .peer_addr()
            .map_err(|e| anyhow!("Failed to get peer address: {}", e))
    }

    /// Get local address
    pub fn local_addr(&self) -> Result<tokio::net::unix::SocketAddr> {
        self.stream
            .local_addr()
            .map_err(|e| anyhow!("Failed to get local address: {}", e))
    }

    /// Set read timeout
    pub async fn set_read_timeout(&self, _timeout: Option<std::time::Duration>) -> Result<()> {
        // Tokio UnixStream doesn't directly support timeouts
        // This would need to be implemented at the application level
        warn!("Read timeout not directly supported on async Unix sockets");
        Ok(())
    }

    /// Set write timeout
    pub async fn set_write_timeout(&self, _timeout: Option<std::time::Duration>) -> Result<()> {
        // Tokio UnixStream doesn't directly support timeouts
        // This would need to be implemented at the application level
        warn!("Write timeout not directly supported on async Unix sockets");
        Ok(())
    }

    /// Close the connection
    pub async fn close(self) -> Result<()> {
        drop(self.stream); // Close on drop
        Ok(())
    }
}

/// Factory for creating secure socket connections
pub struct SecureSocketFactory;

impl SecureSocketFactory {
    /// Create a secure connection to a Unix socket
    pub async fn connect<P: AsRef<Path>>(
        socket_path: P,
        seccomp_profile: Option<SeccompProfile>,
    ) -> Result<SecureSocketConnection> {
        let path = socket_path.as_ref();

        // Validate socket path
        Self::validate_socket_path(path)?;

        let stream = TokioUnixStream::connect(path)
            .await
            .map_err(|e| anyhow!("Failed to connect to socket {:?}: {}", path, e))?;

        let executor = if let Some(profile) = seccomp_profile {
            let mut exec = SecureExecutor::new(profile)?;
            exec.initialize()?;
            Some(exec)
        } else {
            None
        };

        debug!("Connected to secure socket: {:?}", path);

        Ok(SecureSocketConnection { stream, executor })
    }

    /// Validate a socket path for security
    fn validate_socket_path(path: &Path) -> Result<()> {
        // Check for path traversal
        if path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
        {
            return Err(anyhow!(
                "Socket path contains parent directory reference: {:?}",
                path
            ));
        }

        // Check for absolute paths
        if path.is_absolute() {
            if !path.starts_with("/tmp/")
                && !path.starts_with("/var/run/")
                && !path.starts_with("/var/tmp/")
            {
                return Err(anyhow!(
                    "Absolute socket path must be in /tmp, /var/run, or /var/tmp: {:?}",
                    path
                ));
            }
        }

        // Check path length
        if path.to_string_lossy().len() > 255 {
            return Err(anyhow!("Socket path too long: {:?}", path));
        }

        // Check for unsafe characters
        let path_str = path.to_string_lossy();
        if path_str.contains('\0') || path_str.contains('\n') || path_str.contains('\r') {
            return Err(anyhow!(
                "Socket path contains unsafe characters: {:?}",
                path
            ));
        }

        Ok(())
    }
}

/// Socket security validator
pub struct SocketSecurityValidator;

impl SocketSecurityValidator {
    /// Validate socket permissions
    pub fn validate_socket_permissions(path: &Path) -> Result<()> {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        if !path.exists() {
            return Err(anyhow!("Socket does not exist: {:?}", path));
        }

        let metadata =
            fs::metadata(path).map_err(|e| anyhow!("Failed to get socket metadata: {}", e))?;

        let permissions = metadata.permissions();
        let mode = permissions.mode();

        // Check that it's a socket
        if !metadata.file_type().is_socket() {
            return Err(anyhow!("Path is not a socket: {:?}", path));
        }

        // Check permissions (should be 600, 660, or 666)
        let user_perms = mode & 0o700;
        let group_perms = mode & 0o070;
        let other_perms = mode & 0o007;

        // Allow owner read/write
        if user_perms & 0o600 != 0o600 {
            return Err(anyhow!(
                "Socket has insufficient owner permissions: {:?}",
                path
            ));
        }

        // Group and others can have read/write, but not execute
        if (group_perms & 0o001 != 0) || (other_perms & 0o001 != 0) {
            return Err(anyhow!("Socket has execute permissions: {:?}", path));
        }

        // Warn if group or others have write permissions
        if (group_perms & 0o002 != 0) || (other_perms & 0o002 != 0) {
            warn!(
                "Socket has write permissions for group or others: {:?}",
                path
            );
        }

        Ok(())
    }

    /// Check if socket is owned by root or current user
    pub fn validate_socket_ownership(path: &Path) -> Result<()> {
        use nix::unistd::getuid;
        use std::fs;

        let metadata =
            fs::metadata(path).map_err(|e| anyhow!("Failed to get socket metadata: {}", e))?;

        let uid = metadata.uid();
        let current_uid = getuid();

        // Allow root or current user
        if uid != 0 && uid != current_uid.as_raw() {
            return Err(anyhow!(
                "Socket is not owned by root or current user (owner: {}, current: {}): {:?}",
                uid,
                current_uid,
                path
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_secure_socket_factory_validation() {
        let tmp_dir = TempDir::new().unwrap();
        let socket_path = tmp_dir.path().join("test.sock");

        // Valid path should pass
        assert!(SecureSocketFactory::validate_socket_path(&socket_path).is_ok());

        // Path with null byte should fail
        let invalid_path = Path::new("/tmp/test\0.sock");
        assert!(SecureSocketFactory::validate_socket_path(invalid_path).is_err());

        // Path with parent reference should fail
        let parent_path = Path::new("/tmp/../etc/passwd");
        assert!(SecureSocketFactory::validate_socket_path(parent_path).is_err());

        // Absolute path outside allowed directories should fail
        let bad_absolute = Path::new("/etc/passwd.sock");
        assert!(SecureSocketFactory::validate_socket_path(bad_absolute).is_err());
    }

    #[test]
    fn test_data_size_validation() {
        let connection = SecureSocketConnection {
            stream: unsafe { std::mem::zeroed() }, // Not actually used in validation
            executor: None,
        };

        // Small data should pass
        let small_data = vec![0u8; 100];
        assert!(connection.validate_data_size(&small_data).is_ok());

        // Large data should fail
        let large_data = vec![0u8; 20 * 1024 * 1024]; // 20MB
        assert!(connection.validate_data_size(&large_data).is_err());
    }

    #[test]
    fn test_buffer_size_validation() {
        let connection = SecureSocketConnection {
            stream: unsafe { std::mem::zeroed() }, // Not actually used in validation
            executor: None,
        };

        // Small buffer should pass
        let small_buf = vec![0u8; 100];
        assert!(connection.validate_buffer_size(&small_buf).is_ok());

        // Large buffer should fail
        let large_buf = vec![0u8; 20 * 1024 * 1024]; // 20MB
        assert!(connection.validate_buffer_size(&large_buf).is_err());
    }
}
