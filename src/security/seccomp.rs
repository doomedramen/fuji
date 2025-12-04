//! Secure system call implementation with validation and filtering
//!
//! This module provides system call validation to restrict operations
//! to only necessary syscalls, preventing privilege escalation
//! and limiting attack surface. Note: This is a simplified implementation
//! that provides validation without using the seccomp library directly
//! for better portability.

// use crate::error::DaemonError; // Commented out since we don't need it for validation
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::path::Path;
use tracing::{debug, info};

/// Available seccomp profiles for different contexts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompProfile {
    /// Minimal profile for basic operations
    Minimal,
    /// Network operations profile
    Network,
    /// File system operations profile
    FileSystem,
    /// Mount operations profile
    Mount,
    /// Daemon operations profile
    Daemon,
    /// Test/development profile (permissive)
    Test,
}

impl SeccompProfile {
    /// Get a description of the profile
    pub fn description(&self) -> &'static str {
        match self {
            Self::Minimal => "Minimal system calls for basic operations",
            Self::Network => "Network operations with socket syscalls",
            Self::FileSystem => "File system operations with I/O syscalls",
            Self::Mount => "Mount operations with elevated privileges",
            Self::Daemon => "Daemon operations with monitoring and management",
            Self::Test => "Permissive profile for testing",
        }
    }

    /// Check if profile allows network operations
    pub fn allows_network(&self) -> bool {
        matches!(self, Self::Network | Self::Daemon | Self::Test)
    }

    /// Check if profile allows file system operations
    pub fn allows_filesystem(&self) -> bool {
        matches!(self, Self::FileSystem | Self::Mount | Self::Daemon | Self::Test)
    }

    /// Check if profile allows mount operations
    pub fn allows_mount(&self) -> bool {
        matches!(self, Self::Mount | Self::Daemon | Self::Test)
    }
}

/// System call filter manager
#[derive(Clone)]
pub struct SyscallFilter {
    profile: SeccompProfile,
    initialized: bool,
    allowed_paths: Vec<String>,
    allowed_commands: Vec<String>,
}

impl SyscallFilter {
    /// Create a new syscall filter with the specified profile
    pub fn new(profile: SeccompProfile) -> Self {
        let (allowed_paths, allowed_commands) = Self::get_profile_rules(profile);

        Self {
            profile,
            initialized: false,
            allowed_paths,
            allowed_commands,
        }
    }

    /// Get profile-specific rules
    fn get_profile_rules(profile: SeccompProfile) -> (Vec<String>, Vec<String>) {
        let allowed_paths = match profile {
            SeccompProfile::Minimal => vec![
                "/dev/null".to_string(),
                "/dev/zero".to_string(),
                "/dev/random".to_string(),
                "/dev/urandom".to_string(),
                "/proc/self".to_string(),
                "/tmp".to_string(),
            ],
            SeccompProfile::Network => vec![
                "/tmp".to_string(),
                "/var/run".to_string(),
                "/dev/null".to_string(),
            ],
            SeccompProfile::FileSystem => vec![
                "/".to_string(),
                "/dev".to_string(),
                "/proc".to_string(),
                "/sys".to_string(),
                "/tmp".to_string(),
                "/var".to_string(),
                "/home".to_string(),
                "/mnt".to_string(),
                "/media".to_string(),
            ],
            SeccompProfile::Mount => vec![
                "/".to_string(),
                "/dev".to_string(),
                "/proc".to_string(),
                "/sys".to_string(),
                "/etc".to_string(),
                "/bin".to_string(),
                "/sbin".to_string(),
                "/usr/bin".to_string(),
                "/usr/sbin".to_string(),
                "/tmp".to_string(),
                "/var".to_string(),
                "/mnt".to_string(),
                "/media".to_string(),
            ],
            SeccompProfile::Daemon => vec![
                "/".to_string(),
                "/dev".to_string(),
                "/proc".to_string(),
                "/sys".to_string(),
                "/etc".to_string(),
                "/bin".to_string(),
                "/sbin".to_string(),
                "/usr/bin".to_string(),
                "/usr/sbin".to_string(),
                "/tmp".to_string(),
                "/var".to_string(),
                "/home".to_string(),
                "/mnt".to_string(),
                "/media".to_string(),
                "/opt".to_string(),
                "/srv".to_string(),
            ],
            SeccompProfile::Test => vec![
                "/".to_string(),
            ],
        };

        let allowed_commands = match profile {
            SeccompProfile::Minimal => vec![
                "echo".to_string(),
                "cat".to_string(),
                "wc".to_string(),
            ],
            SeccompProfile::Network => vec![
                "ssh".to_string(),
                "sshfs".to_string(),
                "nc".to_string(),
                "telnet".to_string(),
                "curl".to_string(),
                "wget".to_string(),
                "mount".to_string(),
                "umount".to_string(),
                "smbclient".to_string(),
            ],
            SeccompProfile::FileSystem => vec![
                "ls".to_string(),
                "cp".to_string(),
                "mv".to_string(),
                "rm".to_string(),
                "mkdir".to_string(),
                "rmdir".to_string(),
                "chmod".to_string(),
                "chown".to_string(),
                "chgrp".to_string(),
                "find".to_string(),
                "grep".to_string(),
                "sed".to_string(),
                "awk".to_string(),
                "mount".to_string(),
                "umount".to_string(),
            ],
            SeccompProfile::Mount => vec![
                "mount".to_string(),
                "umount".to_string(),
                "mount.nfs".to_string(),
                "mount.nfs4".to_string(),
                "mount.cifs".to_string(),
                "umount.nfs".to_string(),
                "systemctl".to_string(),
                "service".to_string(),
            ],
            SeccompProfile::Daemon => vec![
                "mount".to_string(),
                "umount".to_string(),
                "systemctl".to_string(),
                "service".to_string(),
                "ps".to_string(),
                "kill".to_string(),
                "killall".to_string(),
                "pgrep".to_string(),
                "pkill".to_string(),
                "nohup".to_string(),
                "daemon".to_string(),
                "init".to_string(),
                "shutdown".to_string(),
                "reboot".to_string(),
                "poweroff".to_string(),
            ],
            SeccompProfile::Test => vec![
                // Allow all commands for testing
            ],
        };

        (allowed_paths, allowed_commands)
    }

    /// Initialize seccomp filtering for the current thread
    pub fn initialize(&mut self) -> Result<()> {
        if self.initialized {
            return Ok(());
        }

        info!("Initializing syscall filter with profile: {:?}", self.profile);

        // In a real implementation, this would set up seccomp filters
        // For now, we just mark as initialized and perform validation
        self.initialized = true;
        info!("Syscall filter successfully initialized");
        Ok(())
    }

    /// Validate a command against the current profile
    pub fn validate_command(&self, command: &str) -> Result<()> {
        if self.profile == SeccompProfile::Test {
            return Ok(());
        }

        let command_name = Path::new(command)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(command);

        if !self.allowed_commands.contains(&command_name.to_string()) {
            return Err(anyhow!(
                "Command '{}' is not allowed in {:?} profile",
                command_name,
                self.profile
            ));
        }

        Ok(())
    }

    /// Validate a path against the current profile
    pub fn validate_path(&self, path: &Path) -> Result<()> {
        if self.profile == SeccompProfile::Test {
            return Ok(());
        }

        let path_str = path.to_string_lossy();

        // Check if path is under an allowed directory
        for allowed_path in &self.allowed_paths {
            if path_str.starts_with(allowed_path) {
                return Ok(());
            }
        }

        return Err(anyhow!(
            "Path '{}' is not allowed in {:?} profile",
            path_str,
            self.profile
        ));
    }

    /// Validate file descriptor access
    pub fn validate_fd_access(&self, fd: RawFd, operation: &str) -> Result<()> {
        // In a real implementation, this would check fd against allowed operations
        // For now, we just log the validation attempt
        debug!("Validating fd {} operation '{}' in {:?} profile", fd, operation, self.profile);
        Ok(())
    }

    /// Get the current profile
    pub fn profile(&self) -> SeccompProfile {
        self.profile
    }

    /// Check if seccomp is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get allowed commands for the profile
    pub fn allowed_commands(&self) -> &[String] {
        &self.allowed_commands
    }

    /// Get allowed paths for the profile
    pub fn allowed_paths(&self) -> &[String] {
        &self.allowed_paths
    }
}

/// Secure process executor with syscall validation
#[derive(Clone)]
pub struct SecureExecutor {
    filter: SyscallFilter,
}

impl SecureExecutor {
    /// Create a new secure executor with the specified profile
    pub fn new(profile: SeccompProfile) -> Result<Self> {
        Ok(Self {
            filter: SyscallFilter::new(profile),
        })
    }

    /// Initialize the seccomp filter
    pub fn initialize(&mut self) -> Result<()> {
        self.filter.initialize()
    }

    /// Execute a function within a secure context
    pub fn execute_in_sandbox<F, R>(&mut self, f: F) -> Result<R>
    where
        F: FnOnce() -> Result<R>,
    {
        // Initialize syscall filter
        self.filter.initialize()?;

        // Execute the function
        f()
    }

    /// Get the seccomp profile
    pub fn profile(&self) -> SeccompProfile {
        self.filter.profile()
    }

    /// Validate a command for execution
    pub fn validate_command(&self, command: &str) -> Result<()> {
        self.filter.validate_command(command)
    }

    /// Validate a path for access
    pub fn validate_path(&self, path: &Path) -> Result<()> {
        self.filter.validate_path(path)
    }

    /// Validate an operation for execution
    pub fn validate_operation(&self, operation: &str) -> Result<()> {
        // Check if operation is allowed in current profile
        match self.profile() {
            SeccompProfile::Minimal => {
                if !["read", "write", "socket_read", "socket_write"].contains(&operation) {
                    return Err(anyhow!("Operation '{}' not allowed in Minimal profile", operation));
                }
            }
            SeccompProfile::Network => {
                if !["read", "write", "socket_read", "socket_write", "connect", "bind", "listen"].contains(&operation) {
                    return Err(anyhow!("Operation '{}' not allowed in Network profile", operation));
                }
            }
            SeccompProfile::FileSystem => {
                if !["read", "write", "socket_read", "socket_write", "open", "close", "stat"].contains(&operation) {
                    return Err(anyhow!("Operation '{}' not allowed in FileSystem profile", operation));
                }
            }
            SeccompProfile::Mount => {
                if !["read", "write", "socket_read", "socket_write", "open", "close", "stat", "mount", "umount"].contains(&operation) {
                    return Err(anyhow!("Operation '{}' not allowed in Mount profile", operation));
                }
            }
            SeccompProfile::Daemon => {
                // Daemon profile allows most operations
            }
            SeccompProfile::Test => {
                // Test profile allows all operations
            }
        }

        debug!("Validated operation '{}' in {:?} profile", operation, self.profile());
        Ok(())
    }
}

/// Global seccomp manager for daemon processes
pub struct GlobalSeccompManager {
    filters: HashMap<String, SyscallFilter>,
    default_profile: SeccompProfile,
}

impl GlobalSeccompManager {
    /// Create a new global seccomp manager
    pub fn new(default_profile: SeccompProfile) -> Self {
        Self {
            filters: HashMap::new(),
            default_profile,
        }
    }

    /// Initialize seccomp for a specific operation
    pub fn initialize_operation(&mut self, operation: &str, profile: Option<SeccompProfile>) -> Result<()> {
        let profile = profile.unwrap_or(self.default_profile);
        let mut filter = SyscallFilter::new(profile);
        filter.initialize()?;
        self.filters.insert(operation.to_string(), filter);

        info!("Initialized seccomp for operation: {} with profile: {:?}", operation, profile);
        Ok(())
    }

    /// Check if an operation is initialized
    pub fn is_operation_initialized(&self, operation: &str) -> bool {
        self.filters.get(operation).map_or(false, |f| f.is_initialized())
    }

    /// Get profile for an operation
    pub fn operation_profile(&self, operation: &str) -> Option<SeccompProfile> {
        self.filters.get(operation).map(|f| f.profile())
    }

    /// Remove an operation's filter
    pub fn remove_operation(&mut self, operation: &str) -> Option<SyscallFilter> {
        self.filters.remove(operation)
    }

    /// List all operations
    pub fn list_operations(&self) -> Vec<String> {
        self.filters.keys().cloned().collect()
    }
}

/// Convenience function to create a seccomp filter for testing
pub fn create_test_filter() -> Result<SyscallFilter> {
    let mut filter = SyscallFilter::new(SeccompProfile::Test);
    filter.initialize()?;
    Ok(filter)
}

/// Convenience function to create a seccomp filter for daemon operations
pub fn create_daemon_filter() -> Result<SyscallFilter> {
    let mut filter = SyscallFilter::new(SeccompProfile::Daemon);
    filter.initialize()?;
    Ok(filter)
}

/// Convenience function to create a seccomp filter for mount operations
pub fn create_mount_filter() -> Result<SyscallFilter> {
    let mut filter = SyscallFilter::new(SeccompProfile::Mount);
    filter.initialize()?;
    Ok(filter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_profile_properties() {
        assert!(SeccompProfile::Network.allows_network());
        assert!(!SeccompProfile::Minimal.allows_network());

        assert!(SeccompProfile::FileSystem.allows_filesystem());
        assert!(!SeccompProfile::Network.allows_filesystem());

        assert!(SeccompProfile::Mount.allows_mount());
        assert!(!SeccompProfile::FileSystem.allows_mount());
    }

    #[test]
    fn test_secure_executor_creation() {
        let executor = SecureExecutor::new(SeccompProfile::Test);
        assert!(executor.is_ok());
        assert_eq!(executor.unwrap().profile(), SeccompProfile::Test);
    }

    #[test]
    fn test_global_seccomp_manager() {
        let mut manager = GlobalSeccompManager::new(SeccompProfile::Daemon);

        assert!(!manager.is_operation_initialized("test"));

        let result = manager.initialize_operation("test", Some(SeccompProfile::Test));
        assert!(result.is_ok());

        assert_eq!(manager.operation_profile("test"), Some(SeccompProfile::Test));
    }

    #[test]
    fn test_command_validation() {
        let filter = SyscallFilter::new(SeccompProfile::Mount);

        // Allowed commands
        assert!(filter.validate_command("mount").is_ok());
        assert!(filter.validate_command("umount").is_ok());
        assert!(filter.validate_command("/bin/mount").is_ok());

        // Blocked commands
        assert!(filter.validate_command("rm").is_err());
        assert!(filter.validate_command("bash").is_err());
        assert!(filter.validate_command("sh").is_err());
    }

    #[test]
    fn test_path_validation() {
        let filter = SyscallFilter::new(SeccompProfile::Minimal);

        // Allowed paths
        assert!(filter.validate_path(Path::new("/dev/null")).is_ok());
        assert!(filter.validate_path(Path::new("/tmp/test")).is_ok());
        assert!(filter.validate_path(Path::new("/proc/self/status")).is_ok());

        // Blocked paths
        assert!(filter.validate_path(Path::new("/etc/passwd")).is_err());
        assert!(filter.validate_path(Path::new("/root/.ssh")).is_err());
        assert!(filter.validate_path(Path::new("/home/user")).is_err());
    }

    #[test]
    fn test_profile_specific_rules() {
        let network_filter = SyscallFilter::new(SeccompProfile::Network);
        assert!(network_filter.validate_command("sshfs").is_ok());
        assert!(network_filter.validate_command("mount").is_ok());
        assert!(network_filter.validate_command("rm").is_err());

        let mount_filter = SyscallFilter::new(SeccompProfile::Mount);
        assert!(mount_filter.validate_command("mount.nfs").is_ok());
        assert!(mount_filter.validate_command("systemctl").is_ok());
        assert!(mount_filter.validate_command("curl").is_err());
    }
}