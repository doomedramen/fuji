// Allow dead code - platform utilities for future use
#![allow(dead_code)]

//! Platform abstraction layer
//!
//! This module provides a platform-independent interface for OS-specific operations.
//! It supports Linux/BSD and macOS, with the ability to add more platforms later.

use crate::mount::MountType;
use anyhow::Result;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
use linux as platform_impl;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as platform_impl;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod fallback;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use fallback as platform_impl;

/// Platform-specific operations
/// This trait is object-safe and can be used as Box<dyn Platform>
pub trait Platform: Send + Sync {
    /// Ensure a directory exists with proper permissions
    fn ensure_dir_exists(&self, path: &Path) -> Result<()>;

    /// Check if we have permission to use a path
    fn can_access_path(&self, path: &Path) -> Result<bool>;

    /// Create a directory with proper permissions
    fn create_dir(&self, path: &Path) -> Result<()>;

    /// Remove a directory if it exists
    fn remove_dir(&self, path: &Path) -> Result<()>;

    /// Check if a path exists
    fn path_exists(&self, path: &Path) -> bool;

    /// Get the current user's username
    fn get_current_user(&self) -> Result<String>;

    /// Get the current process ID
    fn get_current_pid(&self) -> u32;

    /// Check if running as root/administrator
    fn is_root(&self) -> bool;

    /// Set up signal handlers for graceful shutdown
    fn setup_signal_handlers(&self) -> Result<()>;

    /// Daemonize the process (detach from terminal)
    fn daemonize(&self) -> Result<()>;

    /// Write a PID file
    fn write_pid_file(&self, pid_file: &Path) -> Result<()>;

    /// Remove a PID file
    fn remove_pid_file(&self, pid_file: &Path) -> Result<()>;

    /// Check if a PID file exists and the process is running
    fn check_pid_file(&self, pid_file: &Path) -> Result<Option<u32>>;

    /// Send a signal to a process
    fn send_signal(&self, pid: u32, signal: Signal) -> Result<()>;

    /// Get platform-specific mount command for a mount type
    fn get_mount_command(&self, mount_type: &MountType) -> Result<Vec<String>>;

    /// Get platform-specific unmount command
    fn get_unmount_command(&self) -> Vec<String>;

    /// Check if a mount point is actually mounted
    fn is_mounted(&self, mount_point: &Path) -> Result<bool>;

    /// Get mount information for a path
    fn get_mount_info(&self, path: &Path) -> Result<Option<MountInfo>>;

    /// Get the socket path for the daemon (with fallback logic)
    /// If config_path is provided, try that first, then fall back to defaults
    fn get_socket_path(&self, config_path: Option<&Path>) -> PathBuf;

    /// Get the configuration directory path (with fallback logic)
    fn get_config_dir(&self) -> PathBuf;

    /// Get the mount directory path
    fn get_mount_dir(&self) -> PathBuf;

    /// List all system mounts
    fn list_system_mounts(&self) -> Result<Vec<(PathBuf, MountInfo)>>;
}

/// Mount information from the system
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MountInfo {
    /// The device being mounted
    pub device: String,
    /// The mount point
    pub mount_point: PathBuf,
    /// The filesystem type
    pub fs_type: String,
    /// Mount options
    pub options: Vec<String>,
}

/// Signal types
#[derive(Debug, Clone, Copy)]
pub enum Signal {
    Terminate,
    Interrupt,
    Hangup,
    Reload,
}

/// Get the platform implementation
pub fn get_platform() -> Box<dyn Platform> {
    platform_impl::get_platform()
}
