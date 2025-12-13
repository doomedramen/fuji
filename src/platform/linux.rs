//! Linux-specific platform implementation

use super::{MountInfo, Platform, Signal};
use crate::mount::MountType;
use anyhow::{Result, anyhow};
use nix::unistd::{self, Pid};
use std::fs;
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info};

pub struct LinuxPlatform;

impl Platform for LinuxPlatform {
    fn ensure_dir_exists(&self, path: &Path) -> Result<()> {
        if !self.path_exists(path) {
            info!("Creating directory: {:?}", path);
            self.create_dir(path)?;
        }
        Ok(())
    }

    fn can_access_path(&self, path: &Path) -> Result<bool> {
        // If the path exists, check if we can access it directly
        if path.exists() {
            match fs::metadata(path) {
                Ok(metadata) => {
                    let mode = metadata.permissions().mode();
                    let current_uid = unistd::getuid().as_raw();
                    let current_gid = unistd::getgid().as_raw();

                    // Check if we have read permission based on ownership
                    let is_owner = current_uid == metadata.st_uid();
                    let is_group = current_gid == metadata.st_gid();
                    let is_root = current_uid == 0;

                    let readable = is_root
                        || (is_owner && (mode & 0o400 != 0))
                        || (is_group && (mode & 0o040 != 0))
                        || (mode & 0o004 != 0);

                    return Ok(readable);
                }
                Err(_) => return Ok(false),
            }
        }

        // Check if parent directory exists and is writable (for creating the path)
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                return Ok(false);
            }

            // Check write permission on parent
            match fs::metadata(parent) {
                Ok(metadata) => {
                    let mode = metadata.permissions().mode();
                    let current_uid = unistd::getuid().as_raw();
                    let current_gid = unistd::getgid().as_raw();

                    // Check if we have write permission based on ownership
                    let is_owner = current_uid == metadata.st_uid();
                    let is_group = current_gid == metadata.st_gid();
                    let is_root = current_uid == 0;

                    let writable = is_root
                        || (is_owner && (mode & 0o200 != 0))
                        || (is_group && (mode & 0o020 != 0))
                        || (mode & 0o002 != 0);

                    Ok(writable)
                }
                Err(_) => Ok(false),
            }
        } else {
            Ok(false)
        }
    }

    fn create_dir(&self, path: &Path) -> Result<()> {
        // Create with mode 755 (rwxr-xr-x)
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
        Ok(())
    }

    fn remove_dir(&self, path: &Path) -> Result<()> {
        if self.path_exists(path) {
            fs::remove_dir_all(path)?;
        }
        Ok(())
    }

    fn path_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn get_current_user(&self) -> Result<String> {
        // Try USER env var first, then LOGNAME, then USERNAME
        std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .or_else(|_| std::env::var("USERNAME"))
            .or_else(|_| {
                // Fallback: use whoami crate
                Ok(whoami::username())
            })
            .map_err(|_: std::env::VarError| anyhow!("Could not determine username"))
    }

    fn get_current_pid(&self) -> u32 {
        unistd::getpid().as_raw() as u32
    }

    fn is_root(&self) -> bool {
        unistd::getuid().is_root()
    }

    fn setup_signal_handlers(&self) -> Result<()> {
        // This will be implemented with tokio signal handling
        info!("Setting up signal handlers for Linux");
        Ok(())
    }

    fn daemonize(&self) -> Result<()> {
        // Built-in daemonization is not supported
        // On Linux, use systemd for proper daemonization
        // For development/testing, use nohup:
        //   nohup fuji daemon start --no-automount > /tmp/fuji.log 2>&1 &
        info!(
            "Built-in daemonization not supported. See documentation for proper daemon management."
        );

        Err(anyhow!(
            "Built-in daemonization is not supported. Use nohup, systemd, or other service manager instead."
        ))
    }

    fn write_pid_file(&self, pid_file: &Path) -> Result<()> {
        if let Some(parent) = pid_file.parent() {
            self.ensure_dir_exists(parent)?;
        }

        let pid = self.get_current_pid();
        fs::write(pid_file, format!("{}", pid))?;
        debug!("Wrote PID {} to {:?}", pid, pid_file);
        Ok(())
    }

    fn remove_pid_file(&self, pid_file: &Path) -> Result<()> {
        if self.path_exists(pid_file) {
            fs::remove_file(pid_file)?;
        }
        Ok(())
    }

    fn check_pid_file(&self, pid_file: &Path) -> Result<Option<u32>> {
        if !self.path_exists(pid_file) {
            return Ok(None);
        }

        let pid_str = fs::read_to_string(pid_file)?;
        let pid: u32 = pid_str
            .trim()
            .parse()
            .map_err(|_| anyhow!("Invalid PID in file"))?;

        // Check if process is still running
        let path = PathBuf::from(format!("/proc/{}", pid));
        if self.path_exists(&path) {
            Ok(Some(pid))
        } else {
            // Process no longer exists, remove stale PID file
            self.remove_pid_file(pid_file)?;
            Ok(None)
        }
    }

    fn send_signal(&self, pid: u32, signal: Signal) -> Result<()> {
        use nix::sys::signal::{Signal as NixSignal, kill};

        let nix_signal = match signal {
            Signal::Terminate => NixSignal::SIGTERM,
            Signal::Interrupt => NixSignal::SIGINT,
            Signal::Hangup => NixSignal::SIGHUP,
            Signal::Reload => NixSignal::SIGUSR1,
        };

        kill(Pid::from_raw(pid as i32), Some(nix_signal))
            .map_err(|e| anyhow!("Failed to send signal to process {}: {}", pid, e))?;

        Ok(())
    }

    fn get_mount_command(&self, mount_type: &MountType) -> Result<Vec<String>> {
        match mount_type {
            MountType::Nfs {
                host,
                share,
                options,
            } => {
                let mut cmd = vec!["mount".to_string(), "-t".to_string(), "nfs".to_string()];

                if !options.is_empty() {
                    cmd.push("-o".to_string());
                    cmd.push(options.join(","));
                }

                cmd.push(format!("{}:{}", host, share));
                Ok(cmd)
            }
            MountType::Smb {
                ..
            } => Err(anyhow!("SMB/CIFS not yet implemented")),
            MountType::Sshfs {
                ..
            } => Err(anyhow!("SSHFS should use sshfs command, not mount")),
        }
    }

    fn get_unmount_command(&self) -> Vec<String> {
        vec!["umount".to_string()]
    }

    fn is_mounted(&self, mount_point: &Path) -> Result<bool> {
        let output = Command::new("findmnt")
            .arg("-n")
            .arg("-o")
            .arg("TARGET")
            .arg("--target")
            .arg(mount_point)
            .output()?;

        Ok(output.status.success() && !output.stdout.is_empty())
    }

    fn get_mount_info(&self, path: &Path) -> Result<Option<MountInfo>> {
        let output = Command::new("findmnt")
            .arg("-n")
            .arg("-o")
            .arg("SOURCE,TARGET,FSTYPE,OPTIONS")
            .arg("--target")
            .arg(path)
            .output()?;

        if !output.status.success() {
            return Ok(None);
        }

        let output_str = String::from_utf8(output.stdout)?;
        let parts: Vec<&str> = output_str.split_whitespace().collect();

        if parts.len() >= 4 {
            Ok(Some(MountInfo {
                device: parts[0].to_string(),
                mount_point: PathBuf::from(parts[1]),
                fs_type: parts[2].to_string(),
                options: parts[3].split(',').map(|s| s.to_string()).collect(),
            }))
        } else {
            Ok(None)
        }
    }

    fn get_socket_path(&self, config_path: Option<&Path>) -> PathBuf {
        // If a config path is provided, try it first
        if let Some(path) = config_path {
            if self.can_access_path(path).unwrap_or(false) {
                return path.to_owned();
            }
        }

        // Check if running as root for system-wide socket
        if self.is_root() {
            // System daemon: use /run/fuji/fuji.sock
            // Ensure directory exists with proper permissions
            let run_dir = PathBuf::from("/run/fuji");
            if let Err(e) = self.ensure_dir_exists(&run_dir) {
                debug!(
                    "Failed to create /run/fuji: {}, falling back to /tmp/fuji",
                    e
                );
                PathBuf::from("/tmp/fuji/fuji.sock")
            } else {
                // Set proper permissions (root only)
                if let Err(e) =
                    std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o755))
                {
                    debug!("Failed to set permissions on /run/fuji: {}", e);
                }
                run_dir.join("fuji.sock")
            }
        } else {
            // User daemon: use /run/user/<uid>/fuji/fuji.sock
            if let Some(run_user) = std::env::var_os("XDG_RUNTIME_DIR") {
                let user_socket = PathBuf::from(run_user).join("fuji/fuji.sock");
                if let Some(parent) = user_socket.parent() {
                    let _ = self.ensure_dir_exists(parent);
                }
                user_socket
            } else {
                // Fallback to temp directory
                PathBuf::from("/tmp/fuji/fuji.sock")
            }
        }
    }

    fn get_config_dir(&self) -> PathBuf {
        // Try user config first
        let user_config = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("fuji");

        if user_config.exists()
            || self
                .can_access_path(user_config.parent().unwrap())
                .unwrap_or(false)
        {
            return user_config;
        }

        // Try system config
        let system_config = PathBuf::from("/etc/fuji");
        if system_config.exists() || self.can_access_path(&system_config).unwrap_or(false) {
            return system_config;
        }

        // Fallback to temp
        PathBuf::from("/tmp/fuji")
    }

    fn get_mount_dir(&self) -> PathBuf {
        // Primary mount directory
        let mount_dir = PathBuf::from("/mnt/fuji");

        // Create if doesn't exist
        if let Err(e) = self.ensure_dir_exists(&mount_dir) {
            debug!("Failed to create /mnt/fuji: {}", e);
            // Fallback to user mount directory if not root
            if !self.is_root() {
                let user_mount = std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("/tmp"))
                    .join("fuji-mounts");
                let _ = self.ensure_dir_exists(&user_mount);
                return user_mount;
            }
        }

        mount_dir
    }

    fn list_system_mounts(&self) -> Result<Vec<(PathBuf, crate::platform::MountInfo)>> {
        let mut mounts = Vec::new();

        // Read /proc/mounts
        let mounts_content = std::fs::read_to_string("/proc/mounts")
            .map_err(|e| anyhow::anyhow!("Failed to read /proc/mounts: {}", e))?;

        for line in mounts_content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let device = parts[0].to_string();
                let mount_point = PathBuf::from(parts[1]);
                let fs_type = parts[2].to_string();
                let options_str = parts[3];

                // Parse options
                let options = options_str.split(',').map(|s| s.to_string()).collect();

                let mount_info = crate::platform::MountInfo {
                    device,
                    mount_point: mount_point.clone(),
                    fs_type,
                    options,
                };

                mounts.push((mount_point, mount_info));
            }
        }

        Ok(mounts)
    }
}

pub fn get_platform() -> Box<dyn Platform> {
    Box::new(LinuxPlatform)
}
