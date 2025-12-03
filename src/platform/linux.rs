//! Linux-specific platform implementation

use super::{Platform, MountInfo, Signal};
use crate::mount::MountType;
use anyhow::{anyhow, Result};
use nix::unistd;
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
        // Check if parent directory exists and is writable
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                return Ok(false);
            }

            // Check write permission
            match fs::metadata(parent) {
                Ok(metadata) => {
                    let perms = metadata.permissions();
                    let mode = perms.mode();

                    // Check if we have write permission
                    let uid = unistd::getuid().is_root();
                    let gid = unistd::getgid().as_raw() == metadata.st_gid();

                    let writable = if uid {
                        mode & 0o200 != 0  // Owner write
                    } else if gid {
                        mode & 0o020 != 0  // Group write
                    } else {
                        mode & 0o002 != 0  // Other write
                    };

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
        // Try USER env var first, then LOGNAME
        std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .or_else(|_| std::env::var("USERNAME"))
            .map_err(|_| anyhow!("Could not determine username"))
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
        use nix::unistd::{fork, setsid, ForkResult};

        unsafe {
            match fork() {
                Ok(ForkResult::Parent { child: _ }) => {
                    // Parent process exits
                    std::process::exit(0);
                }
                Ok(ForkResult::Child) => {
                    // Child process continues
                    setsid()?;

                    // Second fork to ensure we can't acquire a controlling terminal
                    match fork() {
                        Ok(ForkResult::Parent { child: _ }) => {
                            std::process::exit(0);
                        }
                        Ok(ForkResult::Child) => {
                            // We're now daemonized
                            info!("Successfully daemonized");
                            Ok(())
                        }
                        Err(e) => Err(anyhow!("Second fork failed: {}", e)),
                    }
                }
                Err(e) => Err(anyhow!("First fork failed: {}", e)),
            }
        }
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
        let pid: u32 = pid_str.trim().parse()
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
        use nix::sys::signal::{kill, Signal as NixSignal};

        let nix_signal = match signal {
            Signal::Terminate => NixSignal::SIGTERM,
            Signal::Interrupt => NixSignal::SIGINT,
            Signal::Hangup => NixSignal::SIGHUP,
            Signal::Reload => NixSignal::SIGUSR1,
        };

        kill(unistd::Pid::from_raw(pid as i32), Some(nix_signal))
            .map_err(|e| anyhow!("Failed to send signal to process {}: {}", pid, e))?;

        Ok(())
    }

    fn get_mount_command(&self, mount_type: &MountType) -> Result<Vec<String>> {
        match mount_type {
            MountType::NFS { host, share, options } => {
                let mut cmd = vec![
                    "mount".to_string(),
                    "-t".to_string(),
                    "nfs".to_string(),
                ];

                if !options.is_empty() {
                    cmd.push("-o".to_string());
                    cmd.push(options.join(","));
                }

                cmd.push(format!("{}:{}", host, share));
                Ok(cmd)
            }
            MountType::SMB { .. } => {
                Err(anyhow!("SMB/CIFS not yet implemented"))
            }
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
        let parts: Vec<&str> = output_str.trim().split_whitespace().collect();

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

        // Try primary location first
        let primary = PathBuf::from("/run/fuji/fuji.sock");
        if self.can_access_path(&primary).unwrap_or(false) {
            return primary;
        }

        // Fallback to temp
        PathBuf::from("/tmp/fuji/fuji.sock")
    }

    fn get_config_dir(&self) -> PathBuf {
        // Try user config first
        let user_config = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("fuji");

        if user_config.exists() || self.can_access_path(&user_config.parent().unwrap()).unwrap_or(false) {
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
        PathBuf::from("/mnt/fuji")
    }
}

pub fn get_platform() -> Box<dyn Platform> {
    Box::new(LinuxPlatform)
}

