//! macOS-specific platform implementation

use super::{MountInfo, Platform, Signal};
use crate::mount::MountType;
use anyhow::{Result, anyhow};
use nix::unistd;
use std::fs;
use std::os::darwin::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info};

pub struct MacOSPlatform;

impl Platform for MacOSPlatform {
    fn ensure_dir_exists(&self, path: &Path) -> Result<()> {
        if !self.path_exists(path) {
            info!("Creating directory: {:?}", path);
            self.create_dir(path)?;
        }
        Ok(())
    }

    fn can_access_path(&self, path: &Path) -> Result<bool> {
        // Similar to Linux implementation
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                return Ok(false);
            }

            match fs::metadata(parent) {
                Ok(metadata) => {
                    let perms = metadata.permissions();
                    let mode = perms.mode();

                    let uid = unistd::getuid().is_root();
                    let gid = unistd::getgid().as_raw() == metadata.st_gid();

                    let writable = if uid {
                        mode & 0o200 != 0
                    } else if gid {
                        mode & 0o020 != 0
                    } else {
                        mode & 0o002 != 0
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
        // Fallback to environment variables
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
        info!("Setting up signal handlers for macOS");
        Ok(())
    }

    fn daemonize(&self) -> Result<()> {
        // Built-in daemonization is not supported
        // On macOS, use launchd for proper daemonization
        // For development/testing, use nohup:
        //   nohup fuji daemon start --no-automount > /tmp/fuji.log 2>&1 &
        info!(
            "Built-in daemonization not supported. See documentation for proper daemon management."
        );

        Err(anyhow!(
            "Built-in daemonization is not supported. Use nohup, launchd, or systemd instead."
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

        // Check if process is still running using ps
        let output = Command::new("ps")
            .arg("-p")
            .arg(format!("{}", pid))
            .arg("-o")
            .arg("pid=")
            .output()?;

        if output.status.success() {
            let ps_output = String::from_utf8(output.stdout)?;
            if !ps_output.trim().is_empty() {
                Ok(Some(pid))
            } else {
                // Process no longer exists
                self.remove_pid_file(pid_file)?;
                Ok(None)
            }
        } else {
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

        kill(unistd::Pid::from_raw(pid as i32), Some(nix_signal))
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
        let output = Command::new("mount").output()?;

        if output.status.success() {
            let mount_str = String::from_utf8(output.stdout)?;
            Ok(mount_str.contains(&format!(" on {}", mount_point.display())))
        } else {
            Ok(false)
        }
    }

    fn get_mount_info(&self, path: &Path) -> Result<Option<MountInfo>> {
        let output = Command::new("mount").output()?;

        if !output.status.success() {
            return Ok(None);
        }

        let mount_str = String::from_utf8(output.stdout)?;

        for line in mount_str.lines() {
            if line.contains(&format!(" on {}", path.display())) {
                // Parse mount line format: "server:/share on /mnt/fuji (nfs, options)"
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let device = parts[0].to_string();
                    let fs_type = parts
                        .get(2)
                        .and_then(|s| s.strip_prefix('('))
                        .and_then(|s| s.strip_suffix(')'))
                        .unwrap_or("unknown")
                        .split(',')
                        .next()
                        .unwrap_or("unknown")
                        .to_string();

                    return Ok(Some(MountInfo {
                        device,
                        mount_point: path.to_path_buf(),
                        fs_type,
                        options: vec![],
                    }));
                }
            }
        }

        Ok(None)
    }

    fn get_socket_path(&self, config_path: Option<&Path>) -> PathBuf {
        // If a config path is provided, try it first
        if let Some(path) = config_path {
            if self.can_access_path(path).unwrap_or(false) {
                return path.to_owned();
            }
        }

        // Try XDG_RUNTIME_DIR first
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            let path = PathBuf::from(runtime_dir).join("fuji.sock");
            if self.can_access_path(&path).unwrap_or(false) {
                return path;
            }
        }

        // Try /tmp
        let path = PathBuf::from("/tmp/fuji.sock");
        if self.can_access_path(&path).unwrap_or(false) {
            return path;
        }

        // Return default even if not accessible (will be handled by caller)
        PathBuf::from("/tmp/fuji.sock")
    }

    fn get_config_dir(&self) -> PathBuf {
        // Try Application Support first (macOS standard)
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/Library/Application Support"))
            .join("fuji")
    }

    fn get_mount_dir(&self) -> PathBuf {
        PathBuf::from("/mnt/fuji")
    }

    fn list_system_mounts(&self) -> Result<Vec<(PathBuf, crate::platform::MountInfo)>> {
        let mut mounts = Vec::new();

        // Use mount command on macOS
        let output = std::process::Command::new("mount")
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to execute mount command: {}", e))?;

        let output_str = String::from_utf8_lossy(&output.stdout);

        for line in output_str.lines() {
            // Parse mount output format: "device on mount_point (fs_type, options)"
            if let Some(start) = line.find(" on ") {
                let device_part = &line[..start];
                let rest = &line[start + 4..];

                if let Some(end) = rest.find(" (") {
                    let mount_point = PathBuf::from(rest[..end].trim());
                    let options_part = &rest[end + 2..];
                    let options_part = options_part.trim_end_matches(')');

                    // Split into fs_type and options
                    let mut parts = options_part.split(',');
                    let fs_type = parts.next().unwrap_or("unknown").to_string();
                    let options: Vec<String> = parts.map(|s| s.trim().to_string()).collect();

                    let mount_info = crate::platform::MountInfo {
                        device: device_part.to_string(),
                        mount_point: mount_point.clone(),
                        fs_type,
                        options,
                    };

                    mounts.push((mount_point, mount_info));
                }
            }
        }

        Ok(mounts)
    }
}

pub fn get_platform() -> Box<dyn Platform> {
    Box::new(MacOSPlatform)
}
