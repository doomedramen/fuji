//! Fallback platform implementation for other Unix-like systems

use super::{MountInfo, Platform, Signal};
use crate::mount::MountType;
use anyhow::{Result, anyhow};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, error, info, warn};

pub struct FallbackPlatform;

impl Platform for FallbackPlatform {
    fn ensure_dir_exists(&self, path: &Path) -> Result<()> {
        if !self.path_exists(path) {
            info!("Creating directory: {:?}", path);
            self.create_dir(path)?;
        }
        Ok(())
    }

    fn can_access_path(&self, path: &Path) -> Result<bool> {
        if let Some(parent) = path.parent() {
            match fs::metadata(parent) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        } else {
            Ok(false)
        }
    }

    fn create_dir(&self, path: &Path) -> Result<()> {
        fs::create_dir_all(path)?;
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
        std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .ok_or_else(|| anyhow!("Could not determine username"))
    }

    fn get_current_pid(&self) -> u32 {
        unistd::getpid().as_raw()
    }

    fn is_root(&self) -> bool {
        unistd::getuid().is_root()
    }

    fn setup_signal_handlers(&self) -> Result<()> {
        info!("Setting up signal handlers for generic Unix");
        Ok(())
    }

    fn daemonize(&self) -> Result<()> {
        // Built-in daemonization is not supported
        // Use your platform's service manager (systemd, launchd, etc.)
        // For development/testing, use nohup:
        //   nohup fuji daemon start --no-automount > /tmp/fuji.log 2>&1 &
        warn!(
            "Built-in daemonization not supported. See documentation for proper daemon management."
        );

        Err(anyhow!(
            "Built-in daemonization is not supported. Use nohup or your platform's service manager instead."
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

        // Use kill -0 to check if process exists
        use nix::sys::signal::kill;
        match kill(unistd::Pid::from_raw(pid as i32), None) {
            Ok(_) => Ok(Some(pid)),
            Err(_) => {
                self.remove_pid_file(pid_file)?;
                Ok(None)
            }
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
            MountType::NFS {
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
            MountType::SMB {
                ..
            } => Err(anyhow!("SMB/CIFS not yet implemented")),
        }
    }

    fn get_unmount_command(&self) -> Vec<String> {
        vec!["umount".to_string()]
    }

    fn is_mounted(&self, mount_point: &Path) -> Result<bool> {
        // Try common commands to check if mounted
        if let Ok(output) = Command::new("mount").output() {
            if output.status.success() {
                let mount_str = String::from_utf8(output.stdout)?;
                return Ok(mount_str.contains(&format!(" on {}", mount_point.display())));
            }
        }

        // Fallback: check if the directory exists and is not empty
        Ok(path.exists()
            && path
                .read_dir()
                .map(|mut i| i.next().is_some())
                .unwrap_or(false))
    }

    fn get_mount_info(&self, path: &Path) -> Result<Option<MountInfo>> {
        // Basic implementation - just check if we can find it in mount output
        if let Ok(output) = Command::new("mount").output() {
            if output.status.success() {
                let mount_str = String::from_utf8(output.stdout)?;
                for line in mount_str.lines() {
                    if line.contains(&format!(" on {}", path.display())) {
                        return Ok(Some(MountInfo {
                            device: "unknown".to_string(),
                            mount_point: path.to_path_buf(),
                            fs_type: "unknown".to_string(),
                            options: vec![],
                        }));
                    }
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

        // Fallback to /tmp
        PathBuf::from("/tmp/fuji.sock")
    }

    fn get_config_dir(&self) -> PathBuf {
        // Try user config first
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("fuji")
    }

    fn get_mount_dir(&self) -> PathBuf {
        PathBuf::from("/mnt/fuji")
    }

    fn list_system_mounts(&self) -> Result<Vec<(PathBuf, MountInfo)>> {
        let mut mounts = Vec::new();

        // Try to use mount command as a fallback
        if let Ok(output) = Command::new("mount").output() {
            if output.status.success() {
                let mount_str = String::from_utf8(output.stdout)?;
                for line in mount_str.lines() {
                    // Very basic parsing - just extract what we can
                    if let Some(start) = line.find(" on ") {
                        let device_part = &line[..start];
                        let rest = &line[start + 4..];

                        if let Some(space_pos) = rest.find(' ') {
                            let mount_point = PathBuf::from(&rest[..space_pos]);

                            let mount_info = MountInfo {
                                device: device_part.to_string(),
                                mount_point: mount_point.clone(),
                                fs_type: "unknown".to_string(),
                                options: vec![],
                            };

                            mounts.push((mount_point, mount_info));
                        }
                    }
                }
            }
        }

        Ok(mounts)
    }
}

pub fn get_platform() -> Box<dyn Platform> {
    Box::new(FallbackPlatform)
}
