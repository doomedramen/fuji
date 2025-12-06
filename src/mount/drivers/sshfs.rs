//! SSHFS mount handler implementation

use crate::mount::drivers::{
    MountOptionsValidator, MountUrlValidator, SecureCommand, create_secure_mount_command,
};
use crate::mount::{MountConfig, MountHandler, MountState, MountType};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use std::path::PathBuf;
use tokio::fs;
use tracing::{debug, error, info, warn};

pub struct SshfsHandler;

impl SshfsHandler {
    pub fn new() -> Self {
        Self
    }

    /// Check if sshfs is available
    async fn check_sshfs(&self) -> bool {
        SecureCommand::new("which")
            .arg("sshfs")
            .status()
            .await
            .unwrap_or(false)
    }
}

#[async_trait]
impl MountHandler for SshfsHandler {
    fn protocol(&self) -> &'static str {
        "sshfs"
    }

    fn parse_url(&self, url: &str) -> Result<MountType> {
        // Validate URL first
        let validator = MountUrlValidator::new()?;
        validator.validate_url(url)?;

        let parsed = url::Url::parse(url)?;

        if parsed.scheme() != "sshfs" && parsed.scheme() != "ssh" && parsed.scheme() != "sftp" {
            return Err(anyhow!("Invalid scheme for SSHFS: {}", parsed.scheme()));
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("No host specified in URL"))?
            .to_string();

        let username = if !parsed.username().is_empty() {
            Some(parsed.username().to_string())
        } else {
            None
        };

        let _port = parsed.port().map(|p| p.to_string());

        // Path on the remote server
        let _remote_path = if parsed.path().is_empty() || parsed.path() == "/" {
            "".to_string()
        } else {
            parsed.path().to_string()
        };

        // For SSHFS, we'll use the SMB mount type as a temporary storage for connection info
        // TODO: Add a dedicated SSHFS mount type to MountType enum
        let share = format!("sshfs://{}", host);
        Ok(MountType::SMB {
            host,
            share,
            username,
            password: None,
            domain: None,
            options: self.get_default_options(),
        })
    }

    fn validate_config(&self, config: &MountConfig) -> Result<()> {
        match &config.mount_type {
            MountType::SMB {
                host,
                share,
                ..
            } => {
                if host.is_empty() {
                    return Err(anyhow!("SSHFS host cannot be empty"));
                }
                if share.is_empty() {
                    return Err(anyhow!("SSHFS remote path cannot be empty"));
                }
                Ok(())
            }
            _ => Err(anyhow!("Invalid mount type for SSHFS handler")),
        }
    }

    async fn discover_shares(&self, _host: &str) -> Result<Vec<String>> {
        // SSHFS doesn't have a share discovery mechanism like SMB/NFS
        // Could potentially use SSH to list directories, but that's server-specific
        warn!("SSHFS does not support share discovery");
        Ok(vec![])
    }

    async fn mount(&self, config: &MountConfig, mount_point: &PathBuf) -> Result<()> {
        self.validate_config(config)?;

        match &config.mount_type {
            MountType::SMB {
                host: _,
                share,
                username: _,
                password: _,
                domain: _,
                options,
            } => {
                if !self.check_sshfs().await {
                    return Err(anyhow!("sshfs is not installed"));
                }

                info!("Mounting SSHFS {} to {}", share, mount_point.display());

                // Validate and prepare mount options
                let validator = MountOptionsValidator::new()?;
                let mut mount_options = options.clone();

                // Add default options if none specified
                if mount_options.is_empty() {
                    mount_options.extend(self.get_default_options());
                }

                // Validate all options
                validator.validate_options("sshfs", &mount_options)?;

                // Create secure mount command
                let cmd = create_secure_mount_command(
                    "sshfs",
                    share,
                    mount_point.to_str().unwrap(),
                    &mount_options,
                )?;

                // Ensure mount point exists
                fs::create_dir_all(mount_point).await?;

                // Execute mount command
                let output = cmd.output().await?;

                // SecureCommand::output returns Result<String>, not a status object
                // If we get here, the command succeeded
                debug!("Mount command output: {}", output);

                info!(
                    "Successfully mounted SSHFS {} to {}",
                    share,
                    mount_point.display()
                );
                Ok(())
            }
            _ => Err(anyhow!("Invalid mount type for SSHFS handler")),
        }
    }

    async fn unmount(&self, mount_point: &PathBuf) -> Result<()> {
        info!("Unmounting SSHFS at {}", mount_point.display());

        // Try fusermount first (preferred for SSHFS)
        let mount_point_str = mount_point.to_str().unwrap();
        match SecureCommand::new("fusermount")
            .arg("-u")
            .arg(mount_point_str)
            .output()
            .await
        {
            Ok(_) => {
                debug!("Successfully unmounted with fusermount");
            }
            Err(e) => {
                warn!("fusermount failed: {}, trying umount", e);
                // Fallback to umount
                let output = SecureCommand::new("umount")
                    .arg(mount_point_str)
                    .output()
                    .await;

                if let Err(e) = output {
                    error!("Unmount failed: {}", e);
                    return Err(anyhow!("Failed to unmount SSHFS: {}", e));
                }
            }
        }

        // Remove mount point directory
        if let Err(e) = fs::remove_dir(mount_point).await {
            warn!("Could not remove mount point directory: {}", e);
        }

        info!("Successfully unmounted SSHFS at {}", mount_point.display());
        Ok(())
    }

    async fn check_health(&self, mount_point: &PathBuf) -> Result<MountState> {
        // Similar to NFS/SMB health check
        if !mount_point.exists() {
            return Ok(MountState {
                accessible: false,
                last_error: Some("Mount point does not exist".to_string()),
                last_health_check: chrono::Utc::now(),
                health_score: 0,
            });
        }

        // Try to stat the mount point
        let test_path = mount_point.join(".fuji_health_check");
        let health_result = tokio::task::spawn_blocking(move || {
            // Test write access
            std::fs::write(&test_path, b"health_check")?;
            std::fs::read(&test_path)?;
            let _ = std::fs::remove_file(&test_path);
            Ok::<(), std::io::Error>(())
        })
        .await;

        match health_result {
            Ok(Ok(())) => {
                debug!("SSHFS mount at {} is healthy", mount_point.display());
                Ok(MountState {
                    accessible: true,
                    last_error: None,
                    last_health_check: chrono::Utc::now(),
                    health_score: 100,
                })
            }
            Ok(Err(e)) => {
                warn!(
                    "SSHFS mount at {} has health issues: {}",
                    mount_point.display(),
                    e
                );
                Ok(MountState {
                    accessible: false,
                    last_error: Some(e.to_string()),
                    last_health_check: chrono::Utc::now(),
                    health_score: 0,
                })
            }
            Err(e) => {
                error!(
                    "Health check failed for SSHFS mount at {}: {}",
                    mount_point.display(),
                    e
                );
                Ok(MountState {
                    accessible: false,
                    last_error: Some(e.to_string()),
                    last_health_check: chrono::Utc::now(),
                    health_score: 0,
                })
            }
        }
    }

    fn get_default_options(&self) -> Vec<String> {
        vec![]
    }

    fn generate_mount_id(&self, url: &str) -> Result<String> {
        if let Ok(parsed) = url::Url::parse(url) {
            let host = parsed.host_str().unwrap_or("unknown");
            let mut id = format!("{}_sshfs", host);

            // Add path if present and not root
            if !parsed.path().is_empty() && parsed.path() != "/" {
                id.push('_');
                id.push_str(&parsed.path().trim_start_matches('/').replace('/', "_"));
            }

            Ok(id)
        } else {
            Err(anyhow!("Invalid URL format"))
        }
    }

    fn generate_mount_point(&self, url: &str) -> Result<PathBuf> {
        let parsed = url::Url::parse(url)?;
        let host = parsed.host_str().ok_or_else(|| anyhow!("No host in URL"))?;

        // Base: /mnt/fuji/{host}_sshfs
        let mut mount_point = self.get_mount_base_dir().join(format!("{}_sshfs", host));

        // Sanitize and validate the path from the URL to prevent path traversal
        let path = parsed.path();
        if !path.is_empty() && path != "/" {
            let validator = MountUrlValidator::new()?;
            let sanitized_path = validator.sanitize_path_component(path)?;
            if !sanitized_path.is_empty() {
                mount_point = mount_point.join(sanitized_path);
            }
        }

        Ok(mount_point)
    }
}
