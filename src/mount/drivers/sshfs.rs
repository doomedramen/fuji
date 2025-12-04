//! SSHFS mount handler implementation

use crate::mount::options::MountOptionParser;
use crate::mount::{MountConfig, MountHandler, MountState, MountType};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::path::PathBuf;
use std::process::Command;
use tokio::fs;
use tracing::{debug, error, info, warn};

pub struct SshfsHandler;

impl SshfsHandler {
    pub fn new() -> Self {
        Self
    }

    /// Check if sshfs is available
    async fn check_sshfs(&self) -> bool {
        let output =
            tokio::task::spawn_blocking(|| Command::new("which").arg("sshfs").output()).await;

        match output {
            Ok(Ok(output)) => output.status.success(),
            _ => false,
        }
    }
}

#[async_trait]
impl MountHandler for SshfsHandler {
    fn protocol(&self) -> &'static str {
        "sshfs"
    }

    fn parse_url(&self, url: &str) -> Result<MountType> {
        let parsed = url::Url::parse(url)?;

        if parsed.scheme() != "sshfs" && parsed.scheme() != "ssh" {
            return Err(anyhow!("Invalid scheme for SSHFS: {}", parsed.scheme()));
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("No host specified in URL"))?
            .to_string();

        let username = if parsed.username().is_empty() {
            None
        } else {
            Some(parsed.username().to_string())
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
            MountType::SMB { host, share, .. } => {
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
                share,
                username,
                password,
                domain,
                options,
            } => {
                if !self.check_sshfs().await {
                    return Err(anyhow!("sshfs is not installed"));
                }

                info!("Mounting SSHFS {} to {}", share, mount_point.display());

                // Parse and validate options using MountOptionParser
                let parser = MountOptionParser::new();

                // Build options string
                let options_str = if options.is_empty() {
                    ""
                } else {
                    &options.join(",")
                };
                let parsed_options = parser.parse(options_str, "sshfs")?;

                // Format options for mount command
                let formatted_options = parser.format(&parsed_options);
                debug!("Using SSHFS mount options: {}", formatted_options);

                // Ensure mount point exists
                fs::create_dir_all(mount_point).await?;

                // Build mount command
                let mut cmd = Command::new("sshfs");

                // Add options if any
                if !formatted_options.is_empty() {
                    cmd.arg("-o").arg(&formatted_options);
                }

                // Add source and destination
                cmd.arg(share);
                cmd.arg(mount_point);

                // Execute mount command
                let output = tokio::task::spawn_blocking(move || cmd.output()).await??;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    error!("Mount failed: {}", stderr);
                    return Err(anyhow!("Failed to mount SSHFS: {}", stderr));
                }

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
        let mount_point_clone = mount_point.clone();
        let output = tokio::task::spawn_blocking(move || {
            Command::new("fusermount")
                .arg("-u")
                .arg(&mount_point_clone)
                .output()
        })
        .await??;

        if !output.status.success() {
            // Fallback to umount
            warn!("fusermount failed, trying umount");
            let mount_point_clone = mount_point.clone();
            let output = tokio::task::spawn_blocking(move || {
                Command::new("umount").arg(&mount_point_clone).output()
            })
            .await??;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                error!("Unmount failed: {}", stderr);
                return Err(anyhow!("Failed to unmount SSHFS: {}", stderr));
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

        // Append the path from the URL, preserving directory structure
        let path = parsed.path();
        if !path.is_empty() && path != "/" {
            mount_point = mount_point.join(path.trim_start_matches('/'));
        }

        Ok(mount_point)
    }
}
