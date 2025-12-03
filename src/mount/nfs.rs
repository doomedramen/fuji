//! NFS mount handler implementation

use super::{MountHandler, MountConfig, MountState, MountType};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::path::PathBuf;
use std::process::Command;
use tokio::fs;
use tracing::{debug, error, info, warn};
use url::Url;

pub struct NfsHandler;

impl NfsHandler {
    pub fn new() -> Self {
        Self
    }

    /// Check if showmount is available
    async fn check_showmount(&self) -> bool {
        Command::new("which")
            .arg("showmount")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

#[async_trait]
impl MountHandler for NfsHandler {
    fn protocol(&self) -> &'static str {
        "nfs"
    }

    fn parse_url(&self, url: &str) -> Result<MountType> {
        let parsed = Url::parse(url)?;

        if parsed.scheme() != "nfs" {
            return Err(anyhow!("Invalid scheme for NFS: {}", parsed.scheme()));
        }

        let host = parsed.host_str()
            .ok_or_else(|| anyhow!("No host specified in URL"))?
            .to_string();

        let share = if parsed.path().is_empty() || parsed.path() == "/" {
            // Default export if none specified
            "".to_string()
        } else {
            parsed.path().to_string()
        };

        Ok(MountType::NFS {
            host,
            share,
            options: vec![],
        })
    }

    fn validate_config(&self, config: &MountConfig) -> Result<()> {
        match &config.mount_type {
            MountType::NFS { host,  .. } => {
                if host.is_empty() {
                    return Err(anyhow!("NFS host cannot be empty"));
                }
                // Share can be empty (defaults to root export)
                Ok(())
            }
            _ => Err(anyhow!("Invalid mount type for NFS handler")),
        }
    }

    async fn discover_shares(&self, host: &str) -> Result<Vec<String>> {
        if !self.check_showmount().await {
            warn!("showmount not available, cannot discover NFS shares");
            return Ok(vec![]);
        }

        info!("Discovering NFS shares on {}", host);

        let host_owned = host.to_owned();
        let output = tokio::task::spawn_blocking(move || {
            Command::new("showmount")
                .arg("-e")
                .arg(&host_owned)
                .output()
        }).await??;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Failed to discover shares: {}", stderr));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut shares = Vec::new();

        for line in stdout.lines().skip(1) {
            // Skip header line
            if let Some(share) = line.split_whitespace().nth(0) {
                shares.push(share.to_string());
            }
        }

        info!("Discovered {} NFS shares on {}", shares.len(), host);
        Ok(shares)
    }

    async fn mount(&self, config: &MountConfig, mount_point: &PathBuf) -> Result<()> {
        self.validate_config(config)?;

        match &config.mount_type {
            MountType::NFS { host, share, options } => {
                info!("Mounting NFS share {}:{} to {}", host, share, mount_point.display());

                // Ensure mount point exists
                fs::create_dir_all(mount_point).await?;

                // Build mount command
                let mut cmd = Command::new("mount");
                cmd.arg("-t").arg("nfs");

                if !options.is_empty() {
                    cmd.arg("-o").arg(options.join(","));
                }

                let remote_path = if share.is_empty() {
                    format!("{}:/", host)
                } else {
                    format!("{}:{}", host, share)
                };

                cmd.arg(&remote_path);
                cmd.arg(mount_point);

                // Execute mount command
                let output = tokio::task::spawn_blocking(move || cmd.output()).await??;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    error!("Mount failed: {}", stderr);
                    return Err(anyhow!("Failed to mount NFS share: {}", stderr));
                }

                info!("Successfully mounted NFS share {}:{} to {}", host, share, mount_point.display());
                Ok(())
            }
            _ => Err(anyhow!("Invalid mount type for NFS handler")),
        }
    }

    async fn unmount(&self, mount_point: &PathBuf) -> Result<()> {
        info!("Unmounting NFS share at {}", mount_point.display());

        let mount_point_clone = mount_point.clone();
        let output = tokio::task::spawn_blocking(move || {
            Command::new("umount")
                .arg(&mount_point_clone)
                .output()
        }).await??;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("Unmount failed: {}", stderr);
            return Err(anyhow!("Failed to unmount: {}", stderr));
        }

        // Remove mount point directory
        if let Err(e) = fs::remove_dir(mount_point).await {
            warn!("Could not remove mount point directory: {}", e);
        }

        info!("Successfully unmounted NFS share at {}", mount_point.display());
        Ok(())
    }

    async fn check_health(&self, mount_point: &PathBuf) -> Result<MountState> {
        // Check if mount point exists
        if !mount_point.exists() {
            return Ok(MountState {
                accessible: false,
                last_error: Some("Mount point does not exist".to_string()),
                last_health_check: chrono::Utc::now(),
                health_score: 0,
            });
        }

        // Try to stat a file in the mount to verify it's accessible
        let test_path = mount_point.join(".fuji_health_check");
        let health_result = tokio::task::spawn_blocking(move || {
            // Create a temporary file to test write access
            std::fs::write(&test_path, b"health_check")?;

            // Read it back
            std::fs::read(&test_path)?;

            // Clean up
            let _ = std::fs::remove_file(&test_path);

            Ok::<(), std::io::Error>(())
        }).await;

        match health_result {
            Ok(Ok(())) => {
                debug!("NFS mount at {} is healthy", mount_point.display());
                Ok(MountState {
                    accessible: true,
                    last_error: None,
                    last_health_check: chrono::Utc::now(),
                    health_score: 100,
                })
            }
            Ok(Err(e)) => {
                warn!("NFS mount at {} has health issues: {}", mount_point.display(), e);
                Ok(MountState {
                    accessible: false,
                    last_error: Some(e.to_string()),
                    last_health_check: chrono::Utc::now(),
                    health_score: 0,
                })
            }
            Err(e) => {
                error!("Health check failed for NFS mount at {}: {}", mount_point.display(), e);
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
        vec![
            "soft".to_string(),
            "intr".to_string(),
            "rsize=1048576".to_string(),
            "wsize=1048576".to_string(),
            "timeo=300".to_string(),
            "retrans=2".to_string(),
        ]
    }

    fn generate_mount_id(&self, url: &str) -> Result<String> {
        if let Ok(parsed) = Url::parse(url) {
            let host = parsed.host_str().unwrap_or("unknown");
            let mut id = format!("{}_nfs", host);

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
        let parsed = Url::parse(url)?;
        let host = parsed.host_str().ok_or_else(|| anyhow!("No host in URL"))?;

        // Base: /mnt/fuji/{host}_nfs
        let mut mount_point = self.get_mount_base_dir().join(format!("{}_nfs", host));

        // Append the path from the URL, preserving directory structure
        let path = parsed.path();
        if !path.is_empty() && path != "/" {
            mount_point = mount_point.join(path.trim_start_matches('/'));
        }

        Ok(mount_point)
    }
}