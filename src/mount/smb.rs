//! SMB/CIFS mount handler implementation

use super::{MountHandler, MountConfig, MountState, MountType};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::path::PathBuf;
use std::process::Command;
use tokio::fs;
use tracing::{debug, error, info, warn};
use url::Url;

pub struct SmbHandler;

impl SmbHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl MountHandler for SmbHandler {
    fn protocol(&self) -> &'static str {
        "smb"
    }

    fn parse_url(&self, url: &str) -> Result<MountType> {
        let parsed = Url::parse(url)?;

        if !matches!(parsed.scheme(), "smb" | "cifs") {
            return Err(anyhow!("Invalid scheme for SMB/CIFS: {}", parsed.scheme()));
        }

        let host = parsed.host_str()
            .ok_or_else(|| anyhow!("No host specified in URL"))?
            .to_string();

        let share = if parsed.path().is_empty() || parsed.path() == "/" {
            return Err(anyhow!("SMB/CIFS requires a share name"));
        } else {
            parsed.path().trim_start_matches('/').to_string()
        };

        let username = if parsed.username().is_empty() {
            None
        } else {
            Some(parsed.username().to_string())
        };
        let password = parsed.password().map(|p| p.to_string());

        Ok(MountType::SMB {
            host,
            share,
            username,
            password,
            domain: None,
            options: self.get_default_options(),
        })
    }

    fn validate_config(&self, config: &MountConfig) -> Result<()> {
        match &config.mount_type {
            MountType::SMB { host, share, .. } => {
                if host.is_empty() {
                    return Err(anyhow!("SMB host cannot be empty"));
                }
                if share.is_empty() {
                    return Err(anyhow!("SMB share cannot be empty"));
                }
                Ok(())
            }
            _ => Err(anyhow!("Invalid mount type for SMB handler")),
        }
    }

    async fn discover_shares(&self, host: &str) -> Result<Vec<String>> {
        info!("Discovering SMB shares on {}", host);

        let host_owned = host.to_owned();
        // Use smbclient to list shares
        let output = tokio::task::spawn_blocking(move || {
            Command::new("smbclient")
                .arg("-L")
                .arg(&host_owned)
                .arg("-N")
                .output()
        }).await??;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to discover SMB shares: {}", stderr);
            return Ok(vec![]);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut shares = Vec::new();

        // Parse smbclient output
        let in_shares = stdout.lines()
            .skip_while(|l| !l.contains("Sharename"))
            .skip(2)  // Skip header lines
            .take_while(|l| !l.is_empty());

        for line in in_shares {
            if let Some(share) = line.split_whitespace().next() {
                if share != "IPC$" && share != "ADMIN$" {
                    shares.push(share.to_string());
                }
            }
        }

        info!("Discovered {} SMB shares on {}", shares.len(), host);
        Ok(shares)
    }

    async fn mount(&self, config: &MountConfig, mount_point: &PathBuf) -> Result<()> {
        self.validate_config(config)?;

        match &config.mount_type {
            MountType::SMB { host, share, username, password, domain, options } => {
                info!("Mounting SMB share //{}/{}/ to {}", host, share, mount_point.display());

                // Ensure mount point exists
                fs::create_dir_all(mount_point).await?;

                // Build mount command
                let mut cmd = Command::new("mount");
                cmd.arg("-t").arg("cifs");

                let mut mount_opts = vec![];

                // Add credentials
                if let Some(user) = username {
                    mount_opts.push(format!("username={}", user));
                }
                if let Some(pass) = password {
                    mount_opts.push(format!("password={}", pass));
                }
                if let Some(d) = domain {
                    mount_opts.push(format!("domain={}", d));
                }

                // Add custom options
                mount_opts.extend(options.clone());

                // Add defaults if not specified
                if !mount_opts.iter().any(|o| o.contains("vers")) {
                    mount_opts.push("vers=3.0".to_string());
                }

                cmd.arg("-o").arg(mount_opts.join(","));

                let remote_path = format!("//{}/{}", host, share);
                cmd.arg(&remote_path);
                cmd.arg(mount_point);

                // Execute mount command
                let output = tokio::task::spawn_blocking(move || cmd.output()).await??;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    error!("Mount failed: {}", stderr);
                    return Err(anyhow!("Failed to mount SMB share: {}", stderr));
                }

                info!("Successfully mounted SMB share //{}/{}/ to {}", host, share, mount_point.display());
                Ok(())
            }
            _ => Err(anyhow!("Invalid mount type for SMB handler")),
        }
    }

    async fn unmount(&self, mount_point: &PathBuf) -> Result<()> {
        info!("Unmounting SMB share at {}", mount_point.display());

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

        info!("Successfully unmounted SMB share at {}", mount_point.display());
        Ok(())
    }

    async fn check_health(&self, mount_point: &PathBuf) -> Result<MountState> {
        // Similar to NFS health check
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
        }).await;

        match health_result {
            Ok(Ok(())) => {
                debug!("SMB mount at {} is healthy", mount_point.display());
                Ok(MountState {
                    accessible: true,
                    last_error: None,
                    last_health_check: chrono::Utc::now(),
                    health_score: 100,
                })
            }
            Ok(Err(e)) => {
                warn!("SMB mount at {} has health issues: {}", mount_point.display(), e);
                Ok(MountState {
                    accessible: false,
                    last_error: Some(e.to_string()),
                    last_health_check: chrono::Utc::now(),
                    health_score: 0,
                })
            }
            Err(e) => {
                error!("Health check failed for SMB mount at {}: {}", mount_point.display(), e);
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
            "vers=3.0".to_string(),
            "sec=ntlmssp".to_string(),
            "rw".to_string(),
            "file_mode=0777".to_string(),
            "dir_mode=0777".to_string(),
        ]
    }

    fn generate_mount_id(&self, url: &str) -> Result<String> {
        if let Ok(parsed) = Url::parse(url) {
            let host = parsed.host_str().unwrap_or("unknown");
            let mut id = format!("{}_smb", host);

            // Add share name with underscores for path separators
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

        // Base: /mnt/fuji/{host}_smb
        let mut mount_point = self.get_mount_base_dir().join(format!("{}_smb", host));

        // Append the path from the URL, preserving directory structure
        let path = parsed.path();
        if !path.is_empty() && path != "/" {
            mount_point = mount_point.join(path.trim_start_matches('/'));
        }

        Ok(mount_point)
    }
}