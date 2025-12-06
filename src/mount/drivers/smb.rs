//! SMB/CIFS mount handler implementation

use crate::mount::drivers::{
    MountOptionsValidator, MountUrlValidator, SecureCommand, create_secure_mount_command,
};
use crate::mount::{MountConfig, MountHandler, MountState, MountType};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, error, info, warn};
use url::Url;

pub struct SmbHandler;

impl Default for SmbHandler {
    fn default() -> Self {
        Self::new()
    }
}

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
        // Validate URL first
        let validator = MountUrlValidator::new()?;
        validator.validate_url(url)?;

        let parsed = Url::parse(url)?;

        if !matches!(parsed.scheme(), "smb" | "cifs") {
            return Err(anyhow!("Invalid scheme for SMB/CIFS: {}", parsed.scheme()));
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("No host specified in URL"))?
            .to_string();

        let share = if parsed.path().is_empty() || parsed.path() == "/" {
            return Err(anyhow!("SMB/CIFS requires a share name"));
        } else {
            parsed.path().trim_start_matches('/').to_string()
        };

        let username = if !parsed.username().is_empty() {
            Some(parsed.username().to_string())
        } else {
            None
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
            MountType::SMB {
                host,
                share,
                ..
            } => {
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

        // Use smbclient to list shares
        let output = SecureCommand::new("smbclient")
            .arg("-L")
            .arg(host)
            .arg("-N")
            .output()
            .await;

        let stdout = match output {
            Ok(output) => output,
            Err(e) => {
                warn!("Failed to discover SMB shares: {}", e);
                return Ok(vec![]);
            }
        };
        let mut shares = Vec::new();

        // Parse smbclient output
        let in_shares = stdout
            .lines()
            .skip_while(|l| !l.contains("Sharename"))
            .skip(2) // Skip header lines
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

    async fn mount(&self, config: &MountConfig, mount_point: &Path) -> Result<()> {
        self.validate_config(config)?;

        match &config.mount_type {
            MountType::SMB {
                host,
                share,
                username,
                password,
                domain,
                options,
            } => {
                info!(
                    "Mounting SMB share //{}/{}/ to {}",
                    host,
                    share,
                    mount_point.display()
                );

                // Validate and prepare mount options
                let validator = MountOptionsValidator::new()?;
                let mut mount_options = options.clone();

                // Add credentials to options
                if let Some(user) = username {
                    mount_options.push(format!("username={}", user));
                }
                if let Some(pass) = password {
                    mount_options.push(format!("password={}", pass));
                }
                if let Some(d) = domain {
                    mount_options.push(format!("domain={}", d));
                }

                // Add default options if none specified
                if mount_options.is_empty() {
                    mount_options.extend(self.get_default_options());
                }

                // Validate all options
                validator.validate_options("smb", &mount_options)?;

                // Build remote path
                let remote_path = format!("//{}/{}", host, share);

                // Create secure mount command
                let cmd = create_secure_mount_command(
                    "smb",
                    &remote_path,
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
                    "Successfully mounted SMB share //{}/{}/ to {}",
                    host,
                    share,
                    mount_point.display()
                );
                Ok(())
            }
            _ => Err(anyhow!("Invalid mount type for SMB handler")),
        }
    }

    async fn unmount(&self, mount_point: &Path) -> Result<()> {
        info!("Unmounting SMB share at {}", mount_point.display());

        // Create secure unmount command
        let cmd = SecureCommand::new("umount").arg(mount_point.to_str().unwrap());

        // Execute unmount command
        let output = cmd.output().await?;

        if !output.is_empty() {
            // Check if output contains error indicators
            if output.to_lowercase().contains("error") || output.to_lowercase().contains("failed") {
                error!("Unmount failed: {}", output);
                return Err(anyhow!("Failed to unmount: {}", output));
            }
        }

        // Remove mount point directory
        if let Err(e) = fs::remove_dir(mount_point).await {
            warn!("Could not remove mount point directory: {}", e);
        }

        info!(
            "Successfully unmounted SMB share at {}",
            mount_point.display()
        );
        Ok(())
    }

    async fn check_health(&self, mount_point: &Path) -> Result<MountState> {
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
        })
        .await;

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
                warn!(
                    "SMB mount at {} has health issues: {}",
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
                    "Health check failed for SMB mount at {}: {}",
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
