//! NFS mount handler implementation

use crate::mount::drivers::{
    MountOptionsValidator, MountUrlValidator, SecureCommand, create_secure_mount_command,
};
use crate::mount::{MountConfig, MountHandler, MountState, MountType};
use crate::platform::deps::SystemDepsChecker;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, error, info, warn};
use url::Url;

pub struct NfsHandler;

impl Default for NfsHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl NfsHandler {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Check if showmount is available
    async fn check_showmount(&self) -> bool {
        SecureCommand::new("which")
            .arg("showmount")
            .status()
            .await
            .unwrap_or(false)
    }
}

#[async_trait]
impl MountHandler for NfsHandler {
    fn protocol(&self) -> &'static str {
        "nfs"
    }

    fn parse_url(&self, url: &str) -> Result<MountType> {
        // Validate URL first
        let validator = MountUrlValidator::new()?;
        validator.validate_url(url)?;

        let parsed = Url::parse(url)?;

        if parsed.scheme() != "nfs" {
            return Err(anyhow!("Invalid scheme for NFS: {}", parsed.scheme()));
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("No host specified in URL"))?
            .to_string();

        let share = if parsed.path().is_empty() || parsed.path() == "/" {
            // Default export if none specified
            String::new()
        } else {
            parsed.path().to_string()
        };

        Ok(MountType::Nfs {
            host,
            share,
            options: self.get_default_options(),
        })
    }

    fn validate_config(&self, config: &MountConfig) -> Result<()> {
        match &config.mount_type {
            MountType::Nfs {
                host,
                ..
            } => {
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

        let output = SecureCommand::new("showmount")
            .arg("-e")
            .arg(host)
            .output()
            .await?;

        let mut shares = Vec::new();

        for line in output.lines().skip(1) {
            // Skip header line
            if let Some(share) = line.split_whitespace().nth(0) {
                shares.push(share.to_string());
            }
        }

        info!("Discovered {} NFS shares on {}", shares.len(), host);
        Ok(shares)
    }

    async fn mount(&self, config: &MountConfig, mount_point: &Path) -> Result<()> {
        self.validate_config(config)?;

        // Check system dependencies with helpful error messages
        let deps_checker = SystemDepsChecker::new();
        match deps_checker.check_dependency("nfs").await {
            Ok(result) if !result.available => {
                let mut error_msg = "NFS client is not installed or not found in PATH".to_string();
                if let Some(ref instructions) = result.install_instructions {
                    error_msg.push_str(&format!("\nTo install: {instructions}"));
                }
                return Err(anyhow!(error_msg));
            }
            Err(e) => {
                warn!("Failed to check NFS dependency: {}", e);
                // Continue with mount attempt
            }
            _ => {} // Dependency is available
        }

        match &config.mount_type {
            MountType::Nfs {
                host,
                share,
                options,
            } => {
                info!(
                    "Mounting NFS share {}:{} to {}",
                    host,
                    share,
                    mount_point.display()
                );

                // Validate and prepare mount options
                let validator = MountOptionsValidator::new()?;
                let mut mount_options = options.clone();

                // Add default options if none specified
                if mount_options.is_empty() {
                    mount_options.extend(self.get_default_options());
                }

                // Validate all options
                validator.validate_options("nfs", &mount_options)?;

                // Build remote path
                let remote_path = if share.is_empty() {
                    format!("{host}:/")
                } else {
                    format!("{host}:{share}")
                };

                // Create secure mount command
                let cmd = create_secure_mount_command(
                    "nfs",
                    &remote_path,
                    mount_point.to_str().unwrap(),
                    &mount_options,
                )?;

                // Ensure mount point exists
                fs::create_dir_all(mount_point).await?;

                // Log the exact mount command for debugging
                debug!("Executing mount command: {}", cmd.display_command());

                // Execute mount command with timing
                let start = std::time::Instant::now();
                let output = cmd.output().await.map_err(|e| {
                    anyhow!(
                        "Failed to mount {}:{} to {}: {}",
                        host,
                        share,
                        mount_point.display(),
                        e
                    )
                })?;
                let duration = start.elapsed();

                // Log execution time and output
                info!("Mount command completed in {:.2}s", duration.as_secs_f64());
                if !output.trim().is_empty() {
                    debug!("Mount command output: {}", output.trim());
                }

                info!(
                    "Successfully mounted NFS share {}:{} to {}",
                    host,
                    share,
                    mount_point.display()
                );
                Ok(())
            }
            _ => Err(anyhow!("Invalid mount type for NFS handler")),
        }
    }

    async fn unmount(&self, mount_point: &Path) -> Result<()> {
        info!("Unmounting NFS share at {}", mount_point.display());

        // Create secure unmount command
        let cmd = SecureCommand::new("umount").arg(mount_point.to_str().unwrap());

        // Execute unmount command
        let output = cmd.output().await?;

        if !output.is_empty() {
            // Check if output contains error indicators
            if output.to_lowercase().contains("error") || output.to_lowercase().contains("failed") {
                error!("Unmount failed: {}", output);
                return Err(anyhow!("Failed to unmount: {output}"));
            }
        }

        // Remove mount point directory
        if let Err(e) = fs::remove_dir(mount_point).await {
            warn!("Could not remove mount point directory: {}", e);
        }

        info!(
            "Successfully unmounted NFS share at {}",
            mount_point.display()
        );
        Ok(())
    }

    async fn check_health(&self, mount_point: &Path) -> Result<MountState> {
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
        })
        .await;

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
                warn!(
                    "NFS mount at {} has health issues: {}",
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
                    "Health check failed for NFS mount at {}: {}",
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
        vec![
            "nolock".to_string(),    // No remote locking (avoids rpc.statd requirement)
            "timeo=10".to_string(),  // RPC timeout: 1 second (10 * 0.1s)
            "retrans=2".to_string(), // Retransmission attempts before failing
            "soft".to_string(),      // Fail fast instead of hanging indefinitely
            "_netdev".to_string(),   // Proper network device handling
        ]
    }

    fn generate_mount_id(&self, url: &str) -> Result<String> {
        if let Ok(parsed) = Url::parse(url) {
            let host = parsed.host_str().unwrap_or("unknown");
            let mut id = format!("{host}_nfs");

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
        let mut mount_point = self.get_mount_base_dir().join(format!("{host}_nfs"));

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
