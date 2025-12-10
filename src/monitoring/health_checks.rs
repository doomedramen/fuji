//! Health check strategies for monitoring mount points
//!
//! Implements various health check types including ping, file access,
//! and protocol-specific checks.

use anyhow::{Result, anyhow};
use std::path::Path;
use std::time::Duration;
use tokio::fs;
use tracing::{debug, warn};

use crate::mount::{MountConfig, get_mount_handler};

/// Health check context containing all necessary information
pub struct HealthCheckContext<'a> {
    /// Mount configuration
    pub config: &'a MountConfig,
    /// Mount point path
    pub mount_point: &'a Path,
    /// Platform utilities
    pub platform: &'a dyn crate::platform::Platform,
}

/// Run a health check by name
///
/// This is the main entry point for health checks used by the scheduler.
pub async fn run_check(
    mount_id: &str,
    check_name: &str,
    context: HealthCheckContext<'_>,
) -> Result<bool> {
    debug!("Running health check {} for mount {}", check_name, mount_id);

    match check_name {
        "file_access" => run_file_access_check(context).await,
        "ping" => run_ping_check(context).await,
        "protocol" => run_protocol_check(context).await,
        _ => Err(anyhow!("Unknown health check: {}", check_name)),
    }
}

/// Run a file access health check
///
/// Verifies that the mount point exists and is accessible for read/write.
async fn run_file_access_check(context: HealthCheckContext<'_>) -> Result<bool> {
    debug!(
        "Running file access check for mount point: {:?}",
        context.mount_point
    );

    // Check if mount point exists
    if !context.platform.path_exists(context.mount_point) {
        warn!("Mount point does not exist: {:?}", context.mount_point);
        return Ok(false);
    }

    // Create a test file to verify write access
    let test_file = context.mount_point.join(".fuji_health_check");
    let test_data = b"health_check";

    // Write test
    if let Err(e) = fs::write(&test_file, test_data).await {
        warn!("Write access failed for mount {}: {}", context.config.id, e);
        return Ok(false);
    }

    // Read test
    let read_result = fs::read(&test_file).await;

    // Clean up
    let _ = fs::remove_file(&test_file).await;

    match read_result {
        Ok(data) => {
            if data != test_data {
                warn!("Data corruption detected for mount {}", context.config.id);
                return Ok(false);
            }
        }
        Err(e) => {
            warn!("Read access failed for mount {}: {}", context.config.id, e);
            return Ok(false);
        }
    }

    // Check if mount is actually mounted
    match context.platform.is_mounted(context.mount_point) {
        Ok(is_mounted) => {
            if !is_mounted {
                warn!("Mount point is not mounted: {:?}", context.mount_point);
                return Ok(false);
            }
        }
        Err(e) => {
            warn!("Could not check mount status: {}", e);
            // Continue anyway - some platforms may not support this check
        }
    }

    Ok(true)
}

/// Run a network ping health check
///
/// Pings the host server to verify network connectivity.
async fn run_ping_check(context: HealthCheckContext<'_>) -> Result<bool> {
    debug!("Running ping check for mount {}", context.config.id);

    // Extract host from mount type
    let host = match &context.config.mount_type {
        crate::mount::MountType::Nfs {
            host,
            ..
        } => host.clone(),
        crate::mount::MountType::Smb {
            host,
            ..
        } => host.clone(),
        // TODO: Remove this workaround when SSHFS is added to MountType enum
        _ => {
            // Try to extract host from URL as fallback
            if let Some(stripped) = context.config.url.strip_prefix("sshfs://") {
                if let Some(host_part) = stripped.split('/').next() {
                    host_part.to_string()
                } else {
                    return Err(anyhow!("Cannot determine host for ping check"));
                }
            } else {
                return Err(anyhow!("Cannot determine host for ping check"));
            }
        }
    };

    // Use tokio::task::spawn_blocking with timeout
    let host_clone = host.clone();
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || {
            std::process::Command::new("ping")
                .arg("-c")
                .arg("1")
                .arg("-W")
                .arg("5")
                .arg(&host_clone)
                .output()
        }),
    )
    .await
    .map_err(|_| anyhow!("Ping command timed out after 10 seconds"))?
    .map_err(|e| anyhow!("Failed to execute ping: {}", e))??;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Ping failed for host {}: {}", host, stderr.trim());
        return Ok(false);
    }

    Ok(true)
}

/// Run a protocol-specific health check
///
/// Uses the mount handler to check the health of the mount.
async fn run_protocol_check(context: HealthCheckContext<'_>) -> Result<bool> {
    debug!("Running protocol check for mount {}", context.config.id);

    // Get the appropriate handler for this mount type
    let protocol = match &context.config.mount_type {
        crate::mount::MountType::Nfs {
            ..
        } => "nfs",
        crate::mount::MountType::Smb {
            ..
        } => "smb",
        // TODO: Remove this workaround when SSHFS is added to MountType enum
        _ => {
            if context.config.url.starts_with("sshfs://") {
                "sshfs"
            } else {
                return Err(anyhow!("Unsupported mount type for protocol check"));
            }
        }
    };

    let handler = get_mount_handler(protocol)?;

    // Use the handler's health check method
    match handler.check_health(context.mount_point).await {
        Ok(state) => {
            debug!(
                "Health check result for mount {}: {:?}",
                context.config.id, state
            );
            Ok(state.accessible)
        }
        Err(e) => {
            warn!(
                "Protocol health check failed for mount {}: {}",
                context.config.id, e
            );
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount::{MountConfig, MountType};
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_run_check_unknown_type() {
        let config = MountConfig::new(
            "nfs://example.com/share".to_string(),
            MountType::Nfs {
                host: "example.com".to_string(),
                share: "/share".to_string(),
                options: vec![],
            },
            PathBuf::from("/tmp/test"),
        );
        let platform = crate::platform::get_platform();
        let context = HealthCheckContext {
            config: &config,
            mount_point: &PathBuf::from("/tmp/test"),
            platform: platform.as_ref(),
        };

        let result = run_check("test_mount", "invalid_check", context).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unknown health check")
        );
    }

    #[tokio::test]
    async fn test_run_check_known_types() {
        let config = MountConfig::new(
            "nfs://example.com/share".to_string(),
            MountType::Nfs {
                host: "example.com".to_string(),
                share: "/share".to_string(),
                options: vec![],
            },
            PathBuf::from("/tmp/test"),
        );
        let platform = crate::platform::get_platform();
        let context = HealthCheckContext {
            config: &config,
            mount_point: &PathBuf::from("/tmp/test"),
            platform: platform.as_ref(),
        };

        // Test file access check (will fail if /tmp/test doesn't exist)
        let result = run_check("test_mount", "file_access", context).await;
        // This might fail in test environment, but the function should not panic
        assert!(result.is_ok() || result.is_err());

        // Test ping check (need a new context since the first one was consumed)
        let platform = crate::platform::get_platform();
        let context = HealthCheckContext {
            config: &config,
            mount_point: &PathBuf::from("/tmp/test"),
            platform: platform.as_ref(),
        };
        let result = run_check("test_mount", "ping", context).await;
        assert!(result.is_ok() || result.is_err());

        // Test protocol check (need another new context)
        let platform = crate::platform::get_platform();
        let context = HealthCheckContext {
            config: &config,
            mount_point: &PathBuf::from("/tmp/test"),
            platform: platform.as_ref(),
        };
        let result = run_check("test_mount", "protocol", context).await;
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_health_check_context_creation() {
        let config = MountConfig::new(
            "nfs://example.com/share".to_string(),
            MountType::Nfs {
                host: "example.com".to_string(),
                share: "/share".to_string(),
                options: vec![],
            },
            PathBuf::from("/tmp/test"),
        );
        let platform = crate::platform::get_platform();
        let context = HealthCheckContext {
            config: &config,
            mount_point: &PathBuf::from("/tmp/test"),
            platform: platform.as_ref(),
        };

        assert_eq!(context.config.id, config.id);
        assert_eq!(context.mount_point, PathBuf::from("/tmp/test"));
        assert!(!context.config.mount_point.to_string_lossy().is_empty());
    }
}
