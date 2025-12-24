//! Mount retry coordinator
//!
//! Integrates the RetryHandler with mount operations to provide
//! intelligent retry logic with exponential backoff, jitter,
//! and circuit breaker functionality.

use anyhow::Result;
use chrono::Utc;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::daemon::monitor::MountMonitor;
use crate::monitoring::retry::{CircuitBreakerState, RetryHandler, RetryPolicy};
use crate::mount::{MountConfig, MountStatus, get_mount_handler};
use crate::platform::get_platform;

/// Mount retry coordinator that handles retry logic for mount operations
pub struct MountRetryCoordinator {
    /// Retry handler
    retry_handler: Arc<RetryHandler>,
    /// Mount monitor for updating health status
    #[allow(dead_code)]
    monitor: Arc<MountMonitor>,
}

#[allow(dead_code)]
impl MountRetryCoordinator {
    /// Create a new mount retry coordinator
    pub fn new(monitor: Arc<MountMonitor>) -> Self {
        Self {
            retry_handler: Arc::new(RetryHandler::new()),
            monitor,
        }
    }

    /// Mount with retry logic
    pub async fn mount_with_retry(
        &self,
        mount_config: &MountConfig,
        config: Arc<RwLock<crate::config::Config>>,
    ) -> Result<()> {
        let mount_id = mount_config.id.clone();

        // Set retry policy based on mount configuration
        self.set_retry_policy_for_mount(mount_config).await;

        // Check circuit breaker first
        let circuit_breaker = self
            .retry_handler
            .get_circuit_breaker_status(&mount_id)
            .await
            .unwrap_or_else(|| CircuitBreakerState::new(5, StdDuration::from_secs(60)));

        if !circuit_breaker.should_allow_attempt() {
            error!(
                "Circuit breaker open for mount {}, blocking mount operation",
                mount_id
            );
            return Err(anyhow::anyhow!(
                "Circuit breaker is open for mount {}",
                mount_id
            ));
        }

        // Execute mount with retry logic
        let result = self
            .retry_handler
            .execute_with_retry(&mount_id, || {
                self.mount_single_attempt(mount_config.clone(), config.clone())
            })
            .await?;

        if result.value.is_some() {
            // Mount succeeded
            let _ = self
                .update_status_after_success(config.clone(), &mount_id)
                .await;

            info!(
                "Mount {} succeeded after {} attempts in {:?}",
                mount_id, result.attempts, result.total_time
            );
        } else {
            // All attempts failed
            error!(
                "Mount {} failed after {} attempts: {}",
                mount_id,
                result.attempts,
                result
                    .last_error
                    .unwrap_or_else(|| "Unknown error".to_string())
            );
        }

        result
            .value
            .ok_or_else(|| anyhow::anyhow!("Mount failed after {} attempts", result.attempts))
    }

    /// Unmount with retry logic
    pub async fn unmount_with_retry(&self, mount_config: &MountConfig) -> Result<()> {
        let mount_id = mount_config.id.clone();

        info!("Unmounting {} with retry logic", mount_id);

        // Unmount typically doesn't need as many retries
        let policy = RetryPolicy {
            max_attempts: 3,
            initial_delay: StdDuration::from_millis(100),
            max_delay: StdDuration::from_secs(5),
            multiplier: 2.0,
            jitter: 0.2,
            reset_after: StdDuration::from_secs(30),
        };

        self.retry_handler.set_policy(&mount_id, policy).await;

        let result = self
            .retry_handler
            .execute_with_retry(&mount_id, || {
                self.unmount_single_attempt(mount_config.clone())
            })
            .await?;

        if result.value.is_some() {
            info!(
                "Unmount {} succeeded after {} attempts in {:?}",
                mount_id, result.attempts, result.total_time
            );
        }

        result
            .value
            .ok_or_else(|| anyhow::anyhow!("Unmount failed after {} attempts", result.attempts))
    }

    /// Attempt reconnection for failed mounts
    pub async fn attempt_reconnection(
        &self,
        mount_config: &MountConfig,
        config: Arc<RwLock<crate::config::Config>>,
    ) -> Result<bool> {
        let mount_id = mount_config.id.clone();

        info!("Attempting reconnection for {}", mount_id);

        // Check if we should attempt reconnection based on circuit breaker
        if let Some(circuit_breaker) = self
            .retry_handler
            .get_circuit_breaker_status(&mount_id)
            .await
        {
            if !circuit_breaker.should_allow_attempt() {
                warn!(
                    "Circuit breaker preventing reconnection for {}, will retry in {:?}",
                    mount_id,
                    circuit_breaker.time_until_close()
                );
                return Ok(false);
            }
        }

        // Update status to reconnecting
        let _ = self
            .update_status_to_reconnecting(config.clone(), &mount_id)
            .await;

        // Attempt to remount
        match self.mount_with_retry(mount_config, config.clone()).await {
            Ok(()) => {
                info!("Successfully reconnected {}", mount_id);
                Ok(true)
            }
            Err(e) => {
                warn!("Failed to reconnect {}: {}", mount_id, e);
                let _ = self
                    .update_status_to_failed(config.clone(), &mount_id, Some(&e.to_string()))
                    .await;
                Ok(false)
            }
        }
    }

    /// Get retry status for a mount
    pub async fn get_retry_status(&self, mount_id: &str) -> Option<RetryStatus> {
        let circuit_breaker = self
            .retry_handler
            .get_circuit_breaker_status(mount_id)
            .await?;

        Some(RetryStatus {
            mount_id: mount_id.to_string(),
            failure_count: circuit_breaker.failure_count,
            last_failure: circuit_breaker.last_failure,
            is_circuit_open: circuit_breaker.is_open,
            time_until_close: circuit_breaker.time_until_close(),
        })
    }

    /// Reset retry state for a mount
    pub async fn reset_retry_state(&self, mount_id: &str) {
        self.retry_handler.reset(mount_id).await;
        info!("Reset retry state for mount {}", mount_id);
    }

    /// Set retry policy for a mount based on its configuration
    async fn set_retry_policy_for_mount(&self, mount_config: &MountConfig) {
        let policy = if let Some(retry_config) = mount_config.metadata.get("retry_policy") {
            // Parse custom retry policy from metadata
            parse_retry_policy_from_metadata(retry_config).unwrap_or_else(|e| {
                warn!(
                    "Invalid retry policy for {}: {}, using default",
                    mount_config.id, e
                );
                RetryPolicy::default()
            })
        } else {
            // Default policy based on mount type
            default_retry_policy_for_mount_type(&mount_config.mount_type)
        };

        self.retry_handler
            .set_policy(&mount_config.id, policy)
            .await;
    }

    /// Perform a single mount attempt
    async fn mount_single_attempt(
        &self,
        mount_config: MountConfig,
        _config: Arc<RwLock<crate::config::Config>>,
    ) -> Result<()> {
        let mount_id = mount_config.id.clone();
        let protocol = mount_config.url.split("://").next().unwrap_or("");

        let handler = get_mount_handler(protocol)
            .map_err(|e| anyhow::anyhow!("Failed to get mount handler: {}", e))?;

        // Ensure mount point exists
        if !mount_config.mount_point.exists() {
            tokio::fs::create_dir_all(&mount_config.mount_point)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to create mount point: {}", e))?;
        }

        // Unmount if already mounted
        let platform = get_platform();
        if platform
            .is_mounted(&mount_config.mount_point)
            .unwrap_or(false)
        {
            debug!("Unmounting existing mount for {}", mount_id);
            let _ = handler.unmount(&mount_config.mount_point).await;
        }

        // Mount
        handler
            .mount(&mount_config, &mount_config.mount_point)
            .await
            .map_err(|e| anyhow::anyhow!("Mount operation failed: {}", e))?;

        Ok(())
    }

    /// Perform a single unmount attempt
    async fn unmount_single_attempt(&self, mount_config: MountConfig) -> Result<()> {
        let mount_id = mount_config.id.clone();
        let protocol = mount_config.url.split("://").next().unwrap_or("");

        let handler = get_mount_handler(protocol)
            .map_err(|e| anyhow::anyhow!("Failed to get mount handler: {}", e))?;

        // Check if mounted
        let platform = get_platform();
        if !platform
            .is_mounted(&mount_config.mount_point)
            .unwrap_or(false)
        {
            debug!("Mount {} is not mounted, skipping unmount", mount_id);
            return Ok(());
        }

        // Unmount
        handler
            .unmount(&mount_config.mount_point)
            .await
            .map_err(|e| anyhow::anyhow!("Unmount operation failed: {}", e))?;

        Ok(())
    }

    /// Update mount status after successful mount
    async fn update_status_after_success(
        &self,
        config: Arc<RwLock<crate::config::Config>>,
        mount_id: &str,
    ) -> Result<()> {
        let mut cfg = config.write().await;
        if let Some(mount) = cfg.get_mount_mut(mount_id) {
            mount.update_status(MountStatus::Active);
            mount.reconnect_attempts = 0;
            mount.updated_at = Utc::now();
        }
        drop(cfg);

        // Note: Monitor doesn't have update_status method, status is tracked by config

        Ok(())
    }

    /// Update mount to reconnecting
    async fn update_status_to_reconnecting(
        &self,
        config: Arc<RwLock<crate::config::Config>>,
        mount_id: &str,
    ) -> Result<()> {
        let mut cfg = config.write().await;
        if let Some(mount) = cfg.get_mount_mut(mount_id) {
            mount.increment_reconnect_attempts();
            mount.update_status(MountStatus::Reconnecting);
        }
        drop(cfg);

        Ok(())
    }

    /// Update mount to failed
    async fn update_status_to_failed(
        &self,
        config: Arc<RwLock<crate::config::Config>>,
        mount_id: &str,
        error: Option<&str>,
    ) -> Result<()> {
        let mut cfg = config.write().await;
        if let Some(mount) = cfg.get_mount_mut(mount_id) {
            // MountStatus::Error includes error message if provided
            if let Some(err) = error {
                mount.update_status(MountStatus::Error(err.to_string()));
            } else {
                mount.update_status(MountStatus::Failed);
            }
        }
        drop(cfg);

        Ok(())
    }
}

/// Retry status for a mount
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RetryStatus {
    /// Mount ID
    pub mount_id: String,
    /// Number of consecutive failures
    pub failure_count: u32,
    /// Last failure timestamp
    pub last_failure: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether circuit breaker is open
    pub is_circuit_open: bool,
    /// Time until circuit breaker closes
    pub time_until_close: Option<StdDuration>,
}

/// Get default retry policy based on mount type
fn default_retry_policy_for_mount_type(mount_type: &crate::mount::MountType) -> RetryPolicy {
    use crate::mount::MountType;

    match mount_type {
        MountType::Nfs {
            ..
        } => RetryPolicy {
            max_attempts: 5,
            initial_delay: StdDuration::from_secs(2),
            max_delay: StdDuration::from_secs(30),
            multiplier: 2.0,
            jitter: 0.1,
            reset_after: StdDuration::from_secs(600),
        },
        MountType::Smb {
            ..
        } => RetryPolicy {
            max_attempts: 7,
            initial_delay: StdDuration::from_secs(1),
            max_delay: StdDuration::from_secs(180),
            multiplier: 1.8,
            jitter: 0.15,
            reset_after: StdDuration::from_secs(300),
        },
        MountType::Sshfs {
            ..
        } => RetryPolicy {
            max_attempts: 6,
            initial_delay: StdDuration::from_secs(3),
            max_delay: StdDuration::from_secs(240),
            multiplier: 2.2,
            jitter: 0.2,
            reset_after: StdDuration::from_secs(450),
        },
    }
}

/// Parse retry policy from metadata
fn parse_retry_policy_from_metadata(metadata: &str) -> Result<RetryPolicy> {
    // Expected format: "max_attempts=5,initial_delay=2s,max_delay=300s,multiplier=2.0,jitter=0.1"
    let mut policy = RetryPolicy::default();

    for pair in metadata.split(',') {
        let mut parts = pair.split('=');
        if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
            match key.trim() {
                "max_attempts" => {
                    policy.max_attempts = value
                        .parse()
                        .map_err(|e| anyhow::anyhow!("Invalid max_attempts: {}", e))?;
                }
                "initial_delay" => {
                    let seconds = parse_duration(value)?;
                    policy.initial_delay = StdDuration::from_secs(seconds);
                }
                "max_delay" => {
                    let seconds = parse_duration(value)?;
                    policy.max_delay = StdDuration::from_secs(seconds);
                }
                "multiplier" => {
                    policy.multiplier = value
                        .parse()
                        .map_err(|e| anyhow::anyhow!("Invalid multiplier: {}", e))?;
                }
                "jitter" => {
                    policy.jitter = value
                        .parse()
                        .map_err(|e| anyhow::anyhow!("Invalid jitter: {}", e))?;
                }
                _ => {
                    warn!("Unknown retry policy parameter: {}", key);
                }
            }
        }
    }

    Ok(policy)
}

/// Parse duration string like "30s", "5m", "1h"
fn parse_duration(s: &str) -> Result<u64> {
    let s = s.trim().to_lowercase();

    if s.ends_with('s') {
        let num = &s[..s.len() - 1];
        Ok(num
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid seconds: {}", e))?)
    } else if s.ends_with('m') {
        let num = &s[..s.len() - 1];
        let minutes: u64 = num
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid minutes: {}", e))?;
        Ok(minutes * 60)
    } else if s.ends_with('h') {
        let num = &s[..s.len() - 1];
        let hours: u64 = num
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid hours: {}", e))?;
        Ok(hours * 3600)
    } else {
        // Assume seconds
        Ok(s.parse()
            .map_err(|e| anyhow::anyhow!("Invalid duration: {}", e))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30s").unwrap(), 30);
        assert_eq!(parse_duration("5m").unwrap(), 300);
        assert_eq!(parse_duration("1h").unwrap(), 3600);
        assert_eq!(parse_duration("120").unwrap(), 120);
    }

    #[test]
    fn test_parse_retry_policy_from_metadata() {
        let metadata = "max_attempts=7,initial_delay=5s,max_delay=600s,multiplier=1.5,jitter=0.2";
        let policy = parse_retry_policy_from_metadata(metadata).unwrap();

        assert_eq!(policy.max_attempts, 7);
        assert_eq!(policy.initial_delay, StdDuration::from_secs(5));
        assert_eq!(policy.max_delay, StdDuration::from_secs(600));
        assert_eq!(policy.multiplier, 1.5);
        assert_eq!(policy.jitter, 0.2);
    }

    #[test]
    fn test_default_retry_policy_for_mount_type() {
        let nfs_policy = default_retry_policy_for_mount_type(&crate::mount::MountType::Nfs {
            host: "test".to_string(),
            share: "/share".to_string(),
            options: vec![],
        });

        assert_eq!(nfs_policy.max_attempts, 5);
        assert_eq!(nfs_policy.initial_delay, StdDuration::from_secs(2));
        assert_eq!(nfs_policy.multiplier, 2.0);
    }
}
