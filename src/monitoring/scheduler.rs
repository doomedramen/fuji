//! Health check scheduler using tokio-cron-scheduler
//!
//! Provides periodic health checks for mount points with configurable intervals.

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::{HealthState, HealthStatus, health_checks};

/// Health check scheduler
pub struct HealthCheckScheduler {
    /// Tokio cron scheduler
    scheduler: Arc<RwLock<Option<JobScheduler>>>,
    /// Registered health checks
    health_checks: Arc<RwLock<HashMap<String, HealthCheckJob>>>,
    /// Last known health statuses
    last_statuses: Arc<RwLock<HashMap<String, HealthStatus>>>,
    /// Default check interval
    default_interval: String,
    /// Cleanup interval in seconds
    cleanup_interval: u64,
    /// Maximum age for health status entries (in seconds)
    max_status_age: u64,
}

/// A health check job configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct HealthCheckJob {
    /// Mount ID
    mount_id: String,
    /// Check interval as cron expression
    interval: String,
    /// Health check types to run
    check_types: Vec<String>,
    /// Job ID in scheduler
    job_id: Option<Uuid>,
    /// Last run timestamp
    last_run: Option<DateTime<Utc>>,
}

#[allow(dead_code)]
impl HealthCheckScheduler {
    /// Create a new health check scheduler
    pub fn new() -> Result<Self> {
        Ok(Self {
            scheduler: Arc::new(RwLock::new(None)),
            health_checks: Arc::new(RwLock::new(HashMap::new())),
            last_statuses: Arc::new(RwLock::new(HashMap::new())),
            default_interval: "*/30 * * * * *".to_string(), // Every 30 seconds
            cleanup_interval: 300,                          // 5 minutes
            max_status_age: 3600,                           // 1 hour
        })
    }

    /// Start the scheduler
    pub async fn start(&self) -> Result<()> {
        let mut scheduler = self.scheduler.write().await;

        if scheduler.is_some() {
            warn!("Scheduler is already running");
            return Ok(());
        }

        info!("Starting health check scheduler");

        let new_scheduler = JobScheduler::new()
            .await
            .map_err(|e| anyhow!("Failed to create scheduler: {}", e))?;

        *scheduler = Some(new_scheduler);

        // Start cleanup task
        self.start_cleanup_task().await;

        info!("Health check scheduler started");

        Ok(())
    }

    /// Stop the scheduler
    pub async fn stop(&self) -> Result<()> {
        let mut scheduler = self.scheduler.write().await;

        if scheduler.is_none() {
            warn!("Scheduler is not running");
            return Ok(());
        }

        info!("Stopping health check scheduler");

        if let Some(mut s) = scheduler.take() {
            s.shutdown()
                .await
                .map_err(|e| anyhow!("Failed to shutdown scheduler: {}", e))?;
        }

        info!("Health check scheduler stopped");
        Ok(())
    }

    /// Start the cleanup task
    async fn start_cleanup_task(&self) {
        let last_statuses_weak = Arc::downgrade(&self.last_statuses);
        let cleanup_interval = self.cleanup_interval;
        let max_status_age = self.max_status_age;

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(cleanup_interval));

            loop {
                interval.tick().await;

                if let Some(last_statuses) = last_statuses_weak.upgrade() {
                    Self::cleanup_old_status_entries(&last_statuses, max_status_age).await;
                } else {
                    // Scheduler has been dropped, exit cleanup task
                    break;
                }
            }
        });
    }

    /// Clean up old status entries
    async fn cleanup_old_status_entries(
        last_statuses: &Arc<RwLock<HashMap<String, HealthStatus>>>,
        max_age: u64,
    ) {
        let now = Utc::now();
        let cutoff_time = now - chrono::Duration::seconds(max_age as i64);

        let mut statuses = last_statuses.write().await;
        let initial_count = statuses.len();

        statuses.retain(|_, status| status.last_check > cutoff_time);

        let removed_count = initial_count - statuses.len();
        if removed_count > 0 {
            debug!("Cleaned up {} old health status entries", removed_count);
        }
    }

    /// Register health checks for a mount
    pub async fn register_health_checks(
        &self,
        mount_config: &crate::mount::MountConfig,
    ) -> Result<()> {
        let mount_id = mount_config.id.clone();

        // Determine check interval based on mount type and options
        let interval = self.determine_check_interval(mount_config)?;

        // Default health check types
        let check_types = vec!["file_access".to_string(), "ping".to_string()];

        let job = HealthCheckJob {
            mount_id: mount_id.clone(),
            interval,
            check_types,
            job_id: None,
            last_run: None,
        };

        // Add to registry
        let mut health_checks = self.health_checks.write().await;
        health_checks.insert(mount_id.clone(), job);
        drop(health_checks);

        // Schedule the job
        self.schedule_health_check(&mount_id).await?;

        info!("Registered health checks for mount {}", mount_id);
        Ok(())
    }

    /// Unregister health checks for a mount
    pub async fn unregister_health_checks(&self, mount_id: &str) -> Result<()> {
        let mut health_checks = self.health_checks.write().await;

        if let Some(job) = health_checks.remove(mount_id) {
            // Remove from scheduler if it has a job ID
            if let Some(job_id) = job.job_id {
                if let Some(scheduler) = self.scheduler.read().await.as_ref() {
                    match scheduler.remove(&job_id).await {
                        Ok(_) => {
                            debug!("Removed health check job {} for mount {}", job_id, mount_id)
                        }
                        Err(e) => warn!("Failed to remove health check job {}: {}", job_id, e),
                    }
                }
            }
        }

        // Remove last status
        let mut last_statuses = self.last_statuses.write().await;
        last_statuses.remove(mount_id);

        info!("Unregistered health checks for mount {}", mount_id);
        Ok(())
    }

    /// Trigger immediate health check for a mount
    pub async fn trigger_health_check(&self, mount_id: &str) -> Result<HealthStatus> {
        let health_checks = self.health_checks.read().await;
        let job = health_checks
            .get(mount_id)
            .ok_or_else(|| anyhow!("No health checks registered for mount {}", mount_id))?;

        // Run the health checks
        self.run_health_checks(mount_id, &job.check_types).await
    }

    /// Get health status for a mount
    pub async fn get_health_status(&self, mount_id: &str) -> Result<HealthStatus> {
        let last_statuses = self.last_statuses.read().await;

        last_statuses
            .get(mount_id)
            .cloned()
            .ok_or_else(|| anyhow!("No health status available for mount {}", mount_id))
    }

    /// Get all health statuses
    pub async fn get_all_health_statuses(&self) -> Vec<HealthStatus> {
        let last_statuses = self.last_statuses.read().await;
        last_statuses.values().cloned().collect()
    }

    /// Schedule a health check job
    async fn schedule_health_check(&self, mount_id: &str) -> Result<()> {
        let mut health_checks = self.health_checks.write().await;
        let job = health_checks
            .get_mut(mount_id)
            .ok_or_else(|| anyhow!("Health check not found for mount {}", mount_id))?;

        let scheduler = self.scheduler.read().await;
        let scheduler = scheduler
            .as_ref()
            .ok_or_else(|| anyhow!("Scheduler is not running"))?;

        // Use weak references to avoid memory leaks
        let mount_id_for_job = mount_id.to_string();
        let health_checks_weak = Arc::downgrade(&self.health_checks);
        let last_statuses_weak = Arc::downgrade(&self.last_statuses);

        // Create the job using the correct API
        let cron_job = Job::new_async(job.interval.as_str(), move |_uuid, _scheduler| {
            let mount_id = mount_id_for_job.clone();
            let health_checks_weak = health_checks_weak.clone();
            let last_statuses_weak = last_statuses_weak.clone();

            Box::pin(async move {
                // Try to upgrade weak references
                let (health_checks, last_statuses) =
                    match (health_checks_weak.upgrade(), last_statuses_weak.upgrade()) {
                        (Some(hc), Some(ls)) => (hc, ls),
                        _ => {
                            // Scheduler has been dropped, exit
                            return;
                        }
                    };

                // Get check types
                let check_types = {
                    let health_checks = health_checks.read().await;
                    if let Some(job) = health_checks.get(&mount_id) {
                        job.check_types.clone()
                    } else {
                        // Job no longer exists
                        return;
                    }
                };

                // Run health checks
                match Self::run_health_checks_static(&mount_id, &check_types).await {
                    Ok(status) => {
                        // Update last status
                        let mut last_statuses = last_statuses.write().await;
                        last_statuses.insert(mount_id, status);
                    }
                    Err(e) => {
                        warn!("Health check failed for {}: {}", mount_id, e);
                    }
                }
            })
        })
        .map_err(|e| anyhow!("Failed to create cron job: {}", e))?;

        // Add to scheduler
        let job_id = scheduler
            .add(cron_job)
            .await
            .map_err(|e| anyhow!("Failed to add job to scheduler: {}", e))?;

        job.job_id = Some(job_id);
        info!(
            "Scheduled health check job {} for mount {}",
            job_id, mount_id
        );

        Ok(())
    }

    /// Run health checks for a mount
    async fn run_health_checks(
        &self,
        mount_id: &str,
        check_types: &[String],
    ) -> Result<HealthStatus> {
        // Update last run time
        {
            let mut health_checks = self.health_checks.write().await;
            if let Some(job) = health_checks.get_mut(mount_id) {
                job.last_run = Some(Utc::now());
            }
        }

        Self::run_health_checks_static(mount_id, check_types).await
    }

    /// Static method to run health checks
    async fn run_health_checks_static(
        mount_id: &str,
        check_types: &[String],
    ) -> Result<HealthStatus> {
        debug!("Running health checks for mount {}", mount_id);

        let mut healthy_count = 0;
        let total_count = check_types.len();
        let mut last_error = None;
        let mut health_score: u32 = 100;

        for check_type in check_types {
            match health_checks::run_check(mount_id, check_type).await {
                Ok(healthy) => {
                    if healthy {
                        healthy_count += 1;
                    } else {
                        health_score = health_score.saturating_sub(20);
                    }
                }
                Err(e) => {
                    warn!(
                        "Health check {} failed for mount {}: {}",
                        check_type, mount_id, e
                    );
                    last_error = Some(e.to_string());
                    health_score = health_score.saturating_sub(30);
                }
            }
        }

        let status = if healthy_count == total_count {
            HealthState::Healthy
        } else if healthy_count > 0 {
            HealthState::Degraded
        } else {
            HealthState::Failed
        };

        debug!(
            "Health check result for {}: {:?} (score: {})",
            mount_id, status, health_score
        );

        let health_status = HealthStatus {
            mount_id: mount_id.to_string(),
            status,
            last_check: Utc::now(),
            failure_count: 0, // TODO: Track consecutive failures
            last_error,
            health_score: health_score as u8,
        };

        Ok(health_status)
    }

    /// Determine check interval based on mount configuration
    fn determine_check_interval(&self, mount_config: &crate::mount::MountConfig) -> Result<String> {
        // Default to 30 seconds
        let mut interval = self.default_interval.clone();

        // Check for custom interval in mount metadata
        if let Some(check_interval) = mount_config.metadata.get("health_check_interval") {
            // Validate cron expression
            if Job::new_async(check_interval.as_str(), |_uuid, _scheduler| {
                Box::pin(async {})
            })
            .is_ok()
            {
                interval = check_interval.clone();
            } else {
                warn!(
                    "Invalid health_check_interval '{}' for mount {}, using default",
                    check_interval, mount_config.id
                );
            }
        }

        // Adjust interval based on mount type
        match &mount_config.mount_type {
            crate::mount::MountType::Nfs {
                ..
            } => {
                // NFS mounts can be checked less frequently
                if interval == self.default_interval {
                    interval = "*/60 * * * * *".to_string(); // Every minute
                }
            }
            crate::mount::MountType::Smb {
                ..
            } => {
                // SMB mounts benefit from more frequent checks
                if interval == self.default_interval {
                    interval = "*/15 * * * * *".to_string(); // Every 15 seconds
                }
            }
        }

        Ok(interval)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_creation() {
        let scheduler = HealthCheckScheduler::new();
        assert!(scheduler.is_ok());
    }

    #[tokio::test]
    async fn test_scheduler_lifecycle() {
        let scheduler = HealthCheckScheduler::new().unwrap();

        // Should start successfully
        assert!(scheduler.start().await.is_ok());

        // Should not start again
        assert!(scheduler.start().await.is_ok());

        // Should stop successfully
        assert!(scheduler.stop().await.is_ok());

        // Should not stop again
        assert!(scheduler.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_determine_check_interval() {
        let scheduler = HealthCheckScheduler::new().unwrap();

        // Create test mount config
        let mut config = crate::mount::MountConfig::new(
            "test://example.com/share".to_string(),
            crate::mount::MountType::Nfs {
                host: "example.com".to_string(),
                share: "/share".to_string(),
                options: vec![],
            },
            "/mnt/test".into(),
        );

        // Test default interval
        let interval = scheduler.determine_check_interval(&config).unwrap();
        assert_eq!(interval, "*/60 * * * * *"); // NFS default

        // Test custom interval
        config.metadata.insert(
            "health_check_interval".to_string(),
            "*/5 * * * * *".to_string(),
        );
        let interval = scheduler.determine_check_interval(&config).unwrap();
        assert_eq!(interval, "*/5 * * * * *");
    }
}
