//! Health check scheduler using tokio-cron-scheduler
//!
//! Provides periodic health checks for mount points with configurable intervals.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::{health_checks, HealthState, HealthStatus};

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

impl HealthCheckScheduler {
    /// Create a new health check scheduler
    pub fn new() -> Result<Self> {
        Ok(Self {
            scheduler: Arc::new(RwLock::new(None)),
            health_checks: Arc::new(RwLock::new(HashMap::new())),
            last_statuses: Arc::new(RwLock::new(HashMap::new())),
            default_interval: "*/30 * * * * *".to_string(), // Every 30 seconds
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

        // Clone the data we need for the job
        let mount_id_clone = mount_id.to_string();
        let health_checks_clone = self.health_checks.clone();
        let last_statuses_clone = self.last_statuses.clone();

        // Create the job using the correct API
        let cron_job = Job::new_async(job.interval.as_str(), move |_uuid, _scheduler| {
            let mount_id = mount_id_clone.clone();
            let health_checks = health_checks_clone.clone();
            let last_statuses = last_statuses_clone.clone();

            Box::pin(async move {
                let health_checks = health_checks.read().await;
                let check_types = if let Some(job) = health_checks.get(&mount_id) {
                    job.check_types.clone()
                } else {
                    return;
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
            crate::mount::MountType::NFS { .. } => {
                // NFS mounts can be checked less frequently
                if interval == self.default_interval {
                    interval = "*/60 * * * * *".to_string(); // Every minute
                }
            }
            crate::mount::MountType::SMB { .. } => {
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
            crate::mount::MountType::NFS {
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
