//! Health monitoring and recovery system
//!
//! This module provides comprehensive health monitoring, automatic recovery,
//! and persistence for mount points.

pub mod scheduler;
pub mod health_checks;
pub mod retry;
pub mod persistence;
pub mod dependency;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::mount::MountConfig;

/// Main monitoring manager that orchestrates all monitoring components
pub struct MonitoringManager {
    /// Health check scheduler
    scheduler: Arc<scheduler::HealthCheckScheduler>,
    /// Retry logic handler
    retry_handler: Arc<retry::RetryHandler>,
    /// Persistence layer
    persistence: Arc<persistence::PersistenceManager>,
    /// Dependency graph manager
    dependency_graph: Arc<dependency::DependencyGraph>,
    /// Mount configurations being monitored
    mounts: Arc<RwLock<Vec<MountConfig>>>,
    /// Running state
    running: Arc<RwLock<bool>>,
}

impl MonitoringManager {
    /// Create a new monitoring manager
    pub fn new() -> Result<Self> {
        let scheduler = Arc::new(scheduler::HealthCheckScheduler::new()?);
        let retry_handler = Arc::new(retry::RetryHandler::new());
        let persistence = Arc::new(persistence::PersistenceManager::new()?);
        let dependency_graph = Arc::new(dependency::DependencyGraph::new());

        Ok(Self {
            scheduler,
            retry_handler,
            persistence,
            dependency_graph,
            mounts: Arc::new(RwLock::new(Vec::new())),
            running: Arc::new(RwLock::new(false)),
        })
    }

    /// Start the monitoring system
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            warn!("Monitoring manager is already running");
            return Ok(());
        }

        info!("Starting monitoring manager");

        // Start the scheduler
        self.scheduler.start().await?;

        // Load persisted mount states
        self.load_persisted_states().await?;

        *running = true;
        info!("Monitoring manager started successfully");

        Ok(())
    }

    /// Stop the monitoring system
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            warn!("Monitoring manager is not running");
            return Ok(());
        }

        info!("Stopping monitoring manager");

        // Stop the scheduler
        self.scheduler.stop().await?;

        *running = false;
        info!("Monitoring manager stopped successfully");

        Ok(())
    }

    /// Add a mount to be monitored
    pub async fn add_mount(&self, mount_config: MountConfig) -> Result<()> {
        info!("Adding mount {} to monitoring", mount_config.id);

        // Validate dependencies
        self.dependency_graph.validate_dependencies(&mount_config)?;

        // Add to persistence
        self.persistence.save_mount_state(&mount_config).await?;

        // Add to memory
        let mut mounts = self.mounts.write().await;
        mounts.push(mount_config);

        // Register health checks
        self.scheduler.register_health_checks(&mount_config).await?;

        Ok(())
    }

    /// Remove a mount from monitoring
    pub async fn remove_mount(&self, mount_id: &str) -> Result<()> {
        info!("Removing mount {} from monitoring", mount_id);

        // Unregister health checks
        self.scheduler.unregister_health_checks(mount_id).await?;

        // Remove from persistence
        self.persistence.delete_mount_state(mount_id).await?;

        // Remove from memory
        let mut mounts = self.mounts.write().await;
        mounts.retain(|m| m.id != mount_id);

        Ok(())
    }

    /// Get health status of all mounts
    pub async fn get_all_health_status(&self) -> Result<Vec<HealthStatus>> {
        let mounts = self.mounts.read().await;
        let mut statuses = Vec::new();

        for mount in mounts.iter() {
            let status = self.scheduler.get_health_status(&mount.id).await;
            statuses.push(status);
        }

        Ok(statuses)
    }

    /// Get health status of a specific mount
    pub async fn get_health_status(&self, mount_id: &str) -> Result<HealthStatus> {
        self.scheduler.get_health_status(mount_id).await
    }

    /// Trigger immediate health check for a mount
    pub async fn trigger_health_check(&self, mount_id: &str) -> Result<HealthStatus> {
        info!("Triggering immediate health check for {}", mount_id);
        self.scheduler.trigger_health_check(mount_id).await
    }

    /// Get dependency graph
    pub fn dependency_graph(&self) -> &dependency::DependencyGraph {
        &self.dependency_graph
    }

    /// Load persisted mount states
    async fn load_persisted_states(&self) -> Result<()> {
        debug!("Loading persisted mount states");
        let states = self.persistence.load_all_mount_states().await?;

        let mut mounts = self.mounts.write().await;
        for state in states {
            // Reconstruct MountConfig from persisted state
            if let Some(config) = self.persistence.state_to_config(&state) {
                mounts.push(config);
            }
        }

        debug!("Loaded {} persisted mount states", mounts.len());
        Ok(())
    }
}

/// Health status of a mount
#[derive(Debug, Clone)]
pub struct HealthStatus {
    /// Mount ID
    pub mount_id: String,
    /// Current health status
    pub status: HealthState,
    /// Last health check timestamp
    pub last_check: chrono::DateTime<chrono::Utc>,
    /// Number of consecutive failures
    pub failure_count: u32,
    /// Last error message (if any)
    pub last_error: Option<String>,
    /// Health score (0-100)
    pub health_score: u8,
}

/// Health states
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthState {
    /// Mount is healthy
    Healthy,
    /// Mount is unhealthy but may recover
    Degraded,
    /// Mount has failed
    Failed,
    /// Health check is in progress
    Checking,
    /// Mount is being recovered
    Recovering,
}

impl Default for MonitoringManager {
    fn default() -> Self {
        Self::new().expect("Failed to create monitoring manager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_monitoring_manager_creation() {
        let manager = MonitoringManager::new();
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_monitoring_lifecycle() {
        let manager = MonitoringManager::new().unwrap();

        // Should start successfully
        assert!(manager.start().await.is_ok());

        // Should not start again
        assert!(manager.start().await.is_ok());

        // Should stop successfully
        assert!(manager.stop().await.is_ok());

        // Should not stop again
        assert!(manager.stop().await.is_ok());
    }
}