// Allow dead code - infrastructure for future features
#![allow(dead_code)]

//! Health check strategies for monitoring mount points
//!
//! Implements various health check types including ping, file access,
//! and protocol-specific checks.

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::mount::{MountType, get_mount_handler};

/// Semaphore to limit concurrent health check tasks
static TASK_SEMAPHORE: std::sync::LazyLock<Arc<Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(Semaphore::new(10))); // Limit to 10 concurrent tasks

/// Health check trait
#[async_trait]
pub trait HealthCheck: Send + Sync {
    /// Run the health check
    async fn execute(
        &self,
        mount_id: &str,
        mount_config: &crate::mount::MountConfig,
    ) -> Result<HealthCheckResult>;

    /// Get the name of this health check
    fn name(&self) -> &'static str;

    /// Get the default timeout for this check
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(10)
    }
}

/// Result of a health check
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    /// Whether the check passed
    pub passed: bool,
    /// Optional message
    pub message: Option<String>,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// Additional metadata
    pub metadata: std::collections::HashMap<String, String>,
}

/// File access health check
pub struct FileAccessHealthCheck;

impl FileAccessHealthCheck {
    /// Create a new file access health check
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl HealthCheck for FileAccessHealthCheck {
    async fn execute(
        &self,
        _mount_id: &str,
        mount_config: &crate::mount::MountConfig,
    ) -> Result<HealthCheckResult> {
        // Acquire semaphore permit to limit concurrent tasks
        let _permit = TASK_SEMAPHORE
            .acquire()
            .await
            .map_err(|e| anyhow!("Failed to acquire task semaphore: {}", e))?;

        let start = std::time::Instant::now();
        let platform = crate::platform::get_platform();

        // Check if mount point exists
        if !platform.path_exists(&mount_config.mount_point) {
            return Ok(HealthCheckResult {
                passed: false,
                message: Some("Mount point does not exist".to_string()),
                response_time_ms: start.elapsed().as_millis() as u64,
                metadata: std::collections::HashMap::new(),
            });
        }

        // Create a test file to verify write access
        let test_file = mount_config.mount_point.join(".fuji_health_check");
        let test_data = b"health_check";

        // Write test
        let write_result = fs::write(&test_file, test_data).await;
        let write_time = start.elapsed();

        if let Err(e) = write_result {
            return Ok(HealthCheckResult {
                passed: false,
                message: Some(format!("Write access failed: {}", e)),
                response_time_ms: write_time.as_millis() as u64,
                metadata: std::collections::HashMap::new(),
            });
        }

        // Read test
        let read_result = fs::read(&test_file).await;
        let total_time = start.elapsed();

        if let Err(e) = read_result {
            return Ok(HealthCheckResult {
                passed: false,
                message: Some(format!("Read access failed: {}", e)),
                response_time_ms: total_time.as_millis() as u64,
                metadata: std::collections::HashMap::new(),
            });
        }

        // Clean up
        let _ = fs::remove_file(&test_file).await;

        // Check if read data matches
        if let Ok(data) = read_result {
            if data != test_data {
                return Ok(HealthCheckResult {
                    passed: false,
                    message: Some("Data corruption detected".to_string()),
                    response_time_ms: total_time.as_millis() as u64,
                    metadata: std::collections::HashMap::new(),
                });
            }
        }

        // Check if mount is actually mounted
        match platform.is_mounted(&mount_config.mount_point) {
            Ok(is_mounted) => {
                if !is_mounted {
                    return Ok(HealthCheckResult {
                        passed: false,
                        message: Some("Mount point is not mounted".to_string()),
                        response_time_ms: total_time.as_millis() as u64,
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
            Err(e) => {
                warn!("Could not check mount status: {}", e);
            }
        }

        Ok(HealthCheckResult {
            passed: true,
            message: None,
            response_time_ms: total_time.as_millis() as u64,
            metadata: {
                let mut meta = std::collections::HashMap::new();
                meta.insert(
                    "write_time_ms".to_string(),
                    format!("{}", write_time.as_millis()),
                );
                meta
            },
        })
    }

    fn name(&self) -> &'static str {
        "file_access"
    }
}

/// Network ping health check
pub struct PingHealthCheck;

impl PingHealthCheck {
    /// Create a new ping health check
    pub fn new() -> Self {
        Self
    }

    /// Extract host from mount configuration
    pub fn extract_host(&self, mount_config: &crate::mount::MountConfig) -> Result<String> {
        match &mount_config.mount_type {
            MountType::NFS {
                host,
                ..
            } => Ok(host.clone()),
            MountType::SMB {
                host,
                ..
            } => Ok(host.clone()),
        }
    }
}

#[async_trait]
impl HealthCheck for PingHealthCheck {
    async fn execute(
        &self,
        _mount_id: &str,
        mount_config: &crate::mount::MountConfig,
    ) -> Result<HealthCheckResult> {
        // Acquire semaphore permit to limit concurrent tasks
        let _permit = TASK_SEMAPHORE
            .acquire()
            .await
            .map_err(|e| anyhow!("Failed to acquire task semaphore: {}", e))?;

        let start = std::time::Instant::now();

        let host = self.extract_host(mount_config)?;
        let host_clone = host.clone();

        // Use tokio::task::spawn_blocking with timeout and proper error handling
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

        let elapsed = start.elapsed();

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Ok(HealthCheckResult {
                passed: false,
                message: Some(format!("Ping failed: {}", stderr.trim())),
                response_time_ms: elapsed.as_millis() as u64,
                metadata: std::collections::HashMap::new(),
            });
        }

        // Parse ping output for response time
        let stdout = String::from_utf8_lossy(&output.stdout);
        let response_time = if let Some(line) = stdout.lines().find(|l| l.contains("time=")) {
            if let Some(time_part) = line.split("time=").nth(1) {
                if let Some(time_str) = time_part.split_whitespace().next() {
                    time_str.parse::<f64>().unwrap_or(0.0)
                } else {
                    0.0
                }
            } else {
                0.0
            }
        } else {
            0.0
        };

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("host".to_string(), host);
        metadata.insert("ping_time_ms".to_string(), format!("{:.2}", response_time));

        Ok(HealthCheckResult {
            passed: true,
            message: None,
            response_time_ms: elapsed.as_millis() as u64,
            metadata,
        })
    }

    fn name(&self) -> &'static str {
        "ping"
    }
}

/// Protocol-specific health check
pub struct ProtocolHealthCheck;

impl ProtocolHealthCheck {
    /// Create a new protocol health check
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl HealthCheck for ProtocolHealthCheck {
    async fn execute(
        &self,
        _mount_id: &str,
        mount_config: &crate::mount::MountConfig,
    ) -> Result<HealthCheckResult> {
        // Acquire semaphore permit to limit concurrent tasks
        let _permit = TASK_SEMAPHORE
            .acquire()
            .await
            .map_err(|e| anyhow!("Failed to acquire task semaphore: {}", e))?;

        let start = std::time::Instant::now();

        // Get the appropriate handler for this mount type
        let protocol = match &mount_config.mount_type {
            MountType::NFS {
                ..
            } => "nfs",
            MountType::SMB {
                ..
            } => "smb",
        };

        let handler = get_mount_handler(protocol)?;

        // Use the handler's health check method
        let mount_state = handler.check_health(&mount_config.mount_point).await;

        let elapsed = start.elapsed();
        let response_time_ms = elapsed.as_millis() as u64;

        let result = match mount_state {
            Ok(state) => HealthCheckResult {
                passed: state.accessible,
                message: state.last_error,
                response_time_ms,
                metadata: {
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("health_score".to_string(), state.health_score.to_string());
                    meta.insert(
                        "last_check".to_string(),
                        state.last_health_check.to_rfc3339(),
                    );
                    meta
                },
            },
            Err(e) => HealthCheckResult {
                passed: false,
                message: Some(e.to_string()),
                response_time_ms,
                metadata: std::collections::HashMap::new(),
            },
        };

        Ok(result)
    }

    fn name(&self) -> &'static str {
        "protocol"
    }

    fn default_timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
}

/// Registry of health checks
pub struct HealthCheckRegistry {
    checks: std::collections::HashMap<String, Box<dyn HealthCheck>>,
}

impl HealthCheckRegistry {
    /// Create a new health check registry
    pub fn new() -> Self {
        let mut registry = Self {
            checks: std::collections::HashMap::new(),
        };

        // Register default health checks
        registry.register_default_checks();
        registry
    }

    /// Register default health checks
    fn register_default_checks(&mut self) {
        // These will be registered with actual platform later
    }

    /// Register a health check
    pub fn register(&mut self, name: String, check: Box<dyn HealthCheck>) {
        self.checks.insert(name, check);
    }

    /// Get a health check
    pub fn get(&self, name: &str) -> Option<&dyn HealthCheck> {
        self.checks.get(name).map(|c| c.as_ref())
    }

    /// Run a specific health check
    pub async fn run_check(
        mount_id: &str,
        mount_config: &crate::mount::MountConfig,
        check_name: &str,
    ) -> Result<HealthCheckResult> {
        // Create checks on demand
        match check_name {
            "file_access" => {
                let check = FileAccessHealthCheck::new();
                check.execute(mount_id, mount_config).await
            }
            "ping" => {
                let check = PingHealthCheck::new();
                check.execute(mount_id, mount_config).await
            }
            "protocol" => {
                let check = ProtocolHealthCheck::new();
                check.execute(mount_id, mount_config).await
            }
            _ => Err(anyhow!("Unknown health check: {}", check_name)),
        }
    }
}

/// Run a health check by name
pub async fn run_check(mount_id: &str, check_name: &str) -> Result<bool> {
    // This is a simplified version for the scheduler
    // In practice, we'd need the mount config from persistence
    debug!("Running health check {} for mount {}", check_name, mount_id);

    // For now, just return true for the check
    // TODO: Implement full check with mount config
    match check_name {
        "file_access" | "ping" | "protocol" => Ok(true),
        _ => Err(anyhow!("Unknown health check: {}", check_name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_check_registry() {
        let _registry = HealthCheckRegistry::new();
        // Should have default checks registered
    }

    #[tokio::test]
    async fn test_file_access_health_check() {
        let check = FileAccessHealthCheck::new();

        // Test with non-existent mount
        let config = crate::mount::MountConfig::new(
            "nfs://example.com/share".to_string(),
            crate::mount::MountType::NFS {
                host: "example.com".to_string(),
                share: "/share".to_string(),
                options: vec![],
            },
            "/nonexistent/mount".into(),
        );

        let result = check.execute("test", &config).await.unwrap();
        assert!(!result.passed);
        assert!(result.message.unwrap().contains("does not exist"));
    }
}
