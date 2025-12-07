// Allow dead code - infrastructure for future features
#![allow(dead_code)]

//! Comprehensive resource limits management for Fuji daemon
//!
//! This module provides configurable resource limits to prevent resource exhaustion attacks
//! and ensure stable daemon operation. It includes memory limits, CPU throttling, file descriptor
//! limits, and comprehensive resource monitoring with automatic enforcement.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};
use sysinfo::System;
use tokio::sync::{RwLock, Semaphore};
use tokio::time::interval;
use tracing::{error, info, warn};

/// Resource limits configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Memory limits configuration
    pub memory: MemoryLimits,
    /// CPU limits configuration
    pub cpu: CpuLimits,
    /// File descriptor limits
    pub file_descriptors: FileDescriptorLimits,
    /// Process limits
    pub process: ProcessLimits,
    /// Network limits
    pub network: NetworkLimits,
    /// Monitoring and enforcement settings
    pub enforcement: EnforcementSettings,
}

/// Memory usage limits and monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLimits {
    /// Maximum memory usage in bytes (0 = no limit)
    pub max_memory_bytes: u64,
    /// Maximum memory usage percentage (0-100, 0 = no limit)
    pub max_memory_percent: u8,
    /// Memory pressure threshold for warnings (percent)
    pub warning_threshold_percent: u8,
    /// Memory pressure threshold for enforcement (percent)
    pub enforcement_threshold_percent: u8,
    /// Memory check interval in seconds
    pub check_interval_secs: u64,
    /// Enable memory usage tracking
    pub enable_tracking: bool,
}

/// CPU usage limits and throttling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuLimits {
    /// Maximum CPU usage percentage (0-100, 0 = no limit)
    pub max_cpu_percent: u8,
    /// CPU usage window for averaging (seconds)
    pub usage_window_secs: u64,
    /// CPU check interval in milliseconds
    pub check_interval_ms: u64,
    /// Enable CPU throttling when limits exceeded
    pub enable_throttling: bool,
    /// Throttling factor when limit exceeded (0.1-1.0)
    pub throttle_factor: f64,
    /// Grace period before throttling (seconds)
    pub grace_period_secs: u64,
}

/// File descriptor limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDescriptorLimits {
    /// Maximum number of file descriptors (0 = no limit)
    pub max_descriptors: u32,
    /// Warning threshold percentage
    pub warning_threshold_percent: u8,
    /// Check interval in seconds
    pub check_interval_secs: u64,
    /// Track descriptor usage by mount
    pub track_by_mount: bool,
}

/// Process management limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessLimits {
    /// Maximum number of concurrent mount operations
    pub max_concurrent_mounts: u32,
    /// Maximum number of concurrent reconnection attempts
    pub max_concurrent_reconnections: u32,
    /// Operation timeout in seconds
    pub operation_timeout_secs: u64,
    /// Enable operation queuing when limits exceeded
    pub enable_queuing: bool,
    /// Maximum queue size for pending operations
    pub max_queue_size: u32,
}

/// Network resource limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkLimits {
    /// Maximum number of concurrent network connections
    pub max_connections: u32,
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
    /// Maximum data transfer rate per connection (bytes/sec, 0 = no limit)
    pub max_transfer_rate_bps: u64,
    /// Enable connection pooling
    pub enable_connection_pooling: bool,
    /// Maximum connection pool size
    pub max_pool_size: u32,
}

/// Resource enforcement settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementSettings {
    /// Enable automatic resource enforcement
    pub enable_enforcement: bool,
    /// Action when limits exceeded: 'warn', 'throttle', 'reject', 'terminate'
    pub violation_action: ViolationAction,
    /// Grace period before enforcement (seconds)
    pub grace_period_secs: u64,
    /// Enable resource usage reporting
    pub enable_reporting: bool,
    /// Report interval in seconds
    pub report_interval_secs: u64,
    /// Enable adaptive limits based on system resources
    pub enable_adaptive_limits: bool,
}

/// Actions to take when resource limits are violated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationAction {
    /// Only log warnings
    Warn,
    /// Throttle operations
    Throttle,
    /// Reject new operations
    Reject,
    /// Terminate the daemon
    Terminate,
}

/// Current resource usage statistics
#[derive(Debug, Clone)]
pub struct ResourceUsage {
    /// Memory usage statistics
    pub memory: MemoryUsage,
    /// CPU usage statistics
    pub cpu: CpuUsage,
    /// File descriptor usage
    pub file_descriptors: FileDescriptorUsage,
    /// Process statistics
    pub process: ProcessUsage,
    /// Timestamp of the measurement
    pub timestamp: Instant,
}

/// Memory usage statistics
#[derive(Debug, Clone)]
pub struct MemoryUsage {
    /// Total memory used in bytes
    pub total_bytes: u64,
    /// Total memory available in bytes
    pub total_available: u64,
    /// Memory usage percentage
    pub usage_percent: f32,
    /// Virtual memory used in bytes
    pub virtual_bytes: u64,
    /// Resident set size in bytes
    pub rss_bytes: u64,
}

/// CPU usage statistics
#[derive(Debug, Clone)]
pub struct CpuUsage {
    /// Current CPU usage percentage (0-100)
    pub usage_percent: f32,
    /// Average CPU usage over the window
    pub average_percent: f32,
    /// Number of CPU cores
    pub cpu_cores: u32,
    /// Process-specific CPU usage
    pub process_usage: f32,
}

/// File descriptor usage statistics
#[derive(Debug, Clone)]
pub struct FileDescriptorUsage {
    /// Current number of open descriptors
    pub current_count: u32,
    /// Maximum allowed descriptors
    pub max_allowed: u32,
    /// Usage percentage
    pub usage_percent: f32,
    /// Descriptors by category
    pub by_category: HashMap<String, u32>,
}

/// Process statistics
#[derive(Debug, Clone)]
pub struct ProcessUsage {
    /// Current number of active mount operations
    pub active_mounts: u32,
    /// Current number of reconnection attempts
    pub active_reconnections: u32,
    /// Number of pending operations in queue
    pub pending_operations: u32,
    /// Average operation duration
    pub avg_operation_duration_ms: u64,
}

/// Resource limit violation
#[derive(Debug, Clone)]
pub struct ResourceViolation {
    /// Type of resource that exceeded limits
    pub resource_type: ResourceType,
    /// Current usage value
    pub current_value: f64,
    /// Maximum allowed value
    pub max_value: f64,
    /// Usage percentage
    pub usage_percent: f32,
    /// Timestamp of the violation
    pub timestamp: Instant,
    /// Number of consecutive violations
    pub consecutive_count: u32,
}

/// Types of resources that can be limited
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResourceType {
    /// Memory usage
    Memory,
    /// CPU usage
    Cpu,
    /// File descriptors
    FileDescriptors,
    /// Concurrent operations
    ConcurrentOperations,
    /// Network connections
    NetworkConnections,
    /// Operation queue size
    OperationQueue,
}

/// Resource limits manager
pub struct ResourceLimitsManager {
    /// Resource limits configuration
    limits: ResourceLimits,
    /// Current resource usage statistics
    usage: Arc<RwLock<ResourceUsage>>,
    /// System information
    system: Arc<RwLock<System>>,
    /// Semaphores for operation limits
    mount_semaphore: Arc<Semaphore>,
    /// Reconnection semaphore
    reconnection_semaphore: Arc<Semaphore>,
    /// Connection semaphore
    connection_semaphore: Arc<Semaphore>,
    /// Resource violation history
    violations: Arc<RwLock<Vec<ResourceViolation>>>,
    /// Last enforcement timestamp
    last_enforcement: Arc<RwLock<Instant>>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory: MemoryLimits {
                max_memory_bytes: 2 * 1024 * 1024 * 1024, // 2GB
                max_memory_percent: 80,
                warning_threshold_percent: 70,
                enforcement_threshold_percent: 90,
                check_interval_secs: 5,
                enable_tracking: true,
            },
            cpu: CpuLimits {
                max_cpu_percent: 80,
                usage_window_secs: 30,
                check_interval_ms: 1000,
                enable_throttling: true,
                throttle_factor: 0.5,
                grace_period_secs: 10,
            },
            file_descriptors: FileDescriptorLimits {
                max_descriptors: 1024,
                warning_threshold_percent: 80,
                check_interval_secs: 10,
                track_by_mount: true,
            },
            process: ProcessLimits {
                max_concurrent_mounts: 10,
                max_concurrent_reconnections: 5,
                operation_timeout_secs: 300,
                enable_queuing: true,
                max_queue_size: 100,
            },
            network: NetworkLimits {
                max_connections: 100,
                connection_timeout_secs: 30,
                max_transfer_rate_bps: 10 * 1024 * 1024, // 10MB/s
                enable_connection_pooling: true,
                max_pool_size: 20,
            },
            enforcement: EnforcementSettings {
                enable_enforcement: true,
                violation_action: ViolationAction::Throttle,
                grace_period_secs: 30,
                enable_reporting: true,
                report_interval_secs: 60,
                enable_adaptive_limits: true,
            },
        }
    }
}

impl From<crate::config::ResourceLimitsConfig> for ResourceLimits {
    fn from(config: crate::config::ResourceLimitsConfig) -> Self {
        Self {
            memory: MemoryLimits {
                max_memory_bytes: config.max_memory_mb as u64 * 1024 * 1024,
                max_memory_percent: config.max_cpu_percent,
                warning_threshold_percent: 70,
                enforcement_threshold_percent: 90,
                check_interval_secs: 5,
                enable_tracking: true,
            },
            cpu: CpuLimits {
                max_cpu_percent: config.max_cpu_percent,
                usage_window_secs: 30,
                check_interval_ms: 1000,
                enable_throttling: true,
                throttle_factor: 0.5,
                grace_period_secs: 10,
            },
            file_descriptors: FileDescriptorLimits {
                max_descriptors: config.max_file_descriptors,
                warning_threshold_percent: 80,
                check_interval_secs: 10,
                track_by_mount: true,
            },
            process: ProcessLimits {
                max_concurrent_mounts: config.max_concurrent_mounts,
                max_concurrent_reconnections: config.max_concurrent_mounts / 2, // Half of mounts for reconnections
                operation_timeout_secs: 30,
                enable_queuing: true,
                max_queue_size: config.max_concurrent_mounts * 2,
            },
            network: NetworkLimits {
                max_connections: config.max_connections,
                connection_timeout_secs: 30,
                enable_connection_pooling: true,
                max_pool_size: config.max_connections / 2,
                max_transfer_rate_bps: 0, // 0 = unlimited
            },
            enforcement: EnforcementSettings {
                enable_enforcement: config.enable_enforcement,
                violation_action: match config.violation_action.as_str() {
                    "warn" => ViolationAction::Warn,
                    "throttle" => ViolationAction::Throttle,
                    "reject" => ViolationAction::Reject,
                    "terminate" => ViolationAction::Terminate,
                    _ => ViolationAction::Warn,
                },
                grace_period_secs: 30,
                enable_reporting: true,
                report_interval_secs: config.monitoring_interval_secs,
                enable_adaptive_limits: false,
            },
        }
    }
}

#[allow(dead_code)]
impl ResourceLimitsManager {
    /// Create a new resource limits manager
    pub fn new(limits: ResourceLimits) -> Self {
        let mount_semaphore = Arc::new(Semaphore::new(
            limits.process.max_concurrent_mounts as usize,
        ));
        let reconnection_semaphore = Arc::new(Semaphore::new(
            limits.process.max_concurrent_reconnections as usize,
        ));
        let connection_semaphore =
            Arc::new(Semaphore::new(limits.network.max_connections as usize));

        Self {
            limits,
            usage: Arc::new(RwLock::new(ResourceUsage::default())),
            system: Arc::new(RwLock::new(System::new_all())),
            mount_semaphore,
            reconnection_semaphore,
            connection_semaphore,
            violations: Arc::new(RwLock::new(Vec::new())),
            last_enforcement: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Create with default limits
    pub fn with_defaults() -> Self {
        Self::new(ResourceLimits::default())
    }

    /// Start resource monitoring
    pub async fn start_monitoring(&self) -> Result<()> {
        info!("Starting resource limits monitoring");

        let limits = self.limits.clone();
        let usage = self.usage.clone();
        let system = self.system.clone();
        let violations = self.violations.clone();
        let _last_enforcement = self.last_enforcement.clone();

        // Start memory monitoring
        if limits.memory.enable_tracking {
            let memory_limits = limits.memory.clone();
            let memory_usage = usage.clone();
            let memory_system = system.clone();
            let memory_violations = violations.clone();

            tokio::spawn(async move {
                let mut interval =
                    interval(StdDuration::from_secs(memory_limits.check_interval_secs));

                loop {
                    interval.tick().await;

                    if let Err(e) = Self::monitor_memory_usage(
                        &memory_limits,
                        &memory_usage,
                        &memory_system,
                        &memory_violations,
                    )
                    .await
                    {
                        error!("Memory monitoring error: {}", e);
                    }
                }
            });
        }

        // Start CPU monitoring
        let cpu_limits = self.limits.cpu.clone();
        let cpu_usage = self.usage.clone();
        let cpu_system = self.system.clone();
        let cpu_violations = violations.clone();

        tokio::spawn(async move {
            let mut interval = interval(StdDuration::from_millis(cpu_limits.check_interval_ms));

            loop {
                interval.tick().await;

                if let Err(e) =
                    Self::monitor_cpu_usage(&cpu_limits, &cpu_usage, &cpu_system, &cpu_violations)
                        .await
                {
                    error!("CPU monitoring error: {}", e);
                }
            }
        });

        // Start resource reporting
        if self.limits.enforcement.enable_reporting {
            let report_limits = self.limits.clone();
            let report_usage = self.usage.clone();
            let report_violations = violations.clone();

            tokio::spawn(async move {
                let mut interval = interval(StdDuration::from_secs(
                    report_limits.enforcement.report_interval_secs,
                ));

                loop {
                    interval.tick().await;

                    Self::generate_resource_report(
                        &report_limits,
                        &report_usage,
                        &report_violations,
                    )
                    .await;
                }
            });
        }

        info!("Resource limits monitoring started successfully");
        Ok(())
    }

    /// Get a permit for mount operation
    pub async fn acquire_mount_permit(&self) -> Result<()> {
        match self.limits.process.enable_queuing {
            true => {
                match tokio::time::timeout(
                    StdDuration::from_secs(self.limits.process.operation_timeout_secs),
                    self.mount_semaphore.acquire(),
                )
                .await
                {
                    Ok(permit) => {
                        permit?.forget(); // Don't hold the permit
                        Ok(())
                    }
                    Err(_) => Err(anyhow!("Mount operation timeout")),
                }
            }
            false => match self.mount_semaphore.try_acquire() {
                Ok(_) => Ok(()),
                Err(_) => Err(anyhow!("Too many concurrent mount operations")),
            },
        }
    }

    /// Release a mount permit
    pub fn release_mount_permit(&self) {
        self.mount_semaphore.add_permits(1);
    }

    /// Get a permit for reconnection operation
    pub async fn acquire_reconnection_permit(&self) -> Result<()> {
        match self.limits.process.enable_queuing {
            true => {
                match tokio::time::timeout(
                    StdDuration::from_secs(self.limits.process.operation_timeout_secs),
                    self.reconnection_semaphore.acquire(),
                )
                .await
                {
                    Ok(permit) => {
                        permit?.forget();
                        Ok(())
                    }
                    Err(_) => Err(anyhow!("Reconnection operation timeout")),
                }
            }
            false => match self.reconnection_semaphore.try_acquire() {
                Ok(_) => Ok(()),
                Err(_) => Err(anyhow!("Too many concurrent reconnection operations")),
            },
        }
    }

    /// Release a reconnection permit
    pub fn release_reconnection_permit(&self) {
        self.reconnection_semaphore.add_permits(1);
    }

    /// Get a permit for network connection
    pub async fn acquire_connection_permit(&self) -> Result<()> {
        match self.limits.network.enable_connection_pooling {
            true => {
                match tokio::time::timeout(
                    StdDuration::from_secs(self.limits.network.connection_timeout_secs),
                    self.connection_semaphore.acquire(),
                )
                .await
                {
                    Ok(permit) => {
                        permit?.forget();
                        Ok(())
                    }
                    Err(_) => Err(anyhow!("Connection timeout")),
                }
            }
            false => self
                .connection_semaphore
                .try_acquire()
                .map(|_| ())
                .map_err(|_| anyhow!("Too many concurrent connections")),
        }
    }

    /// Release a connection permit
    pub fn release_connection_permit(&self) {
        self.connection_semaphore.add_permits(1);
    }

    /// Check if a resource operation would exceed limits
    pub async fn check_operation_limit(
        &self,
        resource_type: ResourceType,
        count: u32,
    ) -> Result<()> {
        let max_count = match resource_type {
            ResourceType::ConcurrentOperations => self.limits.process.max_concurrent_mounts,
            ResourceType::NetworkConnections => self.limits.network.max_connections,
            ResourceType::OperationQueue => self.limits.process.max_queue_size,
            _ => return Ok(()),
        };

        if count > max_count {
            return Err(anyhow!(
                "Operation would exceed {resource_type:?} limit: {count} > {max_count}"
            ));
        }

        Ok(())
    }

    /// Get current resource usage
    pub async fn get_usage(&self) -> ResourceUsage {
        self.usage.read().await.clone()
    }

    /// Get recent violations
    pub async fn get_violations(&self, limit: usize) -> Vec<ResourceViolation> {
        let violations = self.violations.read().await;
        violations.iter().rev().take(limit).cloned().collect()
    }

    /// Enforce resource limits
    pub async fn enforce_limits(&self) -> Result<bool> {
        if !self.limits.enforcement.enable_enforcement {
            return Ok(true);
        }

        let usage = self.usage.read().await;
        let _violations = self.violations.read().await;
        let last_enforcement = self.last_enforcement.read().await;

        // Check grace period
        if last_enforcement.elapsed()
            < StdDuration::from_secs(self.limits.enforcement.grace_period_secs)
        {
            return Ok(true);
        }

        let mut should_enforce = false;

        // Check memory limits
        if usage.memory.usage_percent > self.limits.memory.enforcement_threshold_percent as f32 {
            should_enforce = true;
            warn!(
                "Memory usage exceeded enforcement threshold: {:.1}%",
                usage.memory.usage_percent
            );
        }

        // Check CPU limits
        if usage.cpu.usage_percent > self.limits.cpu.max_cpu_percent as f32 {
            should_enforce = true;
            warn!("CPU usage exceeded limit: {:.1}%", usage.cpu.usage_percent);
        }

        if should_enforce {
            match self.limits.enforcement.violation_action {
                ViolationAction::Warn => {
                    // Just log warnings
                }
                ViolationAction::Throttle => {
                    // Implement throttling logic
                    warn!("Throttling operations due to resource limits");
                }
                ViolationAction::Reject => {
                    // Reject new operations
                    error!("Rejecting new operations due to resource limits");
                    return Ok(false);
                }
                ViolationAction::Terminate => {
                    // Emergency termination
                    error!("Critical resource limits exceeded, terminating daemon");
                    std::process::exit(1);
                }
            }

            // Update last enforcement timestamp
            let mut last_enforcement = self.last_enforcement.write().await;
            *last_enforcement = Instant::now();
        }

        Ok(should_enforce)
    }

    /// Monitor memory usage and enforce limits
    async fn monitor_memory_usage(
        limits: &MemoryLimits,
        usage: &Arc<RwLock<ResourceUsage>>,
        system: &Arc<RwLock<System>>,
        violations: &Arc<RwLock<Vec<ResourceViolation>>>,
    ) -> Result<()> {
        let mut sys = system.write().await;
        sys.refresh_memory();

        let total_memory = sys.total_memory();
        let used_memory = sys.used_memory();
        let usage_percent = (used_memory as f32 / total_memory as f32) * 100.0;

        {
            let mut current_usage = usage.write().await;
            current_usage.memory = MemoryUsage {
                total_bytes: used_memory,
                total_available: total_memory - used_memory,
                usage_percent,
                virtual_bytes: 0, // Would need process-specific info
                rss_bytes: 0,     // Would need process-specific info
            };
            current_usage.timestamp = Instant::now();
        }

        // Check for violations
        if usage_percent > limits.enforcement_threshold_percent as f32 {
            let violation = ResourceViolation {
                resource_type: ResourceType::Memory,
                current_value: usage_percent as f64,
                max_value: limits.enforcement_threshold_percent as f64,
                usage_percent,
                timestamp: Instant::now(),
                consecutive_count: 1,
            };

            let mut violation_list = violations.write().await;
            violation_list.push(violation);

            if usage_percent > limits.warning_threshold_percent as f32 {
                warn!(
                    "Memory usage high: {:.1}% ({} MB)",
                    usage_percent,
                    used_memory / 1024 / 1024
                );
            }
        }

        Ok(())
    }

    /// Monitor CPU usage and enforce limits
    async fn monitor_cpu_usage(
        limits: &CpuLimits,
        usage: &Arc<RwLock<ResourceUsage>>,
        system: &Arc<RwLock<System>>,
        violations: &Arc<RwLock<Vec<ResourceViolation>>>,
    ) -> Result<()> {
        let mut sys = system.write().await;
        sys.refresh_cpu();

        let cpu_usage = sys.global_cpu_info().cpu_usage();
        let usage_percent = cpu_usage / 100.0;
        let cpu_cores = sys.cpus().len() as u32;

        {
            let mut current_usage = usage.write().await;
            current_usage.cpu = CpuUsage {
                usage_percent,
                average_percent: usage_percent, // Would need averaging logic
                cpu_cores,
                process_usage: 0.0, // Would need process-specific info
            };
            current_usage.timestamp = Instant::now();
        }

        // Check for violations
        if usage_percent > limits.max_cpu_percent as f32 {
            let violation = ResourceViolation {
                resource_type: ResourceType::Cpu,
                current_value: usage_percent as f64,
                max_value: limits.max_cpu_percent as f64,
                usage_percent,
                timestamp: Instant::now(),
                consecutive_count: 1,
            };

            let mut violation_list = violations.write().await;
            violation_list.push(violation);

            if usage_percent > (limits.max_cpu_percent - 10) as f32 {
                warn!("CPU usage high: {:.1}%", usage_percent);
            }
        }

        Ok(())
    }

    /// Generate resource usage report
    async fn generate_resource_report(
        _limits: &ResourceLimits,
        usage: &Arc<RwLock<ResourceUsage>>,
        violations: &Arc<RwLock<Vec<ResourceViolation>>>,
    ) {
        let current_usage = usage.read().await;
        let violation_list = violations.read().await;

        info!("=== Resource Usage Report ===");
        info!(
            "Memory: {} MB / {} MB ({:.1}%)",
            current_usage.memory.total_bytes / 1024 / 1024,
            current_usage.memory.total_available / 1024 / 1024,
            current_usage.memory.usage_percent
        );

        info!(
            "CPU: {:.1}% ({} cores)",
            current_usage.cpu.usage_percent, current_usage.cpu.cpu_cores
        );

        info!(
            "File Descriptors: {} / {} ({:.1}%)",
            current_usage.file_descriptors.current_count,
            current_usage.file_descriptors.max_allowed,
            current_usage.file_descriptors.usage_percent
        );

        info!("Active Mounts: {}", current_usage.process.active_mounts);
        info!(
            "Pending Operations: {}",
            current_usage.process.pending_operations
        );

        if !violation_list.is_empty() {
            warn!("Recent Violations: {}", violation_list.len());
            for (i, violation) in violation_list.iter().rev().take(5).enumerate() {
                warn!(
                    "  {}. {:?}: {:.1}% (limit: {:.1}%)",
                    i + 1,
                    violation.resource_type,
                    violation.usage_percent,
                    violation.max_value
                );
            }
        }
        info!("========================");
    }
}

impl Default for ResourceUsage {
    fn default() -> Self {
        Self {
            memory: MemoryUsage {
                total_bytes: 0,
                total_available: 0,
                usage_percent: 0.0,
                virtual_bytes: 0,
                rss_bytes: 0,
            },
            cpu: CpuUsage {
                usage_percent: 0.0,
                average_percent: 0.0,
                cpu_cores: 1,
                process_usage: 0.0,
            },
            file_descriptors: FileDescriptorUsage {
                current_count: 0,
                max_allowed: 1024,
                usage_percent: 0.0,
                by_category: HashMap::new(),
            },
            process: ProcessUsage {
                active_mounts: 0,
                active_reconnections: 0,
                pending_operations: 0,
                avg_operation_duration_ms: 0,
            },
            timestamp: Instant::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_limits_default() {
        let limits = ResourceLimits::default();

        assert_eq!(limits.memory.max_memory_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(limits.memory.max_memory_percent, 80);
        assert_eq!(limits.cpu.max_cpu_percent, 80);
        assert_eq!(limits.file_descriptors.max_descriptors, 1024);
        assert_eq!(limits.process.max_concurrent_mounts, 10);
        assert_eq!(limits.network.max_connections, 100);
    }

    #[test]
    fn test_resource_limits_manager_creation() {
        let manager = ResourceLimitsManager::with_defaults();

        // Verify semaphores are created with correct permits
        assert_eq!(manager.mount_semaphore.available_permits(), 10);
        assert_eq!(manager.reconnection_semaphore.available_permits(), 5);
        assert_eq!(manager.connection_semaphore.available_permits(), 100);
    }

    #[tokio::test]
    async fn test_mount_permit_acquisition() {
        let manager = ResourceLimitsManager::with_defaults();

        // Should be able to acquire permit
        assert!(manager.acquire_mount_permit().await.is_ok());

        // Permit should be consumed
        assert_eq!(manager.mount_semaphore.available_permits(), 9);

        // Release permit
        manager.release_mount_permit();
        assert_eq!(manager.mount_semaphore.available_permits(), 10);
    }

    #[tokio::test]
    async fn test_operation_limit_check() {
        let manager = ResourceLimitsManager::with_defaults();

        // Should be within limits
        assert!(
            manager
                .check_operation_limit(ResourceType::ConcurrentOperations, 5)
                .await
                .is_ok()
        );

        // Should exceed limits
        assert!(
            manager
                .check_operation_limit(ResourceType::ConcurrentOperations, 15)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_resource_usage_tracking() {
        let manager = ResourceLimitsManager::with_defaults();

        let usage = manager.get_usage().await;
        assert_eq!(usage.memory.total_bytes, 0);
        assert_eq!(usage.cpu.usage_percent, 0.0);
        assert_eq!(usage.file_descriptors.current_count, 0);
    }
}
