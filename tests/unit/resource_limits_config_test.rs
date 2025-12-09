//! Unit tests for resource limits configuration
//!
//! Tests to prevent future issues like the memory limit bug where
//! max_memory_percent was incorrectly set from config.max_cpu_percent instead of a fixed 70%.

use fuji::config::{Config, ResourceLimitsConfig};
use fuji::security::resource_limits::{
    ResourceLimits, ResourceLimitsManager, ResourceType, ViolationAction,
};
use std::collections::HashMap;
use tempfile::TempDir;

/// Test that resource limits configuration parsing works correctly
#[test]
fn test_resource_limits_config_parsing() {
    // Test default configuration
    let config = ResourceLimitsConfig::default();
    assert_eq!(config.max_memory_mb, 1024);
    assert_eq!(config.max_cpu_percent, 80);
    assert_eq!(config.max_concurrent_mounts, 10);
    assert_eq!(config.max_file_descriptors, 1024);
    assert_eq!(config.max_connections, 100);
    assert!(config.enable_enforcement);
    assert_eq!(config.violation_action, "throttle");
    assert_eq!(config.monitoring_interval_secs, 30);

    // Test that violation action parsing works
    let valid_actions = ["warn", "throttle", "reject", "terminate"];
    for action in valid_actions.iter() {
        let mut config = ResourceLimitsConfig::default();
        config.violation_action = action.to_string();

        let resource_limits: ResourceLimits = config.clone().into();
        match *action {
            "warn" => {
                if let ViolationAction::Warn = resource_limits.enforcement.violation_action {
                } else {
                    panic!("Expected ViolationAction::Warn");
                }
            }
            "throttle" => {
                if let ViolationAction::Throttle = resource_limits.enforcement.violation_action {
                } else {
                    panic!("Expected ViolationAction::Throttle");
                }
            }
            "reject" => {
                if let ViolationAction::Reject = resource_limits.enforcement.violation_action {
                } else {
                    panic!("Expected ViolationAction::Reject");
                }
            }
            "terminate" => {
                if let ViolationAction::Terminate = resource_limits.enforcement.violation_action {
                } else {
                    panic!("Expected ViolationAction::Terminate");
                }
            }
            _ => {
                if let ViolationAction::Warn = resource_limits.enforcement.violation_action {
                } else {
                    panic!("Expected default ViolationAction::Warn");
                }
            }
        }
    }

    // Test that invalid violation action defaults to "warn"
    let mut config = ResourceLimitsConfig::default();
    config.violation_action = "invalid_action".to_string();
    let resource_limits: ResourceLimits = config.clone().into();
    if let ViolationAction::Warn = resource_limits.enforcement.violation_action {
    } else {
        panic!("Expected default ViolationAction::Warn for invalid action");
    }
}

/// Test that the ResourceLimits::from conversion correctly sets memory limit to 70%
/// and not from the CPU limit config
#[test]
fn test_resource_limits_from_conversion() {
    // Test with different CPU limits to ensure memory limit is always 70%
    let test_cpu_limits = [10, 30, 50, 70, 90, 100];

    for cpu_limit in test_cpu_limits.iter() {
        let config = ResourceLimitsConfig {
            max_memory_mb: 2048,
            max_cpu_percent: *cpu_limit,
            max_concurrent_mounts: 20,
            max_file_descriptors: 2048,
            max_connections: 200,
            enable_enforcement: false,
            violation_action: "reject".to_string(),
            monitoring_interval_secs: 60,
        };

        let resource_limits: ResourceLimits = config.clone().into();

        // CRITICAL: Memory limit should always be 70%, not from CPU percent
        assert_eq!(
            resource_limits.memory.max_memory_percent, 70,
            "Memory limit should be 70% regardless of CPU limit (CPU was set to {})",
            cpu_limit
        );

        // CPU limit should be correctly set from config
        assert_eq!(
            resource_limits.cpu.max_cpu_percent, *cpu_limit,
            "CPU limit should be set from config"
        );

        // Memory bytes should be correctly converted from MB
        assert_eq!(
            resource_limits.memory.max_memory_bytes,
            2048 * 1024 * 1024,
            "Memory bytes should be correctly converted from MB"
        );

        // Enforcement should be disabled
        assert!(!resource_limits.enforcement.enable_enforcement);

        // Violation action should be "reject"
        if let ViolationAction::Reject = resource_limits.enforcement.violation_action {
        } else {
            panic!("Expected ViolationAction::Reject");
        }

        // Monitoring interval should be set from config
        assert_eq!(
            resource_limits.enforcement.report_interval_secs, 60,
            "Monitoring interval should be set from config"
        );
    }
}

/// Test the specific bug scenario: memory limit should not copy from CPU limit
#[test]
fn test_memory_limit_bug_regression() {
    // This test ensures the memory limit bug doesn't recur
    // The bug was that max_memory_percent was set from config.max_cpu_percent

    let mut config = ResourceLimitsConfig::default();

    // Try various CPU limits
    for cpu_limit in [10, 25, 50, 75, 90, 100].iter() {
        config.max_cpu_percent = *cpu_limit;

        let resource_limits: ResourceLimits = config.clone().into();

        // Memory limit should ALWAYS be 70%, regardless of CPU limit
        assert_eq!(
            resource_limits.memory.max_memory_percent, 70,
            "REGRESSION: Memory limit incorrectly set to CPU limit of {}%. Should be 70%!",
            cpu_limit
        );
    }

    // Also test with different memory MB values to ensure they don't affect percentage
    for memory_mb in [512, 1024, 2048, 4096].iter() {
        config.max_memory_mb = *memory_mb;
        config.max_cpu_percent = 80; // Fixed CPU for this part

        let resource_limits: ResourceLimits = config.clone().into();

        // Memory percentage should still be 70%
        assert_eq!(
            resource_limits.memory.max_memory_percent, 70,
            "Memory percentage should be 70% even when memory MB is {}",
            memory_mb
        );

        // Memory bytes should match the MB value
        assert_eq!(
            resource_limits.memory.max_memory_bytes,
            *memory_mb as u64 * 1024 * 1024,
            "Memory bytes should match configured MB value"
        );
    }
}

/// Test ResourceLimitsManager creation with configuration
#[tokio::test]
async fn test_resource_limits_manager_creation() {
    let config = ResourceLimitsConfig {
        max_memory_mb: 1024,
        max_cpu_percent: 60,
        max_concurrent_mounts: 15,
        max_file_descriptors: 2048,
        max_connections: 150,
        enable_enforcement: true,
        violation_action: "warn".to_string(),
        monitoring_interval_secs: 45,
    };

    let resource_limits: ResourceLimits = config.clone().into();
    let manager = ResourceLimitsManager::new(resource_limits);

    // Check that the manager was created with correct limits
    let usage = manager.get_usage().await;
    assert_eq!(usage.memory.usage_percent, 0.0); // Initial usage should be 0

    // Test permit acquisition
    assert!(manager.acquire_mount_permit().await.is_ok());
    manager.release_mount_permit();

    assert!(manager.acquire_connection_permit().await.is_ok());
    manager.release_connection_permit();

    assert!(manager.acquire_reconnection_permit().await.is_ok());
    manager.release_reconnection_permit();
}

/// Test resource limits enforcement behavior
#[tokio::test]
async fn test_resource_limits_enforcement() {
    let config = ResourceLimitsConfig {
        max_memory_mb: 512,
        max_cpu_percent: 50,
        max_concurrent_mounts: 5,
        max_file_descriptors: 512,
        max_connections: 50,
        enable_enforcement: true,
        violation_action: "terminate".to_string(), // Use terminate for testing
        monitoring_interval_secs: 1,
    };

    let resource_limits: ResourceLimits = config.clone().into();
    let manager = ResourceLimitsManager::new(resource_limits);

    // Test that enforcement settings are correctly applied
    let enforcement_result = manager.enforce_limits().await;

    // Should return Ok(true) when no limits are exceeded
    assert!(enforcement_result.is_ok());

    // Check operation limits
    assert!(
        manager
            .check_operation_limit(ResourceType::ConcurrentOperations, 3)
            .await
            .is_ok()
    );

    // Should exceed limits
    assert!(
        manager
            .check_operation_limit(ResourceType::ConcurrentOperations, 10)
            .await
            .is_err()
    );
}

/// Test daemon startup with minimal configuration
#[tokio::test]
async fn test_daemon_startup_with_resource_limits() {
    // Create a temporary config directory
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test_config.toml");

    // Create minimal config with custom resource limits
    let config = Config {
        version: "1.0".to_string(),
        mounts: HashMap::new(),
        reconnection: fuji::config::ReconnectionConfig::default(),
        global: fuji::config::GlobalConfig {
            health_check_interval_secs: 60,
            log_level: "debug".to_string(),
            auto_mount: false, // Disabled for test
            resource_limits: ResourceLimitsConfig {
                max_memory_mb: 512,
                max_cpu_percent: 60,
                max_concurrent_mounts: 3,
                max_file_descriptors: 256,
                max_connections: 25,
                enable_enforcement: false, // Disabled to prevent terminations during test
                violation_action: "warn".to_string(),
                monitoring_interval_secs: 5,
            },
        },
        platform: fuji::config::PlatformConfig {
            socket_path: Some(temp_dir.path().join("test.sock")),
            config_dir: Some(temp_dir.path().to_path_buf()),
            mount_dir: Some(temp_dir.path().join("mounts")),
        },
    };

    // Save config to file
    let content = toml::to_string_pretty(&config).unwrap();
    std::fs::write(&config_path, content).unwrap();

    // Load config to verify it was saved correctly
    let loaded_content = std::fs::read_to_string(&config_path).unwrap();
    let loaded_config: Config = toml::from_str(&loaded_content).unwrap();

    assert_eq!(loaded_config.global.resource_limits.max_cpu_percent, 60);
    assert_eq!(loaded_config.global.resource_limits.max_memory_mb, 512);
    assert_eq!(
        loaded_config.global.resource_limits.max_concurrent_mounts,
        3
    );
    assert!(!loaded_config.global.resource_limits.enable_enforcement);

    // Test conversion to ResourceLimits
    let resource_limits: ResourceLimits = loaded_config.global.resource_limits.clone().into();
    assert_eq!(resource_limits.memory.max_memory_percent, 70); // Should be fixed at 70%
    assert_eq!(resource_limits.cpu.max_cpu_percent, 60);
    assert_eq!(resource_limits.process.max_concurrent_mounts, 3);
    assert_eq!(resource_limits.network.max_connections, 25);
    assert!(!resource_limits.enforcement.enable_enforcement);
}

/// Property-based test style check with multiple random configurations
#[test]
fn test_resource_limits_conversion_property_based() {
    // Test a variety of configurations to ensure memory limit is always 70%
    let test_cases = vec![
        (512, 10, 5, 128, 20, "warn", 10),
        (1024, 20, 10, 256, 50, "throttle", 30),
        (2048, 30, 15, 512, 100, "reject", 60),
        (4096, 40, 20, 1024, 200, "terminate", 120),
        (8192, 50, 25, 2048, 500, "warn", 300),
        (16000, 60, 30, 4096, 1000, "throttle", 600),
        (128, 70, 1, 64, 10, "reject", 5),
        (256, 80, 2, 128, 15, "terminate", 15),
        (512, 90, 3, 256, 25, "warn", 25),
        (1024, 100, 50, 1024, 10000, "throttle", 3600),
    ];

    for (memory_mb, cpu_percent, mounts, file_descriptors, connections, action, interval) in
        test_cases
    {
        let config = ResourceLimitsConfig {
            max_memory_mb: memory_mb,
            max_cpu_percent: cpu_percent,
            max_concurrent_mounts: mounts,
            max_file_descriptors: file_descriptors,
            max_connections: connections,
            enable_enforcement: true,
            violation_action: action.to_string(),
            monitoring_interval_secs: interval,
        };

        let resource_limits: ResourceLimits = config.clone().into();

        // ALWAYS verify memory limit is 70%
        assert_eq!(
            resource_limits.memory.max_memory_percent, 70,
            "Memory limit must be 70% for config: memory_mb={}, cpu_percent={}",
            memory_mb, cpu_percent
        );

        // Verify other limits are correctly converted
        assert_eq!(
            resource_limits.memory.max_memory_bytes,
            memory_mb as u64 * 1024 * 1024
        );
        assert_eq!(resource_limits.cpu.max_cpu_percent, cpu_percent);
        assert_eq!(resource_limits.process.max_concurrent_mounts, mounts);
        assert_eq!(
            resource_limits.file_descriptors.max_descriptors,
            file_descriptors
        );
        assert_eq!(resource_limits.network.max_connections, connections);
        assert_eq!(resource_limits.enforcement.report_interval_secs, interval);

        // Verify violation action
        match action {
            "warn" => {
                if let ViolationAction::Warn = resource_limits.enforcement.violation_action {
                } else {
                    panic!("Expected ViolationAction::Warn");
                }
            }
            "throttle" => {
                if let ViolationAction::Throttle = resource_limits.enforcement.violation_action {
                } else {
                    panic!("Expected ViolationAction::Throttle");
                }
            }
            "reject" => {
                if let ViolationAction::Reject = resource_limits.enforcement.violation_action {
                } else {
                    panic!("Expected ViolationAction::Reject");
                }
            }
            "terminate" => {
                if let ViolationAction::Terminate = resource_limits.enforcement.violation_action {
                } else {
                    panic!("Expected ViolationAction::Terminate");
                }
            }
            _ => {
                if let ViolationAction::Warn = resource_limits.enforcement.violation_action {
                } else {
                    panic!("Expected default ViolationAction::Warn");
                }
            }
        }
    }
}

/// Test that the default ResourceLimits configuration has correct memory percentage
#[test]
fn test_default_resource_limits_memory_percentage() {
    let defaults = ResourceLimits::default();

    // The default should have 80% memory limit (from direct default, not from conversion)
    assert_eq!(defaults.memory.max_memory_percent, 80);
    assert_eq!(defaults.cpu.max_cpu_percent, 80);
}

/// Test edge cases and boundary values
#[test]
fn test_resource_limits_edge_cases() {
    // Test minimum values
    let mut config = ResourceLimitsConfig {
        max_memory_mb: 0,
        max_cpu_percent: 0,
        max_concurrent_mounts: 1,
        max_file_descriptors: 64,
        max_connections: 10,
        enable_enforcement: false,
        violation_action: "".to_string(), // Empty string
        monitoring_interval_secs: 1,
    };

    let resource_limits: ResourceLimits = config.clone().into();
    assert_eq!(resource_limits.memory.max_memory_percent, 70);
    assert_eq!(resource_limits.cpu.max_cpu_percent, 0);

    // Test empty violation action defaults to warn
    if let ViolationAction::Warn = resource_limits.enforcement.violation_action {
    } else {
        panic!("Expected default ViolationAction::Warn");
    }

    // Test maximum values
    config = ResourceLimitsConfig {
        max_memory_mb: 16384, // 16GB max from validation (16 * 1024)
        max_cpu_percent: 100,
        max_concurrent_mounts: 100,
        max_file_descriptors: 65536,
        max_connections: 10000,
        enable_enforcement: true,
        violation_action: "terminate".to_string(),
        monitoring_interval_secs: 3600,
    };

    let resource_limits: ResourceLimits = config.into();
    assert_eq!(resource_limits.memory.max_memory_percent, 70);
    assert_eq!(resource_limits.cpu.max_cpu_percent, 100);
    if let ViolationAction::Terminate = resource_limits.enforcement.violation_action {
    } else {
        panic!("Expected ViolationAction::Terminate");
    }
}

/// Test that resource limits are properly applied in semaphore counts
#[tokio::test]
async fn test_resource_limits_semaphores() {
    let config = ResourceLimitsConfig {
        max_concurrent_mounts: 7,
        max_connections: 42,
        ..Default::default()
    };

    let resource_limits: ResourceLimits = config.clone().into();
    let manager = ResourceLimitsManager::new(resource_limits);

    // Acquire all mount permits
    for _ in 0..7 {
        assert!(manager.acquire_mount_permit().await.is_ok());
    }

    // Next one should fail
    assert!(manager.acquire_mount_permit().await.is_err());

    // Release one
    manager.release_mount_permit();

    // Should be able to acquire again
    assert!(manager.acquire_mount_permit().await.is_ok());

    // Test connection permits
    for _ in 0..42 {
        assert!(manager.acquire_connection_permit().await.is_ok());
    }

    // Next one should fail
    assert!(manager.acquire_connection_permit().await.is_err());

    // Clean up
    for _ in 0..42 {
        manager.release_connection_permit();
    }
}
