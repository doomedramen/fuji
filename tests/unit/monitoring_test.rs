//! Unit tests for monitoring module

use anyhow;
use chrono::Utc;
use fuji::monitoring::{
    health_checks::{
        FileAccessHealthCheck, HealthCheck, HealthCheckRegistry, HealthCheckResult,
        PingHealthCheck, ProtocolHealthCheck,
    },
    retry::{CircuitBreakerState, RetryHandler, RetryPolicy, RetryResult},
};
use fuji::mount::{MountConfig, MountType};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::RwLock;

#[test]
fn test_health_check_registry_creation() {
    let registry = HealthCheckRegistry::new();
    // Registry should create successfully
    assert!(registry.get("file_access").is_none()); // No default checks registered
}

#[test]
fn test_health_check_result_creation() {
    let mut metadata = HashMap::new();
    metadata.insert("test_key".to_string(), "test_value".to_string());

    let result = HealthCheckResult {
        passed: true,
        message: None,
        response_time_ms: 100,
        metadata: metadata.clone(),
    };

    assert!(result.passed);
    assert_eq!(result.response_time_ms, 100);
    assert_eq!(result.metadata, metadata);
}

#[tokio::test]
async fn test_file_access_health_check_nonexistent() {
    let check = FileAccessHealthCheck::new();

    let config = MountConfig::new(
        "nfs://example.com/share".to_string(),
        MountType::NFS {
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

#[tokio::test]
async fn test_ping_health_check_host_extraction() {
    let check = PingHealthCheck::new();

    // Test NFS host extraction
    let nfs_config = MountConfig::new(
        "nfs://example.com/share".to_string(),
        MountType::NFS {
            host: "example.com".to_string(),
            share: "/share".to_string(),
            options: vec![],
        },
        "/mnt/test".into(),
    );

    // Test SMB host extraction
    let smb_config = MountConfig::new(
        "smb://server.example.com/share".to_string(),
        MountType::SMB {
            host: "server.example.com".to_string(),
            share: "share".to_string(),
            username: None,
            password: None,
            domain: None,
            options: vec![],
        },
        "/mnt/test".into(),
    );

    // Host extraction should work for both types
    assert!(check.extract_host(&nfs_config).is_ok());
    assert_eq!(check.extract_host(&nfs_config).unwrap(), "example.com");
    assert!(check.extract_host(&smb_config).is_ok());
    assert_eq!(
        check.extract_host(&smb_config).unwrap(),
        "server.example.com"
    );
}

#[test]
fn test_retry_policy_default() {
    let policy = RetryPolicy::default();
    assert_eq!(policy.initial_delay, Duration::from_secs(1));
    assert_eq!(policy.max_delay, Duration::from_secs(300));
    assert_eq!(policy.multiplier, 2.0);
    assert_eq!(policy.jitter, 0.1);
    assert_eq!(policy.max_attempts, 5);
    assert_eq!(policy.reset_after, Duration::from_secs(300));
}

#[test]
fn test_circuit_breaker_state_creation() {
    let state = CircuitBreakerState::new(3, Duration::from_secs(60));
    assert_eq!(state.failure_count, 0);
    assert!(!state.is_open);
    assert!(state.should_allow_attempt());
    assert_eq!(state.failure_threshold, 3);
    assert_eq!(state.open_timeout, Duration::from_secs(60));
}

#[test]
fn test_circuit_breaker_success_recording() {
    let mut state = CircuitBreakerState::new(3, Duration::from_secs(60));

    // Record some failures
    state.record_failure();
    state.record_failure();
    assert_eq!(state.failure_count, 2);

    // Success should reset
    state.record_success();
    assert_eq!(state.failure_count, 0);
    assert!(!state.is_open);
    assert!(state.should_allow_attempt());
    assert!(state.opened_at.is_none());
}

#[test]
fn test_circuit_breaker_failure_threshold() {
    let mut state = CircuitBreakerState::new(2, Duration::from_secs(60));

    // First failure - circuit still closed
    state.record_failure();
    assert_eq!(state.failure_count, 1);
    assert!(!state.is_open);
    assert!(state.should_allow_attempt());

    // Second failure - circuit opens
    state.record_failure();
    assert_eq!(state.failure_count, 2);
    assert!(state.is_open);
    assert!(!state.should_allow_attempt());
    assert!(state.opened_at.is_some());
}

#[test]
fn test_circuit_breaker_time_until_close() {
    let mut state = CircuitBreakerState::new(1, Duration::from_secs(60));

    // Circuit is closed - no time until close
    assert!(state.time_until_close().is_none());

    // Open circuit
    state.record_failure();
    assert!(state.is_open);
    assert!(state.time_until_close().is_some());

    // Should be less than or equal to open timeout
    let time_until = state.time_until_close().unwrap();
    assert!(time_until <= Duration::from_secs(60));
}

#[tokio::test]
async fn test_retry_handler_creation() {
    let handler = RetryHandler::new();

    // Check default policy
    let policy = handler.get_policy("test_mount").await;
    assert_eq!(policy.initial_delay, Duration::from_secs(1));
    assert_eq!(policy.max_attempts, 5);
}

#[tokio::test]
async fn test_retry_handler_set_policy() {
    let handler = RetryHandler::new();

    let custom_policy = RetryPolicy {
        initial_delay: Duration::from_millis(500),
        max_delay: Duration::from_secs(120),
        multiplier: 1.5,
        jitter: 0.2,
        max_attempts: 10,
        reset_after: Duration::from_secs(600),
    };

    handler
        .set_policy("test_mount", custom_policy.clone())
        .await;

    let retrieved_policy = handler.get_policy("test_mount").await;
    assert_eq!(retrieved_policy.initial_delay, custom_policy.initial_delay);
    assert_eq!(retrieved_policy.max_attempts, custom_policy.max_attempts);
    assert_eq!(retrieved_policy.multiplier, custom_policy.multiplier);
}

#[tokio::test]
async fn test_retry_handler_immediate_success() {
    let handler = RetryHandler::new();

    let result = handler
        .execute_with_retry("test", || async {
            Ok::<_, anyhow::Error>("immediate_success")
        })
        .await
        .unwrap();

    assert_eq!(result.value, Some("immediate_success"));
    assert_eq!(result.attempts, 1);
    assert!(result.last_error.is_none());
    assert!(result.total_time < Duration::from_millis(100));
}

#[tokio::test]
async fn test_retry_handler_with_retries() {
    let handler = RetryHandler::new();

    // Set a small policy for faster testing
    let mut policy = RetryPolicy::default();
    policy.max_attempts = 3;
    policy.initial_delay = Duration::from_millis(10);
    handler.set_policy("test", policy).await;

    let mut attempt_count = 0;
    let result = handler
        .execute_with_retry("test", || async {
            attempt_count += 1;
            if attempt_count < 3 {
                Err(anyhow::anyhow!("Attempt {} failed", attempt_count))
            } else {
                Ok::<_, anyhow::Error>("success_after_retries")
            }
        })
        .await
        .unwrap();

    assert_eq!(result.value, Some("success_after_retries"));
    assert_eq!(result.attempts, 3);
    assert_eq!(attempt_count, 3);
    assert!(result.total_time >= Duration::from_millis(20)); // At least 2 delays of 10ms
}

#[tokio::test]
async fn test_retry_handler_max_attempts_exceeded() {
    let handler = RetryHandler::new();

    // Set a small policy for faster testing
    let mut policy = RetryPolicy::default();
    policy.max_attempts = 2;
    policy.initial_delay = Duration::from_millis(10);
    handler.set_policy("test", policy).await;

    let mut attempt_count = 0;
    let result = handler
        .execute_with_retry("test", || async {
            attempt_count += 1;
            Err(anyhow::anyhow!("Always fails"))
        })
        .await
        .unwrap();

    assert!(result.value.is_none());
    assert_eq!(result.attempts, 2);
    assert_eq!(attempt_count, 2);
    assert!(result.last_error.is_some());
    assert!(result.last_error.unwrap().contains("Always fails"));
}

#[tokio::test]
async fn test_retry_handler_circuit_breaker() {
    let handler = RetryHandler::new();

    // Set a low threshold for faster circuit opening
    let mut policy = RetryPolicy::default();
    policy.max_attempts = 2; // This will be our circuit breaker threshold too
    policy.initial_delay = Duration::from_millis(10);
    handler.set_policy("test", policy).await;

    // Fail multiple times to open circuit breaker
    for _ in 0..5 {
        let _ = handler
            .execute_with_retry("test", || async { Err(anyhow::anyhow!("Always fails")) })
            .await;
    }

    // Check if circuit breaker is open
    let status = handler.get_circuit_breaker_status("test").await;
    assert!(status.is_some());
    assert!(status.unwrap().is_open);

    // Next attempt should be blocked by circuit breaker
    let result = handler
        .execute_with_retry("test", || async {
            Ok::<_, anyhow::Error>("should_not_execute")
        })
        .await
        .unwrap();

    assert!(result.value.is_none());
    assert!(result.last_error.is_some());
    assert!(result.last_error.unwrap().contains("Circuit breaker open"));
}

#[tokio::test]
async fn test_retry_handler_reset() {
    let handler = RetryHandler::new();

    // Cause failures to open circuit breaker
    let _ = handler
        .execute_with_retry("test", || async { Err(anyhow::anyhow!("Always fails")) })
        .await;

    // Reset should close the circuit
    handler.reset("test").await;

    let status = handler.get_circuit_breaker_status("test").await;
    assert!(status.is_some());
    assert!(!status.unwrap().is_open);
}

#[tokio::test]
async fn test_retry_handler_all_circuit_breaker_statuses() {
    let handler = RetryHandler::new();

    // Add policies for multiple mounts
    handler.set_policy("mount1", RetryPolicy::default()).await;
    handler.set_policy("mount2", RetryPolicy::default()).await;

    // Execute operations to create circuit breakers
    let _ = handler
        .execute_with_retry("mount1", || async { Ok::<_, anyhow::Error>("success") })
        .await;

    let _ = handler
        .execute_with_retry("mount2", || async { Err(anyhow::anyhow!("fail")) })
        .await;

    let all_statuses = handler.get_all_circuit_breaker_statuses().await;
    assert!(all_statuses.contains_key("mount1"));
    assert!(all_statuses.contains_key("mount2"));

    // Mount1 should have closed circuit (success)
    assert!(!all_statuses["mount1"].is_open);

    // Mount2 might have open circuit depending on failure count
}

#[test]
fn test_retry_result_creation() {
    let result = RetryResult {
        value: Some("test_value"),
        attempts: 3,
        total_time: Duration::from_millis(150),
        last_error: None,
    };

    assert_eq!(result.value, Some("test_value"));
    assert_eq!(result.attempts, 3);
    assert_eq!(result.total_time, Duration::from_millis(150));
    assert!(result.last_error.is_none());
}

#[test]
fn test_retry_result_failure() {
    let result = RetryResult {
        value: None,
        attempts: 5,
        total_time: Duration::from_secs(10),
        last_error: Some("Operation failed".to_string()),
    };

    assert!(result.value.is_none());
    assert_eq!(result.attempts, 5);
    assert_eq!(result.total_time, Duration::from_secs(10));
    assert_eq!(result.last_error, Some("Operation failed".to_string()));
}

#[tokio::test]
async fn test_health_check_run_check_by_name() {
    use fuji::monitoring::health_checks::run_check;

    // Test valid check names
    let result = run_check("test_mount", "file_access").await;
    assert!(result.is_ok());
    assert!(result.unwrap()); // Simplified version returns true for valid names

    let result = run_check("test_mount", "ping").await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    let result = run_check("test_mount", "protocol").await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    // Test invalid check name
    let result = run_check("test_mount", "invalid_check").await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Unknown health check"));
}

#[test]
fn test_default_timeout_values() {
    let file_check = FileAccessHealthCheck::new();
    assert_eq!(file_check.default_timeout(), Duration::from_secs(10));

    let ping_check = PingHealthCheck::new();
    assert_eq!(ping_check.default_timeout(), Duration::from_secs(10));

    let protocol_check = ProtocolHealthCheck::new();
    assert_eq!(protocol_check.default_timeout(), Duration::from_secs(30));
}

#[test]
fn test_health_check_names() {
    let file_check = FileAccessHealthCheck::new();
    assert_eq!(file_check.name(), "file_access");

    let ping_check = PingHealthCheck::new();
    assert_eq!(ping_check.name(), "ping");

    let protocol_check = ProtocolHealthCheck::new();
    assert_eq!(protocol_check.name(), "protocol");
}

#[test]
fn test_circuit_breaker_backoff_reset() {
    let mut state = CircuitBreakerState::new(3, Duration::from_millis(100));

    // Open the circuit
    state.record_failure();
    state.record_failure();
    state.record_failure();
    assert!(state.is_open);

    // Simulate time passing (more than timeout)
    let past_time = Utc::now() - chrono::Duration::milliseconds(200);
    state.opened_at = Some(past_time);

    // Should now allow attempts
    assert!(state.should_allow_attempt());
}

#[test]
fn test_retry_policy_extreme_values() {
    let policy = RetryPolicy {
        initial_delay: Duration::from_nanos(1),
        max_delay: Duration::from_secs(3600),
        multiplier: 10.0,
        jitter: 1.0,
        max_attempts: 1000,
        reset_after: Duration::from_secs(86400),
    };

    assert_eq!(policy.initial_delay, Duration::from_nanos(1));
    assert_eq!(policy.max_delay, Duration::from_secs(3600));
    assert_eq!(policy.multiplier, 10.0);
    assert_eq!(policy.jitter, 1.0);
    assert_eq!(policy.max_attempts, 1000);
    assert_eq!(policy.reset_after, Duration::from_secs(86400));
}

#[test]
fn test_circuit_breaker_edge_cases() {
    let mut state = CircuitBreakerState::new(0, Duration::from_secs(1));

    // Zero threshold - should open immediately
    state.record_failure();
    assert!(state.is_open);

    // Reset
    state.record_success();
    assert!(!state.is_open);
    assert_eq!(state.failure_count, 0);
}
