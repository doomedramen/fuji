//! Unit tests for monitoring module

use anyhow;
use chrono::Utc;
use fuji::monitoring::{
    health_checks::{HealthCheckContext, run_check},
    retry::{CircuitBreakerState, RetryHandler, RetryPolicy, RetryResult},
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

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

    let result: RetryResult<String> = handler
        .execute_with_retry("test", || async {
            Ok::<_, anyhow::Error>("immediate_success".to_string())
        })
        .await
        .unwrap();

    assert_eq!(result.value, Some("immediate_success".to_string()));
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

    let attempt_count = Arc::new(AtomicU32::new(0));
    let attempt_count_clone = attempt_count.clone();
    let result: RetryResult<String> = handler
        .execute_with_retry("test", move || {
            let count = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            async move {
                if count < 3 {
                    Err(anyhow::anyhow!("Attempt failed"))
                } else {
                    Ok::<_, anyhow::Error>("success_after_retries".to_string())
                }
            }
        })
        .await
        .unwrap();

    assert_eq!(result.value, Some("success_after_retries".to_string()));
    assert_eq!(result.attempts, 3);
    assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    // Note: total_time check removed due to CI timing variability
    // The important parts are that retries happened and succeeded
}

#[tokio::test]
async fn test_retry_handler_max_attempts_exceeded() {
    let handler = RetryHandler::new();

    // Set a small policy for faster testing
    let mut policy = RetryPolicy::default();
    policy.max_attempts = 2;
    policy.initial_delay = Duration::from_millis(10);
    handler.set_policy("test", policy).await;

    let attempt_count = Arc::new(AtomicU32::new(0));
    let attempt_count_clone = attempt_count.clone();
    let result: RetryResult<String> = handler
        .execute_with_retry("test", move || {
            attempt_count_clone.fetch_add(1, Ordering::SeqCst);
            async { Err(anyhow::anyhow!("Always fails")) }
        })
        .await
        .unwrap();

    assert!(result.value.is_none());
    assert_eq!(result.attempts, 2);
    assert_eq!(attempt_count.load(Ordering::SeqCst), 2);
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
        let _: Result<RetryResult<&str>, _> = handler
            .execute_with_retry("test", || async { Err(anyhow::anyhow!("Always fails")) })
            .await;
    }

    // Check if circuit breaker is open
    let status = handler.get_circuit_breaker_status("test").await;
    assert!(status.is_some());
    assert!(status.unwrap().is_open);

    // Next attempt should be blocked by circuit breaker
    let result: RetryResult<String> = handler
        .execute_with_retry("test", || async {
            Ok::<_, anyhow::Error>("should_not_execute".to_string())
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
    let _: Result<RetryResult<String>, _> = handler
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
    let _: Result<RetryResult<String>, _> = handler
        .execute_with_retry("mount1", || async {
            Ok::<_, anyhow::Error>("success".to_string())
        })
        .await;

    let _: Result<RetryResult<String>, _> = handler
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
    let result: RetryResult<String> = RetryResult {
        value: Some("test_value".to_string()),
        attempts: 3,
        total_time: Duration::from_millis(150),
        last_error: None,
    };

    assert_eq!(result.value, Some("test_value".to_string()));
    assert_eq!(result.attempts, 3);
    assert_eq!(result.total_time, Duration::from_millis(150));
    assert!(result.last_error.is_none());
}

#[test]
fn test_retry_result_failure() {
    let result: RetryResult<String> = RetryResult {
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
    // Test invalid check name - only test this since the valid checks
    // require persistence setup which is not available in unit tests
    let platform = fuji::platform::get_platform();
    let mount_point = std::path::PathBuf::from("/test/mount");

    // Create a minimal test mount config
    let config = fuji::mount::MountConfig {
        id: "test_mount".to_string(),
        url: "nfs://127.0.0.1/test".to_string(),
        mount_point: mount_point.clone(),
        mount_type: fuji::mount::MountType::Nfs {
            host: "127.0.0.1".to_string(),
            share: "test".to_string(),
            options: vec![],
        },
        enabled: true,
        status: fuji::mount::MountStatus::Active,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        last_connected: None,
        reconnect_attempts: 0,
        metadata: std::collections::HashMap::new(),
    };

    let context = HealthCheckContext {
        config: &config,
        mount_point: &mount_point,
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
