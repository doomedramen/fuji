//! Exponential backoff retry logic
//!
//! Provides configurable retry mechanisms with exponential backoff
//! for failed operations and reconnection attempts.

use anyhow::Result;
use backoff::{backoff::Backoff, ExponentialBackoff};
use chrono;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Retry handler for managing retry attempts
pub struct RetryHandler {
    /// Retry policies per mount
    retry_policies: Arc<RwLock<HashMap<String, RetryPolicy>>>,
    /// Circuit breaker states
    circuit_breakers: Arc<RwLock<HashMap<String, CircuitBreakerState>>>,
    /// Default retry policy
    default_policy: RetryPolicy,
}

/// Retry configuration policy
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Initial delay between retries
    pub initial_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Multiplier for exponential backoff
    pub multiplier: f64,
    /// Jitter to add to delay (0.0 to 1.0)
    pub jitter: f64,
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Base delay after which to reset failure count
    pub reset_after: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(300), // 5 minutes
            multiplier: 2.0,
            jitter: 0.1,
            max_attempts: 5,
            reset_after: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Circuit breaker state
#[derive(Debug, Clone)]
pub struct CircuitBreakerState {
    /// Number of consecutive failures
    pub failure_count: u32,
    /// Last failure timestamp
    pub last_failure: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether the circuit is open
    pub is_open: bool,
    /// Time when circuit was opened
    pub opened_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Threshold for opening circuit
    pub failure_threshold: u32,
    /// Time to keep circuit open before trying again
    pub open_timeout: Duration,
}

impl CircuitBreakerState {
    /// Create a new circuit breaker state
    pub fn new(failure_threshold: u32, open_timeout: Duration) -> Self {
        Self {
            failure_count: 0,
            last_failure: None,
            is_open: false,
            opened_at: None,
            failure_threshold,
            open_timeout,
        }
    }

    /// Record a success
    pub fn record_success(&mut self) {
        self.failure_count = 0;
        self.is_open = false;
        self.opened_at = None;
    }

    /// Record a failure
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure = Some(chrono::Utc::now());

        if self.failure_count >= self.failure_threshold && !self.is_open {
            self.is_open = true;
            self.opened_at = Some(chrono::Utc::now());
            warn!(
                "Circuit breaker opened after {} consecutive failures",
                self.failure_count
            );
        }
    }

    /// Check if the circuit should allow an attempt
    pub fn should_allow_attempt(&self) -> bool {
        if !self.is_open {
            return true;
        }

        if let Some(opened_at) = self.opened_at {
            let elapsed = chrono::Utc::now() - opened_at;
            if elapsed.to_std().unwrap_or(Duration::MAX) >= self.open_timeout {
                info!("Circuit breaker timeout elapsed, allowing attempt");
                return true;
            }
        }

        false
    }

    /// Get time until circuit closes
    pub fn time_until_close(&self) -> Option<Duration> {
        if !self.is_open {
            return None;
        }

        if let Some(opened_at) = self.opened_at {
            let elapsed = chrono::Utc::now() - opened_at;
            let elapsed_std = elapsed.to_std().unwrap_or(Duration::MAX);

            if elapsed_std < self.open_timeout {
                Some(self.open_timeout - elapsed_std)
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// Result of a retry attempt
#[derive(Debug, Clone)]
pub struct RetryResult<T> {
    /// The result value
    pub value: Option<T>,
    /// Number of attempts made
    pub attempts: u32,
    /// Total time spent retrying
    pub total_time: Duration,
    /// Last error encountered
    pub last_error: Option<String>,
}

#[allow(dead_code)]
impl RetryHandler {
    /// Create a new retry handler
    pub fn new() -> Self {
        Self {
            retry_policies: Arc::new(RwLock::new(HashMap::new())),
            circuit_breakers: Arc::new(RwLock::new(HashMap::new())),
            default_policy: RetryPolicy::default(),
        }
    }

    /// Set retry policy for a mount
    pub async fn set_policy(&self, mount_id: &str, policy: RetryPolicy) {
        let mut policies = self.retry_policies.write().await;
        policies.insert(mount_id.to_string(), policy);
    }

    /// Get retry policy for a mount
    pub async fn get_policy(&self, mount_id: &str) -> RetryPolicy {
        let policies = self.retry_policies.read().await;
        policies
            .get(mount_id)
            .cloned()
            .unwrap_or_else(|| self.default_policy.clone())
    }

    /// Get or create circuit breaker for a mount
    async fn get_circuit_breaker(&self, mount_id: &str) -> CircuitBreakerState {
        let mut breakers = self.circuit_breakers.write().await;

        if !breakers.contains_key(mount_id) {
            let policy = self.get_policy(mount_id).await;
            breakers.insert(
                mount_id.to_string(),
                CircuitBreakerState::new(policy.max_attempts, Duration::from_secs(60)),
            );
        }

        breakers.get(mount_id).unwrap().clone()
    }

    /// Update circuit breaker state
    async fn update_circuit_breaker(&self, mount_id: &str, success: bool) -> bool {
        let mut breakers = self.circuit_breakers.write().await;

        if let Some(breaker) = breakers.get_mut(mount_id) {
            if success {
                breaker.record_success();
            } else {
                breaker.record_failure();
            }
            true
        } else {
            false
        }
    }

    /// Execute an operation with retry logic
    pub async fn execute_with_retry<F, T, Fut>(
        &self,
        mount_id: &str,
        operation: F,
    ) -> Result<RetryResult<T>>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let policy = self.get_policy(mount_id).await;
        let mut backoff = ExponentialBackoff::default();
        backoff.current_interval = policy.initial_delay;
        backoff.initial_interval = policy.initial_delay;
        backoff.max_interval = policy.max_delay;
        backoff.multiplier = policy.multiplier;
        backoff.max_elapsed_time = Some(Duration::from_secs(3600)); // 1 hour max
        backoff.start_time = std::time::Instant::now();
        // Note: jitter is handled differently in newer backoff versions

        let start_time = std::time::Instant::now();
        let mut attempts = 0;
        let mut last_error: Option<String>;

        loop {
            attempts += 1;

            // Check circuit breaker
            let circuit_breaker = self.get_circuit_breaker(mount_id).await;
            if !circuit_breaker.should_allow_attempt() {
                error!(
                    "Circuit breaker open for mount {}, blocking operation",
                    mount_id
                );
                if let Some(time_until_close) = circuit_breaker.time_until_close() {
                    last_error = Some(format!(
                        "Circuit breaker open, will close in {} seconds",
                        time_until_close.as_secs()
                    ));
                } else {
                    last_error = Some("Circuit breaker open".to_string());
                }
                break;
            }

            // Execute the operation
            match operation().await {
                Ok(value) => {
                    // Record success
                    self.update_circuit_breaker(mount_id, true).await;

                    let total_time = start_time.elapsed();
                    debug!(
                        "Operation succeeded for {} after {} attempts in {:?}",
                        mount_id, attempts, total_time
                    );

                    return Ok(RetryResult {
                        value: Some(value),
                        attempts,
                        total_time,
                        last_error: None,
                    });
                }
                Err(e) => {
                    last_error = Some(e.to_string());

                    // Record failure
                    self.update_circuit_breaker(mount_id, false).await;

                    // Check if we should retry
                    if attempts >= policy.max_attempts {
                        error!(
                            "Max retry attempts ({}) exceeded for mount {}",
                            policy.max_attempts, mount_id
                        );
                        break;
                    }

                    // Calculate next delay
                    if let Some(delay) = backoff.next_backoff() {
                        warn!(
                            "Attempt {} failed for mount {}, retrying in {:?}: {}",
                            attempts, mount_id, delay, e
                        );

                        // Wait before retrying
                        tokio::time::sleep(delay).await;
                    } else {
                        error!("Backoff exhausted for mount {}", mount_id);
                        break;
                    }
                }
            }
        }

        let total_time = start_time.elapsed();
        Ok(RetryResult {
            value: None,
            attempts,
            total_time,
            last_error,
        })
    }

    /// Reset failure count for a mount
    pub async fn reset(&self, mount_id: &str) {
        self.update_circuit_breaker(mount_id, true).await;
        info!("Reset retry state for mount {}", mount_id);
    }

    /// Get circuit breaker status for a mount
    pub async fn get_circuit_breaker_status(&self, mount_id: &str) -> Option<CircuitBreakerState> {
        let breakers = self.circuit_breakers.read().await;
        breakers.get(mount_id).cloned()
    }

    /// Get all circuit breaker statuses
    pub async fn get_all_circuit_breaker_statuses(&self) -> HashMap<String, CircuitBreakerState> {
        let breakers = self.circuit_breakers.read().await;
        breakers.clone()
    }
}

impl Default for RetryHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_retry_policy_default() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.initial_delay, Duration::from_secs(1));
        assert_eq!(policy.max_delay, Duration::from_secs(300));
        assert_eq!(policy.multiplier, 2.0);
        assert_eq!(policy.max_attempts, 5);
    }

    #[tokio::test]
    async fn test_circuit_breaker_state() {
        let mut state = CircuitBreakerState::new(3, Duration::from_secs(60));

        // Initially closed
        assert!(!state.is_open);
        assert!(state.should_allow_attempt());

        // Record failures
        state.record_failure();
        assert_eq!(state.failure_count, 1);
        assert!(!state.is_open);

        state.record_failure();
        assert_eq!(state.failure_count, 2);
        assert!(!state.is_open);

        state.record_failure();
        assert_eq!(state.failure_count, 3);
        assert!(state.is_open);
        assert!(!state.should_allow_attempt());

        // Reset on success
        state.record_success();
        assert_eq!(state.failure_count, 0);
        assert!(!state.is_open);
        assert!(state.should_allow_attempt());
    }

    #[tokio::test]
    async fn test_retry_handler_success() {
        let handler = RetryHandler::new();

        let result = handler
            .execute_with_retry("test", || async { Ok("success") })
            .await
            .unwrap();

        assert_eq!(result.value, Some("success"));
        assert_eq!(result.attempts, 1);
        assert!(result.last_error.is_none());
    }

    #[tokio::test]
    async fn test_retry_handler_failure() {
        let handler = RetryHandler::new();

        // Set a small max attempts for testing
        let mut policy = RetryPolicy::default();
        policy.max_attempts = 3;
        policy.initial_delay = Duration::from_millis(10);
        handler.set_policy("test", policy).await;

        let attempt_count = Arc::new(RwLock::new(0));
        let attempt_count_clone = attempt_count.clone();

        let result = handler
            .execute_with_retry("test", move || {
                let count = attempt_count_clone.clone();
                async move {
                    let mut count = count.write().await;
                    *count += 1;
                    if *count < 3 {
                        Err(anyhow!("Test failure"))
                    } else {
                        Ok("success")
                    }
                }
            })
            .await
            .unwrap();

        assert_eq!(result.value, Some("success"));
        assert_eq!(result.attempts, 3);
        assert_eq!(*attempt_count.read().await, 3);
    }
}
