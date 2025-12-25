//! Custom assertions for integration tests

#![allow(dead_code)]

use anyhow::{Context, Result};
use std::future::Future;
use std::path::Path;
use std::time::Duration;
use tokio::time::{sleep, timeout};

use super::daemon::TestDaemon;

/// Assert that the daemon is running and responsive
pub async fn assert_daemon_running(socket_path: &Path) -> Result<()> {
    if !socket_path.exists() {
        anyhow::bail!("Socket file {:?} does not exist", socket_path);
    }

    Ok(())
}

/// Assert that a mount is active
pub async fn assert_mount_active(daemon: &TestDaemon, mount_id: &str) -> Result<()> {
    let status = daemon
        .status(true)
        .await
        .context("Failed to get daemon status")?;

    if !status.contains(mount_id) {
        anyhow::bail!("Mount {} not found in status", mount_id);
    }

    if !status.contains("Active") && !status.contains("\"Active\"") {
        eprintln!("Status output:\n{}", status);
        anyhow::bail!("Mount {} is not active", mount_id);
    }

    Ok(())
}

/// Assert that a file exists
pub async fn assert_file_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("File {:?} does not exist", path);
    }

    Ok(())
}

/// Assert that a file does not exist
pub async fn assert_file_not_exists(path: &Path) -> Result<()> {
    if path.exists() {
        anyhow::bail!("File {:?} should not exist", path);
    }

    Ok(())
}

/// Assert that a directory is accessible (exists and can be read)
pub async fn assert_directory_accessible(path: &Path) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("Directory {:?} does not exist", path);
    }

    if !path.is_dir() {
        anyhow::bail!("Path {:?} is not a directory", path);
    }

    // Try to read directory
    let _dir = tokio::fs::read_dir(path)
        .await
        .with_context(|| format!("Failed to read directory {:?}", path))?;

    Ok(())
}

/// Wait for a condition to become true
///
/// Polls the condition function until it returns true or timeout is reached.
///
/// # Arguments
/// * `condition` - Async function that returns bool
/// * `timeout_duration` - Maximum time to wait
/// * `poll_interval` - Time between polls
///
/// # Example
/// ```no_run
/// # use anyhow::Result;
/// # use std::time::Duration;
/// # use std::path::Path;
/// # use common::assertions::wait_for_condition;
/// # async fn example() -> Result<()> {
/// wait_for_condition(
///     || async { Path::new("/tmp/file").exists() },
///     Duration::from_secs(10),
///     Duration::from_millis(100),
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub async fn wait_for_condition<F, Fut>(
    mut condition: F,
    timeout_duration: Duration,
    poll_interval: Duration,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let start = std::time::Instant::now();

    loop {
        if condition().await {
            return Ok(());
        }

        if start.elapsed() >= timeout_duration {
            anyhow::bail!("Condition not met within {:?}", timeout_duration);
        }

        sleep(poll_interval).await;
    }
}

/// Retry an operation with exponential backoff
///
/// # Arguments
/// * `operation` - Async operation to retry
/// * `max_attempts` - Maximum number of attempts
/// * `initial_delay` - Initial delay between attempts
///
/// # Example
/// ```no_run
/// # use anyhow::Result;
/// # use std::time::Duration;
/// # use common::assertions::retry_with_backoff;
/// # async fn example() -> Result<()> {
/// let result = retry_with_backoff(
///     || async { Ok::<_, anyhow::Error>(42) },
///     5,
///     Duration::from_millis(100),
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub async fn retry_with_backoff<F, Fut, T>(
    mut operation: F,
    max_attempts: u32,
    initial_delay: Duration,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut delay = initial_delay;

    for attempt in 1..=max_attempts {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) if attempt == max_attempts => {
                return Err(e).context(format!("Operation failed after {} attempts", max_attempts));
            }
            Err(e) => {
                eprintln!(
                    "Attempt {}/{} failed: {}. Retrying in {:?}...",
                    attempt, max_attempts, e, delay
                );
                sleep(delay).await;
                delay = delay.mul_f32(2.0); // Exponential backoff
            }
        }
    }

    unreachable!()
}

/// Assert that an operation completes within a timeout
///
/// # Example
/// ```no_run
/// # use anyhow::Result;
/// # use std::time::Duration;
/// # use common::assertions::assert_completes_within;
/// # async fn example() -> Result<()> {
/// assert_completes_within(
///     Duration::from_secs(5),
///     async { Ok::<_, anyhow::Error>(()) }
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub async fn assert_completes_within<F, Fut, T>(
    timeout_duration: Duration,
    operation: F,
) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    match timeout(timeout_duration, operation()).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(e)) => Err(e),
        Err(_) => anyhow::bail!("Operation did not complete within {:?}", timeout_duration),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wait_for_condition_success() -> Result<()> {
        let mut counter = 0;

        wait_for_condition(
            || {
                counter += 1;
                async move { counter >= 3 }
            },
            Duration::from_secs(1),
            Duration::from_millis(10),
        )
        .await?;

        assert!(counter >= 3);
        Ok(())
    }

    #[tokio::test]
    async fn test_wait_for_condition_timeout() {
        let result = wait_for_condition(
            || async { false },
            Duration::from_millis(100),
            Duration::from_millis(10),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_retry_with_backoff_success() -> Result<()> {
        let mut attempts = 0;

        let result = retry_with_backoff(
            || {
                attempts += 1;
                async move {
                    if attempts >= 3 {
                        Ok(42)
                    } else {
                        anyhow::bail!("Not yet")
                    }
                }
            },
            5,
            Duration::from_millis(10),
        )
        .await?;

        assert_eq!(result, 42);
        assert_eq!(attempts, 3);
        Ok(())
    }

    #[tokio::test]
    async fn test_retry_with_backoff_failure() {
        let result: Result<i32> = retry_with_backoff(
            || async { anyhow::bail!("Always fails") },
            3,
            Duration::from_millis(10),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_assert_completes_within_success() -> Result<()> {
        let result = assert_completes_within(Duration::from_secs(1), || async {
            sleep(Duration::from_millis(10)).await;
            Ok(42)
        })
        .await?;

        assert_eq!(result, 42);
        Ok(())
    }

    #[tokio::test]
    async fn test_assert_completes_within_timeout() {
        let result = assert_completes_within(Duration::from_millis(10), || async {
            sleep(Duration::from_secs(1)).await;
            Ok::<_, anyhow::Error>(42)
        })
        .await;

        assert!(result.is_err());
    }
}
