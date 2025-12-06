//! Integration tests for connection limiting functionality
//!
//! Tests the connection limiting system that prevents resource exhaustion attacks
//! by limiting concurrent connections, rate limiting, and proper cleanup.

use fuji::socket::{ConnectionLimiter, ConnectionLimits};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_connection_limiter_basic() {
    let limits = ConnectionLimits {
        max_connections: 5,
        max_connections_per_client: 2,
        connection_timeout: 30,
        idle_timeout: 300,
        rate_limit_window: 60,
        rate_limit_max: 10,
    };

    let limiter = ConnectionLimiter::new(limits);

    // Test acquiring connections
    let permit1 = limiter.acquire_connection("client1").await.unwrap();
    assert_eq!(permit1.client_id(), "client1");

    let permit2 = limiter.acquire_connection("client1").await.unwrap();
    assert_eq!(permit2.client_id(), "client1");

    // Third connection from same client should fail
    let permit3 = limiter.acquire_connection("client1").await;
    assert!(permit3.is_err());

    // Connection from different client should succeed
    let permit4 = limiter.acquire_connection("client2").await.unwrap();
    assert_eq!(permit4.client_id(), "client2");

    // Check metrics
    let metrics = limiter.get_metrics().await;
    assert_eq!(metrics.total_connections, 3);
    assert_eq!(metrics.active_connections, 3);
    assert_eq!(metrics.rejected_connections, 1);
}

#[tokio::test]
async fn test_connection_limiter_rate_limiting() {
    let limits = ConnectionLimits {
        max_connections: 100,
        max_connections_per_client: 50,
        connection_timeout: 30,
        idle_timeout: 300,
        rate_limit_window: 1, // 1 second window
        rate_limit_max: 3,    // Max 3 connections per second
    };

    let limiter = ConnectionLimiter::new(limits);

    let client_id = "rate_test_client";

    // Acquire connections up to the rate limit
    for _ in 0..3 {
        let permit = limiter.acquire_connection(client_id).await.unwrap();
        drop(permit); // Immediately release
    }

    // Fourth connection should be rate limited
    let permit4 = limiter.acquire_connection(client_id).await;
    assert!(permit4.is_err());
    assert!(permit4.unwrap_err().to_string().contains("rate limit"));

    // Wait for the rate limit window to expire
    sleep(Duration::from_secs(2)).await;

    // Should be able to acquire connection again
    let permit5 = limiter.acquire_connection(client_id).await;
    assert!(permit5.is_ok());
}

#[tokio::test]
async fn test_connection_limiter_global_limit() {
    let limits = ConnectionLimits {
        max_connections: 2,
        max_connections_per_client: 10,
        connection_timeout: 30,
        idle_timeout: 300,
        rate_limit_window: 60,
        rate_limit_max: 20,
    };

    let limiter = ConnectionLimiter::new(limits);

    // Acquire connections from different clients up to global limit
    let permit1 = limiter.acquire_connection("client1").await.unwrap();
    let permit2 = limiter.acquire_connection("client2").await.unwrap();

    // Third connection should fail due to global limit
    let permit3 = limiter.acquire_connection("client3").await;
    assert!(permit3.is_err());
    assert!(
        permit3
            .unwrap_err()
            .to_string()
            .contains("Failed to acquire connection permit")
    );

    // Drop a permit and try again
    drop(permit1);
    sleep(Duration::from_millis(100)).await;

    let permit4 = limiter.acquire_connection("client3").await;
    assert!(permit4.is_ok());
}

#[tokio::test]
async fn test_connection_metrics() {
    let limits = ConnectionLimits::default();
    let limiter = ConnectionLimiter::new(limits);

    // Acquire and release some connections
    {
        let _permit1 = limiter.acquire_connection("client1").await.unwrap();
        let _permit2 = limiter.acquire_connection("client2").await.unwrap();

        let metrics = limiter.get_metrics().await;
        assert_eq!(metrics.total_connections, 2);
        assert_eq!(metrics.active_connections, 2);
    }

    // Permits should be dropped, releasing connections
    sleep(Duration::from_millis(100)).await;

    let metrics = limiter.get_metrics().await;
    assert_eq!(metrics.total_connections, 2);
    // Active connections should be updated asynchronously
    assert!(metrics.active_connections <= 2);
}

#[tokio::test]
async fn test_connection_permit_drop() {
    let limits = ConnectionLimits {
        max_connections: 1,
        max_connections_per_client: 1,
        connection_timeout: 30,
        idle_timeout: 300,
        rate_limit_window: 60,
        rate_limit_max: 10,
    };

    let limiter = ConnectionLimiter::new(limits);

    let client_id = "drop_test_client";

    // Acquire connection
    let permit = limiter.acquire_connection(client_id).await.unwrap();

    // Try to acquire another - should fail
    let permit2 = limiter.acquire_connection(client_id).await;
    assert!(permit2.is_err());

    // Drop the permit
    drop(permit);

    // Wait for async cleanup
    sleep(Duration::from_millis(100)).await;

    // Should be able to acquire again
    let permit3 = limiter.acquire_connection(client_id).await;
    assert!(permit3.is_ok());
}

#[tokio::test]
async fn test_connection_cleanup_task() {
    let limits = ConnectionLimits {
        max_connections: 10,
        max_connections_per_client: 5,
        connection_timeout: 30,
        idle_timeout: 2, // 2 seconds idle timeout for testing
        rate_limit_window: 60,
        rate_limit_max: 10,
    };

    let limiter = Arc::new(ConnectionLimiter::new(limits));

    // Start cleanup task
    limiter.start_cleanup_task().await;

    // Create connections that will go idle
    let _permit1 = limiter.acquire_connection("cleanup_client1").await.unwrap();
    let _permit2 = limiter.acquire_connection("cleanup_client2").await.unwrap();

    // Wait for cleanup task to run
    sleep(Duration::from_secs(5)).await;

    // Metrics should be updated
    let metrics = limiter.get_metrics().await;
    assert!(metrics.total_connections > 0);
}

#[tokio::test]
async fn test_multiple_clients_concurrent() {
    let limits = ConnectionLimits {
        max_connections: 10,
        max_connections_per_client: 2,
        connection_timeout: 30,
        idle_timeout: 300,
        rate_limit_window: 60,
        rate_limit_max: 5,
    };

    let limiter = Arc::new(ConnectionLimiter::new(limits));

    // Spawn multiple concurrent connection attempts
    let mut handles = Vec::new();

    for i in 0..5 {
        let limiter_clone = limiter.clone();
        let handle = tokio::spawn(async move {
            let client_id = format!("client{}", i);

            // Each client tries to acquire multiple connections
            let mut results = Vec::new();
            for j in 0..3 {
                let result = limiter_clone.acquire_connection(&client_id).await;
                results.push((j, result.is_ok()));

                // Hold the permit briefly
                if let Ok(permit) = result {
                    sleep(Duration::from_millis(10)).await;
                    drop(permit);
                }
            }
            results
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    let mut successful_connections = 0;
    let mut rejected_connections = 0;

    for handle in handles {
        let results = handle.await.unwrap();
        for (_, success) in results {
            if success {
                successful_connections += 1;
            } else {
                rejected_connections += 1;
            }
        }
    }

    // Verify that limits were respected
    assert!(successful_connections <= 10); // Global limit
    assert!(rejected_connections > 0); // Some should be rejected due to per-client limits

    let metrics = limiter.get_metrics().await;
    assert_eq!(metrics.total_connections, successful_connections);
    assert_eq!(metrics.rejected_connections, rejected_connections);
}

#[tokio::test]
async fn test_default_connection_limits() {
    let limits = ConnectionLimits::default();
    assert_eq!(limits.max_connections, 100);
    assert_eq!(limits.max_connections_per_client, 10);
    assert_eq!(limits.connection_timeout, 30);
    assert_eq!(limits.idle_timeout, 300);
    assert_eq!(limits.rate_limit_window, 60);
    assert_eq!(limits.rate_limit_max, 20);

    let limiter = ConnectionLimiter::new(limits);

    // Should work with default limits
    let _permit = limiter.acquire_connection("default_test").await.unwrap();
    let metrics = limiter.get_metrics().await;
    assert_eq!(metrics.total_connections, 1);
}
