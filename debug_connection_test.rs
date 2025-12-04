use fuji::socket::{ConnectionLimiter, ConnectionLimits};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() {
    let limits = ConnectionLimits {
        max_connections: 5,
        max_connections_per_client: 2,
        connection_timeout: 30,
        idle_timeout: 300,
        rate_limit_window: 60,
        rate_limit_max: 10,
    };

    let limiter = ConnectionLimiter::new(limits);

    println!("=== Testing connection acquisition ===");
    
    // Test acquiring connections
    println!("1. Getting permit1 for client1...");
    let permit1 = limiter.acquire_connection("client1").await.unwrap();
    println!("   ✓ Success");
    
    let metrics1 = limiter.get_metrics().await;
    println!("   Metrics after permit1: total={}, active={}, rejected={}", 
             metrics1.total_connections, metrics1.active_connections, metrics1.rejected_connections);

    println!("2. Getting permit2 for client1...");
    let permit2 = limiter.acquire_connection("client1").await.unwrap();
    println!("   ✓ Success");
    
    let metrics2 = limiter.get_metrics().await;
    println!("   Metrics after permit2: total={}, active={}, rejected={}", 
             metrics2.total_connections, metrics2.active_connections, metrics2.rejected_connections);

    println!("3. Getting permit3 for client1 (should fail)...");
    let permit3 = limiter.acquire_connection("client1").await;
    if permit3.is_err() {
        println!("   ✓ Failed as expected");
    } else {
        println!("   ✗ Unexpectedly succeeded");
    }
    
    let metrics3 = limiter.get_metrics().await;
    println!("   Metrics after permit3: total={}, active={}, rejected={}", 
             metrics3.total_connections, metrics3.active_connections, metrics3.rejected_connections);

    println!("4. Getting permit4 for client2...");
    let permit4 = limiter.acquire_connection("client2").await.unwrap();
    println!("   ✓ Success");
    
    let metrics4 = limiter.get_metrics().await;
    println!("   Metrics after permit4: total={}, active={}, rejected={}", 
             metrics4.total_connections, metrics4.active_connections, metrics4.rejected_connections);

    println!("Final metrics: total={}, active={}, rejected={}", 
             metrics4.total_connections, metrics4.active_connections, metrics4.rejected_connections);
}
