// Allow dead code - some connection metrics and handlers are for future monitoring features
#![allow(dead_code)]

//! Unix socket communication between CLI and daemon
//!
//! This module provides the communication layer for Fuji with connection limiting
//! to prevent resource exhaustion attacks.

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{Duration as StdDuration, interval, timeout};
use tracing::{debug, error, info, warn};

/// Socket communication protocol
pub mod protocol;

// Re-export protocol types
pub use protocol::{MountStatusInfo, Request, Response};

/// Configuration for connection limits
#[derive(Debug, Clone)]
pub struct ConnectionLimits {
    /// Maximum concurrent connections globally
    pub max_connections: usize,
    /// Maximum connections per unique client identifier
    pub max_connections_per_client: usize,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Idle connection timeout in seconds
    pub idle_timeout: u64,
    /// Rate limiting window in seconds
    pub rate_limit_window: u64,
    /// Maximum connections per window per client
    pub rate_limit_max: usize,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_connections: 100,
            max_connections_per_client: 10,
            connection_timeout: 30,
            idle_timeout: 300, // 5 minutes
            rate_limit_window: 60,
            rate_limit_max: 20,
        }
    }
}

/// Track connection information for rate limiting
#[derive(Debug, Clone)]
struct ConnectionInfo {
    /// Number of active connections
    active_connections: usize,
    /// Connection timestamps for rate limiting
    connection_timestamps: Vec<Instant>,
    /// Last activity timestamp
    last_activity: Instant,
}

impl ConnectionInfo {
    fn new() -> Self {
        Self {
            active_connections: 0,
            connection_timestamps: Vec::new(),
            last_activity: Instant::now(),
        }
    }

    /// Clean up old timestamps outside the rate limit window
    fn cleanup_old_timestamps(&mut self, window_duration: StdDuration) {
        let now = Instant::now();
        self.connection_timestamps
            .retain(|&ts| now.duration_since(ts) <= window_duration);
    }

    /// Check if a new connection is allowed based on rate limits
    fn is_rate_limited(&self, max_connections: usize, window_duration: StdDuration) -> bool {
        let now = Instant::now();
        let recent_count = self
            .connection_timestamps
            .iter()
            .filter(|&&ts| now.duration_since(ts) <= window_duration)
            .count();

        recent_count >= max_connections
    }

    /// Record a new connection
    fn record_connection(&mut self) {
        self.connection_timestamps.push(Instant::now());
        self.active_connections += 1;
        self.last_activity = Instant::now();
    }

    /// Record a connection closure
    fn remove_connection(&mut self) {
        if self.active_connections > 0 {
            self.active_connections -= 1;
        }
        self.last_activity = Instant::now();
    }
}

/// Connection limiter to prevent resource exhaustion
#[derive(Debug)]
pub struct ConnectionLimiter {
    limits: ConnectionLimits,
    global_semaphore: Arc<Semaphore>,
    client_connections: Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    metrics: Arc<Mutex<ConnectionMetrics>>,
}

/// Connection metrics for monitoring
#[derive(Debug, Clone)]
pub struct ConnectionMetrics {
    pub total_connections: u64,
    pub active_connections: u64,
    pub rejected_connections: u64,
    pub rate_limited_connections: u64,
    pub peak_concurrent_connections: u64,
    pub last_reset: Instant,
}

impl Default for ConnectionMetrics {
    fn default() -> Self {
        Self {
            total_connections: 0,
            active_connections: 0,
            rejected_connections: 0,
            rate_limited_connections: 0,
            peak_concurrent_connections: 0,
            last_reset: Instant::now(),
        }
    }
}

impl ConnectionLimiter {
    /// Create a new connection limiter
    #[must_use]
    pub fn new(limits: ConnectionLimits) -> Self {
        Self {
            global_semaphore: Arc::new(Semaphore::new(limits.max_connections)),
            client_connections: Arc::new(Mutex::new(HashMap::new())),
            metrics: Arc::new(Mutex::new(ConnectionMetrics {
                last_reset: Instant::now(),
                ..Default::default()
            })),
            limits,
        }
    }

    /// Attempt to acquire a connection permit
    pub async fn acquire_connection(&self, client_id: &str) -> Result<ConnectionPermit> {
        // Check global limit (try_acquire_owned returns immediately if no permits available)
        let global_permit = if let Ok(permit) = self.global_semaphore.clone().try_acquire_owned() {
            permit
        } else {
            self.increment_rejected("global_limit").await;
            return Err(anyhow!("Failed to acquire connection permit"));
        };

        // Check client-specific limits
        {
            let mut clients = self.client_connections.lock().await;
            let window_duration = StdDuration::from_secs(self.limits.rate_limit_window);

            let client_info = clients
                .entry(client_id.to_string())
                .or_insert_with(ConnectionInfo::new);

            // Clean up old timestamps
            client_info.cleanup_old_timestamps(window_duration);

            // Check rate limit
            if client_info.is_rate_limited(self.limits.rate_limit_max, window_duration) {
                drop(global_permit);
                self.increment_rejected("rate_limited").await;
                return Err(anyhow!(
                    "Connection rate limit exceeded for client: {client_id}"
                ));
            }

            // Check per-client connection limit
            if client_info.active_connections >= self.limits.max_connections_per_client {
                drop(global_permit);
                self.increment_rejected("per_client_limit").await;
                return Err(anyhow!("Per-client connection limit exceeded: {client_id}"));
            }

            // Record the connection
            client_info.record_connection();
        }

        // Update metrics
        self.increment_active().await;

        Ok(ConnectionPermit {
            client_id: client_id.to_string(),
            global_permit: Some(global_permit),
            limiter: self.clone(),
        })
    }

    /// Get current connection metrics
    pub async fn get_metrics(&self) -> ConnectionMetrics {
        self.metrics.lock().await.clone()
    }

    /// Start background cleanup task
    pub async fn start_cleanup_task(&self) {
        let client_connections = self.client_connections.clone();
        let metrics = self.metrics.clone();
        let idle_timeout = self.limits.idle_timeout;

        tokio::spawn(async move {
            let mut interval = interval(StdDuration::from_secs(30));

            loop {
                interval.tick().await;

                let now = Instant::now();
                let idle_duration = StdDuration::from_secs(idle_timeout);

                // Clean up idle clients
                {
                    let mut clients = client_connections.lock().await;
                    clients
                        .retain(|_, info| now.duration_since(info.last_activity) <= idle_duration);
                }

                // Update metrics
                {
                    let mut m = metrics.lock().await;
                    let active_count = client_connections
                        .lock()
                        .await
                        .values()
                        .map(|info| info.active_connections as u64)
                        .sum();
                    m.active_connections = active_count;
                }
            }
        });
    }

    async fn increment_active(&self) {
        let mut metrics = self.metrics.lock().await;
        metrics.total_connections += 1;
        metrics.active_connections += 1;
        if metrics.active_connections > metrics.peak_concurrent_connections {
            metrics.peak_concurrent_connections = metrics.active_connections;
        }
    }

    async fn increment_rejected(&self, reason: &str) {
        let mut metrics = self.metrics.lock().await;
        metrics.rejected_connections += 1;
        if reason == "rate_limited" {
            metrics.rate_limited_connections += 1;
        }
    }

    async fn decrement_active(&self) {
        let mut metrics = self.metrics.lock().await;
        if metrics.active_connections > 0 {
            metrics.active_connections -= 1;
        }
    }

    async fn release_client_connection(&self, client_id: &str) {
        let mut clients = self.client_connections.lock().await;
        if let Some(info) = clients.get_mut(client_id) {
            info.remove_connection();
        }
        self.decrement_active().await;
    }
}

/// Permit for an active connection
#[derive(Debug)]
pub struct ConnectionPermit {
    client_id: String,
    global_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    limiter: ConnectionLimiter,
}

impl ConnectionPermit {
    /// Get the client ID for this connection
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let client_id = self.client_id.clone();
        let limiter = self.limiter.clone();

        // Release resources asynchronously
        tokio::spawn(async move {
            limiter.release_client_connection(&client_id).await;
        });
    }
}

impl Clone for ConnectionLimiter {
    fn clone(&self) -> Self {
        Self {
            limits: self.limits.clone(),
            global_semaphore: self.global_semaphore.clone(),
            client_connections: self.client_connections.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

/// Socket server for the daemon
pub struct SocketServer {
    listener: UnixListener,
    connection_limiter: ConnectionLimiter,
}

impl SocketServer {
    /// Create a new socket server with default connection limits
    pub async fn new<P: AsRef<Path>>(socket_path: P) -> Result<Self> {
        Self::new_with_limits(socket_path, ConnectionLimits::default()).await
    }

    /// Create a new socket server with custom connection limits
    pub async fn new_with_limits<P: AsRef<Path>>(
        socket_path: P,
        limits: ConnectionLimits,
    ) -> Result<Self> {
        // Remove existing socket file if it exists
        if socket_path.as_ref().exists() {
            warn!("Removing existing socket file: {:?}", socket_path.as_ref());
            tokio::fs::remove_file(&socket_path).await?;
        }

        let socket_path_buf = socket_path.as_ref().to_path_buf();
        info!("Attempting to bind socket: {:?}", socket_path_buf);
        let socket_path_buf_clone = socket_path_buf.clone();
        let listener = tokio::task::spawn_blocking(move || {
            info!("Socket bind task starting");
            let result = UnixListener::bind(&socket_path_buf_clone);
            info!("Socket bind result: {:?}", result.is_ok());
            result
        })
        .await
        .map_err(|e| anyhow!("Spawn blocking task failed for socket bind: {}", e))?
        .map_err(|e| anyhow!("Failed to bind to socket {:?}: {}", socket_path_buf, e))?;

        info!("Socket server listening on: {:?}", socket_path.as_ref());
        info!(
            "Connection limits - Max: {}, Per client: {}, Rate window: {}s, Rate max: {}",
            limits.max_connections,
            limits.max_connections_per_client,
            limits.rate_limit_window,
            limits.rate_limit_max
        );

        let connection_limiter = ConnectionLimiter::new(limits);

        Ok(Self {
            listener,
            connection_limiter,
        })
    }

    /// Accept connections and handle requests
    pub async fn run<F, Fut>(&self, handler: F) -> Result<()>
    where
        F: Fn(Request) -> Fut + Clone + Send + Sync + 'static,
        Fut: std::future::Future<Output = Response> + Send,
    {
        // Start the cleanup task
        self.connection_limiter.start_cleanup_task().await;

        loop {
            match self.listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("New connection from: {:?}", addr);

                    // Extract client ID from the connection
                    let client_id = self.extract_client_id(&stream).await.unwrap_or_else(|_| {
                        format!(
                            "unknown-{}",
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0)
                        )
                    });

                    // Try to acquire connection permit
                    match self.connection_limiter.acquire_connection(&client_id).await {
                        Ok(permit) => {
                            let handler = handler.clone();
                            let timeout_duration = StdDuration::from_secs(
                                self.connection_limiter.limits.connection_timeout,
                            );

                            tokio::spawn(async move {
                                let result = timeout(
                                    timeout_duration,
                                    handle_connection_with_permit(stream, handler, permit),
                                )
                                .await;

                                match result {
                                    Ok(Ok(())) => {
                                        debug!(
                                            "Connection handled successfully for client: {}",
                                            client_id
                                        );
                                    }
                                    Ok(Err(e)) => {
                                        error!(
                                            "Error handling connection for {}: {}",
                                            client_id, e
                                        );
                                    }
                                    Err(_) => {
                                        warn!("Connection timeout for client: {}", client_id);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            warn!("Connection rejected for {}: {}", client_id, e);
                            // Close the stream immediately
                            drop(stream);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    /// Extract a unique client identifier from the connection
    async fn extract_client_id(&self, stream: &UnixStream) -> Result<String> {
        // Try to get peer credentials
        match stream.peer_cred() {
            Ok(cred) => {
                // Use UID as the primary identifier
                Ok(format!("uid-{}", cred.uid()))
            }
            Err(_) => {
                // Fallback to peer address if available
                match stream.peer_addr() {
                    Ok(addr) => {
                        if let Some(path) = addr.as_pathname() {
                            Ok(path.to_string_lossy().to_string())
                        } else {
                            Ok(format!("addr-{addr:?}"))
                        }
                    }
                    Err(_) => {
                        // Final fallback to a timestamp-based ID
                        let ts = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        Ok(format!("anon-{ts}"))
                    }
                }
            }
        }
    }

    /// Get connection metrics
    pub async fn get_connection_metrics(&self) -> ConnectionMetrics {
        self.connection_limiter.get_metrics().await
    }
}

/// Handle a single client connection with connection permit
async fn handle_connection_with_permit<F, Fut>(
    mut stream: UnixStream,
    handler: F,
    _permit: ConnectionPermit,
) -> Result<()>
where
    F: Fn(Request) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Response> + Send,
{
    // Read request
    let mut buf = vec![0u8; 4096];
    let n = timeout(StdDuration::from_secs(5), stream.read(&mut buf))
        .await
        .map_err(|_| anyhow!("Connection read timeout"))?
        .map_err(|e| anyhow!("Failed to read from socket: {e}"))?;

    if n == 0 {
        return Ok(());
    }

    // Parse request
    let request: Request =
        serde_json::from_slice(&buf[..n]).map_err(|e| anyhow!("Failed to parse request: {e}"))?;

    debug!("Received request: {:?}", request);

    // Handle request
    let response = handler(request).await;

    debug!("Sending response: {:?}", response);

    // Send response
    let response_bytes = serde_json::to_vec(&response)?;
    stream.write_all(&response_bytes).await?;

    Ok(())
}

/// Handle a single client connection (legacy function for backward compatibility)
async fn handle_connection<F, Fut>(mut stream: UnixStream, handler: F) -> Result<()>
where
    F: Fn(Request) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Response> + Send,
{
    // Read request
    let mut buf = vec![0u8; 4096];
    let n = timeout(StdDuration::from_secs(5), stream.read(&mut buf))
        .await
        .map_err(|_| anyhow!("Connection read timeout"))?
        .map_err(|e| anyhow!("Failed to read from socket: {e}"))?;

    if n == 0 {
        return Ok(());
    }

    // Parse request
    let request: Request =
        serde_json::from_slice(&buf[..n]).map_err(|e| anyhow!("Failed to parse request: {e}"))?;

    debug!("Received request: {:?}", request);

    // Handle request
    let response = handler(request).await;

    debug!("Sending response: {:?}", response);

    // Send response
    let response_bytes = serde_json::to_vec(&response)?;
    stream.write_all(&response_bytes).await?;

    Ok(())
}

/// Socket client for the CLI
pub struct SocketClient {
    socket_path: std::path::PathBuf,
}

impl SocketClient {
    /// Create a new socket client
    pub fn new<P: AsRef<Path>>(socket_path: P) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    /// Send a request and wait for response
    pub async fn send_request(&self, request: Request) -> Result<Response> {
        // Connect to socket with timeout
        let stream = timeout(
            StdDuration::from_secs(5),
            UnixStream::connect(&self.socket_path),
        )
        .await
        .map_err(|_| anyhow!("Connection timeout to daemon"))?
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                anyhow!("Could not connect to Fuji daemon. Is it running?")
            } else {
                anyhow!("Failed to connect to daemon: {e}")
            }
        })?;

        let mut stream = stream;

        // Send request
        let request_bytes = serde_json::to_vec(&request)?;
        stream.write_all(&request_bytes).await?;

        // Read response
        let mut buf = vec![0u8; 4096];
        let n = timeout(StdDuration::from_secs(30), stream.read(&mut buf))
            .await
            .map_err(|_| anyhow!("Response timeout from daemon"))?
            .map_err(|e| anyhow!("Failed to read response: {e}"))?;

        if n == 0 {
            return Err(anyhow!("Empty response from daemon"));
        }

        // Parse response
        let response: Response = serde_json::from_slice(&buf[..n])
            .map_err(|e| anyhow!("Failed to parse response: {e}"))?;

        Ok(response)
    }

    /// Check if the daemon is running
    pub async fn is_daemon_running(&self) -> bool {
        UnixStream::connect(&self.socket_path).await.is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_socket_communication() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        // Start server
        let server = SocketServer::new(&socket_path).await.unwrap();
        let server_handle = tokio::spawn({
            let _socket_path = socket_path.clone();
            async move {
                server
                    .run(|req| async move {
                        match req {
                            Request::Ping => Response::Pong,
                            _ => Response::Error("Unknown request".to_string()),
                        }
                    })
                    .await
                    .unwrap()
            }
        });

        // Give server time to start
        sleep(StdDuration::from_millis(100)).await;

        // Test client
        let client = SocketClient::new(&socket_path);
        let response = client.send_request(Request::Ping).await.unwrap();
        assert!(matches!(response, Response::Pong));

        // Cleanup
        server_handle.abort();
    }
}
