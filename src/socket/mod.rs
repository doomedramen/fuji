//! Unix socket communication between CLI and daemon
//!
//! This module provides the communication layer for Fuji.

use anyhow::{anyhow, Result};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn};

/// Socket communication protocol
pub mod protocol;

// Re-export protocol types
pub use protocol::{Request, Response, MountStatusInfo};

/// Socket server for the daemon
pub struct SocketServer {
    listener: UnixListener,
}

impl SocketServer {
    /// Create a new socket server
    pub async fn new<P: AsRef<Path>>(socket_path: P) -> Result<Self> {
        // Remove existing socket file if it exists
        if socket_path.as_ref().exists() {
            warn!("Removing existing socket file: {:?}", socket_path.as_ref());
            tokio::fs::remove_file(&socket_path).await?;
        }

        let listener = UnixListener::bind(&socket_path)
            .map_err(|e| anyhow!("Failed to bind to socket {:?}: {}", socket_path.as_ref(), e))?;

        info!("Socket server listening on: {:?}", socket_path.as_ref());

        Ok(Self { listener })
    }

    /// Accept connections and handle requests
    pub async fn run<F, Fut>(&self, handler: F) -> Result<()>
    where
        F: Fn(Request) -> Fut + Clone + Send + Sync + 'static,
        Fut: std::future::Future<Output = Response> + Send,
    {
        loop {
            match self.listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("New connection from: {:?}", addr);

                    let handler = handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, handler).await {
                            error!("Error handling connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}

/// Handle a single client connection
async fn handle_connection<F, Fut>(
    mut stream: UnixStream,
    handler: F,
) -> Result<()>
where
    F: Fn(Request) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Response> + Send,
{
    // Read request
    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .map_err(|_| anyhow!("Connection read timeout"))?
        .map_err(|e| anyhow!("Failed to read from socket: {}", e))?;

    if n == 0 {
        return Ok(());
    }

    // Parse request
    let request: Request = serde_json::from_slice(&buf[..n])
        .map_err(|e| anyhow!("Failed to parse request: {}", e))?;

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
            Duration::from_secs(5),
            UnixStream::connect(&self.socket_path)
        )
        .await
        .map_err(|_| anyhow!("Connection timeout to daemon"))?
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                anyhow!("Could not connect to Fuji daemon. Is it running?")
            } else {
                anyhow!("Failed to connect to daemon: {}", e)
            }
        })?;

        let mut stream = stream;

        // Send request
        let request_bytes = serde_json::to_vec(&request)?;
        stream.write_all(&request_bytes).await?;

        // Read response
        let mut buf = vec![0u8; 4096];
        let n = timeout(Duration::from_secs(30), stream.read(&mut buf))
            .await
            .map_err(|_| anyhow!("Response timeout from daemon"))?
            .map_err(|e| anyhow!("Failed to read response: {}", e))?;

        if n == 0 {
            return Err(anyhow!("Empty response from daemon"));
        }

        // Parse response
        let response: Response = serde_json::from_slice(&buf[..n])
            .map_err(|e| anyhow!("Failed to parse response: {}", e))?;

        Ok(response)
    }

    /// Check if the daemon is running
    pub async fn is_daemon_running(&self) -> bool {
        match UnixStream::connect(&self.socket_path).await {
            Ok(_) => true,
            Err(_) => false,
        }
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
            let socket_path = socket_path.clone();
            async move {
                server.run(|req| async move {
                    match req {
                        Request::Ping => Response::Pong,
                        _ => Response::Error("Unknown request".to_string()),
                    }
                }).await.unwrap()
            }
        });

        // Give server time to start
        sleep(Duration::from_millis(100)).await;

        // Test client
        let client = SocketClient::new(&socket_path);
        let response = client.send_request(Request::Ping).await.unwrap();
        assert!(matches!(response, Response::Pong));

        // Cleanup
        server_handle.abort();
    }
}