//! TCP transport layer for cluster communication
//!
//! Provides TCP-based networking for Fuji cluster nodes to communicate
//! configuration changes and sync operations.

use anyhow::Result;
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::config::{ClusterConfig, PeerInfo};
use crate::sync::protocol::SyncMessage;

/// TCP transport manager for cluster communication
pub struct TcpTransport {
    /// Local socket address
    local_addr: SocketAddr,
    /// Active connections to peers
    connections: Arc<RwLock<HashMap<String, PeerConnection>>>,
    /// Cluster configuration
    cluster_config: Arc<RwLock<Option<ClusterConfig>>>,
    /// Whether the server is running
    server_running: Arc<RwLock<bool>>,
}

/// Active connection to a peer
#[derive(Debug)]
#[allow(dead_code)]
pub struct PeerConnection {
    /// Peer ID
    peer_id: String,
    /// Socket address
    addr: SocketAddr,
    /// TCP stream
    stream: Arc<tokio::sync::Mutex<Option<TokioTcpStream>>>,
    /// Last activity
    last_activity: Arc<RwLock<DateTime<Utc>>>,
    /// Connection status
    status: Arc<RwLock<ConnectionStatus>>,
}

/// Connection status
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ConnectionStatus {
    /// Connecting
    Connecting,
    /// Connected and authenticated
    Connected,
    /// Disconnected
    Disconnected,
    /// Error occurred
    Error(String),
}

impl TcpTransport {
    /// Create a new TCP transport manager
    pub fn new(local_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            connections: Arc::new(RwLock::new(HashMap::new())),
            cluster_config: Arc::new(RwLock::new(None)),
            server_running: Arc::new(RwLock::new(false)),
        }
    }

    /// Set cluster configuration
    pub async fn set_cluster_config(&self, config: ClusterConfig) {
        *self.cluster_config.write().await = Some(config);
    }

    /// Start the TCP server
    pub async fn start_server(&self) -> Result<()> {
        {
            let mut running = self.server_running.write().await;
            if *running {
                warn!("TCP server is already running");
                return Ok(());
            }
            *running = true;
        }

        let listener = TokioTcpListener::bind(self.local_addr)
            .await
            .map_err(|e| anyhow!("Failed to bind to {}: {}", self.local_addr, e))?;

        info!("TCP server listening on {}", self.local_addr);

        let connections = self.connections.clone();
        let cluster_config = self.cluster_config.clone();
        let server_running = self.server_running.clone();

        tokio::spawn(async move {
            while *server_running.read().await {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("New connection from {}", addr);

                        // Handle the connection in a separate task
                        let conn = PeerConnection::new(addr);
                        let peer_id = conn.peer_id.clone();

                        // Store the connection
                        {
                            let mut conns = connections.write().await;
                            conns.insert(peer_id.clone(), conn);
                        }

                        // Spawn handler for this connection
                        let connections_clone = connections.clone();
                        let cluster_config_clone = cluster_config.clone();

                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_connection(
                                stream,
                                addr,
                                peer_id,
                                connections_clone,
                                cluster_config_clone,
                            )
                            .await
                            {
                                error!("Error handling connection from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        if !*server_running.read().await {
                            // Server is shutting down
                            break;
                        }
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop the TCP server
    pub async fn stop_server(&self) -> Result<()> {
        {
            let mut running = self.server_running.write().await;
            *running = false;
        }

        // Close all connections
        {
            let mut connections = self.connections.write().await;
            for (_, conn) in connections.drain() {
                if let Ok(mut stream_guard) = conn.stream.try_lock() {
                    if let Some(mut stream) = stream_guard.take() {
                        let _ = stream.shutdown().await;
                    }
                }
            }
        }

        info!("TCP server stopped");
        Ok(())
    }

    /// Connect to a peer
    pub async fn connect_to_peer(&self, peer: &PeerInfo) -> Result<()> {
        let addr: SocketAddr = peer
            .address
            .parse()
            .map_err(|e| anyhow!("Invalid peer address {}: {}", peer.address, e))?;

        info!("Connecting to peer {} at {}", peer.id, addr);

        // Check if already connected
        {
            let connections = self.connections.read().await;
            if connections.contains_key(&peer.id) {
                debug!("Already connected to peer {}", peer.id);
                return Ok(());
            }
        }

        // Attempt connection
        match TokioTcpStream::connect(addr).await {
            Ok(_stream) => {
                let conn = PeerConnection::new(addr);

                // Store connection
                {
                    let mut connections = self.connections.write().await;
                    connections.insert(peer.id.clone(), conn);
                }

                info!("Connected to peer {}", peer.id);
                Ok(())
            }
            Err(e) => {
                warn!("Failed to connect to peer {} at {}: {}", peer.id, addr, e);
                Err(e.into())
            }
        }
    }

    /// Disconnect from a peer
    pub async fn disconnect_from_peer(&self, peer_id: &str) -> Result<()> {
        let mut connections = self.connections.write().await;
        if let Some(conn) = connections.remove(peer_id) {
            if let Ok(mut stream_guard) = conn.stream.try_lock() {
                if let Some(mut stream) = stream_guard.take() {
                    let _ = stream.shutdown().await;
                }
            }
            info!("Disconnected from peer {}", peer_id);
        }
        Ok(())
    }

    /// Send a message to a peer
    pub async fn send_message(&self, peer_id: &str, message: &SyncMessage) -> Result<()> {
        let connections = self.connections.read().await;

        if let Some(conn) = connections.get(peer_id) {
            // Serialize message
            let data = serde_json::to_vec(message)?;
            let length = data.len() as u32;

            // Get stream
            let mut stream_guard = conn
                .stream
                .try_lock()
                .map_err(|_| anyhow!("Failed to lock stream for peer {}", peer_id))?;

            if let Some(stream) = stream_guard.as_mut() {
                // Send length prefix
                stream.write_all(&length.to_be_bytes()).await?;

                // Send message data
                stream.write_all(&data).await?;

                // Update last activity
                let mut last_activity = conn.last_activity.write().await;
                *last_activity = Utc::now();

                debug!("Sent message to peer {}", peer_id);
                Ok(())
            } else {
                Err(anyhow!("No active stream for peer {}", peer_id))
            }
        } else {
            Err(anyhow!("Not connected to peer {}", peer_id))
        }
    }

    /// Broadcast a message to all connected peers
    pub async fn broadcast_message(&self, message: &SyncMessage) -> Result<Vec<String>> {
        let connections = self.connections.read().await;
        let mut failed_peers = Vec::new();

        for (peer_id, _) in connections.iter() {
            if let Err(e) = self.send_message(peer_id, message).await {
                warn!("Failed to send message to peer {}: {}", peer_id, e);
                failed_peers.push(peer_id.clone());
            }
        }

        Ok(failed_peers)
    }

    /// Handle incoming connection
    async fn handle_connection(
        mut stream: TokioTcpStream,
        addr: SocketAddr,
        _peer_id: String,
        _connections: Arc<RwLock<HashMap<String, PeerConnection>>>,
        cluster_config: Arc<RwLock<Option<ClusterConfig>>>,
    ) -> Result<()> {
        // Authenticate the connection
        if let Err(e) = Self::authenticate_connection(&mut stream, &_peer_id, &cluster_config).await
        {
            error!("Authentication failed for {}: {}", addr, e);
            return Err(e);
        }

        debug!("Authenticated connection from {}", addr);

        // Read messages in a loop
        loop {
            // Read message length
            let mut length_bytes = [0u8; 4];
            match stream.read_exact(&mut length_bytes).await {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    debug!("Peer {} disconnected gracefully", addr);
                    break;
                }
                Err(e) => {
                    error!("Failed to read message length from {}: {}", addr, e);
                    break;
                }
            }

            let length = u32::from_be_bytes(length_bytes) as usize;

            // Read message data
            let mut data = vec![0u8; length];
            match stream.read_exact(&mut data).await {
                Ok(_) => {}
                Err(e) => {
                    error!("Failed to read message data from {}: {}", addr, e);
                    break;
                }
            }

            // Deserialize message
            let message: SyncMessage = serde_json::from_slice(&data)?;

            // Handle the message
            if let Err(e) =
                Self::handle_message(&_peer_id, message, &_connections, &cluster_config).await
            {
                error!("Error handling message from {}: {}", addr, e);
            }
        }

        // Clean up connection
        {
            let mut conns = _connections.write().await;
            conns.remove(&_peer_id);
        }

        info!("Connection from {} closed", addr);
        Ok(())
    }

    /// Authenticate an incoming connection
    async fn authenticate_connection(
        stream: &mut TokioTcpStream,
        _peer_id: &str,
        cluster_config: &Arc<RwLock<Option<ClusterConfig>>>,
    ) -> Result<()> {
        // Read auth message
        let mut length_bytes = [0u8; 4];
        stream.read_exact(&mut length_bytes).await?;
        let length = u32::from_be_bytes(length_bytes) as usize;

        let mut data = vec![0u8; length];
        stream.read_exact(&mut data).await?;

        // Parse auth request
        let auth_req: AuthRequest = serde_json::from_slice(&data)?;

        // Check against our cluster config
        let config = cluster_config.read().await;
        if let Some(cluster) = config.as_ref() {
            // Find the peer in our config
            if let Some(peer_info) = cluster.peers.iter().find(|p| p.id == auth_req.instance_id) {
                // Verify PSK
                if peer_info.psk != auth_req.psk {
                    return Err(anyhow!("Invalid PSK for peer {}", auth_req.instance_id));
                }

                // Send success response
                let response = AuthResponse::success();
                let response_data = serde_json::to_vec(&response)?;
                let response_length = response_data.len() as u32;

                stream.write_all(&response_length.to_be_bytes()).await?;
                stream.write_all(&response_data).await?;

                Ok(())
            } else {
                Err(anyhow!(
                    "Peer {} not found in cluster config",
                    auth_req.instance_id
                ))
            }
        } else {
            Err(anyhow!("Cluster not configured"))
        }
    }

    /// Handle received message
    async fn handle_message(
        sender_id: &str,
        message: SyncMessage,
        _connections: &Arc<RwLock<HashMap<String, PeerConnection>>>,
        _cluster_config: &Arc<RwLock<Option<ClusterConfig>>>,
    ) -> Result<()> {
        debug!("Received message from {}: {:?}", sender_id, message);

        match message {
            SyncMessage::SyncRequest(req) => {
                // Handle sync request - log details
                info!(
                    "Received sync request {} from {} for version {}",
                    req.request_id, req.requester_id, req.known_version
                );
                // Note: In a full implementation, this would be forwarded to the sync coordinator
            }
            SyncMessage::SyncResponse(resp) => {
                // Handle sync response - log details
                info!(
                    "Received sync response {} with config version {} and {} conflicts",
                    resp.request_id,
                    resp.sync_version,
                    resp.conflicts.len()
                );
                // Note: In a full implementation, this would be forwarded to the sync coordinator
            }
            SyncMessage::ConfigUpdate(update) => {
                // Handle config update - log details
                info!(
                    "Received config update with sync version {} from {}",
                    update.sync_version, sender_id
                );
                // Note: In a full implementation, this would be forwarded to the sync coordinator
            }
            SyncMessage::SyncComplete(comp) => {
                // Handle sync complete - log details
                info!(
                    "Received sync complete notification for version {} from {}",
                    comp.sync_version, sender_id
                );
                // Note: In a full implementation, this would be forwarded to the sync coordinator
            }
            SyncMessage::Heartbeat(heartbeat) => {
                // Handle heartbeat
                debug!(
                    "Received heartbeat from {} (status: {:?})",
                    sender_id, heartbeat.status
                );
            }
        }

        Ok(())
    }
}

impl PeerConnection {
    /// Create a new peer connection
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            peer_id: format!("{}:{}", addr.ip(), addr.port()),
            addr,
            stream: Arc::new(tokio::sync::Mutex::new(None)),
            last_activity: Arc::new(RwLock::new(Utc::now())),
            status: Arc::new(RwLock::new(ConnectionStatus::Connecting)),
        }
    }
}

/// Authentication request
#[derive(Debug, Serialize, Deserialize)]
struct AuthRequest {
    /// Instance ID
    instance_id: String,
    /// Pre-shared key
    psk: String,
    /// Protocol version
    version: String,
}

/// Authentication response
#[derive(Debug, Serialize, Deserialize)]
struct AuthResponse {
    /// Whether authentication succeeded
    success: bool,
    /// Optional error message
    error: Option<String>,
}

impl AuthResponse {
    fn success() -> Self {
        Self {
            success: true,
            error: None,
        }
    }

    #[allow(dead_code)]
    fn failure(error: String) -> Self {
        Self {
            success: false,
            error: Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_tcp_transport_creation() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let transport = TcpTransport::new(addr);
        assert_eq!(transport.local_addr.port(), 0); // 0 means any available port
    }

    #[tokio::test]
    async fn test_peer_connection() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let conn = PeerConnection::new(addr);
        assert_eq!(conn.peer_id, "127.0.0.1:8080");
        assert_eq!(conn.addr, addr);
    }
}
