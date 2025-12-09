//! Cluster management for Fuji
//!
//! This module provides multi-instance configuration synchronization capabilities,
//! allowing multiple Fuji daemons to maintain consistent configurations across
//! a cluster of nodes.

pub mod discovery;
pub mod election;
pub mod fault_tolerance;
pub mod instance;

use crate::config::{ClusterConfig, PeerInfo, PeerStatus};
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

// Re-export common types
pub use instance::{InstanceInfo, InstanceManager, generate_psk, sign_data, verify_signature};

/// Cluster state management
pub struct ClusterState {
    /// Current cluster configuration
    config: Arc<RwLock<Option<ClusterConfig>>>,
    /// Peer information
    peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
    /// Last time we initiated a sync
    last_sync_initiation: Arc<RwLock<Option<DateTime<Utc>>>>,
    /// Last time we were asked for our config
    last_peer_request: Arc<RwLock<Option<DateTime<Utc>>>>,
}

impl ClusterState {
    /// Create a new cluster state
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
            peers: Arc::new(RwLock::new(HashMap::new())),
            last_sync_initiation: Arc::new(RwLock::new(None)),
            last_peer_request: Arc::new(RwLock::new(None)),
        }
    }

    /// Initialize cluster state with configuration
    pub async fn initialize(&self, config: ClusterConfig) -> Result<()> {
        // Store config
        *self.config.write().await = Some(config.clone());

        // Initialize peers
        let mut peers = self.peers.write().await;
        peers.clear();
        for peer in config.peers {
            peers.insert(peer.id.clone(), peer);
        }

        info!("Cluster initialized with {} peers", peers.len());

        Ok(())
    }

    /// Check if clustering is enabled
    pub async fn is_enabled(&self) -> bool {
        self.config
            .read()
            .await
            .as_ref()
            .map(|c| c.enabled)
            .unwrap_or(false)
    }

    /// Get instance ID
    pub async fn get_instance_id(&self) -> Option<String> {
        self.config
            .read()
            .await
            .as_ref()
            .map(|c| c.instance_id.clone())
    }

    /// Add or update a peer
    pub async fn update_peer(&self, peer: PeerInfo) {
        let peer_id = peer.id.clone();
        let mut peers = self.peers.write().await;
        peers.insert(peer_id.clone(), peer);
        debug!("Updated peer information for {}", peer_id);
    }

    /// Remove a peer
    pub async fn remove_peer(&self, peer_id: &str) -> bool {
        let mut peers = self.peers.write().await;
        if peers.remove(peer_id).is_some() {
            info!("Removed peer {} from cluster", peer_id);
            true
        } else {
            false
        }
    }

    /// Get all peers
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        self.peers.read().await.values().cloned().collect()
    }

    /// Get peer by ID
    pub async fn get_peer(&self, peer_id: &str) -> Option<PeerInfo> {
        self.peers.read().await.get(peer_id).cloned()
    }

    /// Update peer status
    pub async fn update_peer_status(&self, peer_id: &str, status: PeerStatus) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(peer_id) {
            peer.status = status.clone();
            peer.last_seen = Utc::now();
            debug!("Updated status for peer {} to {:?}", peer_id, status);
        }
    }

    /// Mark peer as seen (update last_seen timestamp)
    pub async fn mark_peer_seen(&self, peer_id: &str) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(peer_id) {
            peer.last_seen = Utc::now();
            if peer.status == PeerStatus::Disconnected {
                peer.status = PeerStatus::Connected;
            }
        }
    }

    /// Get healthy peers (connected or recently seen)
    pub async fn get_healthy_peers(&self, timeout: chrono::Duration) -> Vec<PeerInfo> {
        let peers = self.peers.read().await;
        let now = Utc::now();

        peers
            .values()
            .filter(|peer| peer.status == PeerStatus::Connected || (now - peer.last_seen) < timeout)
            .cloned()
            .collect()
    }

    /// Get sync configuration
    pub async fn get_sync_config(&self) -> Option<(chrono::Duration, chrono::Duration)> {
        let config = self.config.read().await;
        config.as_ref().map(|c| (c.sync_interval, c.sync_timeout))
    }

    /// Update last sync initiation time
    pub async fn mark_sync_initiated(&self) {
        *self.last_sync_initiation.write().await = Some(Utc::now());
    }

    /// Update last peer request time
    pub async fn mark_peer_request(&self) {
        *self.last_peer_request.write().await = Some(Utc::now());
    }

    /// Check if we should initiate sync
    pub async fn should_initiate_sync(&self) -> bool {
        let config_guard = self.config.read().await;
        let timeout_guard = self.last_peer_request.read().await;

        if let Some(config) = config_guard.as_ref() {
            match *timeout_guard {
                None => true,
                Some(last) => {
                    // Check if timeout has passed
                    (Utc::now() - last) > config.sync_timeout
                }
            }
        } else {
            false
        }
    }

    /// Get cluster statistics
    pub async fn get_stats(&self) -> ClusterStats {
        let peers = self.peers.read().await;
        let now = Utc::now();

        let stats = ClusterStats {
            total_peers: peers.len(),
            connected_peers: peers
                .values()
                .filter(|p| p.status == PeerStatus::Connected)
                .count(),
            disconnected_peers: peers
                .values()
                .filter(|p| p.status == PeerStatus::Disconnected)
                .count(),
            suspended_peers: peers
                .values()
                .filter(|p| p.status == PeerStatus::Suspended)
                .count(),
            last_sync_initiation: *self.last_sync_initiation.read().await,
            last_peer_request: *self.last_peer_request.read().await,
        };

        // Log any peers that haven't been seen recently
        for peer in peers.values() {
            if now - peer.last_seen > chrono::Duration::minutes(5) {
                warn!(
                    "Peer {} hasn't been seen for {} minutes",
                    peer.id,
                    (now - peer.last_seen).num_minutes()
                );
            }
        }

        stats
    }
}

impl Default for ClusterState {
    fn default() -> Self {
        Self::new()
    }
}

/// Cluster statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStats {
    /// Total number of peers
    pub total_peers: usize,
    /// Number of connected peers
    pub connected_peers: usize,
    /// Number of disconnected peers
    pub disconnected_peers: usize,
    /// Number of suspended peers
    pub suspended_peers: usize,
    /// Last time we initiated a sync
    pub last_sync_initiation: Option<DateTime<Utc>>,
    /// Last time we were asked for our config
    pub last_peer_request: Option<DateTime<Utc>>,
}

/// Cluster invitation token structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterInvitation {
    /// Invitation format version
    pub version: String,
    /// Instance ID of the inviting node
    pub instance_id: String,
    /// Network address to connect to
    pub address: String,
    /// Pre-shared key for authentication
    pub psk: String,
    /// When the invitation expires
    pub expires_at: DateTime<Utc>,
    /// HMAC signature for integrity verification
    pub signature: String,
}

impl ClusterInvitation {
    /// Create a new invitation
    pub fn new(instance_id: String, address: String, psk: String) -> Result<Self> {
        let invitation_data = format!(
            "{}|{}|{}|{}",
            instance_id,
            address,
            psk,
            Utc::now() + chrono::Duration::hours(24)
        );

        let signature = sign_data(&psk, &invitation_data)?;

        Ok(Self {
            version: "1.0".to_string(),
            instance_id,
            address,
            psk,
            expires_at: Utc::now() + chrono::Duration::hours(24),
            signature,
        })
    }

    /// Encode invitation as a base64 string
    pub fn to_string(&self) -> Result<String> {
        let json = serde_json::to_string(self)?;
        Ok(URL_SAFE_NO_PAD.encode(json.as_bytes()))
    }

    /// Decode invitation from a base64 string
    pub fn from_str(s: &str) -> Result<Self> {
        let json = URL_SAFE_NO_PAD.decode(s)?;
        let invitation: ClusterInvitation = serde_json::from_slice(&json)?;
        Ok(invitation)
    }

    /// Verify the invitation signature
    pub fn verify(&self) -> Result<bool> {
        let invitation_data = format!(
            "{}|{}|{}|{}",
            self.instance_id, self.address, self.psk, self.expires_at
        );

        verify_signature(&self.psk, &invitation_data, &self.signature)
    }

    /// Check if the invitation has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// Default cluster port
pub const DEFAULT_CLUSTER_PORT: u16 = 8080;

/// Cluster health check interval
pub const HEALTH_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Peer connection timeout
pub const PEER_CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
