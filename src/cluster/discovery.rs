//! Cluster discovery and invitation system
//!
//! Provides invitation-based cluster joining functionality for Fuji nodes.

use anyhow::{Result, anyhow};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::config::PeerInfo;

/// Cluster port for TCP communication
pub const CLUSTER_PORT: u16 = 8080;

/// Cluster invitation for joining a Fuji cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterInvitation {
    /// Invitation format version
    pub version: String,
    /// ID of the inviting instance
    pub instance_id: String,
    /// Network address of the inviting instance
    pub address: String,
    /// Pre-shared key for authentication
    pub psk: String,
    /// When the invitation expires
    pub expires_at: DateTime<Utc>,
    /// HMAC signature for integrity verification
    pub signature: String,
}

impl ClusterInvitation {
    /// Create a new cluster invitation
    pub fn new(
        instance_id: String,
        address: String,
        psk: String,
        expires_in_hours: i64,
    ) -> Result<Self> {
        let invitation = Self {
            version: "1.0".to_string(),
            instance_id: instance_id.clone(),
            address: address.clone(),
            psk,
            expires_at: Utc::now() + Duration::hours(expires_in_hours),
            signature: String::new(), // Will be set below
        };

        // Generate signature
        let signature = Self::generate_signature(&instance_id, &address, &invitation.expires_at)?;

        Ok(Self {
            signature,
            ..invitation
        })
    }

    /// Generate HMAC signature for the invitation
    fn generate_signature(
        instance_id: &str,
        address: &str,
        expires_at: &DateTime<Utc>,
    ) -> Result<String> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        // Use timestamp_nanos for higher precision to ensure unique signatures
        let data = format!(
            "{}:{}:{}",
            instance_id,
            address,
            expires_at.timestamp_nanos_opt().unwrap_or(0)
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(b"fuji-cluster-invitation")
            .map_err(|e| anyhow!("Failed to create HMAC: {e}"))?;
        mac.update(data.as_bytes());
        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        Ok(base64::engine::general_purpose::STANDARD.encode(code_bytes))
    }

    /// Verify the invitation signature
    pub fn verify(&self) -> Result<bool> {
        let expected_signature =
            Self::generate_signature(&self.instance_id, &self.address, &self.expires_at)?;

        Ok(self.signature == expected_signature)
    }

    /// Check if the invitation has expired
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Convert invitation to a base64 string for easy sharing
    #[allow(clippy::inherent_to_string)]
    #[must_use]
    pub fn to_string(&self) -> String {
        let json = serde_json::to_string(self).unwrap();
        base64::engine::general_purpose::STANDARD.encode(json.as_bytes())
    }

    /// Parse invitation from a base64 string
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        let json = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| anyhow!("Invalid base64 encoding: {e}"))?;

        let invitation: Self =
            serde_json::from_slice(&json).map_err(|e| anyhow!("Invalid invitation format: {e}"))?;

        Ok(invitation)
    }

    /// Get remaining hours until expiration
    #[must_use]
    pub fn hours_until_expiration(&self) -> i64 {
        let now = Utc::now();
        if self.expires_at > now {
            // Use num_seconds() and divide to get more precise calculation
            // This ensures we always return at least 1 if there's any time left
            let seconds_left = (self.expires_at - now).num_seconds();
            // Return at least 1 hour if there's any time left
            std::cmp::max(1, seconds_left / 3600)
        } else {
            0
        }
    }
}

/// Cluster discovery manager
pub struct DiscoveryManager {
    /// Local instance ID
    instance_id: String,
    /// Current invitations we've issued
    issued_invitations: Arc<RwLock<HashMap<String, ClusterInvitation>>>,
}

impl DiscoveryManager {
    /// Create a new discovery manager
    #[must_use]
    pub fn new(instance_id: String) -> Self {
        Self {
            instance_id,
            issued_invitations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate a new invitation for another node to join this cluster
    pub async fn generate_invitation(
        &self,
        peer_count: usize,
        expires_in_hours: Option<i64>,
    ) -> Result<ClusterInvitation> {
        // Get local address
        let local_addr = self.get_local_address().await?;
        let psk = self.generate_psk()?;

        // Create invitation
        let expires_in = expires_in_hours.unwrap_or(24);
        let invitation = ClusterInvitation::new(
            self.instance_id.clone(),
            format!("{}:{}", local_addr.ip(), CLUSTER_PORT),
            psk,
            expires_in,
        )?;

        // Store the invitation
        {
            let mut invitations = self.issued_invitations.write().await;
            invitations.insert(invitation.instance_id.clone(), invitation.clone());
        }

        info!(
            "Generated invitation for cluster with {} peers, expires in {} hours",
            peer_count + 1,
            expires_in
        );

        Ok(invitation)
    }

    /// Accept an invitation and join a cluster
    pub async fn accept_invitation(&self, invitation: ClusterInvitation) -> Result<PeerInfo> {
        // Verify the invitation
        if !invitation.verify()? {
            return Err(anyhow!("Invalid invitation signature"));
        }

        if invitation.is_expired() {
            return Err(anyhow!("Invitation has expired"));
        }

        // Create peer info from invitation
        let peer = PeerInfo {
            id: invitation.instance_id.clone(),
            address: invitation.address.clone(),
            psk: invitation.psk.clone(),
            last_seen: Utc::now(),
            status: crate::config::PeerStatus::Disconnected,
        };

        info!(
            "Accepted invitation from instance {} at {}",
            invitation.instance_id, invitation.address
        );

        Ok(peer)
    }

    /// Get the local network address
    async fn get_local_address(&self) -> Result<SocketAddr> {
        // Try to get a non-localhost IP address first
        if let Ok(addr) = local_ip_address::local_ip() {
            if addr.is_ipv4() && !addr.is_loopback() {
                return Ok(SocketAddr::new(addr, CLUSTER_PORT));
            }
        }

        // Fallback to localhost
        Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            CLUSTER_PORT,
        ))
    }

    /// Generate a pre-shared key for authentication
    fn generate_psk(&self) -> Result<String> {
        use rand::distributions::Alphanumeric;
        use rand::{Rng, thread_rng};

        let psk: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        Ok(psk)
    }

    /// Clean up expired invitations
    #[allow(dead_code)]
    pub async fn cleanup_expired_invitations(&self) {
        let mut invitations = self.issued_invitations.write().await;
        let mut to_remove = Vec::new();

        for (id, invitation) in invitations.iter() {
            if invitation.is_expired() {
                to_remove.push(id.clone());
            }
        }

        for id in to_remove {
            invitations.remove(&id);
            debug!("Removed expired invitation for instance {}", id);
        }
    }

    /// Get list of issued invitations
    #[allow(dead_code)]
    pub async fn get_issued_invitations(&self) -> Vec<ClusterInvitation> {
        self.issued_invitations
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invitation_creation() {
        let invitation = ClusterInvitation::new(
            "test-instance".to_string(),
            "192.168.1.10:8080".to_string(),
            "test-psk-123".to_string(),
            24,
        )
        .unwrap();

        assert_eq!(invitation.version, "1.0");
        assert_eq!(invitation.instance_id, "test-instance");
        assert_eq!(invitation.address, "192.168.1.10:8080");
        assert_eq!(invitation.psk, "test-psk-123");
        assert!(!invitation.is_expired());
    }

    #[test]
    fn test_invitation_signature() {
        let invitation = ClusterInvitation::new(
            "test-instance".to_string(),
            "192.168.1.10:8080".to_string(),
            "test-psk-123".to_string(),
            24,
        )
        .unwrap();

        // Valid signature should verify
        assert!(invitation.verify().unwrap());

        // Tampered invitation should not verify
        let mut tampered = invitation.clone();
        tampered.instance_id = "malicious".to_string();
        assert!(!tampered.verify().unwrap());
    }

    #[test]
    fn test_invitation_serialization() {
        let invitation = ClusterInvitation::new(
            "test-instance".to_string(),
            "192.168.1.10:8080".to_string(),
            "test-psk-123".to_string(),
            24,
        )
        .unwrap();

        let string = invitation.to_string();
        let parsed = ClusterInvitation::from_str(&string).unwrap();

        assert_eq!(invitation.instance_id, parsed.instance_id);
        assert_eq!(invitation.address, parsed.address);
        assert_eq!(invitation.psk, parsed.psk);
    }

    #[tokio::test]
    async fn test_discovery_manager() {
        let manager = DiscoveryManager::new("my-instance".to_string());

        let invitation = manager.generate_invitation(2, Some(1)).await.unwrap();

        assert!(!invitation.is_expired());
        assert_eq!(invitation.instance_id, "my-instance");

        // Accept the invitation
        let peer = manager.accept_invitation(invitation.clone()).await.unwrap();
        assert_eq!(peer.id, "my-instance");
        assert_eq!(peer.address, invitation.address);
        assert_eq!(peer.psk, invitation.psk);
    }
}
