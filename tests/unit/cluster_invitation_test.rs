use std::time::Duration;
use tokio::time::{sleep, timeout};

use fuji::cluster::discovery::{ClusterInvitation, DiscoveryManager};
use fuji::cluster::instance::InstanceInfo;
use fuji::config::PeerInfo;
use fuji::network::tcp::TcpTransport;
use fuji::sync::coordinator::SyncCoordinator;
use fuji::sync::protocol::{SyncMessage, SyncRequest, SyncResponse};

#[tokio::test]
async fn test_invitation_creation_and_verification() {
    // Create a new invitation
    let instance_id = "test-instance-123".to_string();
    let address = "192.168.1.10:8080".to_string();
    let psk = "test-pre-shared-key-123".to_string();

    let invitation =
        ClusterInvitation::new(instance_id.clone(), address.clone(), psk.clone(), 24).unwrap();

    // Verify invitation properties
    assert_eq!(invitation.instance_id, instance_id);
    assert_eq!(invitation.address, address);
    assert_eq!(invitation.psk, psk);
    assert!(!invitation.is_expired());
    assert_eq!(invitation.version, "1.0");

    // Verify signature
    assert!(invitation.verify().unwrap());

    // Test serialization/deserialization
    let invitation_str = invitation.to_string();
    let parsed_invitation = ClusterInvitation::from_str(&invitation_str).unwrap();

    assert_eq!(invitation.instance_id, parsed_invitation.instance_id);
    assert_eq!(invitation.address, parsed_invitation.address);
    assert_eq!(invitation.psk, parsed_invitation.psk);
    assert_eq!(invitation.signature, parsed_invitation.signature);
}

#[tokio::test]
async fn test_invitation_expiration() {
    let invitation = ClusterInvitation::new(
        "test-instance".to_string(),
        "192.168.1.10:8080".to_string(),
        "test-psk".to_string(),
        1, // Expires in 1 hour
    )
    .unwrap();

    // Should not be expired
    assert!(!invitation.is_expired());
    assert!(invitation.hours_until_expiration() > 0);
    assert!(invitation.hours_until_expiration() <= 1);
}

#[tokio::test]
async fn test_invitation_signature_tampering() {
    let mut invitation = ClusterInvitation::new(
        "test-instance".to_string(),
        "192.168.1.10:8080".to_string(),
        "test-psk".to_string(),
        24,
    )
    .unwrap();

    // Tamper with the instance ID
    invitation.instance_id = "malicious-instance".to_string();

    // Signature should no longer verify
    assert!(!invitation.verify().unwrap());
}

#[tokio::test]
async fn test_discovery_manager() {
    let instance_id = "test-discovery-instance".to_string();
    let discovery = DiscoveryManager::new(instance_id.clone());

    // Generate invitation
    let invitation = discovery.generate_invitation(2, Some(24)).await.unwrap();

    assert_eq!(invitation.instance_id, instance_id);
    assert!(!invitation.is_expired());
    assert!(invitation.verify().unwrap());

    // Accept the invitation as a peer
    let peer = discovery
        .accept_invitation(invitation.clone())
        .await
        .unwrap();
    assert_eq!(peer.id, invitation.instance_id);
    assert_eq!(peer.address, invitation.address);
    assert_eq!(peer.psk, invitation.psk);
}

#[tokio::test]
async fn test_invalid_invitation_acceptance() {
    let instance_id = "test-instance".to_string();
    let discovery = DiscoveryManager::new(instance_id);

    // Create a fake invitation with invalid signature
    let mut invitation = ClusterInvitation::new(
        "other-instance".to_string(),
        "192.168.1.20:8080".to_string(),
        "fake-psk".to_string(),
        24,
    )
    .unwrap();
    invitation.signature = "invalid-signature".to_string();

    // Should fail to accept
    let result = discovery.accept_invitation(invitation).await;
    assert!(result.is_err());
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn test_cluster_invitation_workflow() {
        // Simulate two instances joining a cluster

        // Instance 1: Create invitation
        let discovery1 = DiscoveryManager::new("instance-1".to_string());
        let invitation = discovery1.generate_invitation(1, Some(1)).await.unwrap();

        // Instance 2: Accept invitation
        let discovery2 = DiscoveryManager::new("instance-2".to_string());
        let peer_info = discovery2
            .accept_invitation(invitation.clone())
            .await
            .unwrap();

        // Verify peer info
        assert_eq!(peer_info.id, "instance-1");
        assert_eq!(peer_info.status, fuji::config::PeerStatus::Disconnected);
        assert!(!peer_info.psk.is_empty());

        // The invitation should still be valid
        assert!(!invitation.is_expired());
        assert!(invitation.verify().unwrap());
    }

    #[tokio::test]
    async fn test_multiple_invitations() {
        let discovery = DiscoveryManager::new("host-instance".to_string());

        // Generate multiple invitations
        let invitation1 = discovery.generate_invitation(0, Some(1)).await.unwrap();
        let invitation2 = discovery.generate_invitation(0, Some(1)).await.unwrap();

        // They should have different PSKs but same instance info
        assert_eq!(invitation1.instance_id, invitation2.instance_id);
        assert_eq!(invitation1.address, invitation2.address);
        assert_ne!(invitation1.psk, invitation2.psk);
        assert_ne!(invitation1.signature, invitation2.signature);

        // Both should be verifiable
        assert!(invitation1.verify().unwrap());
        assert!(invitation2.verify().unwrap());
    }
}
