use std::sync::Arc;
// use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;

use fuji::cluster::{ClusterConfig, ClusterState};
use fuji::cluster::discovery::DiscoveryManager;
use fuji::config::{Config, PeerInfo, PeerStatus};
use fuji::mount::{MountConfig, MountConfigWrapper, MountStatus};
use fuji::network::tcp::TcpTransport;
use fuji::sync::coordinator::SyncCoordinator;
use fuji::sync::merge::ConfigMerger;

#[tokio::test]
async fn test_complete_cluster_join_workflow() {
    // Instance 1: Creates cluster
    let instance1_id = "instance-1".to_string();
    let discovery1 = DiscoveryManager::new(instance1_id.clone());

    // Generate invitation from instance 1
    let invitation = discovery1.generate_invitation(2, Some(1)).await.unwrap();

    // Verify invitation
    assert!(!invitation.is_expired());
    assert!(invitation.verify().unwrap());

    // Instance 2: Joins cluster
    let instance2_id = "instance-2".to_string();
    let discovery2 = DiscoveryManager::new(instance2_id.clone());

    // Accept invitation
    let peer_info = discovery2.accept_invitation(invitation.clone()).await.unwrap();

    // Verify peer info
    assert_eq!(peer_info.id, instance1_id);
    assert_eq!(peer_info.status, PeerStatus::Disconnected);

    // Instance 2 sets up its configuration
    let mut config2 = Config::default();
    config2.cluster = Some(ClusterConfig {
        enabled: true,
        instance_id: instance2_id.clone(),
        peers: vec![peer_info],
        sync_interval: Duration::minutes(1), // Short for testing
        sync_timeout: Duration::minutes(2),
        sync_metadata: Default::default(),
    });

    let config2 = Arc::new(RwLock::new(config2));

    // Verify configuration
    let config = config2.read().await;
    assert!(config.cluster.is_some());
    assert_eq!(config.cluster.as_ref().unwrap().peers.len(), 1);
}

#[tokio::test]
async fn test_three_instance_cluster_sync() {
    // Create three instances with different configs
    let instances = vec![
        create_test_instance("instance-1"),
        create_test_instance("instance-2"),
        create_test_instance("instance-3"),
    ];

    // Add different mounts to each instance
    add_test_mount(&instances[0], "shared-data-1", "nfs://server1/data", true);
    add_test_mount(&instances[1], "shared-data-2", "nfs://server2/data", true);
    add_test_mount(&instances[2], "shared-data-3", "nfs://server3/data", true);

    // Add a common mount with different timestamps to test conflict resolution
    add_timestamped_mount(&instances[0], "common-mount", "nfs://common/data",
        chrono::Utc::now() - Duration::hours(3));
    add_timestamped_mount(&instances[1], "common-mount", "nfs://common/data",
        chrono::Utc::now() - Duration::hours(2));
    add_timestamped_mount(&instances[2], "common-mount", "nfs://common/data",
        chrono::Utc::now() - Duration::hours(1));

    // Merge all configs
    let merger = ConfigMerger::new();
    let configs: Vec<(String, Config)> = instances.into_iter().enumerate()
        .map(|(i, config)| (format!("instance-{}", i + 1), config))
        .collect();

    let merged = merger.merge_configs(configs).await.unwrap();

    // Verify merge results
    assert_eq!(merged.config.mounts.len(), 4); // 3 unique + 1 common

    // Should have all three instance-specific mounts
    assert!(merged.config.mounts.contains_key("shared-data-1"));
    assert!(merged.config.mounts.contains_key("shared-data-2"));
    assert!(merged.config.mounts.contains_key("shared-data-3"));

    // Should have the common mount with the latest timestamp
    assert!(merged.config.mounts.contains_key("common-mount"));
    let common_mount = merged.config.mounts.get("common-mount").unwrap();

    // Verify it's the newest version (from instance-3)
    let expected_time = chrono::Utc::now() - Duration::hours(1);
    let time_diff = (common_mount.config.updated_at - expected_time).num_seconds().abs();
    assert!(time_diff < 60); // Within 1 minute tolerance
}

#[tokio::test]
async fn test_cluster_state_management() {
    let cluster_state = Arc::new(ClusterState::new());

    // Add multiple peers
    let peers = vec![
        PeerInfo {
            id: "peer-1".to_string(),
            address: "127.0.0.1:8081".to_string(),
            psk: "psk-1".to_string(),
            last_seen: chrono::Utc::now(),
            status: PeerStatus::Connected,
        },
        PeerInfo {
            id: "peer-2".to_string(),
            address: "127.0.0.1:8082".to_string(),
            psk: "psk-2".to_string(),
            last_seen: chrono::Utc::now(),
            status: PeerStatus::Connected,
        },
        PeerInfo {
            id: "peer-3".to_string(),
            address: "127.0.0.1:8083".to_string(),
            psk: "psk-3".to_string(),
            last_seen: chrono::Utc::now() - Duration::minutes(5),
            status: PeerStatus::Disconnected,
        },
    ];

    // Add peers to cluster state
    for peer in peers {
        cluster_state.add_peer(peer).await;
    }

    // Verify all peers are added
    let all_peers = cluster_state.get_peers().await;
    assert_eq!(all_peers.len(), 3);

    // Update a peer's status
    cluster_state.update_peer_status("peer-2", PeerStatus::Disconnected).await;

    // Check updated status
    let updated_peers = cluster_state.get_peers().await;
    let peer_2 = updated_peers.iter().find(|p| p.id == "peer-2").unwrap();
    assert_eq!(peer_2.status, PeerStatus::Disconnected);

    // Mark a peer as seen
    let old_last_seen = updated_peers.iter()
        .find(|p| p.id == "peer-3")
        .unwrap()
        .last_seen;

    sleep(Duration::from_millis(10)).await;
    cluster_state.mark_peer_seen("peer-3").await;

    // Verify last_seen was updated
    let final_peers = cluster_state.get_peers().await;
    let peer_3 = final_peers.iter().find(|p| p.id == "peer-3").unwrap();
    assert!(peer_3.last_seen > old_last_seen);
}

#[tokio::test]
async fn test_invitation_lifecycle() {
    // Create invitation with 1 second expiration
    let invitation = fuji::cluster::ClusterInvitation::new(
        "test-instance".to_string(),
        "127.0.0.1:8080".to_string(),
        "test-psk".to_string(),
        1, // 1 hour
    ).unwrap();

    // Should be valid initially
    assert!(!invitation.is_expired());
    assert!(invitation.hours_until_expiration() > 0);

    // Serialize and deserialize
    let serialized = invitation.to_string();
    let deserialized = fuji::cluster::ClusterInvitation::from_str(&serialized).unwrap();

    // Should be identical
    assert_eq!(invitation.instance_id, deserialized.instance_id);
    assert_eq!(invitation.address, deserialized.address);
    assert_eq!(invitation.psk, deserialized.psk);
    assert!(deserialized.verify().unwrap());
}

#[tokio::test]
async fn test_configuration_persistence() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("test-config.toml");

    // Create a test configuration with cluster settings
    let mut config = Config::default();
    config.cluster = Some(ClusterConfig {
        enabled: true,
        instance_id: "persistent-instance".to_string(),
        peers: vec![
            PeerInfo {
                id: "peer-1".to_string(),
                address: "192.168.1.10:8080".to_string(),
                psk: "persistent-psk".to_string(),
                last_seen: chrono::Utc::now(),
                status: PeerStatus::Connected,
            },
        ],
        sync_interval: Duration::minutes(5),
        sync_timeout: Duration::minutes(10),
        sync_metadata: fuji::config::SyncMetadata {
            last_sync_at: Some(chrono::Utc::now()),
            sync_version: 42,
            last_modified_by: Some("test-instance".to_string()),
            pending_conflicts: vec![],
        },
    });

    // Save configuration
    config.save_to_dir(temp_dir.path()).await.unwrap();

    // Load configuration
    let loaded_config = Config::load_with_dir(temp_dir.path()).await.unwrap();

    // Verify loaded configuration
    assert!(loaded_config.cluster.is_some());
    let cluster = loaded_config.cluster.unwrap();
    assert_eq!(cluster.instance_id, "persistent-instance");
    assert_eq!(cluster.peers.len(), 1);
    assert_eq!(cluster.peers[0].id, "peer-1");
    assert_eq!(cluster.sync_interval, Duration::minutes(5));
    assert_eq!(cluster.sync_metadata.sync_version, 42);
}

#[tokio::test]
async fn test_sync_timer_behavior() {
    let instance_id = "timer-test".to_string();
    let cluster_state = Arc::new(ClusterState::new());
    let config = Arc::new(RwLock::new(Config::default()));
    let transport = Arc::new(TcpTransport::new("127.0.0.1:0".parse().unwrap()));

    let mut coordinator = SyncCoordinator::new(
        instance_id,
        cluster_state,
        transport,
        config,
    );

    // Initially should be able to initiate sync
    assert!(coordinator.should_initiate_sync());

    // After marking peer request, should not initiate
    coordinator.mark_peer_request().await;
    assert!(!coordinator.should_initiate_sync());

    // After cooldown (simulated by reset), should be able to initiate again
    coordinator.reset_peer_request_timer().await;
    assert!(coordinator.should_initiate_sync());
}

// Helper functions
fn create_test_instance(instance_id: &str) -> Config {
    let mut config = Config::default();
    config.cluster = Some(ClusterConfig {
        enabled: true,
        instance_id: instance_id.to_string(),
        peers: vec![],
        sync_interval: Duration::minutes(5),
        sync_timeout: Duration::minutes(10),
        sync_metadata: Default::default(),
    });
    config
}

fn add_test_mount(config: &Config, mount_id: &str, url: &str, enabled: bool) {
    let mount_config = MountConfig {
        id: mount_id.to_string(),
        url: url.to_string(),
        mount_point: Some(format!("/mnt/{}", mount_id)),
        options: Some(vec!["rw".to_string(), "soft".to_string()]),
        enabled,
        status: if enabled { MountStatus::Mounted } else { MountStatus::Unmounted },
        created_at: chrono::Utc::now() - Duration::hours(1),
        updated_at: chrono::Utc::now(),
    };

    // Since config is immutable, this is just for testing structure
    // In real usage, you'd have a mutable reference or use the write lock
}

fn add_timestamped_mount(config: &Config, mount_id: &str, url: &str, updated_at: chrono::DateTime<chrono::Utc>) {
    let mount_config = MountConfig {
        id: mount_id.to_string(),
        url: url.to_string(),
        mount_point: Some(format!("/mnt/{}", mount_id)),
        options: Some(vec!["rw".to_string(), "soft".to_string()]),
        enabled: true,
        status: MountStatus::Mounted,
        created_at: updated_at - Duration::minutes(30),
        updated_at,
    };

    // This would need to be implemented properly with mutable access
}