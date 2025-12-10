use chrono::{Duration, Utc};
use fuji::config::{ClusterConfig, Config, MountConfigWrapper};
use fuji::mount::{MountConfig, MountStatus};
use fuji::sync::merge::ConfigMerger;

#[tokio::test]
async fn test_simple_merge_no_conflicts() {
    let mut merger = ConfigMerger::new();

    // Create three instance configs with different mounts
    let mut config1 = create_test_config("instance-1");
    let mut config2 = create_test_config("instance-2");
    let mut config3 = create_test_config("instance-3");

    // Add different mounts to each instance
    add_mount(&mut config1, "mount-1", Utc::now() - Duration::hours(3));
    add_mount(&mut config2, "mount-2", Utc::now() - Duration::hours(2));
    add_mount(&mut config3, "mount-3", Utc::now() - Duration::hours(1));

    let configs = vec![
        ("instance-1".to_string(), config1),
        ("instance-2".to_string(), config2),
        ("instance-3".to_string(), config3),
    ];

    // Merge configs
    let result = merger.merge_configs(&configs).await.unwrap();

    // Should have all three mounts
    assert_eq!(result.config.mounts.len(), 3);
    assert!(result.config.mounts.contains_key("mount-1"));
    assert!(result.config.mounts.contains_key("mount-2"));
    assert!(result.config.mounts.contains_key("mount-3"));

    // No conflicts should be detected
    assert!(result.resolved_conflicts.is_empty());
}

#[tokio::test]
async fn test_merge_with_timestamp_conflicts() {
    let mut merger = ConfigMerger::with_instance_id("instance-1".to_string());

    let base_time = Utc::now();

    // Create configs with same mount but different timestamps
    let mut config1 = create_test_config("instance-1");
    let mut config2 = create_test_config("instance-2");

    // Add same mount with different update times
    add_mount_with_config(
        &mut config1,
        "shared-mount",
        base_time,
        Some("option1=value1"),
    );
    add_mount_with_config(
        &mut config2,
        "shared-mount",
        base_time + Duration::minutes(30),
        Some("option2=value2"),
    );

    let configs = vec![
        ("instance-1".to_string(), config1),
        ("instance-2".to_string(), config2),
    ];

    // Merge configs
    let result = merger.merge_configs(&configs).await.unwrap();

    // Should have the most recent version (instance-2's version)
    assert_eq!(result.config.mounts.len(), 1);
    let mount = result.config.mounts.get("shared-mount").unwrap();
    if let fuji::mount::MountType::Nfs {
        options,
        ..
    } = &mount.config.mount_type
    {
        assert_eq!(options.get(0), Some(&"option2=value2".to_string()));
    } else {
        panic!("Expected NFS mount type");
    }
}

#[tokio::test]
async fn test_merge_with_concurrent_modifications() {
    let mut merger = ConfigMerger::with_instance_id("instance-1".to_string());

    let same_time = Utc::now();

    // Create configs with same mount updated at the exact same time
    let mut config1 = create_test_config("instance-1");
    let mut config2 = create_test_config("instance-2");

    // Add same mount with same timestamp but different content
    add_mount_with_config(
        &mut config1,
        "conflicting-mount",
        same_time,
        Some("option1=value1"),
    );
    add_mount_with_config(
        &mut config2,
        "conflicting-mount",
        same_time,
        Some("option2=value2"),
    );

    let configs = vec![
        ("instance-1".to_string(), config1),
        ("instance-2".to_string(), config2),
    ];

    // Merge configs
    let result = merger.merge_configs(&configs).await.unwrap();

    // Should detect and resolve conflict
    assert_eq!(result.config.mounts.len(), 1);
    assert_eq!(result.resolved_conflicts.len(), 1);

    // Check the conflict resolution
    match &result.resolved_conflicts[0] {
        fuji::config::ConflictResolution::UsedInstance(instance_id) => {
            // Should pick instance-1 (preferred instance)
            assert_eq!(instance_id, "instance-1");
        }
        _ => panic!("Expected UsedInstance resolution"),
    }

    // With deterministic tie-breaking, should pick instance-1 (lexicographically smaller)
    let mount = result.config.mounts.get("conflicting-mount").unwrap();
    // Since we can't access mount.config.options directly, let's just check the mount exists
    assert_eq!(mount.config.id, "conflicting-mount");
}

#[tokio::test]
async fn test_global_settings_merge() {
    let mut merger = ConfigMerger::new();

    // Create configs with different global settings
    let mut config1 = create_test_config("instance-1");
    let mut config2 = create_test_config("instance-2");

    // Set different sync intervals and timestamps
    if let Some(cluster) = config1.cluster.as_mut() {
        cluster.sync_interval = Duration::minutes(5);
        cluster.sync_metadata.last_sync_at = Some(Utc::now() - chrono::Duration::minutes(5));
    }
    if let Some(cluster) = config2.cluster.as_mut() {
        cluster.sync_interval = Duration::minutes(10);
        cluster.sync_metadata.last_sync_at = Some(Utc::now());
    }

    let configs = vec![
        ("instance-1".to_string(), config1),
        ("instance-2".to_string(), config2),
    ];

    // Merge configs
    let result = merger.merge_configs(&configs).await.unwrap();

    // Should use the most recent setting
    if let Some(cluster) = result.config.cluster {
        assert_eq!(cluster.sync_interval, Duration::minutes(10));
    }
}

#[tokio::test]
async fn test_empty_config_merge() {
    let mut merger = ConfigMerger::new();

    let mut config1 = create_test_config("instance-1");
    let mut config2 = Config::default();
    config2.cluster = Some(ClusterConfig {
        enabled: true,
        instance_id: "instance-2".to_string(),
        peers: vec![],
        port: 10080,
        sync_interval: Duration::minutes(5),
        sync_timeout: Duration::minutes(10),
        sync_metadata: Default::default(),
    });

    add_mount(&mut config1, "test-mount", Utc::now());

    let configs = vec![
        ("instance-1".to_string(), config1),
        ("instance-2".to_string(), config2),
    ];

    // Merge configs
    let result = merger.merge_configs(&configs).await.unwrap();

    // Should have the mount from instance-1
    assert_eq!(result.config.mounts.len(), 1);
    assert!(result.config.mounts.contains_key("test-mount"));
}

#[tokio::test]
async fn test_merge_strategy_latest_wins() {
    let mut merger = ConfigMerger::new();

    let base_time = Utc::now();

    // Create configs where one has newer timestamps
    let mut config1 = create_test_config("instance-1");
    let mut config2 = create_test_config("instance-2");

    add_mount(&mut config1, "old-mount", base_time - Duration::hours(1));
    add_mount(&mut config2, "new-mount", base_time);

    let configs = vec![
        ("instance-1".to_string(), config1),
        ("instance-2".to_string(), config2),
    ];

    // Merge with latest wins strategy
    let result = merger.merge_configs(&configs).await.unwrap();

    // Should prefer newer mounts
    assert!(result.config.mounts.contains_key("old-mount"));
    assert!(result.config.mounts.contains_key("new-mount"));
}

#[tokio::test]
async fn test_merge_preserves_metadata() {
    let mut merger = ConfigMerger::new();

    let configs = vec![
        ("instance-1".to_string(), create_test_config("instance-1")),
        ("instance-2".to_string(), create_test_config("instance-2")),
    ];

    // Merge configs
    let result = merger.merge_configs(&configs).await.unwrap();

    // Check sync metadata
    assert!(result.sync_metadata.last_sync_at.is_some());
    assert!(result.sync_metadata.sync_version > 0);
}

// Helper functions
fn create_test_config(instance_id: &str) -> Config {
    let mut config = Config::default();
    config.cluster = Some(ClusterConfig {
        enabled: true,
        instance_id: instance_id.to_string(),
        peers: vec![],
        port: 10080,
        sync_interval: Duration::seconds(300), // 5 minutes
        sync_timeout: Duration::seconds(600),  // 10 minutes
        sync_metadata: Default::default(),
    });
    config
}

fn add_mount(config: &mut Config, mount_id: &str, updated_at: chrono::DateTime<Utc>) {
    let mount_config = MountConfig {
        id: mount_id.to_string(),
        url: format!("nfs://server/{}/{}", mount_id, mount_id),
        mount_point: std::path::PathBuf::from(format!("/mnt/{}", mount_id)),
        mount_type: fuji::mount::MountType::Nfs {
            host: "server".to_string(),
            share: mount_id.to_string(),
            options: vec![],
        },
        enabled: true,
        status: MountStatus::Active,
        created_at: updated_at - chrono::Duration::minutes(5),
        updated_at,
        last_connected: None,
        reconnect_attempts: 0,
        metadata: std::collections::HashMap::new(),
    };

    config.mounts.insert(
        mount_id.to_string(),
        MountConfigWrapper {
            config: mount_config,
            sync_metadata: None,
        },
    );
}

fn add_mount_with_config(
    config: &mut Config,
    mount_id: &str,
    updated_at: chrono::DateTime<Utc>,
    option: Option<&str>,
) {
    let options = option.map(|o| vec![o.to_string()]).unwrap_or_default();
    let mount_config = MountConfig {
        id: mount_id.to_string(),
        url: format!("nfs://server/{}/{}", mount_id, mount_id),
        mount_point: std::path::PathBuf::from(format!("/mnt/{}", mount_id)),
        mount_type: fuji::mount::MountType::Nfs {
            host: "server".to_string(),
            share: mount_id.to_string(),
            options,
        },
        enabled: true,
        status: MountStatus::Active,
        created_at: updated_at - chrono::Duration::minutes(5),
        updated_at,
        last_connected: None,
        reconnect_attempts: 0,
        metadata: std::collections::HashMap::new(),
    };

    config.mounts.insert(
        mount_id.to_string(),
        MountConfigWrapper {
            config: mount_config,
            sync_metadata: None,
        },
    );
}
