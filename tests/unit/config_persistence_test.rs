//! Unit tests for configuration persistence
//!
//! Tests that configuration changes are properly saved to and loaded from disk.

use chrono::Utc;
use fuji::config::Config;
use fuji::mount::{MountConfig, MountStatus, MountType};
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::TempDir;

// Helper to create a test mount config
fn create_test_mount(id: &str, url: &str, mount_point: &str, enabled: bool) -> MountConfig {
    let now = Utc::now();

    // Parse mount type from URL
    let mount_type = if url.starts_with("nfs://") {
        MountType::Nfs {
            host: "server".to_string(),
            share: "/export".to_string(),
            options: vec![],
        }
    } else if url.starts_with("smb://") || url.starts_with("cifs://") {
        MountType::Smb {
            host: "server".to_string(),
            share: "share".to_string(),
            username: None,
            password: None,
            domain: None,
            options: vec![],
        }
    } else {
        MountType::Sshfs {
            host: "host".to_string(),
            username: Some("user".to_string()),
            path: "/path".to_string(),
            private_key: None,
            password: None,
            options: vec![],
        }
    };

    MountConfig {
        id: id.to_string(),
        url: url.to_string(),
        mount_point: PathBuf::from(mount_point),
        mount_type,
        enabled,
        status: if enabled {
            MountStatus::Active
        } else {
            MountStatus::Disabled
        },
        created_at: now,
        updated_at: now,
        last_connected: None,
        reconnect_attempts: 0,
        metadata: HashMap::new(),
    }
}

#[tokio::test]
async fn test_config_creates_file_on_first_save() {
    // Given: No config file exists
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("mounts.toml");

    // Create a new config
    let config = Config::default();

    // When: Config is saved
    config
        .save_to_dir(temp_dir.path())
        .await
        .expect("Failed to save config");

    // Then: File is created at correct path
    assert!(
        config_path.exists(),
        "Config file should be created at {:?}",
        config_path
    );
    assert!(config_path.is_file(), "Config path should be a file");

    // Verify file is not empty
    let metadata = std::fs::metadata(&config_path).expect("Failed to get file metadata");
    assert!(metadata.len() > 0, "Config file should not be empty");
}

#[tokio::test]
async fn test_config_loads_from_file() {
    // Given: Config file with 2 mounts
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mut config = Config::default();

    // Add two test mounts
    let mount1 = create_test_mount("mount1", "nfs://server1/export1", "/mnt/nfs1", true);
    let mount2 = create_test_mount("mount2", "smb://server2/share2", "/mnt/smb2", false);

    config.add_mount(mount1);
    config.add_mount(mount2);

    // Save to file
    config
        .save_to_dir(temp_dir.path())
        .await
        .expect("Failed to save config");

    // When: Config is loaded from file
    let loaded_config = Config::load_with_dir(temp_dir.path())
        .await
        .expect("Failed to load config");

    // Then: Both mounts are present in memory
    assert_eq!(
        loaded_config.mounts.len(),
        2,
        "Should have 2 mounts after loading"
    );

    let loaded_mount1 = loaded_config
        .get_mount("mount1")
        .expect("Mount1 should exist");
    assert_eq!(loaded_mount1.url, "nfs://server1/export1");
    assert_eq!(loaded_mount1.mount_point, PathBuf::from("/mnt/nfs1"));
    assert!(loaded_mount1.enabled, "Mount1 should be enabled");

    let loaded_mount2 = loaded_config
        .get_mount("mount2")
        .expect("Mount2 should exist");
    assert_eq!(loaded_mount2.url, "smb://server2/share2");
    assert!(!loaded_mount2.enabled, "Mount2 should be disabled");
}

#[tokio::test]
async fn test_add_mount_persists_to_disk() {
    // Given: Empty config
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mut config = Config::default();

    // Save initial empty config
    config
        .save_to_dir(temp_dir.path())
        .await
        .expect("Failed to save initial config");

    // When: Mount is added and saved
    let new_mount = create_test_mount("test-mount", "nfs://192.168.1.100/data", "/mnt/data", true);

    config.add_mount(new_mount.clone());
    config
        .save_to_dir(temp_dir.path())
        .await
        .expect("Failed to save config after adding mount");

    // Then: Mount exists in file after reload
    let reloaded_config = Config::load_with_dir(temp_dir.path())
        .await
        .expect("Failed to reload config");

    assert_eq!(
        reloaded_config.mounts.len(),
        1,
        "Should have 1 mount after reload"
    );

    let persisted_mount = reloaded_config
        .get_mount("test-mount")
        .expect("Mount should exist after reload");
    assert_eq!(persisted_mount.url, new_mount.url);
    assert_eq!(persisted_mount.mount_point, new_mount.mount_point);
    assert_eq!(persisted_mount.enabled, new_mount.enabled);
}

#[tokio::test]
async fn test_remove_mount_persists_to_disk() {
    // Given: Config with 1 mount
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mut config = Config::default();

    let mount = create_test_mount("to-remove", "nfs://server/export", "/mnt/test", true);

    config.add_mount(mount);
    config
        .save_to_dir(temp_dir.path())
        .await
        .expect("Failed to save config");

    // Verify mount exists
    assert_eq!(config.mounts.len(), 1);

    // When: Mount is removed and saved
    config.remove_mount("to-remove");
    config
        .save_to_dir(temp_dir.path())
        .await
        .expect("Failed to save config after removal");

    // Then: Mount is gone from file after reload
    let reloaded_config = Config::load_with_dir(temp_dir.path())
        .await
        .expect("Failed to reload config");

    assert_eq!(
        reloaded_config.mounts.len(),
        0,
        "Should have 0 mounts after removal"
    );
    assert!(
        reloaded_config.get_mount("to-remove").is_none(),
        "Removed mount should not exist after reload"
    );
}

#[tokio::test]
async fn test_enable_disable_persists_to_disk() {
    // Given: Config with disabled mount
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mut config = Config::default();

    let mount = create_test_mount("toggle-mount", "nfs://server/data", "/mnt/data", false);

    config.add_mount(mount);
    config
        .save_to_dir(temp_dir.path())
        .await
        .expect("Failed to save config");

    // When: Mount is enabled and saved
    if let Some(m) = config.get_mount_mut("toggle-mount") {
        m.enable();
    }
    config
        .save_to_dir(temp_dir.path())
        .await
        .expect("Failed to save config after enable");

    // Then: enabled=true in file after reload
    let reloaded_config = Config::load_with_dir(temp_dir.path())
        .await
        .expect("Failed to reload config");

    let persisted_mount = reloaded_config
        .get_mount("toggle-mount")
        .expect("Mount should exist");
    assert!(
        persisted_mount.enabled,
        "Mount should be enabled after reload"
    );

    // Test disable as well
    let mut config = reloaded_config;
    if let Some(m) = config.get_mount_mut("toggle-mount") {
        m.disable();
    }
    config
        .save_to_dir(temp_dir.path())
        .await
        .expect("Failed to save config after disable");

    let final_config = Config::load_with_dir(temp_dir.path())
        .await
        .expect("Failed to reload config after disable");

    let final_mount = final_config
        .get_mount("toggle-mount")
        .expect("Mount should still exist");
    assert!(
        !final_mount.enabled,
        "Mount should be disabled after reload"
    );
}

#[tokio::test]
async fn test_atomic_save_prevents_corruption() {
    // Given: Valid config file
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mut config = Config::default();

    let mount = create_test_mount("atomic-test", "nfs://server/export", "/mnt/atomic", true);

    config.add_mount(mount);
    config
        .save_to_dir(temp_dir.path())
        .await
        .expect("Failed to save initial config");

    let config_path = temp_dir.path().join("mounts.toml");
    let original_content = std::fs::read_to_string(&config_path).expect("Failed to read config");

    // When: Save is called again to same directory
    let mount2 = create_test_mount("atomic-test-2", "smb://server2/share", "/mnt/atomic2", true);

    config.add_mount(mount2);
    config
        .save_to_dir(temp_dir.path())
        .await
        .expect("Failed to save with new mount");

    // Then: File is updated atomically (no .tmp files left)
    assert!(config_path.exists(), "Config file should exist");

    // Check no temp files are left behind
    let temp_files: Vec<_> = std::fs::read_dir(temp_dir.path())
        .expect("Failed to read temp dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();

    assert_eq!(
        temp_files.len(),
        0,
        "No .tmp files should be left after atomic save"
    );

    // Verify new content is different from original
    let new_content = std::fs::read_to_string(&config_path).expect("Failed to read new config");
    assert_ne!(
        original_content, new_content,
        "Config content should have changed"
    );
    assert!(
        new_content.contains("atomic-test-2"),
        "New mount should be in saved file"
    );
}

#[tokio::test]
async fn test_config_roundtrip_preserves_data() {
    // Given: Config with multiple mounts and various states
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mut config = Config::default();

    // Add mounts with different configurations
    let mount1 = create_test_mount("mount-enabled", "nfs://server1/export1", "/mnt/nfs1", true);
    let mount2 = create_test_mount("mount-disabled", "smb://server2/share2", "/mnt/smb2", false);
    let mount3 = create_test_mount("mount-sshfs", "sshfs://user@host:/path", "/mnt/sshfs", true);

    config.add_mount(mount1.clone());
    config.add_mount(mount2.clone());
    config.add_mount(mount3.clone());

    // When: Config is saved and reloaded
    config
        .save_to_dir(temp_dir.path())
        .await
        .expect("Failed to save config");

    let reloaded = Config::load_with_dir(temp_dir.path())
        .await
        .expect("Failed to reload config");

    // Then: All mount data is preserved exactly
    assert_eq!(
        config.mounts.len(),
        reloaded.mounts.len(),
        "Mount count should match"
    );

    for original_mount in [mount1, mount2, mount3] {
        let reloaded_mount = reloaded
            .get_mount(&original_mount.id)
            .unwrap_or_else(|| panic!("Mount {} should exist", original_mount.id));

        assert_eq!(reloaded_mount.id, original_mount.id);
        assert_eq!(reloaded_mount.url, original_mount.url);
        assert_eq!(reloaded_mount.mount_point, original_mount.mount_point);
        assert_eq!(reloaded_mount.enabled, original_mount.enabled);
        // Note: status might be reset on load, that's expected behavior
    }
}

#[tokio::test]
async fn test_config_directory_created_if_missing() {
    // Given: No config directory exists
    let temp_root = TempDir::new().expect("Failed to create temp root");
    let config_dir = temp_root.path().join("nested/config/dir");

    // Verify directory doesn't exist
    assert!(!config_dir.exists(), "Config dir should not exist yet");

    // When: Config is saved
    let mut config = Config::default();
    let mount = create_test_mount("test", "nfs://server/export", "/mnt/test", true);

    config.add_mount(mount);
    config
        .save_to_dir(&config_dir)
        .await
        .expect("Failed to save config");

    // Then: Directory is created and config file exists
    assert!(config_dir.exists(), "Config directory should be created");
    assert!(config_dir.is_dir(), "Config path should be a directory");

    let config_file = config_dir.join("mounts.toml");
    assert!(config_file.exists(), "Config file should exist");
}
