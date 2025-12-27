//! Integration tests for daemon configuration persistence
//!
//! Tests that daemon operations (mount, unmount, enable, disable, remove)
//! properly persist configuration changes to disk.

use anyhow::Result;
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
async fn test_mount_operation_persists_config() -> Result<()> {
    // Given: Empty config in temp directory
    let temp_dir = TempDir::new()?;
    let mut config = Config::default();

    // Save initial empty config
    config.save_to_dir(temp_dir.path()).await?;

    // When: Mount is added (simulating daemon add_mount operation)
    let mount = create_test_mount("test-mount", "nfs://192.168.1.100/data", "/mnt/data", true);
    config.add_mount(mount.clone());

    // Save config (simulating what daemon does after mount)
    config.save_to_dir(temp_dir.path()).await?;

    // Then: Config file should contain the mount
    let reloaded = Config::load_with_dir(temp_dir.path()).await?;
    assert_eq!(reloaded.mounts.len(), 1);

    let persisted_mount = reloaded
        .get_mount("test-mount")
        .expect("Mount should exist");
    assert_eq!(persisted_mount.url, mount.url);
    assert_eq!(persisted_mount.mount_point, mount.mount_point);
    assert!(persisted_mount.enabled);

    Ok(())
}

#[tokio::test]
async fn test_unmount_operation_persists_config() -> Result<()> {
    // Given: Config with one active mount
    let temp_dir = TempDir::new()?;
    let mut config = Config::default();

    let mount = create_test_mount("to-unmount", "nfs://server/export", "/mnt/test", true);
    config.add_mount(mount);
    config.save_to_dir(temp_dir.path()).await?;

    // When: Mount is disabled (simulating daemon unmount operation)
    if let Some(m) = config.get_mount_mut("to-unmount") {
        m.disable();
    }

    // Save config (simulating what daemon does after unmount)
    config.save_to_dir(temp_dir.path()).await?;

    // Then: Config file should show mount as disabled
    let reloaded = Config::load_with_dir(temp_dir.path()).await?;
    let persisted_mount = reloaded
        .get_mount("to-unmount")
        .expect("Mount should exist");
    assert!(!persisted_mount.enabled);

    Ok(())
}

#[tokio::test]
async fn test_enable_operation_persists_config() -> Result<()> {
    // Given: Config with disabled mount
    let temp_dir = TempDir::new()?;
    let mut config = Config::default();

    let mount = create_test_mount("to-enable", "nfs://server/data", "/mnt/data", false);
    config.add_mount(mount);
    config.save_to_dir(temp_dir.path()).await?;

    // Verify mount is disabled
    assert!(!config.get_mount("to-enable").unwrap().enabled);

    // When: Mount is enabled (simulating daemon enable operation)
    if let Some(m) = config.get_mount_mut("to-enable") {
        m.enable();
    }

    // Save config (simulating what daemon does after enable)
    config.save_to_dir(temp_dir.path()).await?;

    // Then: Config file should show mount as enabled
    let reloaded = Config::load_with_dir(temp_dir.path()).await?;
    let persisted_mount = reloaded.get_mount("to-enable").expect("Mount should exist");
    assert!(persisted_mount.enabled);

    Ok(())
}

#[tokio::test]
async fn test_disable_operation_persists_config() -> Result<()> {
    // Given: Config with enabled mount
    let temp_dir = TempDir::new()?;
    let mut config = Config::default();

    let mount = create_test_mount("to-disable", "smb://server/share", "/mnt/smb", true);
    config.add_mount(mount);
    config.save_to_dir(temp_dir.path()).await?;

    // Verify mount is enabled
    assert!(config.get_mount("to-disable").unwrap().enabled);

    // When: Mount is disabled (simulating daemon disable operation)
    if let Some(m) = config.get_mount_mut("to-disable") {
        m.disable();
    }

    // Save config (simulating what daemon does after disable)
    config.save_to_dir(temp_dir.path()).await?;

    // Then: Config file should show mount as disabled
    let reloaded = Config::load_with_dir(temp_dir.path()).await?;
    let persisted_mount = reloaded
        .get_mount("to-disable")
        .expect("Mount should exist");
    assert!(!persisted_mount.enabled);

    Ok(())
}

#[tokio::test]
async fn test_remove_operation_persists_config() -> Result<()> {
    // Given: Config with one mount
    let temp_dir = TempDir::new()?;
    let mut config = Config::default();

    let mount = create_test_mount("to-remove", "nfs://server/export", "/mnt/test", true);
    config.add_mount(mount);
    config.save_to_dir(temp_dir.path()).await?;

    // Verify mount exists
    assert_eq!(config.mounts.len(), 1);

    // When: Mount is removed (simulating daemon remove operation)
    config.remove_mount("to-remove");

    // Save config (simulating what daemon does after remove)
    config.save_to_dir(temp_dir.path()).await?;

    // Then: Config file should not contain the mount
    let reloaded = Config::load_with_dir(temp_dir.path()).await?;
    assert_eq!(reloaded.mounts.len(), 0);
    assert!(reloaded.get_mount("to-remove").is_none());

    Ok(())
}

#[tokio::test]
async fn test_config_directory_created_on_first_save() -> Result<()> {
    // Given: No config directory exists
    let temp_root = TempDir::new()?;
    let config_dir = temp_root.path().join("nested/config/dir");

    // Verify directory doesn't exist
    assert!(!config_dir.exists());

    // When: Config is saved for the first time
    let mut config = Config::default();
    let mount = create_test_mount("first-mount", "nfs://server/export", "/mnt/test", true);
    config.add_mount(mount);

    config.save_to_dir(&config_dir).await?;

    // Then: Directory should be created and config file should exist
    assert!(config_dir.exists());
    assert!(config_dir.is_dir());

    let config_file = config_dir.join("mounts.toml");
    assert!(config_file.exists());

    Ok(())
}

#[tokio::test]
async fn test_multiple_operations_persist_correctly() -> Result<()> {
    // Given: Empty config
    let temp_dir = TempDir::new()?;
    let mut config = Config::default();

    // When: Multiple operations are performed
    // 1. Add first mount
    let mount1 = create_test_mount("mount1", "nfs://server1/export1", "/mnt/nfs1", true);
    config.add_mount(mount1);
    config.save_to_dir(temp_dir.path()).await?;

    // 2. Add second mount
    let mount2 = create_test_mount("mount2", "smb://server2/share2", "/mnt/smb2", true);
    config.add_mount(mount2);
    config.save_to_dir(temp_dir.path()).await?;

    // 3. Disable first mount
    if let Some(m) = config.get_mount_mut("mount1") {
        m.disable();
    }
    config.save_to_dir(temp_dir.path()).await?;

    // 4. Add third mount
    let mount3 = create_test_mount("mount3", "sshfs://user@host:/path", "/mnt/sshfs", false);
    config.add_mount(mount3);
    config.save_to_dir(temp_dir.path()).await?;

    // 5. Remove second mount
    config.remove_mount("mount2");
    config.save_to_dir(temp_dir.path()).await?;

    // Then: Final state should be persisted correctly
    let reloaded = Config::load_with_dir(temp_dir.path()).await?;

    // Should have 2 mounts (mount1 and mount3, mount2 was removed)
    assert_eq!(reloaded.mounts.len(), 2);

    // mount1 should be disabled
    let m1 = reloaded.get_mount("mount1").expect("Mount1 should exist");
    assert!(!m1.enabled);

    // mount2 should not exist
    assert!(reloaded.get_mount("mount2").is_none());

    // mount3 should be disabled (as created)
    let m3 = reloaded.get_mount("mount3").expect("Mount3 should exist");
    assert!(!m3.enabled);

    Ok(())
}

#[tokio::test]
async fn test_config_file_uses_atomic_write() -> Result<()> {
    // Given: Config with one mount
    let temp_dir = TempDir::new()?;
    let mut config = Config::default();

    let mount = create_test_mount("atomic-test", "nfs://server/export", "/mnt/atomic", true);
    config.add_mount(mount);
    config.save_to_dir(temp_dir.path()).await?;

    let config_path = temp_dir.path().join("mounts.toml");
    let original_content = std::fs::read_to_string(&config_path)?;

    // When: Config is saved again (simulating atomic write)
    let mount2 = create_test_mount("atomic-test-2", "smb://server2/share", "/mnt/atomic2", true);
    config.add_mount(mount2);
    config.save_to_dir(temp_dir.path()).await?;

    // Then: File should be updated and no temp files should remain
    assert!(config_path.exists());

    // Check no temp files are left behind
    let temp_files: Vec<_> = std::fs::read_dir(temp_dir.path())?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();

    assert_eq!(
        temp_files.len(),
        0,
        "No .tmp files should remain after save"
    );

    // Verify content changed
    let new_content = std::fs::read_to_string(&config_path)?;
    assert_ne!(original_content, new_content);
    assert!(new_content.contains("atomic-test-2"));

    Ok(())
}

#[tokio::test]
async fn test_failed_mount_does_not_persist() -> Result<()> {
    // Given: Config with one successful mount already saved
    let temp_dir = TempDir::new()?;
    let mut config = Config::default();

    let successful_mount = create_test_mount(
        "successful-mount",
        "nfs://server/existing-share",
        "/mnt/existing",
        true,
    );
    config.add_mount(successful_mount);
    config.save_to_dir(temp_dir.path()).await?;

    // When: A new mount is added to in-memory config (simulating daemon adding before mount attempt)
    let failed_mount = create_test_mount(
        "failed-mount",
        "nfs://server/non-existent-share",
        "/mnt/failed",
        true,
    );
    config.add_mount(failed_mount);

    // Verify it's in memory
    assert_eq!(config.mounts.len(), 2);
    assert!(config.get_mount("failed-mount").is_some());

    // Simulate mount failure: daemon would rollback by removing from in-memory config
    config.remove_mount("failed-mount");

    // Don't save config (mount failed, so we don't persist)
    // This simulates the daemon's rollback behavior

    // Then: Reload config from disk - should only have the successful mount
    let reloaded = Config::load_with_dir(temp_dir.path()).await?;

    assert_eq!(
        reloaded.mounts.len(),
        1,
        "Failed mount should not be persisted to config"
    );
    assert!(
        reloaded.get_mount("successful-mount").is_some(),
        "Successful mount should still exist"
    );
    assert!(
        reloaded.get_mount("failed-mount").is_none(),
        "Failed mount should not exist in persisted config"
    );

    Ok(())
}

#[tokio::test]
async fn test_successful_mount_persists_after_attempt() -> Result<()> {
    // Given: Empty config
    let temp_dir = TempDir::new()?;
    let mut config = Config::default();
    config.save_to_dir(temp_dir.path()).await?;

    // When: Mount is added to in-memory config and mount succeeds
    let successful_mount = create_test_mount("new-mount", "nfs://server/share", "/mnt/new", true);
    config.add_mount(successful_mount);

    // Simulate successful mount: save config after mount succeeds
    config.save_to_dir(temp_dir.path()).await?;

    // Then: Reload config - should contain the successful mount
    let reloaded = Config::load_with_dir(temp_dir.path()).await?;

    assert_eq!(
        reloaded.mounts.len(),
        1,
        "Successful mount should be persisted"
    );
    assert!(
        reloaded.get_mount("new-mount").is_some(),
        "Mount should exist in persisted config"
    );

    Ok(())
}
