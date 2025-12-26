//! Property-based tests for configuration roundtrip
//!
//! Uses proptest to verify that config serialization/deserialization
//! is lossless for a wide range of inputs.

use chrono::Utc;
use fuji::config::Config;
use fuji::mount::{MountConfig, MountStatus, MountType};
use proptest::prelude::*;
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::TempDir;

// Generate arbitrary mount IDs
fn arb_mount_id() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z0-9-]{5,20}").unwrap()
}

// Generate arbitrary mount types
fn arb_mount_type() -> impl Strategy<Value = MountType> {
    prop_oneof![
        // NFS mounts
        (
            prop::string::string_regex("[a-z0-9.-]{3,15}").unwrap(),
            prop::string::string_regex("/[a-z0-9/]{1,30}").unwrap(),
        )
            .prop_map(|(host, share)| MountType::Nfs {
                host,
                share,
                options: vec![],
            }),
        // SMB mounts
        (
            prop::string::string_regex("[a-z0-9.-]{3,15}").unwrap(),
            prop::string::string_regex("[a-z0-9_]{3,15}").unwrap(),
        )
            .prop_map(|(host, share)| MountType::Smb {
                host,
                share,
                username: None,
                password: None,
                domain: None,
                options: vec![],
            }),
        // SSHFS mounts
        (
            prop::string::string_regex("[a-z0-9.-]{3,15}").unwrap(),
            prop::option::of(prop::string::string_regex("[a-z]{3,10}").unwrap()),
            prop::string::string_regex("/[a-z0-9/]{1,30}").unwrap(),
        )
            .prop_map(|(host, username, path)| MountType::Sshfs {
                host,
                username,
                path,
                private_key: None,
                password: None,
                options: vec![],
            }),
    ]
}

// Generate arbitrary mount configs
fn arb_mount_config() -> impl Strategy<Value = MountConfig> {
    (arb_mount_id(), arb_mount_type(), prop::bool::ANY).prop_map(|(id, mount_type, enabled)| {
        let now = Utc::now();
        let url = match &mount_type {
            MountType::Nfs {
                host,
                share,
                ..
            } => format!("nfs://{}{}", host, share),
            MountType::Smb {
                host,
                share,
                ..
            } => format!("smb://{}/{}", host, share),
            MountType::Sshfs {
                host,
                username,
                path,
                ..
            } => {
                if let Some(user) = username {
                    format!("sshfs://{}@{}:{}", user, host, path)
                } else {
                    format!("sshfs://{}:{}", host, path)
                }
            }
        };

        MountConfig {
            id: id.clone(),
            url,
            mount_point: PathBuf::from(format!("/mnt/{}", id)),
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
    })
}

proptest! {
    /// Test that saving and loading a config preserves all data
    #[test]
    fn test_config_roundtrip_single_mount(mount_config in arb_mount_config()) {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            // Create a config with the generated mount
            let temp_dir = TempDir::new().unwrap();
            let mut config = Config::default();
            config.add_mount(mount_config.clone());

            // Save to disk
            config.save_to_dir(temp_dir.path()).await.unwrap();

            // Load from disk
            let loaded = Config::load_with_dir(temp_dir.path()).await.unwrap();

            // Verify the mount was preserved
            let loaded_mount = loaded.get_mount(&mount_config.id)
                .expect("Mount should exist after roundtrip");

            // Check all important fields match
            assert_eq!(loaded_mount.id, mount_config.id);
            assert_eq!(loaded_mount.url, mount_config.url);
            assert_eq!(loaded_mount.mount_point, mount_config.mount_point);
            assert_eq!(loaded_mount.enabled, mount_config.enabled);

            // Mount type should match (basic check)
            match (&loaded_mount.mount_type, &mount_config.mount_type) {
                (MountType::Nfs { .. }, MountType::Nfs { .. }) => {},
                (MountType::Smb { .. }, MountType::Smb { .. }) => {},
                (MountType::Sshfs { .. }, MountType::Sshfs { .. }) => {},
                _ => panic!("Mount type mismatch after roundtrip"),
            }
        });
    }

    /// Test that saving and loading a config with multiple mounts preserves all data
    #[test]
    fn test_config_roundtrip_multiple_mounts(
        mount_configs in prop::collection::vec(arb_mount_config(), 1..5)
    ) {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            // Create a config with all generated mounts
            let temp_dir = TempDir::new().unwrap();
            let mut config = Config::default();

            for mount in &mount_configs {
                config.add_mount(mount.clone());
            }

            // Save to disk
            config.save_to_dir(temp_dir.path()).await.unwrap();

            // Load from disk
            let loaded = Config::load_with_dir(temp_dir.path()).await.unwrap();

            // Verify mount count matches
            assert_eq!(
                loaded.mounts.len(),
                mount_configs.len(),
                "Mount count should match after roundtrip"
            );

            // Verify each mount was preserved
            for original in &mount_configs {
                let loaded_mount = loaded.get_mount(&original.id)
                    .expect(&format!("Mount {} should exist after roundtrip", original.id));

                assert_eq!(loaded_mount.id, original.id);
                assert_eq!(loaded_mount.url, original.url);
                assert_eq!(loaded_mount.enabled, original.enabled);
            }
        });
    }

    /// Test that multiple save/load cycles don't corrupt data
    #[test]
    fn test_config_roundtrip_multiple_cycles(mount_config in arb_mount_config()) {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let temp_dir = TempDir::new().unwrap();
            let mut config = Config::default();
            config.add_mount(mount_config.clone());

            // Perform 5 save/load cycles
            for _ in 0..5 {
                config.save_to_dir(temp_dir.path()).await.unwrap();
                config = Config::load_with_dir(temp_dir.path()).await.unwrap();
            }

            // After all cycles, mount should still match original
            let final_mount = config.get_mount(&mount_config.id)
                .expect("Mount should exist after multiple cycles");

            assert_eq!(final_mount.id, mount_config.id);
            assert_eq!(final_mount.url, mount_config.url);
            assert_eq!(final_mount.enabled, mount_config.enabled);
        });
    }
}
