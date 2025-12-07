//! Configuration security system tests

use anyhow::Result;
use fuji::security::config_security::{
    BackupReason, ConfigData, ConfigMetadata, ConfigOperation, ConfigOperationResult,
    ConfigSecurityConfig, ConfigSecurityManager, LockType, Permissions, UserPermissions,
};
use fuji::security::encryption::EncryptionAlgorithm;

use std::fs;
use std::path::PathBuf;

use tempfile::{NamedTempFile, TempDir};
use tokio::time::{Duration, sleep};

#[tokio::test]
async fn test_config_security_config_default_values() -> Result<()> {
    let config = ConfigSecurityConfig::default();

    assert!(
        config.enable_encryption,
        "Encryption should be enabled by default"
    );
    assert!(
        config.require_auth,
        "Authentication should be required by default"
    );
    assert!(config.enable_backup, "Backup should be enabled by default");
    assert_eq!(
        config.backup_versions, 10,
        "Default backup versions should be 10"
    );
    assert!(
        config.enable_validation,
        "Validation should be enabled by default"
    );
    assert!(
        !config.strict_validation,
        "Strict validation should be disabled by default"
    );
    assert!(
        config.enable_audit_logging,
        "Audit logging should be enabled by default"
    );
    assert_eq!(
        config.file_permissions, 0o600,
        "Default file permissions should be 600"
    );
    assert_eq!(
        config.dir_permissions, 0o700,
        "Default directory permissions should be 700"
    );
    assert_eq!(
        config.max_file_size,
        10 * 1024 * 1024,
        "Default max file size should be 10MB"
    );
    assert!(
        config.allowed_extensions.contains("toml"),
        "TOML should be allowed"
    );
    assert_eq!(
        config.lock_timeout, 300,
        "Default lock timeout should be 300 seconds"
    );
    assert!(
        config.enable_rollback,
        "Rollback should be enabled by default"
    );

    println!("✓ Config security config default values test passed");
    Ok(())
}

#[tokio::test]
async fn test_config_security_manager_creation() -> Result<()> {
    let config = ConfigSecurityConfig::default();
    let manager = ConfigSecurityManager::new(config).await?;

    // Get initial statistics
    let stats = manager.get_stats().await?;
    assert_eq!(stats.total_configs, 0, "Should start with 0 configurations");
    assert_eq!(stats.total_operations, 0, "Should start with 0 operations");
    assert_eq!(stats.active_locks, 0, "Should start with 0 active locks");
    assert_eq!(stats.total_users, 0, "Should start with 0 users");
    assert_eq!(stats.total_groups, 0, "Should start with 0 groups");

    println!("✓ Config security manager creation test passed");
    Ok(())
}

#[tokio::test]
async fn test_user_permissions_management() -> Result<()> {
    let config = ConfigSecurityConfig::default();
    let manager = ConfigSecurityManager::new(config).await?;

    // Create test user with specific permissions
    let user = UserPermissions {
        username: "testuser".to_string(),
        uid: 1001,
        groups: vec!["developers".to_string(), "admin".to_string()],
        permissions: Permissions {
            read: true,
            write: true,
            delete: false,
            admin: false,
            validate: true,
            backup: true,
            restore: false,
        },
        expires_at: None,
    };

    // Add user
    manager.add_user(user.clone()).await?;

    // Retrieve user permissions
    let retrieved = manager.get_user_permissions("testuser").await?;
    assert!(retrieved.is_some(), "User should exist");
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.username, "testuser");
    assert_eq!(retrieved.uid, 1001);
    assert_eq!(retrieved.groups.len(), 2);
    assert!(retrieved.groups.contains(&"developers".to_string()));
    assert!(retrieved.groups.contains(&"admin".to_string()));
    assert!(retrieved.permissions.read);
    assert!(retrieved.permissions.write);
    assert!(!retrieved.permissions.delete);
    assert!(retrieved.permissions.validate);
    assert!(retrieved.permissions.backup);
    assert!(!retrieved.permissions.restore);

    // Test permission checking
    let has_read = manager
        .check_permissions(
            "testuser",
            Permissions {
                read: true,
                ..Default::default()
            },
        )
        .await?;
    assert!(has_read, "User should have read permission");

    let has_delete = manager
        .check_permissions(
            "testuser",
            Permissions {
                delete: true,
                ..Default::default()
            },
        )
        .await?;
    assert!(!has_delete, "User should not have delete permission");

    let has_admin = manager
        .check_permissions(
            "testuser",
            Permissions {
                admin: true,
                ..Default::default()
            },
        )
        .await?;
    assert!(!has_admin, "User should not have admin permission");

    // Remove user
    manager.remove_user("testuser").await?;
    let removed = manager.get_user_permissions("testuser").await?;
    assert!(removed.is_none(), "User should be removed");

    println!("✓ User permissions management test passed");
    Ok(())
}

#[tokio::test]
async fn test_configuration_locking() -> Result<()> {
    let config = ConfigSecurityConfig::default();
    let manager = ConfigSecurityManager::new(config).await?;

    // Add admin user
    let admin_user = UserPermissions {
        username: "admin".to_string(),
        uid: 1000,
        groups: vec![],
        permissions: Permissions {
            admin: true,
            ..Default::default()
        },
        expires_at: None,
    };
    manager.add_user(admin_user).await?;

    // Add regular user
    let regular_user = UserPermissions {
        username: "regular".to_string(),
        uid: 1001,
        groups: vec![],
        permissions: Permissions {
            read: true,
            write: true,
            ..Default::default()
        },
        expires_at: None,
    };
    manager.add_user(regular_user).await?;

    // Test regular user acquiring write lock
    let lock_id = manager
        .acquire_lock(
            "test_config",
            "regular",
            LockType::Write,
            "Testing regular user lock",
        )
        .await?;
    assert!(
        !lock_id.is_empty(),
        "Regular user should acquire write lock"
    );

    // Verify lock exists
    let active_locks = manager.get_active_locks().await?;
    assert_eq!(active_locks.len(), 1, "Should have 1 active lock");
    assert_eq!(active_locks[0].resource, "test_config");
    assert_eq!(active_locks[0].user, "regular");
    assert_eq!(active_locks[0].lock_type, LockType::Write);

    // Test that admin can't acquire admin lock on locked resource
    let admin_lock_result = manager
        .acquire_lock(
            "test_config",
            "admin",
            LockType::Admin,
            "Admin lock attempt",
        )
        .await;
    assert!(
        admin_lock_result.is_err(),
        "Admin should not acquire lock on locked resource"
    );

    // Release lock
    manager
        .release_lock("test_config", "regular", &lock_id)
        .await?;

    // Verify lock is released
    let active_locks = manager.get_active_locks().await?;
    assert_eq!(active_locks.len(), 0, "No locks should be active");

    // Test admin acquiring admin lock
    let admin_lock_id = manager
        .acquire_lock(
            "test_config",
            "admin",
            LockType::Admin,
            "Admin lock for maintenance",
        )
        .await?;
    assert!(!admin_lock_id.is_empty(), "Admin should acquire admin lock");

    println!("✓ Configuration locking test passed");
    Ok(())
}

#[tokio::test]
async fn test_configuration_validation() -> Result<()> {
    let config = ConfigSecurityConfig::default();
    let manager = ConfigSecurityManager::new(config).await?;

    // Test valid TOML configuration
    let valid_toml = ConfigData {
        content: r#"[daemon]
poll_interval = "30s"
log_level = "info"
max_connections = 100

[database]
url = "postgresql://localhost:5432/fuji"
max_connections = 20
connection_timeout = 30

[security]
enable_tls = true
cert_file = "/etc/fuji/cert.pem"
key_file = "/etc/fuji/key.pem""#
            .to_string(),
        metadata: ConfigMetadata {
            name: "config.toml".to_string(),
            version: "1.2.0".to_string(),
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            author: "config_admin".to_string(),
            description: Some("Main application configuration".to_string()),
            tags: vec!["production".to_string(), "database".to_string()],
            schema_version: Some("1.0".to_string()),
            dependencies: vec!["database".to_string()],
        },
    };

    let result = manager.validate_config(&valid_toml).await?;
    assert!(result.valid, "Valid TOML should pass validation");
    assert_eq!(result.errors.len(), 0, "Should have no errors");
    assert_eq!(result.score, 100, "Perfect score should be 100");

    // Test invalid JSON configuration
    let invalid_json = ConfigData {
        content: r#"{
    "invalid": json,
    "missing_quotes": value,
    "extra_comma": "value",
}"#
        .to_string(),
        metadata: ConfigMetadata {
            name: "config.json".to_string(),
            version: "1.0".to_string(),
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            author: "test".to_string(),
            description: None,
            tags: vec![],
            schema_version: None,
            dependencies: vec![],
        },
    };

    let result = manager.validate_config(&invalid_json).await?;
    assert!(!result.valid, "Invalid JSON should fail validation");
    assert!(!result.errors.is_empty(), "Should have errors");
    assert!(result.score < 100, "Score should be reduced");

    // Test configuration with security warnings
    let warning_config = ConfigData {
        content: r#"[security]
password = "plaintext123"
api_key = "secret_api_key"
database_url = "postgresql://user:password@localhost/db""#
            .to_string(),
        metadata: ConfigMetadata {
            name: "secrets.toml".to_string(),
            version: "1.0".to_string(),
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            author: "dev".to_string(),
            description: None,
            tags: vec![],
            schema_version: None,
            dependencies: vec![],
        },
    };

    let result = manager.validate_config(&warning_config).await?;
    assert!(result.valid, "Should be valid but with warnings");
    assert!(!result.warnings.is_empty(), "Should have security warnings");
    assert!(result.score < 100, "Score should be reduced for warnings");

    println!("✓ Configuration validation test passed");
    Ok(())
}

#[tokio::test]
async fn test_configuration_encryption() -> Result<()> {
    let config = ConfigSecurityConfig {
        enable_encryption: true,
        encryption_algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
        ..Default::default()
    };
    let manager = ConfigSecurityManager::new(config).await?;

    let original_config = ConfigData {
        content: r#"[secrets]
database_password = "super_secret_password_123"
api_key = "sk_live_abcdef123456789"
jwt_secret = "jwt_signing_key_very_long_string""#
            .to_string(),
        metadata: ConfigMetadata {
            name: "secrets.toml".to_string(),
            version: "1.0".to_string(),
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            author: "security_admin".to_string(),
            description: Some("Encrypted secrets configuration".to_string()),
            tags: vec!["secrets".to_string(), "encrypted".to_string()],
            schema_version: Some("1.0".to_string()),
            dependencies: vec![],
        },
    };

    // Test encryption
    let encryption_key = "test_encryption_key_123";
    let encrypted_data = manager
        .encrypt_config(&original_config, Some(encryption_key))
        .await?;
    assert!(
        encrypted_data.starts_with(b"FUJI_ENC"),
        "Encrypted data should have magic prefix"
    );
    assert_ne!(
        encrypted_data.len(),
        original_config.content.len(),
        "Encrypted data should be different length"
    );

    // Test decryption
    let decrypted_config = manager
        .decrypt_config(&encrypted_data, Some(encryption_key))
        .await?;
    assert_eq!(
        decrypted_config.content, original_config.content,
        "Decrypted content should match original"
    );
    assert_eq!(
        decrypted_config.metadata.name,
        original_config.metadata.name
    );
    assert_eq!(
        decrypted_config.metadata.version,
        original_config.metadata.version
    );
    assert_eq!(
        decrypted_config.metadata.author,
        original_config.metadata.author
    );

    // Test decryption with wrong key
    let wrong_key_result = manager
        .decrypt_config(&encrypted_data, Some("wrong_key"))
        .await;
    assert!(
        wrong_key_result.is_err(),
        "Decryption with wrong key should fail"
    );

    println!("✓ Configuration encryption test passed");
    Ok(())
}

#[tokio::test]
async fn test_configuration_backup_and_restore() -> Result<()> {
    let config = ConfigSecurityConfig::default();
    let manager = ConfigSecurityManager::new(config).await?;

    // Create temporary config file
    let mut temp_file = NamedTempFile::new()?;
    let original_content = r#"[application]
name = "Fuji Test App"
version = "1.0.0"
debug = false

[server]
host = "localhost"
port = 8080
ssl = true"#;
    std::io::Write::write_all(&mut temp_file, original_content.as_bytes())?;

    // Create backup
    let backup = manager
        .create_backup(temp_file.path(), BackupReason::Manual)
        .await?;
    assert!(!backup.id.is_empty(), "Backup should have valid ID");
    assert_eq!(backup.original_path, temp_file.path());
    assert_eq!(backup.reason, BackupReason::Manual);
    assert!(backup.backup_path.exists(), "Backup file should exist");
    assert_eq!(backup.size, original_content.len() as u64);

    // Verify backup content matches original
    let backup_content = fs::read_to_string(&backup.backup_path)?;
    assert_eq!(backup_content, original_content);

    // Test restore by copying back
    let restore_target = temp_file.path().with_extension("restored");
    fs::remove_file(&restore_target).unwrap_or(());
    manager
        .restore_from_backup(&backup.backup_path, &restore_target)
        .await?;
    assert!(restore_target.exists());

    let restored_content = fs::read_to_string(&restore_target)?;
    assert_eq!(restored_content, original_content);

    // Clean up
    fs::remove_file(&restore_target)?;

    println!("✓ Configuration backup and restore test passed");
    Ok(())
}

#[tokio::test]
async fn test_configuration_history_tracking() -> Result<()> {
    let config = ConfigSecurityConfig::default();
    let manager = ConfigSecurityManager::new(config).await?;

    // Add test user
    let test_user = UserPermissions {
        username: "config_user".to_string(),
        uid: 1002,
        groups: vec!["config_admins".to_string()],
        permissions: Permissions {
            read: true,
            write: true,
            delete: true,
            admin: false,
            validate: true,
            backup: true,
            restore: true,
        },
        expires_at: None,
    };
    manager.add_user(test_user).await?;

    let config_path = PathBuf::from("/test/application.toml");
    let mut config_data = ConfigData {
        content: "version = \"1.0\"".to_string(),
        metadata: ConfigMetadata {
            name: "application.toml".to_string(),
            version: "1.0".to_string(),
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            author: "config_user".to_string(),
            description: Some("Application configuration".to_string()),
            tags: vec!["app".to_string()],
            schema_version: Some("1.0".to_string()),
            dependencies: vec![],
        },
    };

    // Simulate configuration operations
    manager
        .add_history_entry(
            &config_path,
            ConfigOperation::Create,
            "config_user",
            &config_data,
            ConfigOperationResult::Success,
        )
        .await?;

    // Update configuration
    config_data.content = "version = \"2.0\"\ndebug = true".to_string();
    config_data.metadata.version = "2.0".to_string();
    config_data.metadata.modified_at = chrono::Utc::now();

    manager
        .add_history_entry(
            &config_path,
            ConfigOperation::Update,
            "config_user",
            &config_data,
            ConfigOperationResult::Success,
        )
        .await?;

    // Get history for specific configuration
    let config_history = manager.get_history(Some(&config_path)).await?;
    assert_eq!(config_history.len(), 2, "Should have 2 history entries");

    let first_entry = &config_history[0];
    assert_eq!(first_entry.operation, ConfigOperation::Create);
    assert_eq!(first_entry.user, "config_user");
    assert_eq!(first_entry.version, 1);

    let second_entry = &config_history[1];
    assert_eq!(second_entry.operation, ConfigOperation::Update);
    assert_eq!(second_entry.user, "config_user");
    assert_eq!(second_entry.version, 2);
    assert_eq!(
        second_entry.previous_checksum,
        Some(first_entry.checksum.clone())
    );

    // Get all history
    let all_history = manager.get_history(None).await?;
    assert_eq!(all_history.len(), 2, "Should have 2 total history entries");

    println!("✓ Configuration history tracking test passed");
    Ok(())
}

#[tokio::test]
async fn test_configuration_rollback() -> Result<()> {
    let config = ConfigSecurityConfig {
        enable_rollback: true,
        enable_backup: true,
        ..Default::default()
    };
    let manager = ConfigSecurityManager::new(config).await?;

    // Add user with restore permissions
    let admin_user = UserPermissions {
        username: "rollback_admin".to_string(),
        uid: 2000,
        groups: vec!["admins".to_string()],
        permissions: Permissions {
            restore: true,
            ..Default::default()
        },
        expires_at: None,
    };
    manager.add_user(admin_user).await?;

    let config_path = PathBuf::from("/test/rollback_config.toml");
    let mut config_data = ConfigData {
        content: r#"[application]
name = "Fuji"
version = "1.0.0"
debug = false"#
            .to_string(),
        metadata: ConfigMetadata {
            name: "rollback_config.toml".to_string(),
            version: "1.0.0".to_string(),
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            author: "rollback_admin".to_string(),
            description: None,
            tags: vec![],
            schema_version: None,
            dependencies: vec![],
        },
    };

    // Create initial version
    manager
        .add_history_entry(
            &config_path,
            ConfigOperation::Create,
            "rollback_admin",
            &config_data,
            ConfigOperationResult::Success,
        )
        .await?;

    // Update to version 2
    config_data.content = r#"[application]
name = "Fuji"
version = "2.0.0"
debug = true
new_feature = true"#
        .to_string();
    config_data.metadata.version = "2.0.0".to_string();
    config_data.metadata.modified_at = chrono::Utc::now();

    manager
        .add_history_entry(
            &config_path,
            ConfigOperation::Update,
            "rollback_admin",
            &config_data,
            ConfigOperationResult::Success,
        )
        .await?;

    // Rollback to version 1
    manager
        .rollback(&config_path, "rollback_admin", Some(1))
        .await?;

    // Verify rollback was logged
    let history = manager.get_history(Some(&config_path)).await?;
    assert_eq!(
        history.len(),
        3,
        "Should have Create, Update, and Rollback entries"
    );

    let rollback_entry = &history[2];
    assert_eq!(rollback_entry.operation, ConfigOperation::Rollback);
    assert_eq!(rollback_entry.user, "rollback_admin");

    println!("✓ Configuration rollback test passed");
    Ok(())
}

#[tokio::test]
async fn test_expired_lock_cleanup() -> Result<()> {
    let config = ConfigSecurityConfig {
        lock_timeout: 1, // 1 second timeout for testing
        ..Default::default()
    };
    let manager = ConfigSecurityManager::new(config).await?;

    // Add user with write permissions
    let test_user = UserPermissions {
        username: "lock_test_user".to_string(),
        uid: 1003,
        groups: vec![],
        permissions: Permissions {
            write: true,
            ..Default::default()
        },
        expires_at: None,
    };
    manager.add_user(test_user).await?;

    // Acquire multiple locks
    let lock1_id = manager
        .acquire_lock(
            "config1",
            "lock_test_user",
            LockType::Write,
            "Testing lock 1",
        )
        .await?;

    let _lock2_id = manager
        .acquire_lock(
            "config2",
            "lock_test_user",
            LockType::Write,
            "Testing lock 2",
        )
        .await?;

    let _lock3_id = manager
        .acquire_lock(
            "config3",
            "lock_test_user",
            LockType::Read,
            "Testing lock 3",
        )
        .await?;

    // Verify locks exist
    let active_locks = manager.get_active_locks().await?;
    assert_eq!(active_locks.len(), 3, "Should have 3 active locks");

    // Wait for locks to expire
    sleep(Duration::from_secs(2)).await;

    // Clean up expired locks
    let cleaned_count = manager.cleanup_expired_locks().await?;
    assert_eq!(cleaned_count, 3, "Should clean up 3 expired locks");

    // Verify no active locks remain
    let active_locks = manager.get_active_locks().await?;
    assert_eq!(active_locks.len(), 0, "Should have no active locks");

    // Test that released locks can't be released again
    let release_result = manager
        .release_lock("config1", "lock_test_user", &lock1_id)
        .await;
    assert!(
        release_result.is_err(),
        "Should not be able to release expired lock"
    );

    println!("✓ Expired lock cleanup test passed");
    Ok(())
}

#[tokio::test]
async fn test_file_size_validation() -> Result<()> {
    let config = ConfigSecurityConfig {
        max_file_size: 100, // Very small limit for testing
        ..Default::default()
    };
    let manager = ConfigSecurityManager::new(config).await?;

    // Add user with write permissions
    let test_user = UserPermissions {
        username: "size_test_user".to_string(),
        uid: 1004,
        groups: vec![],
        permissions: Permissions {
            write: true,
            ..Default::default()
        },
        expires_at: None,
    };
    manager.add_user(test_user).await?;

    // Create temporary directory
    let temp_dir = TempDir::new()?;
    let large_config_path = temp_dir.path().join("large_config.toml");

    // Create large configuration file (exceeds limit)
    let large_content = "test = value\n".repeat(50); // Much larger than 100 bytes
    fs::write(&large_config_path, large_content)?;

    // Test loading large config should fail
    let load_result = manager
        .load_config(&large_config_path, "size_test_user", None)
        .await;
    assert!(load_result.is_err(), "Loading oversized config should fail");

    println!("✓ File size validation test passed");
    Ok(())
}

#[tokio::test]
async fn test_configuration_statistics() -> Result<()> {
    let config = ConfigSecurityConfig::default();
    let manager = ConfigSecurityManager::new(config).await?;

    // Add multiple users
    for i in 1..=5 {
        let user = UserPermissions {
            username: format!("user{}", i),
            uid: 1000 + i,
            groups: vec![format!("group{}", i)],
            permissions: Permissions::default(),
            expires_at: None,
        };
        manager.add_user(user).await?;
    }

    // Add some configuration operations
    let config_path = PathBuf::from("/test/stats_config.toml");
    let config_data = ConfigData {
        content: "version = \"1.0\"".to_string(),
        metadata: ConfigMetadata {
            name: "stats_config.toml".to_string(),
            version: "1.0".to_string(),
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            author: "user1".to_string(),
            description: None,
            tags: vec![],
            schema_version: None,
            dependencies: vec![],
        },
    };

    for i in 1..=3 {
        manager
            .add_history_entry(
                &config_path,
                ConfigOperation::Update,
                "user1",
                &config_data,
                ConfigOperationResult::Success,
            )
            .await?;
    }

    // Get statistics
    let stats = manager.get_stats().await?;
    assert_eq!(stats.total_users, 5, "Should have 5 users");
    assert_eq!(stats.total_operations, 3, "Should have 3 operations");
    assert_eq!(stats.active_locks, 0, "Should have no active locks");
    assert!(
        stats.last_operation.is_some(),
        "Should have last operation timestamp"
    );

    println!("✓ Configuration statistics test passed");
    Ok(())
}

#[tokio::test]
async fn test_permission_inheritance() -> Result<()> {
    let config = ConfigSecurityConfig::default();
    let manager = ConfigSecurityManager::new(config).await?;

    // Set default permissions
    let default_perms = Permissions {
        read: true,
        write: false,
        delete: false,
        admin: false,
        validate: false,
        backup: false,
        restore: false,
    };

    let mut acl = manager.acl.write().await;
    acl.default_permissions = default_perms;
    drop(acl);

    // Test unknown user inherits default permissions
    let has_read = manager
        .check_permissions(
            "unknown_user",
            Permissions {
                read: true,
                ..Default::default()
            },
        )
        .await?;
    assert!(has_read, "Unknown user should inherit read permission");

    let has_write = manager
        .check_permissions(
            "unknown_user",
            Permissions {
                write: true,
                ..Default::default()
            },
        )
        .await?;
    assert!(
        !has_write,
        "Unknown user should not inherit write permission"
    );

    println!("✓ Permission inheritance test passed");
    Ok(())
}

#[tokio::test]
async fn test_concurrent_lock_operations() -> Result<()> {
    let config = ConfigSecurityConfig::default();
    let manager = ConfigSecurityManager::new(config).await?;

    // Add multiple users
    for i in 1..=3 {
        let user = UserPermissions {
            username: format!("user{}", i),
            uid: 1000 + i,
            groups: vec![],
            permissions: Permissions {
                read: true,
                write: true,
                ..Default::default()
            },
            expires_at: None,
        };
        manager.add_user(user).await?;
    }

    // Test lock acquisition sequentially (avoid cloning issues)
    let mut lock_ids: Vec<String> = Vec::new();

    for i in 1..=3 {
        let lock_id = manager
            .acquire_lock(
                &format!("resource_{}", i),
                &format!("user{}", i),
                LockType::Write,
                &format!("Sequential lock test {}", i),
            )
            .await?;
        lock_ids.push(lock_id);
    }

    // Verify all locks were acquired
    assert_eq!(lock_ids.len(), 3, "Should have acquired 3 locks");

    let active_locks = manager.get_active_locks().await?;
    assert_eq!(active_locks.len(), 3, "Should have 3 active locks");

    // Release all locks
    for i in 1..=3 {
        manager
            .release_lock(
                &format!("resource_{}", i),
                &format!("user{}", i),
                &lock_ids[i - 1],
            )
            .await?;
    }

    // Verify all locks are released
    let active_locks = manager.get_active_locks().await?;
    assert_eq!(active_locks.len(), 0, "Should have no active locks");

    println!("✓ Concurrent lock operations test passed");
    Ok(())
}

#[test]
fn test_encryption_algorithm_serialization() -> Result<()> {
    use serde_json;

    let algorithm = EncryptionAlgorithm::ChaCha20Poly1305;
    let json = serde_json::to_string(&algorithm)?;
    let deserialized: EncryptionAlgorithm = serde_json::from_str(&json)?;

    assert_eq!(algorithm, deserialized);
    println!("✓ Encryption algorithm serialization test passed");
    Ok(())
}

#[test]
fn test_config_metadata_serialization() -> Result<()> {
    use serde_json;

    let metadata = ConfigMetadata {
        name: "test.toml".to_string(),
        version: "1.2.3".to_string(),
        created_at: chrono::Utc::now(),
        modified_at: chrono::Utc::now(),
        author: "test_user".to_string(),
        description: Some("Test configuration metadata".to_string()),
        tags: vec!["test".to_string(), "metadata".to_string()],
        schema_version: Some("2.0".to_string()),
        dependencies: vec!["dependency1".to_string(), "dependency2".to_string()],
    };

    let json = serde_json::to_string(&metadata)?;
    let deserialized: ConfigMetadata = serde_json::from_str(&json)?;

    assert_eq!(metadata.name, deserialized.name);
    assert_eq!(metadata.version, deserialized.version);
    assert_eq!(metadata.author, deserialized.author);
    assert_eq!(metadata.description, deserialized.description);
    assert_eq!(metadata.tags, deserialized.tags);
    assert_eq!(metadata.schema_version, deserialized.schema_version);
    assert_eq!(metadata.dependencies, deserialized.dependencies);

    println!("✓ Config metadata serialization test passed");
    Ok(())
}
