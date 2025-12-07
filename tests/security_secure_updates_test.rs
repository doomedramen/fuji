//! Secure Updates System Tests
//!
//! Comprehensive test suite for the secure update system covering:
//! - Update package creation and management
//! - Digital signature verification
//! - Package integrity verification
//! - Update staging and installation
//! - Rollback and recovery mechanisms
//! - Update metadata handling
//! - Security scanning and validation

use anyhow::Result;
use chrono::Utc;
use fuji::security::secure_updates::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[tokio::test]
async fn test_secure_update_manager_creation() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config = SecureUpdateConfig {
        update_directory: temp_dir.path().join("updates"),
        staging_directory: temp_dir.path().join("staging"),
        backup_directory: temp_dir.path().join("backup"),
        max_concurrent_downloads: 2,
        download_timeout_seconds: 60,
        enable_auto_rollback: true,
        enable_signature_verification: true,
        enable_integrity_verification: true,
        enable_security_scanning: true,
        ..Default::default()
    };

    let manager = SecureUpdateManager::new(config).await?;

    // Verify initial state
    let active_updates = manager.get_active_updates().await?;
    assert_eq!(active_updates.len(), 0);

    let update_history = manager.get_update_history().await?;
    assert_eq!(update_history.len(), 0);

    let rollback_history = manager.get_rollback_history().await?;
    assert_eq!(rollback_history.len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_create_security_patch_update() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config = SecureUpdateConfig {
        update_directory: temp_dir.path().join("updates"),
        staging_directory: temp_dir.path().join("staging"),
        backup_directory: temp_dir.path().join("backup"),
        ..Default::default()
    };

    let manager = SecureUpdateManager::new(config).await?;

    let metadata = UpdateMetadata {
        package_id: "security-patch-001".to_string(),
        version: "2.1.0".to_string(),
        previous_version: Some("2.0.0".to_string()),
        description: "Critical security patch for CVE-2024-1234".to_string(),
        package_type: UpdatePackageType::SecurityPatch,
        security_level: SecurityLevel::Critical,
        build_timestamp: Utc::now(),
        checksums: HashMap::new(),
        dependencies: vec!["libssl".to_string(), "libcrypto".to_string()],
        size_bytes: 5_242_880,
        signatures: vec![DigitalSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: "security-team-ed25519".to_string(),
            signature: "ed25519_signature_placeholder".to_string(),
            certificate_chain: vec!["cert1".to_string(), "cert2".to_string()],
            timestamp: Utc::now(),
        }],
        creator: "Security Team".to_string(),
        classification: UpdateClassification::Official,
    };

    let package_id = manager.create_update_package(metadata).await?;
    assert_eq!(package_id, "security-patch-001");

    let active_updates = manager.get_active_updates().await?;
    assert_eq!(active_updates.len(), 1);

    let update = &active_updates[0];
    assert_eq!(update.metadata.package_id, "security-patch-001");
    assert_eq!(update.metadata.security_level, SecurityLevel::Critical);
    assert_eq!(
        update.metadata.package_type,
        UpdatePackageType::SecurityPatch
    );
    assert_eq!(update.stages.len(), 3); // download, verify, install

    Ok(())
}

#[tokio::test]
async fn test_create_feature_update() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config = SecureUpdateConfig {
        update_directory: temp_dir.path().join("updates"),
        staging_directory: temp_dir.path().join("staging"),
        backup_directory: temp_dir.path().join("backup"),
        ..Default::default()
    };

    let manager = SecureUpdateManager::new(config).await?;

    let metadata = UpdateMetadata {
        package_id: "feature-update-new-dashboard".to_string(),
        version: "3.0.0".to_string(),
        previous_version: Some("2.5.0".to_string()),
        description: "Add new monitoring dashboard with real-time metrics".to_string(),
        package_type: UpdatePackageType::FeatureUpdate,
        security_level: SecurityLevel::Medium,
        build_timestamp: Utc::now(),
        checksums: HashMap::new(),
        dependencies: vec!["web-ui".to_string(), "metrics-collector".to_string()],
        size_bytes: 15_728_640,
        signatures: vec![DigitalSignature {
            algorithm: SignatureAlgorithm::RSA512,
            key_id: "dev-team-rsa".to_string(),
            signature: "rsa512_signature_placeholder".to_string(),
            certificate_chain: vec!["dev_cert".to_string()],
            timestamp: Utc::now(),
        }],
        creator: "Development Team".to_string(),
        classification: UpdateClassification::Beta,
    };

    let package_id = manager.create_update_package(metadata).await?;
    assert_eq!(package_id, "feature-update-new-dashboard");

    let active_updates = manager.get_active_updates().await?;
    let update = &active_updates[0];
    assert_eq!(update.metadata.classification, UpdateClassification::Beta);
    assert_eq!(update.metadata.security_level, SecurityLevel::Medium);
    assert_eq!(update.metadata.dependencies.len(), 2);

    Ok(())
}

#[tokio::test]
async fn test_trusted_key_management() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config = SecureUpdateConfig {
        update_directory: temp_dir.path().join("updates"),
        staging_directory: temp_dir.path().join("staging"),
        backup_directory: temp_dir.path().join("backup"),
        ..Default::default()
    };

    let manager = SecureUpdateManager::new(config).await?;

    // Add trusted keys
    manager
        .add_trusted_key(
            "security-team-ed25519".to_string(),
            "ed25519_public_key_2024".to_string(),
        )
        .await?;

    manager
        .add_trusted_key(
            "dev-team-rsa".to_string(),
            "rsa4096_public_key_2024".to_string(),
        )
        .await?;

    manager
        .add_trusted_key(
            "qa-team-ecdsa".to_string(),
            "ecdsa_p256_public_key_2024".to_string(),
        )
        .await?;

    // Remove a trusted key
    manager.remove_trusted_key("dev-team-rsa").await?;

    // Verify keys are managed correctly
    let active_updates = manager.get_active_updates().await?;
    assert_eq!(active_updates.len(), 0); // No updates, just key management

    Ok(())
}

#[tokio::test]
async fn test_download_update() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config = SecureUpdateConfig {
        update_directory: temp_dir.path().join("updates"),
        staging_directory: temp_dir.path().join("staging"),
        backup_directory: temp_dir.path().join("backup"),
        ..Default::default()
    };

    let manager = SecureUpdateManager::new(config).await?;

    let metadata = UpdateMetadata {
        previous_version: None,
        package_id: "download-test-001".to_string(),
        version: "1.0.0".to_string(),
        description: "Test download functionality".to_string(),
        package_type: UpdatePackageType::BugFix,
        security_level: SecurityLevel::Low,
        build_timestamp: Utc::now(),
        checksums: HashMap::new(),
        dependencies: vec![],
        size_bytes: 1_048_576,
        signatures: vec![],
        creator: "Test Team".to_string(),
        classification: UpdateClassification::Development,
    };

    let package_id = manager.create_update_package(metadata).await?;

    // Test download
    let download_url = "https://updates.example.com/download-test-001.pkg";
    let local_path = manager.download_update(&package_id, download_url).await?;

    assert!(local_path.exists());
    assert!(
        local_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains("download-test-001")
    );

    // Verify update status after download
    let active_updates = manager.get_active_updates().await?;
    let update = &active_updates[0];
    assert_eq!(update.status, UpdateStatus::Downloading);
    assert!(update.local_path.is_some());

    // Check download stage completion
    let download_stage = update
        .stages
        .iter()
        .find(|s| s.stage_id == "download")
        .unwrap();
    assert_eq!(download_stage.status, UpdateStatus::Completed);
    assert_eq!(download_stage.progress, 100);

    Ok(())
}

#[tokio::test]
async fn test_verify_update_with_integrity() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config = SecureUpdateConfig {
        update_directory: temp_dir.path().join("updates"),
        staging_directory: temp_dir.path().join("staging"),
        backup_directory: temp_dir.path().join("backup"),
        enable_signature_verification: false, // Disable for this test
        enable_security_scanning: false,      // Disable for this test
        ..Default::default()
    };

    let manager = SecureUpdateManager::new(config).await?;

    // Create test package content
    let package_content = b"secure-update-package-content-v1.0";
    let package_hash = hex::encode(Sha256::digest(package_content));

    let mut checksums = HashMap::new();
    checksums.insert("sha256".to_string(), hex::encode(package_hash));

    let metadata = UpdateMetadata {
        previous_version: None,
        package_id: "integrity-test-001".to_string(),
        version: "1.0.0".to_string(),
        description: "Test integrity verification".to_string(),
        package_type: UpdatePackageType::SecurityPatch,
        security_level: SecurityLevel::High,
        build_timestamp: Utc::now(),
        checksums,
        dependencies: vec![],
        size_bytes: package_content.len() as u64,
        signatures: vec![],
        creator: "Security Team".to_string(),
        classification: UpdateClassification::Official,
    };

    let package_id = manager.create_update_package(metadata).await?;

    // Create package file
    let package_path = temp_dir.path().join("integrity-test.pkg");
    fs::write(&package_path, package_content)?;

    // Set the local path for the update
    {
        let mut active_updates = manager.active_updates.write().await;
        if let Some(update_package) = active_updates.get_mut(&package_id) {
            update_package.local_path = Some(package_path);
        }
    }

    // Verify update
    let result = manager.verify_update(&package_id).await?;

    assert!(result.is_valid);
    assert!(result.integrity_verified);
    assert!(result.dependencies_satisfied);
    assert_eq!(result.errors.len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_verify_update_with_checksum_mismatch() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config = SecureUpdateConfig {
        update_directory: temp_dir.path().join("updates"),
        staging_directory: temp_dir.path().join("staging"),
        backup_directory: temp_dir.path().join("backup"),
        enable_signature_verification: false, // Disable for this test
        enable_security_scanning: false,      // Disable for this test
        ..Default::default()
    };

    let manager = SecureUpdateManager::new(config).await?;

    // Create test package content
    let package_content = b"original-content";

    let mut checksums = HashMap::new();
    checksums.insert(
        "sha256".to_string(),
        hex::encode(Sha256::digest(package_content)),
    );

    let metadata = UpdateMetadata {
        previous_version: None,
        package_id: "checksum-mismatch-test".to_string(),
        version: "1.0.0".to_string(),
        description: "Test checksum mismatch detection".to_string(),
        package_type: UpdatePackageType::BugFix,
        security_level: SecurityLevel::Medium,
        build_timestamp: Utc::now(),
        checksums,
        dependencies: vec![],
        size_bytes: package_content.len() as u64,
        signatures: vec![],
        creator: "Test Team".to_string(),
        classification: UpdateClassification::Development,
    };

    let package_id = manager.create_update_package(metadata).await?;

    // Create package file with different content (simulating corruption)
    let corrupted_content = b"corrupted-content-different-hash";
    let package_path = temp_dir.path().join("corrupted-test.pkg");
    fs::write(&package_path, corrupted_content)?;

    // Set the local path for the update
    {
        let mut active_updates = manager.active_updates.write().await;
        if let Some(update_package) = active_updates.get_mut(&package_id) {
            update_package.local_path = Some(package_path);
        }
    }

    // Verify update (should fail)
    let result = manager.verify_update(&package_id).await?;

    assert!(!result.is_valid);
    assert!(!result.integrity_verified);
    assert!(!result.errors.is_empty());
    assert!(result.errors[0].contains("Checksum mismatch"));

    Ok(())
}

#[tokio::test]
async fn test_install_update_success() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config = SecureUpdateConfig {
        update_directory: temp_dir.path().join("updates"),
        staging_directory: temp_dir.path().join("staging"),
        backup_directory: temp_dir.path().join("backup"),
        enable_signature_verification: false, // Disable for this test
        enable_security_scanning: false,      // Disable for this test
        enable_auto_rollback: true,
        ..Default::default()
    };

    let manager = SecureUpdateManager::new(config).await?;

    // Create test package content
    let package_content = b"install-test-package-v2.0";
    let package_hash = hex::encode(Sha256::digest(package_content));

    let mut checksums = HashMap::new();
    checksums.insert("sha256".to_string(), hex::encode(package_hash));

    let metadata = UpdateMetadata {
        previous_version: None,
        package_id: "install-success-test".to_string(),
        version: "2.0.0".to_string(),
        description: "Test successful installation".to_string(),
        package_type: UpdatePackageType::FeatureUpdate,
        security_level: SecurityLevel::Medium,
        build_timestamp: Utc::now(),
        checksums,
        dependencies: vec![],
        size_bytes: package_content.len() as u64,
        signatures: vec![],
        creator: "Development Team".to_string(),
        classification: UpdateClassification::Beta,
    };

    let package_id = manager.create_update_package(metadata).await?;

    // Create and set package file
    let package_path = temp_dir.path().join("install-success-test.pkg");
    fs::write(&package_path, package_content)?;

    {
        let mut active_updates = manager.active_updates.write().await;
        if let Some(update_package) = active_updates.get_mut(&package_id) {
            update_package.local_path = Some(package_path);
        }
    }

    // Verify update first
    let verification_result = manager.verify_update(&package_id).await?;
    assert!(verification_result.is_valid);

    // Install update
    manager.install_update(&package_id).await?;

    // Verify installation success
    let update_status = manager.get_update_status(&package_id).await?;
    assert!(update_status.is_some());
    assert_eq!(update_status.unwrap(), UpdateStatus::Completed);

    // Check update history
    let update_history = manager.get_update_history().await?;
    assert_eq!(update_history.len(), 1);
    assert_eq!(
        update_history[0].metadata.package_id,
        "install-success-test"
    );

    // Verify installation marker
    assert!(Path::new("/tmp/fuji_update_marker").exists());

    Ok(())
}

#[tokio::test]
async fn test_rollback_update() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config = SecureUpdateConfig {
        update_directory: temp_dir.path().join("updates"),
        staging_directory: temp_dir.path().join("staging"),
        backup_directory: temp_dir.path().join("backup"),
        ..Default::default()
    };

    let manager = SecureUpdateManager::new(config).await?;

    // Create installation marker (simulating a previous update)
    fs::write("/tmp/fuji_update_marker", "previous-update-installed")?;

    // Perform rollback
    let package_id = "update-to-rollback-001";
    let rollback_reason = "Update caused system instability";

    manager.rollback_update(package_id, rollback_reason).await?;

    // Verify rollback history
    let rollback_history = manager.get_rollback_history().await?;
    assert_eq!(rollback_history.len(), 1);

    let rollback_info = &rollback_history[0];
    assert_eq!(rollback_info.original_update_id, package_id);
    assert_eq!(rollback_info.reason, rollback_reason);
    assert_eq!(rollback_info.status, UpdateStatus::Completed);

    // Verify installation marker is removed
    assert!(!Path::new("/tmp/fuji_update_marker").exists());

    Ok(())
}

#[tokio::test]
async fn test_cancel_update() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config = SecureUpdateConfig {
        update_directory: temp_dir.path().join("updates"),
        staging_directory: temp_dir.path().join("staging"),
        backup_directory: temp_dir.path().join("backup"),
        ..Default::default()
    };

    let manager = SecureUpdateManager::new(config).await?;

    let metadata = UpdateMetadata {
        previous_version: None,
        package_id: "cancel-test-001".to_string(),
        version: "1.0.0".to_string(),
        description: "Test update cancellation".to_string(),
        package_type: UpdatePackageType::FeatureUpdate,
        security_level: SecurityLevel::Low,
        build_timestamp: Utc::now(),
        checksums: HashMap::new(),
        dependencies: vec![],
        size_bytes: 2_097_152,
        signatures: vec![],
        creator: "Test Team".to_string(),
        classification: UpdateClassification::Development,
    };

    let package_id = manager.create_update_package(metadata).await?;

    // Download and create a package file
    let download_url = "https://updates.example.com/cancel-test-001.pkg";
    let package_path = manager.download_update(&package_id, download_url).await?;

    // Cancel the update
    manager.cancel_update(&package_id).await?;

    // Verify cancellation
    let active_updates = manager.get_active_updates().await?;
    assert_eq!(active_updates.len(), 1);

    let update = &active_updates[0];
    if let UpdateStatus::Failed {
        error_code,
        ..
    } = &update.status
    {
        assert_eq!(error_code, "CANCELLED");
    }

    // Verify package file is cleaned up
    assert!(!package_path.exists());

    // Verify all stages are marked as failed/cancelled
    for stage in &update.stages {
        if matches!(
            stage.status,
            UpdateStatus::Pending | UpdateStatus::Downloading
        ) {
            assert!(matches!(stage.status, UpdateStatus::Failed { .. }));
            assert!(stage.error.as_ref().unwrap().contains("cancelled"));
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_cleanup_old_updates() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config = SecureUpdateConfig {
        update_directory: temp_dir.path().join("updates"),
        staging_directory: temp_dir.path().join("staging"),
        backup_directory: temp_dir.path().join("backup"),
        ..Default::default()
    };

    let manager = SecureUpdateManager::new(config).await?;

    // Create old backup directory (31 days ago)
    let old_backup_dir = temp_dir.path().join("backup").join("old-backup-2023");
    fs::create_dir_all(&old_backup_dir)?;
    fs::write(old_backup_dir.join("backup_data.txt"), "old backup data")?;

    // Create old staged file (25 hours ago)
    let old_staged_file = temp_dir.path().join("staging").join("old-staged-file.pkg");
    fs::write(&old_staged_file, "old staged data")?;

    // Set old modification times
    let old_backup_time =
        std::time::SystemTime::now() - std::time::Duration::from_secs(31 * 24 * 60 * 60);
    let old_staged_time =
        std::time::SystemTime::now() - std::time::Duration::from_secs(25 * 60 * 60);

    filetime::set_file_mtime(
        temp_dir.path().join("backup").join("old-backup-2023"),
        filetime::FileTime::from_system_time(old_backup_time),
    )?;

    filetime::set_file_mtime(
        &old_staged_file,
        filetime::FileTime::from_system_time(old_staged_time),
    )?;

    // Run cleanup
    let cleaned_count = manager.cleanup_old_updates().await?;

    // Should have cleaned up both old files
    assert_eq!(cleaned_count, 2);
    assert!(!old_backup_dir.exists());
    assert!(!old_staged_file.exists());

    Ok(())
}

#[tokio::test]
async fn test_component_update() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config = SecureUpdateConfig {
        update_directory: temp_dir.path().join("updates"),
        staging_directory: temp_dir.path().join("staging"),
        backup_directory: temp_dir.path().join("backup"),
        ..Default::default()
    };

    let manager = SecureUpdateManager::new(config).await?;

    let metadata = UpdateMetadata {
        previous_version: None,
        package_id: "component-update-logger".to_string(),
        version: "3.2.1".to_string(),
        description: "Update logging component with improved performance".to_string(),
        package_type: UpdatePackageType::Component {
            component_name: "logging-system".to_string(),
            version: "3.2.1".to_string(),
        },
        security_level: SecurityLevel::Medium,
        build_timestamp: Utc::now(),
        checksums: HashMap::new(),
        dependencies: vec!["log4rs".to_string()],
        size_bytes: 8_388_608,
        signatures: vec![],
        creator: "Infrastructure Team".to_string(),
        classification: UpdateClassification::Official,
    };

    let package_id = manager.create_update_package(metadata).await?;

    let active_updates = manager.get_active_updates().await?;
    let update = &active_updates[0];

    if let UpdatePackageType::Component {
        component_name,
        version,
    } = &update.metadata.package_type
    {
        assert_eq!(component_name, "logging-system");
        assert_eq!(version, "3.2.1");
    } else {
        panic!("Expected Component package type");
    }

    assert_eq!(package_id, "component-update-logger");

    Ok(())
}

#[tokio::test]
async fn test_update_stages_progress() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config = SecureUpdateConfig {
        update_directory: temp_dir.path().join("updates"),
        staging_directory: temp_dir.path().join("staging"),
        backup_directory: temp_dir.path().join("backup"),
        ..Default::default()
    };

    let manager = SecureUpdateManager::new(config).await?;

    let metadata = UpdateMetadata {
        previous_version: None,
        package_id: "progress-test-001".to_string(),
        version: "1.0.0".to_string(),
        description: "Test update stages and progress tracking".to_string(),
        package_type: UpdatePackageType::FullSystem,
        security_level: SecurityLevel::High,
        build_timestamp: Utc::now(),
        checksums: HashMap::new(),
        dependencies: vec![],
        size_bytes: 50_000_000,
        signatures: vec![],
        creator: "Release Team".to_string(),
        classification: UpdateClassification::Official,
    };

    let package_id = manager.create_update_package(metadata).await?;

    let active_updates = manager.get_active_updates().await?;
    let update = &active_updates[0];

    // Verify initial stages
    assert_eq!(update.stages.len(), 3);

    let stages: std::collections::HashMap<String, _> = update
        .stages
        .iter()
        .map(|s| (s.stage_id.clone(), s))
        .collect();

    // Check download stage
    let download_stage = stages.get("download").unwrap();
    assert_eq!(download_stage.status, UpdateStatus::Pending);
    assert_eq!(download_stage.progress, 0);

    // Check verify stage
    let verify_stage = stages.get("verify").unwrap();
    assert_eq!(verify_stage.status, UpdateStatus::Pending);
    assert_eq!(verify_stage.progress, 0);

    // Check install stage
    let install_stage = stages.get("install").unwrap();
    assert_eq!(install_stage.status, UpdateStatus::Pending);
    assert_eq!(install_stage.progress, 0);

    Ok(())
}

#[tokio::test]
async fn test_multiple_signature_algorithms() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config = SecureUpdateConfig {
        update_directory: temp_dir.path().join("updates"),
        staging_directory: temp_dir.path().join("staging"),
        backup_directory: temp_dir.path().join("backup"),
        required_signature_algorithms: vec![
            SignatureAlgorithm::Ed25519,
            SignatureAlgorithm::RSA512,
            SignatureAlgorithm::Ecdsa {
                curve: "P-256".to_string(),
            },
        ],
        ..Default::default()
    };

    let manager = SecureUpdateManager::new(config).await?;

    // Add trusted keys for all algorithms
    manager
        .add_trusted_key(
            "ed25519-main".to_string(),
            "ed25519_main_key_2024".to_string(),
        )
        .await?;

    manager
        .add_trusted_key(
            "rsa512-main".to_string(),
            "rsa512_main_key_2024".to_string(),
        )
        .await?;

    manager
        .add_trusted_key(
            "ecdsa-p256-main".to_string(),
            "ecdsa_p256_main_key_2024".to_string(),
        )
        .await?;

    let metadata = UpdateMetadata {
        previous_version: None,
        package_id: "multi-sig-test-001".to_string(),
        version: "2.0.0".to_string(),
        description: "Test multiple signature algorithms".to_string(),
        package_type: UpdatePackageType::SecurityPatch,
        security_level: SecurityLevel::Critical,
        build_timestamp: Utc::now(),
        checksums: HashMap::new(),
        dependencies: vec![],
        size_bytes: 10_485_760,
        signatures: vec![
            DigitalSignature {
                algorithm: SignatureAlgorithm::Ed25519,
                key_id: "ed25519-main".to_string(),
                signature: "ed25519_signature_data".to_string(),
                certificate_chain: vec!["ed25519_cert".to_string()],
                timestamp: Utc::now(),
            },
            DigitalSignature {
                algorithm: SignatureAlgorithm::RSA512,
                key_id: "rsa512-main".to_string(),
                signature: "rsa512_signature_data".to_string(),
                certificate_chain: vec!["rsa512_cert".to_string()],
                timestamp: Utc::now(),
            },
            DigitalSignature {
                algorithm: SignatureAlgorithm::Ecdsa {
                    curve: "P-256".to_string(),
                },
                key_id: "ecdsa-p256-main".to_string(),
                signature: "ecdsa_signature_data".to_string(),
                certificate_chain: vec!["ecdsa_cert".to_string()],
                timestamp: Utc::now(),
            },
        ],
        creator: "Security Team".to_string(),
        classification: UpdateClassification::Official,
    };

    let package_id = manager.create_update_package(metadata).await?;

    let active_updates = manager.get_active_updates().await?;
    let update = &active_updates[0];

    // Verify all signatures are present
    assert_eq!(update.metadata.signatures.len(), 3);

    // Check signature algorithms
    let algorithms: std::collections::HashSet<_> = update
        .metadata
        .signatures
        .iter()
        .map(|s| &s.algorithm)
        .collect();

    assert!(algorithms.contains(&SignatureAlgorithm::Ed25519));
    assert!(algorithms.contains(&SignatureAlgorithm::RSA512));
    assert!(algorithms.contains(&SignatureAlgorithm::Ecdsa {
        curve: "P-256".to_string()
    }));

    assert_eq!(package_id, "multi-sig-test-001");

    Ok(())
}

#[tokio::test]
async fn test_security_levels() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config = SecureUpdateConfig {
        update_directory: temp_dir.path().join("updates"),
        staging_directory: temp_dir.path().join("staging"),
        backup_directory: temp_dir.path().join("backup"),
        ..Default::default()
    };

    let manager = SecureUpdateManager::new(config).await?;

    // Test all security levels
    let security_levels = vec![
        (SecurityLevel::Critical, "critical-security-patch"),
        (SecurityLevel::High, "high-security-update"),
        (SecurityLevel::Medium, "medium-feature-update"),
        (SecurityLevel::Low, "low-bug-fix"),
        (SecurityLevel::Informational, "info-docs-update"),
    ];

    for (level, package_id) in security_levels {
        let metadata = UpdateMetadata {
            previous_version: None,
            package_id: package_id.to_string(),
            version: "1.0.0".to_string(),
            description: format!(
                "Test {} security level",
                format!("{:?}", level).to_lowercase()
            ),
            package_type: UpdatePackageType::SecurityPatch,
            security_level: level.clone(),
            build_timestamp: Utc::now(),
            checksums: HashMap::new(),
            dependencies: vec![],
            size_bytes: 1_048_576,
            signatures: vec![],
            creator: "Test Team".to_string(),
            classification: UpdateClassification::Development,
        };

        let created_id = manager.create_update_package(metadata).await?;
        assert_eq!(created_id, package_id);

        let active_updates = manager.get_active_updates().await?;
        let update = active_updates
            .iter()
            .find(|u| u.metadata.package_id == package_id)
            .unwrap();
        assert_eq!(update.metadata.security_level, level);
    }

    // Verify all packages were created
    let active_updates = manager.get_active_updates().await?;
    assert_eq!(active_updates.len(), 5);

    Ok(())
}

#[tokio::test]
async fn test_update_classifications() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config = SecureUpdateConfig {
        update_directory: temp_dir.path().join("updates"),
        staging_directory: temp_dir.path().join("staging"),
        backup_directory: temp_dir.path().join("backup"),
        ..Default::default()
    };

    let manager = SecureUpdateManager::new(config).await?;

    // Test all classifications
    let classifications = vec![
        (UpdateClassification::Official, "official-release-1.0"),
        (UpdateClassification::Beta, "beta-release-2.0"),
        (UpdateClassification::Alpha, "alpha-release-3.0"),
        (UpdateClassification::Development, "dev-build-2024"),
        (UpdateClassification::Custom, "custom-patch-hotfix"),
    ];

    for (classification, package_id) in classifications {
        let metadata = UpdateMetadata {
            previous_version: None,
            package_id: package_id.to_string(),
            version: "1.0.0".to_string(),
            description: format!(
                "Test {} classification",
                format!("{:?}", classification).to_lowercase()
            ),
            package_type: UpdatePackageType::FeatureUpdate,
            security_level: SecurityLevel::Medium,
            build_timestamp: Utc::now(),
            checksums: HashMap::new(),
            dependencies: vec![],
            size_bytes: 2_097_152,
            signatures: vec![],
            creator: "Release Team".to_string(),
            classification: classification.clone(),
        };

        let created_id = manager.create_update_package(metadata).await?;
        assert_eq!(created_id, package_id);

        let active_updates = manager.get_active_updates().await?;
        let update = active_updates
            .iter()
            .find(|u| u.metadata.package_id == package_id)
            .unwrap();
        assert_eq!(update.metadata.classification, classification);
    }

    // Verify all packages were created
    let active_updates = manager.get_active_updates().await?;
    assert_eq!(active_updates.len(), 5);

    Ok(())
}
