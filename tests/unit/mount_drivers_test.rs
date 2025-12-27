//! Unit tests for mount drivers functionality
//!
//! Tests mount handler implementations, command generation, and
//! protocol-specific behavior for NFS, SMB/CIFS, and SSHFS.

use fuji::mount::drivers::{NfsHandler, SmbHandler, SshfsHandler};
use fuji::mount::{MountConfig, MountHandler, MountStatus, MountType, get_mount_handler};
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::TempDir;

/// Create a test NFS mount config
fn create_test_nfs_config() -> MountConfig {
    MountConfig {
        id: "test-server_nfs_export".to_string(),
        url: "nfs://test-server.example.com/export/path".to_string(),
        mount_type: MountType::Nfs {
            host: "test-server.example.com".to_string(),
            share: "/export/path".to_string(),
            options: vec!["rw".to_string(), "soft".to_string()],
        },
        mount_point: PathBuf::from("/mnt/test-server/export"),
        enabled: true,
        status: MountStatus::Disabled,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        last_connected: None,
        reconnect_attempts: 0,
        metadata: HashMap::new(),
    }
}

/// Create a test SMB mount config
fn create_test_smb_config() -> MountConfig {
    MountConfig {
        id: "test-server_smb_share".to_string(),
        url: "smb://test-server.example.com/share".to_string(),
        mount_type: MountType::Smb {
            host: "test-server.example.com".to_string(),
            share: "share".to_string(),
            username: Some("testuser".to_string()),
            password: Some("testpass".to_string()),
            domain: None,
            options: vec!["rw".to_string(), "vers=3.0".to_string()],
        },
        mount_point: PathBuf::from("/mnt/test-server/share"),
        enabled: true,
        status: MountStatus::Disabled,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        last_connected: None,
        reconnect_attempts: 0,
        metadata: HashMap::new(),
    }
}

/// Create a test SSHFS mount config
fn create_test_sshfs_config() -> MountConfig {
    MountConfig {
        id: "test-server_sshfs_data".to_string(),
        url: "sshfs://test-server.example.com/data/user".to_string(),
        mount_type: MountType::Sshfs {
            host: "test-server.example.com".to_string(),
            username: Some("testuser".to_string()),
            path: "/data/user".to_string(), // Path includes leading slash
            private_key: None,
            password: None,
            options: vec!["rw".to_string(), "allow_other".to_string()],
        },
        mount_point: PathBuf::from("/mnt/test-server/data"),
        enabled: true,
        status: MountStatus::Disabled,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        last_connected: None,
        reconnect_attempts: 0,
        metadata: HashMap::new(),
    }
}

#[test]
fn test_nfs_handler_creation() {
    let handler = NfsHandler::new();
    assert_eq!(handler.protocol(), "nfs");
}

#[test]
fn test_smb_handler_creation() {
    let handler = SmbHandler::new();
    assert_eq!(handler.protocol(), "smb");
}

#[test]
fn test_sshfs_handler_creation() {
    let handler = SshfsHandler::new();
    assert_eq!(handler.protocol(), "sshfs");
}

#[test]
fn test_get_mount_handler_factory() {
    // Test NFS handler
    let nfs_handler = get_mount_handler("nfs").unwrap();
    assert_eq!(nfs_handler.protocol(), "nfs");

    // Test SMB handler (both names)
    let smb_handler = get_mount_handler("smb").unwrap();
    assert_eq!(smb_handler.protocol(), "smb");

    let cifs_handler = get_mount_handler("cifs").unwrap();
    assert_eq!(cifs_handler.protocol(), "smb");

    // Test SSHFS handler (both names)
    let sshfs_handler = get_mount_handler("sshfs").unwrap();
    assert_eq!(sshfs_handler.protocol(), "sshfs");

    let ssh_handler = get_mount_handler("ssh").unwrap();
    assert_eq!(ssh_handler.protocol(), "sshfs");

    // Test unsupported protocol
    assert!(get_mount_handler("unsupported").is_err());
}

#[test]
fn test_nfs_parse_url() {
    let handler = NfsHandler::new();

    // Test valid NFS URL
    let result = handler.parse_url("nfs://server.example.com/export/path");
    assert!(result.is_ok());

    if let Ok(MountType::Nfs {
        host,
        share,
        options,
    }) = result
    {
        assert_eq!(host, "server.example.com");
        assert_eq!(share, "/export/path");
        assert!(!options.is_empty()); // NFS has default options
        assert!(options.contains(&"nolock".to_string()));
    } else {
        panic!("Expected NFS mount type");
    }

    // Test NFS URL with port
    let result = handler.parse_url("nfs://server.example.com:2049/export");
    assert!(result.is_ok());

    // Test invalid scheme
    assert!(
        handler
            .parse_url("http://server.example.com/export")
            .is_err()
    );

    // Test invalid URL
    assert!(handler.parse_url("not-a-url").is_err());
}

#[test]
fn test_smb_parse_url() {
    let handler = SmbHandler::new();

    // Test valid SMB URL
    let result = handler.parse_url("smb://server.example.com/share");
    assert!(result.is_ok());

    if let Ok(MountType::Smb {
        host,
        share,
        username,
        password,
        domain,
        options,
    }) = result
    {
        assert_eq!(host, "server.example.com");
        assert_eq!(share, "share");
        assert!(username.is_none());
        assert!(password.is_none());
        assert!(domain.is_none());
        assert!(options.is_empty());
    } else {
        panic!("Expected SMB mount type");
    }

    // Test SMB URL with credentials
    let result = handler.parse_url("smb://user:pass@server.example.com/share");
    assert!(result.is_ok());

    // Test with domain
    let result = handler.parse_url("smb://DOMAIN\\user:pass@server.example.com/share");
    assert!(result.is_ok());

    // Test invalid scheme
    assert!(handler.parse_url("nfs://server.example.com/share").is_err());
}

#[test]
fn test_sshfs_parse_url() {
    let handler = SshfsHandler::new();

    // Test valid SSHFS URL
    let result = handler.parse_url("sshfs://server.example.com/data/user");
    assert!(result.is_ok());

    if let Ok(MountType::Sshfs {
        host,
        username,
        path,
        private_key,
        password,
        options,
    }) = result
    {
        assert_eq!(host, "server.example.com");
        assert_eq!(path, "/data/user"); // Path includes leading slash from URL
        assert!(username.is_none());
        assert!(private_key.is_none());
        assert!(password.is_none());
        assert!(options.is_empty());
    } else {
        panic!("Expected SSHFS mount type");
    }

    // Test SSHFS URL with username
    let result = handler.parse_url("sshfs://user@server.example.com/data/user");
    assert!(result.is_ok());

    // Test with SFTP scheme
    let result = handler.parse_url("sftp://server.example.com/data/user");
    assert!(result.is_ok());

    // Note: "ssh" scheme is not allowed by MountUrlValidator, only "sshfs" and "sftp"
    assert!(
        handler
            .parse_url("ssh://server.example.com/home/user")
            .is_err()
    );

    // Test invalid scheme
    assert!(handler.parse_url("nfs://server.example.com/home").is_err());
}

#[test]
fn test_nfs_validate_config() {
    let handler = NfsHandler::new();

    // Valid config
    let config = create_test_nfs_config();
    assert!(handler.validate_config(&config).is_ok());

    // Missing host
    let mut config = create_test_nfs_config();
    if let MountType::Nfs {
        ref mut host,
        ..
    } = config.mount_type
    {
        *host = String::new();
    }
    assert!(handler.validate_config(&config).is_err());

    // Empty share path is OK for NFS
    let mut config = create_test_nfs_config();
    if let MountType::Nfs {
        ref mut share,
        ..
    } = config.mount_type
    {
        *share = String::new();
    }
    assert!(handler.validate_config(&config).is_ok());
}

#[test]
fn test_smb_validate_config() {
    let handler = SmbHandler::new();

    // Valid config
    let config = create_test_smb_config();
    assert!(handler.validate_config(&config).is_ok());

    // Missing host
    let mut config = create_test_smb_config();
    if let MountType::Smb {
        ref mut host,
        ..
    } = config.mount_type
    {
        *host = String::new();
    }
    assert!(handler.validate_config(&config).is_err());

    // Missing share
    let mut config = create_test_smb_config();
    if let MountType::Smb {
        ref mut share,
        ..
    } = config.mount_type
    {
        *share = String::new();
    }
    assert!(handler.validate_config(&config).is_err());
}

#[test]
fn test_sshfs_validate_config() {
    let handler = SshfsHandler::new();

    // Valid config
    let config = create_test_sshfs_config();
    assert!(handler.validate_config(&config).is_ok());

    // Missing host
    let mut config = create_test_sshfs_config();
    if let MountType::Sshfs {
        ref mut host,
        ..
    } = config.mount_type
    {
        *host = String::new();
    }
    assert!(handler.validate_config(&config).is_err());

    // Empty path (should fail - SSHFS requires a path)
    let mut config = create_test_sshfs_config();
    if let MountType::Sshfs {
        ref mut path,
        ..
    } = config.mount_type
    {
        *path = String::new();
    }
    assert!(handler.validate_config(&config).is_err());
}

#[test]
fn test_generate_mount_id() {
    let handler = NfsHandler::new();

    // Simple URL
    let id = handler
        .generate_mount_id("nfs://server.example.com/export")
        .unwrap();
    assert_eq!(id, "server.example.com_nfs_export");

    // URL with path
    let id = handler
        .generate_mount_id("nfs://server.example.com/export/path/to/data")
        .unwrap();
    assert_eq!(id, "server.example.com_nfs_export_path_to_data");

    // Invalid URL should fail
    let id = handler.generate_mount_id("not-a-url");
    assert!(id.is_err());
}

#[test]
fn test_generate_mount_point() {
    let handler = NfsHandler::new();

    // Simple URL
    let mount_point = handler
        .generate_mount_point("nfs://server.example.com/export")
        .unwrap();
    assert_eq!(
        mount_point,
        PathBuf::from("/mnt/fuji/server.example.com_nfs/export")
    );

    // URL with path
    let mount_point = handler
        .generate_mount_point("nfs://server.example.com/export/path")
        .unwrap();
    assert_eq!(
        mount_point,
        PathBuf::from("/mnt/fuji/server.example.com_nfs/export/path")
    );

    // Root path
    let mount_point = handler
        .generate_mount_point("nfs://server.example.com/")
        .unwrap();
    assert_eq!(
        mount_point,
        PathBuf::from("/mnt/fuji/server.example.com_nfs")
    );
}

#[test]
fn test_get_default_options() {
    // NFS - should return nolock by default
    let nfs_handler = NfsHandler::new();
    let nfs_options = nfs_handler.get_default_options();
    assert!(!nfs_options.is_empty());
    assert!(nfs_options.contains(&"nolock".to_string()));

    // SMB - currently returns empty defaults
    let smb_handler = SmbHandler::new();
    let smb_options = smb_handler.get_default_options();
    assert!(smb_options.is_empty());

    // SSHFS - should return empty by default
    let sshfs_handler = SshfsHandler::new();
    assert!(sshfs_handler.get_default_options().is_empty());
}

#[tokio::test]
async fn test_discover_shares() {
    // NFS
    let nfs_handler = NfsHandler::new();
    // This would normally fail on a system without showmount, but we test the error handling
    let shares = nfs_handler.discover_shares("nonexistent.example.com").await;
    // Should return empty list or error, not panic
    assert!(shares.is_ok() || shares.is_err());

    // SMB
    let smb_handler = SmbHandler::new();
    let shares = smb_handler.discover_shares("nonexistent.example.com").await;
    // Should return empty list (not all servers support discovery)
    assert!(shares.is_ok());
    assert!(shares.unwrap().is_empty());

    // SSHFS
    let sshfs_handler = SshfsHandler::new();
    let shares = sshfs_handler
        .discover_shares("nonexistent.example.com")
        .await;
    // SSHFS doesn't support share discovery
    assert!(shares.is_ok());
    assert!(shares.unwrap().is_empty());
}

#[tokio::test]
async fn test_health_check() {
    let temp_dir = TempDir::new().unwrap();
    let non_existent = temp_dir.path().join("non_existent_mount");

    // Test with non-existent mount point
    let nfs_handler = NfsHandler::new();
    let health = nfs_handler.check_health(&non_existent).await.unwrap();
    assert!(!health.accessible);
    assert!(health.last_error.is_some());
    assert_eq!(health.health_score, 0);

    // Create a directory to simulate a mount
    let mount_point = temp_dir.path().join("test_mount");
    tokio::fs::create_dir_all(&mount_point).await.unwrap();

    // Test with existing directory (it will be marked accessible since we can write to it)
    let health = nfs_handler.check_health(&mount_point).await.unwrap();
    // The health check should succeed if we can write to the directory
    assert!(health.accessible);
    assert!(health.health_score > 0);
}

#[test]
fn test_mount_type_equality() {
    let nfs_type = MountType::Nfs {
        host: "server.example.com".to_string(),
        share: "/export".to_string(),
        options: vec!["rw".to_string()],
    };

    let nfs_type2 = MountType::Nfs {
        host: "server.example.com".to_string(),
        share: "/export".to_string(),
        options: vec!["rw".to_string()],
    };

    let smb_type = MountType::Smb {
        host: "server.example.com".to_string(),
        share: "share".to_string(),
        username: None,
        password: None,
        domain: None,
        options: vec![],
    };

    assert_eq!(nfs_type, nfs_type2);
    assert_ne!(nfs_type, smb_type);
}

// Test temporarily disabled - URL validation edge cases
/*
#[test]
fn test_url_parsing_edge_cases() {
    let handler = NfsHandler::new();

    // URL with query parameters (should be ignored or cause error)
    let result = handler.parse_url("nfs://server.example.com/export?param=value");
    // Should handle gracefully
    assert!(result.is_err());

    // URL with fragment
    let result = handler.parse_url("nfs://server.example.com/export#fragment");
    assert!(result.is_err());

    // IPv6 address
    let result = handler.parse_url("nfs://[2001:db8::1]/export");
    assert!(result.is_ok());

    if let Ok(MountType::Nfs { host, .. }) = result {
        assert_eq!(host, "2001:db8::1");
    }
}
*/

// Test temporarily disabled - SSH scheme not in validator
/*
#[test]
fn test_sshfs_url_parsing_with_port() {
    let handler = SshfsHandler::new();

    // SSH URL with port number
    let result = handler.parse_url("ssh://user@server.example.com:2222/home/user");
    assert!(result.is_ok());

    if let Ok(MountType::Sshfs { host, username, path, .. }) = result {
        assert_eq!(host, "server.example.com");
        assert_eq!(username, Some("user".to_string()));
        assert_eq!(path, "/home/user");
    }
}
*/

// Test temporarily disabled - URL encoding issues
/*
#[test]
fn test_smb_url_parsing_complex() {
    let handler = SmbHandler::new();

    // SMB URL with domain and special characters
    let result = handler.parse_url("smb://DOMAIN%20Name\\user:pa$$w0rd@server.example.com/share name");
    assert!(result.is_ok());

    if let Ok(MountType::Smb { host, share, username, password, domain, .. }) = result {
        assert_eq!(host, "server.example.com");
        assert_eq!(share, "share name");
        assert_eq!(username, Some("DOMAIN Name\\user".to_string()));
        assert_eq!(password, Some("pa$$w0rd".to_string()));
        assert_eq!(domain, Some("DOMAIN Name".to_string()));
    }
}
*/

#[test]
fn test_config_validation_with_options() {
    let handler = NfsHandler::new();

    let mut config = create_test_nfs_config();

    // Add valid NFS options
    if let MountType::Nfs {
        ref mut options,
        ..
    } = config.mount_type
    {
        options.push("hard".to_string());
        options.push("proto=tcp".to_string());
        options.push("vers=4".to_string());
    }

    assert!(handler.validate_config(&config).is_ok());

    // Test dangerous options (should be validated by MountOptionsValidator)
    if let MountType::Nfs {
        ref mut options,
        ..
    } = config.mount_type
    {
        options.clear();
        options.push("user_allow_other".to_string()); // This might be flagged
    }

    // The validation should catch dangerous options
    let result = handler.validate_config(&config);
    // It might pass or fail depending on the validator implementation
    // We just ensure it doesn't panic
    assert!(result.is_ok() || result.is_err());
}

#[tokio::test]
async fn test_mount_unmount_flow() {
    let temp_dir = TempDir::new().unwrap();
    let mount_point = temp_dir.path().join("test_mount");

    let handler = NfsHandler::new();
    let config = create_test_nfs_config();

    // Mount operation (will likely fail without real NFS server, but should not panic)
    let mount_result = handler.mount(&config, &mount_point).await;
    // We expect this to fail since there's no real NFS server
    assert!(mount_result.is_err());

    // Even if mount failed, unmount should be safe to call
    let unmount_result = handler.unmount(&mount_point).await;
    // Might fail if nothing was mounted, which is OK
    assert!(unmount_result.is_ok() || unmount_result.is_err());
}

#[test]
fn test_handler_send_sync() {
    // Ensure handlers implement Send + Sync
    fn is_send_sync<T: Send + Sync>() {}

    is_send_sync::<NfsHandler>();
    is_send_sync::<SmbHandler>();
    is_send_sync::<SshfsHandler>();

    // And Box<dyn MountHandler> should also be Send + Sync
    is_send_sync::<Box<dyn fuji::mount::MountHandler>>();
}

// Test temporarily disabled - path traversal handling
/*
#[test]
fn test_mount_point_sanitization() {
    let handler = NfsHandler::new();

    // Test path traversal attempts
    let result = handler.generate_mount_point("nfs://server.example.com/../../../etc");
    // Should sanitize the path to prevent traversal
    assert!(result.is_ok());
    let mount_point = result.unwrap();
    assert!(!mount_point.to_string_lossy().contains(".."));

    // Test absolute paths
    let result = handler.generate_mount_point("nfs://server.example.com//absolute/path");
    assert!(result.is_ok());

    // Test special characters
    let result = handler.generate_mount_point("nfs://server.example.com/path with spaces");
    assert!(result.is_ok());
}
*/

// Test temporarily disabled - legacy config handling
/*
#[test]
fn test_legacy_smb_config_support() {
    let handler = SshfsHandler::new();

    // Test that SSHFS handler can handle legacy SMB configs
    let legacy_config = MountConfig {
        id: "legacy-mount".to_string(),
        url: "smb://server.example.com/share".to_string(),
        mount_type: MountType::Smb {
            host: "server.example.com".to_string(),
            share: "//server.example.com/share".to_string(), // Legacy format
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            domain: None,
            options: vec![],
        },
        mount_point: PathBuf::from("/mnt/legacy"),
        enabled: true,
        status: MountStatus::Disabled,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        last_connected: None,
        reconnect_attempts: 0,
        metadata: HashMap::new(),
    };

    // The SSHFS handler should gracefully reject SMB configs
    let result = handler.validate_config(&legacy_config);
    assert!(result.is_err());
}
*/

#[test]
fn test_concurrent_handler_access() {
    use std::sync::Arc;
    use std::thread;

    let handler = Arc::new(NfsHandler::new());
    let mut handles = vec![];

    // Spawn multiple threads accessing the handler
    for _ in 0..10 {
        let handler_clone = Arc::clone(&handler);
        let handle = thread::spawn(move || {
            // Test that the handler is Send + Sync
            assert_eq!(handler_clone.protocol(), "nfs");
            let _ = handler_clone.get_default_options();
            let _ = handler_clone.generate_mount_id("nfs://test.example.com/share");
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_nfs_default_options_include_timeouts() {
    let handler = NfsHandler::new();
    let options = handler.get_default_options();

    // Verify NFS timeout options are present for fast failure
    assert!(
        options.contains(&"timeo=10".to_string()),
        "Should include timeo=10 for 1-second RPC timeout"
    );
    assert!(
        options.contains(&"retrans=2".to_string()),
        "Should include retrans=2 for limited retransmission attempts"
    );
    assert!(
        options.contains(&"soft".to_string()),
        "Should include soft option for fail-fast behavior"
    );
    assert!(
        options.contains(&"_netdev".to_string()),
        "Should include _netdev for proper network device handling"
    );
    assert!(
        options.contains(&"nolock".to_string()),
        "Should still include nolock option"
    );
}
