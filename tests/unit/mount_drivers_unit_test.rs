//! Unit tests for mount driver implementations
//!
//! Tests individual driver methods for NFS, SMB, and SSHFS

use anyhow::Result;
use fuji::mount::drivers::{NfsHandler, SmbHandler, SshfsHandler};
use fuji::mount::{MountConfig, MountHandler, MountType};
use std::path::PathBuf;

// ============================================================================
// NFS Handler Tests
// ============================================================================

#[test]
fn test_nfs_protocol() {
    let handler = NfsHandler::new();
    assert_eq!(handler.protocol(), "nfs");
}

#[test]
fn test_nfs_parse_url_basic() -> Result<()> {
    let handler = NfsHandler::new();
    let mount_type = handler.parse_url("nfs://server.example.com/export")?;

    match mount_type {
        MountType::Nfs {
            host,
            share,
            ..
        } => {
            assert_eq!(host, "server.example.com");
            assert_eq!(share, "/export");
        }
        _ => panic!("Expected NFS mount type"),
    }

    Ok(())
}

#[test]
fn test_nfs_parse_url_with_ip() -> Result<()> {
    let handler = NfsHandler::new();
    let mount_type = handler.parse_url("nfs://192.168.1.100/data")?;

    match mount_type {
        MountType::Nfs {
            host,
            share,
            ..
        } => {
            assert_eq!(host, "192.168.1.100");
            assert_eq!(share, "/data");
        }
        _ => panic!("Expected NFS mount type"),
    }

    Ok(())
}

#[test]
fn test_nfs_parse_url_empty_share() {
    let handler = NfsHandler::new();
    // URLs without a path will fail validation
    let result = handler.parse_url("nfs://server.example.com");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("path"));
}

#[test]
fn test_nfs_parse_url_root_path() -> Result<()> {
    let handler = NfsHandler::new();
    let mount_type = handler.parse_url("nfs://server.example.com/")?;

    match mount_type {
        MountType::Nfs {
            host,
            share,
            ..
        } => {
            assert_eq!(host, "server.example.com");
            assert_eq!(share, "");
        }
        _ => panic!("Expected NFS mount type"),
    }

    Ok(())
}

#[test]
fn test_nfs_parse_url_invalid_scheme() {
    let handler = NfsHandler::new();
    let result = handler.parse_url("smb://server/share");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Invalid scheme"));
}

#[test]
fn test_nfs_parse_url_no_host() {
    let handler = NfsHandler::new();
    let result = handler.parse_url("nfs:///export");
    assert!(result.is_err());
}

#[test]
fn test_nfs_validate_config_valid() -> Result<()> {
    let handler = NfsHandler::new();
    let mount_type = MountType::Nfs {
        host: "server".to_string(),
        share: "/export".to_string(),
        options: vec![],
    };
    let config = MountConfig::new(
        "nfs://server/export".to_string(),
        mount_type,
        PathBuf::from("/mnt/test"),
    );

    assert!(handler.validate_config(&config).is_ok());
    Ok(())
}

#[test]
fn test_nfs_validate_config_empty_host() {
    let handler = NfsHandler::new();
    let mount_type = MountType::Nfs {
        host: "".to_string(),
        share: "/export".to_string(),
        options: vec![],
    };
    let config = MountConfig::new("nfs://".to_string(), mount_type, PathBuf::from("/mnt/test"));

    let result = handler.validate_config(&config);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("cannot be empty"));
}

#[test]
fn test_nfs_validate_config_wrong_type() {
    let handler = NfsHandler::new();
    let mount_type = MountType::Smb {
        host: "server".to_string(),
        share: "share".to_string(),
        username: None,
        password: None,
        domain: None,
        options: vec![],
    };
    let config = MountConfig::new(
        "smb://server/share".to_string(),
        mount_type,
        PathBuf::from("/mnt/test"),
    );

    let result = handler.validate_config(&config);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Invalid mount type")
    );
}

#[test]
fn test_nfs_get_default_options() {
    let handler = NfsHandler::new();
    let options = handler.get_default_options();

    // Default options should include common NFS settings
    assert!(!options.is_empty());
}

#[test]
fn test_nfs_default_trait() {
    let handler1 = NfsHandler::default();
    let handler2 = NfsHandler::new();

    assert_eq!(handler1.protocol(), handler2.protocol());
}

// ============================================================================
// SMB Handler Tests
// ============================================================================

#[test]
fn test_smb_protocol() {
    let handler = SmbHandler::new();
    assert_eq!(handler.protocol(), "smb");
}

#[test]
fn test_smb_parse_url_with_credentials() -> Result<()> {
    let handler = SmbHandler::new();
    let mount_type = handler.parse_url("smb://user:pass@server/share")?;

    match mount_type {
        MountType::Smb {
            host,
            share,
            username,
            password,
            ..
        } => {
            assert_eq!(host, "server");
            assert_eq!(share, "share");
            assert_eq!(username, Some("user".to_string()));
            assert_eq!(password, Some("pass".to_string()));
        }
        _ => panic!("Expected SMB mount type"),
    }

    Ok(())
}

#[test]
fn test_smb_parse_url_no_credentials() -> Result<()> {
    let handler = SmbHandler::new();
    let mount_type = handler.parse_url("smb://server/share")?;

    match mount_type {
        MountType::Smb {
            host,
            share,
            username,
            password,
            ..
        } => {
            assert_eq!(host, "server");
            assert_eq!(share, "share");
            assert_eq!(username, None);
            assert_eq!(password, None);
        }
        _ => panic!("Expected SMB mount type"),
    }

    Ok(())
}

#[test]
fn test_smb_parse_url_with_domain() -> Result<()> {
    let handler = SmbHandler::new();
    // Backslash gets URL encoded as %5C
    let mount_type = handler.parse_url("smb://DOMAIN\\user:pass@server/share")?;

    match mount_type {
        MountType::Smb {
            host,
            share,
            username,
            ..
        } => {
            assert_eq!(host, "server");
            assert_eq!(share, "share");
            // Username will contain the URL-encoded backslash
            assert!(username.is_some());
            assert!(username.unwrap().contains("user"));
        }
        _ => panic!("Expected SMB mount type"),
    }

    Ok(())
}

#[test]
fn test_smb_parse_url_username_only() -> Result<()> {
    let handler = SmbHandler::new();
    let mount_type = handler.parse_url("smb://user@server/share")?;

    match mount_type {
        MountType::Smb {
            host,
            share,
            username,
            password,
            ..
        } => {
            assert_eq!(host, "server");
            assert_eq!(share, "share");
            assert_eq!(username, Some("user".to_string()));
            assert_eq!(password, None);
        }
        _ => panic!("Expected SMB mount type"),
    }

    Ok(())
}

#[test]
fn test_smb_parse_url_invalid_scheme() {
    let handler = SmbHandler::new();
    let result = handler.parse_url("nfs://server/share");
    assert!(result.is_err());
}

#[test]
fn test_smb_parse_url_no_share() {
    let handler = SmbHandler::new();
    let result = handler.parse_url("smb://server");
    assert!(result.is_err());
    // Error message may vary, but it should fail
}

#[test]
fn test_smb_validate_config_valid() -> Result<()> {
    let handler = SmbHandler::new();
    let mount_type = MountType::Smb {
        host: "server".to_string(),
        share: "share".to_string(),
        username: None,
        password: None,
        domain: None,
        options: vec![],
    };
    let config = MountConfig::new(
        "smb://server/share".to_string(),
        mount_type,
        PathBuf::from("/mnt/test"),
    );

    assert!(handler.validate_config(&config).is_ok());
    Ok(())
}

#[test]
fn test_smb_validate_config_empty_host() {
    let handler = SmbHandler::new();
    let mount_type = MountType::Smb {
        host: "".to_string(),
        share: "share".to_string(),
        username: None,
        password: None,
        domain: None,
        options: vec![],
    };
    let config = MountConfig::new(
        "smb:///share".to_string(),
        mount_type,
        PathBuf::from("/mnt/test"),
    );

    let result = handler.validate_config(&config);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("cannot be empty"));
}

#[test]
fn test_smb_validate_config_empty_share() {
    let handler = SmbHandler::new();
    let mount_type = MountType::Smb {
        host: "server".to_string(),
        share: "".to_string(),
        username: None,
        password: None,
        domain: None,
        options: vec![],
    };
    let config = MountConfig::new(
        "smb://server".to_string(),
        mount_type,
        PathBuf::from("/mnt/test"),
    );

    let result = handler.validate_config(&config);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("cannot be empty"));
}

// ============================================================================
// SSHFS Handler Tests
// ============================================================================

#[test]
fn test_sshfs_protocol() {
    let handler = SshfsHandler::new();
    assert_eq!(handler.protocol(), "sshfs");
}

#[test]
fn test_sshfs_parse_url_basic() -> Result<()> {
    let handler = SshfsHandler::new();
    let mount_type = handler.parse_url("sshfs://user@server:/path")?;

    match mount_type {
        MountType::Sshfs {
            host,
            path,
            username,
            ..
        } => {
            assert_eq!(host, "server");
            assert_eq!(path, "/path");
            assert_eq!(username, Some("user".to_string()));
        }
        _ => panic!("Expected SSHFS mount type"),
    }

    Ok(())
}

#[test]
fn test_sshfs_parse_url_no_username() -> Result<()> {
    let handler = SshfsHandler::new();
    let mount_type = handler.parse_url("sshfs://server/path")?;

    match mount_type {
        MountType::Sshfs {
            host,
            path,
            username,
            ..
        } => {
            assert_eq!(host, "server");
            assert_eq!(path, "/path");
            assert_eq!(username, None);
        }
        _ => panic!("Expected SSHFS mount type"),
    }

    Ok(())
}

#[test]
fn test_sshfs_parse_url_invalid_scheme() {
    let handler = SshfsHandler::new();
    let result = handler.parse_url("nfs://server/share");
    assert!(result.is_err());
}

#[test]
fn test_sshfs_validate_config_valid() -> Result<()> {
    let handler = SshfsHandler::new();
    let mount_type = MountType::Sshfs {
        host: "server".to_string(),
        path: "/path".to_string(),
        username: None,
        private_key: None,
        password: None,
        options: vec![],
    };
    let config = MountConfig::new(
        "sshfs://server/path".to_string(),
        mount_type,
        PathBuf::from("/mnt/test"),
    );

    assert!(handler.validate_config(&config).is_ok());
    Ok(())
}

#[test]
fn test_sshfs_validate_config_empty_host() {
    let handler = SshfsHandler::new();
    let mount_type = MountType::Sshfs {
        host: "".to_string(),
        path: "/path".to_string(),
        username: None,
        private_key: None,
        password: None,
        options: vec![],
    };
    let config = MountConfig::new(
        "sshfs:///path".to_string(),
        mount_type,
        PathBuf::from("/mnt/test"),
    );

    let result = handler.validate_config(&config);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("cannot be empty"));
}

#[test]
fn test_sshfs_validate_config_empty_path() {
    let handler = SshfsHandler::new();
    let mount_type = MountType::Sshfs {
        host: "server".to_string(),
        path: "".to_string(),
        username: None,
        private_key: None,
        password: None,
        options: vec![],
    };
    let config = MountConfig::new(
        "sshfs://server".to_string(),
        mount_type,
        PathBuf::from("/mnt/test"),
    );

    let result = handler.validate_config(&config);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("cannot be empty"));
}

// ============================================================================
// Cross-Driver Tests
// ============================================================================

#[test]
fn test_all_protocols_are_lowercase() {
    assert_eq!(NfsHandler::new().protocol(), "nfs");
    assert_eq!(SmbHandler::new().protocol(), "smb");
    assert_eq!(SshfsHandler::new().protocol(), "sshfs");
}

#[test]
fn test_nfs_handler_has_default_options() {
    // NFS handler should have default options
    assert!(!NfsHandler::new().get_default_options().is_empty());
}

#[test]
fn test_url_parsing_respects_protocol() {
    let nfs_handler = NfsHandler::new();
    let smb_handler = SmbHandler::new();
    let sshfs_handler = SshfsHandler::new();

    // Each handler should reject URLs with wrong protocol
    assert!(nfs_handler.parse_url("smb://server/share").is_err());
    assert!(smb_handler.parse_url("nfs://server/export").is_err());
    assert!(sshfs_handler.parse_url("nfs://server/export").is_err());
}
