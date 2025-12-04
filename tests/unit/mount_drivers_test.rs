//! Unit tests for mount drivers functionality
//!
//! Tests mount driver implementations, command generation, and
//! protocol-specific behavior for NFS, SMB/CIFS, and SSHFS.

use fuji::mount::{MountDriver, MountDriverError, MountConfig, MountStatus};
use fuji::mount::nfs::NfsDriver;
use fuji::mount::smb::SmbDriver;
use fuji::mount::sshfs::SshfsDriver;
use url::Url;
use std::path::PathBuf;
use std::collections::HashMap;

#[test]
fn test_nfs_driver_creation() {
    let driver = NfsDriver::new();
    assert_eq!(driver.get_name(), "nfs");
    assert_eq!(driver.get_protocol(), "nfs");
}

#[test]
fn test_nfs_url_parsing() {
    let driver = NfsDriver::new();

    // Test valid NFS URLs
    let valid_urls = vec![
        ("nfs://server.example.com/export", "server.example.com", "/export"),
        ("nfs://192.168.1.100/data", "192.168.1.100", "/data"),
        ("nfs://server.local/mnt/backup", "server.local", "/mnt/backup"),
        ("nfs://nfs-server.example.com/", "nfs-server.example.com", "/"),
    ];

    for (url_str, expected_host, expected_path) in valid_urls {
        let url = Url::parse(url_str).unwrap();
        let config = driver.parse_url(&url).unwrap();

        assert_eq!(config.server, expected_host);
        assert_eq!(config.remote_path, expected_path);
        assert_eq!(config.protocol, "nfs");
    }
}

#[test]
fn test_nfs_invalid_url_parsing() {
    let driver = NfsDriver::new();

    // Test invalid URLs
    let invalid_urls = vec![
        "http://server.example.com/export",     // Wrong protocol
        "ftp://server.example.com/export",      // Wrong protocol
        "nfs://",                               // Missing host
        "nfs:///export",                        // Missing host
        "",                                     // Empty string
    ];

    for url_str in invalid_urls {
        if let Ok(url) = Url::parse(url_str) {
            let result = driver.parse_url(&url);
            assert!(result.is_err(), "Should reject URL: {}", url_str);
        }
    }
}

#[test]
fn test_nfs_command_generation() {
    let driver = NfsDriver::new();

    let mut config = MountConfig {
        server: "server.example.com".to_string(),
        remote_path: "/export".to_string(),
        protocol: "nfs".to_string(),
        mount_point: PathBuf::from("/mnt/nfs"),
        read_only: false,
        options: HashMap::new(),
    };

    // Add some NFS-specific options
    config.options.insert("vers".to_string(), "4".to_string());
    config.options.insert("rsize".to_string(), "1048576".to_string());
    config.options.insert("wsize".to_string(), "1048576".to_string());

    let command = driver.generate_mount_command(&config);
    let cmd_str = command.join(" ");

    // Check that command contains expected components
    assert!(cmd_str.contains("mount"));
    assert!(cmd_str.contains("-t nfs"));
    assert!(cmd_str.contains("server.example.com:/export"));
    assert!(cmd_str.contains("/mnt/nfs"));
    assert!(cmd_str.contains("vers=4"));
    assert!(cmd_str.contains("rsize=1048576"));
    assert!(cmd_str.contains("wsize=1048576"));
}

#[test]
fn test_nfs_readonly_command() {
    let driver = NfsDriver::new();

    let mut config = MountConfig {
        server: "server.example.com".to_string(),
        remote_path: "/export".to_string(),
        protocol: "nfs".to_string(),
        mount_point: PathBuf::from("/mnt/nfs"),
        read_only: true,
        options: HashMap::new(),
    };

    let command = driver.generate_mount_command(&config);
    let cmd_str = command.join(" ");

    assert!(cmd_str.contains("-o ro") || cmd_str.contains(",ro,"));
}

#[test]
fn test_smb_driver_creation() {
    let driver = SmbDriver::new();
    assert_eq!(driver.get_name(), "smb");
    assert_eq!(driver.get_protocol(), "smb");
}

#[test]
fn test_smb_url_parsing() {
    let driver = SmbDriver::new();

    // Test valid SMB URLs
    let valid_urls = vec![
        ("smb://server.example.com/share", "server.example.com", "share"),
        ("smb://user@server.example.com/share", "server.example.com", "share"),
        ("smb://user:pass@server.example.com/share", "server.example.com", "share"),
        ("cifs://server.local/data", "server.local", "data"),
        ("smb://192.168.1.100/backup", "192.168.1.100", "backup"),
    ];

    for (url_str, expected_host, expected_share) in valid_urls {
        let url = Url::parse(url_str).unwrap();
        let config = driver.parse_url(&url).unwrap();

        assert_eq!(config.server, expected_host);
        assert_eq!(config.remote_path, expected_share);
        assert_eq!(config.protocol, "smb");

        // Check user extraction if present
        if url_str.contains("@") {
            assert!(config.options.contains_key("username"));
        }
    }
}

#[test]
fn test_smb_command_generation() {
    let driver = SmbDriver::new();

    let mut config = MountConfig {
        server: "server.example.com".to_string(),
        remote_path: "share".to_string(),
        protocol: "smb".to_string(),
        mount_point: PathBuf::from("/mnt/smb"),
        read_only: false,
        options: HashMap::new(),
    };

    // Add SMB-specific options
    config.options.insert("username".to_string(), "testuser".to_string());
    config.options.insert("password".to_string(), "testpass".to_string());
    config.options.insert("domain".to_string(), "WORKGROUP".to_string());
    config.options.insert("vers".to_string(), "3.0".to_string());

    let command = driver.generate_mount_command(&config);
    let cmd_str = command.join(" ");

    // Check that command contains expected components
    assert!(cmd_str.contains("mount"));
    assert!(cmd_str.contains("-t cifs") || cmd_str.contains("-t smbfs"));
    assert!(cmd_str.contains("//server.example.com/share"));
    assert!(cmd_str.contains("/mnt/smb"));
    assert!(cmd_str.contains("username=testuser"));
    assert!(cmd_str.contains("password=testpass"));
    assert!(cmd_str.contains("domain=WORKGROUP"));
}

#[test]
fn test_smb_command_without_credentials() {
    let driver = SmbDriver::new();

    let config = MountConfig {
        server: "server.example.com".to_string(),
        remote_path: "share".to_string(),
        protocol: "smb".to_string(),
        mount_point: PathBuf::from("/mnt/smb"),
        read_only: false,
        options: HashMap::new(),
    };

    let command = driver.generate_mount_command(&config);
    let cmd_str = command.join(" ");

    // Should not contain credentials
    assert!(!cmd_str.contains("username="));
    assert!(!cmd_str.contains("password="));
    assert!(cmd_str.contains("guest") || cmd_str.contains("password="));
}

#[test]
fn test_sshfs_driver_creation() {
    let driver = SshfsDriver::new();
    assert_eq!(driver.get_name(), "sshfs");
    assert_eq!(driver.get_protocol(), "sshfs");
}

#[test]
fn test_sshfs_url_parsing() {
    let driver = SshfsDriver::new();

    // Test valid SSHFS URLs
    let valid_urls = vec![
        ("sshfs://user@server.example.com/path", "server.example.com", "/path", "user"),
        ("sshfs://server.example.com/home/user", "server.example.com", "/home/user", ""),
        ("sshfs://admin@192.168.1.100/data", "192.168.1.100", "/data", "admin"),
        ("sshfs://root@server.local/root", "server.local", "/root", "root"),
        ("sshfs://user@host.com:2222/path", "host.com", "/path", "user"), // With port
    ];

    for (url_str, expected_host, expected_path, expected_user) in valid_urls {
        let url = Url::parse(url_str).unwrap();
        let config = driver.parse_url(&url).unwrap();

        assert_eq!(config.server, expected_host);
        assert_eq!(config.remote_path, expected_path);
        assert_eq!(config.protocol, "sshfs");

        if !expected_user.is_empty() {
            assert_eq!(config.options.get("user"), Some(&expected_user.to_string()));
        }

        // Check port extraction
        if url_str.contains(":2222") {
            assert_eq!(config.options.get("port"), Some(&"2222".to_string()));
        }
    }
}

#[test]
fn test_sshfs_command_generation() {
    let driver = SshfsDriver::new();

    let mut config = MountConfig {
        server: "server.example.com".to_string(),
        remote_path: "/home/user".to_string(),
        protocol: "sshfs".to_string(),
        mount_point: PathBuf::from("/mnt/sshfs"),
        read_only: false,
        options: HashMap::new(),
    };

    // Add SSHFS-specific options
    config.options.insert("user".to_string(), "testuser".to_string());
    config.options.insert("port".to_string(), "2222".to_string());
    config.options.insert("IdentityFile".to_string(), "/home/user/.ssh/id_rsa".to_string());

    let command = driver.generate_mount_command(&config);
    let cmd_str = command.join(" ");

    // Check that command contains expected components
    assert!(cmd_str.contains("sshfs"));
    assert!(cmd_str.contains("testuser@server.example.com:/home/user"));
    assert!(cmd_str.contains("/mnt/sshfs"));
    assert!(cmd_str.contains("-p 2222"));
    assert!(cmd_str.contains("-o IdentityFile=/home/user/.ssh/id_rsa"));
}

#[test]
fn test_sshfs_readonly_command() {
    let driver = SshfsDriver::new();

    let config = MountConfig {
        server: "server.example.com".to_string(),
        remote_path: "/data".to_string(),
        protocol: "sshfs".to_string(),
        mount_point: PathBuf::from("/mnt/sshfs"),
        read_only: true,
        options: HashMap::new(),
    };

    let command = driver.generate_mount_command(&config);
    let cmd_str = command.join(" ");

    assert!(cmd_str.contains("-o ro") || cmd_str.contains("-o readonly"));
}

#[test]
fn test_driver_unmount_command() {
    let drivers: Vec<Box<dyn MountDriver>> = vec![
        Box::new(NfsDriver::new()),
        Box::new(SmbDriver::new()),
        Box::new(SshfsDriver::new()),
    ];

    for driver in drivers {
        let command = driver.generate_unmount_command("/mnt/test");
        let cmd_str = command.join(" ");

        // All drivers should generate valid unmount commands
        assert!(cmd_str.contains("umount") || cmd_str.contains("unmount"));
        assert!(cmd_str.contains("/mnt/test"));
    }
}

#[test]
fn test_driver_force_unmount() {
    let drivers: Vec<Box<dyn MountDriver>> = vec![
        Box::new(NfsDriver::new()),
        Box::new(SmbDriver::new()),
        Box::new(SshfsDriver::new()),
    ];

    for driver in drivers {
        let command = driver.generate_unmount_command("/mnt/test");
        let cmd_str = command.join(" ");

        // Check for lazy/force unmount options
        assert!(cmd_str.contains("-l") || cmd_str.contains("-f") ||
                cmd_str.contains("--lazy") || cmd_str.contains("--force"));
    }
}

#[test]
fn test_mount_status_validation() {
    // Test MountStatus enum and conversions
    let statuses = vec![
        MountStatus::Mounted,
        MountStatus::Unmounted,
        MountStatus::Error("Test error".to_string()),
        MountStatus::InProgress,
    ];

    for status in statuses {
        let status_str = status.to_string();
        assert!(!status_str.is_empty());

        // All statuses should be displayable
        assert!(status_str.len() > 0);
    }
}

#[test]
fn test_mount_driver_error() {
    // Test MountDriverError enum
    let errors = vec![
        MountDriverError::UnsupportedProtocol("ftp".to_string()),
        MountDriverError::InvalidUrl("Invalid format".to_string()),
        MountDriverError::MissingRequiredField("server".to_string()),
        MountDriverError::CommandFailed("mount failed".to_string()),
        MountDriverError::PermissionDenied,
        MountDriverError::NotFound,
    ];

    for error in errors {
        let error_str = error.to_string();
        assert!(!error_str.is_empty());

        // All errors should be displayable and contain useful information
        assert!(error_str.len() > 5);
    }
}

#[test]
fn test_driver_option_handling() {
    let driver = NfsDriver::new();

    let mut config = MountConfig {
        server: "server.example.com".to_string(),
        remote_path: "/export".to_string(),
        protocol: "nfs".to_string(),
        mount_point: PathBuf::from("/mnt/nfs"),
        read_only: false,
        options: HashMap::new(),
    };

    // Test various NFS options
    let test_options = vec![
        ("vers", "4"),
        ("proto", "tcp"),
        ("port", "2049"),
        ("rsize", "1048576"),
        ("wsize", "1048576"),
        ("timeo", "600"),
        ("retrans", "2"),
        ("soft", ""),
        ("hard", ""),
        ("intr", ""),
        ("noatime", ""),
        ("nodiratime", ""),
    ];

    for (key, value) in test_options {
        if value.is_empty() {
            config.options.insert(key.to_string(), "".to_string());
        } else {
            config.options.insert(key.to_string(), value.to_string());
        }
    }

    let command = driver.generate_mount_command(&config);
    let cmd_str = command.join(" ");

    // Verify options are included in command
    for (key, value) in test_options {
        if value.is_empty() {
            assert!(cmd_str.contains(&format!("-o {}", key)) ||
                    cmd_str.contains(&format!(",{}", key)));
        } else {
            assert!(cmd_str.contains(&format!("{}={}", key, value)));
        }
    }
}

#[test]
fn test_driver_url_port_extraction() {
    let driver = SshfsDriver::new();

    // Test URL with port
    let url = Url::parse("sshfs://user@server.example.com:2222/path").unwrap();
    let config = driver.parse_url(&url).unwrap();

    assert_eq!(config.server, "server.example.com");
    assert_eq!(config.remote_path, "/path");
    assert_eq!(config.options.get("port"), Some(&"2222".to_string()));
    assert_eq!(config.options.get("user"), Some(&"user".to_string()));
}

#[test]
fn test_driver_special_characters() {
    let driver = SmbDriver::new();

    // Test URL with special characters in password
    let url = Url::parse("smb://user:p%40ss@server.example.com/share").unwrap();
    let config = driver.parse_url(&url).unwrap();

    assert_eq!(config.server, "server.example.com");
    assert_eq!(config.remote_path, "share");

    // Password should be URL-decoded
    assert_eq!(config.options.get("password"), Some(&"p@ss".to_string()));
}

#[test]
fn test_driver_ipv6_addresses() {
    let driver = NfsDriver::new();

    // Test IPv6 address
    let url = Url::parse("nfs://[2001:db8::1]/export").unwrap();
    let config = driver.parse_url(&url).unwrap();

    assert_eq!(config.server, "2001:db8::1");
    assert_eq!(config.remote_path, "/export");
}

#[test]
fn test_driver_edge_cases() {
    let driver = NfsDriver::new();

    // Test URL with query parameters (should be ignored or handled gracefully)
    let url = Url::parse("nfs://server.example.com/export?timeout=60").unwrap();
    let result = driver.parse_url(&url);

    // Should either succeed or fail gracefully
    match result {
        Ok(config) => {
            assert_eq!(config.server, "server.example.com");
            assert_eq!(config.remote_path, "/export");
        },
        Err(_) => {
            // It's acceptable to reject URLs with query parameters
        }
    }
}

#[cfg(test)]
mod property_based_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_nfs_url_parsing_properties(
            host in "[a-zA-Z0-9.-]+",
            path in "/[a-zA-Z0-9/-]*"
        ) {
            // Skip empty host
            prop_assume!(!host.is_empty());

            let url_str = format!("nfs://{}{}", host, path);
            if let Ok(url) = Url::parse(&url_str) {
                let driver = NfsDriver::new();
                let result = driver.parse_url(&url);

                // If parsing succeeds, verify basic properties
                if let Ok(config) = result {
                    assert_eq!(config.server, host);
                    assert_eq!(config.remote_path, path);
                    assert_eq!(config.protocol, "nfs");
                }
            }
        }

        #[test]
        fn test_mount_config_consistency(
            server in "[a-zA-Z0-9.-]+",
            path in "/[a-zA-Z0-9/-]*",
            read_only in any::<bool>()
        ) {
            prop_assume!(!server.is_empty());

            let config = MountConfig {
                server: server.clone(),
                remote_path: path.clone(),
                protocol: "nfs".to_string(),
                mount_point: PathBuf::from("/mnt/test"),
                read_only,
                options: HashMap::new(),
            };

            // Basic consistency checks
            assert_eq!(config.server, server);
            assert_eq!(config.remote_path, path);
            assert_eq!(config.read_only, read_only);
            assert_eq!(config.protocol, "nfs");
        }

        #[test]
        fn test_driver_command_formatting(
            options_count in 0..10usize,
            read_only in any::<bool>()
        ) {
            let driver = NfsDriver::new();
            let mut config = MountConfig {
                server: "server.example.com".to_string(),
                remote_path: "/export".to_string(),
                protocol: "nfs".to_string(),
                mount_point: PathBuf::from("/mnt/nfs"),
                read_only,
                options: HashMap::new(),
            };

            // Add random number of options
            for i in 0..options_count {
                config.options.insert(format!("option{}", i), format!("value{}", i));
            }

            let command = driver.generate_mount_command(&config);
            let cmd_str = command.join(" ");

            // Basic command format checks
            assert!(!cmd_str.is_empty());
            assert!(cmd_str.contains("mount"));
            assert!(cmd_str.contains("server.example.com:/export"));
            assert!(cmd_str.contains("/mnt/nfs"));

            // Check read-only flag
            if read_only {
                assert!(cmd_str.contains("ro"));
            }
        }
    }
}

#[cfg(test)]
mod integration_style_tests {
    use super::*;

    #[test]
    fn test_complete_mount_workflow() {
        // Test complete workflow: URL parsing -> config -> command generation
        let drivers: Vec<Box<dyn MountDriver>> = vec![
            Box::new(NfsDriver::new()),
            Box::new(SmbDriver::new()),
            Box::new(SshfsDriver::new()),
        ];

        let test_urls = vec![
            ("nfs://server.example.com/export", "nfs"),
            ("smb://user@server.example.com/share", "smb"),
            ("sshfs://user@server.example.com/path", "sshfs"),
        ];

        for driver in drivers {
            for (url_str, expected_protocol) in &test_urls {
                if driver.get_protocol() == *expected_protocol {
                    let url = Url::parse(url_str).unwrap();

                    // Parse URL
                    let config = driver.parse_url(&url).expect("Should parse valid URL");
                    assert_eq!(config.protocol, *expected_protocol);

                    // Generate mount command
                    let mount_cmd = driver.generate_mount_command(&config);
                    assert!(!mount_cmd.is_empty());

                    // Generate unmount command
                    let unmount_cmd = driver.generate_unmount_command(&config.mount_point);
                    assert!(!unmount_cmd.is_empty());
                }
            }
        }
    }

    #[test]
    fn test_driver_error_propagation() {
        let driver = NfsDriver::new();

        // Test various error conditions
        let test_cases = vec![
            ("", "Invalid URL"),
            ("http://server.com/export", "Unsupported protocol"),
            ("nfs://", "Missing host"),
            ("nfs://server", "Missing path"),
        ];

        for (url_str, description) in test_cases {
            if let Ok(url) = Url::parse(url_str) {
                let result = driver.parse_url(&url);
                if let Err(error) = result {
                    let error_str = error.to_string();
                    assert!(!error_str.is_empty());
                    // Error message should contain useful information
                    assert!(error_str.len() > 10);
                }
            }
        }
    }
}