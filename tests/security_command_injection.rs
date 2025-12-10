//! Integration tests for command injection vulnerabilities
//!
//! These tests ensure that the mount drivers are properly protected against
//! command injection attacks through malicious URLs and mount options.

use fuji::mount::MountHandler;
use fuji::mount::drivers::{
    MountOptionsValidator, MountUrlValidator, NfsHandler, SecureCommand, SmbHandler, SshfsHandler,
    create_secure_mount_command,
};

#[test]
fn test_command_injection_in_nfs_url() {
    let handler = NfsHandler::new();

    // These should all be rejected
    let malicious_urls = vec![
        "nfs://server.example.com/export; rm -rf /",
        "nfs://server.example.com/export|cat /etc/passwd",
        "nfs://server.example.com/export`whoami`",
        "nfs://server.example.com/export$(cat /etc/shadow)",
        "nfs://server.example.com/export && cat /etc/passwd",
        "nfs://server.example.com/export || cat /etc/passwd",
        "nfs://server;cat /etc/passwd/export",
    ];

    for url in malicious_urls {
        let result = handler.parse_url(url);
        assert!(result.is_err(), "URL should be rejected: {}", url);
        let error_msg = format!("{}", result.unwrap_err());
        assert!(
            error_msg.contains("shell") || error_msg.contains("dangerous"),
            "Error should mention shell injection for URL: {}, error: {}",
            url,
            error_msg
        );
    }
}

#[test]
fn test_command_injection_in_smb_url() {
    let handler = SmbHandler::new();

    // These should all be rejected
    let malicious_urls = vec![
        "smb://server.example.com/share; rm -rf /",
        "smb://server.example.com/share|cat /etc/passwd",
        "smb://server;cat /etc/passwd/share",
        "cifs://server.example.com/share`whoami`",
        "cifs://server.example.com/share$(id)",
    ];

    for url in malicious_urls {
        let result = handler.parse_url(url);
        assert!(result.is_err(), "URL should be rejected: {}", url);
        let error_msg = format!("{}", result.unwrap_err());
        assert!(
            error_msg.contains("shell") || error_msg.contains("dangerous"),
            "Error should mention shell injection for URL: {}, error: {}",
            url,
            error_msg
        );
    }
}

#[test]
fn test_command_injection_in_sshfs_url() {
    let handler = SshfsHandler::new();

    // These should all be rejected
    let malicious_urls = vec![
        "sshfs://server.example.com/path; rm -rf /",
        "sshfs://server.example.com/path|cat /etc/passwd",
        "sshfs://server;cat /etc/passwd/path",
        "sftp://server.example.com/path`whoami`",
        "ssh://server.example.com/path$(id)",
    ];

    for url in malicious_urls {
        let result = handler.parse_url(url);
        assert!(result.is_err(), "URL should be rejected: {}", url);
        let error_msg = format!("{}", result.unwrap_err());
        assert!(
            error_msg.contains("shell") || error_msg.contains("dangerous"),
            "Error should mention shell injection for URL: {}, error: {}",
            url,
            error_msg
        );
    }
}

#[test]
fn test_command_injection_in_mount_options() {
    let validator = MountOptionsValidator::new().unwrap();

    // These should all be rejected
    let malicious_options = vec![
        vec!["ro".to_string(), "exec".to_string()], // Blocked dangerous option
        vec!["rw".to_string(), "suid".to_string()], // Blocked dangerous option
        vec!["user=;rm -rf /".to_string()],         // Command injection in value
        vec!["password=$(cat /etc/passwd)".to_string()], // Command substitution
        vec!["username=`id`".to_string()],          // Command substitution
        vec!["option1".to_string(), "option2|cat /etc/shadow".to_string()], // Pipe injection
    ];

    for options in &malicious_options {
        let result = validator.validate_options("nfs", options);
        assert!(result.is_err(), "Options should be rejected: {:?}", options);

        let error_msg = format!("{}", result.unwrap_err());
        assert!(
            error_msg.contains("blocked")
                || error_msg.contains("dangerous")
                || error_msg.contains("not in allowlist")
                || error_msg.contains("Blocked option"),
            "Error should mention blocked/allowlist for options: {:?}, error: {}",
            options,
            error_msg
        );
    }
}

#[test]
fn test_x_options_allowed() {
    let validator = MountOptionsValidator::new().unwrap();

    // X- options should be allowed even if they contain special characters
    let x_options = vec![
        vec!["x-custom-option".to_string()],
        vec!["x-test=some:value".to_string()],
        vec!["x-debug=true".to_string()],
    ];

    for options in &x_options {
        let result = validator.validate_options("nfs", options);
        assert!(result.is_ok(), "X-options should be allowed: {:?}", options);
    }
}

// NOTE: The test_secure_command_argument_escaping test was removed
// when the get_program() and get_args() methods were deleted from SecureCommand
// as they were unused production code. The functionality is tested
// implicitly through the actual mount operations.

#[test]
fn test_blocked_hostnames() {
    let validator = MountUrlValidator::new().unwrap();

    // These hostnames should be blocked
    let blocked_urls = vec![
        "nfs://localhost/export",
        "nfs://127.0.0.1/export",
        "nfs://::1/export",
        "nfs://0.0.0.0/export",
    ];

    for url in blocked_urls {
        let result = validator.validate_url(url);
        if result.is_err() {
            let error_msg = format!("{}", result.unwrap_err());
            println!("Error for {}: {}", url, error_msg);
            assert!(
                error_msg.contains("blocked") || error_msg.contains("Hostname is blocked"),
                "Error should mention blocked hostname for URL: {}",
                url
            );
        } else {
            panic!("URL with blocked hostname should be rejected: {}", url);
        }
    }
}

#[test]
fn test_path_traversal_prevention() {
    let validator = MountUrlValidator::new().unwrap();

    // These paths should be blocked
    let traversal_urls = vec![
        "nfs://server.example.com/../../../etc",
        "nfs://server.example.com/etc/passwd",
        "nfs://server.example.com/../../root/.ssh",
        "nfs://server.example.com/bin/sh",
        "nfs://server.example.com/path/../../../etc/passwd",
        "nfs://server.example.com/path/to/../../root",
    ];

    for url in traversal_urls {
        let result = validator.validate_url(url);
        assert!(
            result.is_err(),
            "URL with path traversal should be rejected: {}",
            url
        );
    }
}

#[test]
fn test_url_length_limits() {
    let validator = MountUrlValidator::new().unwrap();

    // Test with very long hostname
    let long_hostname = "a".repeat(300);
    let url = format!("nfs://{}.com/export", long_hostname);
    let result = validator.validate_url(&url);
    assert!(result.is_err(), "URL with long hostname should be rejected");

    // Test with very long path
    let long_path = "/".to_string() + &"a".repeat(5000);
    let url = format!("nfs://server.example.com{}", long_path);
    let result = validator.validate_url(&url);
    assert!(result.is_err(), "URL with long path should be rejected");
}

#[test]
fn test_mount_option_limits() {
    let validator = MountOptionsValidator::new().unwrap();

    // Test with too many options
    let too_many_options: Vec<String> = (0..100).map(|i| format!("option{}", i)).collect();
    let result = validator.validate_options("nfs", &too_many_options);
    assert!(result.is_err(), "Too many options should be rejected");
    let error_msg = format!("{}", result.unwrap_err());
    assert!(
        error_msg.contains("Too many options"),
        "Error should mention too many options"
    );

    // Test with option too long
    let long_option = "x-".to_string() + &"a".repeat(300);
    let result = validator.validate_options("nfs", &[long_option]);
    assert!(result.is_err(), "Option too long should be rejected");
    let error_msg = format!("{}", result.unwrap_err());
    assert!(
        error_msg.contains("too long"),
        "Error should mention option too long"
    );
}

#[test]
fn test_numeric_validation_in_options() {
    let validator = MountOptionsValidator::new().unwrap();

    // Valid numeric values should pass
    assert!(
        validator
            .validate_options("smb", &["uid=1000".to_string()])
            .is_ok()
    );
    assert!(
        validator
            .validate_options("smb", &["gid=1000".to_string()])
            .is_ok()
    );

    // Invalid numeric values should fail
    assert!(
        validator
            .validate_options("smb", &["uid=abc".to_string()])
            .is_err()
    );
    assert!(
        validator
            .validate_options("smb", &["uid=-1".to_string()])
            .is_err()
    );
    assert!(
        validator
            .validate_options("smb", &["port=0".to_string()])
            .is_err()
    );
    assert!(
        validator
            .validate_options("smb", &["port=99999".to_string()])
            .is_err()
    );
}

#[test]
fn test_mode_validation_in_options() {
    let validator = MountOptionsValidator::new().unwrap();

    // Valid mode values should pass
    assert!(
        validator
            .validate_options("sshfs", &["file_mode=0644".to_string()])
            .is_ok()
    );
    assert!(
        validator
            .validate_options("sshfs", &["dir_mode=0755".to_string()])
            .is_ok()
    );

    // Invalid mode values should fail
    assert!(
        validator
            .validate_options("sshfs", &["file_mode=7777".to_string()])
            .is_err()
    );
    assert!(
        validator
            .validate_options("sshfs", &["file_mode=abc".to_string()])
            .is_err()
    );
}

#[tokio::test]
async fn test_secure_command_output_handling() {
    // Test that SecureCommand properly handles command output
    let cmd = SecureCommand::new("echo").arg("test");

    // This should succeed and return the output
    let output = cmd.output().await.unwrap();
    assert!(output.contains("test"));

    // Test with a command that will fail
    let cmd = SecureCommand::new("false");
    let result = cmd.output().await;
    assert!(result.is_err());
}

#[test]
fn test_allowlist_enforcement() {
    let validator = MountOptionsValidator::new().unwrap();

    // Options not in allowlist should be rejected in strict mode
    let unsupported_options = vec![
        vec!["unsupported_option".to_string()],
        vec!["exec".to_string()],  // This is explicitly blocked
        vec!["users".to_string()], // This is explicitly blocked
    ];

    for options in unsupported_options {
        let result = validator.validate_options("nfs", &options);
        assert!(
            result.is_err(),
            "Unsupported option should be rejected: {:?}",
            options
        );
    }
}

#[test]
fn test_scheme_validation() {
    let validator = MountUrlValidator::new().unwrap();

    // Only allowed schemes should pass
    let allowed_schemes = vec!["nfs", "smb", "cifs", "sshfs", "sftp", "nfs4"];
    let blocked_schemes = vec!["http", "https", "ftp", "file", "telnet"];

    for scheme in allowed_schemes {
        let url = format!("{}://server.example.com/export", scheme);
        assert!(
            validator.validate_url(&url).is_ok(),
            "Allowed scheme should pass: {}",
            scheme
        );
    }

    for scheme in blocked_schemes {
        let url = format!("{}://server.example.com/export", scheme);
        let result = validator.validate_url(&url);
        assert!(
            result.is_err(),
            "Blocked scheme should be rejected: {}",
            scheme
        );
        let error_msg = format!("{}", result.unwrap_err());
        assert!(
            error_msg.contains("scheme"),
            "Error should mention scheme for URL: {}",
            url
        );
    }
}
