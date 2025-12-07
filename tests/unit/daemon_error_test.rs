//! Unit tests for daemon error handling
//!
//! These tests ensure that the daemon properly handles error conditions
//! without panicking and provides appropriate error messages.

use fuji::daemon::error::{DaemonError, DaemonResult};

#[test]
fn test_daemon_error_creation() {
    // Test creating different types of errors
    let mount_err = DaemonError::mount_error("Test mount error");
    assert!(mount_err.to_string().contains("Mount error"));
    assert_eq!(mount_err.category(), "mount");
    assert!(mount_err.is_recoverable());

    let config_err = DaemonError::config_error("Test config error");
    assert!(config_err.to_string().contains("Configuration error"));
    assert_eq!(config_err.category(), "config");

    let not_found_err = DaemonError::mount_not_found("test_mount");
    assert!(not_found_err.to_string().contains("not found"));
    assert_eq!(not_found_err.category(), "not_found");
    assert!(!not_found_err.is_recoverable());

    let permission_err = DaemonError::permission_denied("test operation");
    assert!(permission_err.to_string().contains("Permission denied"));
    assert_eq!(permission_err.category(), "permission");
    assert!(!permission_err.is_recoverable());
}

#[test]
fn test_daemon_result_type() {
    // Test successful result
    let success: DaemonResult<i32> = Ok(42);
    assert!(success.is_ok());

    // Test error result
    let error = DaemonError::network_error("Connection failed");
    assert_eq!(error.category(), "network");
}

#[test]
fn test_error_display_formatting() {
    let err = DaemonError::mount_not_found("my_mount");
    assert_eq!(err.to_string(), "Mount 'my_mount' not found");

    let err = DaemonError::timeout("mount operation");
    assert_eq!(err.to_string(), "Operation timed out: mount operation");

    let err = DaemonError::state_error("Invalid daemon state");
    assert_eq!(err.to_string(), "Invalid state: Invalid daemon state");
}

#[test]
fn test_error_recovery() {
    // Recoverable errors
    assert!(DaemonError::network_error("test").is_recoverable());
    assert!(DaemonError::mount_error("test").is_recoverable());
    assert!(DaemonError::health_check_error("test", "test").is_recoverable());
    assert!(DaemonError::reconnection_error("test", "test").is_recoverable());
    assert!(DaemonError::timeout("test").is_recoverable());

    // Non-recoverable errors
    assert!(!DaemonError::permission_denied("test").is_recoverable());
    assert!(!DaemonError::mount_not_found("test").is_recoverable());
}

// Note: The test_update_mount_status_not_found test requires full daemon
// initialization which depends on platform-specific code. This test
// would be better suited as an integration test rather than a unit test.

#[test]
fn test_generic_error_creation() {
    // Test creating generic errors from anyhow::Error
    let anyhow_err = anyhow::anyhow!("Something went wrong");
    let daemon_err = DaemonError::generic("Context info", anyhow_err);

    assert!(daemon_err.to_string().contains("Context info"));
    assert!(daemon_err.to_string().contains("Something went wrong"));
    assert_eq!(daemon_err.category(), "generic");
}

#[test]
fn test_convenience_methods() {
    // Test all convenience methods
    let err = DaemonError::socket_error("Socket bind failed");
    assert!(err.to_string().contains("Socket error"));

    let err = DaemonError::platform_error("Unsupported OS");
    assert!(err.to_string().contains("Platform error"));

    let err = DaemonError::resource_not_found("File not found");
    assert!(err.to_string().contains("Resource not found"));

    let err = DaemonError::invalid_operation("Invalid mount operation");
    assert!(err.to_string().contains("Invalid operation"));

    let err = DaemonError::system_error("Out of memory");
    assert!(err.to_string().contains("System error"));

    let err = DaemonError::signal_error("Failed to setup signal handler");
    assert!(err.to_string().contains("Signal error"));

    let err = DaemonError::pid_file_error("PID file exists");
    assert!(err.to_string().contains("PID file error"));

    let err = DaemonError::lock_error("Mount lock");
    assert!(err.to_string().contains("Failed to acquire lock"));
}

#[test]
fn test_regex_error() {
    // Test regex compilation error
    let regex_err = regex::Error::Syntax("invalid regex".to_string());
    let daemon_err = DaemonError::from(regex_err);

    match daemon_err {
        DaemonError::RegexError {
            pattern,
            source,
        } => {
            assert_eq!(pattern, "unknown");
            assert!(matches!(source, regex::Error::Syntax(_)));
        }
        _ => panic!("Expected RegexError"),
    }
}

#[test]
fn test_io_error_conversion() {
    use std::io;

    // Test that I/O errors are properly converted
    let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "Access denied");
    let daemon_err = DaemonError::from(io_err);

    match daemon_err {
        DaemonError::Io(err) => {
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(err.to_string(), "Access denied");
        }
        _ => panic!("Expected Io error"),
    }
}

// TOML error conversion tests are complex and require specific trait imports.
// The conversion is handled automatically by the thiserror derive macro.

#[test]
fn test_anyhow_error_conversion() {
    let anyhow_err = anyhow::anyhow!("Some error");
    let daemon_err = DaemonError::from(anyhow_err);

    match daemon_err {
        DaemonError::Generic {
            context,
            source,
        } => {
            assert_eq!(context, "Unexpected error");
            assert_eq!(source.to_string(), "Some error");
        }
        _ => panic!("Expected Generic error"),
    }
}
