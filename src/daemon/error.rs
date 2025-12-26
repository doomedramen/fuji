// Allow dead code - error types for future features
#![allow(dead_code)]

//! Custom error types for the Fuji daemon
//!
//! This module defines comprehensive error types using thiserror for better
//! error handling and context throughout the daemon operations.

use thiserror::Error;

/// Main daemon error type
#[derive(Error, Debug)]
pub enum DaemonError {
    /// Mount-related errors
    #[error("Mount error: {message}")]
    MountError {
        message: String,
    },

    /// Configuration errors
    #[error("Configuration error: {message}")]
    ConfigError {
        message: String,
    },

    /// I/O related errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Network-related errors
    #[error("Network error: {message}")]
    NetworkError {
        message: String,
    },

    /// Protocol parsing errors
    #[error("Invalid protocol in URL: {url}")]
    InvalidProtocol {
        url: String,
    },

    /// Mount not found errors
    #[error("Mount '{mount_id}' not found")]
    MountNotFound {
        mount_id: String,
    },

    /// Mount operation conflicts
    #[error("Mount operation conflict: {message}")]
    MountConflict {
        message: String,
    },

    /// Regex compilation errors
    #[error("Failed to compile regex pattern '{pattern}': {source}")]
    RegexError {
        pattern: String,
        #[source]
        source: regex::Error,
    },

    /// Serialization/Deserialization errors
    #[error("Serialization error: {0}")]
    Serialization(#[from] toml::ser::Error),

    /// Deserialization errors
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] toml::de::Error),

    /// Socket/communication errors
    #[error("Socket error: {message}")]
    SocketError {
        message: String,
    },

    /// Platform-specific errors
    #[error("Platform error: {message}")]
    PlatformError {
        message: String,
    },

    /// Permission errors
    #[error("Permission denied: {operation}")]
    PermissionDenied {
        operation: String,
    },

    /// Resource not found errors
    #[error("Resource not found: {resource}")]
    ResourceNotFound {
        resource: String,
    },

    /// Invalid operation errors
    #[error("Invalid operation: {operation}")]
    InvalidOperation {
        operation: String,
    },

    /// Timeout errors
    #[error("Operation timed out: {operation}")]
    Timeout {
        operation: String,
    },

    /// State errors
    #[error("Invalid state: {message}")]
    StateError {
        message: String,
    },

    /// System errors
    #[error("System error: {message}")]
    SystemError {
        message: String,
    },

    /// Signal handling errors
    #[error("Signal error: {message}")]
    SignalError {
        message: String,
    },

    /// PID file errors
    #[error("PID file error: {message}")]
    PidFileError {
        message: String,
    },

    /// Lock acquisition errors
    #[error("Failed to acquire lock: {lock_name}")]
    LockError {
        lock_name: String,
    },

    /// Health check errors
    #[error("Health check failed for mount '{mount_id}': {reason}")]
    HealthCheckError {
        mount_id: String,
        reason: String,
    },

    /// Reconnection errors
    #[error("Reconnection failed for mount '{mount_id}': {reason}")]
    ReconnectionError {
        mount_id: String,
        reason: String,
    },

    /// Generic errors with context
    #[error("{context}: {source}")]
    Generic {
        context: String,
        #[source]
        source: anyhow::Error,
    },
}

/// Result type alias for daemon operations
pub type DaemonResult<T> = Result<T, DaemonError>;

#[allow(dead_code)]
impl DaemonError {
    /// Create a new mount error
    pub fn mount_error<S: Into<String>>(message: S) -> Self {
        Self::MountError {
            message: message.into(),
        }
    }

    /// Create a new config error
    pub fn config_error<S: Into<String>>(message: S) -> Self {
        Self::ConfigError {
            message: message.into(),
        }
    }

    /// Create a new network error
    pub fn network_error<S: Into<String>>(message: S) -> Self {
        Self::NetworkError {
            message: message.into(),
        }
    }

    /// Create a new mount not found error
    pub fn mount_not_found<S: Into<String>>(mount_id: S) -> Self {
        Self::MountNotFound {
            mount_id: mount_id.into(),
        }
    }

    /// Create a new mount conflict error
    pub fn mount_conflict<S: Into<String>>(message: S) -> Self {
        Self::MountConflict {
            message: message.into(),
        }
    }

    /// Create a new socket error
    pub fn socket_error<S: Into<String>>(message: S) -> Self {
        Self::SocketError {
            message: message.into(),
        }
    }

    /// Create a new platform error
    pub fn platform_error<S: Into<String>>(message: S) -> Self {
        Self::PlatformError {
            message: message.into(),
        }
    }

    /// Create a new permission denied error
    pub fn permission_denied<S: Into<String>>(operation: S) -> Self {
        Self::PermissionDenied {
            operation: operation.into(),
        }
    }

    /// Create a new resource not found error
    pub fn resource_not_found<S: Into<String>>(resource: S) -> Self {
        Self::ResourceNotFound {
            resource: resource.into(),
        }
    }

    /// Create a new invalid operation error
    pub fn invalid_operation<S: Into<String>>(operation: S) -> Self {
        Self::InvalidOperation {
            operation: operation.into(),
        }
    }

    /// Create a new timeout error
    pub fn timeout<S: Into<String>>(operation: S) -> Self {
        Self::Timeout {
            operation: operation.into(),
        }
    }

    /// Create a new state error
    pub fn state_error<S: Into<String>>(message: S) -> Self {
        Self::StateError {
            message: message.into(),
        }
    }

    /// Create a new system error
    pub fn system_error<S: Into<String>>(message: S) -> Self {
        Self::SystemError {
            message: message.into(),
        }
    }

    /// Create a new signal error
    pub fn signal_error<S: Into<String>>(message: S) -> Self {
        Self::SignalError {
            message: message.into(),
        }
    }

    /// Create a new PID file error
    pub fn pid_file_error<S: Into<String>>(message: S) -> Self {
        Self::PidFileError {
            message: message.into(),
        }
    }

    /// Create a new lock error
    pub fn lock_error<S: Into<String>>(lock_name: S) -> Self {
        Self::LockError {
            lock_name: lock_name.into(),
        }
    }

    /// Create a new health check error
    pub fn health_check_error<S: Into<String>>(mount_id: S, reason: S) -> Self {
        Self::HealthCheckError {
            mount_id: mount_id.into(),
            reason: reason.into(),
        }
    }

    /// Create a new reconnection error
    pub fn reconnection_error<S: Into<String>>(mount_id: S, reason: S) -> Self {
        Self::ReconnectionError {
            mount_id: mount_id.into(),
            reason: reason.into(),
        }
    }

    /// Create a generic error from another error type with context
    pub fn generic<S: Into<String>>(context: S, source: anyhow::Error) -> Self {
        Self::Generic {
            context: context.into(),
            source,
        }
    }

    /// Check if this error is recoverable
    #[must_use]
    pub const fn is_recoverable(&self) -> bool {
        match self {
            Self::NetworkError {
                ..
            }
            | Self::MountError {
                ..
            }
            | Self::HealthCheckError {
                ..
            }
            | Self::ReconnectionError {
                ..
            }
            | Self::Timeout {
                ..
            } => true,

            Self::PermissionDenied {
                ..
            }
            | Self::InvalidProtocol {
                ..
            }
            | Self::MountNotFound {
                ..
            }
            | Self::InvalidOperation {
                ..
            }
            | Self::Deserialization(_)
            | Self::Serialization(_) => false,

            // Default to recoverable for other cases
            _ => true,
        }
    }

    /// Get the error category for logging/metrics
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::MountError {
                ..
            } => "mount",
            Self::ConfigError {
                ..
            } => "config",
            Self::Io(_) => "io",
            Self::NetworkError {
                ..
            } => "network",
            Self::InvalidProtocol {
                ..
            } => "protocol",
            Self::MountNotFound {
                ..
            } => "not_found",
            Self::MountConflict {
                ..
            } => "conflict",
            Self::RegexError {
                ..
            } => "regex",
            Self::Serialization(_) | Self::Deserialization(_) => "serialization",
            Self::SocketError {
                ..
            } => "socket",
            Self::PlatformError {
                ..
            } => "platform",
            Self::PermissionDenied {
                ..
            } => "permission",
            Self::ResourceNotFound {
                ..
            } => "resource",
            Self::InvalidOperation {
                ..
            } => "operation",
            Self::Timeout {
                ..
            } => "timeout",
            Self::StateError {
                ..
            } => "state",
            Self::SystemError {
                ..
            } => "system",
            Self::SignalError {
                ..
            } => "signal",
            Self::PidFileError {
                ..
            } => "pidfile",
            Self::LockError {
                ..
            } => "lock",
            Self::HealthCheckError {
                ..
            } => "health",
            Self::ReconnectionError {
                ..
            } => "reconnection",
            Self::Generic {
                ..
            } => "generic",
        }
    }
}

/// Note: From<std::io::Error> is automatically derived by thiserror
/// and will use the Io variant
///
/// Conversion from `regex::Error` to `DaemonError`
impl From<regex::Error> for DaemonError {
    fn from(err: regex::Error) -> Self {
        Self::RegexError {
            pattern: "unknown".to_string(),
            source: err,
        }
    }
}

/// Conversion from `anyhow::Error` to `DaemonError`
impl From<anyhow::Error> for DaemonError {
    fn from(err: anyhow::Error) -> Self {
        Self::generic("Unexpected error", err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_categories() {
        let err = DaemonError::mount_error("test");
        assert_eq!(err.category(), "mount");

        let err = DaemonError::network_error("test");
        assert_eq!(err.category(), "network");

        let err = DaemonError::permission_denied("test");
        assert_eq!(err.category(), "permission");
    }

    #[test]
    fn test_all_error_categories() {
        // Test all category variants
        assert_eq!(DaemonError::mount_error("test").category(), "mount");
        assert_eq!(DaemonError::config_error("test").category(), "config");
        assert_eq!(DaemonError::network_error("test").category(), "network");
        assert_eq!(DaemonError::mount_not_found("test").category(), "not_found");
        assert_eq!(DaemonError::mount_conflict("test").category(), "conflict");
        assert_eq!(DaemonError::socket_error("test").category(), "socket");
        assert_eq!(DaemonError::platform_error("test").category(), "platform");
        assert_eq!(
            DaemonError::permission_denied("test").category(),
            "permission"
        );
        assert_eq!(
            DaemonError::resource_not_found("test").category(),
            "resource"
        );
        assert_eq!(
            DaemonError::invalid_operation("test").category(),
            "operation"
        );
        assert_eq!(DaemonError::timeout("test").category(), "timeout");
        assert_eq!(DaemonError::state_error("test").category(), "state");
        assert_eq!(DaemonError::system_error("test").category(), "system");
        assert_eq!(DaemonError::signal_error("test").category(), "signal");
        assert_eq!(DaemonError::pid_file_error("test").category(), "pidfile");
        assert_eq!(DaemonError::lock_error("test").category(), "lock");
        assert_eq!(
            DaemonError::health_check_error("m1", "reason").category(),
            "health"
        );
        assert_eq!(
            DaemonError::reconnection_error("m1", "reason").category(),
            "reconnection"
        );

        let generic_err = DaemonError::generic("ctx", anyhow::anyhow!("inner"));
        assert_eq!(generic_err.category(), "generic");

        let invalid_proto = DaemonError::InvalidProtocol {
            url: "bad://".to_string(),
        };
        assert_eq!(invalid_proto.category(), "protocol");

        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let daemon_io = DaemonError::from(io_err);
        assert_eq!(daemon_io.category(), "io");
    }

    #[test]
    fn test_recoverable_errors() {
        assert!(DaemonError::network_error("test").is_recoverable());
        assert!(DaemonError::mount_error("test").is_recoverable());
        assert!(DaemonError::health_check_error("test", "test").is_recoverable());

        assert!(!DaemonError::permission_denied("test").is_recoverable());
        assert!(
            !DaemonError::InvalidProtocol {
                url: "test://".to_string()
            }
            .is_recoverable()
        );
    }

    #[test]
    fn test_all_recoverable_checks() {
        // Recoverable errors
        assert!(DaemonError::network_error("test").is_recoverable());
        assert!(DaemonError::mount_error("test").is_recoverable());
        assert!(DaemonError::health_check_error("m1", "reason").is_recoverable());
        assert!(DaemonError::reconnection_error("m1", "reason").is_recoverable());
        assert!(DaemonError::timeout("test").is_recoverable());

        // Non-recoverable errors
        assert!(!DaemonError::permission_denied("test").is_recoverable());
        assert!(
            !DaemonError::InvalidProtocol {
                url: "bad://".to_string()
            }
            .is_recoverable()
        );
        assert!(!DaemonError::mount_not_found("m1").is_recoverable());
        assert!(!DaemonError::invalid_operation("test").is_recoverable());

        // Default recoverable
        assert!(DaemonError::config_error("test").is_recoverable());
        assert!(DaemonError::socket_error("test").is_recoverable());
        assert!(DaemonError::platform_error("test").is_recoverable());
        assert!(DaemonError::state_error("test").is_recoverable());
        assert!(DaemonError::system_error("test").is_recoverable());
    }

    #[test]
    fn test_error_display() {
        let err = DaemonError::mount_not_found("test_mount");
        assert_eq!(err.to_string(), "Mount 'test_mount' not found");

        let err = DaemonError::permission_denied("mount operation");
        assert_eq!(err.to_string(), "Permission denied: mount operation");
    }

    #[test]
    fn test_all_error_display() {
        assert_eq!(
            DaemonError::mount_error("failed to mount").to_string(),
            "Mount error: failed to mount"
        );
        assert_eq!(
            DaemonError::config_error("invalid config").to_string(),
            "Configuration error: invalid config"
        );
        assert_eq!(
            DaemonError::network_error("connection refused").to_string(),
            "Network error: connection refused"
        );
        assert_eq!(
            DaemonError::InvalidProtocol {
                url: "ftp://host".to_string()
            }
            .to_string(),
            "Invalid protocol in URL: ftp://host"
        );
        assert_eq!(
            DaemonError::mount_not_found("my-mount").to_string(),
            "Mount 'my-mount' not found"
        );
        assert_eq!(
            DaemonError::mount_conflict("already mounted").to_string(),
            "Mount operation conflict: already mounted"
        );
        assert_eq!(
            DaemonError::socket_error("bind failed").to_string(),
            "Socket error: bind failed"
        );
        assert_eq!(
            DaemonError::platform_error("unsupported os").to_string(),
            "Platform error: unsupported os"
        );
        assert_eq!(
            DaemonError::permission_denied("write").to_string(),
            "Permission denied: write"
        );
        assert_eq!(
            DaemonError::resource_not_found("file.txt").to_string(),
            "Resource not found: file.txt"
        );
        assert_eq!(
            DaemonError::invalid_operation("mount while stopped").to_string(),
            "Invalid operation: mount while stopped"
        );
        assert_eq!(
            DaemonError::timeout("health check").to_string(),
            "Operation timed out: health check"
        );
        assert_eq!(
            DaemonError::state_error("daemon not running").to_string(),
            "Invalid state: daemon not running"
        );
        assert_eq!(
            DaemonError::system_error("out of memory").to_string(),
            "System error: out of memory"
        );
        assert_eq!(
            DaemonError::signal_error("handler failed").to_string(),
            "Signal error: handler failed"
        );
        assert_eq!(
            DaemonError::pid_file_error("stale pid").to_string(),
            "PID file error: stale pid"
        );
        assert_eq!(
            DaemonError::lock_error("config_lock").to_string(),
            "Failed to acquire lock: config_lock"
        );
        assert_eq!(
            DaemonError::health_check_error("nfs-mount", "timeout").to_string(),
            "Health check failed for mount 'nfs-mount': timeout"
        );
        assert_eq!(
            DaemonError::reconnection_error("nfs-mount", "max retries").to_string(),
            "Reconnection failed for mount 'nfs-mount': max retries"
        );
    }

    #[test]
    fn test_error_conversions() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "test");
        let daemon_err = DaemonError::from(io_err);
        match daemon_err {
            DaemonError::Io(io_error) => {
                assert_eq!(io_error.kind(), std::io::ErrorKind::PermissionDenied);
                assert_eq!(io_error.to_string(), "test");
            }
            _ => panic!("Expected Io error"),
        }

        // Test creating a PermissionDenied error directly
        let permission_err = DaemonError::permission_denied("test operation");
        match permission_err {
            DaemonError::PermissionDenied {
                operation,
            } => {
                assert_eq!(operation, "test operation");
            }
            _ => panic!("Expected PermissionDenied error"),
        }
    }

    #[test]
    fn test_regex_error_conversion() {
        #[allow(clippy::invalid_regex)]
        let regex_err = regex::Regex::new("[").unwrap_err();
        let daemon_err = DaemonError::from(regex_err);
        match &daemon_err {
            DaemonError::RegexError {
                pattern,
                ..
            } => {
                assert_eq!(pattern, "unknown");
            }
            _ => panic!("Expected RegexError"),
        }
        assert_eq!(daemon_err.category(), "regex");
    }

    #[test]
    fn test_anyhow_error_conversion() {
        let anyhow_err = anyhow::anyhow!("something went wrong");
        let daemon_err = DaemonError::from(anyhow_err);
        match daemon_err {
            DaemonError::Generic {
                context,
                ..
            } => {
                assert_eq!(context, "Unexpected error");
            }
            _ => panic!("Expected Generic error"),
        }
    }

    #[test]
    fn test_generic_error_creation() {
        let source_err = anyhow::anyhow!("root cause");
        let daemon_err = DaemonError::generic("Failed to process request", source_err);

        assert!(daemon_err.to_string().contains("Failed to process request"));
        assert_eq!(daemon_err.category(), "generic");
        assert!(daemon_err.is_recoverable()); // Generic defaults to recoverable
    }

    #[test]
    fn test_error_factory_methods() {
        // Test that all factory methods create the correct variants
        let mount = DaemonError::mount_error("msg");
        assert!(matches!(mount, DaemonError::MountError { .. }));

        let config = DaemonError::config_error("msg");
        assert!(matches!(config, DaemonError::ConfigError { .. }));

        let network = DaemonError::network_error("msg");
        assert!(matches!(network, DaemonError::NetworkError { .. }));

        let not_found = DaemonError::mount_not_found("id");
        assert!(matches!(not_found, DaemonError::MountNotFound { .. }));

        let conflict = DaemonError::mount_conflict("msg");
        assert!(matches!(conflict, DaemonError::MountConflict { .. }));

        let socket = DaemonError::socket_error("msg");
        assert!(matches!(socket, DaemonError::SocketError { .. }));

        let platform = DaemonError::platform_error("msg");
        assert!(matches!(platform, DaemonError::PlatformError { .. }));

        let permission = DaemonError::permission_denied("op");
        assert!(matches!(permission, DaemonError::PermissionDenied { .. }));

        let resource = DaemonError::resource_not_found("res");
        assert!(matches!(resource, DaemonError::ResourceNotFound { .. }));

        let invalid_op = DaemonError::invalid_operation("op");
        assert!(matches!(invalid_op, DaemonError::InvalidOperation { .. }));

        let timeout = DaemonError::timeout("op");
        assert!(matches!(timeout, DaemonError::Timeout { .. }));

        let state = DaemonError::state_error("msg");
        assert!(matches!(state, DaemonError::StateError { .. }));

        let system = DaemonError::system_error("msg");
        assert!(matches!(system, DaemonError::SystemError { .. }));

        let signal = DaemonError::signal_error("msg");
        assert!(matches!(signal, DaemonError::SignalError { .. }));

        let pid = DaemonError::pid_file_error("msg");
        assert!(matches!(pid, DaemonError::PidFileError { .. }));

        let lock = DaemonError::lock_error("name");
        assert!(matches!(lock, DaemonError::LockError { .. }));

        let health = DaemonError::health_check_error("id", "reason");
        assert!(matches!(health, DaemonError::HealthCheckError { .. }));

        let reconnect = DaemonError::reconnection_error("id", "reason");
        assert!(matches!(reconnect, DaemonError::ReconnectionError { .. }));
    }

    #[test]
    fn test_daemon_result_type() {
        fn returns_ok() -> DaemonResult<i32> {
            Ok(42)
        }

        fn returns_err() -> DaemonResult<i32> {
            Err(DaemonError::mount_error("test"))
        }

        assert_eq!(returns_ok().unwrap(), 42);
        assert!(returns_err().is_err());
    }

    #[test]
    fn test_error_debug_format() {
        let err = DaemonError::mount_error("test error");
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("MountError"));
        assert!(debug_str.contains("test error"));
    }
}
