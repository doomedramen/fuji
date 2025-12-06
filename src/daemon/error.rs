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
    pub fn is_recoverable(&self) -> bool {
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
    pub fn category(&self) -> &'static str {
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
/// Conversion from regex::Error to DaemonError
impl From<regex::Error> for DaemonError {
    fn from(err: regex::Error) -> Self {
        Self::RegexError {
            pattern: "unknown".to_string(),
            source: err,
        }
    }
}

/// Conversion from anyhow::Error to DaemonError
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
    fn test_error_display() {
        let err = DaemonError::mount_not_found("test_mount");
        assert_eq!(err.to_string(), "Mount 'test_mount' not found");

        let err = DaemonError::permission_denied("mount operation");
        assert_eq!(err.to_string(), "Permission denied: mount operation");
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
}
