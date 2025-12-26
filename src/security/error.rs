// Allow dead code - error types and extensions for future security features
#![allow(dead_code)]

//! Comprehensive Security Error Types
//!
//! This module defines standardized error types for all security-related operations
//! using thiserror for better error handling, context preservation, and debugging.

use std::fmt;
use thiserror::Error;

/// Main security error type for all security operations
#[derive(Error, Debug)]
pub enum SecurityError {
    /// Cryptographic operation errors
    #[error("Cryptographic error: {operation} - {reason}")]
    CryptographicError {
        operation: String,
        reason: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Authentication and authorization errors
    #[error("Authentication failed: {details}")]
    AuthenticationFailed {
        details: String,
        user_id: Option<String>,
        attempt_count: u32,
    },

    /// Authorization errors (permission denied)
    #[error("Access denied: {operation} - {reason}")]
    AccessDenied {
        operation: String,
        reason: String,
        required_permission: Option<String>,
    },

    /// Credential management errors
    #[error("Credential error: {operation} - {reason}")]
    CredentialError {
        operation: String,
        reason: String,
        credential_type: String,
    },

    /// Encryption/decryption errors
    #[error("Encryption error: {algorithm} - {reason}")]
    EncryptionError {
        algorithm: String,
        reason: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Key management errors
    #[error("Key management error: {operation} - {reason}")]
    KeyManagementError {
        operation: String,
        reason: String,
        key_id: Option<String>,
    },

    /// Audit and logging errors
    #[error("Audit error: {operation} - {reason}")]
    AuditError {
        operation: String,
        reason: String,
        event_id: Option<String>,
    },

    /// Intrusion detection errors
    #[error("Intrusion detection error: {component} - {reason}")]
    IntrusionDetectionError {
        component: String,
        reason: String,
        threat_level: Option<String>,
    },

    /// System security errors
    #[error("System security error: {component} - {reason}")]
    System {
        component: String,
        reason: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Configuration security errors
    #[error("Security configuration error: {setting} - {reason}")]
    ConfigurationError {
        setting: String,
        reason: String,
        config_file: Option<String>,
    },

    /// Network security errors
    #[error("Network security error: {protocol} - {reason}")]
    Network {
        protocol: String,
        reason: String,
        remote_address: Option<String>,
    },

    /// File system security errors
    #[error("File system security error: {path} - {reason}")]
    FileSystem {
        path: String,
        reason: String,
        operation: String,
    },

    /// Validation errors for security inputs
    #[error("Security validation error: {field} - {reason}")]
    ValidationError {
        field: String,
        reason: String,
        value: Option<String>,
    },

    /// Resource limit errors
    #[error("Security resource limit exceeded: {resource} - {current}/{limit}")]
    ResourceLimitExceeded {
        resource: String,
        current: u64,
        limit: u64,
    },

    /// Timeout errors for security operations
    #[error("Security operation timeout: {operation} after {duration_ms}ms")]
    TimeoutError {
        operation: String,
        duration_ms: u64,
    },

    /// Hardware security module errors
    #[error("HSM error: {module} - {reason}")]
    HsmError {
        module: String,
        reason: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Secure update errors
    #[error("Secure update error: {stage} - {reason}")]
    SecureUpdateError {
        stage: String,
        reason: String,
        update_id: Option<String>,
    },

    /// Policy violation errors
    #[error("Security policy violation: {policy} - {reason}")]
    PolicyViolation {
        policy: String,
        reason: String,
        severity: PolicySeverity,
    },

    /// Generic security error with context
    #[error("{context}: {source}")]
    Generic {
        context: String,
        #[source]
        source: anyhow::Error,
    },
}

impl Clone for SecurityError {
    fn clone(&self) -> Self {
        match self {
            Self::CryptographicError {
                operation,
                reason,
                source: _,
            } => {
                Self::CryptographicError {
                    operation: operation.clone(),
                    reason: reason.clone(),
                    source: None, // Cannot clone Box<dyn Error>
                }
            }
            Self::AuthenticationFailed {
                details,
                user_id,
                attempt_count,
            } => Self::AuthenticationFailed {
                details: details.clone(),
                user_id: user_id.clone(),
                attempt_count: *attempt_count,
            },
            Self::AccessDenied {
                operation,
                reason,
                required_permission,
            } => Self::AccessDenied {
                operation: operation.clone(),
                reason: reason.clone(),
                required_permission: required_permission.clone(),
            },
            Self::CredentialError {
                operation,
                reason,
                credential_type,
            } => Self::CredentialError {
                operation: operation.clone(),
                reason: reason.clone(),
                credential_type: credential_type.clone(),
            },
            Self::EncryptionError {
                algorithm,
                reason,
                source: _,
            } => {
                Self::EncryptionError {
                    algorithm: algorithm.clone(),
                    reason: reason.clone(),
                    source: None, // Cannot clone Box<dyn Error>
                }
            }
            Self::KeyManagementError {
                operation,
                reason,
                key_id,
            } => Self::KeyManagementError {
                operation: operation.clone(),
                reason: reason.clone(),
                key_id: key_id.clone(),
            },
            Self::AuditError {
                operation,
                reason,
                event_id,
            } => Self::AuditError {
                operation: operation.clone(),
                reason: reason.clone(),
                event_id: event_id.clone(),
            },
            Self::IntrusionDetectionError {
                component,
                reason,
                threat_level,
            } => Self::IntrusionDetectionError {
                component: component.clone(),
                reason: reason.clone(),
                threat_level: threat_level.clone(),
            },
            Self::System {
                component,
                reason,
                source: _,
            } => {
                Self::System {
                    component: component.clone(),
                    reason: reason.clone(),
                    source: None, // Cannot clone Box<dyn Error>
                }
            }
            Self::ConfigurationError {
                setting,
                reason,
                config_file,
            } => Self::ConfigurationError {
                setting: setting.clone(),
                reason: reason.clone(),
                config_file: config_file.clone(),
            },
            Self::Network {
                protocol,
                reason,
                remote_address,
            } => Self::Network {
                protocol: protocol.clone(),
                reason: reason.clone(),
                remote_address: remote_address.clone(),
            },
            Self::FileSystem {
                path,
                reason,
                operation,
            } => Self::FileSystem {
                path: path.clone(),
                reason: reason.clone(),
                operation: operation.clone(),
            },
            Self::ValidationError {
                field,
                reason,
                value,
            } => Self::ValidationError {
                field: field.clone(),
                reason: reason.clone(),
                value: value.clone(),
            },
            Self::ResourceLimitExceeded {
                resource,
                current,
                limit,
            } => Self::ResourceLimitExceeded {
                resource: resource.clone(),
                current: *current,
                limit: *limit,
            },
            Self::TimeoutError {
                operation,
                duration_ms,
            } => Self::TimeoutError {
                operation: operation.clone(),
                duration_ms: *duration_ms,
            },
            Self::HsmError {
                module,
                reason,
                source: _,
            } => {
                Self::HsmError {
                    module: module.clone(),
                    reason: reason.clone(),
                    source: None, // Cannot clone Box<dyn Error>
                }
            }
            Self::SecureUpdateError {
                stage,
                reason,
                update_id,
            } => Self::SecureUpdateError {
                stage: stage.clone(),
                reason: reason.clone(),
                update_id: update_id.clone(),
            },
            Self::PolicyViolation {
                policy,
                reason,
                severity,
            } => Self::PolicyViolation {
                policy: policy.clone(),
                reason: reason.clone(),
                severity: *severity,
            },
            Self::Generic {
                context,
                source,
            } => {
                Self::Generic {
                    context: context.clone(),
                    source: anyhow::anyhow!(source.to_string()), // Create new anyhow::Error from string
                }
            }
        }
    }
}

/// Severity levels for policy violations
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicySeverity {
    /// Informational - policy noted but not violated
    Info,
    /// Warning - minor policy deviation
    Warning,
    /// Low - minor security issue
    Low,
    /// Medium - significant security issue
    Medium,
    /// High - serious security violation
    High,
    /// Critical - severe security threat
    Critical,
}

impl fmt::Display for PolicySeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARNING"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Result type alias for security operations
pub type SecurityResult<T> = Result<T, SecurityError>;

/// Extension trait for converting common error types to `SecurityError`
pub trait IntoSecurityError<T> {
    /// Convert the result into a `SecurityResult` with context
    fn with_security_context(self, context: &str) -> SecurityResult<T>;

    /// Convert the result with operation context
    fn with_operation(self, operation: &str) -> SecurityResult<T>;
}

impl<T, E> IntoSecurityError<T> for Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn with_security_context(self, context: &str) -> SecurityResult<T> {
        self.map_err(|e| SecurityError::Generic {
            context: context.to_string(),
            source: anyhow::Error::from(e),
        })
    }

    fn with_operation(self, operation: &str) -> SecurityResult<T> {
        self.map_err(|e| SecurityError::Generic {
            context: format!("Operation failed: {operation}"),
            source: anyhow::Error::from(e),
        })
    }
}

/// Extension trait for Result with security-specific error mapping
pub trait SecurityResultExt<T> {
    /// Add credential context to the error
    fn with_credential_context(self, operation: &str, credential_type: &str) -> SecurityResult<T>;

    /// Add cryptographic context to the error
    fn with_crypto_context(self, operation: &str, reason: &str) -> SecurityResult<T>;

    /// Add authentication context to the error
    fn with_auth_context(self, details: &str, user_id: Option<&str>) -> SecurityResult<T>;

    /// Add audit context to the error
    fn with_audit_context(self, operation: &str, reason: &str) -> SecurityResult<T>;
}

impl<T> SecurityResultExt<T> for SecurityResult<T> {
    fn with_credential_context(self, operation: &str, credential_type: &str) -> Self {
        self.map_err(|e| match e {
            SecurityError::Generic {
                context,
                source: _,
            } => SecurityError::CredentialError {
                operation: operation.to_string(),
                reason: context,
                credential_type: credential_type.to_string(),
            },
            other => other,
        })
    }

    fn with_crypto_context(self, operation: &str, reason: &str) -> Self {
        self.map_err(|e| match e {
            SecurityError::Generic {
                context: _context,
                source,
            } => SecurityError::CryptographicError {
                operation: operation.to_string(),
                reason: reason.to_string(),
                source: Some(source.into()),
            },
            other => other,
        })
    }

    fn with_auth_context(self, details: &str, user_id: Option<&str>) -> Self {
        self.map_err(|e| match e {
            SecurityError::Generic {
                context: _context,
                ..
            } => SecurityError::AuthenticationFailed {
                details: details.to_string(),
                user_id: user_id.map(std::string::ToString::to_string),
                attempt_count: 1,
            },
            other => other,
        })
    }

    fn with_audit_context(self, operation: &str, reason: &str) -> Self {
        self.map_err(|e| match e {
            SecurityError::Generic {
                context: _context,
                ..
            } => SecurityError::AuditError {
                operation: operation.to_string(),
                reason: reason.to_string(),
                event_id: None,
            },
            other => other,
        })
    }
}

/// Helper macros for creating security errors with reduced boilerplate
#[macro_export]
macro_rules! security_credential_error {
    ($operation:expr, $reason:expr, $type:expr) => {
        $crate::security::SecurityError::CredentialError {
            operation: $operation.to_string(),
            reason: $reason.to_string(),
            credential_type: $type.to_string(),
        }
    };
}

#[macro_export]
macro_rules! security_crypto_error {
    ($operation:expr, $reason:expr) => {
        $crate::security::SecurityError::CryptographicError {
            operation: $operation.to_string(),
            reason: $reason.to_string(),
            source: None,
        }
    };
    ($operation:expr, $source:expr) => {
        $crate::security::SecurityError::CryptographicError {
            operation: $operation.to_string(),
            reason: $source.to_string(),
            source: None,
        }
    };
}

#[macro_export]
macro_rules! security_auth_error {
    ($details:expr) => {
        $crate::security::SecurityError::AuthenticationFailed {
            details: $details.to_string(),
            user_id: None,
            attempt_count: 1,
        }
    };
    ($details:expr, $user_id:expr) => {
        $crate::security::SecurityError::AuthenticationFailed {
            details: $details.to_string(),
            user_id: Some($user_id.to_string()),
            attempt_count: 1,
        }
    };
    ($details:expr, $user_id:expr, $attempts:expr) => {
        $crate::security::SecurityError::AuthenticationFailed {
            details: $details.to_string(),
            user_id: Some($user_id.to_string()),
            attempt_count: $attempts,
        }
    };
}

#[macro_export]
macro_rules! security_validation_error {
    ($field:expr, $reason:expr) => {
        $crate::security::SecurityError::ValidationError {
            field: $field.to_string(),
            reason: $reason.to_string(),
            value: None,
        }
    };
    ($field:expr, $reason:expr, $value:expr) => {
        $crate::security::SecurityError::ValidationError {
            field: $field.to_string(),
            reason: $reason.to_string(),
            value: Some($value.to_string()),
        }
    };
}

/// Security error metrics for monitoring
#[derive(Debug, Clone)]
pub struct SecurityErrorMetrics {
    /// Total number of security errors
    pub total_errors: u64,
    /// Errors by category
    pub errors_by_category: std::collections::HashMap<String, u64>,
    /// Errors by severity
    pub errors_by_severity: std::collections::HashMap<PolicySeverity, u64>,
    /// Most recent errors
    pub recent_errors: Vec<SecurityError>,
    /// Error rate per hour
    pub errors_per_hour: f64,
}

impl SecurityErrorMetrics {
    /// Create new error metrics
    #[must_use]
    pub fn new() -> Self {
        Self {
            total_errors: 0,
            errors_by_category: std::collections::HashMap::new(),
            errors_by_severity: std::collections::HashMap::new(),
            recent_errors: Vec::new(),
            errors_per_hour: 0.0,
        }
    }

    /// Record a security error
    pub fn record_error(&mut self, error: &SecurityError) {
        self.total_errors += 1;

        // Update category counts
        let category = self.error_category(error);
        *self.errors_by_category.entry(category).or_insert(0) += 1;

        // Track recent errors (keep last 100)
        self.recent_errors.push(error.clone());
        if self.recent_errors.len() > 100 {
            self.recent_errors.remove(0);
        }
    }

    /// Get the category of an error
    fn error_category(&self, error: &SecurityError) -> String {
        match error {
            SecurityError::CryptographicError {
                ..
            } => "cryptographic".to_string(),
            SecurityError::AuthenticationFailed {
                ..
            } => "authentication".to_string(),
            SecurityError::AccessDenied {
                ..
            } => "authorization".to_string(),
            SecurityError::CredentialError {
                ..
            } => "credential".to_string(),
            SecurityError::EncryptionError {
                ..
            } => "encryption".to_string(),
            SecurityError::KeyManagementError {
                ..
            } => "key_management".to_string(),
            SecurityError::AuditError {
                ..
            } => "audit".to_string(),
            SecurityError::IntrusionDetectionError {
                ..
            } => "intrusion_detection".to_string(),
            SecurityError::System {
                ..
            } => "system_security".to_string(),
            SecurityError::ConfigurationError {
                ..
            } => "configuration".to_string(),
            SecurityError::Network {
                ..
            } => "network_security".to_string(),
            SecurityError::FileSystem {
                ..
            } => "file_system_security".to_string(),
            SecurityError::ValidationError {
                ..
            } => "validation".to_string(),
            SecurityError::ResourceLimitExceeded {
                ..
            } => "resource_limit".to_string(),
            SecurityError::TimeoutError {
                ..
            } => "timeout".to_string(),
            SecurityError::HsmError {
                ..
            } => "hsm".to_string(),
            SecurityError::SecureUpdateError {
                ..
            } => "secure_update".to_string(),
            SecurityError::PolicyViolation {
                ..
            } => "policy_violation".to_string(),
            SecurityError::Generic {
                ..
            } => "generic".to_string(),
        }
    }
}

impl Default for SecurityErrorMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Conversions from common error types to `SecurityError`
impl From<std::io::Error> for SecurityError {
    fn from(err: std::io::Error) -> Self {
        Self::System {
            component: "filesystem".to_string(),
            reason: format!("I/O error: {err}"),
            source: Some(Box::new(err)),
        }
    }
}

impl From<serde_json::Error> for SecurityError {
    fn from(err: serde_json::Error) -> Self {
        Self::ValidationError {
            field: "serialization".to_string(),
            reason: format!("JSON serialization error: {err}"),
            value: None,
        }
    }
}

impl From<toml::de::Error> for SecurityError {
    fn from(err: toml::de::Error) -> Self {
        Self::ConfigurationError {
            setting: "config_parsing".to_string(),
            reason: format!("TOML parsing error: {err}"),
            config_file: None,
        }
    }
}
