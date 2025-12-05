# Security Error Handling Guidelines

This document provides comprehensive guidelines for standardized error handling across all security modules in the Fuji filesystem.

## Overview

All security modules should use the standardized `SecurityError` type from `src/security/error.rs` instead of generic error types. This ensures:

1. **Consistent error categorization** - Security errors are properly classified and can be tracked systematically
2. **Rich error context** - Each error includes relevant context for debugging and incident response
3. **Type safety** - Compile-time guarantees about error types
4. **Metrics integration** - Automatic error categorization for monitoring
5. **User-friendly messages** - Clear, actionable error messages for operators

## Error Type Hierarchy

### Core Security Error Categories

1. **Cryptographic Errors** (`CryptographicError`)
   - Failed encryption/decryption operations
   - Key derivation failures
   - Certificate validation issues

2. **Authentication Errors** (`AuthenticationFailed`)
   - Failed login attempts
   - Invalid credentials
   - Session expiration

3. **Authorization Errors** (`AccessDenied`)
   - Permission denied
   - Insufficient privileges
   - Role-based access control failures

4. **Credential Errors** (`CredentialError`)
   - Storage/retrieval failures
   - Invalid credential formats
   - Provider-specific errors

5. **Audit Errors** (`AuditError`)
   - Logging failures
   - Audit trail corruption
   - Compliance violations

6. **Intrusion Detection Errors** (`IntrusionDetectionError`)
   - Anomaly detection failures
   - Threat analysis errors
   - Response mechanism failures

## Standard Error Handling Patterns

### 1. Basic Error Return

```rust
use crate::security::{SecurityError, SecurityResult};

// ✅ Good - Use SecurityResult
fn validate_password(password: &str) -> SecurityResult<()> {
    if password.len() < 8 {
        return Err(SecurityError::ValidationError {
            field: "password".to_string(),
            reason: "Password must be at least 8 characters".to_string(),
            value: None,
        });
    }
    Ok(())
}

// ❌ Avoid - Use generic Result
fn validate_password_bad(password: &str) -> anyhow::Result<()> {
    if password.len() < 8 {
        return Err(anyhow!("Password must be at least 8 characters"));
    }
    Ok(())
}
```

### 2. Error Context with Extensions

```rust
use crate::security::{SecurityResult, SecurityResultExt};

// ✅ Good - Use extension traits for context
fn decrypt_file(path: &Path) -> SecurityResult<Vec<u8>> {
    std::fs::read(path)
        .with_security_context("Failed to read encrypted file")
        .with_crypto_context("file_read", "Unable to access file")
}

// ✅ Good - Use macros for common patterns
fn validate_api_key(key: &str) -> SecurityResult<()> {
    if key.len() != 32 {
        return Err(security_validation_error!(
            "api_key",
            "API key must be exactly 32 characters",
            key.len()
        ));
    }
    Ok(())
}
```

### 3. Error Conversion with Context

```rust
use crate::security::{SecurityResult, IntoSecurityError};

// ✅ Good - Convert external errors with context
fn load_config() -> SecurityResult<Config> {
    let toml_content = std::fs::read_to_string("config.toml")
        .with_security_context("Failed to load configuration file")?;

    toml::from_str::<Config>(&toml_content)
        .with_security_context("Failed to parse configuration")
}
```

### 4. Error Creation with Macros

```rust
use crate::security::SecurityError;

// ✅ Good - Use macros for common error types
fn authenticate_user(username: &str, password: &str) -> SecurityResult<()> {
    if password.is_empty() {
        return Err(security_auth_error!("Password cannot be empty", username));
    }

    // Authentication logic here
    Ok(())
}

// ✅ Good - Complex error creation
fn perform_encryption(data: &[u8], key: &[u8]) -> SecurityResult<Vec<u8>> {
    let cipher = match create_cipher(key) {
        Ok(c) => c,
        Err(e) => return Err(security_crypto_error!("cipher_creation", &e)),
    };

    cipher.encrypt(data)
        .map_err(|e| SecurityError::EncryptionError {
            algorithm: "AES-256-GCM".to_string(),
            reason: format!("Encryption failed: {}", e),
            source: Some(Box::new(e)),
        })
}
```

## Error Propagation Guidelines

### 1. Preserve Context

```rust
// ✅ Good - Preserve original context while adding new context
fn process_file(path: &Path) -> SecurityResult<ProcessedData> {
    let encrypted_data = read_encrypted_file(path)
        .map_err(|e| {
            if let SecurityError::FileSystemSecurityError { reason, .. } = &e {
                SecurityError::FileSystemSecurityError {
                    path: path.display().to_string(),
                    reason: format!("Failed to read encrypted file: {}", reason),
                    operation: "read_file".to_string(),
                }
            } else {
                e
            }
        })?;

    // Process data...
    Ok(processed_data)
}
```

### 2. Avoid Error Swallowing

```rust
// ❌ Bad - Swallows error context
fn risky_operation() -> SecurityResult<()> {
    match some_operation() {
        Ok(_) => Ok(()),
        Err(_) => {
            // Error context lost!
            Err(SecurityError::SystemSecurityError {
                component: "unknown".to_string(),
                reason: "Operation failed".to_string(),
                source: None,
            })
        }
    }
}

// ✅ Good - Preserve error information
fn risky_operation() -> SecurityResult<()> {
    some_operation().map_err(|e| SecurityError::SystemSecurityError {
        component: "risky_operation".to_string(),
        reason: format!("Operation failed: {}", e),
        source: Some(Box::new(e)),
    })
}
```

## Error Metrics and Monitoring

### 1. Error Metrics Collection

```rust
use crate::security::SecurityErrorMetrics;

// ✅ Good - Track security errors for monitoring
struct SecurityModule {
    error_metrics: Arc<Mutex<SecurityErrorMetrics>>,
}

impl SecurityModule {
    fn record_error(&self, error: &SecurityError) {
        let mut metrics = self.error_metrics.lock().unwrap();
        metrics.record_error(error);

        // Log for monitoring
        tracing::error!(
            error = ?error as &dyn std::error::Error,
            "Security error occurred"
        );
    }
}
```

### 2. Error Rate Monitoring

```rust
// ✅ Good - Monitor error rates for health checks
impl SecurityModule {
    fn get_error_rate(&self) -> f64 {
        let metrics = self.error_metrics.lock().unwrap();
        metrics.errors_per_hour
    }

    fn is_healthy(&self) -> bool {
        self.get_error_rate() < 10.0 // Maximum 10 errors per hour
    }
}
```

## Error Recovery Strategies

### 1. Retry Mechanisms

```rust
use tokio::time::{sleep, Duration};

// ✅ Good - Retry with exponential backoff
async fn robust_operation() -> SecurityResult<Data> {
    let mut attempts = 0;
    let max_attempts = 3;

    loop {
        match try_operation().await {
            Ok(data) => return Ok(data),
            Err(SecurityError::NetworkSecurityError { .. }) if attempts < max_attempts => {
                attempts += 1;
                let delay = Duration::from_secs(2_u64.pow(attempts));
                sleep(delay).await;
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}
```

### 2. Graceful Degradation

```rust
// ✅ Good - Fall back to less secure but functional options
async fn get_encrypted_data() -> SecurityResult<Data> {
    match read_hsm_encrypted_data().await {
        Ok(data) => Ok(data),
        Err(SecurityError::HsmError { .. }) => {
            tracing::warn!("HSM unavailable, falling back to software encryption");
            read_software_encrypted_data().await
        }
        Err(e) => Err(e),
    }
}
```

## Integration with Existing Error Types

### 1. Converting from anyhow

```rust
use anyhow::{Context, Result};
use crate::security::{SecurityError, SecurityResult};

fn convert_from_anyhow() -> SecurityResult<String> {
    std::fs::read_to_string("config.json")
        .context("Failed to read config")
        .map_err(|e| SecurityError::Generic {
            context: "Config file read error".to_string(),
            source: e,
        })
}
```

### 2. Converting from std::io::Error

```rust
use std::io;
use crate::security::SecurityError;

fn convert_from_io() -> SecurityResult<()> {
    std::fs::create_dir_all("/secure/storage")
        .map_err(|e| SecurityError::FileSystemSecurityError {
            path: "/secure/storage".to_string(),
            reason: format!("Directory creation failed: {}", e),
            operation: "create_directory".to_string(),
            source: Some(Box::new(e)),
        })
}
```

## Best Practices

### 1. DOs

- ✅ Use `SecurityResult<T>` for all security operations
- ✅ Provide specific error context (what, where, why)
- ✅ Use appropriate error variants from the hierarchy
- ✅ Include user IDs, file paths, and operation details
- ✅ Log security errors at appropriate levels
- ✅ Track error metrics for monitoring
- ✅ Implement proper error recovery mechanisms

### 2. DON'Ts

- ❌ Use generic `anyhow::Error` for security operations
- ❌ Create string-based errors without structure
- ❌ Swallow error context during propagation
- ❌ Return generic errors without security context
- ❌ Ignore error metrics and monitoring
   -  ❌ Use unwrap() or expect() in production security code

## Migration Guide

### Converting Existing Code

1. **Update function signatures**:
   ```rust
   // Before
   fn process_data() -> anyhow::Result<Vec<u8>>

   // After
   fn process_data() -> SecurityResult<Vec<u8>>
   ```

2. **Update error returns**:
   ```rust
   // Before
   Err(anyhow!("Invalid data format"))

   // After
   Err(SecurityError::ValidationError {
       field: "data_format".to_string(),
       reason: "Invalid data format".to_string(),
       value: None,
   })
   ```

3. **Update imports**:
   ```rust
   // Add to imports
   use crate::security::{SecurityResult, SecurityError};
   ```

4. **Update error handling**:
   ```rust
   // Before
   result.map_err(|e| anyhow!("Operation failed: {}", e))

   // After
   result.with_security_context("Operation failed")
   ```

## Testing Error Handling

### 1. Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_error() {
        let result = validate_password("short");
        assert!(result.is_err());

        match result.unwrap_err() {
            SecurityError::ValidationError { field, reason, .. } => {
                assert_eq!(field, "password");
                assert!(reason.contains("8 characters"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }
}
```

### 2. Error Injection Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_not_found_error() {
        let result = read_encrypted_file(Path::new("/nonexistent/file.enc")).await;
        assert!(result.is_err());

        // Verify error contains relevant context
        let error_str = format!("{}", result.unwrap_err());
        assert!(error_str.contains("/nonexistent/file.enc"));
    }
}
```

## Conclusion

Following these guidelines ensures consistent, informative, and maintainable error handling across all security modules. The standardized error types provide:

- **Better debugging** with rich error context
- **Improved monitoring** through automatic categorization
- **Enhanced security** with proper error tracking
- **Consistent user experience** with standardized error messages
- **Easier maintenance** with type-safe error handling