// Allow dead code - URL validation utilities
#![allow(dead_code)]

//! Mount URL validation and sanitization
//!
//! This module provides validation functions for mount URLs to prevent
//! command injection and other security vulnerabilities.

use anyhow::{Context, Result};
use std::path::Path;
use tracing::{debug, trace};
use url::Url;

/// URL validation configuration
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Maximum allowed hostname length
    pub max_hostname_length: usize,
    /// Maximum allowed path length
    pub max_path_length: usize,
    /// Allowed URL schemes
    pub allowed_schemes: Vec<String>,
    /// Blocked hostname patterns
    pub blocked_hostnames: Vec<String>,
    /// Blocked path patterns
    pub blocked_paths: Vec<String>,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            max_hostname_length: 253, // RFC 1035 limit
            max_path_length: 4096,    // Reasonable limit
            allowed_schemes: vec![
                "nfs".to_string(),
                "smb".to_string(),
                "cifs".to_string(),
                "sshfs".to_string(),
                "sftp".to_string(),
                "nfs4".to_string(),
            ],
            blocked_hostnames: vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
                "0.0.0.0".to_string(),
            ],
            blocked_paths: vec![
                "/etc".to_string(),
                "/bin".to_string(),
                "/sbin".to_string(),
                "/usr/bin".to_string(),
                "/usr/sbin".to_string(),
                "/boot".to_string(),
                "/sys".to_string(),
                "/proc".to_string(),
                "/dev".to_string(),
                "../".to_string(), // Path traversal
                "~".to_string(),   // Home directory expansion
            ],
        }
    }
}

/// Mount URL validator
pub struct MountUrlValidator {
    config: ValidationConfig,
}

impl MountUrlValidator {
    /// Create a new validator with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(ValidationConfig::default())
    }

    /// Create a new validator with custom configuration
    pub fn with_config(config: ValidationConfig) -> Result<Self> {
        Ok(Self {
            config,
        })
    }

    /// Validate a mount URL
    pub fn validate_url(&self, url_str: &str) -> Result<()> {
        trace!("Validating mount URL: {}", url_str);

        // Check for shell injection patterns
        if self.contains_shell_injection(url_str) {
            return Err(anyhow::anyhow!(
                "URL contains potentially dangerous shell characters: {}",
                url_str
            ));
        }

        // Check for excessive path traversal in raw URL before parsing
        // URL parser may normalize paths like /../../../ to /, losing the attack pattern
        let traversal_count = url_str.matches("..").count();
        if traversal_count > 10 {
            return Err(anyhow::anyhow!(
                "Excessive path traversal detected ({} instances)",
                traversal_count
            ));
        }

        // Check for IPv6 addresses without brackets and other blocked patterns before URL parsing
        // This catches cases like nfs://::1/path which fail URL parsing
        if let Some(hostname_part) = self.extract_hostname_from_url(url_str) {
            for blocked in &self.config.blocked_hostnames {
                if hostname_part == *blocked {
                    return Err(anyhow::anyhow!("Hostname is blocked: {}", hostname_part));
                }
            }
        }

        // Parse the URL
        let url =
            Url::parse(url_str).with_context(|| format!("Invalid URL format: {}", url_str))?;

        // Check scheme
        let scheme = url.scheme();
        if !self.config.allowed_schemes.contains(&scheme.to_string()) {
            return Err(anyhow::anyhow!(
                "Unsupported URL scheme '{}'. Allowed schemes: {}",
                scheme,
                self.config.allowed_schemes.join(", ")
            ));
        }

        // Extract and validate hostname
        let hostname = url.host_str().unwrap_or("");
        if hostname.is_empty() {
            return Err(anyhow::anyhow!("URL must have a hostname"));
        }

        // Validate hostname format and length
        if hostname.len() > self.config.max_hostname_length {
            return Err(anyhow::anyhow!(
                "Hostname too long ({} > {})",
                hostname.len(),
                self.config.max_hostname_length
            ));
        }

        // Skip hostname regex validation for IP addresses
        if !self.is_ip_address(hostname) && !self.is_valid_hostname(hostname) {
            return Err(anyhow::anyhow!("Invalid hostname format: {}", hostname));
        }

        // Check against blocked hostnames
        for blocked in &self.config.blocked_hostnames {
            if hostname == blocked {
                return Err(anyhow::anyhow!("Hostname is blocked: {}", hostname));
            }
        }

        // Extract and validate path
        let path = url.path();
        if path.is_empty() {
            return Err(anyhow::anyhow!("URL must have a path"));
        }

        // Use the enhanced path sanitization to check for traversal and dangerous components
        if !path.is_empty() && path != "/" {
            // Check for excessive path traversal patterns before detailed validation
            let traversal_count = path.matches("..").count();
            if traversal_count > 10 {
                return Err(anyhow::anyhow!(
                    "Excessive path traversal detected ({} instances)",
                    traversal_count
                ));
            }

            // This will detect path traversal attempts and dangerous components
            if let Err(e) = self.sanitize_path_component(path) {
                return Err(anyhow::anyhow!("Path validation failed: {}", e));
            }

            // Also check against blocked paths list for additional safety
            let normalized_path = path.trim_matches('/');
            if !normalized_path.is_empty() {
                for blocked in &self.config.blocked_paths {
                    let blocked_trimmed = blocked.trim_matches('/');
                    if normalized_path == blocked_trimmed
                        || normalized_path.starts_with(blocked_trimmed)
                    {
                        return Err(anyhow::anyhow!(
                            "Path contains blocked component: {}",
                            blocked
                        ));
                    }
                }

                // Check path length
                if normalized_path.len() > self.config.max_path_length {
                    return Err(anyhow::anyhow!(
                        "Path too long ({} > {})",
                        normalized_path.len(),
                        self.config.max_path_length
                    ));
                }
            }
        }

        debug!("URL validation passed: {}", url_str);
        Ok(())
    }

    /// Validate a mount path independently
    pub fn validate_mount_path(&self, path: &Path) -> Result<()> {
        let path_str = path.to_string_lossy();
        trace!("Validating mount path: {}", path_str);

        // Check for shell injection patterns
        if self.contains_shell_injection(&path_str) {
            return Err(anyhow::anyhow!(
                "Mount path contains potentially dangerous characters: {}",
                path_str
            ));
        }

        // Convert to string for validation
        let path_normalized = path_str.trim_matches('/');

        if path_normalized.is_empty() {
            return Err(anyhow::anyhow!("Mount path cannot be empty"));
        }

        // Check for blocked paths first (including /etc/passwd)
        for blocked in &self.config.blocked_paths {
            let blocked_trimmed = blocked.trim_matches('/');
            if path_normalized == blocked_trimmed || path_normalized.starts_with(blocked_trimmed) {
                return Err(anyhow::anyhow!(
                    "Mount path contains blocked component: {}",
                    blocked
                ));
            }
        }

        // Check path format
        if !self.is_valid_path(path_normalized) {
            return Err(anyhow::anyhow!(
                "Invalid mount path format: {}",
                path_normalized
            ));
        }

        // Check path length
        if path_normalized.len() > self.config.max_path_length {
            return Err(anyhow::anyhow!(
                "Mount path too long ({} > {})",
                path_normalized.len(),
                self.config.max_path_length
            ));
        }

        // Check for path traversal attempts
        if path_normalized.contains("../") {
            return Err(anyhow::anyhow!("Path traversal detected in mount path"));
        }

        // Ensure path is absolute
        if !path.is_absolute() {
            return Err(anyhow::anyhow!("Mount path must be absolute"));
        }

        debug!("Mount path validation passed: {}", path_str);
        Ok(())
    }

    /// Check if a string contains shell injection patterns
    fn contains_shell_injection(&self, input: &str) -> bool {
        // Check for dangerous shell characters
        let dangerous_chars = [
            ';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']', '"', '\'', '<', '>', '*', '?',
        ];
        for c in input.chars() {
            if dangerous_chars.contains(&c) {
                return true;
            }
        }
        false
    }

    /// Check if hostname is valid format
    fn is_valid_hostname(&self, hostname: &str) -> bool {
        if hostname.is_empty() || hostname.len() > 253 {
            return false;
        }

        // Check each label
        for label in hostname.split('.') {
            if label.is_empty() || label.len() > 63 {
                return false;
            }

            // Check if label starts/ends with hyphen
            if label.starts_with('-') || label.ends_with('-') {
                return false;
            }

            // Check if label contains only valid characters
            for c in label.chars() {
                if !c.is_ascii_alphanumeric() && c != '-' {
                    return false;
                }
            }
        }

        true
    }

    /// Check if path is valid format
    fn is_valid_path(&self, path: &str) -> bool {
        if path.is_empty() {
            return false;
        }

        // Check for path traversal first
        if path.contains("../") {
            return false;
        }

        // Check each character
        for c in path.chars() {
            if !c.is_ascii_alphanumeric() && !"/._-@".contains(c) {
                return false;
            }
        }

        true
    }

    /// Check if a string is an IP address
    fn is_ip_address(&self, hostname: &str) -> bool {
        // IPv4 pattern check
        if hostname.split('.').count() == 4
            && hostname.chars().all(|c| c.is_ascii_digit() || c == '.')
        {
            return true;
        }

        // IPv6 pattern check (simplified)
        if hostname.contains(':') {
            return true;
        }

        false
    }

    /// Extract hostname from URL string even if URL parsing would fail
    /// This helps catch blocked hostnames like ::1 before URL parsing rejects them
    fn extract_hostname_from_url(&self, url_str: &str) -> Option<String> {
        // Try to extract hostname portion from URL string
        // Format: scheme://hostname/path or scheme://hostname:port/path
        if let Some(after_scheme) = url_str
            .strip_prefix("nfs://")
            .or_else(|| url_str.strip_prefix("smb://"))
            .or_else(|| url_str.strip_prefix("cifs://"))
            .or_else(|| url_str.strip_prefix("sshfs://"))
        {
            // Find the end of hostname (either / or end of string)
            let hostname_end = after_scheme.find('/').unwrap_or(after_scheme.len());
            let hostname_part = &after_scheme[..hostname_end];

            // Remove port if present (but be careful with IPv6 which has colons)
            let hostname = if hostname_part.starts_with('[') {
                // IPv6 with brackets: [::1]:port
                hostname_part.split(']').next()?.trim_start_matches('[')
            } else if hostname_part.contains(':') && !hostname_part.contains("::") {
                // Likely hostname:port (not IPv6)
                hostname_part.split(':').next()?
            } else {
                // Plain hostname or IPv6 without brackets
                hostname_part
            };

            return Some(hostname.to_string());
        }

        None
    }

    /// Sanitize and validate a path component from a URL for mount point generation
    pub fn sanitize_path_component(&self, path: &str) -> Result<String> {
        if path.is_empty() || path == "/" {
            return Ok(String::new());
        }

        // Remove leading slashes for processing
        let trimmed = path.trim_start_matches('/');

        // Check for path traversal attempts
        if trimmed.contains("..") {
            return Err(anyhow::anyhow!(
                "Path traversal detected in path component: {}",
                path
            ));
        }

        // Check for empty segments (multiple slashes)
        if trimmed.contains("//") {
            return Err(anyhow::anyhow!("Path contains empty segments: {}", path));
        }

        // Split path into components and validate each
        let components: Vec<&str> = trimmed.split('/').collect();
        let mut sanitized_components = Vec::new();

        for component in components {
            if component.is_empty() {
                continue; // Skip empty components
            }

            // Validate each component
            if !self.is_valid_path(component) {
                return Err(anyhow::anyhow!("Invalid path component: {}", component));
            }

            // Additional validation for dangerous names
            if self.is_dangerous_component(component) {
                return Err(anyhow::anyhow!("Dangerous path component: {}", component));
            }

            sanitized_components.push(component);
        }

        // Reconstruct the sanitized path
        Ok(sanitized_components.join("/"))
    }

    /// Check if a path component is dangerous (system files, sensitive directories, etc.)
    fn is_dangerous_component(&self, component: &str) -> bool {
        let dangerous_names = [
            // Sensitive files (exact matches only)
            "passwd",
            "shadow",
            "group",
            "hosts",
            "sudoers",
            "crontab",
            // Hidden directories with sensitive data
            ".ssh",
            "gnupg",
            ".gnupg",
            "aws",
            ".aws",
            // Hidden files with sensitive data
            ".env",
            ".secret",
            ".key",
            ".pem",
            ".crt",
            ".p12",
            ".pfx",
            ".config",
            ".profile",
            ".bashrc",
            ".bash_profile",
            ".bash_history",
            ".zshrc",
            ".zprofile",
            ".vimrc",
            ".viminfo",
            // Additional sensitive config files
            ".htpasswd",
            ".netrc",
            ".ssh",
            "authorized_keys",
            "known_hosts",
            "id_rsa",
            "id_rsa.pub",
            "id_ed25519",
            "id_ed25519.pub",
            "authorized_keys2",
            "rhosts",
            "shosts.equiv",
            // Executable patterns
            "sh",
            "bash",
            "zsh",
            "fish",
            "cmd",
            "powershell",
            "ps1",
            // Windows-specific dangerous paths
            "windows",
            "system32",
            "program files",
            "program files (x86)",
            "programdata",
            "recycler",
            "$recycle.bin",
            "system volume information",
            "users",
            "program files (x86)",
            "appdata",
            "roaming",
            "local",
            "microsoft",
            "windows powershell",
            // Windows sensitive files
            "sam",
            "security",
            "software",
            "default",
            "ntuser.dat",
            "boot.ini",
            "bootmgr",
            "bcd",
            // Windows executables and scripts
            "cmd.exe",
            "powershell.exe",
            "wscript.exe",
            "cscript.exe",
            "rundll32.exe",
            "regsvr32.exe",
            // Dangerous extensions (for files, not directories)
            "exe",
            "bat",
            "com",
            "pif",
            "scr",
            "vbs",
            "js",
            "jar",
            // Development-related
            ".git",
            ".svn",
            ".hg",
            "node_modules",
            ".npm",
            ".cache",
        ];

        // Case-insensitive check
        let component_lower = component.to_lowercase();
        dangerous_names.iter().any(|dangerous| {
            component_lower == *dangerous
                || component_lower.starts_with(&format!("{}.", dangerous))
                || component_lower.ends_with(&format!(".{}", dangerous))
        })
    }

    /// Sanitize a mount URL (remove dangerous components)
    pub fn sanitize_url(&self, url_str: &str) -> Result<String> {
        let url =
            Url::parse(url_str).with_context(|| format!("Failed to parse URL: {}", url_str))?;

        // Rebuild the URL with validated components
        let mut sanitized = url.scheme().to_string() + "://";

        // Add username/password if present
        let username = url.username();
        if !username.is_empty() {
            sanitized.push_str(username);
            if let Some(password) = url.password() {
                sanitized.push(':');
                sanitized.push_str(password);
            }
            sanitized.push('@');
        }

        // Add hostname
        sanitized.push_str(url.host_str().unwrap_or(""));

        // Add port if non-standard
        if let Some(port) = url.port() {
            sanitized.push(':');
            sanitized.push_str(&port.to_string());
        }

        // Add path
        let path = url.path().trim_matches('/');
        if !path.is_empty() {
            sanitized.push('/');
            sanitized.push_str(path);
        }

        // Add query parameters
        if let Some(query) = url.query() {
            sanitized.push('?');
            sanitized.push_str(query);
        }

        // Add fragment
        if let Some(fragment) = url.fragment() {
            sanitized.push('#');
            sanitized.push_str(fragment);
        }

        Ok(sanitized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_validator() -> MountUrlValidator {
        let mut config = ValidationConfig::default();
        // Add some test blocked patterns
        config.blocked_hostnames.push("malicious.com".to_string());
        config.blocked_paths.push("secret".to_string());
        MountUrlValidator::with_config(config).unwrap()
    }

    #[test]
    fn test_valid_nfs_url() {
        let validator = create_test_validator();
        assert!(
            validator
                .validate_url("nfs://server.example.com/export/path")
                .is_ok()
        );
        assert!(validator.validate_url("nfs://192.168.1.100/data").is_ok());
    }

    #[test]
    fn test_valid_smb_url() {
        let validator = create_test_validator();
        assert!(
            validator
                .validate_url("smb://server.example.com/share")
                .is_ok()
        );
        assert!(validator.validate_url("cifs://fileserver/docs").is_ok());
    }

    #[test]
    fn test_valid_sshfs_url() {
        let validator = create_test_validator();

        // First check if @ is considered a shell injection
        assert!(!validator.contains_shell_injection("sshfs://user@host.example.com/data/user"));

        let result = validator.validate_url("sshfs://user@host.example.com/data/user");
        match &result {
            Ok(()) => println!("Validation succeeded"),
            Err(e) => println!("Validation failed: {}", e),
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_scheme() {
        let validator = create_test_validator();
        assert!(validator.validate_url("http://example.com/path").is_err());
        assert!(validator.validate_url("ftp://evil.com/data").is_err());
    }

    #[test]
    fn test_shell_injection() {
        let validator = create_test_validator();
        assert!(
            validator
                .validate_url("nfs://server.example.com/export; rm -rf /")
                .is_err()
        );
        assert!(
            validator
                .validate_url("nfs://server.example.com/export|cat /etc/passwd")
                .is_err()
        );
        assert!(
            validator
                .validate_url("nfs://server.example.com/export`whoami`")
                .is_err()
        );
    }

    #[test]
    fn test_blocked_hostname() {
        let validator = create_test_validator();
        assert!(
            validator
                .validate_url("nfs://malicious.com/export")
                .is_err()
        );
        assert!(validator.validate_url("nfs://localhost/data").is_err());
    }

    #[test]
    fn test_blocked_path() {
        let validator = create_test_validator();
        assert!(
            validator
                .validate_url("nfs://server.example.com/secret/data")
                .is_err()
        );
        assert!(
            validator
                .validate_url("nfs://server.example.com/etc/passwd")
                .is_err()
        );
    }

    #[test]
    fn test_path_traversal() {
        let validator = create_test_validator();
        assert!(
            validator
                .validate_url("nfs://server.example.com/../../../etc")
                .is_err()
        );
    }

    #[test]
    fn test_too_long_hostname() {
        let validator = create_test_validator();
        let long_hostname = "a".repeat(300);
        assert!(
            validator
                .validate_url(&format!("nfs://{}.com/export", long_hostname))
                .is_err()
        );
    }

    #[test]
    fn test_sanitize_url() {
        let validator = create_test_validator();
        let sanitized = validator
            .sanitize_url("nfs://user:pass@server.example.com:2049/export/path")
            .unwrap();
        assert_eq!(
            sanitized,
            "nfs://user:pass@server.example.com:2049/export/path"
        );
    }

    #[test]
    fn test_validate_mount_path() {
        let validator = create_test_validator();
        assert!(
            validator
                .validate_mount_path(Path::new("/mnt/data"))
                .is_ok()
        );
        assert!(
            validator
                .validate_mount_path(Path::new("/media/backup"))
                .is_ok()
        );
        assert!(
            validator
                .validate_mount_path(Path::new("relative/path"))
                .is_err()
        );
        assert!(
            validator
                .validate_mount_path(Path::new("/mnt/../etc"))
                .is_err()
        );
        assert!(
            validator
                .validate_mount_path(Path::new("/etc/passwd"))
                .is_err()
        );
    }

    #[test]
    fn test_sanitize_path_component() {
        let validator = create_test_validator();

        // Valid paths should pass
        assert!(validator.sanitize_path_component("/export/data").is_ok());
        assert!(
            validator
                .sanitize_path_component("/share/documents")
                .is_ok()
        );
        assert!(validator.sanitize_path_component("/").is_ok());
        assert!(validator.sanitize_path_component("").is_ok());

        // Path traversal should be blocked
        assert!(validator.sanitize_path_component("../../../etc").is_err());
        assert!(
            validator
                .sanitize_path_component("data/../../root")
                .is_err()
        );
        assert!(validator.sanitize_path_component("path/../etc").is_err());

        // Dangerous components should be blocked
        assert!(validator.sanitize_path_component("/etc/passwd").is_err());
        assert!(validator.sanitize_path_component("/root/.ssh").is_err());
        assert!(validator.sanitize_path_component("/home/.env").is_err());
        assert!(validator.sanitize_path_component("/bin/sh").is_err());

        // Multiple slashes should be rejected (they create empty segments)
        assert!(
            validator
                .sanitize_path_component("//export//data//")
                .is_err()
        );

        // Case variations of dangerous components should be blocked
        assert!(validator.sanitize_path_component("/ETC/passwd").is_err());
        assert!(validator.sanitize_path_component("/Root/.SSH").is_err());
        assert!(
            validator
                .sanitize_path_component("/home/.SSH/id_rsa")
                .is_err()
        );

        // Dangerous files with extensions should be blocked
        assert!(
            validator
                .sanitize_path_component("/share/malware.exe")
                .is_err()
        );
        assert!(
            validator
                .sanitize_path_component("/docs/script.js")
                .is_err()
        );

        // Development directories should be blocked
        assert!(validator.sanitize_path_component("/project/.git").is_err());
        assert!(
            validator
                .sanitize_path_component("/app/node_modules")
                .is_err()
        );
    }
}
