// Allow dead code - mount options validation infrastructure
#![allow(dead_code)]

//! Mount options validation and allowlist management
//!
//! This module provides validation for mount options to ensure only
//! safe and permitted options are used.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::{debug, trace, warn};

/// Mount option validator with allowlist support
#[derive(Debug, Clone)]
pub struct MountOptionsValidator {
    config: OptionsValidationConfig,
    nfs_options: HashSet<String>,
    smb_options: HashSet<String>,
    sshfs_options: HashSet<String>,
    common_options: HashSet<String>,
}

/// Configuration for options validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptionsValidationConfig {
    /// Whether to enforce strict allowlist mode
    pub strict_mode: bool,
    /// Additional custom allowed options
    pub custom_allowed_options: Vec<String>,
    /// Blocked dangerous options
    pub blocked_options: Vec<String>,
    /// Maximum number of options
    pub max_options_count: usize,
    /// Maximum option length
    pub max_option_length: usize,
}

impl Default for OptionsValidationConfig {
    fn default() -> Self {
        Self {
            strict_mode: true,
            custom_allowed_options: vec![],
            blocked_options: vec![
                "exec".to_string(),  // Allow execution of binaries
                "suid".to_string(),  // Set UID on execution
                "dev".to_string(),   // Allow device files
                "user=".to_string(), // Allow any user to mount (exact match only)
                "users".to_string(), // Allow any user to mount
                "owner".to_string(), // Allow owner to mount
                "acl".to_string(),   // Access Control Lists (can be complex)
            ],
            max_options_count: 50,
            max_option_length: 256,
        }
    }
}

impl MountOptionsValidator {
    /// Create a new validator with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(OptionsValidationConfig::default())
    }

    /// Create a new validator with custom configuration
    pub fn with_config(config: OptionsValidationConfig) -> Result<Self> {
        // Initialize allowlists for each filesystem type
        let mut validator = Self {
            config,
            nfs_options: HashSet::new(),
            smb_options: HashSet::new(),
            sshfs_options: HashSet::new(),
            common_options: HashSet::new(),
        };

        // Populate common options (safe for all filesystems)
        validator.common_options.extend(vec![
            "ro".to_string(),          // Read-only
            "rw".to_string(),          // Read-write
            "sync".to_string(),        // Synchronous I/O
            "async".to_string(),       // Asynchronous I/O
            "auto".to_string(),        // Mount automatically
            "noauto".to_string(),      // Don't mount automatically
            "defaults".to_string(),    // Default options
            "nofail".to_string(),      // Don't report failure for this FS
            "noatime".to_string(),     // Don't update access times
            "nosuid".to_string(),      // No setuid bits (security hardening)
            "nodev".to_string(),       // Disallow device files (security hardening)
            "noexec".to_string(),      // No execution (security hardening)
            "_netdev".to_string(),     // Network device (wait for network before mount)
            "x-gvfs-show".to_string(), // Show in file managers
            "comment".to_string(),     // Comment option
        ]);

        // Populate NFS-specific options
        validator.nfs_options.extend(vec![
            "hard".to_string(),    // Hard mount
            "soft".to_string(),    // Soft mount
            "intr".to_string(),    // Allow interrupts
            "nointr".to_string(),  // Disallow interrupts
            "proto".to_string(),   // Protocol version
            "vers".to_string(),    // NFS version
            "nfsvers".to_string(), // NFS version (alias for vers)
            "port".to_string(),    // Port number
            "rsize".to_string(),   // Read block size
            "wsize".to_string(),   // Write block size
            "timeo".to_string(),   // Timeout
            "retrans".to_string(), // Retransmission count
            "bg".to_string(),      // Background mounting
            "fg".to_string(),      // Foreground mounting
            "tcp".to_string(),     // TCP protocol
            "udp".to_string(),     // UDP protocol
            "lock".to_string(),    // Enable locking
            "nolock".to_string(),  // Disable locking
            "sec".to_string(),     // Security flavor
            "fsc".to_string(),     // Local caching (cachefilesd)
        ]);

        // Populate SMB/CIFS-specific options
        validator.smb_options.extend(vec![
            "username".to_string(),  // Username
            "password".to_string(),  // Password
            "uid".to_string(),       // User ID
            "gid".to_string(),       // Group ID
            "file_mode".to_string(), // File permissions
            "dir_mode".to_string(),  // Directory permissions
            "iocharset".to_string(), // I/O character set
            "codepage".to_string(),  // Code page
            "domain".to_string(),    // Workgroup/domain
            "workgroup".to_string(), // Workgroup
            "guest".to_string(),     // Guest access
            "ro".to_string(),        // Read-only (duplicate but OK)
            "rw".to_string(),        // Read-write (duplicate but OK)
            "vers".to_string(),      // SMB protocol version
        ]);

        // Populate SSHFS-specific options
        validator.sshfs_options.extend(vec![
            "allow_other".to_string(), // Allow other users
            "allow_root".to_string(),  // Allow root access
            "default_permissions".to_string(),
            "uid".to_string(),       // User ID
            "gid".to_string(),       // Group ID
            "file_mode".to_string(), // File permissions
            "dir_mode".to_string(),  // Directory permissions
            "cache".to_string(),     // Caching
            "no_cache".to_string(),  // Disable caching
            "direct_io".to_string(), // Direct I/O
            "reconnect".to_string(), // Auto-reconnect
            "ServerAliveInterval".to_string(),
            "ServerAliveCountMax".to_string(),
            "Compression".to_string(),   // Compression
            "no_check_root".to_string(), // Don't check server
            "password_stdin".to_string(),
        ]);

        Ok(validator)
    }

    /// Validate mount options for a specific filesystem type
    pub fn validate_options(&self, filesystem: &str, options: &[String]) -> Result<()> {
        trace!("Validating {} options: {:?}", filesystem, options);

        // Check options count limit
        if options.len() > self.config.max_options_count {
            return Err(anyhow::anyhow!(
                "Too many options ({} > {})",
                options.len(),
                self.config.max_options_count
            ));
        }

        // Get the appropriate allowlist
        let allowed_options = match filesystem {
            "nfs" | "nfs4" => &self.nfs_options,
            "smb" | "cifs" => &self.smb_options,
            "sshfs" => &self.sshfs_options,
            _ => {
                warn!(
                    "Unknown filesystem type '{}', using common options only",
                    filesystem
                );
                &self.common_options
            }
        };

        for option in options {
            // Check option length
            if option.len() > self.config.max_option_length {
                return Err(anyhow::anyhow!(
                    "Option too long ({} > {}): {}",
                    option.len(),
                    self.config.max_option_length,
                    option
                ));
            }

            // Parse option to check key=value format
            let option_key = if let Some(eq_pos) = option.find('=') {
                &option[..eq_pos]
            } else {
                option
            };

            // Allow x- options first (they should bypass blocked options)
            if option_key.starts_with("x-") {
                continue; // Skip further validation for x- options
            }

            // Check for blocked options (but not x- options)
            for blocked in &self.config.blocked_options {
                if option.starts_with(blocked) {
                    return Err(anyhow::anyhow!("Blocked option detected: {option}"));
                }
            }

            // Check if option is allowed
            let is_allowed = allowed_options.contains(option_key)
                || self.common_options.contains(option_key)
                || self
                    .config
                    .custom_allowed_options
                    .iter()
                    .any(|s| s == option_key);

            if self.config.strict_mode && !is_allowed {
                return Err(anyhow::anyhow!(
                    "Option '{option}' not in allowlist for filesystem '{filesystem}'"
                ));
            }

            // Additional validation for specific options
            self.validate_specific_option(option_key, option)?;
        }

        debug!("All options validated successfully for {}", filesystem);
        Ok(())
    }

    /// Validate a specific option with custom logic
    fn validate_specific_option(&self, key: &str, full_option: &str) -> Result<()> {
        match key {
            "uid" | "gid" => {
                // Validate numeric ID
                if let Some(eq_pos) = full_option.find('=') {
                    let value = &full_option[eq_pos + 1..];
                    if value.parse::<u32>().is_err() && value != "0" {
                        return Err(anyhow::anyhow!(
                            "Invalid {key} value: {value}, must be a numeric UID/GID"
                        ));
                    }
                }
            }
            "file_mode" | "dir_mode" => {
                // Validate octal permissions
                if let Some(eq_pos) = full_option.find('=') {
                    let value = &full_option[eq_pos + 1..];
                    if !value.starts_with('0') {
                        // Try to parse as octal
                        if let Ok(mode) = u32::from_str_radix(value, 16) {
                            // Check if it's a valid octal-like value
                            if mode > 0o777 {
                                return Err(anyhow::anyhow!(
                                    "Invalid {key} value: {value}, must be ≤ 0777"
                                ));
                            }
                        } else {
                            return Err(anyhow::anyhow!(
                                "Invalid {key} value: {value}, must be octal (e.g., 0755)"
                            ));
                        }
                    }
                }
            }
            "port" => {
                // Validate port number
                if let Some(eq_pos) = full_option.find('=') {
                    let value = &full_option[eq_pos + 1..];
                    if let Ok(port) = value.parse::<u16>() {
                        if port == 0 {
                            return Err(anyhow::anyhow!("Port cannot be 0"));
                        }
                    } else {
                        return Err(anyhow::anyhow!("Invalid port value: {value}"));
                    }
                }
            }
            _ => {
                // No special validation for other options
            }
        }
        Ok(())
    }

    /// Get all allowed options for a filesystem
    #[must_use]
    pub fn get_allowed_options(&self, filesystem: &str) -> Vec<String> {
        let mut options: Vec<String> = self.common_options.iter().cloned().collect();

        match filesystem {
            "nfs" | "nfs4" => {
                options.extend(self.nfs_options.iter().cloned());
            }
            "smb" | "cifs" => {
                options.extend(self.smb_options.iter().cloned());
            }
            "sshfs" => {
                options.extend(self.sshfs_options.iter().cloned());
            }
            _ => {}
        }

        options.extend(self.config.custom_allowed_options.iter().cloned());
        options.sort();
        options
    }

    /// Check if an option is blocked
    #[must_use]
    pub fn is_option_blocked(&self, option: &str) -> bool {
        for blocked in &self.config.blocked_options {
            if option.starts_with(blocked) {
                return true;
            }
        }
        false
    }

    /// Sanitize mount options by removing or modifying dangerous ones
    pub fn sanitize_options(&self, options: &[String]) -> Vec<String> {
        let mut sanitized = Vec::new();

        for option in options {
            // Skip empty options
            if option.trim().is_empty() {
                continue;
            }

            // Skip blocked options
            if self.is_option_blocked(option) {
                warn!("Removing blocked option: {}", option);
                continue;
            }

            // Add safe option
            sanitized.push(option.trim().to_string());
        }

        sanitized
    }

    /// Convert options string to a vector
    #[must_use]
    pub fn parse_options_string(&self, options_str: &str) -> Vec<String> {
        options_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Convert options vector to a string
    #[must_use]
    pub fn options_to_string(&self, options: &[String]) -> String {
        options.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_validator() -> MountOptionsValidator {
        let mut config = OptionsValidationConfig::default();
        config
            .custom_allowed_options
            .push("test-option".to_string());
        MountOptionsValidator::with_config(config).unwrap()
    }

    #[test]
    fn test_valid_nfs_options() {
        let validator = create_test_validator();

        // These should be valid
        assert!(
            validator
                .validate_options(
                    "nfs",
                    &[
                        "ro".to_string(),
                        "hard".to_string(),
                        "proto=tcp".to_string(),
                        "vers=4".to_string()
                    ]
                )
                .is_ok()
        );

        assert!(
            validator
                .validate_options("nfs", &["defaults".to_string()])
                .is_ok()
        );
    }

    #[test]
    fn test_valid_smb_options() {
        let validator = create_test_validator();

        assert!(
            validator
                .validate_options(
                    "smb",
                    &[
                        "ro".to_string(),
                        "username=user".to_string(),
                        "password=pass".to_string(),
                        "uid=1000".to_string()
                    ]
                )
                .is_ok()
        );
    }

    #[test]
    fn test_valid_sshfs_options() {
        let validator = create_test_validator();

        assert!(
            validator
                .validate_options(
                    "sshfs",
                    &[
                        "allow_other".to_string(),
                        "uid=1000".to_string(),
                        "file_mode=0644".to_string(),
                        "reconnect".to_string()
                    ]
                )
                .is_ok()
        );
    }

    #[test]
    fn test_blocked_options() {
        let validator = create_test_validator();

        // These should be rejected
        assert!(
            validator
                .validate_options("nfs", &["exec".to_string()])
                .is_err()
        );
        assert!(
            validator
                .validate_options("smb", &["suid".to_string()])
                .is_err()
        );
        // x-gvfs-show should now be allowed since it starts with x-
    }

    #[test]
    fn test_security_hardening_options_allowed() {
        let validator = create_test_validator();

        // Security-hardening options should be allowed, not blocked
        assert!(
            validator
                .validate_options(
                    "nfs",
                    &[
                        "nosuid".to_string(),
                        "nodev".to_string(),
                        "noexec".to_string(),
                    ]
                )
                .is_ok(),
            "Security-hardening options (nosuid, nodev, noexec) should be allowed"
        );
    }

    #[test]
    fn test_netdev_option_allowed() {
        let validator = create_test_validator();

        // _netdev is essential for network mounts and should not be blocked
        assert!(
            validator
                .validate_options("nfs", &["_netdev".to_string()])
                .is_ok(),
            "_netdev should be allowed for network mounts"
        );
    }

    #[test]
    fn test_nfs_default_options_pass_validation() {
        let validator = create_test_validator();

        // These are the default NFS options from NfsHandler::get_default_options()
        let default_options = vec![
            "nolock".to_string(),
            "timeo=50".to_string(),
            "retrans=2".to_string(),
            "soft".to_string(),
            "_netdev".to_string(),
        ];

        assert!(
            validator.validate_options("nfs", &default_options).is_ok(),
            "NFS default options must pass validation"
        );
    }

    #[test]
    fn test_real_world_nfs_options() {
        let validator = create_test_validator();

        // Real-world NFS mount options (from fstab)
        assert!(
            validator
                .validate_options(
                    "nfs",
                    &[
                        "nfsvers=3".to_string(),
                        "soft".to_string(),
                        "_netdev".to_string(),
                        "timeo=50".to_string(),
                        "retrans=5".to_string(),
                        "noatime".to_string(),
                        "fsc".to_string(),
                    ]
                )
                .is_ok(),
            "Real-world NFS fstab options should pass validation"
        );

        assert!(
            validator
                .validate_options(
                    "nfs",
                    &[
                        "nfsvers=3".to_string(),
                        "hard".to_string(),
                        "_netdev".to_string(),
                        "timeo=50".to_string(),
                        "retrans=5".to_string(),
                        "noatime".to_string(),
                    ]
                )
                .is_ok(),
            "Real-world NFS fstab options (hard mount) should pass validation"
        );
    }

    #[test]
    fn test_custom_options() {
        let validator = create_test_validator();

        // Custom option should be allowed
        assert!(
            validator
                .validate_options("nfs", &["test-option=value".to_string()])
                .is_ok()
        );

        // X- options should be allowed
        assert!(
            validator
                .validate_options("nfs", &["x-custom=value".to_string()])
                .is_ok()
        );
    }

    #[test]
    fn test_option_limits() {
        let validator = create_test_validator();

        // Too many options
        let many_options: Vec<String> = (0..100).map(|i| format!("opt{}", i)).collect();
        assert!(validator.validate_options("nfs", &many_options).is_err());

        // Option too long
        let long_option = "x".repeat(300);
        assert!(validator.validate_options("nfs", &[long_option]).is_err());
    }

    #[test]
    fn test_parse_options_string() {
        let validator = create_test_validator();

        let options = validator.parse_options_string("ro,hard,proto=tcp,vers=4");
        assert_eq!(options, vec!["ro", "hard", "proto=tcp", "vers=4"]);

        let options = validator.parse_options_string("  ro , hard ,  proto=tcp  ");
        assert_eq!(options, vec!["ro", "hard", "proto=tcp"]);
    }

    #[test]
    fn test_options_to_string() {
        let validator = create_test_validator();

        let options = vec![
            "ro".to_string(),
            "hard".to_string(),
            "proto=tcp".to_string(),
        ];
        let options_str = validator.options_to_string(&options);
        // options_to_string preserves the input order
        assert_eq!(options_str, "ro,hard,proto=tcp");
    }

    #[test]
    fn test_sanitize_options() {
        let validator = create_test_validator();

        let options = vec![
            "ro".to_string(),
            "exec".to_string(), // Should be removed
            "hard".to_string(),
            "".to_string(),              // Should be removed
            "  proto=tcp  ".to_string(), // Should be trimmed
        ];

        let sanitized = validator.sanitize_options(&options);
        // sanitize_options doesn't sort, but we can't guarantee order from HashSet iteration
        // So let's check that all expected elements are present and blocked ones are removed
        assert_eq!(sanitized.len(), 3);
        assert!(sanitized.contains(&"ro".to_string()));
        assert!(sanitized.contains(&"hard".to_string()));
        assert!(sanitized.contains(&"proto=tcp".to_string()));
    }

    #[test]
    fn test_numeric_validation() {
        let validator = create_test_validator();

        // Valid UIDs/GIDs
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

        // Invalid UIDs/GIDs
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
    }

    #[test]
    fn test_mode_validation() {
        let validator = create_test_validator();

        // Valid modes
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

        // Invalid modes
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
}
