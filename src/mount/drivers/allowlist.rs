//! Mount commands allowlist system
//!
//! This module provides a comprehensive allowlist system for mount-related commands
//! to ensure only approved commands and options can be executed, preventing command
//! injection vulnerabilities.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, trace, warn};

/// Represents an allowed command with its permitted arguments and options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedCommand {
    /// Command name (e.g., "mount", "umount", "sshfs")
    pub name: String,
    /// Full path to the command (optional, for additional validation)
    pub path: Option<String>,
    /// Description of what the command does
    pub description: String,
    /// Allowed arguments and flags for this command
    pub allowed_args: Vec<String>,
    /// Allowed options with their expected patterns
    pub allowed_options: HashMap<String, Option<String>>, // key -> regex pattern or None
    /// Maximum number of arguments allowed
    pub max_args: usize,
    /// Whether this command requires root privileges
    pub requires_root: bool,
    /// Security context for this command
    pub security_context: SecurityContext,
}

/// Security context for command execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityContext {
    /// Local filesystem operations only
    LocalFileSystem,
    /// Network filesystem operations
    NetworkFileSystem,
    /// System mounting operations (requires elevated privileges)
    SystemMount,
    /// User-space filesystem operations (FUSE)
    UserFileSystem,
    /// Diagnostic commands (read-only)
    Diagnostic,
}

/// Allowlist configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistConfig {
    /// Whether to enforce strict allowlist mode
    pub strict_mode: bool,
    /// Additional custom allowed commands
    pub custom_commands: Vec<AllowedCommand>,
    /// Blocked command patterns
    pub blocked_patterns: Vec<String>,
    /// Maximum command execution timeout in seconds
    pub max_execution_time: u64,
    /// Whether to log all command executions
    pub log_executions: bool,
}

impl Default for AllowlistConfig {
    fn default() -> Self {
        Self {
            strict_mode: true,
            custom_commands: vec![],
            blocked_patterns: vec![
                "rm -rf".to_string(), // More specific dangerous command
                "dd if=".to_string(),
                "mkfs.".to_string(),
                "format ".to_string(),
                "fdisk ".to_string(),
                "parted ".to_string(),
                "/bin/sh".to_string(),
                "/bin/bash".to_string(),
                " && ".to_string(),
                " || ".to_string(),
                "; ".to_string(),
                " | ".to_string(),
                "`rm".to_string(),
                "$(rm".to_string(),
                " > /dev".to_string(),
                " >> /dev".to_string(),
            ],
            max_execution_time: 300, // 5 minutes
            log_executions: true,
        }
    }
}

/// Mount commands allowlist validator
#[derive(Debug, Clone)]
pub struct MountCommandsAllowlist {
    config: AllowlistConfig,
    commands: HashMap<String, AllowedCommand>,
}

impl MountCommandsAllowlist {
    /// Create a new allowlist with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(AllowlistConfig::default())
    }

    /// Create a new allowlist with custom configuration
    pub fn with_config(config: AllowlistConfig) -> Result<Self> {
        let mut allowlist = Self {
            config,
            commands: HashMap::new(),
        };

        // Initialize default allowed commands
        allowlist.initialize_default_commands()?;

        // Add custom commands
        for cmd in allowlist.config.custom_commands.clone() {
            allowlist.add_command(cmd)?;
        }

        Ok(allowlist)
    }

    /// Initialize the default set of allowed commands
    fn initialize_default_commands(&mut self) -> Result<()> {
        // Mount/Unmount commands
        self.add_command(AllowedCommand {
            name: "mount".to_string(),
            path: Some("/bin/mount".to_string()),
            description: "Mount filesystems".to_string(),
            allowed_args: vec![
                "-t".to_string(), // Filesystem type
                "-o".to_string(), // Options
                "-r".to_string(), // Read-only
                "-w".to_string(), // Read-write
                "-v".to_string(), // Verbose
                "--no-mtab".to_string(),
                "--fake".to_string(),
                "--fstab".to_string(),
                "--options-mode".to_string(),
                "--test-opts".to_string(),
            ],
            allowed_options: {
                let mut opts = HashMap::new();
                opts.insert("t".to_string(), Some(r"^[a-zA-Z0-9_-]+$".to_string()));
                opts.insert("o".to_string(), Some(r"^[a-zA-Z0-9_=,.-]+$".to_string()));
                opts.insert("fstab".to_string(), Some(r"^[a-zA-Z0-9/_.-]+$".to_string()));
                opts
            },
            max_args: 10,
            requires_root: true,
            security_context: SecurityContext::SystemMount,
        })?;

        self.add_command(AllowedCommand {
            name: "umount".to_string(),
            path: Some("/bin/umount".to_string()),
            description: "Unmount filesystems".to_string(),
            allowed_args: vec![
                "-r".to_string(), // Read-only
                "-l".to_string(), // Lazy unmount
                "-f".to_string(), // Force unmount
                "-v".to_string(), // Verbose
                "-n".to_string(), // Don't write to /etc/mtab
                "--no-mtab".to_string(),
                "--lazy".to_string(),
                "--force".to_string(),
                "--fake".to_string(),
            ],
            allowed_options: HashMap::new(),
            max_args: 5,
            requires_root: true,
            security_context: SecurityContext::SystemMount,
        })?;

        // NFS-specific commands
        self.add_command(AllowedCommand {
            name: "mount.nfs".to_string(),
            path: Some("/sbin/mount.nfs".to_string()),
            description: "Mount NFS filesystems".to_string(),
            allowed_args: vec![
                "-r".to_string(),
                "-w".to_string(),
                "-v".to_string(),
                "-o".to_string(),
                "-t".to_string(),
                "--no-mtab".to_string(),
                "-n".to_string(),
            ],
            allowed_options: {
                let mut opts = HashMap::new();
                opts.insert("o".to_string(), Some(r"^[a-zA-Z0-9_=,.-]+$".to_string()));
                opts.insert("t".to_string(), Some(r"^nfs[4]?$".to_string()));
                opts
            },
            max_args: 8,
            requires_root: true,
            security_context: SecurityContext::NetworkFileSystem,
        })?;

        self.add_command(AllowedCommand {
            name: "showmount".to_string(),
            path: Some("/usr/sbin/showmount".to_string()),
            description: "Show mount information for NFS server".to_string(),
            allowed_args: vec![
                "-a".to_string(), // Show all mounts
                "-d".to_string(), // Show only directories
                "-e".to_string(), // Show exports
                "-h".to_string(), // Show help
                "-v".to_string(), // Show version
                "--no-headers".to_string(),
                "--all".to_string(),
                "--exports".to_string(),
            ],
            allowed_options: HashMap::new(),
            max_args: 3,
            requires_root: false,
            security_context: SecurityContext::Diagnostic,
        })?;

        // SMB/CIFS commands
        self.add_command(AllowedCommand {
            name: "mount.cifs".to_string(),
            path: Some("/sbin/mount.cifs".to_string()),
            description: "Mount SMB/CIFS filesystems".to_string(),
            allowed_args: vec![
                "-o".to_string(),
                "-r".to_string(),
                "-w".to_string(),
                "-v".to_string(),
                "-n".to_string(),
                "--no-mtab".to_string(),
            ],
            allowed_options: {
                let mut opts = HashMap::new();
                opts.insert("o".to_string(), Some(r"^[a-zA-Z0-9_=,.-]+$".to_string()));
                opts
            },
            max_args: 8,
            requires_root: true,
            security_context: SecurityContext::NetworkFileSystem,
        })?;

        self.add_command(AllowedCommand {
            name: "smbclient".to_string(),
            path: Some("/usr/bin/smbclient".to_string()),
            description: "SMB client for browsing shares".to_string(),
            allowed_args: vec![
                "-L".to_string(), // List shares
                "-N".to_string(), // No password
                "-U".to_string(), // Username
                "-W".to_string(), // Workgroup
                "-g".to_string(), // grepable output
                "--list".to_string(),
                "--no-pass".to_string(),
                "--user".to_string(),
                "--workgroup".to_string(),
            ],
            allowed_options: {
                let mut opts = HashMap::new();
                opts.insert("L".to_string(), Some(r"^[a-zA-Z0-9.-]+$".to_string()));
                opts.insert("U".to_string(), Some(r"^[a-zA-Z0-9@._%-]+$".to_string()));
                opts.insert("W".to_string(), Some(r"^[a-zA-Z0-9._-]+$".to_string()));
                opts
            },
            max_args: 5,
            requires_root: false,
            security_context: SecurityContext::Diagnostic,
        })?;

        // SSHFS commands
        self.add_command(AllowedCommand {
            name: "sshfs".to_string(),
            path: Some("/usr/bin/sshfs".to_string()),
            description: "Mount SSH filesystems".to_string(),
            allowed_args: vec![
                "-o".to_string(), // Options
                "-p".to_string(), // Port
                "-d".to_string(), // Debug
                "-f".to_string(), // Foreground
                "-s".to_string(), // Disable multithreading
                "-h".to_string(), // Help
                "-V".to_string(), // Version
                "--debug".to_string(),
                "--foreground".to_string(),
                "--help".to_string(),
                "--version".to_string(),
                "--password_stdin".to_string(),
            ],
            allowed_options: {
                let mut opts = HashMap::new();
                opts.insert("o".to_string(), Some(r"^[a-zA-Z0-9_=,.-]+$".to_string()));
                opts.insert("p".to_string(), Some(r"^[0-9]+$".to_string()));
                opts
            },
            max_args: 15,
            requires_root: false,
            security_context: SecurityContext::UserFileSystem,
        })?;

        // FUSE commands
        self.add_command(AllowedCommand {
            name: "fusermount".to_string(),
            path: Some("/bin/fusermount".to_string()),
            description: "FUSE filesystem mount/umount utility".to_string(),
            allowed_args: vec![
                "-u".to_string(), // Unmount
                "-q".to_string(), // Quiet
                "-z".to_string(), // Lazy unmount
                "-v".to_string(), // Verbose
                "-h".to_string(), // Help
                "--unmount".to_string(),
                "--quiet".to_string(),
                "--lazy".to_string(),
                "--verbose".to_string(),
                "--help".to_string(),
            ],
            allowed_options: HashMap::new(),
            max_args: 5,
            requires_root: false,
            security_context: SecurityContext::UserFileSystem,
        })?;

        // System utility commands
        self.add_command(AllowedCommand {
            name: "which".to_string(),
            path: Some("/usr/bin/which".to_string()),
            description: "Locate a command in the PATH".to_string(),
            allowed_args: vec![
                "-a".to_string(), // Show all matches
                "--all".to_string(),
                "--read-alias".to_string(),
                "--skip-alias".to_string(),
                "--skip-dot".to_string(),
                "--skip-tilde".to_string(),
                "--show-dot".to_string(),
                "--show-tilde".to_string(),
                "--tty-only".to_string(),
                "--version".to_string(),
                "--help".to_string(),
            ],
            allowed_options: HashMap::new(),
            max_args: 5,
            requires_root: false,
            security_context: SecurityContext::Diagnostic,
        })?;

        // Directory management commands
        self.add_command(AllowedCommand {
            name: "mkdir".to_string(),
            path: Some("/bin/mkdir".to_string()),
            description: "Create directories".to_string(),
            allowed_args: vec![
                "-p".to_string(), // Create parent directories
                "-m".to_string(), // Set permissions
                "-v".to_string(), // Verbose
                "--parents".to_string(),
                "--mode".to_string(),
                "--verbose".to_string(),
                "--help".to_string(),
                "--version".to_string(),
            ],
            allowed_options: {
                let mut opts = HashMap::new();
                opts.insert("m".to_string(), Some(r"^0?[0-7]{3}$".to_string())); // Octal mode
                opts
            },
            max_args: 10,
            requires_root: false,
            security_context: SecurityContext::LocalFileSystem,
        })?;

        self.add_command(AllowedCommand {
            name: "rmdir".to_string(),
            path: Some("/bin/rmdir".to_string()),
            description: "Remove empty directories".to_string(),
            allowed_args: vec![
                "-p".to_string(), // Remove parent directories
                "-v".to_string(), // Verbose
                "--ignore-fail-on-non-empty".to_string(),
                "--parents".to_string(),
                "--verbose".to_string(),
                "--help".to_string(),
                "--version".to_string(),
            ],
            allowed_options: HashMap::new(),
            max_args: 10,
            requires_root: false,
            security_context: SecurityContext::LocalFileSystem,
        })?;

        Ok(())
    }

    /// Add a new command to the allowlist
    pub fn add_command(&mut self, command: AllowedCommand) -> Result<()> {
        let command_name = command.name.clone();

        if self.commands.contains_key(&command_name) {
            return Err(anyhow!(
                "Command '{}' already exists in allowlist",
                command_name
            ));
        }

        // Validate the command definition
        self.validate_command_definition(&command)?;

        self.commands.insert(command_name.clone(), command);
        debug!("Added command to allowlist: {}", command_name);
        Ok(())
    }

    /// Remove a command from the allowlist
    pub fn remove_command(&mut self, name: &str) -> Result<()> {
        if !self.commands.contains_key(name) {
            return Err(anyhow!("Command '{}' not found in allowlist", name));
        }

        self.commands.remove(name);
        debug!("Removed command from allowlist: {}", name);
        Ok(())
    }

    /// Validate a command and its arguments against the allowlist
    pub fn validate_command(&self, command: &str, args: &[String]) -> Result<()> {
        trace!("Validating command '{}' with args: {:?}", command, args);

        // Check for blocked patterns first
        if self.contains_blocked_patterns(command, args)? {
            return Err(anyhow!("Command contains blocked patterns"));
        }

        // Check if command is in allowlist
        let allowed_cmd = self
            .commands
            .get(command)
            .ok_or_else(|| anyhow::anyhow!("Command '{}' is not in the allowlist", command))?;

        // Validate argument count
        if args.len() > allowed_cmd.max_args {
            return Err(anyhow::anyhow!(
                "Too many arguments for command '{}' ({} > {})",
                command,
                args.len(),
                allowed_cmd.max_args
            ));
        }

        // Validate each argument, taking into account context (like -o followed by its value)
        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];

            // Handle options that take values (like -o option_value)
            if arg == "-o" && i + 1 < args.len() {
                // Validate the -o flag itself
                self.validate_argument(allowed_cmd, arg)?;

                // Validate the option value
                let option_value = &args[i + 1];
                self.validate_option_value(allowed_cmd, "o", option_value)?;
                i += 2;
            } else if arg == "-p" && i + 1 < args.len() {
                // Handle -p port option
                self.validate_argument(allowed_cmd, arg)?;
                let port_value = &args[i + 1];
                self.validate_option_value(allowed_cmd, "p", port_value)?;
                i += 2;
            } else {
                // Regular argument validation
                self.validate_argument(allowed_cmd, arg)?;
                i += 1;
            }
        }

        debug!("Command validation passed: {}", command);
        Ok(())
    }

    /// Validate an option value against the command's allowed options
    fn validate_option_value(
        &self,
        command: &AllowedCommand,
        option_name: &str,
        value: &str,
    ) -> Result<()> {
        if let Some(pattern) = command.allowed_options.get(option_name) {
            if let Some(regex_str) = pattern {
                let regex = regex::Regex::new(regex_str)
                    .with_context(|| format!("Invalid regex pattern: {}", regex_str))?;

                if !regex.is_match(value) {
                    return Err(anyhow::anyhow!(
                        "Option value '{}' doesn't match pattern '{}' for option '{}'",
                        value,
                        regex_str,
                        option_name
                    ));
                }
            }
        }
        Ok(())
    }

    /// Validate a command definition before adding it to the allowlist
    fn validate_command_definition(&self, command: &AllowedCommand) -> Result<()> {
        if command.name.is_empty() {
            return Err(anyhow!("Command name cannot be empty"));
        }

        if command.name.contains(' ') {
            return Err(anyhow!("Command name cannot contain spaces"));
        }

        // Validate that the name doesn't contain dangerous characters
        let dangerous_chars = [
            ';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']', '"', '\'', '<', '>', '*',
        ];
        for c in command.name.chars() {
            if dangerous_chars.contains(&c) {
                return Err(anyhow!("Command name contains dangerous character: {}", c));
            }
        }

        // Validate allowed args
        for arg in &command.allowed_args {
            if arg.is_empty() {
                return Err(anyhow!("Allowed argument cannot be empty"));
            }
        }

        Ok(())
    }

    /// Validate a single argument against the command's allowlist
    fn validate_argument(&self, command: &AllowedCommand, arg: &str) -> Result<()> {
        // Skip validation of source and target paths (these come after the options)
        if arg.starts_with('/') || (arg.contains(':') && !arg.starts_with('-')) {
            // This looks like a path (absolute or remote path like server:share)
            // Validate that it doesn't contain dangerous characters
            self.validate_path_argument(arg)?;
            return Ok(());
        }

        // Check if it's a flag or option
        if arg.starts_with('-') {
            let arg_key = if let Some(eq_pos) = arg.find('=') {
                &arg[..eq_pos]
            } else {
                arg
            };

            // Check if the argument is in the allowed list
            if !command.allowed_args.contains(&arg_key.to_string()) {
                // Allow --help and --version flags even if not explicitly listed
                if arg_key == "--help"
                    || arg_key == "--version"
                    || arg_key == "-h"
                    || arg_key == "-V"
                {
                    return Ok(());
                }

                if self.config.strict_mode {
                    return Err(anyhow::anyhow!(
                        "Argument '{}' not in allowlist for command '{}'",
                        arg_key,
                        command.name
                    ));
                } else {
                    warn!(
                        "Allowing potentially unsafe argument '{}' for command '{}'",
                        arg_key, command.name
                    );
                    return Ok(());
                }
            }

            // If it has a value, validate it against the regex pattern
            if let Some(eq_pos) = arg.find('=') {
                let arg_name = &arg[..eq_pos];
                let arg_value = &arg[eq_pos + 1..];

                if let Some(pattern) = command
                    .allowed_options
                    .get(arg_name.trim_start_matches('-'))
                {
                    if let Some(regex_str) = pattern {
                        let regex = regex::Regex::new(regex_str)
                            .with_context(|| format!("Invalid regex pattern: {}", regex_str))?;

                        if !regex.is_match(arg_value) {
                            return Err(anyhow::anyhow!(
                                "Argument value '{}' doesn't match pattern '{}' for option '{}'",
                                arg_value,
                                regex_str,
                                arg_name
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate a path argument for dangerous characters
    fn validate_path_argument(&self, path: &str) -> Result<()> {
        // Check for dangerous shell characters in paths
        let dangerous_chars = [
            ';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']', '"', '\'', '<', '>', '*',
        ];
        for c in path.chars() {
            if dangerous_chars.contains(&c) {
                return Err(anyhow!("Path contains dangerous character: {}", c));
            }
        }

        // Check for command injection patterns
        if path.contains("..") && path.contains('/') {
            return Err(anyhow!("Path traversal detected in: {}", path));
        }

        Ok(())
    }

    /// Check if command or arguments contain blocked patterns
    fn contains_blocked_patterns(&self, command: &str, args: &[String]) -> Result<bool> {
        let full_command = format!("{} {}", command, args.join(" "));
        trace!("Checking blocked patterns in command: {}", full_command);

        for pattern in &self.config.blocked_patterns {
            if full_command.contains(pattern) {
                warn!(
                    "Blocked pattern '{}' detected in command: {}",
                    pattern, full_command
                );
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Get all allowed commands
    pub fn get_allowed_commands(&self) -> Vec<String> {
        self.commands.keys().cloned().collect()
    }

    /// Get detailed information about a command
    pub fn get_command_info(&self, name: &str) -> Option<&AllowedCommand> {
        self.commands.get(name)
    }

    /// Check if a command requires root privileges
    pub fn command_requires_root(&self, command: &str) -> bool {
        self.commands
            .get(command)
            .map(|cmd| cmd.requires_root)
            .unwrap_or(true) // Assume root is required if command is unknown
    }

    /// Get the security context for a command
    pub fn get_command_security_context(&self, command: &str) -> Option<&SecurityContext> {
        self.commands.get(command).map(|cmd| &cmd.security_context)
    }

    /// Export the allowlist for inspection or backup
    pub fn export_allowlist(&self) -> serde_json::Value {
        serde_json::to_value(&self.commands).unwrap_or_else(|_| serde_json::Value::Null)
    }

    /// Import allowlist from external source (with validation)
    pub fn import_allowlist(&mut self, data: &str) -> Result<()> {
        let imported_commands: HashMap<String, AllowedCommand> =
            serde_json::from_str(data).with_context(|| "Failed to parse allowlist data")?;

        for (name, command) in imported_commands {
            self.validate_command_definition(&command)?;
            self.commands.insert(name, command);
        }

        debug!("Imported {} commands into allowlist", self.commands.len());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_allowlist() -> MountCommandsAllowlist {
        MountCommandsAllowlist::new().unwrap()
    }

    #[test]
    fn test_valid_mount_command() {
        let allowlist = create_test_allowlist();

        // Valid mount command
        assert!(allowlist
            .validate_command(
                "mount",
                &[
                    "-t".to_string(),
                    "nfs".to_string(),
                    "server:/export".to_string(),
                    "/mnt/nfs".to_string()
                ]
            )
            .is_ok());
    }

    #[test]
    fn test_valid_sshfs_command() {
        let allowlist = create_test_allowlist();

        // Valid sshfs command - typical format
        assert!(allowlist
            .validate_command(
                "sshfs",
                &[
                    "user@server:/path".to_string(),
                    "/mnt/sshfs".to_string(),
                    "-o".to_string(),
                    "allow_other".to_string()
                ]
            )
            .is_ok());

        // Also test compound option format
        assert!(allowlist
            .validate_command(
                "sshfs",
                &[
                    "user@server:/path".to_string(),
                    "/mnt/sshfs".to_string(),
                    "-o".to_string(),
                    "allow_other,reconnect".to_string()
                ]
            )
            .is_ok());
    }

    #[test]
    fn test_blocked_command() {
        let allowlist = create_test_allowlist();

        // Blocked command
        assert!(allowlist
            .validate_command("rm", &["-rf".to_string(), "/".to_string()])
            .is_err());
    }

    #[test]
    fn test_command_injection_attempt() {
        let allowlist = create_test_allowlist();

        // Command injection attempt
        assert!(allowlist
            .validate_command(
                "mount",
                &[
                    "-t".to_string(),
                    "nfs".to_string(),
                    "server:/export; rm -rf /".to_string(),
                    "/mnt/nfs".to_string()
                ]
            )
            .is_err());
    }

    #[test]
    fn test_too_many_arguments() {
        let allowlist = create_test_allowlist();

        // Too many arguments
        let many_args: Vec<String> = (0..20).map(|_| "arg".to_string()).collect();
        assert!(allowlist.validate_command("mount", &many_args).is_err());
    }

    #[test]
    fn test_invalid_option() {
        let allowlist = create_test_allowlist();

        // Invalid option
        assert!(allowlist
            .validate_command(
                "mount",
                &[
                    "--invalid-option".to_string(),
                    "server:/export".to_string(),
                    "/mnt/nfs".to_string()
                ]
            )
            .is_err());
    }

    #[test]
    fn test_custom_command_addition() {
        let mut allowlist = create_test_allowlist();

        let custom_cmd = AllowedCommand {
            name: "test-mount".to_string(),
            path: None,
            description: "Test mount command".to_string(),
            allowed_args: vec!["-o".to_string()],
            allowed_options: HashMap::new(),
            max_args: 5,
            requires_root: false,
            security_context: SecurityContext::LocalFileSystem,
        };

        assert!(allowlist.add_command(custom_cmd).is_ok());
        assert!(allowlist
            .validate_command("test-mount", &["-o".to_string(), "test".to_string()])
            .is_ok());
    }

    #[test]
    fn test_command_security_context() {
        let allowlist = create_test_allowlist();

        assert!(matches!(
            allowlist.get_command_security_context("mount"),
            Some(SecurityContext::SystemMount)
        ));

        assert!(matches!(
            allowlist.get_command_security_context("sshfs"),
            Some(SecurityContext::UserFileSystem)
        ));

        assert!(matches!(
            allowlist.get_command_security_context("showmount"),
            Some(SecurityContext::Diagnostic)
        ));
    }

    #[test]
    fn test_root_requirement() {
        let allowlist = create_test_allowlist();

        assert!(allowlist.command_requires_root("mount"));
        assert!(allowlist.command_requires_root("umount"));
        assert!(!allowlist.command_requires_root("which"));
        assert!(!allowlist.command_requires_root("sshfs"));
    }

    #[test]
    fn test_invalid_option_value() {
        let allowlist = create_test_allowlist();

        // Invalid port number for sshfs
        assert!(allowlist
            .validate_command(
                "sshfs",
                &[
                    "user@server:/path".to_string(),
                    "/mnt/sshfs".to_string(),
                    "-p".to_string(),
                    "invalid_port".to_string()
                ]
            )
            .is_err());

        // Valid port number
        assert!(allowlist
            .validate_command(
                "sshfs",
                &[
                    "user@server:/path".to_string(),
                    "/mnt/sshfs".to_string(),
                    "-p".to_string(),
                    "22".to_string()
                ]
            )
            .is_ok());
    }

    #[test]
    fn test_path_validation() {
        let allowlist = create_test_allowlist();

        // Valid paths
        assert!(allowlist
            .validate_command(
                "mount",
                &[
                    "-t".to_string(),
                    "nfs".to_string(),
                    "server:/export/path".to_string(),
                    "/mnt/nfs".to_string()
                ]
            )
            .is_ok());

        // Path with dangerous characters
        assert!(allowlist
            .validate_command(
                "mount",
                &[
                    "-t".to_string(),
                    "nfs".to_string(),
                    "server:/export;rm -rf /".to_string(),
                    "/mnt/nfs".to_string()
                ]
            )
            .is_err());

        // Path traversal
        assert!(allowlist
            .validate_command(
                "mount",
                &[
                    "-t".to_string(),
                    "nfs".to_string(),
                    "server:/export".to_string(),
                    "/mnt/../etc".to_string()
                ]
            )
            .is_err());
    }
}
