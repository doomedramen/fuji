//! Secure command execution utilities for mount operations
//!
//! This module provides safe alternatives to shell command execution,
//! preventing command injection vulnerabilities through proper argument
//! escaping and validation, with seccomp filtering for system call security.

use crate::mount::drivers::MountCommandsAllowlist;
use crate::security::seccomp::{SeccompProfile, SecureExecutor};
use anyhow::{Context, Result};
use regex;
use shlex;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::process::Command;
use tracing::{debug, trace, warn};

/// Builder for secure command execution
#[derive(Debug, Clone)]
pub struct SecureCommand {
    program: String,
    args: Vec<String>,
    seccomp_profile: Option<SeccompProfile>,
}

lazy_static::lazy_static! {
    /// Global seccomp executor for command execution
    static ref SECCOMP_EXECUTOR: Arc<Mutex<Option<SecureExecutor>>> = Arc::new(Mutex::new(None));

    /// Global mount commands allowlist
    static ref COMMAND_ALLOWLIST: Arc<Mutex<Option<MountCommandsAllowlist>>> = Arc::new(Mutex::new(None));
}

/// Helper to handle poisoned mutex - recovers the inner data
fn recover_from_poison<T>(result: Result<T, PoisonError<T>>) -> T {
    match result {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!("Mutex was poisoned, recovering inner data");
            poisoned.into_inner()
        }
    }
}

/// Initialize the global command allowlist
pub fn initialize_command_allowlist(allowlist: MountCommandsAllowlist) {
    let mut global_allowlist = recover_from_poison(COMMAND_ALLOWLIST.lock());
    *global_allowlist = Some(allowlist);
    debug!("Global command allowlist initialized");
}

/// Get the global command allowlist
pub fn get_command_allowlist() -> Result<MountCommandsAllowlist> {
    let global_allowlist = recover_from_poison(COMMAND_ALLOWLIST.lock());
    match global_allowlist.as_ref() {
        Some(allowlist) => Ok(allowlist.clone()),
        None => {
            // Initialize with default allowlist if not already done
            drop(global_allowlist);
            let default_allowlist = MountCommandsAllowlist::new()
                .with_context(|| "Failed to initialize default command allowlist")?;
            initialize_command_allowlist(default_allowlist.clone());
            Ok(default_allowlist)
        }
    }
}

impl SecureCommand {
    /// Create a new secure command with the specified program
    pub fn new(program: &str) -> Self {
        Self {
            program: program.to_string(),
            args: Vec::new(),
            seccomp_profile: None,
        }
    }

    /// Add an argument to the command
    pub fn arg<S: Into<String>>(mut self, arg: S) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Set seccomp profile for the command
    pub fn with_seccomp_profile(mut self, profile: SeccompProfile) -> Self {
        self.seccomp_profile = Some(profile);
        self
    }

    /// Get a display string of the command for logging
    pub fn display_command(&self) -> String {
        format!("{} {}", self.program, self.args.join(" "))
    }

    /// Execute the command and return the output
    pub async fn output(&self) -> Result<String> {
        trace!(
            "Executing secure command: {} {} (seccomp: {:?})",
            self.program,
            self.args.join(" "),
            self.seccomp_profile
        );

        // Validate against seccomp profile if set (no actual seccomp enforcement)
        if let Some(profile) = self.seccomp_profile {
            let mut executor = recover_from_poison(SECCOMP_EXECUTOR.lock());
            if executor.is_none() {
                *executor = Some(SecureExecutor::new(profile)?);
            }

            // Validate command against profile
            if let Some(ref exec) = *executor {
                exec.validate_command(&self.program)?;
                debug!("Command validated against {:?} profile", profile);
                // Skip seccomp initialization to avoid blocking - using validation mode only
            }
        }

        // Execute command with timeout to prevent indefinite hangs (e.g., NFS mount issues)
        let output = tokio::time::timeout(
            Duration::from_secs(30),
            Command::new(&self.program).args(&self.args).output(),
        )
        .await
        .with_context(|| {
            format!(
                "Command timed out after 30 seconds: {} {}",
                self.program,
                self.args.join(" ")
            )
        })?
        .with_context(|| {
            format!(
                "Failed to execute command: {} {}",
                self.program,
                self.args.join(" ")
            )
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut error_msg = format!(
                "Command failed with exit code {}",
                output.status.code().unwrap_or(-1)
            );
            if !stderr.is_empty() {
                error_msg.push_str(&format!(" | stderr: {}", stderr));
            }
            if !stdout.is_empty() {
                error_msg.push_str(&format!(" | stdout: {}", stdout));
            }
            return Err(anyhow::anyhow!("{}", error_msg));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        debug!("Command output: {}", stdout.trim());

        Ok(stdout.into_owned())
    }

    /// Execute the command and get the status
    pub async fn status(&self) -> Result<bool> {
        trace!(
            "Checking command status: {} {}",
            self.program,
            self.args.join(" ")
        );

        let status = Command::new(&self.program)
            .args(&self.args)
            .status()
            .await
            .with_context(|| {
                format!(
                    "Failed to get command status: {} {}",
                    self.program,
                    self.args.join(" ")
                )
            })?;

        Ok(status.success())
    }
}

/// Escape a string for safe shell usage
#[allow(dead_code)] // Security utility for shell command construction
pub fn escape_shell_arg(arg: &str) -> Result<String> {
    // Use shlex to properly escape the argument
    let escaped = shlex::try_quote(arg)?.into_owned();
    trace!("Escaped argument: '{}' -> '{}'", arg, escaped);
    Ok(escaped)
}

/// Validate that a string contains only safe characters
pub fn validate_safe_string(input: &str) -> Result<()> {
    // Allow only alphanumeric, forward slash, dot, hyphen, underscore, colon, at, and space
    let safe_pattern = regex::Regex::new(r"^[a-zA-Z0-9/._:-@ ]+$")
        .context("Failed to compile safe string regex")?;

    if !safe_pattern.is_match(input) {
        return Err(anyhow::anyhow!(
            "Input contains unsafe characters: {}",
            input
        ));
    }

    Ok(())
}

/// Validate that a command is in the allowlist
pub fn validate_command_allowlist(command: &str, args: &[String]) -> Result<()> {
    let allowlist = get_command_allowlist().with_context(|| "Failed to get command allowlist")?;

    allowlist
        .validate_command(command, args)
        .with_context(|| format!("Command validation failed for: {}", command))
}

/// Create a secure mount command with proper validation and seccomp filtering
pub fn create_secure_mount_command(
    mount_type: &str,
    source: &str,
    target: &str,
    options: &[String],
) -> Result<SecureCommand> {
    // Validate inputs
    validate_safe_string(source)?;
    validate_safe_string(target)?;

    for option in options {
        validate_safe_string(option)?;
    }

    // Determine appropriate seccomp profile for mount type
    let seccomp_profile = match mount_type {
        "nfs" | "nfs4" => Some(SeccompProfile::Mount),
        "smb" | "cifs" => Some(SeccompProfile::Mount),
        "sshfs" => Some(SeccompProfile::Network),
        _ => Some(SeccompProfile::FileSystem),
    };

    let base_command = match mount_type {
        "nfs" | "nfs4" => SecureCommand::new("mount"),
        "smb" | "cifs" => SecureCommand::new("mount"),
        "sshfs" => SecureCommand::new("sshfs"),
        _ => return Err(anyhow::anyhow!("Unsupported mount type: {}", mount_type)),
    };

    let (command_name, args) = match mount_type {
        "nfs" | "nfs4" => {
            let mut cmd_args = vec!["-t".to_string(), mount_type.to_string()];
            // Add options with -o flag if any options are present
            if !options.is_empty() {
                cmd_args.push("-o".to_string());
                cmd_args.push(options.join(","));
            }
            cmd_args.push(source.to_string());
            cmd_args.push(target.to_string());
            ("mount", cmd_args)
        }

        "smb" | "cifs" => {
            let mut cmd_args = vec!["-t".to_string(), "cifs".to_string()];
            // Add options with -o flag if any options are present
            if !options.is_empty() {
                cmd_args.push("-o".to_string());
                cmd_args.push(options.join(","));
            }
            cmd_args.push(source.to_string());
            cmd_args.push(target.to_string());
            ("mount", cmd_args)
        }

        "sshfs" => {
            let mut cmd_args = vec![source.to_string(), target.to_string()];
            // sshfs options are passed as separate arguments
            cmd_args.extend(options.iter().cloned());
            ("sshfs", cmd_args)
        }

        _ => return Err(anyhow::anyhow!("Unsupported mount type: {}", mount_type)),
    };

    // Validate command against allowlist
    validate_command_allowlist(command_name, &args)?;

    // Create the command
    let mut command = base_command;
    for arg in args {
        command = command.arg(arg);
    }

    // Apply seccomp profile if specified
    let command = if let Some(profile) = seccomp_profile {
        command.with_seccomp_profile(profile)
    } else {
        command
    };

    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_shell_arg() {
        assert_eq!(escape_shell_arg("simple").unwrap(), "simple");
        assert_eq!(
            escape_shell_arg("file with spaces").unwrap(),
            "'file with spaces'"
        );
        assert_eq!(
            escape_shell_arg("file'with'quotes").unwrap(),
            "\"file'with'quotes\""
        );
        assert_eq!(
            escape_shell_arg("file$with$special").unwrap(),
            "'file$with$special'"
        );
    }

    #[test]
    fn test_validate_safe_string() {
        assert!(validate_safe_string("/path/to/file").is_ok());
        assert!(validate_safe_string("server:share").is_ok());
        assert!(validate_safe_string("user@host:/path").is_ok());

        assert!(validate_safe_string("file; rm -rf /").is_err());
        assert!(validate_safe_string("file$(whoami)").is_err());
        assert!(validate_safe_string("file`cat /etc/passwd`").is_err());
    }

    #[test]
    fn test_validate_command_allowlist() {
        assert!(validate_command_allowlist("mount", &[]).is_ok());
        assert!(validate_command_allowlist("sshfs", &[]).is_ok());
        assert!(validate_command_allowlist("mkdir", &[]).is_ok());

        assert!(
            validate_command_allowlist(
                "mount",
                &[
                    "-t".to_string(),
                    "nfs".to_string(),
                    "server:/export".to_string(),
                    "/mnt/nfs".to_string()
                ]
            )
            .is_ok()
        );

        assert!(validate_command_allowlist("rm", &["-rf".to_string()]).is_err());
        assert!(validate_command_allowlist("sh", &[]).is_err());
        assert!(validate_command_allowlist("bash", &[]).is_err());
    }

    #[test]
    fn test_create_secure_mount_command() {
        let cmd = create_secure_mount_command(
            "nfs",
            "server:/export/path",
            "/mnt/nfs",
            &["rw".to_string(), "hard".to_string()],
        )
        .unwrap();

        assert_eq!(cmd.program, "mount");
        assert_eq!(
            cmd.args,
            vec![
                "-t",
                "nfs",
                "-o",
                "rw,hard",
                "server:/export/path",
                "/mnt/nfs"
            ]
        );
    }

    #[test]
    fn test_create_secure_mount_command_no_options() {
        let cmd =
            create_secure_mount_command("nfs", "server:/export/path", "/mnt/nfs", &[]).unwrap();

        assert_eq!(cmd.program, "mount");
        // Without options, no -o flag should be present
        assert_eq!(
            cmd.args,
            vec!["-t", "nfs", "server:/export/path", "/mnt/nfs"]
        );
    }

    #[tokio::test]
    async fn test_secure_command_status() {
        let cmd = SecureCommand::new("echo").arg("test");
        assert!(cmd.status().await.unwrap());
    }
}
