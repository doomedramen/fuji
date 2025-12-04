//! Secure command execution utilities for mount operations
//!
//! This module provides safe alternatives to shell command execution,
//! preventing command injection vulnerabilities through proper argument
//! escaping and validation.

use anyhow::{Context, Result};
use shlex;
use std::process::Command;
use tracing::{debug, trace};

/// Builder for secure command execution
#[derive(Debug, Clone)]
pub struct SecureCommand {
    program: String,
    args: Vec<String>,
}

impl SecureCommand {
    /// Create a new secure command with the specified program
    pub fn new(program: &str) -> Self {
        Self {
            program: program.to_string(),
            args: Vec::new(),
        }
    }

    /// Add an argument to the command
    pub fn arg<S: Into<String>>(mut self, arg: S) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Add multiple arguments to the command
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for arg in args {
            self.args.push(arg.into());
        }
        self
    }

    /// Execute the command and return the output
    pub async fn output(&self) -> Result<String> {
        trace!(
            "Executing secure command: {} {}",
            self.program,
            self.args.join(" ")
        );

        let output = Command::new(&self.program)
            .args(&self.args)
            .output()
            .with_context(|| {
                format!(
                    "Failed to execute command: {} {}",
                    self.program,
                    self.args.join(" ")
                )
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "Command failed with exit code {}: {}",
                output.status.code().unwrap_or(-1),
                stderr
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        debug!("Command output: {}", stdout.trim());

        Ok(stdout.into_owned())
    }

    /// Execute the command without capturing output
    pub async fn spawn(&self) -> Result<()> {
        trace!(
            "Spawning secure command: {} {}",
            self.program,
            self.args.join(" ")
        );

        let mut child = Command::new(&self.program)
            .args(&self.args)
            .spawn()
            .with_context(|| {
                format!(
                    "Failed to spawn command: {} {}",
                    self.program,
                    self.args.join(" ")
                )
            })?;

        let status = child
            .wait()
            .with_context(|| "Failed to wait for command completion")?;

        if !status.success() {
            return Err(anyhow::anyhow!(
                "Command failed with exit code: {}",
                status.code().unwrap_or(-1)
            ));
        }

        Ok(())
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
pub fn escape_shell_arg(arg: &str) -> Result<String> {
    // Use shlex to properly escape the argument
    let escaped = shlex::try_quote(arg)?.into_owned();
    trace!("Escaped argument: '{}' -> '{}'", arg, escaped);
    Ok(escaped)
}

/// Validate that a string contains only safe characters
pub fn validate_safe_string(input: &str) -> Result<()> {
    // Allow only alphanumeric, forward slash, dot, hyphen, underscore, colon, and at
    let safe_pattern = regex::Regex::new(r"^[a-zA-Z0-9/._:-@]+$")
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
pub fn validate_command_allowlist(command: &str) -> Result<()> {
    let allowed_commands = vec![
        "mount",
        "umount",
        "mount.nfs",
        "mount.cifs",
        "sshfs",
        "smbclient",
        "mkdir",
        "rmdir",
        "rm",
        "ln",
        "chmod",
        "chown",
    ];

    if !allowed_commands.contains(&command) {
        return Err(anyhow::anyhow!(
            "Command '{}' is not in the allowlist",
            command
        ));
    }

    Ok(())
}

/// Create a secure mount command with proper validation
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

    let command = match mount_type {
        "nfs" => SecureCommand::new("mount")
            .arg("-t")
            .arg("nfs")
            .arg(source)
            .arg(target)
            .args(options),

        "smb" | "cifs" => SecureCommand::new("mount")
            .arg("-t")
            .arg("cifs")
            .arg(source)
            .arg(target)
            .args(options),

        "sshfs" => SecureCommand::new("sshfs")
            .arg(source)
            .arg(target)
            .args(options),

        _ => return Err(anyhow::anyhow!("Unsupported mount type: {}", mount_type)),
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
        assert!(validate_command_allowlist("mount").is_ok());
        assert!(validate_command_allowlist("sshfs").is_ok());
        assert!(validate_command_allowlist("mkdir").is_ok());

        assert!(validate_command_allowlist("rm -rf").is_err());
        assert!(validate_command_allowlist("sh").is_err());
        assert!(validate_command_allowlist("bash").is_err());
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
            vec!["-t", "nfs", "server:/export/path", "/mnt/nfs", "rw", "hard"]
        );
    }

    #[tokio::test]
    async fn test_secure_command_status() {
        let cmd = SecureCommand::new("echo").arg("test");
        assert!(cmd.status().await.unwrap());
    }
}
