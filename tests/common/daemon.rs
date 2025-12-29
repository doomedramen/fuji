//! TestDaemon helper for managing daemon lifecycle in tests

#![allow(dead_code)]

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::process::{Child, Command};
use tokio::time::sleep;

/// Helper for managing Fuji daemon lifecycle in tests
///
/// Provides RAII-style daemon management with automatic cleanup.
/// Each instance runs in an isolated temporary directory.
pub struct TestDaemon {
    socket_path: PathBuf,
    pid_file: PathBuf,
    process: Option<Child>,
    temp_dir: TempDir,
    binary_path: PathBuf,
}

impl TestDaemon {
    /// Start a daemon with default settings
    ///
    /// Creates an isolated test environment with temporary directories
    pub async fn start() -> Result<Arc<Self>> {
        Self::start_with_options(None, false).await
    }

    /// Start a daemon with custom options
    ///
    /// # Arguments
    /// * `socket_path` - Custom socket path (default: temp dir + "/fuji.sock")
    /// * `no_automount` - Disable auto-mounting on startup
    pub async fn start_with_options(
        socket_path: Option<PathBuf>,
        no_automount: bool,
    ) -> Result<Arc<Self>> {
        // Create temporary directory for this test
        let temp_dir = TempDir::new().context("Failed to create temp directory")?;

        // Determine binary path
        let binary_path = std::env::current_dir()
            .context("Failed to get current directory")?
            .join("target")
            .join(if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            })
            .join("fuji");

        if !binary_path.exists() {
            anyhow::bail!(
                "Fuji binary not found at {:?}. Run 'cargo build' first.",
                binary_path
            );
        }

        // Set up paths
        let socket_path = socket_path.unwrap_or_else(|| temp_dir.path().join("fuji.sock"));
        let pid_file = socket_path.with_extension("pid");

        // Build daemon command
        let mut cmd = Command::new(&binary_path);
        cmd.arg("daemon")
            .arg("start")
            .env("FUJI_SOCKET_PATH", &socket_path)
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        if no_automount {
            cmd.arg("--no-automount");
        }

        // Start daemon process
        let process = cmd.spawn().context("Failed to spawn daemon process")?;

        let daemon = Self {
            socket_path,
            pid_file,
            process: Some(process),
            temp_dir,
            binary_path,
        };

        // Wait for daemon to be ready
        daemon.wait_ready(Duration::from_secs(20)).await?;

        Ok(Arc::new(daemon))
    }

    /// Check if daemon process is still running
    pub async fn is_running(&self) -> bool {
        // Check socket file exists
        if !self.socket_path.exists() {
            return false;
        }

        // Try to ping daemon
        self.ping().await.is_ok()
    }

    /// Ping the daemon to check if it's responsive
    async fn ping(&self) -> Result<()> {
        let output = Command::new(&self.binary_path)
            .args(["status", "--json"])
            .env("FUJI_SOCKET_PATH", &self.socket_path)
            .output()
            .await
            .context("Failed to ping daemon")?;

        if !output.status.success() {
            anyhow::bail!(
                "Daemon ping failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// Wait for daemon to become ready
    ///
    /// Polls the daemon socket until it's responsive or timeout is reached
    pub async fn wait_ready(&self, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(100);

        loop {
            // Check if socket file exists
            if self.socket_path.exists() {
                // Try to ping
                if self.ping().await.is_ok() {
                    eprintln!("✓ Daemon ready ({}ms)", start.elapsed().as_millis());
                    return Ok(());
                }
            }

            if start.elapsed() >= timeout {
                // Collect daemon logs for debugging
                if let Some(_process) = &self.process {
                    eprintln!("Daemon failed to start within {:?}", timeout);
                }
                anyhow::bail!("Daemon did not become ready within {:?}", timeout);
            }

            sleep(poll_interval).await;
        }
    }

    /// Send a request to the daemon via CLI
    ///
    /// This uses the CLI binary to communicate with the daemon,
    /// which is more reliable than direct socket communication in tests.
    pub async fn execute_command(&self, args: &[&str]) -> Result<std::process::Output> {
        let output = Command::new(&self.binary_path)
            .args(args)
            .env("FUJI_SOCKET_PATH", &self.socket_path)
            .output()
            .await
            .with_context(|| format!("Failed to execute command: {:?}", args))?;

        Ok(output)
    }

    /// Mount a share via the daemon
    pub async fn mount(&self, url: &str, options: Option<Vec<String>>) -> Result<String> {
        let mut args = vec!["mount".to_string(), url.to_string()];

        if let Some(opts) = options {
            for opt in opts {
                args.push("-o".to_string());
                args.push(opt);
            }
        }

        // Convert to &str for command
        let args_str: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = self.execute_command(&args_str).await?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to mount {}: {}",
                url,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Parse mount ID from output
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mount_id = stdout
            .lines()
            .find(|line| line.contains("mounted as"))
            .and_then(|line| line.split_whitespace().last())
            .ok_or_else(|| anyhow::anyhow!("Failed to parse mount ID from output"))?
            .to_string();

        Ok(mount_id)
    }

    /// Unmount a share
    pub async fn unmount(&self, mount_id: &str, force: bool) -> Result<()> {
        let mut args = vec!["unmount", mount_id];
        if force {
            args.push("--force");
        }

        let output = self.execute_command(&args).await?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to unmount {}: {}",
                mount_id,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// Get daemon status
    pub async fn status(&self, json: bool) -> Result<String> {
        let mut args = vec!["status"];
        if json {
            args.push("--json");
        }

        let output = self.execute_command(&args).await?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to get status: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Get socket path
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Get PID file path
    pub fn pid_file(&self) -> &Path {
        &self.pid_file
    }

    /// Get temporary directory path
    pub fn temp_dir(&self) -> &Path {
        self.temp_dir.path()
    }

    /// Get daemon process ID
    ///
    /// Returns the PID of the running daemon process
    pub async fn pid(&self) -> Result<u32> {
        // First try to get PID from the process handle
        if let Some(process) = &self.process {
            if let Some(pid) = process.id() {
                return Ok(pid);
            }
        }

        // Fall back to reading PID file
        if self.pid_file.exists() {
            let pid_str = tokio::fs::read_to_string(&self.pid_file)
                .await
                .context("Failed to read PID file")?;
            let pid = pid_str
                .trim()
                .parse::<u32>()
                .context("Failed to parse PID")?;
            return Ok(pid);
        }

        anyhow::bail!("Unable to determine daemon PID")
    }

    /// Stop the daemon gracefully
    pub async fn stop(&mut self) -> Result<()> {
        // Send stop command
        let output = self.execute_command(&["daemon", "stop"]).await?;

        if !output.status.success() {
            eprintln!(
                "Warning: daemon stop command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Wait for process to exit
        if let Some(mut process) = self.process.take() {
            match tokio::time::timeout(Duration::from_secs(5), process.wait()).await {
                Ok(Ok(status)) => {
                    eprintln!("✓ Daemon stopped (exit code: {})", status);
                }
                Ok(Err(e)) => {
                    eprintln!("Warning: Failed to wait for daemon: {}", e);
                }
                Err(_) => {
                    eprintln!("Warning: Daemon did not stop within timeout, killing...");
                    let _ = process.kill().await;
                }
            }
        }

        Ok(())
    }
}

impl Drop for TestDaemon {
    /// Cleanup: Stop daemon and remove socket/PID files
    ///
    /// Uses best-effort cleanup - errors are logged but don't panic
    fn drop(&mut self) {
        eprintln!("Cleaning up TestDaemon...");

        // Try to stop daemon gracefully
        if let Some(mut process) = self.process.take() {
            // Send SIGTERM on Unix
            #[cfg(unix)]
            {
                use nix::sys::signal::{Signal, kill};
                use nix::unistd::Pid;
                if let Some(pid) = process.id() {
                    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
                }
            }

            // Wait briefly for graceful shutdown
            std::thread::sleep(std::time::Duration::from_millis(500));

            // Force kill if still running
            let _ = process.start_kill();
        }

        // Remove socket file
        if self.socket_path.exists() {
            if let Err(e) = std::fs::remove_file(&self.socket_path) {
                eprintln!("Warning: Failed to remove socket file: {}", e);
            }
        }

        // Remove PID file
        if self.pid_file.exists() {
            if let Err(e) = std::fs::remove_file(&self.pid_file) {
                eprintln!("Warning: Failed to remove PID file: {}", e);
            }
        }

        eprintln!("✓ TestDaemon cleaned up");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires built binary
    async fn test_daemon_lifecycle() -> Result<()> {
        let daemon = TestDaemon::start().await?;

        // Check daemon is running
        assert!(daemon.is_running().await);

        // Check socket exists
        assert!(daemon.socket_path().exists());

        // Get status
        let status = daemon.status(false).await?;
        assert!(!status.is_empty());

        // Cleanup happens via Drop
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires built binary
    async fn test_daemon_restart() -> Result<()> {
        let mut daemon = Arc::try_unwrap(TestDaemon::start().await?)
            .map_err(|_| anyhow::anyhow!("Failed to unwrap Arc"))?;

        // Stop daemon
        daemon.stop().await?;

        // Socket should be removed
        assert!(!daemon.socket_path().exists());

        Ok(())
    }
}
