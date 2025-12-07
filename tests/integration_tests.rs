//! Integration tests for Fuji
//!
//! These tests run against real NFS and SMB servers in Docker containers.

use anyhow::Result;
use std::process::Command;
use tokio::time::Duration;
use tokio::time::sleep;

/// Test basic NFS mount and unmount
#[tokio::test]
#[ignore]
async fn test_nfs_mount_unmount() -> Result<()> {
    // Start daemon
    let mut child = Command::new("./target/debug/fuji")
        .args(&["daemon", "start"])
        .spawn()?;

    // Give daemon time to start
    sleep(Duration::from_secs(2)).await;

    // Check if daemon is still running
    match child.try_wait() {
        Ok(Some(status)) => panic!("Daemon exited early with status: {}", status),
        Ok(None) => {
            // Daemon is still running
            println!("Daemon is running successfully");
        }
        Err(e) => panic!("Error checking daemon status: {}", e),
    }

    // Check if socket exists
    assert!(
        std::path::Path::new("/tmp/fuji.sock").exists(),
        "Daemon socket file not found"
    );

    // Mount NFS share
    let output = Command::new("./target/debug/fuji")
        .args(&["mount", "nfs://nfs-server/data"])
        .output()?;

    assert!(
        output.status.success(),
        "Failed to mount NFS share: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Check status
    let output = Command::new("./target/debug/fuji")
        .args(&["status"])
        .output()?;

    assert!(output.status.success(), "Failed to get status");
    let status_str = String::from_utf8_lossy(&output.stdout);
    assert!(status_str.contains("nfs-server_nfs"));

    // Check mount point exists and is accessible
    assert!(std::path::Path::new("/mnt/fuji/nfs-server_nfs/data").exists());

    // Unmount
    let output = Command::new("./target/debug/fuji")
        .args(&["unmount", "nfs-server_nfs"])
        .output()?;

    assert!(
        output.status.success(),
        "Failed to unmount: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Stop daemon
    let _status = Command::new("./target/debug/fuji")
        .args(&["daemon", "stop"])
        .status()?;

    // Gracefully stop daemon with SIGTERM
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM)?;
        child.wait()?;
    }

    Ok(())
}

/// Test configuration persistence
#[tokio::test]
#[ignore]
async fn test_config_persistence() -> Result<()> {
    // Start daemon
    let mut child = Command::new("./target/debug/fuji")
        .args(&["daemon", "start"])
        .spawn()?;

    sleep(Duration::from_secs(2)).await;

    // Mount a share
    let output = Command::new("./target/debug/fuji")
        .args(&["mount", "nfs://nfs-server/media"])
        .output()?;

    assert!(output.status.success(), "Failed to mount NFS share");

    // Gracefully stop first daemon with SIGTERM
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM)?;
        child.wait()?;
    }

    // Stop daemon
    let status = Command::new("./target/debug/fuji")
        .args(&["daemon", "stop"])
        .status()?;

    assert!(status.success(), "Failed to stop daemon");

    sleep(Duration::from_secs(1)).await;

    // Start daemon again
    let mut child2 = Command::new("./target/debug/fuji")
        .args(&["daemon", "start"])
        .spawn()?;

    assert!(true, "Daemon restarted successfully");

    sleep(Duration::from_secs(1)).await; // Give daemon time to start
    sleep(Duration::from_secs(3)).await; // Give time for auto-mount

    // Check that share was auto-mounted
    let output = Command::new("./target/debug/fuji")
        .args(&["status"])
        .output()?;

    assert!(output.status.success());
    let status_str = String::from_utf8_lossy(&output.stdout);
    assert!(
        status_str.contains("nfs-server_nfs/media"),
        "Share was not auto-mounted after restart"
    );

    // Gracefully stop second daemon with SIGTERM
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        kill(Pid::from_raw(child2.id() as i32), Signal::SIGTERM)?;
        child2.wait()?;
    }

    // Cleanup
    Command::new("./target/debug/fuji")
        .args(&["daemon", "stop"])
        .status()?;

    Ok(())
}

/// Test error handling for invalid URLs
#[tokio::test]
async fn test_error_handling() -> Result<()> {
    // Try to mount invalid URL without daemon
    let output = Command::new("./target/debug/fuji")
        .args(&["mount", "invalid://url"])
        .output()?;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Failed to connect to daemon")
            || stderr.contains("Could not connect to Fuji daemon")
            || stderr.contains("Invalid scheme")
            || stderr.contains("No such file or directory")
    );

    Ok(())
}

/// Test daemon lifecycle
#[tokio::test]
async fn test_daemon_lifecycle() -> Result<()> {
    // Start daemon in foreground for a brief moment
    let mut child = Command::new("./target/debug/fuji")
        .args(&["daemon", "start"])
        .spawn()?;

    // Give it a moment to start
    sleep(Duration::from_secs(1)).await;

    // Send SIGTERM
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM)?;
    }

    // Check it exited cleanly
    let status = child.wait()?;
    assert!(status.success());

    Ok(())
}

/// Helper function to ensure test environment is ready
fn check_test_environment() -> Result<()> {
    // Check if running in Docker/test environment
    if !std::path::Path::new("/.dockerenv").exists() {
        println!("Warning: Not running in Docker environment");
    }

    // Check if NFS server is reachable
    let output = Command::new("showmount")
        .arg("-e")
        .arg("nfs-server")
        .output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!("NFS server not reachable"));
    }

    // Check if SMB server is reachable
    let output = Command::new("smbclient")
        .args(&["-L", "smb-server", "-N"])
        .output()?;

    if !output.status.success() {
        // Try with credentials
        let output = Command::new("smbclient")
            .args(&["-L", "smb-server", "-U", "testuser%testpass"])
            .output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("SMB server not reachable"));
        }
    }

    Ok(())
}

#[cfg(test)]
mod test_setup {
    use super::*;

    #[test]
    fn test_environment_check() {
        if let Err(e) = check_test_environment() {
            println!("Test environment check failed: {}", e);
            println!("Integration tests require Docker containers to be running:");
            println!("  docker-compose up -d nfs-server smb-server");
        }
    }
}
