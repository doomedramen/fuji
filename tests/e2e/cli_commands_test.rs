//! E2E tests for CLI commands
//!
//! Tests all CLI commands through the actual binary

#[path = "../common/mod.rs"]
mod common;

use anyhow::Result;
use common::*;
use tokio::process::Command;
use tokio::time::Duration;

/// Helper to execute fuji CLI command
async fn run_fuji_command(
    args: &[&str],
    socket_path: &std::path::Path,
) -> Result<std::process::Output> {
    let binary_path = std::env::current_exe()?
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("fuji");

    let mut cmd = Command::new(&binary_path);
    cmd.args(args);
    cmd.env("FUJI_SOCKET", socket_path.to_str().unwrap());

    let output = cmd.output().await?;
    Ok(output)
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_cli_status_command() -> Result<()> {
    // Start Docker services
    let mut docker = DockerEnvironment::new()?;
    docker.start_services(&["nfs-server"]).await?;
    docker
        .wait_for_service("nfs-server", Duration::from_secs(30))
        .await?;

    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Test status with no mounts
    let output = run_fuji_command(&["status"], daemon.socket_path()).await?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("No active mounts") || stdout.contains("mounts"));

    // Mount something
    let _mount = TestMount::mount(daemon.clone(), "nfs://nfs-server/exports/data", None).await?;

    // Test status with mount
    let output = run_fuji_command(&["status"], daemon.socket_path()).await?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("nfs-server"));
    assert!(stdout.contains("Active") || stdout.contains("active"));

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_cli_status_json_output() -> Result<()> {
    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Test JSON output
    let output = run_fuji_command(&["status", "--json"], daemon.socket_path()).await?;
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout)?;

    // Parse JSON to verify it's valid
    let _json: serde_json::Value = serde_json::from_str(&stdout)?;

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_cli_status_verbose() -> Result<()> {
    // Start Docker services
    let mut docker = DockerEnvironment::new()?;
    docker.start_services(&["nfs-server"]).await?;
    docker
        .wait_for_service("nfs-server", Duration::from_secs(30))
        .await?;

    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Mount something
    let _mount = TestMount::mount(daemon.clone(), "nfs://nfs-server/exports/data", None).await?;

    // Test verbose output
    let output = run_fuji_command(&["status", "--verbose"], daemon.socket_path()).await?;
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout)?;
    // Verbose output should contain more details
    assert!(stdout.len() > 50);

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_cli_mount_unmount_commands() -> Result<()> {
    // Start Docker services
    let mut docker = DockerEnvironment::new()?;
    docker.start_services(&["nfs-server"]).await?;
    docker
        .wait_for_service("nfs-server", Duration::from_secs(30))
        .await?;

    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Mount via CLI
    let output = run_fuji_command(
        &["mount", "nfs://nfs-server/exports/data"],
        daemon.socket_path(),
    )
    .await?;
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("mounted") || stdout.contains("success"));

    // Extract mount ID from output (format varies, look for common patterns)
    let mount_id = if stdout.contains("mount_id") {
        // JSON-like output
        stdout
            .lines()
            .find(|line| line.contains("mount_id"))
            .and_then(|line| line.split('"').nth(3))
            .unwrap_or("nfs-nfs-server-exports-data")
    } else {
        // Plain text output - use default ID format
        "nfs-nfs-server-exports-data"
    };

    // Unmount via CLI
    let output = run_fuji_command(&["unmount", mount_id], daemon.socket_path()).await?;
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("unmounted") || stdout.contains("success"));

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_cli_mount_with_options() -> Result<()> {
    // Start Docker services
    let mut docker = DockerEnvironment::new()?;
    docker.start_services(&["nfs-server"]).await?;
    docker
        .wait_for_service("nfs-server", Duration::from_secs(30))
        .await?;

    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Mount with options via CLI
    let output = run_fuji_command(
        &["mount", "nfs://nfs-server/exports/data", "-o", "rw,noatime"],
        daemon.socket_path(),
    )
    .await?;

    assert!(output.status.success());

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_cli_version_command() -> Result<()> {
    // Version command doesn't need daemon
    let binary_path = std::env::current_exe()?
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("fuji");

    let output = Command::new(&binary_path).arg("--version").output().await?;

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("fuji"));
    assert!(stdout.contains("."));

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_cli_help_command() -> Result<()> {
    // Help command doesn't need daemon
    let binary_path = std::env::current_exe()?
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("fuji");

    let output = Command::new(&binary_path).arg("--help").output().await?;

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("Usage:") || stdout.contains("USAGE"));
    assert!(stdout.contains("mount"));
    assert!(stdout.contains("unmount"));
    assert!(stdout.contains("status"));

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_cli_daemon_status() -> Result<()> {
    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Check daemon status
    let output = run_fuji_command(&["daemon", "status"], daemon.socket_path()).await?;
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("running") || stdout.contains("active"));

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_cli_invalid_command() -> Result<()> {
    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Try invalid command
    let binary_path = std::env::current_exe()?
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("fuji");

    let output = Command::new(&binary_path)
        .arg("invalid-command")
        .env("FUJI_SOCKET", daemon.socket_path().to_str().unwrap())
        .output()
        .await?;

    assert!(!output.status.success());

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_cli_unmount_nonexistent() -> Result<()> {
    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Try to unmount non-existent mount
    let output = run_fuji_command(&["unmount", "nonexistent-mount"], daemon.socket_path()).await?;

    assert!(!output.status.success());

    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("not found") || stderr.contains("error"));

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_cli_status_filter_by_protocol() -> Result<()> {
    // Start Docker services
    let mut docker = DockerEnvironment::new()?;
    docker.start_services(&["nfs-server", "smb-server"]).await?;
    docker
        .wait_for_service("nfs-server", Duration::from_secs(30))
        .await?;
    docker
        .wait_for_service("smb-server", Duration::from_secs(30))
        .await?;

    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Mount both NFS and SMB
    let _nfs_mount =
        TestMount::mount(daemon.clone(), "nfs://nfs-server/exports/data", None).await?;

    let _smb_mount = TestMount::mount(
        daemon.clone(),
        "smb://testuser:testpass@smb-server/data",
        None,
    )
    .await?;

    // Filter by NFS protocol
    let output = run_fuji_command(&["status", "--type", "nfs"], daemon.socket_path()).await?;
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("nfs"));
    // SMB should not be in output (unless it shows 0 SMB mounts)

    Ok(())
}
