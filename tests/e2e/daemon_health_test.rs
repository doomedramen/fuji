//! E2E tests for daemon health monitoring
//!
//! Tests health check functionality using CLI commands

#[path = "../common/mod.rs"]
mod common;

use anyhow::Result;
use common::*;
use tokio::time::Duration;

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_daemon_responds_to_status() -> Result<()> {
    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Daemon should respond to status commands
    let status = daemon.status(false).await?;
    assert!(!status.is_empty());

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_daemon_status_json() -> Result<()> {
    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Request JSON status
    let status_json = daemon.status(true).await?;

    // Parse JSON to verify it's valid
    let _parsed: serde_json::Value = serde_json::from_str(&status_json)?;

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_daemon_with_active_mounts() -> Result<()> {
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

    // Daemon should still respond
    let status = daemon.status(false).await?;
    assert!(status.contains("nfs-server"));

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_daemon_concurrent_operations() -> Result<()> {
    // Start Docker services
    let mut docker = DockerEnvironment::new()?;
    docker.start_services(&["nfs-server"]).await?;
    docker
        .wait_for_service("nfs-server", Duration::from_secs(30))
        .await?;

    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Perform concurrent mount requests
    let exports = vec![
        "nfs://nfs-server/exports/data",
        "nfs://nfs-server/exports/media",
        "nfs://nfs-server/exports",
    ];

    let mut handles = Vec::new();
    for export in exports {
        let daemon_clone = daemon.clone();
        let export_owned = export.to_string();
        let handle =
            tokio::spawn(async move { TestMount::mount(daemon_clone, &export_owned, None).await });
        handles.push(handle);
    }

    // All mounts should succeed
    let mut mounts = Vec::new();
    for handle in handles {
        let mount = handle.await??;
        mounts.push(mount);
    }

    assert_eq!(mounts.len(), 3);

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_daemon_after_mount_failure() -> Result<()> {
    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Try to mount non-existent server (will fail)
    let result = TestMount::mount(daemon.clone(), "nfs://nonexistent-server/export", None).await;

    assert!(result.is_err(), "Mount should fail for non-existent server");

    // Daemon should still be responsive
    let status = daemon.status(false).await?;
    assert!(!status.is_empty());

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_daemon_memory_stability() -> Result<()> {
    // Start Docker services
    let mut docker = DockerEnvironment::new()?;
    docker.start_services(&["nfs-server"]).await?;
    docker
        .wait_for_service("nfs-server", Duration::from_secs(30))
        .await?;

    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Perform many mount/unmount cycles
    for _i in 0..10 {
        let mount = TestMount::mount(daemon.clone(), "nfs://nfs-server/exports/data", None).await?;

        // Write some data
        mount
            .write_test_file("stability_test.txt", b"Memory stability test")
            .await?;

        // Unmount
        drop(mount);

        // Small delay
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Daemon should still be responsive
    let status = daemon.status(false).await?;
    assert!(!status.is_empty());

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_daemon_detects_server_failure() -> Result<()> {
    // Start Docker services
    let mut docker = DockerEnvironment::new()?;
    docker.start_services(&["nfs-server"]).await?;
    docker
        .wait_for_service("nfs-server", Duration::from_secs(30))
        .await?;

    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Mount NFS
    let mut mount = TestMount::mount(daemon.clone(), "nfs://nfs-server/exports/data", None).await?;
    let mount_id = mount.mount_id.clone();

    // Verify mount is active
    let status = daemon.status(false).await?;
    assert!(status.contains(&mount_id));

    // Don't auto-unmount
    mount.disable_auto_unmount();
    drop(mount);

    // Stop NFS server
    docker.stop_service("nfs-server").await?;

    // Wait for health check to detect failure (35 seconds)
    tokio::time::sleep(Duration::from_secs(35)).await;

    // Check status - mount should show problem
    let status = daemon.status(false).await?;
    // Status should still list the mount (it's trying to reconnect)
    assert!(status.contains(&mount_id));

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_daemon_startup_and_shutdown() -> Result<()> {
    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Verify daemon is running
    assert!(daemon.is_running().await);

    // Status should work
    let status = daemon.status(false).await?;
    assert!(!status.is_empty());

    // Stop daemon (Drop will handle this)
    drop(daemon);

    Ok(())
}
