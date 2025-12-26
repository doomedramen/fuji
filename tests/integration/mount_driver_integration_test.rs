//! Integration tests for mount drivers (NFS, SMB, SSHFS)
//!
//! Tests real mount operations with Docker-based servers

#[path = "../common/mod.rs"]
mod common;

use anyhow::Result;
use common::*;
use tokio::time::Duration;

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "Integration tests require Linux")]
async fn test_nfs_mount_with_options() -> Result<()> {
    // Start Docker NFS server
    let mut docker = DockerEnvironment::new()?;
    docker.start_services(&["nfs-server"]).await?;
    docker
        .wait_for_service("nfs-server", Duration::from_secs(30))
        .await?;

    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Test NFS mount with various options
    let mount_options = vec![
        vec!["rw".to_string(), "noatime".to_string()],
        vec!["ro".to_string()],
        vec!["vers=4".to_string(), "proto=tcp".to_string()],
    ];

    for opts in mount_options {
        let mount = TestMount::mount(
            daemon.clone(),
            "nfs://nfs-server/exports/data",
            Some(opts.clone()),
        )
        .await?;

        assert_mount_active(&daemon, &mount.mount_id).await?;

        // Verify mount is accessible
        mount.verify_accessible().await?;

        // Write and read test file
        let test_file = mount
            .write_test_file("nfs_options_test.txt", b"NFS options test")
            .await?;
        let content = mount.read_test_file(&test_file).await?;
        assert_eq!(content, b"NFS options test");

        // Cleanup
        drop(mount);
    }

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "Integration tests require Linux")]
async fn test_smb_mount_with_credentials() -> Result<()> {
    // Start Docker SMB server
    let mut docker = DockerEnvironment::new()?;
    docker.start_services(&["smb-server"]).await?;
    docker
        .wait_for_service("smb-server", Duration::from_secs(30))
        .await?;

    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Test SMB mount with credentials
    let mount = TestMount::mount(
        daemon.clone(),
        "smb://testuser:testpass@smb-server/data",
        Some(vec!["uid=1000".to_string(), "gid=1000".to_string()]),
    )
    .await?;

    assert_mount_active(&daemon, &mount.mount_id).await?;

    // Verify mount is accessible
    mount.verify_accessible().await?;

    // Write and read test file
    let test_file = mount
        .write_test_file("smb_creds_test.txt", b"SMB credentials test")
        .await?;
    let content = mount.read_test_file(&test_file).await?;
    assert_eq!(content, b"SMB credentials test");

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "Integration tests require Linux")]
async fn test_mount_unmount_cycle() -> Result<()> {
    // Start Docker services
    let mut docker = DockerEnvironment::new()?;
    docker.start_services(&["nfs-server"]).await?;
    docker
        .wait_for_service("nfs-server", Duration::from_secs(30))
        .await?;

    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Perform multiple mount/unmount cycles
    for i in 0..5 {
        let mount = TestMount::mount(daemon.clone(), "nfs://nfs-server/exports/data", None).await?;

        assert_mount_active(&daemon, &mount.mount_id).await?;

        // Write test file
        let test_file = mount
            .write_test_file(&format!("cycle_{}.txt", i), b"Mount cycle test")
            .await?;
        let content = mount.read_test_file(&test_file).await?;
        assert_eq!(content, b"Mount cycle test");

        // Explicitly unmount
        drop(mount);

        // Small delay between cycles
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "Integration tests require Linux")]
async fn test_multiple_exports_same_server() -> Result<()> {
    // Start Docker NFS server
    let mut docker = DockerEnvironment::new()?;
    docker.start_services(&["nfs-server"]).await?;
    docker
        .wait_for_service("nfs-server", Duration::from_secs(30))
        .await?;

    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Mount multiple exports from same server
    let exports = vec![
        "nfs://nfs-server/exports/data",
        "nfs://nfs-server/exports/media",
        "nfs://nfs-server/exports",
    ];

    let mut mounts = Vec::new();
    for export in &exports {
        let mount = TestMount::mount(daemon.clone(), export, None).await?;
        assert_mount_active(&daemon, &mount.mount_id).await?;
        mounts.push(mount);
    }

    // Verify all mounts are accessible
    for (i, mount) in mounts.iter().enumerate() {
        let test_file = mount
            .write_test_file(&format!("export_{}.txt", i), b"Export test")
            .await?;
        let content = mount.read_test_file(&test_file).await?;
        assert_eq!(content, b"Export test");
    }

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "Integration tests require Linux")]
async fn test_invalid_mount_url() -> Result<()> {
    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Test invalid URLs
    let invalid_urls = vec![
        "nfs://nonexistent-server/export",
        "smb://invalid:creds@server/share",
        "nfs://server", // Missing export path
    ];

    for url in invalid_urls {
        let result = TestMount::mount(daemon.clone(), url, None).await;
        assert!(result.is_err(), "Expected error for invalid URL: {}", url);
    }

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "Integration tests require Linux")]
async fn test_mount_permission_denied() -> Result<()> {
    // Start Docker SMB server
    let mut docker = DockerEnvironment::new()?;
    docker.start_services(&["smb-server"]).await?;
    docker
        .wait_for_service("smb-server", Duration::from_secs(30))
        .await?;

    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Test SMB mount with invalid credentials
    let result = TestMount::mount(
        daemon.clone(),
        "smb://wronguser:wrongpass@smb-server/data",
        None,
    )
    .await;

    assert!(result.is_err(), "Expected error for invalid credentials");

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "Integration tests require Linux")]
async fn test_concurrent_mounts_different_protocols() -> Result<()> {
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

    // Mount NFS and SMB concurrently
    let daemon_nfs = daemon.clone();
    let daemon_smb = daemon.clone();

    let nfs_future = tokio::spawn(async move {
        TestMount::mount(daemon_nfs, "nfs://nfs-server/exports/data", None).await
    });

    let smb_future = tokio::spawn(async move {
        TestMount::mount(daemon_smb, "smb://testuser:testpass@smb-server/data", None).await
    });

    let (nfs_result, smb_result) = tokio::join!(nfs_future, smb_future);
    let nfs_mount = nfs_result??;
    let smb_mount = smb_result??;

    // Verify both mounts are active
    assert_mount_active(&daemon, &nfs_mount.mount_id).await?;
    assert_mount_active(&daemon, &smb_mount.mount_id).await?;

    // Concurrent file operations
    let nfs_file = nfs_mount
        .write_test_file("nfs_concurrent.txt", b"NFS concurrent")
        .await?;
    let smb_file = smb_mount
        .write_test_file("smb_concurrent.txt", b"SMB concurrent")
        .await?;

    let nfs_content = nfs_mount.read_test_file(&nfs_file).await?;
    let smb_content = smb_mount.read_test_file(&smb_file).await?;

    assert_eq!(nfs_content, b"NFS concurrent");
    assert_eq!(smb_content, b"SMB concurrent");

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "Integration tests require Linux")]
async fn test_large_file_transfer() -> Result<()> {
    // Start Docker NFS server
    let mut docker = DockerEnvironment::new()?;
    docker.start_services(&["nfs-server"]).await?;
    docker
        .wait_for_service("nfs-server", Duration::from_secs(30))
        .await?;

    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Mount NFS
    let mount = TestMount::mount(daemon.clone(), "nfs://nfs-server/exports/data", None).await?;
    assert_mount_active(&daemon, &mount.mount_id).await?;

    // Generate and write large file (10MB)
    use common::filesystem::random_test_data;
    let large_data = random_test_data(10 * 1024 * 1024);
    let large_file = mount.write_test_file("large_file.bin", &large_data).await?;

    // Read back and verify
    let read_data = mount.read_test_file(&large_file).await?;
    assert_eq!(large_data.len(), read_data.len());
    assert_eq!(large_data, read_data);

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "Integration tests require Linux")]
async fn test_mount_idempotency() -> Result<()> {
    // Start Docker NFS server
    let mut docker = DockerEnvironment::new()?;
    docker.start_services(&["nfs-server"]).await?;
    docker
        .wait_for_service("nfs-server", Duration::from_secs(30))
        .await?;

    // Start daemon
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(5)).await?;

    // Mount NFS
    let mount1 = TestMount::mount(daemon.clone(), "nfs://nfs-server/exports/data", None).await?;
    assert_mount_active(&daemon, &mount1.mount_id).await?;

    // Try to mount the same export again - should handle gracefully
    let result = TestMount::mount(daemon.clone(), "nfs://nfs-server/exports/data", None).await;

    // Either succeeds with a new mount point or returns existing mount
    match result {
        Ok(mount2) => {
            // If it succeeds, verify it's accessible
            mount2.verify_accessible().await?;
        }
        Err(_) => {
            // If it fails, original mount should still be active
            assert_mount_active(&daemon, &mount1.mount_id).await?;
        }
    }

    Ok(())
}
