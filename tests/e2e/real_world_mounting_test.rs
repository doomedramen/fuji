//! Real-world E2E tests for actual NFS and SMB mounting
//!
//! These tests verify that fuji can actually mount real NFS and SMB servers
//! and that files are accessible with correct content.

#[path = "../common/mod.rs"]
mod common;

use common::assertions::wait_for_condition;
use common::daemon::TestDaemon;
use common::docker::DockerEnvironment;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tokio;

/// Helper to get mount point from status JSON
async fn get_mount_point(daemon: &TestDaemon, mount_id: &str) -> anyhow::Result<PathBuf> {
    let status_json = daemon.status(true).await?;
    let status: serde_json::Value = serde_json::from_str(&status_json)?;

    let mounts = status["mounts"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("No mounts array in status"))?;

    let mount_info = mounts
        .iter()
        .find(|m| m["id"].as_str() == Some(mount_id))
        .ok_or_else(|| anyhow::anyhow!("Mount {} not found in status", mount_id))?;

    let mount_point = mount_info["mount_point"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No mount_point in status"))?;

    Ok(PathBuf::from(mount_point))
}

// ============================================================================
// Real NFS Mounting Tests
// ============================================================================

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_real_nfs_mount_and_verify_files() {
    println!("\n=== Testing Real NFS Mount with File Verification ===\n");

    // 1. Start Docker environment with NFS server
    println!("Starting Docker NFS server...");
    let mut docker = DockerEnvironment::new().expect("Failed to create Docker environment");
    docker
        .start_services(&["nfs-server"])
        .await
        .expect("Failed to start NFS server");
    docker
        .wait_for_service("nfs-server", Duration::from_secs(60))
        .await
        .expect("NFS server failed to become healthy");

    println!("✓ NFS server is healthy");

    // 2. Start fuji daemon
    println!("Starting fuji daemon...");
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    daemon
        .wait_ready(Duration::from_secs(10))
        .await
        .expect("Daemon failed to become ready");

    println!("✓ Daemon is ready");

    // 3. Mount NFS share
    println!("Mounting NFS share...");
    let mount_id = daemon
        .mount("nfs://nfs-server/exports/data", None)
        .await
        .expect("Failed to mount NFS share");

    println!("✓ Mount succeeded: {}", mount_id);

    // 4. Get mount point
    let mount_point = get_mount_point(&daemon, &mount_id)
        .await
        .expect("Failed to get mount point");

    println!("✓ Mount point: {}", mount_point.display());

    // 5. Wait for mount to be accessible
    println!("Waiting for mount to be accessible...");
    wait_for_condition(
        || async { mount_point.exists() && mount_point.is_dir() },
        Duration::from_secs(30),
        Duration::from_millis(500),
    )
    .await
    .expect("Mount point never became accessible");

    println!("✓ Mount point is accessible");

    // 6. CRITICAL: Verify the pre-existing test file exists and has correct content
    println!("Verifying pre-existing test.txt file...");
    let test_file_path = mount_point.join("test.txt");

    assert!(
        test_file_path.exists(),
        "Expected file test.txt does not exist in mount at {}",
        test_file_path.display()
    );

    let test_file_content = fs::read_to_string(&test_file_path).expect("Failed to read test.txt");

    assert_eq!(
        test_file_content.trim(),
        "This is the data export",
        "test.txt content mismatch. Expected 'This is the data export', got '{}'",
        test_file_content.trim()
    );

    println!("✓ Pre-existing file verified: test.txt contains expected content");

    // 7. Write a new file to the mount
    println!("Writing new file to mount...");
    let new_file_path = mount_point.join("fuji_test_write.txt");
    let test_content = "Hello from Fuji E2E test! 🎉";

    fs::write(&new_file_path, test_content).expect("Failed to write test file");

    println!("✓ New file written successfully");

    // 8. Read the file back and verify content
    println!("Reading file back...");
    let read_content = fs::read_to_string(&new_file_path).expect("Failed to read back test file");

    assert_eq!(
        read_content, test_content,
        "File content mismatch after write/read"
    );

    println!("✓ File content verified after read");

    // 9. List directory contents
    println!("Listing directory contents...");
    let entries: Vec<_> = fs::read_dir(&mount_point)
        .expect("Failed to read directory")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    println!("Directory contents: {:?}", entries);

    assert!(
        entries.contains(&"test.txt".to_string()),
        "Pre-existing test.txt not found in directory listing"
    );
    assert!(
        entries.contains(&"fuji_test_write.txt".to_string()),
        "Newly written file not found in directory listing"
    );

    println!("✓ Directory listing verified");

    // 10. Test large file transfer
    println!("Testing large file transfer...");
    let large_file_path = mount_point.join("large_file.bin");
    let large_data = vec![0u8; 1024 * 1024]; // 1MB of zeros

    fs::write(&large_file_path, &large_data).expect("Failed to write large file");

    let read_large_data = fs::read(&large_file_path).expect("Failed to read large file");

    assert_eq!(
        read_large_data.len(),
        large_data.len(),
        "Large file size mismatch"
    );

    println!("✓ Large file (1MB) transfer verified");

    // 11. Unmount
    println!("Unmounting...");
    daemon
        .unmount(&mount_id, false)
        .await
        .expect("Failed to unmount");

    // Wait for unmount to complete
    tokio::time::sleep(Duration::from_secs(2)).await;

    println!("✓ Unmounted successfully");

    // 12. Verify mount point is no longer accessible
    let is_still_mounted = mount_point.exists() && fs::read_dir(&mount_point).is_ok();
    assert!(
        !is_still_mounted,
        "Mount point still accessible after unmount"
    );

    println!("✓ Mount point confirmed inaccessible after unmount");

    println!("\n=== ✓ Real NFS Mount Test PASSED ===\n");
}

// ============================================================================
// Real SMB Mounting Tests
// ============================================================================

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_real_smb_mount_with_credentials() {
    println!("\n=== Testing Real SMB Mount with Credentials ===\n");

    // 1. Start Docker environment with SMB server
    println!("Starting Docker SMB server...");
    let mut docker = DockerEnvironment::new().expect("Failed to create Docker environment");
    docker
        .start_services(&["smb-server"])
        .await
        .expect("Failed to start SMB server");
    docker
        .wait_for_service("smb-server", Duration::from_secs(60))
        .await
        .expect("SMB server failed to become healthy");

    println!("✓ SMB server is healthy");

    // 2. Start fuji daemon
    println!("Starting fuji daemon...");
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    daemon
        .wait_ready(Duration::from_secs(10))
        .await
        .expect("Daemon failed to become ready");

    println!("✓ Daemon is ready");

    // 3. Mount SMB share with credentials
    println!("Mounting SMB share with credentials (testuser:testpass)...");
    let mount_id = daemon
        .mount("smb://testuser:testpass@smb-server/data", None)
        .await
        .expect("Failed to mount SMB share");

    println!("✓ Mount succeeded: {}", mount_id);

    // 4. Get mount point
    let mount_point = get_mount_point(&daemon, &mount_id)
        .await
        .expect("Failed to get mount point");

    println!("✓ Mount point: {}", mount_point.display());

    // 5. Wait for mount to be accessible
    println!("Waiting for mount to be accessible...");
    wait_for_condition(
        || async { mount_point.exists() && mount_point.is_dir() },
        Duration::from_secs(30),
        Duration::from_millis(500),
    )
    .await
    .expect("Mount point never became accessible");

    println!("✓ Mount point is accessible");

    // 6. Write a test file to SMB share
    println!("Writing test file to SMB share...");
    let test_file_path = mount_point.join("smb_test.txt");
    let test_content = "SMB test content from Fuji";

    fs::write(&test_file_path, test_content).expect("Failed to write to SMB share");

    println!("✓ File written to SMB share");

    // 7. Read back and verify
    println!("Reading file back from SMB share...");
    let read_content = fs::read_to_string(&test_file_path).expect("Failed to read from SMB share");

    assert_eq!(read_content, test_content, "SMB file content mismatch");

    println!("✓ SMB file content verified");

    // 8. Test directory creation
    println!("Testing directory creation on SMB...");
    let test_dir = mount_point.join("test_directory");
    fs::create_dir(&test_dir).expect("Failed to create directory on SMB");

    assert!(test_dir.exists() && test_dir.is_dir());

    println!("✓ Directory created on SMB share");

    // 9. Test file in subdirectory
    println!("Testing file in subdirectory...");
    let subdir_file = test_dir.join("nested.txt");
    fs::write(&subdir_file, "Nested file content").expect("Failed to write nested file");

    let nested_content = fs::read_to_string(&subdir_file).expect("Failed to read nested file");

    assert_eq!(nested_content, "Nested file content");

    println!("✓ Nested file operations verified");

    // 10. Unmount
    println!("Unmounting SMB share...");
    daemon
        .unmount(&mount_id, false)
        .await
        .expect("Failed to unmount");

    tokio::time::sleep(Duration::from_secs(2)).await;

    println!("✓ SMB share unmounted successfully");

    println!("\n=== ✓ Real SMB Mount Test PASSED ===\n");
}

// ============================================================================
// Read-Only NFS Mount Test
// ============================================================================

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_nfs_read_only_mount() {
    println!("\n=== Testing Read-Only NFS Mount ===\n");

    // Start NFS server
    let mut docker = DockerEnvironment::new().expect("Failed to create Docker environment");
    docker
        .start_services(&["nfs-server"])
        .await
        .expect("Failed to start NFS server");
    docker
        .wait_for_service("nfs-server", Duration::from_secs(60))
        .await
        .expect("NFS server failed to become healthy");

    // Start daemon
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    daemon
        .wait_ready(Duration::from_secs(10))
        .await
        .expect("Daemon failed");

    // Mount the read-only export (/exports/media is configured as ro)
    println!("Mounting read-only NFS export...");
    let mount_id = daemon
        .mount(
            "nfs://nfs-server/exports/media",
            Some(vec!["ro".to_string()]),
        )
        .await
        .expect("Failed to mount");

    println!("✓ Read-only mount succeeded: {}", mount_id);

    // Get mount point
    let mount_point = get_mount_point(&daemon, &mount_id)
        .await
        .expect("Failed to get mount point");

    // Wait for accessibility
    wait_for_condition(
        || async { mount_point.exists() },
        Duration::from_secs(30),
        Duration::from_millis(500),
    )
    .await
    .expect("Mount failed to become accessible");

    // Verify pre-existing file can be read
    println!("Verifying read access to pre-existing file...");
    let test_file = mount_point.join("test.txt");
    assert!(test_file.exists(), "test.txt should exist");

    let content = fs::read_to_string(&test_file).expect("Should be able to read from ro mount");
    assert_eq!(content.trim(), "This is the media export");

    println!("✓ Read access verified");

    // Verify write operations fail
    println!("Verifying write operations are blocked...");
    let write_test = mount_point.join("write_test.txt");
    let write_result = fs::write(&write_test, "This should fail");

    assert!(
        write_result.is_err(),
        "Write should fail on read-only mount"
    );

    println!("✓ Write correctly blocked on read-only mount");

    // Cleanup
    daemon
        .unmount(&mount_id, false)
        .await
        .expect("Failed to unmount");

    println!("\n=== ✓ Read-Only Mount Test PASSED ===\n");
}

// ============================================================================
// Concurrent Mounts Test
// ============================================================================

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_concurrent_nfs_and_smb_mounts() {
    println!("\n=== Testing Concurrent NFS and SMB Mounts ===\n");

    // Start both servers
    let mut docker = DockerEnvironment::new().expect("Failed to create Docker environment");
    docker
        .start_services(&["nfs-server", "smb-server"])
        .await
        .expect("Failed to start servers");

    docker
        .wait_for_service("nfs-server", Duration::from_secs(60))
        .await
        .expect("NFS failed");
    docker
        .wait_for_service("smb-server", Duration::from_secs(60))
        .await
        .expect("SMB failed");

    println!("✓ Both servers are healthy");

    // Start daemon
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    daemon
        .wait_ready(Duration::from_secs(10))
        .await
        .expect("Daemon failed");

    // Mount NFS
    println!("Mounting NFS export...");
    let nfs_id = daemon
        .mount("nfs://nfs-server/exports/data", None)
        .await
        .expect("NFS mount failed");

    // Mount SMB
    println!("Mounting SMB share...");
    let smb_id = daemon
        .mount("smb://testuser:testpass@smb-server/data", None)
        .await
        .expect("SMB mount failed");

    println!("✓ Both mounts succeeded");

    // Get mount points
    let nfs_mount_point = get_mount_point(&daemon, &nfs_id)
        .await
        .expect("Failed to get NFS mount point");
    let smb_mount_point = get_mount_point(&daemon, &smb_id)
        .await
        .expect("Failed to get SMB mount point");

    // Wait for both to be accessible
    wait_for_condition(
        || async { nfs_mount_point.exists() && smb_mount_point.exists() },
        Duration::from_secs(30),
        Duration::from_millis(500),
    )
    .await
    .expect("Mounts failed to become accessible");

    println!("✓ Both mounts are accessible");

    // Write to both simultaneously
    println!("Testing concurrent writes...");
    let nfs_file = nfs_mount_point.join("concurrent_test.txt");
    let smb_file = smb_mount_point.join("concurrent_test.txt");

    fs::write(&nfs_file, "NFS concurrent write").expect("Failed to write to NFS");
    fs::write(&smb_file, "SMB concurrent write").expect("Failed to write to SMB");

    println!("✓ Files written to both mounts");

    // Verify both files exist and have correct content
    println!("Verifying file existence and content...");
    assert!(nfs_file.exists(), "NFS test file does not exist");
    assert!(smb_file.exists(), "SMB test file does not exist");

    let nfs_content = fs::read_to_string(&nfs_file).expect("Failed to read from NFS");
    let smb_content = fs::read_to_string(&smb_file).expect("Failed to read from SMB");

    assert_eq!(
        nfs_content, "NFS concurrent write",
        "NFS file content mismatch"
    );
    assert_eq!(
        smb_content, "SMB concurrent write",
        "SMB file content mismatch"
    );

    println!("✓ Both files verified - concurrent operations successful");

    // Cleanup
    daemon
        .unmount(&nfs_id, false)
        .await
        .expect("Failed to unmount NFS");
    daemon
        .unmount(&smb_id, false)
        .await
        .expect("Failed to unmount SMB");

    println!("\n=== ✓ Concurrent Mounts Test PASSED ===\n");
}
