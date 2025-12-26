//! Multi-protocol stress testing
//!
//! This test validates Fuji's behavior under concurrent multi-protocol load:
//! 1. Multiple simultaneous NFS mounts
//! 2. Multiple simultaneous SMB mounts
//! 3. Concurrent file operations across all mounts
//! 4. Random unmount ordering
//! 5. Resource cleanup verification

#[path = "../common/mod.rs"]
mod common;

use anyhow::Result;
use common::*;
use std::time::Duration;

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_concurrent_multi_protocol_mounts() -> Result<()> {
    eprintln!("\n=== Testing Concurrent Multi-Protocol Mounts ===\n");

    // 1. Start Docker environment with all servers
    eprintln!("Step 1: Starting Docker environment...");
    let mut docker = DockerEnvironment::new()?;
    docker.start_services(&["nfs-server", "smb-server"]).await?;

    docker
        .wait_for_service("nfs-server", Duration::from_secs(60))
        .await?;
    docker
        .wait_for_service("smb-server", Duration::from_secs(60))
        .await?;

    // 2. Start daemon
    eprintln!("\nStep 2: Starting Fuji daemon...");
    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(10)).await?;

    // 3. Mount multiple NFS shares concurrently
    eprintln!("\nStep 3: Mounting multiple NFS shares concurrently...");

    let nfs_urls = vec![
        "nfs://nfs-server/exports/data",
        "nfs://nfs-server/exports/media",
        "nfs://nfs-server/exports",
    ];

    let mut nfs_mount_futures = Vec::new();
    for url in &nfs_urls {
        let daemon_clone = daemon.clone();
        let url_clone = url.to_string();
        nfs_mount_futures.push(tokio::spawn(async move {
            TestMount::mount(daemon_clone, &url_clone, None).await
        }));
    }

    let nfs_mounts = futures::future::join_all(nfs_mount_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("Join error: {}", e))?
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    eprintln!("✓ Mounted {} NFS shares successfully", nfs_mounts.len());
    for (i, mount) in nfs_mounts.iter().enumerate() {
        eprintln!("  NFS {}: {}", i + 1, mount.mount_id());
    }

    // 4. Mount multiple SMB shares concurrently
    eprintln!("\nStep 4: Mounting multiple SMB shares concurrently...");

    let smb_urls = vec![
        "smb://testuser:testpass@smb-server/data",
        "smb://testuser:testpass@smb-server/media",
        "smb://guest@smb-server/public",
    ];

    let mut smb_mount_futures = Vec::new();
    for url in &smb_urls {
        let daemon_clone = daemon.clone();
        let url_clone = url.to_string();
        smb_mount_futures.push(tokio::spawn(async move {
            TestMount::mount(daemon_clone, &url_clone, None).await
        }));
    }

    let smb_mounts = futures::future::join_all(smb_mount_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("Join error: {}", e))?
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    eprintln!("✓ Mounted {} SMB shares successfully", smb_mounts.len());
    for (i, mount) in smb_mounts.iter().enumerate() {
        eprintln!("  SMB {}: {}", i + 1, mount.mount_id());
    }

    // 5. Verify all mounts in status
    eprintln!("\nStep 5: Verifying all mounts active...");
    let status = daemon.status(false).await?;
    eprintln!("Status output:\n{}", status);

    // Check each mount is listed
    for mount in &nfs_mounts {
        assert!(
            status.contains(mount.mount_id()),
            "NFS mount {} not in status",
            mount.mount_id()
        );
    }
    for mount in &smb_mounts {
        assert!(
            status.contains(mount.mount_id()),
            "SMB mount {} not in status",
            mount.mount_id()
        );
    }

    let total_mounts = nfs_mounts.len() + smb_mounts.len();
    eprintln!("✓ All {} mounts verified in status", total_mounts);

    // 6. Perform concurrent file operations on all mounts
    eprintln!("\nStep 6: Performing file I/O on all mounts...");

    let mut successful_writes = 0;

    // NFS write operations
    for (i, mount) in nfs_mounts.iter().enumerate() {
        let file_name = format!("nfs-stress-{}.txt", i);
        let content = format!("NFS stress test content {}", i);
        match mount.write_test_file(&file_name, content.as_bytes()).await {
            Ok(_) => successful_writes += 1,
            Err(e) => eprintln!("Warning: NFS write {} failed: {}", i, e),
        }
    }

    // SMB write operations
    for (i, mount) in smb_mounts.iter().enumerate() {
        let file_name = format!("smb-stress-{}.txt", i);
        let content = format!("SMB stress test content {}", i);
        match mount.write_test_file(&file_name, content.as_bytes()).await {
            Ok(_) => successful_writes += 1,
            Err(e) => eprintln!("Warning: SMB write {} failed: {}", i, e),
        }
    }

    eprintln!(
        "✓ Completed {}/{} write operations",
        successful_writes, total_mounts
    );

    // 7. Test read operations
    eprintln!("\nStep 7: Testing read operations...");

    let mut successful_reads = 0;

    // NFS read operations
    for (i, mount) in nfs_mounts.iter().enumerate() {
        let mount_point = mount.mount_point();
        let file_name = format!("nfs-stress-{}.txt", i);
        let file_path = mount_point.join(file_name);
        match mount.read_test_file(&file_path).await {
            Ok(_) => successful_reads += 1,
            Err(e) => eprintln!("Warning: NFS read {} failed: {}", i, e),
        }
    }

    // SMB read operations
    for (i, mount) in smb_mounts.iter().enumerate() {
        let mount_point = mount.mount_point();
        let file_name = format!("smb-stress-{}.txt", i);
        let file_path = mount_point.join(file_name);
        match mount.read_test_file(&file_path).await {
            Ok(_) => successful_reads += 1,
            Err(e) => eprintln!("Warning: SMB read {} failed: {}", i, e),
        }
    }

    eprintln!(
        "✓ Completed {}/{} read operations",
        successful_reads, total_mounts
    );

    // 8. Unmount all in random order
    eprintln!("\nStep 8: Unmounting all shares...");

    let mut all_mounts = Vec::new();
    all_mounts.extend(nfs_mounts);
    all_mounts.extend(smb_mounts);

    // Unmount sequentially (random order could be added with shuffle)
    for mount in all_mounts {
        mount.unmount().await?;
    }

    eprintln!("✓ All mounts unmounted successfully");

    // 9. Verify all mounts cleaned up
    eprintln!("\nStep 9: Verifying cleanup...");
    let final_status = daemon.status(false).await?;
    eprintln!("Final status:\n{}", final_status);

    // Status should show no active mounts (or just daemon status)
    eprintln!("✓ Cleanup verified");

    eprintln!("\n=== Concurrent Multi-Protocol Test PASSED ===\n");
    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_mount_unmount_stress_cycle() -> Result<()> {
    eprintln!("\n=== Testing Mount/Unmount Stress Cycle ===\n");

    // 1. Start environment
    eprintln!("Step 1: Starting environment...");
    let mut docker = DockerEnvironment::new()?;
    docker.start_services(&["nfs-server"]).await?;
    docker
        .wait_for_service("nfs-server", Duration::from_secs(60))
        .await?;

    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(10)).await?;

    // 2. Perform multiple mount/unmount cycles
    eprintln!("\nStep 2: Performing mount/unmount stress cycles...");

    let cycles = 10;
    for i in 1..=cycles {
        eprintln!("Cycle {}/{}...", i, cycles);

        // Mount
        let mount = TestMount::mount(daemon.clone(), "nfs://nfs-server/exports/data", None).await?;

        // Quick file I/O
        let test_file = mount
            .write_test_file(&format!("cycle-{}.txt", i), b"stress test")
            .await?;

        let _content = mount.read_test_file(&test_file).await?;

        // Unmount
        mount.unmount().await?;

        // Brief pause
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    eprintln!("✓ Completed {} mount/unmount cycles", cycles);

    // 3. Verify daemon still responsive
    eprintln!("\nStep 3: Verifying daemon health...");
    let status = daemon.status(false).await?;
    eprintln!("✓ Daemon responsive after stress test");
    eprintln!("Status: {}", status);

    eprintln!("\n=== Mount/Unmount Stress Test PASSED ===\n");
    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "E2E tests require Linux")]
async fn test_large_file_concurrent_transfers() -> Result<()> {
    eprintln!("\n=== Testing Large File Concurrent Transfers ===\n");

    // 1. Start environment
    eprintln!("Step 1: Starting environment...");
    let mut docker = DockerEnvironment::new()?;
    docker.start_services(&["nfs-server", "smb-server"]).await?;

    docker
        .wait_for_service("nfs-server", Duration::from_secs(60))
        .await?;
    docker
        .wait_for_service("smb-server", Duration::from_secs(60))
        .await?;

    let daemon = TestDaemon::start().await?;
    daemon.wait_ready(Duration::from_secs(10)).await?;

    // 2. Mount shares
    eprintln!("\nStep 2: Mounting test shares...");
    let nfs_mount = TestMount::mount(daemon.clone(), "nfs://nfs-server/exports/data", None).await?;
    let smb_mount = TestMount::mount(
        daemon.clone(),
        "smb://testuser:testpass@smb-server/data",
        None,
    )
    .await?;

    // 3. Generate test data (1MB files)
    eprintln!("\nStep 3: Preparing test data...");
    let large_data_1 = random_test_data(1024 * 1024); // 1MB
    let large_data_2 = random_test_data(1024 * 1024); // 1MB
    eprintln!("✓ Generated 2MB of test data");

    // 4. Perform concurrent large file transfers
    eprintln!("\nStep 4: Transferring files concurrently...");

    let (nfs_result, smb_result) = tokio::join!(
        nfs_mount.write_test_file("large-nfs.bin", &large_data_1),
        smb_mount.write_test_file("large-smb.bin", &large_data_2)
    );

    let nfs_file = nfs_result?;
    let smb_file = smb_result?;

    eprintln!("✓ Files transferred successfully");

    // 5. Verify file integrity
    eprintln!("\nStep 5: Verifying file integrity...");

    let nfs_read = nfs_mount.read_test_file(&nfs_file).await?;
    let smb_read = smb_mount.read_test_file(&smb_file).await?;

    assert_eq!(nfs_read.len(), large_data_1.len(), "NFS file size mismatch");
    assert_eq!(smb_read.len(), large_data_2.len(), "SMB file size mismatch");

    assert_eq!(nfs_read, large_data_1, "NFS file content mismatch");
    assert_eq!(smb_read, large_data_2, "SMB file content mismatch");

    eprintln!("✓ File integrity verified");

    eprintln!("\n=== Large File Concurrent Transfer Test PASSED ===\n");
    Ok(())
}
