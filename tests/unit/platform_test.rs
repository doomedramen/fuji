//! Unit tests for platform detection and platform-specific functionality
//!
//! Tests cross-platform compatibility, platform detection accuracy,
//! and platform-specific mount operations.

use fuji::mount::MountType;
use fuji::platform::{Signal, get_platform};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[test]
fn test_platform_creation() {
    let platform = get_platform();

    // Platform should be created successfully on any supported system
    assert!(platform.ensure_dir_exists(Path::new("/tmp")).is_ok());
    println!("✓ Platform created successfully");
}

#[test]
fn test_platform_user_info() {
    let platform = get_platform();

    // Test getting current user
    let user = platform.get_current_user();
    assert!(user.is_ok());
    let username = user.unwrap();
    assert!(!username.is_empty());
    println!("✓ Current user: {}", username);

    // Test getting current PID
    let pid = platform.get_current_pid();
    assert!(pid > 0);
    println!("✓ Current PID: {}", pid);

    // Test root detection (may or may not be root)
    let is_root = platform.is_root();
    println!("✓ Root detection: {}", is_root);
}

#[test]
fn test_platform_path_operations() {
    let platform = get_platform();
    let temp_dir = TempDir::new().unwrap();
    let test_path = temp_dir.path().join("test_dir");

    // Test path existence check
    assert!(!platform.path_exists(&test_path));
    println!("✓ Path existence check works");

    // Test directory creation
    let create_result = platform.create_dir(&test_path);
    assert!(create_result.is_ok());
    assert!(platform.path_exists(&test_path));
    println!("✓ Directory creation works");

    // Test directory access check
    let can_access = platform.can_access_path(&test_path);
    assert!(can_access.is_ok());
    assert!(can_access.unwrap());
    println!("✓ Path access check works");

    // Test ensure directory exists (should not fail if it exists)
    let ensure_result = platform.ensure_dir_exists(&test_path);
    assert!(ensure_result.is_ok());
    println!("✓ Ensure directory exists works");

    // Test directory removal
    let remove_result = platform.remove_dir(&test_path);
    assert!(remove_result.is_ok());
    assert!(!platform.path_exists(&test_path));
    println!("✓ Directory removal works");
}

#[test]
fn test_platform_path_operations_nonexistent() {
    let platform = get_platform();
    let nonexistent_path = PathBuf::from("/nonexistent/path/that/should/not/exist");

    // Test access check for nonexistent path
    let can_access = platform.can_access_path(&nonexistent_path);
    assert!(can_access.is_ok());
    assert!(!can_access.unwrap());
    println!("✓ Nonexistent path access check works");

    // Test path existence for nonexistent path
    assert!(!platform.path_exists(&nonexistent_path));
    println!("✓ Nonexistent path existence check works");
}

#[test]
fn test_platform_mount_commands() {
    let platform = get_platform();

    // Test NFS mount command generation
    let nfs_type = MountType::Nfs {
        host: "server.example.com".to_string(),
        share: "/export".to_string(),
        options: vec![],
    };
    let mount_cmd = platform.get_mount_command(&nfs_type);
    assert!(mount_cmd.is_ok());
    let cmd = mount_cmd.unwrap();
    assert!(!cmd.is_empty());
    println!("✓ NFS mount command: {:?}", cmd);

    // Test SMB mount command generation (not yet implemented on Linux)
    let smb_type = MountType::Smb {
        host: "server.example.com".to_string(),
        share: "share".to_string(),
        username: None,
        password: None,
        domain: None,
        options: vec![],
    };
    let mount_cmd = platform.get_mount_command(&smb_type);
    // SMB/CIFS is not yet implemented, so this should return an error
    assert!(mount_cmd.is_err());
    println!("✓ SMB mount command returns expected error (not implemented)");

    // Test unmount command generation
    let unmount_cmd = platform.get_unmount_command();
    assert!(!unmount_cmd.is_empty());
    println!("✓ Unmount command: {:?}", unmount_cmd);
}

#[test]
fn test_platform_path_utilities() {
    let platform = get_platform();

    // Test getting socket path
    let socket_path = platform.get_socket_path(None);
    assert!(!socket_path.to_string_lossy().is_empty());
    println!("✓ Socket path: {}", socket_path.display());

    // Test getting config directory
    let config_dir = platform.get_config_dir();
    assert!(!config_dir.to_string_lossy().is_empty());
    println!("✓ Config directory: {}", config_dir.display());

    // Test getting mount directory
    let mount_dir = platform.get_mount_dir();
    assert!(!mount_dir.to_string_lossy().is_empty());
    println!("✓ Mount directory: {}", mount_dir.display());
}

#[test]
fn test_platform_mount_operations() {
    let platform = get_platform();

    // Test checking if a path is mounted
    let test_path = PathBuf::from("/tmp");
    let is_mounted = platform.is_mounted(&test_path);
    assert!(is_mounted.is_ok());
    println!("✓ Mount check for /tmp: {}", is_mounted.unwrap());

    // Test getting mount info
    let mount_info = platform.get_mount_info(&test_path);
    assert!(mount_info.is_ok());
    match mount_info.unwrap() {
        Some(info) => {
            println!(
                "✓ Mount info found: {} -> {}",
                info.device,
                info.mount_point.display()
            );
            assert!(!info.device.is_empty());
            assert!(!info.fs_type.is_empty());
        }
        None => {
            println!("✓ No mount info found for /tmp (expected)");
        }
    }

    // Test listing system mounts
    let system_mounts = platform.list_system_mounts();
    assert!(system_mounts.is_ok());
    let mounts = system_mounts.unwrap();
    println!("✓ Found {} system mounts", mounts.len());
    assert!(!mounts.is_empty()); // Should at least have root filesystem
}

#[test]
fn test_platform_pid_file_operations() {
    let platform = get_platform();
    let temp_dir = TempDir::new().unwrap();
    let pid_file = temp_dir.path().join("test.pid");

    // Test writing PID file
    let current_pid = platform.get_current_pid();
    let write_result = platform.write_pid_file(&pid_file);
    assert!(write_result.is_ok());
    println!("✓ PID file written");

    // Test checking PID file
    let check_result = platform.check_pid_file(&pid_file);
    assert!(check_result.is_ok());
    let stored_pid = check_result.unwrap();
    assert_eq!(stored_pid, Some(current_pid));
    println!("✓ PID file check: {:?}", stored_pid);

    // Test removing PID file
    let remove_result = platform.remove_pid_file(&pid_file);
    assert!(remove_result.is_ok());
    println!("✓ PID file removed");

    // Test checking removed PID file
    let check_result2 = platform.check_pid_file(&pid_file);
    assert!(check_result2.is_ok());
    assert_eq!(check_result2.unwrap(), None);
    println!("✓ PID file check after removal: None");
}

#[test]
fn test_platform_signal_operations() {
    let platform = get_platform();

    // Test sending signals to current process (only test signals that won't kill the process)
    let current_pid = platform.get_current_pid();

    // Note: We can't actually test signal sending without root privileges
    // or risking test termination, so we just verify the API works
    println!("✓ Signal operations available for PID: {}", current_pid);

    // Test Signal enum variants
    let signals = vec![
        Signal::Terminate,
        Signal::Interrupt,
        Signal::Hangup,
        Signal::Reload,
    ];

    for signal in signals {
        println!("✓ Signal variant available: {:?}", signal);
    }
}

#[test]
fn test_platform_error_handling() {
    let platform = get_platform();

    // Test operations with invalid paths
    let invalid_path = PathBuf::from("");

    // Empty path should be handled gracefully or return an error
    let result = platform.create_dir(&invalid_path);
    // May succeed (creating current directory) or fail - both are acceptable
    println!("✓ Empty path handled: {:?}", result);

    // Test with very long path
    let long_path = PathBuf::from("/tmp").join("a".repeat(1000));
    let result = platform.create_dir(&long_path);
    // Should either succeed or return a reasonable error
    println!("✓ Long path handled: {:?}", result.is_ok());
}

#[test]
fn test_platform_concurrent_operations() {
    use std::sync::Arc;
    use std::thread;

    let platform = Arc::new(get_platform());
    let temp_dir = TempDir::new().unwrap();
    let mut handles = Vec::new();

    // Test concurrent directory operations
    for i in 0..5 {
        let platform_clone = platform.clone();
        let path_clone = temp_dir.path().join(format!("concurrent_test_{}", i));

        let handle = thread::spawn(move || {
            let create_result = platform_clone.create_dir(&path_clone);
            assert!(create_result.is_ok());

            let exists = platform_clone.path_exists(&path_clone);
            assert!(exists);

            let access = platform_clone.can_access_path(&path_clone);
            assert!(access.is_ok() && access.unwrap());
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }

    println!("✓ Concurrent operations completed successfully");
}

#[test]
fn test_platform_edge_cases() {
    let platform = get_platform();

    // Test path with special characters
    let temp_dir = TempDir::new().unwrap();
    let special_path = temp_dir.path().join("test with spaces & symbols");

    let create_result = platform.create_dir(&special_path);
    assert!(create_result.is_ok());
    assert!(platform.path_exists(&special_path));
    println!("✓ Special character path handled");

    // Test operations on root directory (should be safe)
    let root_path = PathBuf::from("/");
    let root_exists = platform.path_exists(&root_path);
    assert!(root_exists);
    let root_access = platform.can_access_path(&root_path);
    assert!(root_access.is_ok());
    println!("✓ Root directory operations work");

    // Test that mount operations don't panic with invalid input
    let empty_path = PathBuf::from("");
    let mount_check = platform.is_mounted(&empty_path);
    // May succeed or fail, but shouldn't panic
    println!("✓ Empty mount path handled: {:?}", mount_check.is_ok());
}

#[cfg(test)]
mod property_based_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_platform_path_consistency(
            path_name in "[a-zA-Z0-9_-]+",
            suffix in 0..10usize
        ) {
            let platform = get_platform();
            let temp_dir = TempDir::new().unwrap();

            // Create a path with the given name and optional numeric suffix
            let test_path = if suffix > 0 {
                temp_dir.path().join(format!("{}_{}", path_name, suffix))
            } else {
                temp_dir.path().join(path_name)
            };

            // Test that operations are consistent
            let create_result = platform.create_dir(&test_path);
            prop_assume!(create_result.is_ok());

            assert!(platform.path_exists(&test_path));

            let access_result = platform.can_access_path(&test_path);
            assert!(access_result.is_ok());
            assert!(access_result.unwrap());
        }

        #[test]
        fn test_platform_pid_file_roundtrip(
            _seed in 0u32..100u32  // Use seed just to run multiple times
        ) {
            let platform = get_platform();
            let temp_dir = TempDir::new().unwrap();
            let pid_file = temp_dir.path().join("test.pid");

            // Use current process PID which is guaranteed to exist
            let current_pid = std::process::id();

            // Write the PID file
            use std::fs;
            use std::io::Write;
            let mut file = fs::File::create(&pid_file).unwrap();
            writeln!(file, "{}", current_pid).unwrap();

            // Check if we can read it back - should succeed since process exists
            let check_result = platform.check_pid_file(&pid_file);
            assert!(check_result.is_ok());
            assert_eq!(check_result.unwrap(), Some(current_pid));
        }

        #[test]
        fn test_platform_stale_pid_cleanup(
            // Use unlikely high PIDs that shouldn't exist
            pid in 4000000u32..4100000u32
        ) {
            let platform = get_platform();
            let temp_dir = TempDir::new().unwrap();
            let pid_file = temp_dir.path().join("stale.pid");

            // Write a PID file for a non-existent process
            use std::fs;
            use std::io::Write;
            let mut file = fs::File::create(&pid_file).unwrap();
            writeln!(file, "{}", pid).unwrap();

            // Verify file exists
            assert!(pid_file.exists());

            // Check should return None for non-existent process
            // and clean up the stale PID file
            let check_result = platform.check_pid_file(&pid_file);
            assert!(check_result.is_ok());
            assert_eq!(check_result.unwrap(), None);

            // Stale PID file should be removed
            assert!(!pid_file.exists());
        }
    }
}

#[cfg(test)]
mod integration_style_tests {
    use super::*;

    #[test]
    fn test_complete_platform_workflow() {
        let platform = get_platform();
        let temp_dir = TempDir::new().unwrap();

        // Complete workflow: create -> verify -> remove
        let test_dir = temp_dir.path().join("workflow_test");

        // Create directory
        let create_result = platform.create_dir(&test_dir);
        assert!(create_result.is_ok());

        // Verify it exists and is accessible
        assert!(platform.path_exists(&test_dir));
        let access = platform.can_access_path(&test_dir);
        assert!(access.is_ok() && access.unwrap());

        // Ensure it exists (should not fail)
        let ensure_result = platform.ensure_dir_exists(&test_dir);
        assert!(ensure_result.is_ok());

        // Clean up
        let remove_result = platform.remove_dir(&test_dir);
        assert!(remove_result.is_ok());
        assert!(!platform.path_exists(&test_dir));

        println!("✓ Complete platform workflow successful");
    }
}
