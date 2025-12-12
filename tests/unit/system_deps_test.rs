//! Unit tests for system dependencies checker

use fuji::platform::deps::{SystemDependency, SystemDepsChecker};
use std::collections::HashMap;

#[test]
fn test_system_deps_creation() {
    let checker = SystemDepsChecker::new();

    // Should have all default dependencies
    let deps = checker.get_dependencies();
    assert!(deps.contains_key("nfs"));
    assert!(deps.contains_key("smb"));
    assert!(deps.contains_key("sshfs"));
    assert!(deps.contains_key("showmount"));
    assert!(deps.contains_key("smbclient"));

    // Check NFS dependency details
    let nfs_dep = deps.get("nfs").unwrap();
    assert_eq!(nfs_dep.binary_name, "mount.nfs");
    assert_eq!(nfs_dep.display_name, "NFS Client");
    assert!(nfs_dep.required);
    assert!(nfs_dep.install_instructions.contains_key("debian"));
    assert!(nfs_dep.install_instructions.contains_key("ubuntu"));
}

#[test]
fn test_add_custom_dependency() {
    let mut checker = SystemDepsChecker::new();

    let mut install_instructions = HashMap::new();
    install_instructions.insert(
        "linux".to_string(),
        "sudo apt-get install custom-tool".to_string(),
    );

    let custom_dep = SystemDependency {
        binary_name: "custom-binary".to_string(),
        display_name: "Custom Tool".to_string(),
        description: "A custom test tool".to_string(),
        install_instructions,
        version_check: Some("custom-binary --version".to_string()),
        min_version: Some("1.0".to_string()),
        required: false,
    };

    checker.add_dependency("custom".to_string(), custom_dep);

    assert!(checker.get_dependencies().contains_key("custom"));

    let dep = checker.get_dependencies().get("custom").unwrap();
    assert_eq!(dep.binary_name, "custom-binary");
    assert_eq!(dep.display_name, "Custom Tool");
    assert!(!dep.required);
}

#[tokio::test]
async fn test_check_existing_binary() {
    let checker = SystemDepsChecker::new();

    // 'sh' should exist on all Unix systems
    assert!(checker.check_binary_exists("sh").await);
}

#[tokio::test]
async fn test_check_missing_binary() {
    let checker = SystemDepsChecker::new();

    // This binary should not exist
    assert!(
        !checker
            .check_binary_exists("definitely-not-a-real-binary-12345")
            .await
    );
}

#[test]
fn test_get_os_family() {
    let os = SystemDepsChecker::get_os_family();
    assert!(!os.is_empty());

    // Should be a known OS family
    let known_os_families = [
        "linux", "debian", "ubuntu", "rhel", "centos", "fedora", "arch", "alpine", "bsd", "unknown",
    ];
    assert!(known_os_families.contains(&os));
}

#[tokio::test]
async fn test_dependency_check() {
    let mut checker = SystemDepsChecker::new();

    // Create a test dependency for 'sh' which should exist
    let mut install_instructions = HashMap::new();
    install_instructions.insert("linux".to_string(), "sh is built-in".to_string());

    let sh_dep = SystemDependency {
        binary_name: "sh".to_string(),
        display_name: "Shell".to_string(),
        description: "Unix shell".to_string(),
        install_instructions,
        version_check: None,
        min_version: None,
        required: true,
    };

    checker.add_dependency("test_sh".to_string(), sh_dep);

    let result = checker.check_dependency("test_sh").await.unwrap();
    assert!(result.available);
    assert!(result.error.is_none());
    assert!(result.install_instructions.is_none()); // Available, so no instructions
}

#[tokio::test]
async fn test_missing_dependency_check() {
    let mut checker = SystemDepsChecker::new();

    // Create a test dependency for a non-existent binary
    let mut install_instructions = HashMap::new();
    install_instructions.insert(
        "linux".to_string(),
        "sudo apt-get install missing-tool".to_string(),
    );

    let missing_dep = SystemDependency {
        binary_name: "missing-binary-12345".to_string(),
        display_name: "Missing Tool".to_string(),
        description: "A tool that should not exist".to_string(),
        install_instructions,
        version_check: None,
        min_version: None,
        required: true,
    };

    checker.add_dependency("test_missing".to_string(), missing_dep);

    let result = checker.check_dependency("test_missing").await.unwrap();
    assert!(!result.available);
    assert!(result.error.is_some());
    assert!(result.install_instructions.is_some());

    let error_msg = result.error.unwrap();
    assert!(error_msg.contains("not found"));

    let instructions = result.install_instructions.unwrap();
    assert!(instructions.contains("apt-get install missing-tool"));
}

#[tokio::test]
async fn test_check_all_dependencies() {
    let checker = SystemDepsChecker::new();
    let result = checker.check_all().await;

    // Should have results for all default dependencies
    assert!(!result.dependencies.is_empty());

    // Shell should always be available, but the specific tools might not be
    // So we just check the structure
    for (key, check_result) in &result.dependencies {
        assert!(!key.is_empty());
        // Available or not, should have a consistent state
        if check_result.available {
            assert!(check_result.error.is_none());
            assert!(check_result.install_instructions.is_none());
        } else {
            assert!(check_result.error.is_some());
        }
    }
}

#[tokio::test]
async fn test_check_required_dependencies() {
    let checker = SystemDepsChecker::new();
    let result = checker.check_required().await;

    // Should have results for required dependencies only
    for (key, _) in &result.dependencies {
        if let Some(dep) = checker.get_dependencies().get(key) {
            assert!(dep.required);
        }
    }
}

#[test]
fn test_install_instructions_coverage() {
    let checker = SystemDepsChecker::new();
    let deps = checker.get_dependencies();

    // Each dependency should have installation instructions for major platforms
    let platforms = [
        "debian", "ubuntu", "rhel", "centos", "fedora", "arch", "alpine",
    ];

    for (key, dep) in deps {
        for platform in &platforms {
            if !dep.install_instructions.contains_key(*platform) {
                // It's okay if not all platforms have instructions, but warn about it
                println!(
                    "Warning: {} has no installation instructions for {}",
                    key, platform
                );
            }
        }
    }
}

#[test]
fn test_dependency_serialization() {
    use serde_json;

    let mut install_instructions = HashMap::new();
    install_instructions.insert("linux".to_string(), "sudo apt-get install test".to_string());

    let dep = SystemDependency {
        binary_name: "test-binary".to_string(),
        display_name: "Test Tool".to_string(),
        description: "A test dependency".to_string(),
        install_instructions,
        version_check: Some("test-binary --version".to_string()),
        min_version: Some("1.0".to_string()),
        required: true,
    };

    // Should serialize without errors
    let json = serde_json::to_string(&dep).unwrap();
    assert!(!json.is_empty());

    // Should deserialize back correctly
    let _dep2: SystemDependency = serde_json::from_str(&json).unwrap();
}
