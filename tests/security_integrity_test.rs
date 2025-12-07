//! Runtime integrity checking system tests

use anyhow::Result;
use fuji::security::integrity::{
    HashAlgorithm, IntegrityConfig, IntegrityResponseConfig, IntegrityStatus, IntegrityViolation,
    IntegrityViolationType, MemoryRegion, ProcessInfo, RuntimeIntegrityChecker, ViolationSeverity,
    ViolationStatus,
};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use tempfile::{NamedTempFile, TempDir};

#[tokio::test]
async fn test_integrity_config_default_values() -> Result<()> {
    let config = IntegrityConfig::default();

    assert!(
        config.enable_code_integrity,
        "Code integrity should be enabled by default"
    );
    assert!(
        config.enable_memory_integrity,
        "Memory integrity should be enabled by default"
    );
    assert!(
        config.enable_data_integrity,
        "Data integrity should be enabled by default"
    );
    assert_eq!(
        config.check_interval, 300,
        "Default check interval should be 300 seconds"
    );
    assert_eq!(
        config.alert_threshold, 3,
        "Default alert threshold should be 3"
    );
    assert_eq!(
        config.hash_algorithm,
        HashAlgorithm::Sha256,
        "Default hash algorithm should be SHA-256"
    );
    assert!(
        !config.monitored_paths.is_empty(),
        "Should have default monitored paths"
    );
    assert!(
        !config.critical_libraries.is_empty(),
        "Should have default critical libraries"
    );

    println!("✓ Integrity config default values test passed");
    Ok(())
}

#[tokio::test]
async fn test_hash_algorithms_consistency() -> Result<()> {
    let test_data = b"fuji integrity test data";

    // Test SHA-256
    let sha256_hash1 = HashAlgorithm::Sha256.hash_string(test_data);
    let sha256_hash2 = HashAlgorithm::Sha256.hash_string(test_data);
    assert_eq!(
        sha256_hash1, sha256_hash2,
        "SHA-256 should be deterministic"
    );
    assert_eq!(
        sha256_hash1.len(),
        64,
        "SHA-256 should produce 64-character hex string"
    );

    // Test SHA-512
    let sha512_hash1 = HashAlgorithm::Sha512.hash_string(test_data);
    let sha512_hash2 = HashAlgorithm::Sha512.hash_string(test_data);
    assert_eq!(
        sha512_hash1, sha512_hash2,
        "SHA-512 should be deterministic"
    );
    assert_eq!(
        sha512_hash1.len(),
        128,
        "SHA-512 should produce 128-character hex string"
    );

    // Verify different algorithms produce different hashes
    assert_ne!(
        sha256_hash1, sha512_hash1,
        "Different algorithms should produce different hashes"
    );

    println!("✓ Hash algorithms consistency test passed");
    Ok(())
}

#[tokio::test]
async fn test_integrity_violation_creation() -> Result<()> {
    let violation = IntegrityViolation {
        id: "test-violation-001".to_string(),
        violation_type: IntegrityViolationType::DataCorruption {
            expected_checksum: "abc123def456".to_string(),
            actual_checksum: "def456abc123".to_string(),
            file_path: PathBuf::from("/etc/fuji/config.toml"),
        },
        timestamp: chrono::Utc::now(),
        severity: ViolationSeverity::High,
        source_process: ProcessInfo {
            pid: 1234,
            ppid: 1,
            name: "fuji".to_string(),
            command_line: "fuji daemon".to_string(),
            executable_path: PathBuf::from("/usr/local/bin/fuji"),
            uid: 1000,
            gid: 1000,
            start_time: chrono::Utc::now(),
        },
        context: HashMap::from([
            ("user".to_string(), "testuser".to_string()),
            ("action".to_string(), "file_modification".to_string()),
        ]),
        status: ViolationStatus::New,
    };

    assert_eq!(violation.id, "test-violation-001");
    assert_eq!(violation.severity, ViolationSeverity::High);
    assert_eq!(violation.status, ViolationStatus::New);
    assert_eq!(violation.source_process.pid, 1234);
    assert_eq!(violation.context.get("user"), Some(&"testuser".to_string()));

    if let IntegrityViolationType::DataCorruption {
        file_path,
        ..
    } = violation.violation_type
    {
        assert_eq!(file_path, PathBuf::from("/etc/fuji/config.toml"));
    } else {
        panic!("Expected DataCorruption violation type");
    }

    println!("✓ Integrity violation creation test passed");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_runtime_integrity_checker_creation() -> Result<()> {
    // TODO: This test accesses private fields and needs to be refactored to use public APIs
    let config = IntegrityConfig::default();
    let _checker = RuntimeIntegrityChecker::new(config)?;

    // The following checks access private fields and need to be updated
    // assert!(!checker.executable_path.as_os_str().is_empty());
    // assert_eq!(checker.process_info.pid, std::process::id());
    // assert!(!checker.process_info.name.is_empty());
    // assert!(!checker.process_info.executable_path.as_os_str().is_empty());

    println!("✓ Runtime integrity checker creation test passed (simplified)");
    Ok(())
}

#[tokio::test]
async fn test_file_hash_computation() -> Result<()> {
    let config = IntegrityConfig::default();
    let checker = RuntimeIntegrityChecker::new(config)?;

    // Create a temporary file with known content
    let mut temp_file = NamedTempFile::new()?;
    let test_content = b"fuji integrity test content";
    std::io::Write::write_all(&mut temp_file, test_content)?;

    // Compute hash
    let hash1 = checker.compute_file_hash(temp_file.path())?;
    let hash2 = checker.compute_file_hash(temp_file.path())?;

    // Verify consistency
    assert_eq!(hash1, hash2, "File hashes should be consistent");
    assert!(!hash1.is_empty(), "Hash should not be empty");

    // Modify file and verify hash changes
    let mut temp_file2 = NamedTempFile::new()?;
    temp_file2.write_all(b"different content")?;
    let hash3 = checker.compute_file_hash(temp_file2.path())?;
    assert_ne!(
        hash1, hash3,
        "Different content should produce different hashes"
    );

    println!("✓ File hash computation test passed");
    Ok(())
}

#[tokio::test]
async fn test_library_path_detection() -> Result<()> {
    let config = IntegrityConfig::default();
    let checker = RuntimeIntegrityChecker::new(config)?;

    // Test finding common libraries
    let common_libraries = vec!["libc.so.6", "libpthread.so.0", "libm.so.6"];
    let mut found_count = 0;

    for library in &common_libraries {
        if let Some(lib_path) = checker.find_library_path(library) {
            assert!(lib_path.exists(), "Library path should exist");
            assert!(
                lib_path.to_string_lossy().contains(library),
                "Path should contain library name"
            );
            found_count += 1;
        }
    }

    // Should find at least one library on most Linux systems
    assert!(found_count > 0, "Should find at least one system library");

    println!(
        "✓ Library path detection test passed (found {}/{} libraries)",
        found_count,
        common_libraries.len()
    );
    Ok(())
}

#[tokio::test]
async fn test_memory_region_structure() -> Result<()> {
    let region = MemoryRegion {
        start: 0x10000000,
        end: 0x20000000,
        size: 0x10000000,
        protection: "r-xp".to_string(),
        name: Some("test_region".to_string()),
    };

    assert_eq!(region.start, 0x10000000);
    assert_eq!(region.end, 0x20000000);
    assert_eq!(region.size, 0x10000000);
    assert_eq!(region.protection, "r-xp");
    assert_eq!(region.name, Some("test_region".to_string()));

    println!("✓ Memory region structure test passed");
    Ok(())
}

#[tokio::test]
async fn test_integrity_status_structure() -> Result<()> {
    let status = IntegrityStatus {
        is_baseline_established: true,
        baseline_created_at: Some(chrono::Utc::now()),
        total_violations: 5,
        active_violations: 2,
        last_violation: None,
        last_check_time: chrono::Utc::now(),
    };

    assert!(status.is_baseline_established);
    assert!(status.baseline_created_at.is_some());
    assert_eq!(status.total_violations, 5);
    assert_eq!(status.active_violations, 2);
    assert!(status.last_violation.is_none());

    println!("✓ Integrity status structure test passed");
    Ok(())
}

#[tokio::test]
async fn test_violation_severity_levels() -> Result<()> {
    let severities = vec![
        (ViolationSeverity::Low, 0),
        (ViolationSeverity::Medium, 1),
        (ViolationSeverity::High, 2),
        (ViolationSeverity::Critical, 3),
    ];

    for (severity, expected_value) in severities {
        assert_eq!(
            severity as i32, expected_value,
            "Severity level {:?} should have value {}",
            severity, expected_value
        );
    }

    println!("✓ Violation severity levels test passed");
    Ok(())
}

#[tokio::test]
async fn test_violation_status_transitions() -> Result<()> {
    let mut violation_status = ViolationStatus::New;

    // Test status transitions
    assert_eq!(violation_status, ViolationStatus::New);

    violation_status = ViolationStatus::Investigating;
    assert_eq!(violation_status, ViolationStatus::Investigating);

    violation_status = ViolationStatus::Confirmed;
    assert_eq!(violation_status, ViolationStatus::Confirmed);

    violation_status = ViolationStatus::Resolved;
    assert_eq!(violation_status, ViolationStatus::Resolved);

    println!("✓ Violation status transitions test passed");
    Ok(())
}

#[tokio::test]
async fn test_code_integrity_violation_type() -> Result<()> {
    let region = MemoryRegion {
        start: 0x400000,
        end: 0x500000,
        size: 0x100000,
        protection: "r-xp".to_string(),
        name: Some("text_segment".to_string()),
    };

    let violation_type = IntegrityViolationType::CodeModification {
        expected_hash: "a1b2c3d4e5f6".to_string(),
        actual_hash: "f6e5d4c3b2a1".to_string(),
        region: region.clone(),
    };

    if let IntegrityViolationType::CodeModification {
        expected_hash,
        actual_hash,
        region: r,
    } = violation_type
    {
        assert_eq!(expected_hash, "a1b2c3d4e5f6");
        assert_eq!(actual_hash, "f6e5d4c3b2a1");
        assert_eq!(r.start, 0x400000);
        assert_eq!(r.end, 0x500000);
    } else {
        panic!("Expected CodeModification violation type");
    }

    println!("✓ Code integrity violation type test passed");
    Ok(())
}

#[tokio::test]
async fn test_library_injection_violation_type() -> Result<()> {
    let violation_type = IntegrityViolationType::LibraryInjection {
        library_path: PathBuf::from("/tmp/malicious.so"),
        injection_method: "LD_PRELOAD".to_string(),
    };

    if let IntegrityViolationType::LibraryInjection {
        library_path,
        injection_method,
    } = violation_type
    {
        assert_eq!(library_path, PathBuf::from("/tmp/malicious.so"));
        assert_eq!(injection_method, "LD_PRELOAD");
    } else {
        panic!("Expected LibraryInjection violation type");
    }

    println!("✓ Library injection violation type test passed");
    Ok(())
}

#[tokio::test]
async fn test_control_flow_integrity_violation_type() -> Result<()> {
    let violation_type = IntegrityViolationType::ControlFlowViolation {
        expected_target: 0x401000,
        actual_target: 0xdeadbeef,
        function_name: "authenticate_user".to_string(),
    };

    if let IntegrityViolationType::ControlFlowViolation {
        expected_target,
        actual_target,
        function_name,
    } = violation_type
    {
        assert_eq!(expected_target, 0x401000);
        assert_eq!(actual_target, 0xdeadbeef);
        assert_eq!(function_name, "authenticate_user");
    } else {
        panic!("Expected ControlFlowViolation violation type");
    }

    println!("✓ Control flow integrity violation type test passed");
    Ok(())
}

#[tokio::test]
async fn test_memory_protection_violation_type() -> Result<()> {
    let violation_type = IntegrityViolationType::MemoryProtectionViolation {
        address: 0x7fff12345678,
        operation: "write".to_string(),
        protection_flags: 0x5, // PROT_READ | PROT_EXEC
    };

    if let IntegrityViolationType::MemoryProtectionViolation {
        address,
        operation,
        protection_flags,
    } = violation_type
    {
        assert_eq!(address, 0x7fff12345678);
        assert_eq!(operation, "write");
        assert_eq!(protection_flags, 0x5);
    } else {
        panic!("Expected MemoryProtectionViolation violation type");
    }

    println!("✓ Memory protection violation type test passed");
    Ok(())
}

#[tokio::test]
async fn test_runtime_hooking_violation_type() -> Result<()> {
    let violation_type = IntegrityViolationType::RuntimeHooking {
        function_name: "open".to_string(),
        hook_address: 0x12345678,
        original_address: 0x87654321,
    };

    if let IntegrityViolationType::RuntimeHooking {
        function_name,
        hook_address,
        original_address,
    } = violation_type
    {
        assert_eq!(function_name, "open");
        assert_eq!(hook_address, 0x12345678);
        assert_eq!(original_address, 0x87654321);
    } else {
        panic!("Expected RuntimeHooking violation type");
    }

    println!("✓ Runtime hooking violation type test passed");
    Ok(())
}

#[tokio::test]
async fn test_integrity_response_config() -> Result<()> {
    let config = IntegrityResponseConfig::default();

    assert!(config.enable_alerts, "Alerts should be enabled by default");
    assert!(
        !config.enable_termination,
        "Termination should be disabled by default"
    );
    assert!(
        !config.enable_core_dump,
        "Core dump should be disabled by default"
    );
    assert!(
        config.enable_secure_shutdown,
        "Secure shutdown should be enabled by default"
    );
    assert!(
        !config.alert_recipients.is_empty(),
        "Should have default alert recipients"
    );
    assert!(
        config.custom_response_script.is_none(),
        "Custom script should be None by default"
    );

    // Test custom config
    let mut custom_config = IntegrityResponseConfig::default();
    custom_config.enable_termination = true;
    custom_config.enable_core_dump = true;
    custom_config
        .alert_recipients
        .push("admin@company.com".to_string());

    assert!(custom_config.enable_termination);
    assert!(custom_config.enable_core_dump);
    assert_eq!(custom_config.alert_recipients.len(), 2);

    println!("✓ Integrity response config test passed");
    Ok(())
}

#[tokio::test]
async fn test_integrity_checker_file_integrity() -> Result<()> {
    let config = IntegrityConfig::default();
    let checker = RuntimeIntegrityChecker::new(config)?;

    // Create temporary test files
    let temp_dir = TempDir::new()?;
    let test_file1 = temp_dir.path().join("test1.txt");
    let test_file2 = temp_dir.path().join("test2.txt");

    fs::write(&test_file1, b"test content 1")?;
    fs::write(&test_file2, b"test content 2")?;

    // Compute hashes
    let hash1_1 = checker.compute_file_hash(&test_file1)?;
    let hash1_2 = checker.compute_file_hash(&test_file2)?;

    // Modify first file
    fs::write(&test_file1, b"modified content")?;
    let hash2_1 = checker.compute_file_hash(&test_file1)?;
    let hash2_2 = checker.compute_file_hash(&test_file2)?; // Should be unchanged

    assert_ne!(hash1_1, hash2_1, "Hash should change when file is modified");
    assert_eq!(
        hash1_2, hash2_2,
        "Hash should remain same for unchanged file"
    );

    println!("✓ Integrity checker file integrity test passed");
    Ok(())
}

#[tokio::test]
async fn test_hash_algorithm_comparison() -> Result<()> {
    let test_data = b"comprehensive test data for hash algorithm comparison";

    let algorithms = vec![
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha512,
        HashAlgorithm::Sha3,
        HashAlgorithm::Blake3,
    ];

    let mut hashes = Vec::new();

    for algorithm in algorithms {
        let hash = algorithm.hash_string(test_data);
        println!("{:?}: {}", algorithm, hash);
        hashes.push((algorithm, hash));
    }

    // Verify all hashes are unique
    for (i, (_, hash_i)) in hashes.iter().enumerate() {
        for (j, (_, hash_j)) in hashes.iter().enumerate() {
            if i != j {
                assert_ne!(
                    hash_i, hash_j,
                    "Hashes from different algorithms should be unique"
                );
            }
        }
    }

    // Verify SHA-512 produces longer hash than SHA-256
    let sha256_hash = hashes
        .iter()
        .find(|(algo, _)| matches!(algo, HashAlgorithm::Sha256))
        .unwrap()
        .1
        .clone();
    let sha512_hash = hashes
        .iter()
        .find(|(algo, _)| matches!(algo, HashAlgorithm::Sha512))
        .unwrap()
        .1
        .clone();
    assert!(
        sha512_hash.len() > sha256_hash.len(),
        "SHA-512 should produce longer hash than SHA-256"
    );

    println!("✓ Hash algorithm comparison test passed");
    Ok(())
}

#[tokio::test]
async fn test_violation_context_manipulation() -> Result<()> {
    let mut context = HashMap::new();

    // Add context information
    context.insert("source_ip".to_string(), "192.168.1.100".to_string());
    context.insert("user_agent".to_string(), "Mozilla/5.0".to_string());
    context.insert("request_path".to_string(), "/api/v1/mounts".to_string());

    // Verify context contents
    assert_eq!(context.len(), 3);
    assert_eq!(context.get("source_ip"), Some(&"192.168.1.100".to_string()));
    assert_eq!(context.get("user_agent"), Some(&"Mozilla/5.0".to_string()));
    assert_eq!(
        context.get("request_path"),
        Some(&"/api/v1/mounts".to_string())
    );

    // Modify context
    context.insert("source_ip".to_string(), "10.0.0.1".to_string());
    context.remove("user_agent");

    assert_eq!(context.get("source_ip"), Some(&"10.0.0.1".to_string()));
    assert_eq!(context.get("user_agent"), None);
    assert_eq!(context.len(), 2);

    println!("✓ Violation context manipulation test passed");
    Ok(())
}

#[tokio::test]
async fn test_process_info_creation() -> Result<()> {
    let current_pid = std::process::id();
    let process_info = ProcessInfo {
        pid: current_pid,
        ppid: 1, // Usually init or the shell that started this test
        name: "test_process".to_string(),
        command_line: "cargo test security_integrity_test".to_string(),
        executable_path: PathBuf::from("/usr/local/bin/fuji"),
        uid: 1000,
        gid: 1000,
        start_time: chrono::Utc::now(),
    };

    assert_eq!(process_info.pid, current_pid);
    assert_eq!(process_info.ppid, 1);
    assert_eq!(process_info.name, "test_process");
    assert_eq!(process_info.uid, 1000);
    assert_eq!(process_info.gid, 1000);

    println!("✓ Process info creation test passed");
    Ok(())
}

#[tokio::test]
async fn test_integrity_violation_serialization() -> Result<()> {
    let violation = IntegrityViolation {
        id: "test-serialization-001".to_string(),
        violation_type: IntegrityViolationType::DataCorruption {
            expected_checksum: "expected123".to_string(),
            actual_checksum: "actual456".to_string(),
            file_path: PathBuf::from("/test/file.txt"),
        },
        timestamp: chrono::Utc::now(),
        severity: ViolationSeverity::Medium,
        source_process: ProcessInfo {
            pid: 9999,
            ppid: 1,
            name: "test".to_string(),
            command_line: "test".to_string(),
            executable_path: PathBuf::from("/test"),
            uid: 0,
            gid: 0,
            start_time: chrono::Utc::now(),
        },
        context: HashMap::from([
            ("key1".to_string(), "value1".to_string()),
            ("key2".to_string(), "value2".to_string()),
        ]),
        status: ViolationStatus::New,
    };

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&violation)?;

    // Deserialize from JSON
    let deserialized: IntegrityViolation = serde_json::from_str(&json)?;

    // Verify serialization/deserialization preserved data
    assert_eq!(violation.id, deserialized.id);
    assert_eq!(violation.severity, deserialized.severity);
    assert_eq!(violation.status, deserialized.status);
    assert_eq!(
        violation.source_process.pid,
        deserialized.source_process.pid
    );
    assert_eq!(violation.context.len(), deserialized.context.len());

    println!("✓ Integrity violation serialization test passed");
    Ok(())
}

#[tokio::test]
async fn test_violation_severity_comparison() -> Result<()> {
    let severities = vec![
        ViolationSeverity::Low,
        ViolationSeverity::Medium,
        ViolationSeverity::High,
        ViolationSeverity::Critical,
    ];

    // Test severity ordering (by integer value)
    for i in 0..severities.len() {
        for j in i + 1..severities.len() {
            assert!(
                (severities[i] as i32) < (severities[j] as i32),
                "{:?} should have lower severity value than {:?}",
                severities[i],
                severities[j]
            );
        }
    }

    println!("✓ Violation severity comparison test passed");
    Ok(())
}

#[test]
fn test_memory_mapping_parsing() -> Result<()> {
    use fuji::security::integrity::MemoryMapping;

    // Test valid memory mapping line
    let line = "555555554000-555555555000 r--p 00000000 08:01 12345678 /usr/bin/fuji";
    let mapping = MemoryMapping::from_line(line)?;

    assert_eq!(mapping.start, 0x555555554000);
    assert_eq!(mapping.end, 0x555555555000);
    assert_eq!(mapping.permissions, "r--p");
    assert_eq!(mapping.path, "/usr/bin/fuji");

    // Test anonymous mapping
    let anon_line = "7fff12345000-7fff12346000 rw-p 00000000 00:00 0";
    let anon_mapping = MemoryMapping::from_line(anon_line)?;

    assert_eq!(anon_mapping.start, 0x7fff12345000);
    assert_eq!(anon_mapping.end, 0x7fff12346000);
    assert_eq!(anon_mapping.permissions, "rw-p");
    assert_eq!(anon_mapping.path, "");

    println!("✓ Memory mapping parsing test passed");
    Ok(())
}

#[tokio::test]
async fn test_config_customization() -> Result<()> {
    let mut config = IntegrityConfig::default();

    // Customize configuration
    config.check_interval = 600; // 10 minutes
    config.alert_threshold = 5;
    config.enable_code_integrity = false;
    config.monitored_paths.push(PathBuf::from("/custom/path"));
    config.critical_libraries.push("custom_lib.so".to_string());

    assert_eq!(config.check_interval, 600);
    assert_eq!(config.alert_threshold, 5);
    assert!(!config.enable_code_integrity);
    assert!(
        config
            .monitored_paths
            .contains(&PathBuf::from("/custom/path"))
    );
    assert!(
        config
            .critical_libraries
            .contains(&"custom_lib.so".to_string())
    );

    println!("✓ Config customization test passed");
    Ok(())
}

#[tokio::test]
async fn test_hash_performance() -> Result<()> {
    let test_data = vec![0u8; 1024 * 1024]; // 1MB of data
    let algorithms = vec![HashAlgorithm::Sha256, HashAlgorithm::Sha512];

    for algorithm in algorithms {
        let start = std::time::Instant::now();
        let _hash = algorithm.hash_string(&test_data);
        let duration = start.elapsed();

        println!("{:?} took {:?} to hash 1MB", algorithm, duration);
        assert!(
            duration.as_secs() < 1,
            "Hashing should complete in under 1 second"
        );
    }

    println!("✓ Hash performance test passed");
    Ok(())
}

#[tokio::test]
async fn test_violation_count_tracking() -> Result<()> {
    let config = IntegrityConfig::default();
    let checker = RuntimeIntegrityChecker::new(config)?;

    // Initially should have no violations
    let initial_status = checker.get_integrity_status().await?;
    assert_eq!(initial_status.total_violations, 0);
    assert_eq!(initial_status.active_violations, 0);

    // Test clearing violations (shouldn't error even when empty)
    checker.clear_violations().await?;
    let status_after_clear = checker.get_integrity_status().await?;
    assert_eq!(status_after_clear.total_violations, 0);

    println!("✓ Violation count tracking test passed");
    Ok(())
}

// Integration test for baseline creation and update
#[tokio::test]
async fn test_baseline_creation_and_update() -> Result<()> {
    let config = IntegrityConfig::default();
    let checker = RuntimeIntegrityChecker::new(config)?;

    // Check initial state
    let status_before = checker.get_integrity_status().await?;
    assert!(!status_before.is_baseline_established);

    // Note: We can't actually create the baseline in tests because it requires
    // reading system files and might fail in CI environments
    // But we can test the status reporting

    println!("✓ Baseline creation and update test passed (status verification only)");
    Ok(())
}

// Stress test for hash computation
#[tokio::test]
async fn test_hash_computation_stress() -> Result<()> {
    let config = IntegrityConfig::default();
    let checker = RuntimeIntegrityChecker::new(config)?;

    // Create temporary file
    let mut temp_file = NamedTempFile::new()?;
    let test_content = b"stress test content for repeated hashing";
    std::io::Write::write_all(&mut temp_file, test_content)?;

    // Compute hash multiple times
    let iterations = 100;
    let mut hashes = Vec::new();

    for _ in 0..iterations {
        let hash = checker.compute_file_hash(temp_file.path())?;
        hashes.push(hash);
    }

    // All hashes should be identical
    let first_hash = &hashes[0];
    for hash in &hashes[1..] {
        assert_eq!(hash, first_hash, "All hashes should be identical");
    }

    println!(
        "✓ Hash computation stress test passed ({} iterations)",
        iterations
    );
    Ok(())
}

#[tokio::test]
async fn test_large_file_hashing() -> Result<()> {
    let config = IntegrityConfig::default();
    let checker = RuntimeIntegrityChecker::new(config)?;

    // Create larger temporary file (1MB)
    let mut temp_file = NamedTempFile::new()?;
    let large_content = vec![0u8; 1024 * 1024];
    temp_file.write_all(&large_content)?;

    let start = std::time::Instant::now();
    let hash = checker.compute_file_hash(temp_file.path())?;
    let duration = start.elapsed();

    assert!(!hash.is_empty(), "Hash should not be empty");
    assert!(
        duration.as_secs() < 5,
        "Large file hashing should complete in under 5 seconds"
    );

    println!("✓ Large file hashing test passed (took {:?})", duration);
    Ok(())
}
