//! Integration tests for path traversal protection in mount operations

use fuji::mount::drivers::validation::MountUrlValidator;
use fuji::mount::drivers::{NfsHandler, SmbHandler, SshfsHandler};
use fuji::mount::MountHandler;

#[test]
fn test_nfs_path_traversal_protection() {
    let handler = NfsHandler::new();
    let validator = MountUrlValidator::new().unwrap();

    // These should be rejected
    let malicious_urls = vec![
        "nfs://evil.com/../../../etc/passwd",
        "nfs://server.com/../../../../root/.ssh",
        "nfs://host.com/export/../../../bin/sh",
        "nfs://example.com/data/../../etc/shadow",
        "nfs://test.com/path/../../../../boot/vmlinuz",
        "nfs://malicious.com/share/../../../usr/bin/sudo",
        "nfs://attacker.com/docs/../../../var/log/auth.log",
        "nfs://bad.com/files/../../../home/user/.aws/credentials",
        "nfs://hacker.com/data/../../../etc/hosts",
        "nfs://victim.com/export/../../../proc/version",
    ];

    for url in &malicious_urls {
        println!("Testing malicious URL: {}", url);
        assert!(
            validator.validate_url(url).is_err(),
            "URL should be rejected: {}",
            url
        );
        assert!(handler.parse_url(url).is_err(), "Parse should fail: {}", url);
    }
}

#[test]
fn test_smb_path_traversal_protection() {
    let handler = SmbHandler::new();
    let validator = MountUrlValidator::new().unwrap();

    // These should be rejected
    let malicious_urls = vec![
        "smb://evil.com/../../../Windows/System32/config/sam",
        "smb://server.com/share/../../Users/Administrator/.ssh",
        "cifs://host.com/data/../../../Windows/System32/drivers/etc/hosts",
        "smb://example.com/share/../../../Program Files/evil.exe",
        "smb://malicious.com/docs/../../Windows/System32/cmd.exe",
        "cifs://attacker.com/files/../../../Users/Default/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
        "smb://bad.com/share/../../../Windows/System32/config/SECURITY",
        "smb://hacker.com/data/../../../Users/Administrator/Desktop/passwords.txt",
    ];

    for url in &malicious_urls {
        println!("Testing malicious SMB URL: {}", url);
        assert!(
            validator.validate_url(url).is_err(),
            "URL should be rejected: {}",
            url
        );
        assert!(handler.parse_url(url).is_err(), "Parse should fail: {}", url);
    }
}

#[test]
fn test_sshfs_path_traversal_protection() {
    let handler = SshfsHandler::new();
    let validator = MountUrlValidator::new().unwrap();

    // These should be rejected
    let malicious_urls = vec![
        "sshfs://user@evil.com/../../../etc/passwd",
        "sshfs://root@server.com/../../../root/.ssh/id_rsa",
        "sshfs://admin@host.com/home/../../../etc/shadow",
        "sshfs://user@example.com/data/../../../.bash_history",
        "sshfs://attacker@malicious.com/.ssh/../../../etc/sudoers",
        "sshfs://victim@hacker.com/home/../../../proc/cpuinfo",
        "sshfs://baduser@bad.com/docs/../../../var/log/auth.log",
        "sshfs://admin@server.com/config/../../../root/.aws/credentials",
    ];

    for url in &malicious_urls {
        println!("Testing malicious SSHFS URL: {}", url);
        assert!(
            validator.validate_url(url).is_err(),
            "URL should be rejected: {}",
            url
        );
        assert!(handler.parse_url(url).is_err(), "Parse should fail: {}", url);
    }
}

#[test]
fn test_dangerous_path_components() {
    let validator = MountUrlValidator::new().unwrap();

    // These should be rejected due to dangerous path components
    let dangerous_urls = vec![
        "nfs://server.com/etc/passwd",
        "nfs://server.com/bin/sh",
        "nfs://server.com/usr/bin/sudo",
        "nfs://server.com/root/.ssh",
        "nfs://server.com/home/user/.env",
        "nfs://server.com/tmp/.key",
        "nfs://server.com/var/log/.secret",
        "nfs://server.com/share/malware.exe",
        "nfs://server.com/docs/script.js",
        "nfs://server.com/project/.git",
        "nfs://server.com/app/node_modules",
        "nfs://server.com/data/.config",
        "nfs://server.com/config/.bashrc",
        "nfs://server.com/home/.ssh/id_rsa",
        "nfs://server.com/opt/.pem",
    ];

    for url in &dangerous_urls {
        println!("Testing dangerous URL: {}", url);
        assert!(
            validator.validate_url(url).is_err(),
            "URL should be rejected: {}",
            url
        );
    }
}

#[test]
fn test_encoded_path_traversal_attempts() {
    let validator = MountUrlValidator::new().unwrap();

    // These should be rejected - URL encoded path traversal attempts
    let encoded_attacks = vec![
        "nfs://evil.com/%2e%2e%2f%2e%2e%2fetc%2fpasswd",  // ../../../etc/passwd
        "nfs://server.com/..%2f..%2f..%2fetc%2fshadow", // /../../etc/shadow
        "nfs://host.com/data%2f..%2f..%2froot%2fssh", // /data/../../root/ssh
        "nfs://example.com/share%2F..%2F..%2F..%2Fbin%2Fsh", // /share/../../bin/sh
    ];

    for url in &encoded_attacks {
        println!("Testing encoded attack URL: {}", url);
        assert!(
            validator.validate_url(url).is_err(),
            "URL should be rejected: {}",
            url
        );
    }
}

#[test]
fn test_unicode_and_special_char_attacks() {
    let validator = MountUrlValidator::new().unwrap();

    // These should be rejected - Unicode and special character attacks
    let special_attacks = vec![
        "nfs://server.com/..\u{0000}/etc/passwd", // Null byte
        "nfs://evil.com/..../..//etc/passwd",     // Obfuscated traversal
        "nfs://hacker.com/..//etc/passwd",       // Double slash with traversal
        "nfs://bad.com/path/../../../etc/passwd/", // Trailing slash
        "nfs://attacker.com/..\\../..\\..\\windows\\system32\\cmd.exe", // Windows style
    ];

    for url in &special_attacks {
        println!("Testing special char attack URL: {}", url);
        assert!(
            validator.validate_url(url).is_err(),
            "URL should be rejected: {}",
            url
        );
    }
}

#[test]
fn test_mount_point_generation_safety() {
    let handler = NfsHandler::new();
    let validator = MountUrlValidator::new().unwrap();

    // First test individual components
    println!("=== Testing individual path components ===");
    let components = vec!["share", "data", "etc", "documents", "files"];
    for component in components {
        let result = validator.sanitize_path_component(component);
        println!("Component '{}': {:?}", component, result);
    }

    // These should generate safe mount points even with malicious input
    let test_cases = vec![
        ("nfs://server.com/../../../etc/passwd", "should fail"),
        ("nfs://server.com/share/data", "should succeed"),
        ("nfs://evil.com/../../root/.ssh", "should fail"),
        ("nfs://good.com/export/data", "should succeed"),
    ];

    println!("\n=== Testing mount point generation ===");
    for (url, expected) in test_cases {
        println!("Testing mount point generation for: {}", url);
        let result = handler.generate_mount_point(url);

        match expected {
            "should fail" => {
                if let Err(ref e) = result {
                    println!("✓ Correctly failed with error: {}", e);
                }
                assert!(result.is_err(), "Mount point generation should fail for malicious URL: {}", url);
            }
            "should succeed" => {
                if let Err(ref e) = result {
                    println!("✗ Unexpectedly failed with error: {}", e);
                }
                assert!(result.is_ok(), "Mount point generation should succeed for valid URL: {}", url);
                if let Ok(mount_point) = result {
                    let mount_str = mount_point.to_string_lossy();
                    println!("✓ Generated mount point: {}", mount_str);
                    // Ensure no path traversal in generated mount point
                    assert!(!mount_str.contains(".."), "Mount point should not contain '..': {}", mount_str);
                    assert!(!mount_str.contains("/etc/"), "Mount point should not contain /etc/: {}", mount_str);
                    assert!(!mount_str.contains("/bin/"), "Mount point should not contain /bin/: {}", mount_str);
                }
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn test_case_insensitive_dangerous_components() {
    let validator = MountUrlValidator::new().unwrap();

    // These should be rejected - case variations of dangerous components
    let case_variations = vec![
        "nfs://server.com/ETC/passwd",
        "nfs://server.com/etc/PASSWD",
        "nfs://server.com/BIN/sh",
        "nfs://server.com/bin/SH",
        "nfs://server.com/Root/.ssh",
        "nfs://server.com/root/.SSH",
        "nfs://server.com/Home/user.env",
        "nfs://server.com/home/.ENV",
        "nfs://server.com/Tmp/.key",
        "nfs://server.com/tmp/.KEY",
    ];

    for url in &case_variations {
        println!("Testing case variation URL: {}", url);
        assert!(
            validator.validate_url(url).is_err(),
            "URL should be rejected: {}",
            url
        );
    }
}

#[test]
fn test_very_deep_nested_traversal() {
    let validator = MountUrlValidator::new().unwrap();

    // Test very deep traversal attempts
    let deep_traversal = vec![
        format!("nfs://server.com/{}", "../".repeat(50)),
        format!("nfs://evil.com/share/{}", "..\\ ".repeat(30)),
        format!("nfs://hacker.com/data/{}", "/..".repeat(100)),
    ];

    for url in &deep_traversal {
        println!("Testing deep traversal URL (length: {})", url.len());
        assert!(
            validator.validate_url(url).is_err(),
            "Deep traversal URL should be rejected: {}",
            &url[..std::cmp::min(50, url.len())]
        );
    }
}