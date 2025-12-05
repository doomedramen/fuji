//! Unit tests for mount options parsing

use fuji::mount::options::{MountOptionParser, MountOptions, PerformanceOptions, SecurityOptions};
use std::collections::HashMap;

#[test]
fn test_nfs_options_parsing() {
    let parser = MountOptionParser::new();

    // Test with various NFS options
    let options_str = "rsize=1M,wsize=2M,soft,timeo=30,retrans=2,tcp,nfsvers=4";
    let parsed = parser.parse(options_str, "nfs").unwrap();

    assert_eq!(parsed.fs_type, "nfs");
    assert_eq!(parsed.options.get("rsize"), Some(&"1048576".to_string()));
    assert_eq!(parsed.options.get("wsize"), Some(&"2097152".to_string()));
    assert_eq!(parsed.options.get("timeo"), Some(&"30".to_string()));
    assert_eq!(parsed.options.get("retrans"), Some(&"2".to_string()));
    assert_eq!(parsed.options.get("tcp"), Some(&"".to_string()));
    assert_eq!(parsed.options.get("nfsvers"), Some(&"4".to_string()));
    assert!(parsed.performance.soft);
    assert_eq!(parsed.performance.timeo, Some(30));
    assert_eq!(parsed.performance.retrans, Some(2));
    assert_eq!(parsed.performance.nfsvers, Some(4));
}

#[test]
fn test_smb_options_parsing() {
    let parser = MountOptionParser::new();

    // Test with SMB/CIFS options
    let options_str = "username=user,password=pass,domain=WORKGROUP,rw,file_mode=0644";
    let parsed = parser.parse(options_str, "cifs").unwrap();

    assert_eq!(parsed.fs_type, "cifs");
    assert_eq!(parsed.options.get("username"), Some(&"user".to_string()));
    assert_eq!(parsed.options.get("password"), Some(&"pass".to_string()));
    assert_eq!(parsed.options.get("domain"), Some(&"WORKGROUP".to_string()));
    assert_eq!(parsed.options.get("rw"), Some(&"".to_string()));
    assert_eq!(parsed.options.get("file_mode"), Some(&"0644".to_string()));
    assert!(!parsed.security.read_only);
}

#[test]
fn test_security_options() {
    let parser = MountOptionParser::new();

    // Test security-related options
    let options_str = "ro,nosuid,nodev,noexec,uid=1000,gid=1000";
    let parsed = parser.parse(options_str, "nfs").unwrap();

    assert!(parsed.security.read_only);
    assert!(parsed.security.nosuid);
    assert!(parsed.security.nodev);
    assert!(parsed.security.noexec);
    assert!(!parsed.security.suid);
    assert_eq!(parsed.security.uid, Some(1000));
    assert_eq!(parsed.security.gid, Some(1000));
}

#[test]
fn test_default_options_nfs() {
    let parser = MountOptionParser::new();

    // Test empty options get defaults for NFS
    let parsed = parser.parse("", "nfs").unwrap();

    // Should have NFS defaults
    assert!(parsed.options.contains_key("hard"));
    assert!(parsed.options.contains_key("intr"));
    assert_eq!(parsed.options.get("rsize"), Some(&"1048576".to_string()));
    assert_eq!(parsed.options.get("wsize"), Some(&"1048576".to_string()));
    assert_eq!(parsed.options.get("timeo"), Some(&"600".to_string()));
    assert_eq!(parsed.options.get("retrans"), Some(&"2".to_string()));
    assert!(!parsed.performance.soft);
    assert!(parsed.performance.intr);
}

#[test]
fn test_default_options_cifs() {
    let parser = MountOptionParser::new();

    // Test empty options get defaults for CIFS
    let parsed = parser.parse("", "cifs").unwrap();

    // Should have CIFS defaults
    assert!(parsed.options.contains_key("rw"));
    assert_eq!(parsed.options.get("rsize"), Some(&"1048576".to_string()));
    assert_eq!(parsed.options.get("wsize"), Some(&"1048576".to_string()));
    assert!(!parsed.security.read_only);
}

#[test]
fn test_boolean_options() {
    let parser = MountOptionParser::new();

    // Test boolean flags
    let options_str = "ro,soft,bg,noatime";
    let parsed = parser.parse(options_str, "nfs").unwrap();

    assert!(parsed.security.read_only);
    assert!(parsed.performance.soft);
    assert!(parsed.options.contains_key("bg"));
    assert!(parsed.options.contains_key("noatime"));
}

#[test]
fn test_invalid_options() {
    let parser = MountOptionParser::new();

    // Test conflicting options
    assert!(parser.parse("ro,rw", "nfs").is_err());

    // Test invalid rsize values
    assert!(parser.parse("rsize=100", "nfs").is_err()); // Too small
    assert!(parser.parse("rsize=200M", "nfs").is_err()); // Too large

    // Test invalid wsize values
    assert!(parser.parse("wsize=100", "nfs").is_err()); // Too small
    assert!(parser.parse("wsize=200M", "nfs").is_err()); // Too large
}

#[test]
fn test_format_options() {
    let parser = MountOptionParser::new();

    let options_str = "rsize=1M,wsize=2M,soft,timeo=30";
    let parsed = parser.parse(options_str, "nfs").unwrap();
    let formatted = parser.format(&parsed);

    // Should round-trip correctly
    let reparsed = parser.parse(&formatted, "nfs").unwrap();
    assert_eq!(parsed.options, reparsed.options);
}

#[test]
fn test_file_permissions() {
    let parser = MountOptionParser::new();

    let options_str = "fmode=0644,dmode=0755";
    let parsed = parser.parse(options_str, "nfs").unwrap();

    assert_eq!(parsed.security.fmode, Some(0o644));
    assert_eq!(parsed.security.dmode, Some(0o0755));
}

#[test]
fn test_mixed_valid_invalid() {
    let parser = MountOptionParser::new();

    // Test with some valid and some invalid options
    let options_str = "rsize=1M,wsize=invalid,soft,timeo=30";
    let result = parser.parse(options_str, "nfs");

    // Should fail due to invalid wsize
    assert!(result.is_err());
}

#[test]
fn test_nfs_version_validation() {
    let parser = MountOptionParser::new();

    // Valid NFS versions
    assert!(parser.parse("nfsvers=3", "nfs").is_ok());
    assert!(parser.parse("nfsvers=4", "nfs").is_ok());

    // Invalid NFS versions
    assert!(parser.parse("nfsvers=2", "nfs").is_err());
    assert!(parser.parse("nfsvers=5", "nfs").is_err());
}

#[test]
fn test_special_characters() {
    let parser = MountOptionParser::new();

    // Test options with special characters in values
    let options_str = "username=user@domain,password=p@ssw0rd";
    let parsed = parser.parse(options_str, "cifs").unwrap();

    assert_eq!(
        parsed.options.get("username"),
        Some(&"user@domain".to_string())
    );
    assert_eq!(
        parsed.options.get("password"),
        Some(&"p@ssw0rd".to_string())
    );
}

#[test]
fn test_empty_values() {
    let parser = MountOptionParser::new();

    // Test options with empty values
    let options_str = "username=,password=";
    let parsed = parser.parse(options_str, "cifs").unwrap();

    assert_eq!(parsed.options.get("username"), Some(&"".to_string()));
    assert_eq!(parsed.options.get("password"), Some(&"".to_string()));
}
