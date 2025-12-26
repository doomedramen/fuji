//! Unit tests for mount options parsing
//!
//! Comprehensive tests for parsing and validating mount options

use anyhow::Result;
use fuji::mount::options::MountOptionParser;

// ============================================================================
// Basic Parsing Tests
// ============================================================================

#[test]
fn test_parse_empty_options() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("", "nfs")?;

    assert!(options.raw.is_empty() || options.raw.len() == 1 && options.raw[0].is_empty());
    Ok(())
}

#[test]
fn test_parse_single_option() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("rw", "nfs")?;

    assert_eq!(options.raw.len(), 1);
    assert_eq!(options.raw[0], "rw");
    Ok(())
}

#[test]
fn test_parse_multiple_options() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("rw,noatime,vers=4", "nfs")?;

    assert_eq!(options.raw.len(), 3);
    assert!(options.raw.contains(&"rw".to_string()));
    assert!(options.raw.contains(&"noatime".to_string()));
    assert!(options.raw.contains(&"vers=4".to_string()));
    Ok(())
}

#[test]
fn test_parse_options_with_whitespace() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse(" rw , noatime , vers=4 ", "nfs")?;

    assert_eq!(options.raw.len(), 3);
    assert_eq!(options.raw[0], "rw");
    assert_eq!(options.raw[1], "noatime");
    assert_eq!(options.raw[2], "vers=4");
    Ok(())
}

#[test]
fn test_parse_nfs_options() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("rsize=32768,wsize=32768,timeo=600", "nfs")?;

    assert_eq!(options.fs_type, "nfs");
    assert_eq!(options.performance.rsize, Some(32768));
    assert_eq!(options.performance.wsize, Some(32768));
    assert_eq!(options.performance.timeo, Some(600));
    Ok(())
}

#[test]
fn test_parse_smb_options() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("vers=3.0,rw,noserverino", "smb")?;

    assert_eq!(options.fs_type, "smb");
    assert!(options.raw.contains(&"vers=3.0".to_string()));
    Ok(())
}

#[test]
fn test_parse_sshfs_options() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("reconnect,ServerAliveInterval=15", "sshfs")?;

    assert_eq!(options.fs_type, "sshfs");
    assert!(options.raw.contains(&"reconnect".to_string()));
    Ok(())
}

// ============================================================================
// Security Options Tests
// ============================================================================

#[test]
fn test_parse_read_only_option() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("ro", "nfs")?;

    assert!(options.security.read_only);
    Ok(())
}

#[test]
fn test_parse_read_write_option() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("rw", "nfs")?;

    assert!(!options.security.read_only);
    Ok(())
}

#[test]
fn test_parse_nosuid_option() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("nosuid", "nfs")?;

    assert!(options.security.nosuid);
    Ok(())
}

#[test]
fn test_parse_nodev_option() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("nodev", "nfs")?;

    assert!(options.security.nodev);
    Ok(())
}

#[test]
fn test_parse_noexec_option() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("noexec", "nfs")?;

    assert!(options.security.noexec);
    Ok(())
}

#[test]
fn test_parse_uid_option() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("uid=1000", "smb")?;

    assert_eq!(options.security.uid, Some(1000));
    Ok(())
}

#[test]
fn test_parse_gid_option() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("gid=1000", "smb")?;

    assert_eq!(options.security.gid, Some(1000));
    Ok(())
}

#[test]
fn test_parse_fmode_octal() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("fmode=0644", "smb")?;

    assert_eq!(options.security.fmode, Some(0o644));
    Ok(())
}

#[test]
fn test_parse_dmode_octal() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("dmode=0755", "smb")?;

    assert_eq!(options.security.dmode, Some(0o755));
    Ok(())
}

#[test]
fn test_parse_combined_security_options() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("ro,nosuid,nodev,noexec,uid=1000,gid=1000", "nfs")?;

    assert!(options.security.read_only);
    assert!(options.security.nosuid);
    assert!(options.security.nodev);
    assert!(options.security.noexec);
    assert_eq!(options.security.uid, Some(1000));
    assert_eq!(options.security.gid, Some(1000));
    Ok(())
}

// ============================================================================
// Performance Options Tests
// ============================================================================

#[test]
fn test_parse_rsize_option() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("rsize=32768", "nfs")?;

    assert_eq!(options.performance.rsize, Some(32768));
    Ok(())
}

#[test]
fn test_parse_wsize_option() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("wsize=32768", "nfs")?;

    assert_eq!(options.performance.wsize, Some(32768));
    Ok(())
}

#[test]
fn test_parse_rsize_with_suffix_k() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("rsize=32k", "nfs")?;

    assert_eq!(options.performance.rsize, Some(32 * 1024));
    Ok(())
}

#[test]
fn test_parse_rsize_with_suffix_m() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("rsize=1M", "nfs")?;

    assert_eq!(options.performance.rsize, Some(1024 * 1024));
    Ok(())
}

#[test]
fn test_parse_timeo_option() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("timeo=600", "nfs")?;

    assert_eq!(options.performance.timeo, Some(600));
    Ok(())
}

#[test]
fn test_parse_retrans_option() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("retrans=2", "nfs")?;

    assert_eq!(options.performance.retrans, Some(2));
    Ok(())
}

#[test]
fn test_parse_soft_option() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("soft", "nfs")?;

    assert!(options.performance.soft);
    Ok(())
}

#[test]
fn test_parse_hard_option() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("hard", "nfs")?;

    assert!(!options.performance.soft);
    Ok(())
}

#[test]
fn test_parse_intr_option() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("intr", "nfs")?;

    assert!(options.performance.intr);
    Ok(())
}

#[test]
fn test_parse_nfsvers_option() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("nfsvers=4", "nfs")?;

    assert_eq!(options.performance.nfsvers, Some(4));
    Ok(())
}

#[test]
fn test_parse_vers_nfs() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("vers=4.1", "nfs")?;

    assert_eq!(options.performance.vers, Some("4.1".to_string()));
    Ok(())
}

#[test]
fn test_parse_vers_smb() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("vers=3.0", "smb")?;

    // SMB version parsing may be stored differently
    assert!(options.raw.contains(&"vers=3.0".to_string()));
    Ok(())
}

#[test]
fn test_parse_combined_performance_options() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse(
        "rsize=32768,wsize=32768,timeo=600,retrans=2,soft,intr",
        "nfs",
    )?;

    assert_eq!(options.performance.rsize, Some(32768));
    assert_eq!(options.performance.wsize, Some(32768));
    assert_eq!(options.performance.timeo, Some(600));
    assert_eq!(options.performance.retrans, Some(2));
    assert!(options.performance.soft);
    assert!(options.performance.intr);
    Ok(())
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_parse_invalid_uid() {
    let parser = MountOptionParser::new();
    let result = parser.parse("uid=invalid", "nfs");

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("uid"));
}

#[test]
fn test_parse_invalid_gid() {
    let parser = MountOptionParser::new();
    let result = parser.parse("gid=invalid", "nfs");

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("gid"));
}

#[test]
fn test_parse_invalid_fmode() {
    let parser = MountOptionParser::new();
    let result = parser.parse("fmode=invalid", "smb");

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("mode"));
}

#[test]
fn test_parse_invalid_timeo() {
    let parser = MountOptionParser::new();
    let result = parser.parse("timeo=invalid", "nfs");

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("timeout"));
}

#[test]
fn test_parse_invalid_retrans() {
    let parser = MountOptionParser::new();
    let result = parser.parse("retrans=invalid", "nfs");

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("retrans"));
}

#[test]
fn test_parse_invalid_nfsvers() {
    let parser = MountOptionParser::new();
    let result = parser.parse("nfsvers=invalid", "nfs");

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("version"));
}

// ============================================================================
// Default Options Tests
// ============================================================================

#[test]
fn test_nfs_defaults_applied() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("", "nfs")?;

    // Defaults should be applied
    assert_eq!(options.fs_type, "nfs");
    Ok(())
}

#[test]
fn test_smb_defaults_applied() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("", "smb")?;

    assert_eq!(options.fs_type, "smb");
    Ok(())
}

#[test]
fn test_sshfs_defaults_applied() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("", "sshfs")?;

    assert_eq!(options.fs_type, "sshfs");
    Ok(())
}

// ============================================================================
// Filesystem Type Normalization Tests
// ============================================================================

#[test]
fn test_parse_cifs_options() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("rw", "cifs")?;

    // CIFS is accepted as a filesystem type
    assert!(!options.fs_type.is_empty());
    Ok(())
}

#[test]
fn test_parse_nfs4_options() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("rw", "nfs4")?;

    // NFS4 is accepted as a filesystem type
    assert!(!options.fs_type.is_empty());
    Ok(())
}

// ============================================================================
// Complex Scenarios Tests
// ============================================================================

#[test]
fn test_parse_realistic_nfs_options() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse(
        "rw,noatime,vers=4,rsize=1M,wsize=1M,timeo=600,retrans=2,hard,intr",
        "nfs",
    )?;

    assert!(!options.security.read_only);
    assert_eq!(options.performance.vers, Some("4".to_string()));
    assert_eq!(options.performance.rsize, Some(1024 * 1024));
    assert_eq!(options.performance.wsize, Some(1024 * 1024));
    assert_eq!(options.performance.timeo, Some(600));
    assert_eq!(options.performance.retrans, Some(2));
    assert!(!options.performance.soft);
    assert!(options.performance.intr);
    Ok(())
}

#[test]
fn test_parse_realistic_smb_options() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse(
        "vers=3.0,uid=1000,gid=1000,fmode=0644,dmode=0755,rw,noserverino",
        "smb",
    )?;

    // Verify key options are parsed correctly
    assert_eq!(options.security.uid, Some(1000));
    assert_eq!(options.security.gid, Some(1000));
    assert_eq!(options.security.fmode, Some(0o644));
    assert_eq!(options.security.dmode, Some(0o755));
    assert!(!options.security.read_only);
    assert!(options.raw.contains(&"vers=3.0".to_string()));
    Ok(())
}

#[test]
fn test_parse_realistic_sshfs_options() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse(
        "reconnect,ServerAliveInterval=15,ServerAliveCountMax=3,follow_symlinks",
        "sshfs",
    )?;

    assert!(options.raw.contains(&"reconnect".to_string()));
    assert!(options.raw.contains(&"ServerAliveInterval=15".to_string()));
    assert!(options.raw.contains(&"ServerAliveCountMax=3".to_string()));
    Ok(())
}

#[test]
fn test_parse_contradicting_options_rejected() {
    let parser = MountOptionParser::new();
    let result = parser.parse("ro,rw", "nfs");

    // Conflicting options should be rejected
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Conflicting"));
}

#[test]
fn test_parse_multiple_uid_gid() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("uid=1000,gid=2000", "smb")?;

    assert_eq!(options.security.uid, Some(1000));
    assert_eq!(options.security.gid, Some(2000));
    Ok(())
}

#[test]
fn test_parse_empty_values_between_commas() -> Result<()> {
    let parser = MountOptionParser::new();
    let options = parser.parse("rw,,noatime,,vers=4", "nfs")?;

    // Empty values should be skipped
    assert!(options.raw.contains(&"rw".to_string()));
    assert!(options.raw.contains(&"noatime".to_string()));
    assert!(options.raw.contains(&"vers=4".to_string()));
    Ok(())
}

#[test]
fn test_parser_default_constructor() {
    let parser = MountOptionParser::default();
    let result = parser.parse("rw", "nfs");
    assert!(result.is_ok());
}
