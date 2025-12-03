//! Mount options parsing and validation
//!
//! Provides comprehensive mount option parsing and validation for different filesystem types.

use anyhow::{anyhow, bail, Result};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Parsed mount options with metadata
#[derive(Debug, Clone)]
pub struct MountOptions {
    /// Raw options as provided
    pub raw: Vec<String>,
    /// Parsed key-value options
    pub options: HashMap<String, String>,
    /// Filesystem type
    pub fs_type: String,
    /// Security-related options
    pub security: SecurityOptions,
    /// Performance-related options
    pub performance: PerformanceOptions,
}

/// Security-related mount options
#[derive(Debug, Clone)]
pub struct SecurityOptions {
    /// Read-only mount
    pub read_only: bool,
    /// No setuid execution
    pub nosuid: bool,
    /// No device file access
    pub nodev: bool,
    /// No execution
    pub noexec: bool,
    /// SUID/SGID allowed
    pub suid: bool,
    /// Default file permissions
    pub fmode: Option<u32>,
    /// Default directory permissions
    pub dmode: Option<u32>,
    /// UID mapping
    pub uid: Option<u32>,
    /// GID mapping
    pub gid: Option<u32>,
}

/// Performance-related mount options
#[derive(Debug, Clone)]
pub struct PerformanceOptions {
    /// Buffer size in bytes
    pub rsize: Option<usize>,
    /// Write buffer size in bytes
    pub wsize: Option<usize>,
    /// Timeout in seconds
    pub timeo: Option<u32>,
    /// Retransmission timeout
    pub retrans: Option<u32>,
    /// Soft vs hard mount
    pub soft: bool,
    /// Interruptible mount
    pub intr: bool,
    /// Number of NFS threads
    pub nfsvers: Option<u32>,
    /// NFS version
    pub vers: Option<String>,
    /// SMB protocol version
    pub vers_smb: Option<String>,
}

/// Mount option parser
pub struct MountOptionParser {
    /// Known filesystem-specific options
    fs_options: HashMap<String, HashSet<String>>,
    /// Global security options
    global_security: HashSet<String>,
    /// Boolean options that don't take values
    boolean_options: HashSet<String>,
}

impl MountOptionParser {
    /// Create a new mount option parser
    pub fn new() -> Self {
        let mut fs_options = HashMap::new();

        // NFS options
        fs_options.insert("nfs".to_string(), [
            "rsize", "wsize", "timeo", "retrans", "soft", "hard", "intr", "nointr", "tcp", "udp", "vers", "nfsvers",
            "port", "proto", "ac", "noac", "acregmin", "acregmax", "acdirmin", "acdirmax", "lookupcache",
            "fsc", "local_lock", "fscache", "nolock", "bg", "fg",
        ].iter().map(|s| s.to_string()).collect());

        // SMB/CIFS options
        fs_options.insert("cifs".to_string(), [
            "rsize", "wsize", "vers", "username", "password", "domain", "uid", "gid", "file_mode", "dir_mode",
            "iocharset", "codepage", "sec", "serverino", "cache", "unc", "ip", "port", "netbiosname",
            "workgroup", "user", "pass", "rw", "ro", "guest", "nobrl", "servern", "posix",
            "mfsymlinks", "dynperm", "inode64", "acl", "noperm", "noserverino", "cifsacl",
        ].iter().map(|s| s.to_string()).collect());

        // SSHFS options
        fs_options.insert("sshfs".to_string(), [
            "ssh_command", "sftp_server", "direct_io", "cache", "cache_timeout", "cache_link_timeout",
            "cache_dir", "cache_xattr_timeout", "follow_symlinks", "transform_symlinks",
            "noatime", "nodiratime", "readonly", "allow_root", "allow_other", "default_permissions",
            "uid", "gid", "umask", "fmask", "dmask", "idmap", "nomap", "uidfile", "gidfile",
            "modules", "modulespath", "ssh_command_known_hosts_policy", "reconnect",
            "ServerAliveInterval", "ServerAliveCountMax", "controlpath",
        ].iter().map(|s| s.to_string()).collect());

        // Global security options
        let global_security = [
            "nosuid", "nodev", "noexec", "suid", "exec", "dev", "ro", "rw",
        ].iter().map(|s| s.to_string()).collect();

        // Boolean options
        let boolean_options = [
            "ro", "rw", "suid", "nosuid", "dev", "nodev", "exec", "noexec", "sync", "async",
            "dirsync", "nodiratime", "relatime", "norelatime", "noatime", "atime",
            "diratime", "nodiratime", "strictatime", "nostrictatime", "lazy", "nolazy",
            "soft", "hard", "intr", "nointr", "bg", "fg", "defaults", "auto", "noauto",
            "user", "nouser", "users", "nouser", "_netdev", "nofail",
        ].iter().map(|s| s.to_string()).collect();

        Self {
            fs_options,
            global_security,
            boolean_options,
        }
    }

    /// Parse mount options string
    pub fn parse(&self, options_str: &str, fs_type: &str) -> Result<MountOptions> {
        let raw: Vec<String> = options_str.split(',').map(|s| s.trim().to_string()).collect();

        let mut options = HashMap::new();
        let mut security = SecurityOptions::default();
        let mut performance = PerformanceOptions::default();

        // Process each option
        for opt in &raw {
            if opt.is_empty() {
                continue;
            }

            // Parse key=value or boolean option
            if let Some((key, value)) = opt.split_once('=') {
                // Key-value option
                self.process_key_value_option(key, value, &mut options, &mut security, &mut performance)?;
            } else {
                // Boolean option
                self.process_boolean_option(opt, &mut options, &mut security, &mut performance)?;
            }
        }

        // Apply defaults and validate
        self.apply_defaults(&mut options, &mut security, &mut performance, fs_type)?;
        self.validate_options(&options, &security, &performance, fs_type)?;

        Ok(MountOptions {
            raw,
            options,
            fs_type: fs_type.to_string(),
            security,
            performance,
        })
    }

    /// Process a key-value option
    fn process_key_value_option(
        &self,
        key: &str,
        value: &str,
        options: &mut HashMap<String, String>,
        security: &mut SecurityOptions,
        performance: &mut PerformanceOptions,
    ) -> Result<()> {
        // Check if it's a known filesystem option
        if let Some(fs_specific) = self.fs_options.get(&self.normalize_fs_type(options.get("type").unwrap_or(&"auto".to_string()))) {
            if fs_specific.contains(key) {
                options.insert(key.to_string(), value.to_string());
                return Ok(());
            }
        }

        // Security options
        match key {
            "uid" => {
                security.uid = Some(value.parse().map_err(|_| anyhow!("Invalid UID: {}", value))?);
            }
            "gid" => {
                security.gid = Some(value.parse().map_err(|_| anyhow!("Invalid GID: {}", value))?);
            }
            "fmode" => {
                security.fmode = Some(
                    u32::from_str_radix(value, 8).map_err(|_| anyhow!("Invalid file mode: {}", value))?
                );
            }
            "dmode" => {
                security.dmode = Some(
                    u32::from_str_radix(value, 8).map_err(|_| anyhow!("Invalid dir mode: {}", value))?
                );
            }
            _ => {
                options.insert(key.to_string(), value.to_string());
            },
        }

        // Performance options
        match key {
            "rsize" => {
                performance.rsize = Some(value.parse().map_err(|_| anyhow!("Invalid rsize: {}", value))?);
            }
            "wsize" => {
                performance.wsize = Some(value.parse().map_err(|_| anyhow!("Invalid wsize: {}", value))?);
            }
            "timeo" => {
                performance.timeo = Some(value.parse().map_err(|_| anyhow!("Invalid timeout: {}", value))?);
            }
            "retrans" => {
                performance.retrans = Some(value.parse().map_err(|_| anyhow!("Invalid retrans: {}", value))?);
            }
            "nfsvers" => {
                performance.nfsvers = Some(value.parse().map_err(|_| anyhow!("Invalid NFS version: {}", value))?);
            }
            "vers" => {
                if value.starts_with("3") || value.starts_with("4") {
                    performance.vers = Some(value.to_string());
                } else if ["1.0", "2.0", "2.1", "3.0"].contains(&value) {
                    performance.vers_smb = Some(value.to_string());
                }
            }
            _ => (), // Don't modify for other options
        }

        Ok(())
    }

    /// Process a boolean option
    fn process_boolean_option(
        &self,
        option: &str,
        options: &mut HashMap<String, String>,
        security: &mut SecurityOptions,
        performance: &mut PerformanceOptions,
    ) -> Result<()> {
        // Security boolean options
        match option {
            "ro" => {
                security.read_only = true;
                options.insert(option.to_string(), "".to_string());
            }
            "rw" => {
                security.read_only = false;
                options.insert(option.to_string(), "".to_string());
            }
            "nosuid" => {
                security.nosuid = true;
                security.suid = false;
                options.insert(option.to_string(), "".to_string());
            }
            "nodev" => {
                security.nodev = true;
                options.insert(option.to_string(), "".to_string());
            }
            "noexec" => {
                security.noexec = true;
                options.insert(option.to_string(), "".to_string());
            }
            "suid" => {
                security.suid = true;
                security.nosuid = false;
                options.insert(option.to_string(), "".to_string());
            }
            "soft" => {
                performance.soft = true;
                options.insert(option.to_string(), "".to_string());
            }
            "hard" => {
                performance.soft = false;
                options.insert(option.to_string(), "".to_string());
            }
            "intr" => {
                options.insert(option.to_string(), "".to_string());
            }
            "nointr" => {
                options.insert(option.to_string(), "".to_string());
            }
            "noatime" => {
                options.insert(option.to_string(), "".to_string());
            }
            "relatime" => {
                options.insert(option.to_string(), "".to_string());
            }
            _ => {
                options.insert(option.to_string(), "".to_string());
            }
        }

        Ok(())
    }

    /// Normalize filesystem type
    fn normalize_fs_type(&self, fs_type: &str) -> String {
        match fs_type {
            "cifs" => "cifs",
            "smbfs" => "cifs",
            "nfs4" => "nfs",
            _ => fs_type,
        }
        .to_string()
    }

    /// Apply default options
    fn apply_defaults(
        &self,
        options: &mut HashMap<String, String>,
        security: &mut SecurityOptions,
        performance: &mut PerformanceOptions,
        fs_type: &str,
    ) -> Result<()> {
        match fs_type {
            "nfs" => {
                // NFS defaults
                if !options.contains_key("hard") && !options.contains_key("soft") {
                    options.insert("hard".to_string(), "".to_string());
                    performance.soft = false;
                }
                if !options.contains_key("intr") && !options.contains_key("nointr") {
                    options.insert("intr".to_string(), "".to_string());
                }
                if !options.contains_key("rsize") {
                    options.insert("rsize".to_string(), "1048576".to_string()); // 1MB
                    performance.rsize = Some(1048576);
                }
                if !options.contains_key("wsize") {
                    options.insert("wsize".to_string(), "1048576".to_string()); // 1MB
                    performance.wsize = Some(1048576);
                }
                if !options.contains_key("timeo") {
                    options.insert("timeo".to_string(), "600".to_string()); // 10 minutes
                    performance.timeo = Some(600);
                }
                if !options.contains_key("retrans") {
                    options.insert("retrans".to_string(), "2".to_string());
                    performance.retrans = Some(2);
                }
            }
            "cifs" | "smbfs" => {
                // SMB/CIFS defaults
                if !options.contains_key("rw") && !options.contains_key("ro") {
                    options.insert("rw".to_string(), "".to_string());
                    security.read_only = false;
                }
                if !options.contains_key("rsize") {
                    options.insert("rsize".to_string(), "1048576".to_string());
                    performance.rsize = Some(1048576);
                }
                if !options.contains_key("wsize") {
                    options.insert("wsize".to_string(), "1048576".to_string());
                    performance.wsize = Some(1048576);
                }
            }
            "sshfs" => {
                // SSHFS defaults
                if !options.contains_key("allow_other") {
                    options.insert("allow_other".to_string(), "".to_string());
                }
                if !options.contains_key("default_permissions") {
                    options.insert("default_permissions".to_string(), "".to_string());
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Validate parsed options
    fn validate_options(
        &self,
        options: &HashMap<String, String>,
        security: &SecurityOptions,
        performance: &PerformanceOptions,
        fs_type: &str,
    ) -> Result<()> {
        // Validate conflicting options
        if security.read_only && options.contains_key("rw") {
            bail!("Conflicting options: ro and rw");
        }
        if !performance.soft && performance.timeo.is_some() && performance.timeo.unwrap() == 0 {
            bail!("Hard mount cannot have zero timeout");
        }

        // Validate NFS-specific options
        if fs_type == "nfs" {
            if let Some(nfsvers) = performance.nfsvers {
                if nfsvers < 3 || nfsvers > 4 {
                    bail!("Unsupported NFS version: {}", nfsvers);
                }
            }
        }

        // Validate values
        if let Some(rsize) = performance.rsize {
            if rsize < 1024 {
                bail!("rsize too small: {} bytes (minimum 1024)", rsize);
            }
            if rsize > 104857600 {
                bail!("rsize too large: {} bytes (maximum 100MB)", rsize);
            }
        }

        if let Some(wsize) = performance.wsize {
            if wsize < 1024 {
                bail!("wsize too small: {} bytes (minimum 1024)", wsize);
            }
            if wsize > 104857600 {
                bail!("wsize too large: {} bytes (maximum 100MB)", wsize);
            }
        }

        Ok(())
    }

    /// Format options back to string
    pub fn format(&self, options: &MountOptions) -> String {
        let mut formatted = Vec::new();

        for (key, value) in &options.options {
            if value.is_empty() {
                formatted.push(key.clone());
            } else {
                formatted.push(format!("{}={}", key, value));
            }
        }

        formatted.join(",")
    }
}

impl Default for MountOptionParser {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SecurityOptions {
    fn default() -> Self {
        Self {
            read_only: false,
            nosuid: true,
            nodev: false,
            noexec: false,
            suid: false,
            fmode: None,
            dmode: None,
            uid: None,
            gid: None,
        }
    }
}

impl Default for PerformanceOptions {
    fn default() -> Self {
        Self {
            rsize: None,
            wsize: None,
            timeo: None,
            retrans: None,
            soft: false,
            intr: true,
            nfsvers: None,
            vers: None,
            vers_smb: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nfs_options_parsing() {
        let parser = MountOptionParser::new();

        let options = parser.parse("rsize=1M,wsize=2M,soft,timeo=30", "nfs").unwrap();

        assert_eq!(options.fs_type, "nfs");
        assert_eq!(options.options.get("rsize"), Some(&"1048576".to_string()));
        assert_eq!(options.options.get("wsize"), Some(&"2097152".to_string()));
        assert!(options.performance.soft);
        assert_eq!(options.performance.timeo, Some(30));
    }

    #[test]
    fn test_security_options() {
        let parser = MountOptionParser::new();

        let options = parser.parse("ro,nosuid,uid=1000,gid=1000", "nfs").unwrap();

        assert!(options.security.read_only);
        assert!(options.security.nosuid);
        assert_eq!(options.security.uid, Some(1000));
        assert_eq!(options.security.gid, Some(1000));
    }

    #[test]
    fn test_boolean_options() {
        let parser = MountOptionParser::new();

        let options = parser.parse("ro,nosuid,noexec", "nfs").unwrap();

        assert!(options.security.read_only);
        assert!(options.security.nosuid);
        assert!(options.security.noexec);
    }

    #[test]
    fn test_cifs_options_parsing() {
        let parser = MountOptionParser::new();

        let options = parser.parse("username=user,password=pass,domain=WORKGROUP", "cifs").unwrap();

        assert_eq!(options.fs_type, "cifs");
        assert_eq!(options.options.get("username"), Some(&"user".to_string()));
        assert_eq!(options.options.get("password"), Some(&"pass".to_string()));
        assert_eq!(options.options.get("domain"), Some(&"WORKGROUP".to_string()));
    }

    #[test]
    fn test_defaults_application() {
        let parser = MountOptionParser::new();

        // Empty options should get defaults
        let options = parser.parse("", "nfs").unwrap();

        assert!(options.options.contains_key("hard"));
        assert!(options.options.contains_key("intr"));
        assert_eq!(options.options.get("rsize"), Some(&"1048576".to_string()));
        assert!(!options.performance.soft);
    }

    #[test]
    fn test_format_options() {
        let parser = MountOptionParser::new();

        let parsed = parser.parse("rsize=1M,soft", "nfs").unwrap();
        let formatted = parser.format(&parsed);

        assert!(formatted.contains("rsize=1048576"));
        assert!(formatted.contains("soft"));
    }

    #[test]
    fn test_validation() {
        let parser = MountOptionParser::new();

        // Invalid: conflicting ro and rw
        assert!(parser.parse("ro,rw", "nfs").is_err());

        // Invalid: hard mount with zero timeout
        assert!(parser.parse("hard,timeo=0", "nfs").is_err());

        // Valid: soft mount with zero timeout
        assert!(parser.parse("soft,timeo=0", "nfs").is_ok());
    }
}