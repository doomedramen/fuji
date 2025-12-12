//! System-wide constants for Fuji
//!
//! This module contains centralized constants for ports, paths,
//! timeouts, and other magic numbers used throughout the codebase.

/// Default cluster communication port
pub const DEFAULT_CLUSTER_PORT: u16 = 10080;

/// Legacy cluster port (deprecated)
#[deprecated(since = "0.1.7", note = "Use DEFAULT_CLUSTER_PORT instead")]
pub const LEGACY_CLUSTER_PORT: u16 = 8080;

/// Standard network ports
pub mod ports {
    /// SSH port
    pub const SSH: u16 = 22;
    /// NFS port
    pub const NFS: u16 = 2049;
    /// SMB/CIFS port
    pub const SMB: u16 = 445;
}

/// Default resource limits
pub mod resource_limits {
    /// Default maximum memory in MB
    pub const MAX_MEMORY_MB: u64 = 1024;
    /// Default maximum CPU percentage
    pub const MAX_CPU_PERCENT: u8 = 80;
    /// Default maximum concurrent mounts
    pub const MAX_CONCURRENT_MOUNTS: u32 = 10;
    /// Default maximum file descriptors
    pub const MAX_FILE_DESCRIPTORS: u32 = 1024;
    /// Default maximum connections
    pub const MAX_CONNECTIONS: u32 = 100;
}

/// Default retry configuration
pub mod retry {
    /// Default maximum retry attempts
    pub const MAX_RETRIES: u32 = 5;
    /// Default initial delay in milliseconds
    pub const INITIAL_DELAY_MS: u64 = 1000;
    /// Default maximum delay in milliseconds
    pub const MAX_DELAY_MS: u64 = 60000;
    /// Default backoff multiplier
    pub const BACKOFF_MULTIPLIER: f64 = 2.0;
}

/// Default intervals in seconds
pub mod intervals {
    /// Default monitoring interval
    pub const MONITORING: u64 = 30;
    /// Default health check interval
    pub const HEALTH_CHECK: u64 = 30;
    /// Default sync interval in minutes
    pub const SYNC_INTERVAL_MINUTES: u64 = 5;
    /// Default sync cooldown in minutes
    pub const SYNC_COOLDOWN_MINUTES: u64 = 10;
}

/// Standard Unix paths
pub mod paths {
    /// /etc directory
    pub const ETC: &str = "/etc";
    /// /usr/bin directory
    pub const USR_BIN: &str = "/usr/bin";
    /// /usr/sbin directory
    pub const USR_SBIN: &str = "/usr/sbin";
    /// /var/log directory
    pub const VAR_LOG: &str = "/var/log";
    /// /var/run directory
    pub const VAR_RUN: &str = "/var/run";
    /// /var/tmp directory
    pub const VAR_TMP: &str = "/var/tmp";
    /// /tmp directory
    pub const TMP: &str = "/tmp";
    /// /mnt directory
    pub const MNT: &str = "/mnt";
    /// /media directory
    pub const MEDIA: &str = "/media";

    /// Fuji-specific paths
    pub mod fuji {
        /// Fuji config directory under /etc
        pub const CONFIG_DIR: &str = "/etc/fuji";
        /// Fuji runtime directory under /var/run
        pub const RUN_DIR: &str = "/var/run/fuji";
        /// Fuji log directory under /var/log
        pub const LOG_DIR: &str = "/var/log/fuji";
    }
}

/// Default file permissions (octal)
pub mod permissions {
    /// Default file permissions (rw-------)
    pub const FILE: u32 = 0o600;
    /// Default directory permissions (rwx------)
    pub const DIR: u32 = 0o700;
    /// Default umask
    pub const UMASK: u32 = 0o022;
}

/// Default security thresholds
pub mod security {
    /// Maximum file size for config files (10MB)
    pub const MAX_CONFIG_FILE_SIZE: usize = 10 * 1024 * 1024;
    /// Default backup versions to keep
    pub const BACKUP_VERSIONS: u32 = 10;
    /// Security dashboard snapshots to keep (7 days of minutes)
    pub const DASHBOARD_SNAPSHOTS: usize = 10080;
}

/// Default user IDs for privilege dropping
pub mod uids {
    /// Default unprivileged user ID
    pub const UNPRIVILEGED: u32 = 1000;
    /// Daemon user ID
    pub const DAEMON: u32 = 1001;
    /// Fuji service user ID
    pub const FUJI_SERVICE: u32 = 1002;
}

/// Standard system paths for security checks
pub mod security_paths {
    /// List of sensitive system files
    pub const SENSITIVE_FILES: &[&str] = &[
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/sudoers",
        "/etc/hosts",
        "/etc/crontab",
        "/usr/bin/passwd",
        "/usr/bin/chsh",
        "/var/log",
        "/var/spool",
        "/etc/ssh",
        "/etc/my.cnf",
        "/etc/postgresql",
    ];
}

/// Network timeouts in seconds
pub mod timeouts {
    /// Default connection timeout
    pub const CONNECTION: u64 = 30;
    /// Default operation timeout
    pub const OPERATION: u64 = 60;
    /// Default heartbeat interval
    pub const HEARTBEAT: u64 = 10;
}
