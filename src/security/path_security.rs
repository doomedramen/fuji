//! Enhanced path security module for runtime validation and monitoring
//!
//! This module provides advanced path security features including runtime validation,
//! symlink attack protection, mount integrity verification, and security event logging.
//! It extends the existing static validation with dynamic runtime checks.

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::fs;

/// Security event types for path validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PathSecurityEvent {
    /// Path validation event
    PathValidation {
        path: String,
        operation: String,
        result: ValidationResult,
        timestamp: DateTime<Utc>,
        context: HashMap<String, String>,
    },
    /// Mount integrity check
    MountIntegrityCheck {
        mount_id: String,
        mount_point: String,
        integrity_status: IntegrityStatus,
        timestamp: DateTime<Utc>,
        violations: Vec<String>,
    },
    /// Symlink attack detection
    SymlinkAttack {
        mount_point: String,
        suspicious_path: String,
        attack_type: SymlinkAttackType,
        timestamp: DateTime<Utc>,
        blocked: bool,
    },
    /// Runtime path validation
    RuntimeValidation {
        original_path: String,
        current_path: String,
        validation_result: ValidationResult,
        timestamp: DateTime<Utc>,
        mount_age_seconds: u64,
    },
}

/// Types of symlink attacks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SymlinkAttackType {
    /// Symlink to sensitive system files
    SystemFileSymlink,
    /// Symlink escaping mount boundaries
    BoundaryEscape,
    /// Symlink chain (deep linking)
    SymlinkChain,
    /// Race condition symlink swap
    RaceCondition,
    /// Time-of-check to time-of-use (TOCTOU) attack
    TOCTOU,
}

/// Path validation results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the path is considered safe
    pub is_safe: bool,
    /// Warning message if validation failed
    pub warning_message: Option<String>,
    /// Security events detected during validation
    pub security_events: Vec<PathSecurityEvent>,
    /// Validation status
    pub status: ValidationStatus,
}

/// Validation status enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidationStatus {
    /// Path is valid and safe
    Valid,
    /// Path is blocked due to security policy
    Blocked(String),
    /// Path requires additional verification
    RequiresVerification,
    /// Path validation failed
    Failed(String),
}

/// Mount integrity status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntegrityStatus {
    /// Mount integrity is intact
    Intact,
    /// Mount has been modified
    Modified,
    /// Mount has suspicious changes
    Suspicious,
    /// Mount integrity check failed
    Failed,
    /// Mount requires verification
    RequiresVerification,
}

/// Mount configuration for security tracking
#[derive(Debug, Clone)]
pub struct MountSecurityConfig {
    pub mount_id: String,
    pub mount_point: PathBuf,
    pub source_path: String,
    pub mount_time: Instant,
    pub allowed_paths: Vec<PathBuf>,
    pub security_profile: SecurityProfile,
    pub integrity_hash: Option<String>,
}

/// Security profile for path validation
#[derive(Debug, Clone)]
pub enum SecurityProfile {
    /// Minimal security - basic validation only
    Minimal,
    /// Standard security - comprehensive validation
    Standard,
    /// High security - strict validation with monitoring
    High,
    /// Maximum security - paranoid validation and logging
    Maximum,
}

impl SecurityProfile {
    /// Get the maximum allowed symlink depth
    pub fn max_symlink_depth(&self) -> usize {
        match self {
            Self::Minimal => 5,
            Self::Standard => 3,
            Self::High => 2,
            Self::Maximum => 1,
        }
    }

    /// Get validation interval in seconds
    pub fn validation_interval(&self) -> Duration {
        match self {
            Self::Minimal => Duration::from_secs(300),  // 5 minutes
            Self::Standard => Duration::from_secs(120), // 2 minutes
            Self::High => Duration::from_secs(60),      // 1 minute
            Self::Maximum => Duration::from_secs(30),   // 30 seconds
        }
    }

    /// Get maximum mount age before requiring re-validation
    pub fn max_mount_age(&self) -> Duration {
        match self {
            Self::Minimal => Duration::from_secs(86400),  // 24 hours
            Self::Standard => Duration::from_secs(43200), // 12 hours
            Self::High => Duration::from_secs(21600),     // 6 hours
            Self::Maximum => Duration::from_secs(10800),  // 3 hours
        }
    }
}

/// Runtime path security validator
#[derive(Debug)]
pub struct PathSecurityValidator {
    mounts: Arc<RwLock<HashMap<String, MountSecurityConfig>>>,
    security_events: Arc<Mutex<Vec<PathSecurityEvent>>>,
    blocked_paths: Arc<RwLock<Vec<String>>>,
    dangerous_system_files: Vec<String>,
    security_profile: SecurityProfile,
}

impl PathSecurityValidator {
    /// Create a new path security validator
    pub fn new(security_profile: SecurityProfile) -> Self {
        let dangerous_system_files = vec![
            // System configuration files
            "/etc/passwd".to_string(),
            "/etc/shadow".to_string(),
            "/etc/group".to_string(),
            "/etc/sudoers".to_string(),
            "/etc/hosts".to_string(),
            "/etc/crontab".to_string(),
            // System binaries
            "/bin/sh".to_string(),
            "/bin/bash".to_string(),
            "/bin/su".to_string(),
            "/bin/sudo".to_string(),
            "/usr/bin/passwd".to_string(),
            "/usr/bin/chsh".to_string(),
            // System directories
            "/root".to_string(),
            "/var/log".to_string(),
            "/var/spool".to_string(),
            "/tmp/.X11-unix".to_string(),
            // Kernel interfaces
            "/proc/kcore".to_string(),
            "/proc/kmsg".to_string(),
            "/dev/mem".to_string(),
            "/dev/kmem".to_string(),
            "/dev/port".to_string(),
            // SSH keys and certificates
            "/root/.ssh".to_string(),
            "/home/*/.ssh".to_string(),
            "/etc/ssh".to_string(),
            // Database files
            "/etc/my.cnf".to_string(),
            "/etc/postgresql".to_string(),
        ];

        Self {
            mounts: Arc::new(RwLock::new(HashMap::new())),
            security_events: Arc::new(Mutex::new(Vec::new())),
            blocked_paths: Arc::new(RwLock::new(Vec::new())),
            dangerous_system_files,
            security_profile,
        }
    }

    /// Register a mount for security monitoring
    pub async fn register_mount(
        &self,
        mount_id: String,
        mount_point: PathBuf,
        source_path: String,
        allowed_paths: Vec<PathBuf>,
    ) -> Result<()> {
        // Validate mount point before registration
        self.validate_mount_point(&mount_point)
            .await
            .context("Mount point validation failed")?;

        // Calculate initial integrity hash
        let integrity_hash = self.calculate_mount_integrity_hash(&mount_point).await?;

        let config = MountSecurityConfig {
            mount_id: mount_id.clone(),
            mount_point: mount_point.clone(),
            source_path,
            mount_time: Instant::now(),
            allowed_paths,
            security_profile: self.security_profile.clone(),
            integrity_hash,
        };

        // Register the mount
        {
            let mut mounts = self.mounts.write().unwrap();
            mounts.insert(mount_id.clone(), config);
        }

        info!(
            "Registered mount for security monitoring: {}",
            mount_point.display()
        );

        // Log the registration event
        self.log_security_event(PathSecurityEvent::PathValidation {
            path: mount_point.to_string_lossy().to_string(),
            operation: "mount_registration".to_string(),
            result: ValidationResult {
                is_safe: true,
                warning_message: None,
                security_events: vec![],
                status: ValidationStatus::Valid,
            },
            timestamp: Utc::now(),
            context: {
                let mut ctx = HashMap::new();
                ctx.insert("mount_id".to_string(), mount_id);
                ctx.insert(
                    "security_profile".to_string(),
                    format!("{:?}", self.security_profile),
                );
                ctx
            },
        });

        Ok(())
    }

    /// Validate a path against security policies
    pub async fn validate_path(
        &self,
        path: &Path,
        operation: &str,
        mount_id: Option<&str>,
    ) -> Result<ValidationResult> {
        // Get absolute path
        let abs_path = match fs::canonicalize(path).await {
            Ok(p) => p,
            Err(_) => {
                // Try to make absolute without canonicalization
                match std::fs::canonicalize(path) {
                    Ok(p) => p,
                    Err(_) => path.to_path_buf(),
                }
            }
        };

        // Check against blocked paths
        if self.is_path_blocked(&abs_path) {
            return Ok(ValidationResult {
                is_safe: false,
                warning_message: Some("Path is blocked by security policy".to_string()),
                security_events: vec![],
                status: ValidationStatus::Blocked("Path is blocked by security policy".to_string()),
            });
        }

        // Check for dangerous system files
        for dangerous_file in &self.dangerous_system_files {
            if abs_path.starts_with(dangerous_file) {
                return Ok(ValidationResult {
                    is_safe: false,
                    warning_message: Some(format!(
                        "Access to dangerous system file: {}",
                        dangerous_file
                    )),
                    security_events: vec![],
                    status: ValidationStatus::Blocked("Access violation".to_string()),
                });
            }
        }

        // Validate against mount configurations if mount_id is provided
        if let Some(mount_id) = mount_id {
            if let Some(mount_config) = self.get_mount_config(mount_id) {
                // Check if path is within mount boundaries
                if !abs_path.starts_with(&mount_config.mount_point) {
                    return Ok(ValidationResult {
                        is_safe: false,
                        warning_message: Some("Path escapes mount boundaries".to_string()),
                        security_events: vec![],
                        status: ValidationStatus::Blocked("Security violation".to_string()),
                    });
                }

                // Check if path is in allowed paths
                if !mount_config.allowed_paths.is_empty() {
                    let mut allowed = false;
                    for allowed_path in &mount_config.allowed_paths {
                        if abs_path.starts_with(allowed_path) {
                            allowed = true;
                            break;
                        }
                    }
                    if !allowed {
                        return Ok(ValidationResult {
                            is_safe: false,
                            warning_message: Some(
                                "Path not in allowed paths for this mount".to_string(),
                            ),
                            security_events: vec![],
                            status: ValidationStatus::Blocked("Security violation".to_string()),
                        });
                    }
                }

                // Perform symlink depth validation
                if let Err(e) = self
                    .validate_symlink_depth(
                        &abs_path,
                        mount_config.security_profile.max_symlink_depth(),
                    )
                    .await
                {
                    return Ok(ValidationResult {
                        is_safe: false,
                        warning_message: Some(format!("Symlink validation failed: {}", e)),
                        security_events: vec![],
                        status: ValidationStatus::Blocked(format!(
                            "Symlink validation failed: {}",
                            e
                        )),
                    });
                }
            }
        }

        // Additional validation for specific operations
        match operation {
            "write" | "create" | "delete" | "execute" => {
                // Extra validation for write operations
                if let Err(e) = self.validate_write_permissions(&abs_path).await {
                    return Ok(ValidationResult {
                        is_safe: false,
                        warning_message: Some(e.to_string()),
                        security_events: vec![],
                        status: ValidationStatus::Failed(e.to_string()),
                    });
                }
            }
            _ => {} // No extra validation needed
        }

        Ok(ValidationResult {
            is_safe: true,
            warning_message: None,
            security_events: vec![],
            status: ValidationStatus::Valid,
        })
    }

    /// Validate mount point for security
    pub async fn validate_mount_point(&self, mount_point: &Path) -> Result<ValidationResult> {
        // Check if mount point exists and is a directory
        if !mount_point.exists() {
            return Err(anyhow!(
                "Mount point does not exist: {}",
                mount_point.display()
            ));
        }

        if !mount_point.is_dir() {
            return Err(anyhow!(
                "Mount point is not a directory: {}",
                mount_point.display()
            ));
        }

        // Check for dangerous mount locations
        let dangerous_locations = vec![
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin",
            "/etc",
            "/boot",
            "/sys",
            "/proc",
            "/dev",
        ];

        for location in dangerous_locations {
            if mount_point.starts_with(location) {
                return Ok(ValidationResult {
                    is_safe: false,
                    warning_message: Some(format!(
                        "Mount point in dangerous location: {}",
                        location
                    )),
                    security_events: vec![],
                    status: ValidationStatus::Blocked(format!(
                        "Mount point in dangerous location: {}",
                        location
                    )),
                });
            }
        }

        Ok(ValidationResult {
            is_safe: true,
            warning_message: None,
            security_events: vec![],
            status: ValidationStatus::Valid,
        })
    }

    /// Get mount configuration by ID
    fn get_mount_config(&self, mount_id: &str) -> Option<MountSecurityConfig> {
        let mounts = self.mounts.read().unwrap();
        mounts.get(mount_id).cloned()
    }

    /// Check mount integrity for a specific mount
    pub async fn check_mount_integrity(
        &self,
        mount_id: &str,
        mount_point: &Path,
    ) -> Result<IntegrityStatus> {
        // Check if mount point exists
        if !mount_point.exists() {
            return Ok(IntegrityStatus::Failed);
        }

        // Check mount configuration integrity
        if let Some(_mount_config) = self.get_mount_config(mount_id) {
            // Verify mount point hasn't been modified
            if let Ok(metadata) = fs::metadata(mount_point).await {
                if let Ok(modified) = metadata.modified() {
                    let time_diff = std::time::SystemTime::now()
                        .duration_since(modified)
                        .unwrap_or_default();

                    // If modified recently, requires verification
                    if time_diff.as_secs() < 300 {
                        // 5 minutes
                        return Ok(IntegrityStatus::RequiresVerification);
                    }
                }
            }
        }

        // Perform basic integrity checks
        let suspicious_patterns = vec!["su", "passwd", "shadow", "sudoers"];
        if let Ok(mut entries) = fs::read_dir(mount_point).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let file_name = entry.file_name().to_string_lossy().to_string();
                for pattern in &suspicious_patterns {
                    if file_name.contains(pattern) {
                        return Ok(IntegrityStatus::Suspicious);
                    }
                }
            }
        }

        Ok(IntegrityStatus::Intact)
    }

    /// Check if a path is blocked
    fn is_path_blocked(&self, path: &Path) -> bool {
        let blocked_paths = self.blocked_paths.read().unwrap();
        let path_str = path.to_string_lossy();
        blocked_paths
            .iter()
            .any(|blocked| path_str.starts_with(blocked))
    }

    /// Block a path for security reasons
    pub fn block_path(&self, path: &str) {
        let mut blocked_paths = self.blocked_paths.write().unwrap();
        if !blocked_paths.contains(&path.to_string()) {
            blocked_paths.push(path.to_string());
            warn!("Blocked path for security reasons: {}", path);
        }
    }

    /// Calculate integrity hash for a mount
    async fn calculate_mount_integrity_hash(&self, mount_point: &Path) -> Result<Option<String>> {
        // For now, use a simple hash based on mount metadata
        // In a real implementation, this could calculate checksums of important files
        let metadata = fs::metadata(mount_point).await?;
        let modified = metadata.modified()?;
        let hash = format!(
            "{}-{}",
            mount_point.display(),
            modified.duration_since(UNIX_EPOCH)?.as_secs()
        );
        Ok(Some(hash))
    }

    /// Validate symlink depth to prevent symlink attacks
    async fn validate_symlink_depth(&self, path: &Path, max_depth: usize) -> Result<()> {
        let mut current_depth = 0;
        let mut current_path = path.to_path_buf();

        loop {
            // Check if current path is a symlink
            match fs::symlink_metadata(&current_path).await {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    current_depth += 1;
                    if current_depth > max_depth {
                        return Err(anyhow!(
                            "Symlink depth exceeded maximum allowed depth: {}",
                            max_depth
                        ));
                    }

                    // Resolve symlink and continue
                    match fs::read_link(&current_path).await {
                        Ok(target) => {
                            // Handle relative and absolute symlinks
                            if target.is_absolute() {
                                current_path = target;
                            } else {
                                let parent =
                                    current_path.parent().unwrap_or_else(|| Path::new("/"));
                                current_path = parent.join(target);
                            }
                        }
                        Err(e) => {
                            return Err(anyhow!("Failed to read symlink: {}", e));
                        }
                    }
                }
                Ok(_) => break, // Not a symlink, validation complete
                Err(e) => {
                    return Err(anyhow!("Failed to check symlink metadata: {}", e));
                }
            }
        }

        Ok(())
    }

    /// Validate write permissions for sensitive paths
    async fn validate_write_permissions(&self, path: &Path) -> Result<()> {
        // Check if path is in a sensitive location
        let sensitive_patterns = vec![
            "/etc/",
            "/usr/bin/",
            "/usr/sbin/",
            "/bin/",
            "/sbin/",
            "/boot/",
            "/sys/",
            "/proc/",
        ];

        for pattern in sensitive_patterns {
            if path.to_string_lossy().starts_with(pattern) {
                return Err(anyhow!(
                    "Write access denied to sensitive path: {}",
                    pattern
                ));
            }
        }

        Ok(())
    }

    /// Perform runtime validation of all registered mounts
    pub async fn validate_all_mounts(&self) -> Result<Vec<(String, IntegrityStatus)>> {
        let mounts = self.mounts.read().unwrap();
        let mut results = Vec::new();

        for (mount_id, config) in mounts.iter() {
            let status = self.validate_mount_integrity(config).await?;
            results.push((mount_id.clone(), status));
        }

        Ok(results)
    }

    /// Validate mount integrity
    async fn validate_mount_integrity(
        &self,
        config: &MountSecurityConfig,
    ) -> Result<IntegrityStatus> {
        // Check if mount point still exists
        if !config.mount_point.exists() {
            return Ok(IntegrityStatus::Failed);
        }

        // Check mount age
        let mount_age = config.mount_time.elapsed();
        if mount_age > config.security_profile.max_mount_age() {
            return Ok(IntegrityStatus::Modified);
        }

        // Calculate current integrity hash
        let current_hash = self
            .calculate_mount_integrity_hash(&config.mount_point)
            .await?;

        // Compare with stored hash
        match (config.integrity_hash.as_ref(), current_hash.as_ref()) {
            (Some(stored), Some(current)) => {
                if stored != current {
                    return Ok(IntegrityStatus::Suspicious);
                }
            }
            (None, _) | (_, None) => {
                // One of the hashes couldn't be calculated
                return Ok(IntegrityStatus::RequiresVerification);
            }
        }

        // Check for suspicious files
        if let Err(_e) = self.check_suspicious_files(&config.mount_point).await {
            return Ok(IntegrityStatus::Suspicious);
        }

        Ok(IntegrityStatus::Intact)
    }

    /// Check for suspicious files in mount
    async fn check_suspicious_files(&self, mount_point: &Path) -> Result<()> {
        let suspicious_patterns = vec![
            "script.sh",
            "exploit",
            "payload",
            "backdoor",
            "rootkit",
            ".bashrc",
            ".profile",
            ".ssh/authorized_keys",
            "cron.",
            "tmp.",
        ];

        let mut entries = match fs::read_dir(mount_point).await {
            Ok(e) => e,
            Err(_) => return Ok(()), // Directory might not be readable
        };

        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name().to_string_lossy().to_string();
            for pattern in &suspicious_patterns {
                if file_name.contains(pattern) {
                    warn!(
                        "Suspicious file detected in mount {}: {}",
                        mount_point.display(),
                        file_name
                    );
                }
            }
        }

        Ok(())
    }

    /// Log a security event
    pub fn log_security_event(&self, event: PathSecurityEvent) {
        let mut events = self.security_events.lock().unwrap();

        // Keep only the last 1000 events to prevent memory issues
        if events.len() >= 1000 {
            events.drain(0..500);
        }

        events.push(event.clone());

        match &event {
            PathSecurityEvent::PathValidation { result, path, .. } => match &result.status {
                ValidationStatus::Blocked(reason) => {
                    warn!("Path blocked: {} - {}", path, reason);
                }
                ValidationStatus::Failed(reason) => {
                    error!("Path validation failed: {} - {}", path, reason);
                }
                _ => {
                    debug!("Path validated: {}", path);
                }
            },
            PathSecurityEvent::MountIntegrityCheck {
                integrity_status,
                mount_point,
                ..
            } => match integrity_status {
                IntegrityStatus::Intact => {
                    debug!("Mount integrity check passed: {}", mount_point);
                }
                status => {
                    warn!(
                        "Mount integrity issue detected: {} - {:?}",
                        mount_point, status
                    );
                }
            },
            PathSecurityEvent::SymlinkAttack {
                blocked,
                suspicious_path,
                ..
            } => {
                if *blocked {
                    warn!("Symlink attack blocked: {}", suspicious_path);
                } else {
                    error!(
                        "Symlink attack detected but not blocked: {}",
                        suspicious_path
                    );
                }
            }
            _ => {
                debug!("Security event logged: {:?}", event);
            }
        }
    }

    /// Get recent security events
    pub fn get_security_events(&self, limit: usize) -> Vec<PathSecurityEvent> {
        let events = self.security_events.lock().unwrap();
        let len = events.len();
        if len > limit {
            events[len - limit..].to_vec()
        } else {
            events.clone()
        }
    }

    /// Get security statistics
    pub fn get_security_statistics(&self) -> HashMap<String, u64> {
        let events = self.security_events.lock().unwrap();
        let mut stats = HashMap::new();

        stats.insert("total_events".to_string(), events.len() as u64);

        let mut validation_events = 0;
        let mut integrity_events = 0;
        let mut symlink_events = 0;
        let mut runtime_events = 0;

        let mut blocked_paths = 0;
        let mut failed_validations = 0;

        for event in events.iter() {
            match event {
                PathSecurityEvent::PathValidation { result, .. } => {
                    validation_events += 1;
                    match &result.status {
                        ValidationStatus::Blocked(_) => blocked_paths += 1,
                        ValidationStatus::Failed(_) => failed_validations += 1,
                        _ => {}
                    }
                }
                PathSecurityEvent::MountIntegrityCheck { .. } => integrity_events += 1,
                PathSecurityEvent::SymlinkAttack { .. } => symlink_events += 1,
                PathSecurityEvent::RuntimeValidation { .. } => runtime_events += 1,
            }
        }

        stats.insert("validation_events".to_string(), validation_events);
        stats.insert("integrity_events".to_string(), integrity_events);
        stats.insert("symlink_events".to_string(), symlink_events);
        stats.insert("runtime_events".to_string(), runtime_events);
        stats.insert("blocked_paths".to_string(), blocked_paths);
        stats.insert("failed_validations".to_string(), failed_validations);

        let blocked_paths = self.blocked_paths.read().unwrap();
        stats.insert(
            "total_blocked_paths".to_string(),
            blocked_paths.len() as u64,
        );

        let mounts = self.mounts.read().unwrap();
        stats.insert("monitored_mounts".to_string(), mounts.len() as u64);

        stats
    }

    /// Generate security report
    pub async fn generate_security_report(&self) -> Result<String> {
        let stats = self.get_security_statistics();
        let recent_events = self.get_security_events(50);
        let validation_results = self.validate_all_mounts().await?;

        let mut report = String::new();
        report.push_str("# Fuji Path Security Report\n\n");
        report.push_str(&format!(
            "Generated at: {}\n\n",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ));

        // Statistics section
        report.push_str("## Statistics\n\n");
        report.push_str("| Metric | Count |\n");
        report.push_str("|--------|-------|\n");
        for (key, value) in stats {
            report.push_str(&format!("| {} | {} |\n", key, value));
        }
        report.push_str("\n");

        // Mount integrity section
        report.push_str("## Mount Integrity Status\n\n");
        report.push_str("| Mount ID | Status |\n");
        report.push_str("|----------|--------|\n");
        for (mount_id, status) in validation_results {
            report.push_str(&format!("| {} | {:?} |\n", mount_id, status));
        }
        report.push_str("\n");

        // Recent events section
        report.push_str("## Recent Security Events (Last 50)\n\n");
        if recent_events.is_empty() {
            report.push_str("No recent security events.\n");
        } else {
            for event in recent_events.iter().rev() {
                match event {
                    PathSecurityEvent::PathValidation {
                        path,
                        result,
                        timestamp,
                        ..
                    } => {
                        let status_str = match &result.status {
                            ValidationStatus::Valid => "✅ Valid".to_string(),
                            ValidationStatus::Blocked(reason) => format!("🚫 Blocked: {}", reason),
                            ValidationStatus::RequiresVerification => {
                                "⚠️  Requires Verification".to_string()
                            }
                            ValidationStatus::Failed(reason) => format!("❌ Failed: {}", reason),
                        };
                        report.push_str(&format!(
                            "- [{}] {}: {}\n",
                            timestamp.format("%H:%M:%S"),
                            path,
                            status_str
                        ));
                    }
                    PathSecurityEvent::SymlinkAttack {
                        suspicious_path,
                        attack_type,
                        timestamp,
                        blocked,
                        ..
                    } => {
                        report.push_str(&format!(
                            "- [{}] {}: {} - {:?} {}\n",
                            timestamp.format("%H:%M:%S"),
                            if *blocked {
                                "🚫 Blocked"
                            } else {
                                "⚠️  Detected"
                            },
                            suspicious_path,
                            attack_type,
                            if *blocked { "" } else { "(not blocked)" }
                        ));
                    }
                    _ => {
                        let timestamp = Utc::now();
                        report.push_str(&format!(
                            "- [{}] {:?}\n",
                            timestamp.format("%H:%M:%S"),
                            event
                        ));
                    }
                }
            }
        }

        Ok(report)
    }

    /// Remove a mount from monitoring
    pub async fn unregister_mount(&self, mount_id: &str) -> Result<()> {
        let mount_config = {
            let mut mounts = self.mounts.write().unwrap();
            mounts.remove(mount_id)
        };

        if let Some(config) = mount_config {
            info!(
                "Unregistered mount from security monitoring: {}",
                config.mount_point.display()
            );

            // Log the unregistration event
            self.log_security_event(PathSecurityEvent::PathValidation {
                path: config.mount_point.to_string_lossy().to_string(),
                operation: "mount_unregistration".to_string(),
                result: ValidationResult {
                    is_safe: true,
                    warning_message: None,
                    security_events: vec![],
                    status: ValidationStatus::Valid,
                },
                timestamp: Utc::now(),
                context: {
                    let mut ctx = HashMap::new();
                    ctx.insert("mount_id".to_string(), mount_id.to_string());
                    ctx
                },
            });
        }

        Ok(())
    }
}

/// Default implementation for testing
impl Default for PathSecurityValidator {
    fn default() -> Self {
        Self::new(SecurityProfile::Standard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::fs;

    #[tokio::test]
    async fn test_path_security_validator_creation() {
        let validator = PathSecurityValidator::new(SecurityProfile::Standard);
        let stats = validator.get_security_statistics();
        assert_eq!(stats.get("total_events"), Some(&0));
    }

    #[tokio::test]
    async fn test_mount_registration() -> Result<()> {
        let validator = PathSecurityValidator::new(SecurityProfile::Standard);
        let temp_dir = TempDir::new()?;
        let mount_point = temp_dir.path().join("test_mount");

        // Create mount directory
        fs::create_dir(&mount_point).await?;

        let mount_id = "test-mount-1".to_string();
        validator
            .register_mount(
                mount_id.clone(),
                mount_point.clone(),
                "nfs://server.example.com/export".to_string(),
                vec![mount_point.clone()],
            )
            .await?;

        // Check that mount was registered
        let config = validator.get_mount_config(&mount_id);
        assert!(config.is_some());
        assert_eq!(config.unwrap().mount_id, mount_id);

        Ok(())
    }

    #[tokio::test]
    async fn test_path_validation() -> Result<()> {
        let validator = PathSecurityValidator::new(SecurityProfile::Standard);
        let temp_dir = TempDir::new()?;
        let test_path = temp_dir.path().join("test_file.txt");

        // Create test file
        fs::write(&test_path, "test content").await?;

        // Test valid path
        let result = validator.validate_path(&test_path, "read", None).await?;
        assert!(result.is_safe && result.status == ValidationStatus::Valid);

        // Test dangerous system file path
        let dangerous_path = PathBuf::from("/etc/passwd");
        let result = validator
            .validate_path(&dangerous_path, "read", None)
            .await?;
        assert!(!result.is_safe && result.warning_message.is_some());

        Ok(())
    }

    #[tokio::test]
    async fn test_blocked_paths() -> Result<()> {
        let validator = PathSecurityValidator::new(SecurityProfile::Standard);
        let blocked_path = "/tmp/suspicious";

        // Initially should not be blocked
        let result = validator
            .validate_path(Path::new(blocked_path), "read", None)
            .await?;
        assert!(result.is_safe && result.status == ValidationStatus::Valid);

        // Block the path
        validator.block_path(blocked_path);

        // Now should be blocked
        let result = validator
            .validate_path(Path::new(blocked_path), "read", None)
            .await?;
        assert!(!result.is_safe && result.warning_message.is_some());

        Ok(())
    }

    #[tokio::test]
    async fn test_symlink_depth_validation() -> Result<()> {
        let validator = PathSecurityValidator::new(SecurityProfile::High);
        let temp_dir = TempDir::new()?;

        // Create a chain of symlinks exceeding the max depth (2 for High profile)
        let link1 = temp_dir.path().join("link1");
        let link2 = temp_dir.path().join("link2");
        let target_file = temp_dir.path().join("target.txt");

        fs::write(&target_file, "test").await?;

        // Create symlink chain: link1 -> link2 -> target.txt
        std::os::unix::fs::symlink(&link2, &link1)?;
        std::os::unix::fs::symlink(&target_file, &link2)?;

        // This should fail due to deep symlinks
        let result = validator.validate_symlink_depth(&link1, 2).await;
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_security_event_logging() -> Result<()> {
        let validator = PathSecurityValidator::new(SecurityProfile::Standard);
        let temp_dir = TempDir::new()?;
        let test_path = temp_dir.path().join("test.txt");

        // Generate some security events
        validator.log_security_event(PathSecurityEvent::PathValidation {
            path: test_path.to_string_lossy().to_string(),
            operation: "test".to_string(),
            result: ValidationResult {
                is_safe: true,
                warning_message: None,
                security_events: vec![],
                status: ValidationStatus::Valid,
            },
            timestamp: Utc::now(),
            context: HashMap::new(),
        });

        validator.log_security_event(PathSecurityEvent::PathValidation {
            path: "/etc/passwd".to_string(),
            operation: "test".to_string(),
            result: ValidationResult {
                is_safe: false,
                warning_message: Some("System file".to_string()),
                security_events: vec![],
                status: ValidationStatus::Blocked("Access violation".to_string()),
            },
            timestamp: Utc::now(),
            context: HashMap::new(),
        });

        // Check events
        let events = validator.get_security_events(10);
        assert_eq!(events.len(), 2);

        // Check statistics
        let stats = validator.get_security_statistics();
        assert_eq!(stats.get("total_events"), Some(&2));
        assert_eq!(stats.get("blocked_paths"), Some(&1));

        Ok(())
    }

    #[tokio::test]
    async fn test_security_report() -> Result<()> {
        let validator = PathSecurityValidator::new(SecurityProfile::Standard);
        let temp_dir = TempDir::new()?;
        let mount_point = temp_dir.path().join("test_mount");

        fs::create_dir(&mount_point).await?;

        let mount_id = "test-mount-report".to_string();
        validator
            .register_mount(
                mount_id,
                mount_point.clone(),
                "nfs://server.example.com/export".to_string(),
                vec![],
            )
            .await?;

        // Generate some events
        validator.log_security_event(PathSecurityEvent::MountIntegrityCheck {
            mount_id: "test-mount-report".to_string(),
            mount_point: mount_point.to_string_lossy().to_string(),
            integrity_status: IntegrityStatus::Intact,
            timestamp: Utc::now(),
            violations: vec![],
        });

        // Generate report
        let report = validator.generate_security_report().await?;
        assert!(report.contains("Fuji Path Security Report"));
        assert!(report.contains("Statistics"));
        assert!(report.contains("Mount Integrity Status"));

        Ok(())
    }
}
