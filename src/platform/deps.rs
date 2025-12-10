//! System dependencies checker
//!
//! This module provides functionality to check for required system binaries
//! and provide helpful error messages with installation instructions.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::process::Command;
use tracing::{debug, info, warn};

/// System dependency information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemDependency {
    /// Name of the binary/command
    pub binary_name: String,
    /// Display name for the dependency
    pub display_name: String,
    /// Description of what this dependency is for
    pub description: String,
    /// Installation instructions keyed by OS family
    pub install_instructions: HashMap<String, String>,
    /// Version check command (optional)
    pub version_check: Option<String>,
    /// Minimum required version (optional)
    pub min_version: Option<String>,
    /// Whether this dependency is required or optional
    pub required: bool,
}

/// Result of a dependency check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyCheckResult {
    /// Whether the dependency is available
    pub available: bool,
    /// Version string if available
    pub version: Option<String>,
    /// Error message if not available
    pub error: Option<String>,
    /// Installation instructions
    pub install_instructions: Option<String>,
}

/// Overall system dependencies check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemDepsCheckResult {
    /// Results for each dependency
    pub dependencies: HashMap<String, DependencyCheckResult>,
    /// Whether all required dependencies are available
    pub all_required_available: bool,
    /// List of missing required dependencies
    pub missing_required: Vec<String>,
}

/// System dependencies checker
pub struct SystemDepsChecker {
    /// Known dependencies
    dependencies: HashMap<String, SystemDependency>,
}

impl Default for SystemDepsChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemDepsChecker {
    /// Create a new system dependencies checker
    pub fn new() -> Self {
        let mut checker = Self {
            dependencies: HashMap::new(),
        };

        // Initialize with known dependencies
        checker.init_dependencies();
        checker
    }

    /// Initialize known dependencies
    fn init_dependencies(&mut self) {
        // NFS client
        let mut nfs_install = HashMap::new();
        nfs_install.insert(
            "debian".to_string(),
            "sudo apt-get install nfs-common".to_string(),
        );
        nfs_install.insert(
            "ubuntu".to_string(),
            "sudo apt-get install nfs-common".to_string(),
        );
        nfs_install.insert("rhel".to_string(), "sudo yum install nfs-utils".to_string());
        nfs_install.insert(
            "centos".to_string(),
            "sudo yum install nfs-utils".to_string(),
        );
        nfs_install.insert(
            "fedora".to_string(),
            "sudo dnf install nfs-utils".to_string(),
        );
        nfs_install.insert("arch".to_string(), "sudo pacman -S nfs-utils".to_string());
        nfs_install.insert("alpine".to_string(), "sudo apk add nfs-utils".to_string());
        nfs_install.insert("macos".to_string(), "NFS is built into macOS".to_string());
        nfs_install.insert("bsd".to_string(), "NFS is built into BSD".to_string());

        self.dependencies.insert(
            "nfs".to_string(),
            SystemDependency {
                binary_name: "mount.nfs".to_string(),
                display_name: "NFS Client".to_string(),
                description: "For mounting NFS shares".to_string(),
                install_instructions: nfs_install,
                version_check: Some("mount.nfs --version".to_string()),
                min_version: None,
                required: true,
            },
        );

        // SMB/CIFS client
        let mut smb_install = HashMap::new();
        smb_install.insert(
            "debian".to_string(),
            "sudo apt-get install cifs-utils".to_string(),
        );
        smb_install.insert(
            "ubuntu".to_string(),
            "sudo apt-get install cifs-utils".to_string(),
        );
        smb_install.insert(
            "rhel".to_string(),
            "sudo yum install cifs-utils".to_string(),
        );
        smb_install.insert(
            "centos".to_string(),
            "sudo yum install cifs-utils".to_string(),
        );
        smb_install.insert(
            "fedora".to_string(),
            "sudo dnf install cifs-utils".to_string(),
        );
        smb_install.insert("arch".to_string(), "sudo pacman -S smbclient".to_string());
        smb_install.insert("alpine".to_string(), "sudo apk add cifs-utils".to_string());
        smb_install.insert("macos".to_string(), "brew install cifs-utils".to_string());
        smb_install.insert(
            "bsd".to_string(),
            "pkg install sysutils/fusefs-cifs".to_string(),
        );

        self.dependencies.insert(
            "smb".to_string(),
            SystemDependency {
                binary_name: "mount.cifs".to_string(),
                display_name: "SMB/CIFS Client".to_string(),
                description: "For mounting Windows/Samba shares".to_string(),
                install_instructions: smb_install,
                version_check: None,
                min_version: None,
                required: true,
            },
        );

        // SSHFS
        let mut sshfs_install = HashMap::new();
        sshfs_install.insert(
            "debian".to_string(),
            "sudo apt-get install sshfs".to_string(),
        );
        sshfs_install.insert(
            "ubuntu".to_string(),
            "sudo apt-get install sshfs".to_string(),
        );
        sshfs_install.insert(
            "rhel".to_string(),
            "sudo yum install fuse-sshfs".to_string(),
        );
        sshfs_install.insert(
            "centos".to_string(),
            "sudo yum install fuse-sshfs".to_string(),
        );
        sshfs_install.insert(
            "fedora".to_string(),
            "sudo dnf install fuse-sshfs".to_string(),
        );
        sshfs_install.insert("arch".to_string(), "sudo pacman -S sshfs".to_string());
        sshfs_install.insert("alpine".to_string(), "sudo apk add sshfs-fuse".to_string());
        sshfs_install.insert("macos".to_string(), "brew install sshfs".to_string());
        sshfs_install.insert("bsd".to_string(), "pkg install fusefs-sshfs".to_string());

        self.dependencies.insert(
            "sshfs".to_string(),
            SystemDependency {
                binary_name: "sshfs".to_string(),
                display_name: "SSHFS".to_string(),
                description: "For mounting remote filesystems over SSH".to_string(),
                install_instructions: sshfs_install,
                version_check: Some("sshfs --version".to_string()),
                min_version: None,
                required: true,
            },
        );

        // Additional optional dependencies
        let mut showmount_install = HashMap::new();
        showmount_install.insert(
            "debian".to_string(),
            "sudo apt-get install nfs-common".to_string(),
        );
        showmount_install.insert(
            "ubuntu".to_string(),
            "sudo apt-get install nfs-common".to_string(),
        );
        showmount_install.insert("rhel".to_string(), "sudo yum install nfs-utils".to_string());
        showmount_install.insert(
            "centos".to_string(),
            "sudo yum install nfs-utils".to_string(),
        );
        showmount_install.insert(
            "fedora".to_string(),
            "sudo dnf install nfs-utils".to_string(),
        );
        showmount_install.insert("arch".to_string(), "sudo pacman -S nfs-utils".to_string());
        showmount_install.insert("alpine".to_string(), "sudo apk add nfs-utils".to_string());
        showmount_install.insert(
            "macos".to_string(),
            "showmount is built into macOS".to_string(),
        );
        showmount_install.insert("bsd".to_string(), "showmount is built into BSD".to_string());

        self.dependencies.insert(
            "showmount".to_string(),
            SystemDependency {
                binary_name: "showmount".to_string(),
                display_name: "Showmount".to_string(),
                description: "For discovering NFS exports".to_string(),
                install_instructions: showmount_install,
                version_check: None,
                min_version: None,
                required: false,
            },
        );

        let mut smbclient_install = HashMap::new();
        smbclient_install.insert(
            "debian".to_string(),
            "sudo apt-get install smbclient".to_string(),
        );
        smbclient_install.insert(
            "ubuntu".to_string(),
            "sudo apt-get install smbclient".to_string(),
        );
        smbclient_install.insert(
            "rhel".to_string(),
            "sudo yum install samba-client".to_string(),
        );
        smbclient_install.insert(
            "centos".to_string(),
            "sudo yum install samba-client".to_string(),
        );
        smbclient_install.insert(
            "fedora".to_string(),
            "sudo dnf install samba-client".to_string(),
        );
        smbclient_install.insert("arch".to_string(), "sudo pacman -S smbclient".to_string());
        smbclient_install.insert(
            "alpine".to_string(),
            "sudo apk add samba-client".to_string(),
        );
        smbclient_install.insert("macos".to_string(), "brew install smbclient".to_string());
        smbclient_install.insert("bsd".to_string(), "pkg install samba416".to_string());

        self.dependencies.insert(
            "smbclient".to_string(),
            SystemDependency {
                binary_name: "smbclient".to_string(),
                display_name: "SMB Client".to_string(),
                description: "For discovering SMB shares and testing connections".to_string(),
                install_instructions: smbclient_install,
                version_check: Some("smbclient --version".to_string()),
                min_version: None,
                required: false,
            },
        );
    }

    /// Add a custom dependency
    pub fn add_dependency(&mut self, key: String, dependency: SystemDependency) {
        self.dependencies.insert(key, dependency);
    }

    /// Get all dependencies
    pub fn get_dependencies(&self) -> &HashMap<String, SystemDependency> {
        &self.dependencies
    }

    /// Check if a binary exists in PATH
    pub async fn check_binary_exists(&self, binary: &str) -> bool {
        #[cfg(unix)]
        {
            use std::process::Stdio;

            match Command::new("which")
                .arg(binary)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
            {
                Ok(status) => status.success(),
                Err(_) => {
                    // Fallback: try to run the binary directly
                    match Command::new(binary)
                        .arg("--version")
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                        .await
                    {
                        Ok(status) => status.success(),
                        Err(_) => false,
                    }
                }
            }
        }

        #[cfg(not(unix))]
        {
            // Windows fallback
            match Command::new("where")
                .arg(binary)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
            {
                Ok(status) => status.success(),
                Err(_) => false,
            }
        }
    }

    /// Get version of a binary
    async fn get_binary_version(&self, dependency: &SystemDependency) -> Option<String> {
        if let Some(ref version_cmd) = dependency.version_check {
            let parts: Vec<&str> = version_cmd.split_whitespace().collect();
            if parts.is_empty() {
                return None;
            }

            match Command::new(parts[0]).args(&parts[1..]).output().await {
                Ok(output) => {
                    if output.status.success() {
                        String::from_utf8(output.stdout).ok().and_then(|s| {
                            // Extract first line that looks like a version
                            s.lines()
                                .find(|line| {
                                    line.contains('.') || line.chars().any(|c| c.is_ascii_digit())
                                })
                                .map(|line| line.trim().to_string())
                        })
                    } else {
                        None
                    }
                }
                Err(e) => {
                    debug!(
                        "Failed to get version for {}: {}",
                        dependency.binary_name, e
                    );
                    None
                }
            }
        } else {
            None
        }
    }

    /// Get the current OS family
    pub fn get_os_family() -> &'static str {
        #[cfg(target_os = "linux")]
        {
            // Try to detect Linux distribution
            if Path::new("/etc/debian_version").exists() {
                "debian"
            } else if Path::new("/etc/ubuntu-release").exists()
                || Path::new("/etc/lsb-release").exists()
            {
                "ubuntu"
            } else if Path::new("/etc/redhat-release").exists() {
                "rhel"
            } else if Path::new("/etc/centos-release").exists() {
                "centos"
            } else if Path::new("/etc/fedora-release").exists() {
                "fedora"
            } else if Path::new("/etc/arch-release").exists() {
                "arch"
            } else if Path::new("/etc/alpine-release").exists() {
                "alpine"
            } else {
                "linux" // Generic Linux
            }
        }
        #[cfg(target_os = "macos")]
        {
            "macos"
        }
        #[cfg(target_os = "freebsd")]
        {
            "bsd"
        }
        #[cfg(target_os = "netbsd")]
        {
            "bsd"
        }
        #[cfg(target_os = "openbsd")]
        {
            "bsd"
        }
        #[cfg(target_os = "dragonfly")]
        {
            "bsd"
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        )))]
        {
            "unknown"
        }
    }

    /// Check a single dependency
    pub async fn check_dependency(&self, key: &str) -> Result<DependencyCheckResult> {
        let dependency = self
            .dependencies
            .get(key)
            .ok_or_else(|| anyhow!("Unknown dependency: {}", key))?;

        debug!("Checking dependency: {}", key);

        let exists = self.check_binary_exists(&dependency.binary_name).await;

        if exists {
            let version = self.get_binary_version(dependency).await;
            info!(
                "Dependency {} is available{}",
                key,
                version
                    .as_ref()
                    .map_or(String::new(), |v| format!(" (version {})", v))
            );

            Ok(DependencyCheckResult {
                available: true,
                version,
                error: None,
                install_instructions: None,
            })
        } else {
            let os_family = Self::get_os_family();
            let install_instructions = dependency
                .install_instructions
                .get(os_family)
                .or_else(|| dependency.install_instructions.get("linux"))
                .or_else(|| dependency.install_instructions.get("unknown"))
                .cloned();

            warn!("Missing dependency: {}", key);

            Ok(DependencyCheckResult {
                available: false,
                version: None,
                error: Some(format!(
                    "Binary '{}' not found in PATH",
                    dependency.binary_name
                )),
                install_instructions,
            })
        }
    }

    /// Check all dependencies
    pub async fn check_all(&self) -> SystemDepsCheckResult {
        info!("Checking all system dependencies");

        let mut results = HashMap::new();
        let mut all_required_available = true;
        let mut missing_required = Vec::new();

        for (key, dependency) in &self.dependencies {
            match self.check_dependency(key).await {
                Ok(result) => {
                    if !result.available && dependency.required {
                        all_required_available = false;
                        missing_required.push(key.clone());
                    }
                    results.insert(key.clone(), result);
                }
                Err(e) => {
                    warn!("Failed to check dependency {}: {}", key, e);
                    results.insert(
                        key.clone(),
                        DependencyCheckResult {
                            available: false,
                            version: None,
                            error: Some(e.to_string()),
                            install_instructions: None,
                        },
                    );
                    if dependency.required {
                        all_required_available = false;
                        missing_required.push(key.clone());
                    }
                }
            }
        }

        SystemDepsCheckResult {
            dependencies: results,
            all_required_available,
            missing_required,
        }
    }

    /// Check only required dependencies
    pub async fn check_required(&self) -> SystemDepsCheckResult {
        let all_results = self.check_all().await;

        let mut required_results = HashMap::new();
        for (key, result) in all_results.dependencies {
            if let Some(dep) = self.dependencies.get(&key) {
                if dep.required {
                    required_results.insert(key, result);
                }
            }
        }

        SystemDepsCheckResult {
            dependencies: required_results,
            all_required_available: all_results.all_required_available,
            missing_required: all_results.missing_required,
        }
    }

    /// Check dependencies for a specific mount type
    pub async fn check_for_mount_type(
        &self,
        mount_type: &crate::mount::MountType,
    ) -> Result<SystemDepsCheckResult> {
        let required_deps = match mount_type {
            crate::mount::MountType::Nfs {
                ..
            } => vec!["nfs"],
            crate::mount::MountType::Smb {
                ..
            } => vec!["smb"],
            crate::mount::MountType::Sshfs {
                ..
            } => vec!["sshfs"],
        };

        let mut results = HashMap::new();
        let mut all_required_available = true;
        let mut missing_required = Vec::new();

        for dep_key in required_deps {
            match self.check_dependency(dep_key).await {
                Ok(result) => {
                    if !result.available {
                        all_required_available = false;
                        missing_required.push(dep_key.to_string());
                    }
                    results.insert(dep_key.to_string(), result);
                }
                Err(e) => {
                    results.insert(
                        dep_key.to_string(),
                        DependencyCheckResult {
                            available: false,
                            version: None,
                            error: Some(e.to_string()),
                            install_instructions: None,
                        },
                    );
                    all_required_available = false;
                    missing_required.push(dep_key.to_string());
                }
            }
        }

        Ok(SystemDepsCheckResult {
            dependencies: results,
            all_required_available,
            missing_required,
        })
    }

    /// Print a formatted report of the check results
    pub fn print_report(&self, result: &SystemDepsCheckResult) {
        println!("\n=== System Dependencies Check ===");

        // Sort dependencies for consistent output
        let mut sorted_deps: Vec<_> = result.dependencies.iter().collect();
        sorted_deps.sort_by_key(|(k, _)| *k);

        for (key, check_result) in sorted_deps {
            if let Some(dep) = self.dependencies.get(key) {
                if check_result.available {
                    let version_str = check_result
                        .version
                        .as_ref()
                        .map_or(String::new(), |v| format!(" v{}", v));
                    println!(
                        "✓ {}{} - {}",
                        dep.display_name, version_str, dep.description
                    );
                } else {
                    let req_str = if dep.required {
                        " (REQUIRED)"
                    } else {
                        " (optional)"
                    };
                    println!("✗ {}{} - {}", dep.display_name, req_str, dep.description);

                    if let Some(ref error) = check_result.error {
                        println!("  Error: {}", error);
                    }

                    if let Some(ref instructions) = check_result.install_instructions {
                        println!("  To install: {}", instructions);
                    }
                }
            }
        }

        println!();

        if result.all_required_available {
            println!("✓ All required dependencies are available!");
        } else {
            println!("✗ Some required dependencies are missing:");
            for missing in &result.missing_required {
                if let Some(dep) = self.dependencies.get(missing) {
                    println!("  - {}", dep.display_name);
                }
            }
            println!("\nPlease install the missing dependencies before continuing.");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_system_deps_creation() {
        let checker = SystemDepsChecker::new();
        assert!(!checker.get_dependencies().is_empty());
        assert!(checker.get_dependencies().contains_key("nfs"));
        assert!(checker.get_dependencies().contains_key("smb"));
        assert!(checker.get_dependencies().contains_key("sshfs"));
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

    #[tokio::test]
    async fn test_get_os_family() {
        let os = SystemDepsChecker::get_os_family();
        assert!(!os.is_empty());
        println!("Detected OS family: {}", os);
    }

    #[tokio::test]
    async fn test_dependency_check() {
        let checker = SystemDepsChecker::new();

        // Check sh (should exist)
        let mut custom_dep = SystemDependency {
            binary_name: "sh".to_string(),
            display_name: "Shell".to_string(),
            description: "Unix shell".to_string(),
            install_instructions: HashMap::new(),
            version_check: None,
            min_version: None,
            required: true,
        };

        checker.add_dependency("test_shell".to_string(), custom_dep);
        let result = checker.check_dependency("test_shell").await.unwrap();
        assert!(result.available);

        // Check a non-existent binary
        custom_dep = SystemDependency {
            binary_name: "nonexistent-binary-12345".to_string(),
            display_name: "Non-existent".to_string(),
            description: "Should not exist".to_string(),
            install_instructions: HashMap::new(),
            version_check: None,
            min_version: None,
            required: true,
        };

        checker.add_dependency("test_missing".to_string(), custom_dep);
        let result = checker.check_dependency("test_missing").await.unwrap();
        assert!(!result.available);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_check_all() {
        let checker = SystemDepsChecker::new();
        let result = checker.check_all().await;

        // Should have results for all known dependencies
        assert!(!result.dependencies.is_empty());

        // Shell should always be available
        assert!(result.dependencies.len() >= 3); // At least nfs, smb, sshfs
    }
}
