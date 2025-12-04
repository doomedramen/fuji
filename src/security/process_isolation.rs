//! Process isolation and namespace management
//!
//! This module provides comprehensive process isolation using Linux namespaces
//! and privilege separation techniques to enhance security.

use anyhow::{anyhow, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use tokio::process::Command as TokioCommand;
use tracing::{debug, error, info, warn};

// Use standard library types for cross-platform compatibility
#[cfg(unix)]
use std::os::unix::raw::{gid_t, uid_t};

// Conditional compilation for namespace support
#[cfg(target_os = "linux")]
use libc::c_int;

#[cfg(target_os = "linux")]
use nix::unistd::{chroot, getgid, getuid, setgid, setuid};

#[cfg(target_os = "linux")]
use nix::sched::{clone, CloneFlags};

/// Namespace isolation configuration
#[derive(Debug, Clone)]
pub struct NamespaceConfig {
    /// Enable PID namespace isolation
    pub pid_namespace: bool,
    /// Enable mount namespace isolation
    pub mount_namespace: bool,
    /// Enable network namespace isolation
    pub network_namespace: bool,
    /// Enable UTS namespace isolation (hostname)
    pub uts_namespace: bool,
    /// Enable IPC namespace isolation
    pub ipc_namespace: bool,
    /// Enable user namespace isolation
    pub user_namespace: bool,
    /// Enable cgroup namespace isolation
    pub cgroup_namespace: bool,
    /// Target hostname for UTS namespace
    pub hostname: Option<String>,
    /// Root directory for chroot/pivot_root
    pub root_dir: Option<PathBuf>,
    /// Drop privileges to this user
    pub drop_uid: Option<uid_t>,
    /// Drop privileges to this group
    pub drop_gid: Option<gid_t>,
    /// Mount points to create in new namespace
    pub mount_points: Vec<MountPoint>,
    /// Network interfaces to configure
    pub network_config: Option<NetworkConfig>,
}

/// Mount point configuration
#[derive(Debug, Clone)]
pub struct MountPoint {
    /// Source path
    pub source: PathBuf,
    /// Target mount point
    pub target: PathBuf,
    /// Filesystem type
    pub fs_type: String,
    /// Mount options
    pub options: Vec<String>,
    /// Read-only mount
    pub read_only: bool,
    /// Create target directory if needed
    pub create_target: bool,
}

/// Network configuration for isolated namespace
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Network interface name
    pub interface: String,
    /// IP address
    pub ip_address: String,
    /// Netmask
    pub netmask: String,
    /// Gateway
    pub gateway: Option<String>,
}

/// Isolated process manager
pub struct ProcessIsolator {
    config: NamespaceConfig,
    isolated_processes: Arc<Mutex<Vec<IsolatedProcess>>>,
}

/// Information about an isolated process
#[derive(Debug)]
pub struct IsolatedProcess {
    /// Process ID
    pub pid: u32,
    /// Namespace configuration
    pub config: NamespaceConfig,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Process status
    pub status: ProcessStatus,
}

/// Process status in isolation
#[derive(Debug, Clone)]
pub enum ProcessStatus {
    /// Process is running
    Running,
    /// Process completed successfully
    Completed,
    /// Process failed
    Failed,
    /// Process was killed
    Killed,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            pid_namespace: true,
            mount_namespace: true,
            network_namespace: false,
            uts_namespace: true,
            ipc_namespace: true,
            user_namespace: false,
            cgroup_namespace: false,
            hostname: Some("fuji-isolated".to_string()),
            root_dir: None,
            drop_uid: None,
            drop_gid: None,
            mount_points: Vec::new(),
            network_config: None,
        }
    }
}

impl ProcessIsolator {
    /// Create a new process isolator
    pub fn new(config: NamespaceConfig) -> Self {
        Self {
            config,
            isolated_processes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a process with namespace isolation (Linux only)
    #[cfg(target_os = "linux")]
    pub fn create_isolated_process(&self, command: &str, args: Vec<String>) -> Result<u32> {
        info!("Creating isolated process for command: {}", command);

        // Determine clone flags based on configuration
        let clone_flags = self.build_clone_flags();

        // Setup stack for cloned process
        let stack = &mut [0u8; 1024 * 1024]; // 1MB stack

        // Create callback for the isolated process
        let config = self.config.clone();
        let cmd = command.to_string();
        let process_args = args.clone();

        extern "C" fn isolated_process_main(arg: *mut libc::c_void) -> c_int {
            unsafe {
                let config = Box::from_raw(arg as *mut NamespaceConfig);

                // Setup namespaces
                if let Err(e) = setup_namespaces(&config) {
                    error!("Failed to setup namespaces: {}", e);
                    return 1;
                }

                // Execute the command
                let mut command = Command::new(
                    &config
                        .root_dir
                        .as_ref()
                        .map(|r| Path::new(r).join(&cmd))
                        .as_deref()
                        .unwrap_or(Path::new(&cmd)),
                );

                command.args(&process_args);
                command.stdout(Stdio::inherit());
                command.stderr(Stdio::inherit());
                command.stdin(Stdio::inherit());

                match command.status() {
                    Ok(status) => {
                        if status.success() {
                            info!("Isolated process completed successfully");
                            0
                        } else {
                            error!("Isolated process failed with status: {}", status);
                            status.code().unwrap_or(1)
                        }
                    }
                    Err(e) => {
                        error!("Failed to execute isolated process: {}", e);
                        1
                    }
                }
            }
        }

        // Clone the process with isolation
        let config_box = Box::new(self.config.clone());
        let config_ptr = Box::into_raw(config_box);

        match unsafe {
            clone(
                clone_flags,
                isolated_process_main as extern "C" fn(*mut libc::c_void) -> c_int,
                stack.as_mut_ptr() as *mut _,
                config_ptr as *mut _,
            )
        } {
            Ok(pid) => {
                info!("Created isolated process with PID: {}", pid);

                // Track the isolated process
                let process = IsolatedProcess {
                    pid: pid as u32,
                    config: self.config.clone(),
                    created_at: chrono::Utc::now(),
                    status: ProcessStatus::Running,
                };

                self.isolated_processes.lock().unwrap().push(process);
                Ok(pid as u32)
            }
            Err(e) => {
                // Clean up the boxed config
                unsafe {
                    Box::from_raw(config_ptr);
                }
                Err(anyhow!("Failed to create isolated process: {}", e))
            }
        }
    }

    /// Create a process with isolation (fallback for non-Linux)
    #[cfg(not(target_os = "linux"))]
    pub fn create_isolated_process(&self, command: &str, args: Vec<String>) -> Result<u32> {
        // Fallback to basic process execution without namespaces
        info!("Creating process (no namespace isolation): {}", command);

        let mut cmd = Command::new(command);
        cmd.args(args);
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
        cmd.stdin(Stdio::inherit());

        match cmd.spawn() {
            Ok(child) => {
                let pid = child.id() as u32;

                // Track the process
                let process = IsolatedProcess {
                    pid,
                    config: self.config.clone(),
                    created_at: chrono::Utc::now(),
                    status: ProcessStatus::Running,
                };

                self.isolated_processes.lock().unwrap().push(process);
                Ok(pid)
            }
            Err(e) => Err(anyhow!("Failed to create process: {}", e)),
        }
    }

    /// Create isolated process using async approach
    pub async fn create_isolated_process_async(
        &self,
        command: &str,
        args: Vec<String>,
    ) -> Result<tokio::process::Child> {
        info!("Creating isolated async process for command: {}", command);

        // Create unshare command for namespace setup
        let mut unshare_cmd = TokioCommand::new("unshare");

        // Add namespace flags
        if self.config.pid_namespace {
            unshare_cmd.arg("--pid");
            unshare_cmd.arg("--fork");
        }
        if self.config.mount_namespace {
            unshare_cmd.arg("--mount");
        }
        if self.config.network_namespace {
            unshare_cmd.arg("--net");
        }
        if self.config.uts_namespace {
            unshare_cmd.arg("--uts");
        }
        if self.config.ipc_namespace {
            unshare_cmd.arg("--ipc");
        }
        if self.config.user_namespace {
            unshare_cmd.arg("--user");
        }
        if self.config.cgroup_namespace {
            unshare_cmd.arg("--cgroup");
        }

        // Set hostname if UTS namespace is enabled
        if self.config.uts_namespace && self.config.hostname.is_some() {
            unshare_cmd.arg("--hostname");
            unshare_cmd.arg(self.config.hostname.as_ref().unwrap());
        }

        // Add the actual command
        unshare_cmd.arg(command);
        unshare_cmd.args(args);

        // Execute the command
        let child = unshare_cmd
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .stdin(Stdio::inherit())
            .spawn()?;

        Ok(child)
    }

    /// Build clone flags based on configuration (Linux only)
    #[cfg(target_os = "linux")]
    fn build_clone_flags(&self) -> CloneFlags {
        let mut flags = CloneFlags::empty();

        if self.config.pid_namespace {
            flags |= CloneFlags::CLONE_NEWPID;
        }
        if self.config.mount_namespace {
            flags |= CloneFlags::CLONE_NEWNS;
        }
        if self.config.network_namespace {
            flags |= CloneFlags::CLONE_NEWNET;
        }
        if self.config.uts_namespace {
            flags |= CloneFlags::CLONE_NEWUTS;
        }
        if self.config.ipc_namespace {
            flags |= CloneFlags::CLONE_NEWIPC;
        }
        if self.config.user_namespace {
            flags |= CloneFlags::CLONE_NEWUSER;
        }
        if self.config.cgroup_namespace {
            flags |= CloneFlags::CLONE_NEWCGROUP;
        }

        flags
    }

    /// Get list of isolated processes
    pub fn get_isolated_processes(&self) -> Vec<IsolatedProcess> {
        self.isolated_processes.lock().unwrap().clone()
    }

    /// Terminate an isolated process
    pub fn terminate_isolated_process(&self, pid: u32) -> Result<()> {
        info!("Terminating isolated process: {}", pid);

        // Send SIGTERM to the process
        #[cfg(target_os = "linux")]
        {
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGTERM,
            )?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Fallback for non-Linux platforms
            std::process::Command::new("kill")
                .arg(pid.to_string())
                .output()?;
        }

        // Update process status
        if let Ok(mut processes) = self.isolated_processes.lock() {
            if let Some(process) = processes.iter_mut().find(|p| p.pid == pid) {
                process.status = ProcessStatus::Killed;
            }
        }

        Ok(())
    }

    /// Clean up terminated processes
    pub fn cleanup_terminated_processes(&self) -> Result<usize> {
        let mut processes = self.isolated_processes.lock().unwrap();
        let initial_count = processes.len();

        // Remove processes that are no longer running
        processes.retain(|p| {
            #[cfg(target_os = "linux")]
            {
                match nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(p.pid as i32),
                    nix::sys::signal::Signal::SIGCONT,
                ) {
                    Ok(_) => {
                        // Process still exists
                        true
                    }
                    Err(nix::Error::ESRCH) => {
                        // Process doesn't exist anymore
                        info!("Cleaning up terminated process: {}", p.pid);
                        false
                    }
                    Err(_) => {
                        // Other error, keep for now
                        true
                    }
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                // Fallback for non-Linux platforms
                match std::process::Command::new("kill")
                    .arg("-0")
                    .arg(p.pid.to_string())
                    .output()
                {
                    Ok(output) => {
                        if output.status.success() {
                            true // Process still exists
                        } else {
                            info!("Cleaning up terminated process: {}", p.pid);
                            false // Process doesn't exist
                        }
                    }
                    Err(_) => {
                        true // Error checking, keep for now
                    }
                }
            }
        });

        Ok(initial_count - processes.len())
    }
}

/// Setup namespaces for the current process (Linux only)
#[cfg(target_os = "linux")]
fn setup_namespaces(config: &NamespaceConfig) -> Result<()> {
    debug!("Setting up namespaces for isolated process");

    // Setup UTS namespace (hostname)
    if config.uts_namespace {
        if let Some(ref hostname) = config.hostname {
            nix::unistd::sethostname(hostname)?;
            debug!("Set hostname to: {}", hostname);
        }
    }

    // Setup mount namespace and chroot
    if config.mount_namespace {
        setup_mount_namespace(config)?;
    }

    // Setup network namespace
    if config.network_namespace {
        setup_network_namespace(config)?;
    }

    // Drop privileges if configured
    if let Some(uid) = config.drop_uid {
        setuid(uid.into())?;
        debug!("Dropped privileges to UID: {}", uid);
    }

    if let Some(gid) = config.drop_gid {
        setgid(gid.into())?;
        debug!("Dropped privileges to GID: {}", gid);
    }

    Ok(())
}

/// Setup namespaces for the current process (fallback for non-Linux)
#[cfg(not(target_os = "linux"))]
fn setup_namespaces(_config: &NamespaceConfig) -> Result<()> {
    debug!("Namespace setup not supported on this platform");
    Ok(())
}

/// Setup mount namespace with isolated filesystem (Linux only)
#[cfg(target_os = "linux")]
fn setup_mount_namespace(config: &NamespaceConfig) -> Result<()> {
    debug!("Setting up mount namespace");

    // Make all mounts private
    nix::mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
        None::<&str>,
    )?;

    // Create mount points
    for mount_point in &config.mount_points {
        create_mount_point(mount_point)?;
    }

    // Setup chroot if configured
    if let Some(ref root_dir) = config.root_dir {
        setup_chroot(root_dir)?;
    }

    Ok(())
}

/// Setup mount namespace with isolated filesystem (fallback for non-Linux)
#[cfg(not(target_os = "linux"))]
fn setup_mount_namespace(_config: &NamespaceConfig) -> Result<()> {
    debug!("Mount namespace setup not supported on this platform");
    Ok(())
}

/// Create a mount point in the isolated namespace (Linux only)
#[cfg(target_os = "linux")]
fn create_mount_point(mount: &MountPoint) -> Result<()> {
    // Create target directory if needed
    if mount.create_target {
        if let Some(parent) = mount.target.parent() {
            fs::create_dir_all(parent)?;
        }
        if !mount.target.exists() {
            fs::create_dir(&mount.target)?;
            let mut perms = mount.target.metadata()?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&mount.target, perms)?;
        }
    }

    let mut flags = nix::mount::MsFlags::empty();
    let mut options_str = String::new();

    for option in &mount.options {
        if option == "noexec" {
            flags |= nix::mount::MsFlags::MS_NOEXEC;
        } else if option == "nosuid" {
            flags |= nix::mount::MsFlags::MS_NOSUID;
        } else if option == "nodev" {
            flags |= nix::mount::MsFlags::MS_NODEV;
        } else if option == "ro" {
            flags |= nix::mount::MsFlags::MS_RDONLY;
        } else {
            if !options_str.is_empty() {
                options_str.push(',');
            }
            options_str.push_str(option);
        }
    }

    if mount.read_only {
        flags |= nix::mount::MsFlags::MS_RDONLY;
    }

    // Perform the mount
    nix::mount::mount(
        Some(&mount.source),
        &mount.target,
        Some(&mount.fs_type),
        flags,
        Some(&options_str),
    )?;

    info!(
        "Mounted {} at {}",
        mount.source.display(),
        mount.target.display()
    );
    Ok(())
}

/// Create a mount point in the isolated namespace (fallback for non-Linux)
#[cfg(not(target_os = "linux"))]
fn create_mount_point(_mount: &MountPoint) -> Result<()> {
    debug!("Mount point creation not supported on this platform");
    Ok(())
}

/// Setup chroot or pivot_root for filesystem isolation (Linux only)
#[cfg(target_os = "linux")]
fn setup_chroot(root_dir: &Path) -> Result<()> {
    if !root_dir.exists() {
        return Err(anyhow!(
            "Root directory does not exist: {}",
            root_dir.display()
        ));
    }

    // Ensure root directory is absolute
    let root_dir = root_dir.canonicalize()?;

    // Create necessary directories in chroot
    let chroot_dev = root_dir.join("dev");
    let chroot_proc = root_dir.join("proc");
    let chroot_sys = root_dir.join("sys");

    if !chroot_dev.exists() {
        fs::create_dir(&chroot_dev)?;
        let mut perms = chroot_dev.metadata()?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&chroot_dev, perms)?;
    }
    if !chroot_proc.exists() {
        fs::create_dir(&chroot_proc)?;
        let mut perms = chroot_proc.metadata()?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&chroot_proc, perms)?;
    }
    if !chroot_sys.exists() {
        fs::create_dir(&chroot_sys)?;
        let mut perms = chroot_sys.metadata()?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&chroot_sys, perms)?;
    }

    // Mount essential filesystems
    nix::mount::mount(
        Some("none"),
        &chroot_proc,
        Some("proc"),
        nix::mount::MsFlags::empty(),
        None::<&str>,
    )?;

    // Change root
    chroot(&root_dir)?;
    nix::unistd::chdir("/")?;

    info!("Changed root to: {}", root_dir.display());
    Ok(())
}

/// Setup chroot or pivot_root for filesystem isolation (fallback for non-Linux)
#[cfg(not(target_os = "linux"))]
fn setup_chroot(_root_dir: &Path) -> Result<()> {
    debug!("Chroot setup not supported on this platform");
    Ok(())
}

/// Setup network namespace configuration (Linux only)
#[cfg(target_os = "linux")]
fn setup_network_namespace(config: &NamespaceConfig) -> Result<()> {
    debug!("Setting up network namespace");

    if let Some(ref net_config) = config.network_config {
        // Bring up loopback interface
        Command::new("ip")
            .args(&["link", "set", "lo", "up"])
            .output()?;

        // Configure network interface
        Command::new("ip")
            .args(&["link", "set", &net_config.interface, "up"])
            .output()?;

        // Assign IP address
        Command::new("ip")
            .args(&[
                "addr",
                "add",
                &format!("{}/{}", net_config.ip_address, net_config.netmask),
                "dev",
                &net_config.interface,
            ])
            .output()?;

        // Set gateway if configured
        if let Some(ref gateway) = net_config.gateway {
            Command::new("ip")
                .args(&["route", "add", "default", "via", gateway])
                .output()?;
        }

        info!("Configured network interface: {}", net_config.interface);
    }

    Ok(())
}

/// Setup network namespace configuration (fallback for non-Linux)
#[cfg(not(target_os = "linux"))]
fn setup_network_namespace(_config: &NamespaceConfig) -> Result<()> {
    debug!("Network namespace setup not supported on this platform");
    Ok(())
}

/// Create a secure sandbox environment
pub struct Sandbox {
    isolator: ProcessIsolator,
    temp_dir: PathBuf,
}

impl Sandbox {
    /// Create a new sandbox
    pub fn new() -> Result<Self> {
        let temp_dir = std::env::temp_dir().join("fuji-sandbox");
        fs::create_dir_all(&temp_dir)?;

        let config = NamespaceConfig {
            pid_namespace: true,
            mount_namespace: true,
            network_namespace: true,
            uts_namespace: true,
            ipc_namespace: true,
            user_namespace: false,
            cgroup_namespace: false,
            hostname: Some("fuji-sandbox".to_string()),
            root_dir: Some(temp_dir.clone()),
            drop_uid: Some(65534), // nobody
            drop_gid: Some(65534), // nogroup
            mount_points: vec![MountPoint {
                source: PathBuf::from("none"),
                target: PathBuf::from("/tmp"),
                fs_type: "tmpfs".to_string(),
                options: vec![
                    "size=100m".to_string(),
                    "noexec".to_string(),
                    "nosuid".to_string(),
                ],
                read_only: false,
                create_target: true,
            }],
            network_config: None,
        };

        Ok(Self {
            isolator: ProcessIsolator::new(config),
            temp_dir,
        })
    }

    /// Execute a command in the sandbox
    pub async fn execute(&self, command: &str, args: Vec<String>) -> Result<tokio::process::Child> {
        self.isolator
            .create_isolated_process_async(command, args)
            .await
    }

    /// Cleanup sandbox resources
    pub fn cleanup(&self) -> Result<()> {
        // Terminate all processes
        let processes = self.isolator.get_isolated_processes();
        for process in processes {
            let _ = self.isolator.terminate_isolated_process(process.pid);
        }

        // Clean up temp directory
        if self.temp_dir.exists() {
            fs::remove_dir_all(&self.temp_dir)?;
        }

        Ok(())
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_config_default() {
        let config = NamespaceConfig::default();
        assert!(config.pid_namespace);
        assert!(config.mount_namespace);
        assert!(!config.network_namespace);
        assert!(config.uts_namespace);
        assert_eq!(config.hostname, Some("fuji-isolated".to_string()));
    }

    #[test]
    fn test_process_isolator_creation() {
        let config = NamespaceConfig::default();
        let isolator = ProcessIsolator::new(config);
        assert_eq!(isolator.get_isolated_processes().len(), 0);
    }

    #[test]
    fn test_sandbox_creation() {
        let sandbox = Sandbox::new();
        assert!(sandbox.is_ok());
    }
}
