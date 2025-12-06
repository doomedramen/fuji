//! Fuji daemon implementation
//!
//! The daemon handles all mount operations, monitoring, and reconnection logic.

use crate::config::Config;
use crate::mount::{get_mount_handler, MountConfig, MountState, MountStatus};
use crate::platform::Platform;
use std::path::Path;
use crate::security::path_security::{
    IntegrityStatus, PathSecurityEvent, PathSecurityValidator, SecurityProfile,
};
use crate::security::resource_limits::ResourceLimitsManager;
use crate::socket::protocol::DaemonHealthInfo;
use crate::socket::{MountStatusInfo, Request, Response, SocketServer};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use regex;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{oneshot, RwLock};
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

lazy_static::lazy_static! {
    /// A fallback regex that matches nothing - used when user-provided regex is invalid
    static ref EMPTY_REGEX: regex::Regex = regex::Regex::new("^$").expect("Empty regex is always valid");
}

pub mod error;
pub mod monitor;

use error::{DaemonError, DaemonResult};

use monitor::MountMonitor;

/// Main daemon structure
pub struct Daemon {
    /// Platform-specific operations
    platform: Box<dyn Platform>,
    /// Configuration
    config: Arc<RwLock<Config>>,
    /// Mount monitor
    monitor: Arc<MountMonitor>,
    /// Path security validator for enhanced runtime path validation
    path_security: Arc<PathSecurityValidator>,
    /// Resource limits manager for preventing resource exhaustion attacks
    resource_limits: Arc<ResourceLimitsManager>,
    /// Shutdown channel receiver
    shutdown_rx: Arc<RwLock<Option<oneshot::Receiver<()>>>>,
    /// Daemon start time for uptime tracking
    start_time: Instant,
}

/// Internal mount state tracking
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct MountInternalState {
    /// Mount configuration
    config: MountConfig,
    /// Current health state
    health: MountState,
    /// Last reconnection attempt
    last_reconnect_attempt: Option<DateTime<Utc>>,
}

impl Daemon {
    /// Create a new daemon instance
    pub async fn new(platform: Box<dyn Platform>) -> Result<Self> {
        let config = Config::load(platform.as_ref()).await?;
        let config = Arc::new(RwLock::new(config));
        let monitor = Arc::new(MountMonitor::new());

        // Initialize path security validator with high-security profile for daemon operations
        let path_security = Arc::new(PathSecurityValidator::new(SecurityProfile::High));

        // Initialize resource limits manager with configuration
        let resource_limits = {
            let config_read = config.read().await;
            Arc::new(ResourceLimitsManager::new(
                config_read.global.resource_limits.clone().into(),
            ))
        };

        let start_time = Instant::now();

        Ok(Self {
            platform,
            config,
            monitor,
            path_security,
            resource_limits,
            shutdown_rx: Arc::new(RwLock::new(None)),
            start_time,
        })
    }

    /// Start the daemon
    pub async fn start(
        &mut self,
        socket_path: Option<PathBuf>,
        detach: bool,
        no_automount: bool,
    ) -> Result<()> {
        info!("Starting Fuji daemon");

        // Get socket path
        let socket_path = match socket_path {
            Some(path) => path,
            None => {
                let config = self.config.read().await;
                config.get_socket_path(self.platform.as_ref())?
            }
        };

        // Ensure socket directory exists
        if let Some(parent) = socket_path.parent() {
            self.platform.ensure_dir_exists(parent)?;
        }

        // Setup signal handlers
        self.platform.setup_signal_handlers()?;

        // Write PID file
        let pid_file = socket_path.with_extension("pid");
        self.platform.write_pid_file(&pid_file)?;

        // Daemonize if requested
        if detach {
            self.platform.daemonize()?;
        }

        // Create shutdown channel
        let (_shutdown_tx, shutdown_rx) = oneshot::channel();
        *self.shutdown_rx.write().await = Some(shutdown_rx);

        // Start socket server
        let server = SocketServer::new(&socket_path).await?;
        let config = Arc::clone(&self.config);
        let monitor = Arc::clone(&self.monitor);
        let path_security = Arc::clone(&self.path_security);
        let resource_limits = Arc::clone(&self.resource_limits);
        let _platform = self.platform.as_ref() as *const dyn Platform;

        let start_time = self.start_time;
        let server_handle = tokio::spawn(async move {
            server
                .run(move |request| {
                    let config = Arc::clone(&config);
                    let monitor = Arc::clone(&monitor);
                    let path_security = Arc::clone(&path_security);
                    let resource_limits = Arc::clone(&resource_limits);

                    async move {
                        handle_request(
                            request,
                            config,
                            monitor,
                            path_security,
                            resource_limits,
                            start_time,
                        )
                        .await
                    }
                })
                .await
        });

        // Start monitoring task
        let monitor_handle = {
            let config = Arc::clone(&self.config);
            let monitor = Arc::clone(&self.monitor);
            let path_security = Arc::clone(&self.path_security);
            let _platform = self.platform.as_ref() as *const dyn Platform;

            tokio::spawn(async move {
                if let Err(e) =
                    run_monitoring_loop(config, monitor, path_security, no_automount).await
                {
                    error!("Monitoring loop failed: {}", e);
                }
            })
        };

        // Start resource limits monitoring task
        let resource_limits_handle = {
            let resource_limits = Arc::clone(&self.resource_limits);
            tokio::spawn(async move {
                if let Err(e) = resource_limits.start_monitoring().await {
                    error!("Resource limits monitoring failed: {}", e);
                }
            })
        };

        // Wait for shutdown signal
        tokio::select! {
            _ = self.wait_for_shutdown() => {
                info!("Received shutdown signal");
            }
            result = server_handle => {
                match result {
                    Ok(_) => info!("Socket server task completed"),
                    Err(e) => error!("Socket server task error: {}", e),
                }
            }
            result = monitor_handle => {
                match result {
                    Ok(_) => info!("Monitor task completed"),
                    Err(e) => error!("Monitor task error: {}", e),
                }
            }
            result = resource_limits_handle => {
                match result {
                    Ok(_) => info!("Resource limits task completed"),
                    Err(e) => error!("Resource limits task error: {}", e),
                }
            }
        }

        // Cleanup
        self.cleanup(&socket_path, &pid_file).await?;

        info!("Fuji daemon stopped");
        Ok(())
    }

    /// Wait for shutdown signal
    async fn wait_for_shutdown(&mut self) -> Result<()> {
        if let Some(rx) = self.shutdown_rx.write().await.take() {
            rx.await.map_err(|_| anyhow!("Shutdown channel closed"))?;
        }
        Ok(())
    }

    /// Clean up resources
    async fn cleanup(&self, socket_path: &Path, pid_file: &Path) -> Result<()> {
        info!("Cleaning up daemon resources");

        // Unmount all active mounts
        let config = self.config.read().await;
        for mount in config.get_active_mounts() {
            info!("Unmounting {} during shutdown", mount.id);
            if let Ok(handler) = get_mount_handler(mount.url.split("://").next().unwrap_or("")) {
                if let Err(e) = handler.unmount(&mount.mount_point).await {
                    warn!("Failed to unmount {}: {}", mount.id, e);
                }
            }
        }

        // Remove socket and PID files
        if self.platform.path_exists(socket_path) {
            if let Err(e) = std::fs::remove_file(socket_path) {
                warn!("Failed to remove socket file: {}", e);
            }
        }

        self.platform.remove_pid_file(pid_file)?;

        Ok(())
    }

    /// Safely update mount status with error handling
    async fn update_mount_status(
        config: Arc<RwLock<Config>>,
        mount_id: &str,
        status: MountStatus,
    ) -> DaemonResult<()> {
        let mut cfg = config.write().await;
        match cfg.get_mount_mut(mount_id) {
            Some(mount) => {
                mount.update_status(status);
                Ok(())
            }
            None => {
                error!(
                    "Mount '{}' not found when updating status to {:?}",
                    mount_id, status
                );
                Err(DaemonError::mount_not_found(mount_id))
            }
        }
    }
}

/// Handle incoming requests
async fn handle_request(
    request: Request,
    config: Arc<RwLock<Config>>,
    monitor: Arc<MountMonitor>,
    path_security: Arc<PathSecurityValidator>,
    resource_limits: Arc<ResourceLimitsManager>,
    start_time: Instant,
) -> Response {
    match request {
        Request::Ping => Response::Pong,

        Request::Mount {
            url,
            mount_point,
            options,
            disable,
            dry_run,
            progress,
        } => {
            handle_mount_request(MountRequestParams {
                url,
                mount_point,
                options,
                disable,
                dry_run,
                progress,
                config,
                path_security,
                resource_limits,
            })
            .await
        }

        Request::Unmount { mount_id, force } => {
            handle_unmount_request(mount_id, force, config).await
        }

        Request::Status {
            verbose,
            watch,
            json,
            filter_url,
            filter_type,
            filter_point,
        } => {
            handle_status_request(StatusRequestParams {
                verbose,
                watch,
                json,
                filter_url,
                filter_type,
                filter_point,
                config,
                monitor,
                start_time,
            })
            .await
        }

        Request::List {
            enabled_only,
            disabled_only,
            json,
            filter_url,
            filter_type,
            filter_point,
        } => {
            handle_list_request(
                enabled_only,
                disabled_only,
                json,
                filter_url,
                filter_type,
                filter_point,
                config,
            )
            .await
        }

        Request::StopDaemon => Response::Success,

        Request::GetLogs { lines: _ } => {
            // TODO: Implement log retrieval
            Response::Logs { lines: vec![] }
        }

        Request::Discover { url } => handle_discover_request(url).await,

        Request::Enable { mount_id } => handle_enable_request(mount_id, config).await,

        Request::Disable { mount_id } => handle_disable_request(mount_id, config).await,

        Request::Remove { mount_id } => handle_remove_request(mount_id, config).await,

        Request::Remount { mount_id } => handle_remount_request(mount_id, config).await,

        Request::GetConfig => handle_get_config_request(config).await,

        Request::Doctor => handle_doctor_request().await,
    }
}

/// Parameters for mount requests
struct MountRequestParams {
    url: String,
    mount_point: Option<String>,
    options: Option<Vec<String>>, // TODO: Integrate options into MountType
    disable: bool,
    dry_run: bool,
    progress: bool, // TODO: Implement progress reporting
    config: Arc<RwLock<Config>>,
    path_security: Arc<PathSecurityValidator>,
    resource_limits: Arc<ResourceLimitsManager>,
}

/// Handle mount request
async fn handle_mount_request(params: MountRequestParams) -> Response {
    // Parse URL
    let protocol = params.url.split("://").next().unwrap_or("");
    let handler = match get_mount_handler(protocol) {
        Ok(h) => h,
        Err(e) => return Response::Error(e.to_string()),
    };

    // Parse mount type
    let mount_type = match handler.parse_url(&params.url) {
        Ok(mt) => mt,
        Err(e) => return Response::Error(e.to_string()),
    };

    // Generate mount ID
    let mount_id = match handler.generate_mount_id(&params.url) {
        Ok(id) => id,
        Err(e) => return Response::Error(e.to_string()),
    };

    // Check if mount already exists
    {
        let cfg = params.config.read().await;
        if cfg.get_mount(&mount_id).is_some() {
            return Response::Error(format!("Mount {} already exists", mount_id));
        }
    }

    // Use provided mount point or generate one
    let mount_point = if let Some(mp) = params.mount_point {
        std::path::PathBuf::from(mp)
    } else {
        match handler.generate_mount_point(&params.url) {
            Ok(path) => path,
            Err(e) => return Response::Error(e.to_string()),
        }
    };

    // Validate mount point path security using enhanced path security validator
    match params.path_security.validate_mount_point(&mount_point).await {
        Ok(validation_result) => {
            if !validation_result.is_safe {
                error!(
                    "Mount point path security validation failed for {}: {}",
                    mount_point.display(),
                    validation_result
                        .warning_message
                        .as_deref()
                        .unwrap_or("Security violation detected")
                );
                return Response::Error(format!(
                    "Mount point path security validation failed: {}",
                    validation_result
                        .warning_message
                        .as_deref()
                        .unwrap_or("Security violation detected")
                ));
            }

            // Log security events if any
            for event in validation_result.security_events {
                match event {
                    PathSecurityEvent::PathValidation {
                        path,
                        operation,
                        result: _,
                        timestamp,
                        context: _,
                    } => {
                        warn!(
                            "Path security event for {}: {} operation on {} at {}",
                            mount_point.display(),
                            operation,
                            path,
                            timestamp
                        );
                    }
                    PathSecurityEvent::MountIntegrityCheck {
                        mount_id,
                        mount_point: mp,
                        integrity_status,
                        timestamp: _timestamp,
                        violations,
                    } => {
                        warn!(
                            "Mount integrity event for {}: mount {} at {} - status: {:?}, violations: {:?}",
                            mount_point.display(),
                            mount_id,
                            mp,
                            integrity_status,
                            violations
                        );
                    }
                    PathSecurityEvent::SymlinkAttack {
                        mount_point: mp,
                        suspicious_path,
                        attack_type,
                        timestamp: _timestamp,
                        blocked,
                    } => {
                        warn!(
                            "Symlink attack detected for {}: {:?} attack on {} at {} - blocked: {}",
                            mount_point.display(),
                            attack_type,
                            suspicious_path,
                            mp,
                            blocked
                        );
                    }
                    PathSecurityEvent::RuntimeValidation {
                        original_path,
                        current_path,
                        validation_result: _,
                        timestamp,
                        mount_age_seconds: _,
                    } => {
                        warn!(
                            "Runtime validation event for {}: original {} != current {} at {}",
                            mount_point.display(),
                            original_path,
                            current_path,
                            timestamp
                        );
                    }
                }
            }
        }
        Err(e) => {
            error!(
                "Path security validation error for {}: {}",
                mount_point.display(),
                e
            );
            return Response::Error(format!("Path security validation failed: {}", e));
        }
    }

    // Create mount config
    let mut mount_config = MountConfig::new(params.url.clone(), mount_type, mount_point.clone());
    if params.disable {
        mount_config.disable();
    }

    // Register mount with path security validator for ongoing monitoring
    if let Err(e) = params.path_security
        .register_mount(
            mount_id.clone(),
            mount_point.clone(),
            mount_config.url.clone(),
            vec![mount_point.clone()], // allowed paths
        )
        .await
    {
        warn!(
            "Failed to register mount {} with path security validator: {}",
            mount_id, e
        );
        // Continue anyway - this is not a fatal error
    }

    // If dry run, just return what would happen
    if params.dry_run {
        return Response::MountSuccess {
            mount_id,
            mount_point: mount_config.mount_point,
        };
    }

    // Save to configuration
    params.config.write().await.add_mount(mount_config.clone());

    // If enabled, attempt to mount
    if !params.disable {
        // Check resource limits before attempting mount operation
        let mount_permit = match params.resource_limits.acquire_mount_permit().await {
            Ok(permit) => {
                info!("Acquired mount permit for {}", mount_id);
                Some(permit)
            }
            Err(e) => {
                warn!("Failed to acquire mount permit for {}: {}", mount_id, e);
                return Response::Error(format!("Resource limit exceeded: {}", e));
            }
        };

        // Perform the actual mount operation
        let mount_result = handler
            .mount(&mount_config, &mount_config.mount_point)
            .await;

        // Release the mount permit
        if let Some(_permit) = mount_permit {
            params.resource_limits.release_mount_permit();
        }

        // Handle mount result
        if let Err(e) = mount_result {
            error!("Failed to mount {}: {}", mount_id, e);
            if let Err(status_err) =
                Daemon::update_mount_status(params.config.clone(), &mount_id, MountStatus::Failed).await
            {
                error!("Failed to update mount status: {}", status_err);
            }
            return Response::Error(e.to_string());
        }

        // Update status
        if let Err(status_err) =
            Daemon::update_mount_status(params.config.clone(), &mount_id, MountStatus::Active).await
        {
            error!("Failed to update mount status: {}", status_err);
        }

        info!(
            "Successfully mounted {} to {}",
            mount_id,
            mount_config.mount_point.display()
        );
    }

    Response::MountSuccess {
        mount_id,
        mount_point: mount_config.mount_point,
    }
}

/// Handle unmount request
async fn handle_unmount_request(
    mount_id: String,
    _force: bool,
    config: Arc<RwLock<Config>>,
) -> Response {
    let mount = {
        let cfg = config.read().await;
        match cfg.get_mount(&mount_id) {
            Some(m) => m.clone(),
            None => return Response::Error(format!("Mount {} not found", mount_id)),
        }
    };

    if !mount.is_active() {
        return Response::Error(format!("Mount {} is not active", mount_id));
    }

    // Get handler and unmount
    let protocol = mount.url.split("://").next().unwrap_or("");
    if let Ok(handler) = get_mount_handler(protocol) {
        if let Err(e) = handler.unmount(&mount.mount_point).await {
            error!("Failed to unmount {}: {}", mount_id, e);
            return Response::Error(e.to_string());
        }
    }

    // Update configuration
    {
        let mut cfg = config.write().await;
        if let Some(m) = cfg.get_mount_mut(&mount_id) {
            m.disable();
        }
    }

    info!("Successfully unmounted {}", mount_id);
    Response::UnmountSuccess
}

/// Parameters for status requests
struct StatusRequestParams {
    verbose: bool,
    watch: bool,
    json: bool,
    filter_url: Option<String>,
    filter_type: Option<String>,
    filter_point: Option<String>,
    config: Arc<RwLock<Config>>,
    monitor: Arc<MountMonitor>,
    start_time: Instant,
}

/// Handle status request
async fn handle_status_request(params: StatusRequestParams) -> Response {
    let cfg = params.config.read().await;
    let mut mounts = Vec::new();

    for mount in cfg.get_all_mounts() {
        // Apply filters
        if let Some(ref filter_url) = params.filter_url {
            let regex = match regex::Regex::new(filter_url) {
                Ok(r) => r,
                Err(_) => {
                    warn!("Invalid URL filter regex: {}", filter_url);
                    EMPTY_REGEX.clone()
                }
            };
            if !regex.is_match(&mount.url) {
                continue;
            }
        }

        if let Some(ref filter_type) = params.filter_type {
            let mount_type_str = match &mount.mount_type {
                crate::mount::MountType::NFS { .. } => "nfs",
                crate::mount::MountType::SMB { .. } => "smb",
            };
            if !filter_type.eq_ignore_ascii_case(mount_type_str) {
                continue;
            }
        }

        if let Some(ref filter_point) = params.filter_point {
            let mount_point_str = mount.mount_point.to_string_lossy();
            let regex = match regex::Regex::new(filter_point) {
                Ok(r) => r,
                Err(_) => {
                    warn!("Invalid mount point filter regex: {}", filter_point);
                    EMPTY_REGEX.clone()
                }
            };
            if !regex.is_match(&mount_point_str) {
                continue;
            }
        }
        let health_score = if params.verbose {
            Some(params.monitor.get_health_score(&mount.id).await.unwrap_or(0))
        } else {
            None
        };

        mounts.push(MountStatusInfo {
            id: mount.id.clone(),
            url: mount.url.clone(),
            mount_point: mount.mount_point.clone(),
            status: mount.status.clone(),
            enabled: mount.enabled,
            created_at: mount.created_at,
            updated_at: mount.updated_at,
            last_connected: mount.last_connected,
            reconnect_attempts: mount.reconnect_attempts,
            health_score,
        });
    }

    // Create daemon health info
    let uptime = params.start_time.elapsed();
    let mut issues = Vec::new();

    // Check if we have any failed mounts
    let failed_count = mounts
        .iter()
        .filter(|m| matches!(m.status, MountStatus::Failed))
        .count();

    if failed_count > 0 {
        issues.push(format!("{} mounts are in failed state", failed_count));
    }

    let daemon_health = DaemonHealthInfo {
        healthy: failed_count == 0,
        uptime: Some(uptime),
        last_check: Some(Utc::now()),
        issues,
    };

    Response::Status {
        mounts,
        daemon_running: true,
        daemon_health: Some(daemon_health),
    }
}

/// Handle list request
async fn handle_list_request(
    enabled_only: bool,
    disabled_only: bool,
    _json: bool,
    filter_url: Option<String>,
    filter_type: Option<String>,
    filter_point: Option<String>,
    config: Arc<RwLock<Config>>,
) -> Response {
    let cfg = config.read().await;
    let mounts: Vec<MountConfig> = cfg
        .get_all_mounts()
        .filter(|m| {
            // Apply enabled/disabled filter
            if enabled_only {
                m.enabled
            } else if disabled_only {
                !m.enabled
            } else {
                true
            }
        })
        .filter(|m| {
            // Apply URL filter
            if let Some(ref filter_url) = filter_url {
                let regex = match regex::Regex::new(filter_url) {
                    Ok(r) => r,
                    Err(_) => {
                        warn!("Invalid URL filter regex: {}", filter_url);
                        EMPTY_REGEX.clone()
                    }
                };
                regex.is_match(&m.url)
            } else {
                true
            }
        })
        .filter(|m| {
            // Apply type filter
            if let Some(ref filter_type) = filter_type {
                let mount_type_str = match &m.mount_type {
                    crate::mount::MountType::NFS { .. } => "nfs",
                    crate::mount::MountType::SMB { .. } => "smb",
                };
                filter_type.eq_ignore_ascii_case(mount_type_str)
            } else {
                true
            }
        })
        .filter(|m| {
            // Apply mount point filter
            if let Some(ref filter_point) = filter_point {
                let mount_point_str = m.mount_point.to_string_lossy();
                let regex = match regex::Regex::new(filter_point) {
                    Ok(r) => r,
                    Err(_) => {
                        warn!("Invalid mount point filter regex: {}", filter_point);
                        EMPTY_REGEX.clone()
                    }
                };
                regex.is_match(&mount_point_str)
            } else {
                true
            }
        })
        .cloned()
        .collect();

    Response::MountList { mounts }
}

/// Handle discover request
async fn handle_discover_request(url: String) -> Response {
    let protocol = url.split("://").next().unwrap_or("");
    let handler = match get_mount_handler(protocol) {
        Ok(h) => h,
        Err(e) => return Response::Error(e.to_string()),
    };

    let parsed = match handler.parse_url(&url) {
        Ok(p) => p,
        Err(e) => return Response::Error(e.to_string()),
    };

    let host = match parsed {
        crate::mount::MountType::NFS { host, .. } => host,
        crate::mount::MountType::SMB { host, .. } => host,
    };

    match handler.discover_shares(&host).await {
        Ok(shares) => Response::DiscoveredShares { url, shares },
        Err(e) => Response::Error(e.to_string()),
    }
}

/// Handle enable request
async fn handle_enable_request(mount_id: String, config: Arc<RwLock<Config>>) -> Response {
    let mut cfg = config.write().await;
    match cfg.get_mount_mut(&mount_id) {
        Some(mount) => {
            mount.enable();
            Response::Success
        }
        None => Response::Error(format!("Mount {} not found", mount_id)),
    }
}

/// Handle disable request
async fn handle_disable_request(mount_id: String, config: Arc<RwLock<Config>>) -> Response {
    let mut cfg = config.write().await;
    match cfg.get_mount_mut(&mount_id) {
        Some(mount) => {
            mount.disable();
            Response::Success
        }
        None => Response::Error(format!("Mount {} not found", mount_id)),
    }
}

/// Handle remove request
async fn handle_remove_request(mount_id: String, config: Arc<RwLock<Config>>) -> Response {
    // Unmount if active
    {
        let cfg = config.read().await;
        if let Some(mount) = cfg.get_mount(&mount_id) {
            if mount.is_active() {
                drop(cfg);
                handle_unmount_request(mount_id.clone(), false, Arc::clone(&config)).await;
            }
        }
    }

    // Remove from configuration
    config.write().await.remove_mount(&mount_id);

    info!("Removed mount {}", mount_id);
    Response::Success
}

/// Handle remount request
async fn handle_remount_request(mount_id: String, config: Arc<RwLock<Config>>) -> Response {
    let mount = {
        let cfg = config.read().await;
        match cfg.get_mount(&mount_id) {
            Some(m) => m.clone(),
            None => return Response::Error(format!("Mount {} not found", mount_id)),
        }
    };

    let protocol = mount.url.split("://").next().unwrap_or("");
    let handler = match get_mount_handler(protocol) {
        Ok(h) => h,
        Err(e) => return Response::Error(e.to_string()),
    };

    // Force unmount first
    if mount.is_active() {
        if let Err(e) = handler.unmount(&mount.mount_point).await {
            warn!("Failed to unmount {} before remount: {}", mount_id, e);
        }
    }

    // Mount again
    if let Err(e) = handler.mount(&mount, &mount.mount_point).await {
        return Response::Error(e.to_string());
    }

    // Update status
    if let Err(status_err) =
        Daemon::update_mount_status(config, &mount_id, MountStatus::Active).await
    {
        error!(
            "Failed to update mount status after remount: {}",
            status_err
        );
    }

    info!("Successfully remounted {}", mount_id);
    Response::Success
}

/// Handle get config request
async fn handle_get_config_request(config: Arc<RwLock<Config>>) -> Response {
    let cfg = config.read().await;
    match toml::to_string_pretty(&*cfg) {
        Ok(s) => Response::Config { config: s },
        Err(e) => Response::Error(format!("Failed to serialize config: {}", e)),
    }
}

/// Handle doctor request
async fn handle_doctor_request() -> Response {
    // TODO: Implement comprehensive system checks
    Response::DoctorReport {
        issues: vec![],
        suggestions: vec![],
    }
}

/// Convert monitor health states to HealthStatus structs
#[allow(dead_code)]
async fn get_all_health_statuses_from_monitor(
    monitor: &MountMonitor,
) -> Option<Vec<crate::monitoring::HealthStatus>> {
    use crate::monitoring::{HealthState, HealthStatus};
    use chrono::Utc;

    let health_states = monitor.get_all_health().await;
    if health_states.is_empty() {
        return None;
    }

    let mut health_statuses = Vec::new();
    for (mount_id, state) in health_states {
        let health_state = if state.accessible && state.health_score > 80 {
            HealthState::Healthy
        } else if state.accessible && state.health_score > 40 {
            HealthState::Degraded
        } else {
            HealthState::Failed
        };

        health_statuses.push(HealthStatus {
            mount_id,
            status: health_state,
            last_check: Utc::now(),
            failure_count: 0,
            last_error: None,
            health_score: state.health_score,
        });
    }

    Some(health_statuses)
}

/// Run the monitoring loop
async fn run_monitoring_loop(
    config: Arc<RwLock<Config>>,
    monitor: Arc<MountMonitor>,
    path_security: Arc<PathSecurityValidator>,
    no_automount: bool,
) -> Result<()> {
    // Auto-mount enabled shares on startup if requested
    if !no_automount {
        auto_mount_enabled_shares(config.clone()).await?;
    }

    // Start health checking
    let mut interval = interval(Duration::from_secs(30));
    interval.tick().await; // Skip first immediate tick

    loop {
        interval.tick().await;

        // Check health of all active mounts
        if let Err(e) = check_mount_health(config.clone(), monitor.clone()).await {
            error!("Health check error: {}", e);
        }

        // Check mount integrity using path security validator
        if let Err(e) = check_mount_integrity(config.clone(), path_security.clone()).await {
            error!("Mount integrity check error: {}", e);
        }

        // Attempt reconnections for failed mounts
        if let Err(e) = attempt_reconnections(config.clone()).await {
            error!("Reconnection error: {}", e);
        }
    }
}

/// Auto-mount all enabled shares on startup
async fn auto_mount_enabled_shares(config: Arc<RwLock<Config>>) -> Result<()> {
    info!("Auto-mounting enabled shares");

    let mounts_to_mount: Vec<MountConfig> = {
        let cfg = config.read().await;
        cfg.get_enabled_mounts()
            .filter(|m| m.status == MountStatus::Disabled)
            .cloned()
            .collect()
    };

    for mount in mounts_to_mount {
        info!("Mounting {} on startup", mount.id);

        let protocol = mount.url.split("://").next().unwrap_or("");
        if let Ok(handler) = get_mount_handler(protocol) {
            match handler.mount(&mount, &mount.mount_point).await {
                Ok(_) => {
                    if let Err(status_err) =
                        Daemon::update_mount_status(config.clone(), &mount.id, MountStatus::Active)
                            .await
                    {
                        error!(
                            "Failed to update mount status after auto-mount: {}",
                            status_err
                        );
                    }
                    info!("Successfully auto-mounted {}", mount.id);

                    // Stagger mounts to avoid overwhelming network
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) => {
                    error!("Failed to auto-mount {}: {}", mount.id, e);
                    if let Err(status_err) =
                        Daemon::update_mount_status(config.clone(), &mount.id, MountStatus::Failed)
                            .await
                    {
                        error!(
                            "Failed to update mount status after failed auto-mount: {}",
                            status_err
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// Check health of all active mounts
async fn check_mount_health(config: Arc<RwLock<Config>>, monitor: Arc<MountMonitor>) -> Result<()> {
    let active_mounts: Vec<MountConfig> = {
        let cfg = config.read().await;
        cfg.get_active_mounts().cloned().collect()
    };

    for mount in active_mounts {
        let protocol = mount.url.split("://").next().unwrap_or("");
        if let Ok(handler) = get_mount_handler(protocol) {
            match handler.check_health(&mount.mount_point).await {
                Ok(state) => {
                    let accessible = state.accessible;
                    let last_error = state.last_error.clone();
                    monitor.update_health(&mount.id, state).await;

                    if !accessible {
                        let error_msg = last_error.unwrap_or_else(|| "Unknown".to_string());
                        warn!("Mount {} appears unhealthy: {}", mount.id, error_msg);

                        if let Err(status_err) = Daemon::update_mount_status(
                            config.clone(),
                            &mount.id,
                            MountStatus::Failed,
                        )
                        .await
                        {
                            error!(
                                "Failed to update mount status after health check: {}",
                                status_err
                            );
                        }
                    }
                }
                Err(e) => {
                    error!("Health check failed for {}: {}", mount.id, e);
                    if let Err(status_err) =
                        Daemon::update_mount_status(config.clone(), &mount.id, MountStatus::Failed)
                            .await
                    {
                        error!(
                            "Failed to update mount status after failed health check: {}",
                            status_err
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// Attempt reconnections for failed mounts
async fn attempt_reconnections(config: Arc<RwLock<Config>>) -> Result<()> {
    let mut mounts_to_reconnect: Vec<MountConfig> = {
        let cfg = config.read().await;
        cfg.get_failed_mounts()
            .filter(|m| {
                // Check if we should attempt reconnection based on backoff
                let delay = cfg.get_reconnection_delay(m.reconnect_attempts);
                let time_since_last_attempt = match m.updated_at {
                    updated => {
                        let now = Utc::now();
                        let duration = now.signed_duration_since(updated);
                        duration.num_milliseconds() as u64 >= delay.num_milliseconds() as u64
                    }
                };
                time_since_last_attempt
            })
            .cloned()
            .collect()
    };

    for mount in mounts_to_reconnect.drain(..) {
        info!(
            "Attempting to reconnect {} (attempt {})",
            mount.id,
            mount.reconnect_attempts + 1
        );

        // Increment attempt counter
        {
            let mut cfg = config.write().await;
            if let Some(m) = cfg.get_mount_mut(&mount.id) {
                m.increment_reconnect_attempts();
                m.update_status(MountStatus::Reconnecting);
            }
        }

        let protocol = mount.url.split("://").next().unwrap_or("");
        if let Ok(handler) = get_mount_handler(protocol) {
            // Unmount if still mounted
            if mount.mount_point.exists() {
                let _ = handler.unmount(&mount.mount_point).await;
            }

            // Attempt to mount
            match handler.mount(&mount, &mount.mount_point).await {
                Ok(_) => {
                    if let Err(status_err) =
                        Daemon::update_mount_status(config.clone(), &mount.id, MountStatus::Active)
                            .await
                    {
                        error!(
                            "Failed to update mount status after reconnection: {}",
                            status_err
                        );
                    }
                    info!("Successfully reconnected {}", mount.id);
                }
                Err(e) => {
                    warn!("Failed to reconnect {}: {}", mount.id, e);
                    if let Err(status_err) =
                        Daemon::update_mount_status(config.clone(), &mount.id, MountStatus::Failed)
                            .await
                    {
                        error!(
                            "Failed to update mount status after failed reconnection: {}",
                            status_err
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// Check integrity of all mount points using path security validator
async fn check_mount_integrity(
    config: Arc<RwLock<Config>>,
    path_security: Arc<PathSecurityValidator>,
) -> Result<()> {
    let active_mounts: Vec<MountConfig> = {
        let cfg = config.read().await;
        cfg.get_active_mounts().cloned().collect()
    };

    for mount in active_mounts {
        // Perform periodic path integrity check
        match path_security
            .check_mount_integrity(&mount.id, &mount.mount_point)
            .await
        {
            Ok(integrity_result) => {
                match integrity_result {
                    IntegrityStatus::Intact => {
                        // Mount is intact, no action needed
                    }
                    status => {
                        warn!(
                            "Mount integrity check failed for {}: {:?}",
                            mount.id, status
                        );
                    }
                }
            }
            Err(e) => {
                error!("Mount integrity check error for {}: {}", mount.id, e);
            }
        }
    }

    Ok(())
}
