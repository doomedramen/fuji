//! Fuji daemon implementation
//!
//! The daemon handles all mount operations, monitoring, and reconnection logic.

use crate::config::Config;
use crate::mount::{get_mount_handler, MountConfig, MountStatus, MountState};
use crate::platform::Platform;
use crate::socket::{SocketServer, Request, Response, MountStatusInfo};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{RwLock, oneshot};
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

pub mod monitor;

use monitor::MountMonitor;

/// Main daemon structure
pub struct Daemon {
    /// Platform-specific operations
    platform: Box<dyn Platform>,
    /// Configuration
    config: Arc<RwLock<Config>>,
    /// Mount monitor
    monitor: Arc<MountMonitor>,
    /// Shutdown channel receiver
    shutdown_rx: Arc<RwLock<Option<oneshot::Receiver<()>>>>,
}

/// Internal mount state tracking
#[derive(Debug, Clone)]
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

        Ok(Self {
            platform,
            config,
            monitor,
            shutdown_rx: Arc::new(RwLock::new(None)),
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
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        *self.shutdown_rx.write().await = Some(shutdown_rx);

        // Start socket server
        let server = SocketServer::new(&socket_path).await?;
        let config = Arc::clone(&self.config);
        let monitor = Arc::clone(&self.monitor);
        let platform = self.platform.as_ref() as *const dyn Platform;

        let server_handle = tokio::spawn(async move {
            server.run(move |request| {
                let config = Arc::clone(&config);
                let monitor = Arc::clone(&monitor);

                async move {
                    handle_request(request, config, monitor).await
                }
            }).await
        });

        // Start monitoring task
        let monitor_handle = {
            let config = Arc::clone(&self.config);
            let monitor = Arc::clone(&self.monitor);
            let platform = self.platform.as_ref() as *const dyn Platform;

            tokio::spawn(async move {
                if let Err(e) = run_monitoring_loop(config, monitor, no_automount).await {
                    error!("Monitoring loop failed: {}", e);
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
    async fn cleanup(&self, socket_path: &PathBuf, pid_file: &PathBuf) -> Result<()> {
        info!("Cleaning up daemon resources");

        // Unmount all active mounts
        let config = self.config.read().await;
        for mount in config.get_active_mounts() {
            info!("Unmounting {} during shutdown", mount.id);
            if let Ok(handler) = get_mount_handler(&mount.url.split("://").next().unwrap_or("")) {
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
}

/// Handle incoming requests
async fn handle_request(
    request: Request,
    config: Arc<RwLock<Config>>,
    monitor: Arc<MountMonitor>,
) -> Response {
    match request {
        Request::Ping => Response::Pong,

        Request::Mount { url, disable, dry_run } => {
            handle_mount_request(url, disable, dry_run, config).await
        }

        Request::Unmount { mount_id, force } => {
            handle_unmount_request(mount_id, force, config).await
        }

        Request::Status { verbose, watch, json } => {
            handle_status_request(verbose, watch, json, config, monitor).await
        }

        Request::List { enabled_only, disabled_only, json } => {
            handle_list_request(enabled_only, disabled_only, json, config).await
        }

        Request::StopDaemon => {
            Response::Success
        }

        Request::GetLogs { lines } => {
            // TODO: Implement log retrieval
            Response::Logs { lines: vec![] }
        }

        Request::Discover { url } => {
            handle_discover_request(url).await
        }

        Request::Enable { mount_id } => {
            handle_enable_request(mount_id, config).await
        }

        Request::Disable { mount_id } => {
            handle_disable_request(mount_id, config).await
        }

        Request::Remove { mount_id } => {
            handle_remove_request(mount_id, config).await
        }

        Request::Remount { mount_id } => {
            handle_remount_request(mount_id, config).await
        }

        Request::GetConfig => {
            handle_get_config_request(config).await
        }

        Request::Doctor => {
            handle_doctor_request().await
        }
    }
}

/// Handle mount request
async fn handle_mount_request(
    url: String,
    disable: bool,
    dry_run: bool,
    config: Arc<RwLock<Config>>,
) -> Response {
    // Parse URL
    let protocol = url.split("://").next().unwrap_or("");
    let handler = match get_mount_handler(protocol) {
        Ok(h) => h,
        Err(e) => return Response::Error(e.to_string()),
    };

    // Parse mount type
    let mount_type = match handler.parse_url(&url) {
        Ok(mt) => mt,
        Err(e) => return Response::Error(e.to_string()),
    };

    // Generate mount ID
    let mount_id = match handler.generate_mount_id(&url) {
        Ok(id) => id,
        Err(e) => return Response::Error(e.to_string()),
    };

    // Check if mount already exists
    {
        let cfg = config.read().await;
        if cfg.get_mount(&mount_id).is_some() {
            return Response::Error(format!("Mount {} already exists", mount_id));
        }
    }

    // Generate mount point (preserving directory structure from URL)
    let mount_point = match handler.generate_mount_point(&url) {
        Ok(path) => path,
        Err(e) => return Response::Error(e.to_string()),
    };

    // Create mount config
    let mut mount_config = MountConfig::new(url.clone(), mount_type, mount_point);
    if disable {
        mount_config.disable();
    }

    // If dry run, just return what would happen
    if dry_run {
        return Response::MountSuccess {
            mount_id,
            mount_point: mount_config.mount_point,
        };
    }

    // Save to configuration
    config.write().await.add_mount(mount_config.clone());

    // If enabled, attempt to mount
    if !disable {
        if let Err(e) = handler.mount(&mount_config, &mount_config.mount_point).await {
            error!("Failed to mount {}: {}", mount_id, e);
            config.write().await
                .get_mount_mut(&mount_id)
                .unwrap()
                .update_status(MountStatus::Failed);
            return Response::Error(e.to_string());
        }

        // Update status
        config.write().await
            .get_mount_mut(&mount_id)
            .unwrap()
            .update_status(MountStatus::Active);

        info!("Successfully mounted {} to {}", mount_id, mount_config.mount_point.display());
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

/// Handle status request
async fn handle_status_request(
    verbose: bool,
    _watch: bool,
    _json: bool,
    config: Arc<RwLock<Config>>,
    monitor: Arc<MountMonitor>,
) -> Response {
    let cfg = config.read().await;
    let mut mounts = Vec::new();

    for mount in cfg.get_all_mounts() {
        let health_score = if verbose {
            Some(monitor.get_health_score(&mount.id).await.unwrap_or(0))
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

    Response::Status {
        mounts,
        daemon_running: true,
    }
}

/// Handle list request
async fn handle_list_request(
    enabled_only: bool,
    disabled_only: bool,
    _json: bool,
    config: Arc<RwLock<Config>>,
) -> Response {
    let cfg = config.read().await;
    let mounts: Vec<MountConfig> = cfg.get_all_mounts()
        .filter(|m| {
            if enabled_only { m.enabled }
            else if disabled_only { !m.enabled }
            else { true }
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
async fn handle_enable_request(
    mount_id: String,
    config: Arc<RwLock<Config>>,
) -> Response {
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
async fn handle_disable_request(
    mount_id: String,
    config: Arc<RwLock<Config>>,
) -> Response {
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
async fn handle_remove_request(
    mount_id: String,
    config: Arc<RwLock<Config>>,
) -> Response {
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
async fn handle_remount_request(
    mount_id: String,
    config: Arc<RwLock<Config>>,
) -> Response {
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
    config.write().await
        .get_mount_mut(&mount_id)
        .unwrap()
        .update_status(MountStatus::Active);

    info!("Successfully remounted {}", mount_id);
    Response::Success
}

/// Handle get config request
async fn handle_get_config_request(
    config: Arc<RwLock<Config>>,
) -> Response {
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

/// Run the monitoring loop
async fn run_monitoring_loop(
    config: Arc<RwLock<Config>>,
    monitor: Arc<MountMonitor>,
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
                    config.write().await
                        .get_mount_mut(&mount.id)
                        .unwrap()
                        .update_status(MountStatus::Active);
                    info!("Successfully auto-mounted {}", mount.id);

                    // Stagger mounts to avoid overwhelming network
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) => {
                    error!("Failed to auto-mount {}: {}", mount.id, e);
                    config.write().await
                        .get_mount_mut(&mount.id)
                        .unwrap()
                        .update_status(MountStatus::Failed);
                }
            }
        }
    }

    Ok(())
}

/// Check health of all active mounts
async fn check_mount_health(
    config: Arc<RwLock<Config>>,
    monitor: Arc<MountMonitor>,
) -> Result<()> {
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
                        warn!("Mount {} appears unhealthy: {}", mount.id,
                              last_error.unwrap_or_else(|| "Unknown".to_string()));

                        config.write().await
                            .get_mount_mut(&mount.id)
                            .unwrap()
                            .update_status(MountStatus::Failed);
                    }
                }
                Err(e) => {
                    error!("Health check failed for {}: {}", mount.id, e);
                    config.write().await
                        .get_mount_mut(&mount.id)
                        .unwrap()
                        .update_status(MountStatus::Failed);
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
        info!("Attempting to reconnect {} (attempt {})",
              mount.id, mount.reconnect_attempts + 1);

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
                    config.write().await
                        .get_mount_mut(&mount.id)
                        .unwrap()
                        .update_status(MountStatus::Active);
                    info!("Successfully reconnected {}", mount.id);
                }
                Err(e) => {
                    warn!("Failed to reconnect {}: {}", mount.id, e);
                    config.write().await
                        .get_mount_mut(&mount.id)
                        .unwrap()
                        .update_status(MountStatus::Failed);
                }
            }
        }
    }

    Ok(())
}