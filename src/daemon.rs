use crate::config::Config;
use crate::error::{FujiError, Result};
use crate::platform::{get_platform, MountInfo};
use chrono;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

#[derive(Debug, Serialize, Deserialize)]
pub enum Command {
    Ping,
    Status,
    Mount { url: String },
    Unmount { mount_id: String },
    Stop,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub success: bool,
    pub message: Option<String>,
    pub error: Option<String>,
    pub data: Option<ResponseData>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ResponseData {
    Pong {
        timestamp: u64,
    },
    Status {
        pid: u32,
        uptime_seconds: u64,
        mounts: Vec<MountInfo>,
        socket_path: String,
    },
    Mount {
        mount_id: String,
        mount_point: String,
    },
    Unmount {
        mount_id: String,
    },
}

pub struct Daemon {
    config: Arc<Mutex<Config>>,
    platform: Box<dyn crate::platform::Platform + Send + Sync>,
    mounts: Arc<Mutex<HashMap<String, MountInfo>>>,
    start_time: std::time::Instant,
    no_automount: bool,
}

impl Daemon {
    pub fn new(config: Config, no_automount: bool) -> Result<Self> {
        let platform = get_platform()?;

        Ok(Self {
            config: Arc::new(Mutex::new(config)),
            platform: platform, // Just assign the boxed platform directly
            mounts: Arc::new(Mutex::new(HashMap::new())),
            start_time: std::time::Instant::now(),
            no_automount,
        })
    }

    pub async fn run(self) -> Result<()> {
        let daemon = Arc::new(self);

        // Set up signal handlers for graceful shutdown
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            use std::sync::{Arc as StdArc, Mutex as StdMutex};

            let shutdown_tx = StdArc::new(StdMutex::new(Some(shutdown_tx)));

            let tx_sigterm = StdArc::clone(&shutdown_tx);
            let tx_sigint = StdArc::clone(&shutdown_tx);

            tokio::spawn(async move {
                let mut sigterm = signal(SignalKind::terminate()).expect("Failed to setup SIGTERM handler");
                let mut sigint = signal(SignalKind::interrupt()).expect("Failed to setup SIGINT handler");

                tokio::select! {
                    _ = sigterm.recv() => {
                        error!("🚨 Received SIGTERM signal");
                        if let Some(tx) = tx_sigterm.lock().unwrap().take() {
                            let _ = tx.send(());
                        }
                    }
                    _ = sigint.recv() => {
                        error!("🚨 Received SIGINT signal");
                        if let Some(tx) = tx_sigint.lock().unwrap().take() {
                            let _ = tx.send(());
                        }
                    }
                }
            });
        }

        let socket_path = {
            let config_guard = daemon.config.lock().await;
            config_guard.socket_path().to_path_buf()
        };

        // Remove existing socket if it exists
        if socket_path.exists() {
            info!("🧹 Removing existing socket file: {:?}", socket_path);
            std::fs::remove_file(&socket_path).map_err(|e| {
                FujiError::Socket(format!("Failed to remove existing socket: {}", e))
            })?;
        }

        info!("🔌 Attempting to bind to socket: {}", socket_path.display());
        let listener = UnixListener::bind(&socket_path)
            .map_err(|e| {
                error!("❌ Failed to bind to socket {}: {}", socket_path.display(), e);
                FujiError::Socket(format!("Failed to bind to socket {}: {}", socket_path.display(), e))
            })?;

        info!("✅ Daemon successfully bound and listening on: {:?}", socket_path);

        // Verify the socket file exists
        if !socket_path.exists() {
            error!("❌ Socket file does not exist after binding: {:?}", socket_path);
            return Err(FujiError::Socket("Socket file not found after binding".to_string()));
        }
        info!("✅ Verified socket file exists: {:?}", socket_path);

        // Auto-mount enabled shares on startup (unless disabled)
        if !daemon.no_automount {
            daemon.auto_mount_enabled_shares().await?;
        } else {
            info!("⏭️ Skipping auto-mount due to --no-automount flag");
        }

        // Spawn the connection handler with shared state
        let daemon_handler = Arc::clone(&daemon);
        let server_task = tokio::spawn(async move {
            info!("🚀 Starting server loop to accept connections");
            loop {
                match listener.accept().await {
                    Ok((mut stream, addr)) => {
                        info!("👤 Client connected from {:?}", addr);
                        let daemon = Arc::clone(&daemon_handler);
                        // Spawn a separate task to handle this client, making sure errors don't affect main loop
                        tokio::spawn(async move {
                            info!("🧵 Handling client connection in spawned task");
                            // Capture all possible errors to ensure the task doesn't panic
                            let result = daemon.handle_client(&mut stream).await;
                            match result {
                                Ok(()) => info!("✅ Client connection handled successfully"),
                                Err(e) => error!("❌ Failed to handle client connection: {}", e),
                            }
                            info!("✅ Client connection task completed");
                        });
                    }
                    Err(e) => {
                        error!("❌ Failed to accept connection: {}", e);
                        // Continue the loop instead of exiting on error
                        // Add a small delay to prevent busy-looping if accept keeps failing
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });

        // Spawn the monitoring task for reconnection
        let daemon_monitor = Arc::clone(&daemon);
        let monitoring_task = tokio::spawn(async move {
            info!("🔄 Starting monitoring loop");
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                match daemon_monitor.monitor_connections().await {
                    Ok(()) => info!("🔍 Connection monitoring completed"),
                    Err(e) => error!("❌ Error in connection monitoring: {}", e),
                }
            }
        });

        // Wait for shutdown signal
        info!("🚀 Daemon running, waiting for shutdown signal...");
        let _ = shutdown_rx.await;

        info!("🛑 Shutdown signal received, stopping daemon...");

        // Cancel the tasks
        server_task.abort();
        monitoring_task.abort();

        // Clean up socket file
        if socket_path.exists() {
            if let Err(e) = std::fs::remove_file(&socket_path) {
                warn!("⚠️ Failed to remove socket file during shutdown: {}", e);
            } else {
                info!("🧹 Socket file removed successfully");
            }
        }

        info!("🏁 Daemon stopped successfully");
        Ok(())
    }

    async fn handle_client(&self, stream: &mut tokio::net::UnixStream) -> Result<()> {
        info!("👤 Client connected, processing request");

        let mut buffer = vec![0u8; 1024];
        let n = stream
            .read(&mut buffer)
            .await
            .map_err(|e| {
                error!("❌ Failed to read from socket: {}", e);
                FujiError::Socket(format!("Failed to read from socket: {}", e))
            })?;

        if n == 0 {
            info!("👤 Client disconnected with no data");
            return Ok(());
        }

        let command_json = String::from_utf8_lossy(&buffer[..n]);
        info!("📧 Received command JSON: {}", &command_json[..std::cmp::min(200, command_json.len())]); // Limit log size

        let command: Command = serde_json::from_str(&command_json)
            .map_err(|e| {
                error!("❌ Failed to parse command JSON: {}", e);
                error!("JSON content: {}", &command_json[..std::cmp::min(500, command_json.len())]);
                FujiError::InvalidCommand(format!("Failed to parse command: {}", e))
            })?;

        info!("🔄 Processing command: {:?}", command);

        let response = self.process_command(command).await;
        let response_json = serde_json::to_string(&response)
            .map_err(|e| {
                error!("❌ Failed to serialize response: {}", e);
                FujiError::Socket(format!("Failed to serialize response: {}", e))
            })?;

        info!("📤 Sending response: success={}, error={:?}", response.success, response.error);

        stream
            .write_all(response_json.as_bytes())
            .await
            .map_err(|e| {
                error!("❌ Failed to write to socket: {}", e);
                FujiError::Socket(format!("Failed to write to socket: {}", e))
            })?;
        stream
            .flush()
            .await
            .map_err(|e| {
                error!("❌ Failed to flush socket: {}", e);
                FujiError::Socket(format!("Failed to flush socket: {}", e))
            })?;

        info!("✅ Response sent to client successfully");
        Ok(())
    }

    async fn process_command(&self, command: Command) -> Response {
        match command {
            Command::Ping => {
                info!("🏓 Processing Ping command");
                Response {
                    success: true,
                    message: Some("Pong".to_string()),
                    error: None,
                    data: Some(ResponseData::Pong {
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    }),
                }
            },
            Command::Status => {
                info!("📊 Processing Status command");
                let mounts = match self.platform.list_mounts() {
                    Ok(mounts) => mounts,
                    Err(e) => {
                        error!("❌ Failed to list mounts for status: {}", e);
                        vec![] // Return empty list if platform call fails
                    }
                };

                let config_guard = self.config.lock().await;
                Response {
                    success: true,
                    message: Some("Status retrieved".to_string()),
                    error: None,
                    data: Some(ResponseData::Status {
                        pid: std::process::id(),
                        uptime_seconds: self.start_time.elapsed().as_secs(),
                        mounts,
                        socket_path: config_guard.socket_path().display().to_string(),
                    }),
                }
            },
            Command::Mount { url } => {
                info!("📁 Processing Mount command for URL: {}", url);

                // Validate URL format
                if !url.starts_with("nfs://") && !url.starts_with("smb://") && !url.starts_with("cifs://") {
                    return Response {
                        success: false,
                        message: None,
                        error: Some(format!(
                            "Invalid mount URL: {}. URL must start with 'nfs://', 'smb://', or 'cifs://'",
                            url
                        )),
                        data: None,
                    };
                }

                match self.platform.mount(&url, "") {
                    Ok(mount_info) => {
                        info!("✅ Mount successful: {} -> {}", url, mount_info.mount_point);

                        // Save to configuration
                        let now = chrono::Utc::now().to_rfc3339();
                        let mount_config = crate::config::MountConfig {
                            id: mount_info.id.clone(),
                            url: url.clone(),
                            mount_point: mount_info.mount_point.clone(),
                            enabled: true,
                            created_at: now.clone(),
                            updated_at: now,
                            alias: None,
                        };

                        // Update internal tracking
                        {
                            let mut mounts_guard = self.mounts.lock().await;
                            mounts_guard.insert(mount_info.id.clone(), mount_info.clone());
                        }

                        // Update config
                        {
                            let mut config_guard = self.config.lock().await;
                            config_guard
                                .app_config_mut()
                                .mounts
                                .insert(mount_info.id.clone(), mount_config);
                            if let Err(e) = config_guard.save() {
                                warn!("⚠️ Failed to save config file: {}", e);
                            }
                        }

                        Response {
                            success: true,
                            message: Some(format!("Successfully mounted {} at {}", url, mount_info.mount_point)),
                            error: None,
                            data: Some(ResponseData::Mount {
                                mount_id: mount_info.id,
                                mount_point: mount_info.mount_point,
                            }),
                        }
                    }
                    Err(e) => {
                        error!("❌ Mount failed: {}", e);
                        Response {
                            success: false,
                            message: None,
                            error: Some(format!("Mount failed: {}", e)),
                            data: None,
                        }
                    },
                }
            },
            Command::Unmount { mount_id } => {
                info!("📂 Processing Unmount command for: {}", mount_id);

                // Check if mount exists in our tracking
                {
                    let mounts = self.mounts.lock().await;
                    if !mounts.contains_key(&mount_id) {
                        return Response {
                            success: false,
                            message: None,
                            error: Some(format!(
                                "Mount not found: {}. Check mount ID with 'fuji status'",
                                mount_id
                            )),
                            data: None,
                        };
                    }
                }

                match self.platform.unmount(&mount_id) {
                    Ok(_) => {
                        info!("✅ Unmount successful: {}", mount_id);

                        // Update mount config to mark as disabled
                        {
                            let mut config_guard = self.config.lock().await;
                            if let Some(mount_config) =
                                config_guard.app_config_mut().mounts.get_mut(&mount_id)
                            {
                                mount_config.enabled = false;
                                mount_config.updated_at = chrono::Utc::now().to_rfc3339();

                                // Save config to file
                                if let Err(e) = config_guard.save() {
                                    warn!("⚠️ Failed to save config file: {}", e);
                                }
                            }
                        }

                        // Remove from internal tracking
                        {
                            let mut mounts_guard = self.mounts.lock().await;
                            mounts_guard.remove(&mount_id);
                        }

                        Response {
                            success: true,
                            message: Some(format!("Successfully unmounted {}", mount_id)),
                            error: None,
                            data: Some(ResponseData::Unmount { mount_id }),
                        }
                    },
                    Err(e) => {
                        error!("❌ Unmount failed: {}", e);
                        Response {
                            success: false,
                            message: None,
                            error: Some(format!("Unmount failed: {}", e)),
                            data: None,
                        }
                    },
                }
            },
            Command::Stop => {
                error!("🛑 Received stop command, shutting down daemon NOW!");
                std::process::exit(0);
            }
        }
    }

    async fn auto_mount_enabled_shares(&self) -> Result<()> {
        info!("🔄 Auto-mounting enabled shares on startup");

        let enabled_mounts = {
            let config_guard = self.config.lock().await;
            config_guard.get_enabled_mounts().into_iter().cloned().collect::<Vec<_>>()
        };
        let mount_count = enabled_mounts.len();

        if mount_count == 0 {
            info!("⏭️ No enabled mounts found, skipping auto-mount");
            return Ok(());
        }

        info!("🔍 Found {} enabled mount(s) to auto-mount", mount_count);

        for (i, mount_config) in enabled_mounts.into_iter().enumerate() {
            info!(
                "📁 Mounting {}/{}: {}",
                i + 1,
                mount_count,
                mount_config.id
            );

            match self.platform.mount(&mount_config.url, &mount_config.mount_point) {
                Ok(mount_info) => {
                    {
                        let mut mounts_guard = self.mounts.lock().await;
                        mounts_guard.insert(mount_config.id.clone(), mount_info);
                    }
                    info!("✅ Successfully mounted {}", mount_config.id);
                }
                Err(e) => {
                    warn!("⚠️ Failed to auto-mount {}: {}", mount_config.id, e);
                }
            }

            // Stagger mounts to avoid overwhelming the network
            if i < mount_count - 1 {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }

        info!("🎉 Auto-mount process completed");
        Ok(())
    }

    async fn monitor_connections(&self) -> Result<()> {
        info!("🔍 Checking connection status of all mounts");

        // Get current list of active mounts from system
        let current_mounts = match self.platform.list_mounts() {
            Ok(mounts) => mounts,
            Err(e) => {
                warn!("⚠️ Failed to list mounts: {}", e);
                return Ok(());
            }
        };

        // Get internally tracked mounts
        let tracked_mounts = {
            let mounts_guard = self.mounts.lock().await;
            mounts_guard.clone()
        };

        // Check which tracked mounts are not in system mounts (disconnected)
        let mut missing_mounts = Vec::new();
        for (mount_id, _mount_info) in &tracked_mounts {
            if !current_mounts.iter().any(|m| m.id == *mount_id) {
                missing_mounts.push(mount_id.clone());
            }
        }

        // Attempt to reconnect missing mounts
        if !missing_mounts.is_empty() {
            info!(
                "⚠️ Found {} missing mount(s), attempting to reconnect",
                missing_mounts.len()
            );

            for mount_id in &missing_mounts {
                let mount_config = {
                    let config_guard = self.config.lock().await;
                    config_guard.get_mount(mount_id).cloned()  // cloned() ensures we get an owned value
                };

                if let Some(mount_config) = mount_config {
                    if !mount_config.enabled {
                        continue; // Skip disabled mounts
                    }

                    match self.platform.mount(&mount_config.url, &mount_config.mount_point) {
                        Ok(mount_info) => {
                            {
                                let mut mounts_guard = self.mounts.lock().await;
                                mounts_guard.insert(mount_id.clone(), mount_info);
                            }
                            info!("✅ Successfully reconnected mount: {}", mount_id);
                        }
                        Err(e) => {
                            warn!("⚠️ Failed to reconnect {}: {}", mount_id, e);
                        }
                    }
                }
            }
        }

        if missing_mounts.is_empty() {
            info!("✅ All tracked mounts are active");
        } else {
            info!("📊 Reconnection attempts completed");
        }

        Ok(())
    }
}

pub struct DaemonClient {
    socket_path: PathBuf,
}

impl DaemonClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    pub async fn send_command(&self, command: Command) -> Result<()> {
        tracing::debug!("Attempting to connect to daemon at: {:?}", self.socket_path);
        tracing::trace!("Command to send: {:?}", command);

        let mut stream = tokio::net::UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| {
                tracing::error!("Failed to connect to daemon at {:?}: {}", self.socket_path, e);
                tracing::debug!("Socket file exists: {}", self.socket_path.exists());
                tracing::debug!("Socket file metadata: {:?}", std::fs::metadata(&self.socket_path));
                FujiError::DaemonNotRunning
            })?;

        tracing::debug!("Successfully connected to daemon");

        let command_json = serde_json::to_string(&command)
            .map_err(|e| FujiError::Socket(format!("Failed to serialize command: {}", e)))?;

        tracing::trace!("Sending command JSON: {}", command_json);

        stream
            .write_all(command_json.as_bytes())
            .await
            .map_err(|e| {
                tracing::error!("Failed to write to socket: {}", e);
                FujiError::Socket(format!("Failed to write to socket: {}", e))
            })?;
        stream
            .flush()
            .await
            .map_err(|e| {
                tracing::error!("Failed to flush socket: {}", e);
                FujiError::Socket(format!("Failed to flush socket: {}", e))
            })?;

        tracing::debug!("Command sent successfully, waiting for response...");
        let mut buffer = vec![0u8; 4096];
        let n = stream
            .read(&mut buffer)
            .await
            .map_err(|e| FujiError::Socket(format!("Failed to read from socket: {}", e)))?;

        let response_json = String::from_utf8_lossy(&buffer[..n]);
        let response: Response = serde_json::from_str(&response_json)
            .map_err(|e| FujiError::Socket(format!("Failed to parse response: {}", e)))?;

        self.handle_response(response)?;
        Ok(())
    }

    fn handle_response(&self, response: Response) -> Result<()> {
        if response.success {
            if let Some(message) = response.message {
                println!("{}", message);
            }

            if let Some(data) = response.data {
                match data {
                    ResponseData::Pong { timestamp } => {
                        println!("Daemon is running (timestamp: {})", timestamp);
                    }
                    ResponseData::Status {
                        pid,
                        uptime_seconds,
                        mounts,
                        socket_path,
                    } => {
                        println!("Daemon Status:");
                        println!("  PID: {}", pid);
                        println!("  Uptime: {}s", uptime_seconds);
                        println!("  Socket: {}", socket_path);
                        if mounts.is_empty() {
                            println!("  Active Mounts: None");
                        } else {
                            println!("  Active Mounts:");
                            for mount in mounts {
                                println!(
                                    "    - {}: {} -> {}",
                                    mount.id, mount.url, mount.mount_point
                                );
                            }
                        }
                    }
                    ResponseData::Mount {
                        mount_id,
                        mount_point,
                    } => {
                        println!("Mount successful:");
                        println!("  Mount ID: {}", mount_id);
                        println!("  Mount Point: {}", mount_point);
                    }
                    ResponseData::Unmount { mount_id } => {
                        println!("Unmount successful:");
                        println!("  Mount ID: {}", mount_id);
                    }
                }
            }
        } else {
            if let Some(error) = response.error {
                eprintln!("Error: {}", error);
            }
        }

        Ok(())
    }
}

pub async fn start_daemon(config: Config, detach: bool, no_automount: bool) -> Result<()> {
    // Get the current executable path
    let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/local/bin/fuji"));

    let mut command = std::process::Command::new(exe_path);
    command
        .arg("--daemon-mode")
        .arg("--config")
        .arg(config.config_path().display().to_string());

    // Add no-automount flag if specified
    if no_automount {
        command.arg("--no-automount");
    }

    // If in detach mode, redirect stdout/stderr to /dev/null
    if detach {
        command
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
    }

    match command.spawn() {
        Ok(child) => {
            if detach {
                println!("Daemon process started with PID: {}", child.id());
                // Don't wait for daemon to start in detach mode
                Ok(())
            } else {
                info!("Daemon process started with PID: {}", child.id());

                // Give the daemon a moment to start
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

                // Check if daemon is responsive
                let client = DaemonClient::new(config.socket_path().clone());
                if let Err(e) = client.send_command(Command::Ping).await {
                    warn!("Daemon ping failed: {}", e);
                    return Err(FujiError::DaemonNotRunning);
                }

                println!("Daemon started successfully");
                Ok(())
            }
        }
        Err(e) => Err(FujiError::CommandFailed(format!(
            "Failed to start daemon: {}",
            e
        ))),
    }
}