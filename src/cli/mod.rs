//! CLI implementation for Fuji

use crate::platform::Platform;
use crate::socket::{SocketClient, Request, Response};
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use tracing::{error, warn};

#[derive(Debug, Parser)]
#[command(name = "fuji")]
#[command(about = "A network file system mount manager", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Mount a network share
    Mount {
        /// URL of the share to mount (e.g., nfs://192.168.1.1/data)
        url: String,

        /// Add mount but don't activate it
        #[arg(short, long)]
        disable: bool,

        /// Preview what would happen without mounting
        #[arg(long)]
        dry_run: bool,
    },

    /// Unmount a share
    Unmount {
        /// Mount ID to unmount
        mount_id: String,

        /// Force unmount even if in use
        #[arg(short, long)]
        force: bool,
    },

    /// Show current status
    Status {
        /// Show detailed information
        #[arg(short, long)]
        verbose: bool,

        /// Continuously monitor status
        #[arg(short, long)]
        watch: bool,

        /// Output in JSON format
        #[arg(short, long)]
        json: bool,
    },

    /// List configured mounts
    List {
        /// Show only enabled mounts
        #[arg(long)]
        enabled: bool,

        /// Show only disabled mounts
        #[arg(long)]
        disabled: bool,

        /// Output in JSON format
        #[arg(short, long)]
        json: bool,
    },

    /// Daemon management
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },

    /// Discover available shares on a server
    Discover {
        /// Server URL (e.g., nfs://192.168.1.1/)
        url: String,
    },

    /// Enable a disabled mount
    Enable {
        /// Mount ID to enable
        mount_id: String,
    },

    /// Disable a mount (but keep it configured)
    Disable {
        /// Mount ID to disable
        mount_id: String,
    },

    /// Remove a mount completely
    Remove {
        /// Mount ID to remove
        mount_id: String,
    },

    /// Force reconnection of a mount
    Remount {
        /// Mount ID to remount
        mount_id: String,
    },

    /// Configuration management
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },

    /// Check system for issues
    Doctor,
}

#[derive(Debug, Subcommand)]
pub enum DaemonCommand {
    /// Start the daemon
    Start {
        /// Run in background
        #[arg(short, long)]
        detach: bool,

        /// Don't auto-mount enabled shares
        #[arg(long)]
        no_automount: bool,
    },

    /// Stop the daemon
    Stop,

    /// Show daemon logs
    Logs {
        /// Number of lines to show
        #[arg(short, long)]
        lines: Option<usize>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Show configuration
    Show,

    /// Edit configuration in default editor
    Edit,
}

/// Run the CLI command
pub async fn run(cli: Cli, platform: Box<dyn Platform>) -> Result<()> {
    match cli.command {
        Commands::Mount { url, disable, dry_run } => {
            handle_mount(url, disable, dry_run, platform).await
        }
        Commands::Unmount { mount_id, force } => {
            handle_unmount(mount_id, force, platform).await
        }
        Commands::Status { verbose, watch, json } => {
            handle_status(verbose, watch, json, platform).await
        }
        Commands::List { enabled, disabled, json } => {
            handle_list(enabled, disabled, json, platform).await
        }
        Commands::Daemon { command } => {
            handle_daemon(command, platform).await
        }
        Commands::Discover { url } => {
            handle_discover(url, platform).await
        }
        Commands::Enable { mount_id } => {
            handle_enable(mount_id, platform).await
        }
        Commands::Disable { mount_id } => {
            handle_disable(mount_id, platform).await
        }
        Commands::Remove { mount_id } => {
            handle_remove(mount_id, platform).await
        }
        Commands::Remount { mount_id } => {
            handle_remount(mount_id, platform).await
        }
        Commands::Config { command } => {
            handle_config(command, platform).await
        }
        Commands::Doctor => {
            handle_doctor(platform).await
        }
    }
}

/// Handle mount command
async fn handle_mount(
    url: String,
    disable: bool,
    dry_run: bool,
    platform: Box<dyn Platform>,
) -> Result<()> {
    let request = Request::Mount {
        url: url.clone(),
        disable,
        dry_run,
    };

    let client = create_socket_client(platform.as_ref()).await?;
    let response = client.send_request(request).await;

    match response {
        Ok(Response::MountSuccess { mount_id, mount_point }) => {
            if dry_run {
                println!("Would mount {} to:", url);
                println!("  Mount ID: {}", mount_id);
                println!("  Mount point: {}", mount_point.display());
            } else {
                println!("Successfully mounted {} to:", url);
                println!("  Mount ID: {}", mount_id);
                println!("  Mount point: {}", mount_point.display());
            }
            Ok(())
        }
        Ok(Response::Error(msg)) => {
            error!("Mount failed: {}", msg);
            Err(anyhow!(msg))
        }
        Ok(_) => Err(anyhow!("Unexpected response")),
        Err(e) => {
            error!("Failed to communicate with daemon: {}", e);
            Err(e)
        }
    }
}

/// Handle unmount command
async fn handle_unmount(
    mount_id: String,
    force: bool,
    platform: Box<dyn Platform>,
) -> Result<()> {
    let mount_id_display = mount_id.clone();
    let request = Request::Unmount { mount_id, force };

    let client = create_socket_client(platform.as_ref()).await?;
    let response = client.send_request(request).await;

    match response {
        Ok(Response::UnmountSuccess) => {
            println!("Successfully unmounted {}", mount_id_display);
            Ok(())
        }
        Ok(Response::Error(msg)) => {
            error!("Unmount failed: {}", msg);
            Err(anyhow!(msg))
        }
        Ok(_) => Err(anyhow!("Unexpected response")),
        Err(e) => Err(e.into()),
    }
}

/// Handle status command
async fn handle_status(
    verbose: bool,
    watch: bool,
    json: bool,
    platform: Box<dyn Platform>,
) -> Result<()> {
    if watch {
        // TODO: Implement watch mode
        warn!("Watch mode not yet implemented");
    }

    let request = Request::Status { verbose, watch, json };
    let client = create_socket_client(platform.as_ref()).await?;
    let response = client.send_request(request).await;

    match response {
        Ok(Response::Status { mounts, daemon_running }) => {
            if !daemon_running {
                println!("Daemon is not running");
                return Ok(());
            }

            if mounts.is_empty() {
                println!("No mounts configured");
                return Ok(());
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&mounts)?);
            } else {
                for mount in mounts {
                    println!("{}: {}", mount.id, mount.status);
                    println!("  URL: {}", mount.url);
                    println!("  Mount point: {}", mount.mount_point.display());
                    println!("  Enabled: {}", mount.enabled);

                    if verbose {
                        if let Some(last_connected) = mount.last_connected {
                            println!("  Last connected: {}", last_connected.format("%Y-%m-%d %H:%M:%S UTC"));
                        }
                        if mount.reconnect_attempts > 0 {
                            println!("  Reconnect attempts: {}", mount.reconnect_attempts);
                        }
                        if let Some(health) = mount.health_score {
                            println!("  Health score: {}%", health);
                        }
                    }
                    println!();
                }
            }
            Ok(())
        }
        Ok(Response::Error(msg)) => {
            error!("Failed to get status: {}", msg);
            Err(anyhow!(msg))
        }
        Ok(_) => Err(anyhow!("Unexpected response")),
        Err(e) => Err(e.into()),
    }
}

/// Handle list command
async fn handle_list(
    enabled: bool,
    disabled: bool,
    json: bool,
    platform: Box<dyn Platform>,
) -> Result<()> {
    let request = Request::List {
        enabled_only: enabled,
        disabled_only: disabled,
        json,
    };

    let client = create_socket_client(platform.as_ref()).await?;
    let response = client.send_request(request).await;

    match response {
        Ok(Response::MountList { mounts }) => {
            if mounts.is_empty() {
                println!("No mounts found");
                return Ok(());
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&mounts)?);
            } else {
                for mount in mounts {
                    let status = if mount.enabled { "enabled" } else { "disabled" };
                    println!("{} ({})", mount.id, status);
                    println!("  URL: {}", mount.url);
                    println!("  Created: {}", mount.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
                    println!();
                }
            }
            Ok(())
        }
        Ok(Response::Error(msg)) => {
            error!("Failed to list mounts: {}", msg);
            Err(anyhow!(msg))
        }
        Ok(_) => Err(anyhow!("Unexpected response")),
        Err(e) => Err(e.into()),
    }
}

/// Handle daemon command
async fn handle_daemon(
    command: DaemonCommand,
    platform: Box<dyn Platform>,
) -> Result<()> {
    match command {
        DaemonCommand::Start { detach, no_automount } => {
            // Start the daemon directly (not through socket)
            let mut daemon = crate::daemon::Daemon::new(platform).await?;
            daemon.start(None, detach, no_automount).await
        }
        DaemonCommand::Stop => {
            let client = create_socket_client(platform.as_ref()).await?;
            let response = client.send_request(Request::StopDaemon).await;

            match response {
                Ok(Response::Success) => {
                    println!("Daemon stop signal sent");
                    Ok(())
                }
                Ok(Response::Error(msg)) => {
                    error!("Failed to stop daemon: {}", msg);
                    Err(anyhow!(msg))
                }
                Ok(_) => Err(anyhow!("Unexpected response")),
                Err(e) => Err(e.into()),
            }
        }
        DaemonCommand::Logs { lines } => {
            let client = create_socket_client(platform.as_ref()).await?;
            let response = client.send_request(Request::GetLogs { lines }).await;

            match response {
                Ok(Response::Logs { lines: log_lines }) => {
                    for line in log_lines {
                        println!("{}", line);
                    }
                    Ok(())
                }
                Ok(Response::Error(msg)) => {
                    error!("Failed to get logs: {}", msg);
                    Err(anyhow!(msg))
                }
                Ok(_) => Err(anyhow!("Unexpected response")),
                Err(e) => Err(e.into()),
            }
        }
    }
}

/// Handle discover command
async fn handle_discover(url: String, platform: Box<dyn Platform>) -> Result<()> {
    let client = create_socket_client(platform.as_ref()).await?;
    let response = client.send_request(Request::Discover { url }).await;

    match response {
        Ok(Response::DiscoveredShares { url, shares }) => {
            println!("Available shares on {}:", url);
            if shares.is_empty() {
                println!("  No shares found");
            } else {
                for share in shares {
                    println!("  {}", share);
                }
            }
            Ok(())
        }
        Ok(Response::Error(msg)) => {
            error!("Discovery failed: {}", msg);
            Err(anyhow!(msg))
        }
        Ok(_) => Err(anyhow!("Unexpected response")),
        Err(e) => Err(e.into()),
    }
}

/// Handle enable command
async fn handle_enable(mount_id: String, platform: Box<dyn Platform>) -> Result<()> {
    let client = create_socket_client(platform.as_ref()).await?;
    let response = client.send_request(Request::Enable { mount_id }).await;

    match response {
        Ok(Response::Success) => {
            println!("Enabled mount");
            Ok(())
        }
        Ok(Response::Error(msg)) => {
            error!("Failed to enable mount: {}", msg);
            Err(anyhow!(msg))
        }
        Ok(_) => Err(anyhow!("Unexpected response")),
        Err(e) => Err(e.into()),
    }
}

/// Handle disable command
async fn handle_disable(mount_id: String, platform: Box<dyn Platform>) -> Result<()> {
    let client = create_socket_client(platform.as_ref()).await?;
    let response = client.send_request(Request::Disable { mount_id }).await;

    match response {
        Ok(Response::Success) => {
            println!("Disabled mount");
            Ok(())
        }
        Ok(Response::Error(msg)) => {
            error!("Failed to disable mount: {}", msg);
            Err(anyhow!(msg))
        }
        Ok(_) => Err(anyhow!("Unexpected response")),
        Err(e) => Err(e.into()),
    }
}

/// Handle remove command
async fn handle_remove(mount_id: String, platform: Box<dyn Platform>) -> Result<()> {
    let client = create_socket_client(platform.as_ref()).await?;
    let response = client.send_request(Request::Remove { mount_id }).await;

    match response {
        Ok(Response::Success) => {
            println!("Removed mount");
            Ok(())
        }
        Ok(Response::Error(msg)) => {
            error!("Failed to remove mount: {}", msg);
            Err(anyhow!(msg))
        }
        Ok(_) => Err(anyhow!("Unexpected response")),
        Err(e) => Err(e.into()),
    }
}

/// Handle remount command
async fn handle_remount(mount_id: String, platform: Box<dyn Platform>) -> Result<()> {
    let client = create_socket_client(platform.as_ref()).await?;
    let response = client.send_request(Request::Remount { mount_id }).await;

    match response {
        Ok(Response::Success) => {
            println!("Remounted successfully");
            Ok(())
        }
        Ok(Response::Error(msg)) => {
            error!("Failed to remount: {}", msg);
            Err(anyhow!(msg))
        }
        Ok(_) => Err(anyhow!("Unexpected response")),
        Err(e) => Err(e.into()),
    }
}

/// Handle config command
async fn handle_config(command: ConfigCommand, platform: Box<dyn Platform>) -> Result<()> {
    match command {
        ConfigCommand::Show => {
            let client = create_socket_client(platform.as_ref()).await?;
            let response = client.send_request(Request::GetConfig).await;

            match response {
                Ok(Response::Config { config }) => {
                    println!("{}", config);
                    Ok(())
                }
                Ok(Response::Error(msg)) => {
                    error!("Failed to get config: {}", msg);
                    Err(anyhow!(msg))
                }
                Ok(_) => Err(anyhow!("Unexpected response")),
                Err(e) => Err(e.into()),
            }
        }
        ConfigCommand::Edit => {
            // TODO: Implement config editing
            warn!("Config edit not yet implemented");
            Ok(())
        }
    }
}

/// Handle doctor command
async fn handle_doctor(platform: Box<dyn Platform>) -> Result<()> {
    let client = create_socket_client(platform.as_ref()).await?;
    let response = client.send_request(Request::Doctor).await;

    match response {
        Ok(Response::DoctorReport { issues, suggestions }) => {
            println!("System Diagnosis:\n");

            if issues.is_empty() {
                println!("✓ No issues found");
            } else {
                for issue in issues {
                    let icon = match issue.severity {
                        crate::socket::protocol::IssueSeverity::Error => "❌",
                        crate::socket::protocol::IssueSeverity::Warning => "⚠️",
                        crate::socket::protocol::IssueSeverity::Info => "ℹ️",
                    };
                    println!("{} {}: {}", icon, issue.component, issue.message);
                }
            }

            if !suggestions.is_empty() {
                println!("\nSuggestions:");
                for suggestion in suggestions {
                    println!("  • {}", suggestion);
                }
            }

            Ok(())
        }
        Ok(Response::Error(msg)) => {
            error!("Doctor failed: {}", msg);
            Err(anyhow!(msg))
        }
        Ok(_) => Err(anyhow!("Unexpected response")),
        Err(e) => Err(e.into()),
    }
}

/// Create a socket client with the platform's socket path
async fn create_socket_client(platform: &dyn Platform) -> Result<SocketClient> {
    // Try to load config to get socket path
    let socket_path = {
        let config = crate::config::Config::load(platform).await;
        match config {
            Ok(cfg) => cfg.get_socket_path(platform).ok(),
            Err(_) => None,
        }
    };

    // Use the socket path from config, or let platform decide defaults
    let final_path = platform.get_socket_path(socket_path.as_deref());

    Ok(SocketClient::new(final_path))
}