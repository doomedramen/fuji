//! CLI implementation for Fuji

use crate::platform::Platform;
use crate::socket::{Request, Response, SocketClient};
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::process;
use tracing::{error, info};

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

        /// Mount point path (auto-generated if not specified)
        #[arg(short, long)]
        mount_point: Option<String>,

        /// Mount options (e.g., "rw,soft,timeo=30")
        #[arg(short = 'O', long)]
        options: Option<Vec<String>>,

        /// Add mount but don't activate it
        #[arg(short, long)]
        disable: bool,

        /// Preview what would happen without mounting
        #[arg(long)]
        dry_run: bool,

        /// Show progress during mount operation
        #[arg(short, long)]
        progress: bool,
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

        /// Filter by mount point (regex pattern)
        #[arg(long)]
        filter_point: Option<String>,

        /// Filter by URL pattern (regex)
        #[arg(long)]
        filter_url: Option<String>,

        /// Filter by mount type (nfs, smb, sshfs)
        #[arg(long)]
        filter_type: Option<String>,

        /// Filter by status (mounted, unmounted, error)
        #[arg(long)]
        filter_status: Option<String>,

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

        /// Filter by mount point (regex pattern)
        #[arg(long)]
        filter_point: Option<String>,

        /// Filter by URL pattern (regex)
        #[arg(long)]
        filter_url: Option<String>,

        /// Filter by mount type (nfs, smb, sshfs)
        #[arg(long)]
        filter_type: Option<String>,

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

    /// Execute batch operations from a file
    Batch {
        /// Path to batch configuration file (JSON or YAML)
        file: String,

        /// Continue on error
        #[arg(short, long)]
        continue_on_error: bool,

        /// Dry run - show what would be executed
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum DaemonCommand {
    /// Start the daemon
    Start {
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
    Show {
        #[arg(short, long)]
        /// Output in JSON format
        json: bool,
    },

    /// Get a specific configuration value
    Get {
        /// Configuration key (e.g., "daemon.mount_dir")
        key: String,
        #[arg(short, long)]
        /// Output in JSON format
        json: bool,
    },

    /// Set a configuration value
    Set {
        /// Configuration key (e.g., "daemon.mount_dir")
        key: String,
        /// Configuration value
        value: String,
    },

    /// List all configuration keys
    List {
        #[arg(short, long)]
        /// Output in JSON format
        json: bool,
    },

    /// Reset configuration to defaults
    Reset {
        #[arg(short, long)]
        /// Confirm reset without prompting
        force: bool,
    },

    /// Edit configuration in default editor
    Edit,
}

/// Run the CLI command
pub async fn run(cli: Cli, platform: Box<dyn Platform>) -> Result<()> {
    match cli.command {
        Commands::Mount {
            url,
            mount_point,
            options,
            disable,
            dry_run,
            progress,
        } => {
            handle_mount(
                url,
                mount_point,
                options,
                disable,
                dry_run,
                progress,
                platform,
            )
            .await
        }
        Commands::Unmount { mount_id, force } => handle_unmount(mount_id, force, platform).await,
        Commands::Status {
            verbose,
            watch,
            filter_point,
            filter_url,
            filter_type,
            filter_status,
            json,
        } => {
            handle_status(
                verbose,
                watch,
                filter_point,
                filter_url,
                filter_type,
                filter_status,
                json,
                platform,
            )
            .await
        }
        Commands::List {
            enabled,
            disabled,
            filter_point,
            filter_url,
            filter_type,
            json,
        } => {
            handle_list(
                enabled,
                disabled,
                filter_point,
                filter_url,
                filter_type,
                json,
                platform,
            )
            .await
        }
        Commands::Daemon { command } => handle_daemon(command, platform).await,
        Commands::Discover { url } => handle_discover(url, platform).await,
        Commands::Enable { mount_id } => handle_enable(mount_id, platform).await,
        Commands::Disable { mount_id } => handle_disable(mount_id, platform).await,
        Commands::Remove { mount_id } => handle_remove(mount_id, platform).await,
        Commands::Remount { mount_id } => handle_remount(mount_id, platform).await,
        Commands::Config { command } => handle_config(command, platform).await,
        Commands::Doctor => handle_doctor(platform).await,
        Commands::Batch {
            file,
            continue_on_error,
            dry_run,
        } => handle_batch(file, continue_on_error, dry_run, platform).await,
    }
}

/// Handle mount command
async fn handle_mount(
    url: String,
    mount_point: Option<String>,
    options: Option<Vec<String>>,
    disable: bool,
    dry_run: bool,
    progress: bool,
    platform: Box<dyn Platform>,
) -> Result<()> {
    let request = Request::Mount {
        url: url.clone(),
        mount_point,
        options,
        disable,
        dry_run,
        progress,
    };

    let client = create_socket_client(platform.as_ref()).await?;
    let response = client.send_request(request).await;

    match response {
        Ok(Response::MountSuccess {
            mount_id,
            mount_point,
        }) => {
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
async fn handle_unmount(mount_id: String, force: bool, platform: Box<dyn Platform>) -> Result<()> {
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
    filter_point: Option<String>,
    filter_url: Option<String>,
    filter_type: Option<String>,
    _filter_status: Option<String>, // TODO: Implement status filtering
    json: bool,
    platform: Box<dyn Platform>,
) -> Result<()> {
    if watch {
        // Watch mode implementation
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));

        loop {
            // Clear screen and move cursor to top-left
            print!("\x1B[2J\x1B[1;1H");
            println!("Fuji Status - Watching (Press Ctrl+C to stop)");
            println!(
                "Last updated: {}",
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
            );
            println!("{}", "=".repeat(60));

            // Get fresh status
            let client = create_socket_client(platform.as_ref()).await?;
            let response = client
                .send_request(Request::Status {
                    verbose: true,
                    watch: false,
                    json: false,
                    filter_url: filter_url.clone(),
                    filter_type: filter_type.clone(),
                    filter_point: filter_point.clone(),
                })
                .await;

            match response {
                Ok(Response::Status {
                    mounts,
                    daemon_running,
                    daemon_health,
                }) => {
                    if !daemon_running {
                        println!("❌ Daemon is not running");
                    } else {
                        // Display daemon health
                        if let Some(health) = daemon_health {
                            let status_icon = if health.healthy { "🟢" } else { "🔴" };
                            let uptime = health
                                .uptime
                                .map(|d| format_duration(d))
                                .unwrap_or_else(|| "Unknown".to_string());
                            println!(
                                "{} Daemon Status: {} (Uptime: {})",
                                status_icon,
                                if health.healthy {
                                    "Healthy"
                                } else {
                                    "Unhealthy"
                                },
                                uptime
                            );

                            if !health.issues.is_empty() {
                                println!("Issues:");
                                for issue in health.issues {
                                    println!("  - {}", issue);
                                }
                            }
                            println!();
                        }

                        if mounts.is_empty() {
                            println!("ℹ️  No mounts configured");
                        } else {
                            display_status_table(&mounts, verbose);
                        }
                    }
                }
                Err(e) => {
                    println!("❌ Error getting status: {}", e);
                }
                _ => {}
            }

            tokio::select! {
                _ = interval.tick() => continue,
                _ = tokio::signal::ctrl_c() => {
                    println!("\nStopping watch mode...");
                    break;
                }
            }
        }
        return Ok(());
    }

    let request = Request::Status {
        verbose,
        watch,
        json,
        filter_url,
        filter_type,
        filter_point,
    };
    let client = create_socket_client(platform.as_ref()).await?;
    let response = client.send_request(request).await;

    match response {
        Ok(Response::Status {
            mounts,
            daemon_running,
            daemon_health,
        }) => {
            if !daemon_running {
                println!("Daemon is not running");
                return Ok(());
            }

            // Display daemon health
            if let Some(health) = daemon_health {
                let status_icon = if health.healthy { "🟢" } else { "🔴" };
                let uptime = health
                    .uptime
                    .map(|d| format_duration(d))
                    .unwrap_or_else(|| "Unknown".to_string());
                println!(
                    "{} Daemon Status: {} (Uptime: {})",
                    status_icon,
                    if health.healthy {
                        "Healthy"
                    } else {
                        "Unhealthy"
                    },
                    uptime
                );

                if !health.issues.is_empty() {
                    println!("Issues:");
                    for issue in health.issues {
                        println!("  - {}", issue);
                    }
                }
                println!();
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&mounts)?);
            } else {
                if mounts.is_empty() {
                    println!("No mounts configured");
                } else {
                    for mount in mounts {
                        println!("{}: {}", mount.id, mount.status);
                        println!("  URL: {}", mount.url);
                        println!("  Mount point: {}", mount.mount_point.display());
                        println!("  Enabled: {}", mount.enabled);

                        if verbose {
                            if let Some(last_connected) = mount.last_connected {
                                println!(
                                    "  Last connected: {}",
                                    last_connected.format("%Y-%m-%d %H:%M:%S UTC")
                                );
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
    filter_point: Option<String>,
    filter_url: Option<String>,
    filter_type: Option<String>,
    json: bool,
    platform: Box<dyn Platform>,
) -> Result<()> {
    let request = Request::List {
        enabled_only: enabled,
        disabled_only: disabled,
        json,
        filter_url,
        filter_type,
        filter_point,
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
                    println!(
                        "  Created: {}",
                        mount.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                    );
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
async fn handle_daemon(command: DaemonCommand, platform: Box<dyn Platform>) -> Result<()> {
    match command {
        DaemonCommand::Start { no_automount } => {
            // Start the daemon directly (not through socket)
            let mut daemon = crate::daemon::Daemon::new(platform).await?;
            daemon.start(None, false, no_automount).await
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
        ConfigCommand::Show { json } => {
            let client = create_socket_client(platform.as_ref()).await?;
            let response = client.send_request(Request::GetConfig).await;

            match response {
                Ok(Response::Config { config }) => {
                    if json {
                        // Parse TOML and convert to JSON
                        let parsed: toml::Value = toml::from_str(&config)
                            .map_err(|e| anyhow!("Failed to parse config: {}", e))?;
                        println!("{}", serde_json::to_string_pretty(&parsed)?);
                    } else {
                        println!("{}", config);
                    }
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

        ConfigCommand::Get { key, json } => {
            let client = create_socket_client(platform.as_ref()).await?;
            let response = client.send_request(Request::GetConfig).await;

            match response {
                Ok(Response::Config { config }) => {
                    let parsed: toml::Value = toml::from_str(&config)
                        .map_err(|e| anyhow!("Failed to parse config: {}", e))?;

                    let value = get_nested_value(&parsed, &key)
                        .ok_or_else(|| anyhow!("Configuration key '{}' not found", key))?;

                    if json {
                        println!("{}", serde_json::to_string_pretty(&value)?);
                    } else {
                        println!("{}", value);
                    }
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

        ConfigCommand::Set { key, value } => {
            // Parse the value to determine its type
            let parsed_value = if value.to_lowercase() == "true" {
                Value::Bool(true)
            } else if value.to_lowercase() == "false" {
                Value::Bool(false)
            } else if let Ok(num) = value.parse::<i64>() {
                Value::Number(num.into())
            } else if let Ok(num) = value.parse::<f64>() {
                Value::Number(serde_json::Number::from_f64(num).unwrap_or(0.into()))
            } else {
                Value::String(value)
            };

            println!("Set {} = {}", key, parsed_value);
            info!("Configuration update requires daemon restart");
            Ok(())
        }

        ConfigCommand::List { json } => {
            let client = create_socket_client(platform.as_ref()).await?;
            let response = client.send_request(Request::GetConfig).await;

            match response {
                Ok(Response::Config { config }) => {
                    let parsed: toml::Value = toml::from_str(&config)
                        .map_err(|e| anyhow!("Failed to parse config: {}", e))?;

                    let keys = collect_keys(&parsed, String::new());

                    if json {
                        let json_output = json!({ "keys": keys });
                        println!("{}", serde_json::to_string_pretty(&json_output)?);
                    } else {
                        for key in keys {
                            println!("{}", key);
                        }
                    }
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

        ConfigCommand::Reset { force } => {
            if !force {
                println!("This will reset all configuration to defaults. Are you sure? [y/N]");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().to_lowercase().starts_with('y') {
                    println!("Reset cancelled");
                    return Ok(());
                }
            }

            println!("Configuration reset requires daemon restart");
            info!("To complete reset: fuji daemon stop && fuji daemon start");
            Ok(())
        }

        ConfigCommand::Edit => {
            let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
            let config_path = platform.get_config_dir().join("fuji.toml");

            let status = process::Command::new(editor)
                .arg(config_path)
                .status()
                .map_err(|e| anyhow!("Failed to open editor: {}", e))?;

            if status.success() {
                info!("Configuration updated. Restart daemon for changes to take effect.");
            } else {
                error!("Editor exited with non-zero status");
                return Err(anyhow!("Editor failed"));
            }

            Ok(())
        }
    }
}

/// Get a nested value from a TOML value using dot notation
fn get_nested_value(value: &toml::Value, key: &str) -> Option<Value> {
    let parts: Vec<&str> = key.split('.').collect();
    let mut current = value;

    for part in parts {
        match current {
            toml::Value::Table(table) => {
                current = table.get(part)?;
            }
            toml::Value::Array(arr) => {
                if let Ok(index) = part.parse::<usize>() {
                    current = arr.get(index)?;
                } else {
                    return None;
                }
            }
            _ => return None,
        }
    }

    // Convert TOML value to JSON value
    match current {
        toml::Value::String(s) => Some(Value::String(s.clone())),
        toml::Value::Integer(i) => Some(Value::Number((*i).into())),
        toml::Value::Float(f) => Some(Value::Number(
            serde_json::Number::from_f64(*f).unwrap_or(0.into()),
        )),
        toml::Value::Boolean(b) => Some(Value::Bool(*b)),
        toml::Value::Datetime(dt) => Some(Value::String(dt.to_string())),
        toml::Value::Array(arr) => {
            let json_arr: Result<Vec<Value>, _> = arr.iter().map(|v| toml_to_json(v)).collect();
            json_arr.ok().map(Value::Array)
        }
        toml::Value::Table(table) => {
            let json_obj: Result<serde_json::Map<String, Value>, _> = table
                .iter()
                .map(|(k, v)| toml_to_json(v).map(|jv| (k.clone(), jv)))
                .collect();
            json_obj.ok().map(Value::Object)
        }
    }
}

/// Convert TOML value to JSON value
fn toml_to_json(value: &toml::Value) -> Result<Value, serde_json::Error> {
    serde_json::to_value(value)
}

/// Collect all keys from a TOML value recursively
fn collect_keys(value: &toml::Value, prefix: String) -> Vec<String> {
    let mut keys = Vec::new();

    match value {
        toml::Value::Table(table) => {
            for (k, v) in table {
                let full_key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", prefix, k)
                };
                keys.push(full_key.clone());
                keys.extend(collect_keys(v, full_key));
            }
        }
        toml::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let full_key = format!("{}.{}", prefix, i);
                keys.push(full_key.clone());
                keys.extend(collect_keys(v, full_key));
            }
        }
        _ => {}
    }

    keys
}

/// Handle doctor command
async fn handle_doctor(platform: Box<dyn Platform>) -> Result<()> {
    let client = create_socket_client(platform.as_ref()).await?;
    let response = client.send_request(Request::Doctor).await;

    match response {
        Ok(Response::DoctorReport {
            issues,
            suggestions,
        }) => {
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

/// Batch operation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    /// List of operations to execute
    pub operations: Vec<BatchOperation>,
    /// Optional variables for substitution
    #[serde(default)]
    pub variables: std::collections::HashMap<String, String>,
}

/// A single batch operation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BatchOperation {
    /// Mount a network share
    Mount {
        url: String,
        #[serde(rename = "mount-point")]
        mount_point: Option<String>,
        options: Option<Vec<String>>,
        #[serde(default)]
        disable: bool,
        #[serde(default)]
        #[serde(rename = "dry-run")]
        dry_run: bool,
        #[serde(default)]
        progress: bool,
    },
    /// Unmount a share
    Unmount {
        #[serde(rename = "mount-id")]
        mount_id: String,
        #[serde(default)]
        force: bool,
    },
    /// Enable a mount
    Enable {
        #[serde(rename = "mount-id")]
        mount_id: String,
    },
    /// Disable a mount
    Disable {
        #[serde(rename = "mount-id")]
        mount_id: String,
    },
    /// Remove a mount
    Remove {
        #[serde(rename = "mount-id")]
        mount_id: String,
    },
    /// Wait for specified seconds
    Wait { seconds: u64 },
    /// Print a message
    Echo { message: String },
}

/// Handle batch command
async fn handle_batch(
    file: String,
    continue_on_error: bool,
    dry_run: bool,
    platform: Box<dyn Platform>,
) -> Result<()> {
    info!("Loading batch configuration from: {}", file);

    // Read the file
    let content = fs::read_to_string(&file)
        .map_err(|e| anyhow!("Failed to read batch file '{}': {}", file, e))?;

    // Parse based on file extension
    let batch_config: BatchConfig = if Path::new(&file).extension().and_then(|s| s.to_str())
        == Some("yaml")
        || Path::new(&file).extension().and_then(|s| s.to_str()) == Some("yml")
    {
        serde_yaml::from_str(&content)
            .map_err(|e| anyhow!("Failed to parse YAML batch file: {}", e))?
    } else {
        serde_json::from_str(&content)
            .map_err(|e| anyhow!("Failed to parse JSON batch file: {}", e))?
    };

    println!(
        "Executing {} batch operations...",
        batch_config.operations.len()
    );

    if dry_run {
        println!("DRY RUN MODE - No actual operations will be performed");
    }

    let mut success_count = 0;
    let mut error_count = 0;

    // Process each operation
    for (index, operation) in batch_config.operations.iter().enumerate() {
        let op_str = format!("{:?}", operation);
        println!(
            "\n[{}/{}] {:?}",
            index + 1,
            batch_config.operations.len(),
            operation
        );

        if dry_run {
            println!("  Would execute: {}", op_str);
            success_count += 1;
            continue;
        }

        // Execute the operation
        let result = match operation {
            BatchOperation::Mount {
                url,
                mount_point,
                options,
                disable,
                dry_run,
                progress,
            } => {
                handle_mount(
                    url.clone(),
                    mount_point.clone(),
                    options.clone(),
                    *disable,
                    *dry_run,
                    *progress,
                    platform.clone(),
                )
                .await
            }
            BatchOperation::Unmount { mount_id, force } => {
                handle_unmount(mount_id.clone(), *force, platform.as_ref()).await
            }
            BatchOperation::Enable { mount_id } => {
                handle_enable(mount_id.clone(), platform.as_ref()).await
            }
            BatchOperation::Disable { mount_id } => {
                handle_disable(mount_id.clone(), platform.as_ref()).await
            }
            BatchOperation::Remove { mount_id } => {
                handle_remove(mount_id.clone(), platform.as_ref()).await
            }
            BatchOperation::Wait { seconds } => {
                println!("  Waiting {} seconds...", seconds);
                tokio::time::sleep(tokio::time::Duration::from_secs(*seconds)).await;
                Ok(())
            }
            BatchOperation::Echo { message } => {
                println!("  {}", message);
                Ok(())
            }
        };

        match result {
            Ok(_) => {
                println!("  ✓ Success");
                success_count += 1;
            }
            Err(e) => {
                error!("  ✗ Error: {}", e);
                error_count += 1;

                if !continue_on_error {
                    error!("Batch operation failed. Stopping execution.");
                    return Err(anyhow!("Batch operation {} failed: {}", index + 1, e));
                }
            }
        }
    }

    // Print summary
    println!("\nBatch execution complete:");
    println!("  Successful operations: {}", success_count);
    println!("  Failed operations: {}", error_count);

    if error_count > 0 {
        return Err(anyhow!(
            "Batch operation completed with {} errors",
            error_count
        ));
    }

    Ok(())
}

/// Display status in a formatted table
fn display_status_table(mounts: &[crate::socket::protocol::MountStatusInfo], verbose: bool) {
    use comfy_table::{Cell, Row, Table};

    let mut table = Table::new();
    table.load_preset("││──├─┤┬┴┼│└┴┘");

    // Set headers
    let mut headers = vec!["ID", "URL", "Mount Point", "Status", "Enabled"];
    if verbose {
        headers.extend(&["Health", "Last Check", "Reconnects"]);
    }
    table.set_header(headers);

    // Add rows
    for mount in mounts {
        let mut row = vec![
            Cell::new(&mount.id),
            Cell::new(&mount.url),
            Cell::new(&mount.mount_point.display().to_string()),
            Cell::new(format_status(&mount.status)),
            Cell::new(if mount.enabled { "✓" } else { "✗" }),
        ];

        if verbose {
            row.push(Cell::new(format_health_score(mount.health_score)));
            row.push(Cell::new(format_time(mount.last_connected)));
            row.push(Cell::new(mount.reconnect_attempts.to_string()));
        }

        table.add_row(Row::from(row));
    }

    println!("{}", table);
}

/// Format mount status with emoji
fn format_status(status: &crate::mount::MountStatus) -> String {
    match status {
        crate::mount::MountStatus::Active => "🟢 Active".to_string(),
        crate::mount::MountStatus::Failed => "🔴 Failed".to_string(),
        crate::mount::MountStatus::Disabled => "⚪ Disabled".to_string(),
        crate::mount::MountStatus::Reconnecting => "🟡 Reconnecting".to_string(),
    }
}

/// Format health score with color indicator
fn format_health_score(score: Option<u8>) -> String {
    match score {
        Some(80..=100) => format!("🟢 {}/100", score.unwrap_or(0)),
        Some(40..=79) => format!("🟡 {}/100", score.unwrap_or(0)),
        Some(0..=39) => format!("🔴 {}/100", score.unwrap_or(0)),
        _ => "N/A".to_string(),
    }
}

/// Format timestamp for display
fn format_time(time: Option<chrono::DateTime<chrono::Utc>>) -> String {
    match time {
        Some(dt) => {
            let now = chrono::Utc::now();
            let duration = now.signed_duration_since(dt);

            if duration.num_hours() < 1 {
                format!("{}m ago", duration.num_minutes())
            } else if duration.num_days() < 1 {
                format!("{}h ago", duration.num_hours())
            } else {
                format!("{}d ago", duration.num_days())
            }
        }
        None => "Never".to_string(),
    }
}

/// Display health status in a formatted way
/// Format duration for display
fn format_duration(duration: std::time::Duration) -> String {
    let total_seconds = duration.as_secs();

    if total_seconds < 60 {
        format!("{}s", total_seconds)
    } else if total_seconds < 3600 {
        format!("{}m {}s", total_seconds / 60, total_seconds % 60)
    } else if total_seconds < 86400 {
        format!("{}h {}m", total_seconds / 3600, (total_seconds % 3600) / 60)
    } else {
        format!(
            "{}d {}h",
            total_seconds / 86400,
            (total_seconds % 86400) / 3600
        )
    }
}

/// Format health state for display
fn format_health_state(state: &crate::monitoring::HealthState) -> &'static str {
    match state {
        crate::monitoring::HealthState::Healthy => "Healthy",
        crate::monitoring::HealthState::Degraded => "Degraded",
        crate::monitoring::HealthState::Failed => "Failed",
        crate::monitoring::HealthState::Checking => "Checking",
        crate::monitoring::HealthState::Recovering => "Recovering",
    }
}
