use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;

mod cli;
mod config;
mod daemon;
mod error;
mod platform;

use daemon::{start_daemon, Daemon, DaemonClient};

#[derive(Parser, Debug)]
#[command(name = "fuji")]
#[command(about = "Network File System Manager - Rust Implementation")]
struct Args {
    /// Run in daemon mode
    #[arg(long, hide = true)]
    daemon_mode: bool,

    /// Configuration file path
    #[arg(long, hide = true)]
    config: Option<PathBuf>,

    /// Skip automatic mounting of enabled shares on startup
    #[arg(long, hide = true)]
    no_automount: bool,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Daemon management
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    /// Mount a network file system
    Mount {
        /// URL of the network file system (e.g., nfs://192.168.1.1/export or smb://server/share)
        url: String,
    },
    /// Unmount a network file system
    Unmount {
        /// Mount ID to unmount
        mount_id: String,
    },
    /// Show daemon and mount status
    Status,
}

#[derive(Subcommand, Debug)]
enum DaemonAction {
    /// Start the daemon
    Start {
        /// Run daemon in background (detached mode)
        #[arg(short, long)]
        detach: bool,
        /// Skip automatic mounting of enabled shares on startup
        #[arg(long)]
        no_automount: bool,
        /// Enable debug logging
        #[arg(short, long)]
        debug: bool,
    },
    /// Stop the daemon
    Stop,
}

#[tokio::main]
async fn main() -> Result<(), crate::error::FujiError> {
    let args = Args::parse();

    // Initialize tracing with appropriate log level
    let log_level = if args.debug {
        "debug"
    } else {
        "info"
    };

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(args.debug) // Show line numbers in debug mode
        .init();

    // Handle daemon mode
    if args.daemon_mode {
        tracing::error!("🚀 STARTING DAEMON MODE");
        tracing::error!("  - PID: {}", std::process::id());
        tracing::error!("  - Args: {:?}", args);

        let config = if let Some(config_path) = args.config {
            tracing::error!("📁 Loading config from path: {:?}", config_path);
            config::Config::load_from_path(config_path)?
        } else {
            tracing::error!("📁 Loading default config");
            config::Config::load()?
        };

        tracing::error!("🏗️ Creating daemon instance");
        let mut daemon = Daemon::new(config, args.no_automount)?;

        tracing::error!("▶️ Starting daemon run loop");
        match daemon.run().await {
            Ok(_) => {
                tracing::error!("✅ Daemon run completed successfully");
            }
            Err(e) => {
                tracing::error!("❌ Daemon run failed with error: {}", e);
                return Err(e);
            }
        }
        tracing::error!("🏁 Daemon mode finished");
        return Ok(());
    }

    // Handle CLI commands
    let config = config::Config::load()?;
    let client = DaemonClient::new(config.socket_path().to_path_buf());

    if let Some(command) = args.command {
        match command {
            Commands::Daemon { action } => match action {
                DaemonAction::Start {
                    detach,
                    no_automount,
                    debug: _,
                } => {
                    info!("Starting daemon...");
                    start_daemon(config, detach, no_automount).await?;
                }
                DaemonAction::Stop => {
                    info!("Stopping daemon...");
                    client.send_command(daemon::Command::Stop).await?;
                }
            },
            Commands::Mount { url } => {
                info!("Mounting: {}", url);
                client.send_command(daemon::Command::Mount { url }).await?;
            }
            Commands::Unmount { mount_id } => {
                info!("Unmounting: {}", mount_id);
                client
                    .send_command(daemon::Command::Unmount { mount_id })
                    .await?;
            }
            Commands::Status => {
                info!("Getting status...");
                client.send_command(daemon::Command::Status).await?;
            }
        }
    } else {
        // Show help if no command provided
        Args::command().print_help()?;
    }

    Ok(())
}
