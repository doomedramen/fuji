//! Fuji - Network File System Mount Manager
//!
//! A daemon-based tool that manages network file system mounts automatically.

// Test comment for pre-commit hook formatting

mod cli;
mod cluster;
mod config;
mod daemon;
mod monitoring;
mod mount;
mod network;
mod platform;
mod security;
mod socket;
mod sync;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, run};
use platform::get_platform;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Initialize logging based on RUST_LOG or default to info
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::ChronoUtc::rfc_3339())
        .init();

    // Get platform implementation
    let platform = get_platform();

    // Run the command
    run(cli, platform).await
}
