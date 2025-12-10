//! Cluster management CLI commands

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Subcommand;
use comfy_table::{Cell, Table, presets::UTF8_FULL};
use std::sync::Arc;
use tracing::error;

use crate::cli::CliContext;
use crate::cluster::ClusterInvitation;
use crate::cluster::ClusterState;
use crate::cluster::discovery::DiscoveryManager;
use crate::network::tcp::TcpTransport;
use crate::sync::coordinator::SyncCoordinator;

/// Cluster management subcommands
#[derive(Subcommand, Debug)]
pub enum ClusterCommands {
    /// Get cluster information and generate an invitation
    Info,
    /// Join a cluster using an invitation
    Join {
        /// The invitation string from an existing cluster node
        invitation: String,
    },
    /// Show cluster status
    Status,
    /// Leave the current cluster
    Leave,
    /// Show cluster sync history
    History,
    /// Force synchronization with all peers
    SyncForce,
}

/// Handle cluster subcommands
pub async fn handle_cluster_command(cmd: ClusterCommands, ctx: Arc<CliContext>) -> Result<()> {
    match cmd {
        ClusterCommands::Info => handle_info(ctx).await,
        ClusterCommands::Join {
            invitation,
        } => handle_join(invitation, ctx).await,
        ClusterCommands::Status => handle_status(ctx).await,
        ClusterCommands::Leave => handle_leave(ctx).await,
        ClusterCommands::History => handle_history(ctx).await,
        ClusterCommands::SyncForce => handle_sync_force(ctx).await,
    }
}

/// Handle cluster info command - generate and display invitation
async fn handle_info(ctx: Arc<CliContext>) -> Result<()> {
    let config = ctx.config.read().await;

    if let Some(cluster) = &config.cluster {
        if cluster.enabled {
            // We're already in a cluster
            println!("✓ Already part of a cluster");
            println!("Instance ID: {}", cluster.instance_id);
            println!("Peers: {}", cluster.peers.len());

            if !cluster.peers.is_empty() {
                let mut table = Table::new();
                table.load_preset(UTF8_FULL).set_header(vec![
                    "Peer ID",
                    "Address",
                    "Status",
                    "Last Seen",
                ]);

                for peer in &cluster.peers {
                    let last_seen = peer.last_seen.format("%Y-%m-%d %H:%M:%S UTC");
                    table.add_row(vec![
                        Cell::new(&peer.id),
                        Cell::new(&peer.address),
                        Cell::new(format!("{:?}", peer.status)),
                        Cell::new(&last_seen),
                    ]);
                }

                println!("\nCurrent Peers:");
                println!("{}", table);
            }

            // Generate invitation anyway for new nodes to join
            println!("\nGenerating invitation for new nodes to join...");
        } else {
            println!("Cluster mode is disabled in configuration");
            return Ok(());
        }
    } else {
        println!("Not currently in a cluster. Generating invitation to create one...");
    }

    // Create discovery manager and generate invitation
    let instance_manager = ctx.instance_manager.clone();
    let instance_id = instance_manager.get_instance_id().to_string();
    let discovery = DiscoveryManager::new(instance_id);

    let peer_count = if let Some(cluster) = ctx.config.read().await.cluster.as_ref() {
        cluster.peers.len()
    } else {
        0
    };

    let invitation = discovery.generate_invitation(peer_count, Some(24)).await?;

    println!("\n=== Cluster Invitation ===");
    println!("\nShare this string with other Fuji nodes to join this cluster:");
    println!("\n{}", invitation.to_string());
    println!(
        "\nExpiration: {} hours",
        invitation.hours_until_expiration()
    );
    println!("========================\n");

    // Save invitation to file for easy access
    let invitation_file = ctx.config_dir.join("latest-invitation.txt");
    std::fs::write(&invitation_file, invitation.to_string())?;
    println!("Invitation also saved to: {:?}", invitation_file);

    Ok(())
}

/// Handle cluster join command
async fn handle_join(invitation: String, ctx: Arc<CliContext>) -> Result<()> {
    println!("Joining cluster with invitation...");

    // Parse invitation
    let invitation = match ClusterInvitation::from_str(&invitation) {
        Ok(inv) => inv,
        Err(e) => {
            error!("Invalid invitation: {}", e);
            return Err(e);
        }
    };

    // Check expiration
    if invitation.is_expired() {
        error!("Invitation has expired on {}", invitation.expires_at);
        return Err(anyhow::anyhow!("Invitation has expired"));
    }

    // Verify signature
    if !invitation.verify()? {
        error!("Invalid invitation signature");
        return Err(anyhow::anyhow!("Invalid invitation signature"));
    }

    println!("Invitation verified successfully");
    println!("From instance: {}", invitation.instance_id);
    println!("Address: {}", invitation.address);
    println!("Expires in: {} hours", invitation.hours_until_expiration());

    // Get instance manager and accept invitation
    let instance_manager = ctx.instance_manager.clone();
    let instance_id = instance_manager.get_instance_id().to_string();
    let discovery = DiscoveryManager::new(instance_id.clone());
    let peer = discovery.accept_invitation(invitation.clone()).await?;

    // Update configuration
    {
        let mut config = ctx.config.write().await;
        if config.cluster.is_none() {
            config.initialize_cluster(instance_id.clone());
        }

        if let Some(cluster) = config.get_cluster_config_mut() {
            // Add the peer
            cluster.peers.push(peer);
        }
    }

    // Save configuration
    ctx.save_config().await?;

    // Initialize sync coordinator with configurable port
    let cluster_state = Arc::new(ClusterState::new());
    let config = ctx.config.read().await;
    let cluster_port = config.cluster.as_ref().map(|c| c.port).unwrap_or(10080);
    drop(config);
    let local_addr = format!("0.0.0.0:{}", cluster_port)
        .parse()
        .with_context(|| format!("Invalid cluster port: {}", cluster_port))?;
    let transport = Arc::new(TcpTransport::new(local_addr));
    let coordinator = SyncCoordinator::new(
        instance_id,
        cluster_state.clone(),
        transport.clone(),
        ctx.config.clone(),
    );

    // Join the cluster
    coordinator.join_cluster(&invitation).await?;

    // Initialize the coordinator
    coordinator.initialize().await?;

    println!("\n✓ Successfully joined the cluster!");
    println!(
        "You are now connected to instance {}",
        invitation.instance_id
    );

    Ok(())
}

/// Handle cluster status command
async fn handle_status(ctx: Arc<CliContext>) -> Result<()> {
    let config = ctx.config.read().await;

    if let Some(cluster) = &config.cluster {
        if !cluster.enabled {
            println!("Cluster mode: disabled");
            return Ok(());
        }

        println!("Cluster Status:");
        println!("  Instance ID: {}", cluster.instance_id);
        println!("  Sync Interval: {:?}", cluster.sync_interval);
        println!("  Sync Timeout: {:?}", cluster.sync_timeout);

        if let Some(last_sync) = cluster.sync_metadata.last_sync_at {
            println!("  Last Sync: {}", last_sync.format("%Y-%m-%d %H:%M:%S UTC"));
        } else {
            println!("  Last Sync: Never");
        }

        println!("  Sync Version: {}", cluster.sync_metadata.sync_version);

        if let Some(modified_by) = &cluster.sync_metadata.last_modified_by {
            println!("  Last Modified By: {}", modified_by);
        }

        println!("\nPeers ({} total):", cluster.peers.len());

        if cluster.peers.is_empty() {
            println!("  No peers connected");
        } else {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL).set_header(vec![
                "Peer ID",
                "Address",
                "Status",
                "Last Seen",
            ]);

            for peer in &cluster.peers {
                let last_seen = if peer.last_seen == Utc::now() {
                    "Now".to_string()
                } else {
                    peer.last_seen.format("%Y-%m-%d %H:%M:%S UTC").to_string()
                };

                table.add_row(vec![
                    Cell::new(&peer.id),
                    Cell::new(&peer.address),
                    Cell::new(format!("{:?}", peer.status)),
                    Cell::new(&last_seen),
                ]);
            }

            println!("{}", table);
        }

        // Show pending conflicts if any
        if !cluster.sync_metadata.pending_conflicts.is_empty() {
            println!("\n⚠️  Pending Conflicts:");
            for conflict in &cluster.sync_metadata.pending_conflicts {
                println!("  - Mount: {}", conflict.mount_id);
                println!("    Type: {:?}", conflict.conflict_type);
                println!("    Resolution: {:?}", conflict.resolution);
            }
        }
    } else {
        println!("Not part of any cluster");
        println!("Use 'fuji cluster info' to create a new cluster or");
        println!("Use 'fuji cluster join <invitation>' to join an existing one");
    }

    Ok(())
}

/// Handle cluster leave command
async fn handle_leave(ctx: Arc<CliContext>) -> Result<()> {
    println!("Leaving cluster...");

    // Update configuration to disable cluster
    {
        let mut config = ctx.config.write().await;
        if let Some(cluster) = config.cluster.as_mut() {
            cluster.enabled = false;
            cluster.peers.clear();
        }
    }

    // Save configuration
    ctx.save_config().await?;

    println!("✓ Successfully left the cluster");
    println!("Note: You may need to restart the daemon for changes to take effect");

    Ok(())
}

/// Handle cluster history command
async fn handle_history(ctx: Arc<CliContext>) -> Result<()> {
    let config = ctx.config.read().await;

    if let Some(cluster) = &config.cluster {
        if let Some(last_sync) = cluster.sync_metadata.last_sync_at {
            println!("Sync History:");
            println!("  Last Sync: {}", last_sync.format("%Y-%m-%d %H:%M:%S UTC"));
            println!("  Sync Version: {}", cluster.sync_metadata.sync_version);

            if let Some(modified_by) = &cluster.sync_metadata.last_modified_by {
                println!("  Last Modified By: {}", modified_by);
            }

            // TODO: Implement more detailed sync history tracking
            println!(
                "\nNote: Detailed sync history tracking will be implemented in a future version"
            );
        } else {
            println!("No sync history available");
        }
    } else {
        println!("Not part of any cluster");
    }

    Ok(())
}

/// Handle force sync command
async fn handle_sync_force(ctx: Arc<CliContext>) -> Result<()> {
    let config = ctx.config.read().await;

    if let Some(cluster) = &config.cluster {
        if !cluster.enabled {
            error!("Cluster mode is disabled");
            return Err(anyhow::anyhow!("Cluster mode is disabled"));
        }

        if cluster.peers.is_empty() {
            println!("No peers to sync with");
            return Ok(());
        }

        println!(
            "Forcing synchronization with {} peers...",
            cluster.peers.len()
        );

        // TODO: Implement force sync functionality
        println!("Note: Force sync functionality will be implemented in a future version");
        println!(
            "For now, sync happens automatically every {} minutes",
            cluster.sync_interval.num_minutes()
        );
    } else {
        println!("Not part of any cluster");
    }

    Ok(())
}
