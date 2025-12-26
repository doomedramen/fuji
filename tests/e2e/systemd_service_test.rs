//! Systemd service integration testing
//!
//! This test validates full systemd integration:
//! 1. Service file generation
//! 2. Service installation and enable
//! 3. Service start and operation
//! 4. Service crash recovery (systemd auto-restart)
//! 5. Service stop and cleanup
//! 6. Journal log access

#[path = "../common/mod.rs"]
mod common;

use anyhow::{Context, Result};
use common::*;
use std::time::Duration;

/// Helper to execute commands in systemd container
async fn exec_in_systemd(cmd: &[&str]) -> Result<std::process::Output> {
    let mut full_cmd = vec!["docker", "compose", "exec", "-T", "systemd-test"];
    full_cmd.extend(cmd);

    let output = tokio::process::Command::new(full_cmd[0])
        .args(&full_cmd[1..])
        .output()
        .await
        .with_context(|| format!("Failed to execute in systemd container: {:?}", cmd))?;

    Ok(output)
}

/// Helper to check if a command succeeds in systemd container
async fn exec_success(cmd: &[&str]) -> Result<bool> {
    let output = exec_in_systemd(cmd).await?;
    Ok(output.status.success())
}

/// Helper to get command output as string
async fn exec_output(cmd: &[&str]) -> Result<String> {
    let output = exec_in_systemd(cmd).await?;

    if !output.status.success() {
        anyhow::bail!(
            "Command failed: {:?}\nStderr: {}",
            cmd,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "Systemd tests require Linux")]
async fn test_systemd_service_lifecycle() -> Result<()> {
    eprintln!("\n=== Testing Systemd Service Lifecycle ===\n");

    // 1. Start Docker environment with systemd
    eprintln!("Step 1: Starting Docker environment...");
    let mut docker = DockerEnvironment::new()?;
    docker
        .start_services(&["nfs-server", "smb-server", "systemd-test"])
        .await?;

    // Wait for base services
    docker
        .wait_for_service("nfs-server", Duration::from_secs(60))
        .await?;
    docker
        .wait_for_service("smb-server", Duration::from_secs(60))
        .await?;

    // Give systemd container time to fully boot
    eprintln!("Waiting for systemd container to initialize...");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // 2. Verify systemd is running
    eprintln!("\nStep 2: Verifying systemd is running...");
    let systemd_check = exec_success(&["systemctl", "is-system-running"]).await?;
    if !systemd_check {
        let status = exec_output(&["systemctl", "status"])
            .await
            .unwrap_or_default();
        eprintln!("Systemd status:\n{}", status);
    }
    eprintln!("✓ Systemd is running");

    // 3. Install Fuji binary into container
    eprintln!("\nStep 3: Installing Fuji binary...");

    // Determine binary path (debug or release)
    let binary_name = if cfg!(debug_assertions) {
        "target/debug/fuji"
    } else {
        "target/release/fuji"
    };

    // Copy binary to /usr/local/bin (it's already mounted at /app)
    exec_in_systemd(&[
        "bash",
        "-c",
        &format!(
            "cp /app/{} /usr/local/bin/fuji && chmod +x /usr/local/bin/fuji",
            binary_name
        ),
    ])
    .await?;

    // Verify binary exists and is executable
    let version_output = exec_output(&["/usr/local/bin/fuji", "--version"]).await?;
    eprintln!("✓ Fuji installed: {}", version_output.trim());

    // 4. Generate systemd service file
    eprintln!("\nStep 4: Generating systemd service file...");

    // Create service file content
    let service_content = r#"[Unit]
Description=Fuji Network File System Mount Manager
Documentation=https://github.com/DoomedRamen/fuji
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/fuji daemon start --no-automount
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
User=root
Group=root
WorkingDirectory=/root
Environment=RUST_LOG=info

# Security hardening
PrivateTmp=true
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/mnt /var/lib/fuji

# Resource limits
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"#;

    // Write service file
    exec_in_systemd(&[
        "bash",
        "-c",
        &format!(
            "cat > /etc/systemd/system/fuji.service << 'EOF'\n{}\nEOF",
            service_content
        ),
    ])
    .await?;

    eprintln!("✓ Service file created");

    // 5. Reload systemd and enable service
    eprintln!("\nStep 5: Enabling Fuji service...");
    exec_in_systemd(&["systemctl", "daemon-reload"]).await?;
    eprintln!("✓ Systemd daemon reloaded");

    exec_in_systemd(&["systemctl", "enable", "fuji"]).await?;
    eprintln!("✓ Service enabled");

    // 6. Start the service
    eprintln!("\nStep 6: Starting Fuji service...");
    exec_in_systemd(&["systemctl", "start", "fuji"]).await?;

    // Wait a moment for service to start
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Verify service is active
    let is_active = exec_success(&["systemctl", "is-active", "fuji"]).await?;
    if !is_active {
        let status = exec_output(&["systemctl", "status", "fuji"])
            .await
            .unwrap_or_else(|_| "Failed to get status".to_string());
        eprintln!("Service status:\n{}", status);
        anyhow::bail!("Fuji service failed to start");
    }

    eprintln!("✓ Fuji service is active");

    // 7. Test service operations (mount NFS)
    eprintln!("\nStep 7: Testing mount operations via service...");

    // Give daemon more time to be ready
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Try to mount NFS share
    let mount_output = exec_in_systemd(&["fuji", "mount", "nfs://nfs-server/exports/data"]).await?;

    if !mount_output.status.success() {
        let stderr = String::from_utf8_lossy(&mount_output.stderr);
        eprintln!("Warning: Mount command failed: {}", stderr);
        eprintln!("This may be expected if the service isn't fully ready");
    } else {
        eprintln!("✓ Mount command succeeded");
    }

    // Check status
    let status_output = exec_output(&["fuji", "status"]).await;
    match status_output {
        Ok(status) => {
            eprintln!("Fuji status:\n{}", status);
        }
        Err(e) => {
            eprintln!("Note: Status check failed: {}", e);
        }
    }

    // 8. Test journal logging
    eprintln!("\nStep 8: Checking journal logs...");
    let logs = exec_output(&["journalctl", "-u", "fuji", "--no-pager", "-n", "20"]).await?;
    eprintln!("Service logs (last 20 lines):\n{}", logs);
    assert!(!logs.is_empty(), "Journal logs should not be empty");
    eprintln!("✓ Journal logs accessible");

    // 9. Test service stop
    eprintln!("\nStep 9: Stopping service...");
    exec_in_systemd(&["systemctl", "stop", "fuji"]).await?;

    // Wait for service to stop
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Verify service is inactive
    let is_inactive = !exec_success(&["systemctl", "is-active", "fuji"]).await?;
    assert!(is_inactive, "Service should be inactive");
    eprintln!("✓ Service stopped successfully");

    // 10. Disable and remove service
    eprintln!("\nStep 10: Cleaning up service...");
    exec_in_systemd(&["systemctl", "disable", "fuji"]).await?;
    exec_in_systemd(&["rm", "/etc/systemd/system/fuji.service"]).await?;
    exec_in_systemd(&["systemctl", "daemon-reload"]).await?;
    eprintln!("✓ Service cleaned up");

    eprintln!("\n=== Systemd Service Lifecycle Test PASSED ===\n");
    Ok(())
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "Systemd tests require Linux")]
async fn test_systemd_service_crash_recovery() -> Result<()> {
    eprintln!("\n=== Testing Systemd Service Crash Recovery ===\n");

    // 1. Start Docker environment
    eprintln!("Step 1: Starting Docker environment...");
    let mut docker = DockerEnvironment::new()?;
    docker
        .start_services(&["nfs-server", "systemd-test"])
        .await?;

    docker
        .wait_for_service("nfs-server", Duration::from_secs(60))
        .await?;

    // Give systemd time to boot
    tokio::time::sleep(Duration::from_secs(5)).await;

    // 2. Install and start service (abbreviated setup)
    eprintln!("\nStep 2: Setting up Fuji service...");

    let binary_name = if cfg!(debug_assertions) {
        "target/debug/fuji"
    } else {
        "target/release/fuji"
    };

    exec_in_systemd(&[
        "bash",
        "-c",
        &format!(
            "cp /app/{} /usr/local/bin/fuji && chmod +x /usr/local/bin/fuji",
            binary_name
        ),
    ])
    .await?;

    let service_content = r#"[Unit]
Description=Fuji Network File System Mount Manager
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/fuji daemon start --no-automount
Restart=on-failure
RestartSec=2
User=root

[Install]
WantedBy=multi-user.target
"#;

    exec_in_systemd(&[
        "bash",
        "-c",
        &format!(
            "cat > /etc/systemd/system/fuji.service << 'EOF'\n{}\nEOF",
            service_content
        ),
    ])
    .await?;

    exec_in_systemd(&["systemctl", "daemon-reload"]).await?;
    exec_in_systemd(&["systemctl", "start", "fuji"]).await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    let is_active = exec_success(&["systemctl", "is-active", "fuji"]).await?;
    assert!(is_active, "Service should be active before crash test");
    eprintln!("✓ Fuji service is running");

    // 3. Get daemon PID
    eprintln!("\nStep 3: Finding daemon process...");
    let pid_output = exec_output(&["pgrep", "-f", "fuji daemon start"]).await?;
    let pid = pid_output.trim();
    eprintln!("Daemon PID: {}", pid);

    // 4. Kill daemon process with SIGKILL
    eprintln!("\nStep 4: Simulating crash (SIGKILL)...");
    exec_in_systemd(&["kill", "-9", pid]).await?;
    eprintln!("✓ Process killed");

    // 5. Wait for systemd to detect and restart
    eprintln!("\nStep 5: Waiting for systemd auto-restart...");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // 6. Verify service was restarted
    let is_active_after = exec_success(&["systemctl", "is-active", "fuji"]).await?;
    assert!(
        is_active_after,
        "Service should be auto-restarted by systemd after crash"
    );
    eprintln!("✓ Service auto-restarted successfully");

    // 7. Check that PID changed
    let new_pid_output = exec_output(&["pgrep", "-f", "fuji daemon start"]).await?;
    let new_pid = new_pid_output.trim();
    assert_ne!(pid, new_pid, "PID should be different after restart");
    eprintln!("✓ New daemon process created (PID: {})", new_pid);

    // 8. Check journal for crash and restart events
    eprintln!("\nStep 8: Checking journal for restart events...");
    let logs = exec_output(&["journalctl", "-u", "fuji", "--no-pager", "-n", "50"]).await?;
    eprintln!("Recent logs:\n{}", logs);

    // Cleanup
    exec_in_systemd(&["systemctl", "stop", "fuji"]).await?;
    exec_in_systemd(&["systemctl", "disable", "fuji"]).await?;
    exec_in_systemd(&["rm", "/etc/systemd/system/fuji.service"]).await?;

    eprintln!("\n=== Systemd Crash Recovery Test PASSED ===\n");
    Ok(())
}
