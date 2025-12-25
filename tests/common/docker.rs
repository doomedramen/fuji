//! Docker Compose environment management for integration tests

#![allow(dead_code)]

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::sleep;

/// Manages Docker Compose services for integration testing
///
/// This struct provides RAII-style management of Docker Compose services,
/// ensuring proper cleanup even if tests panic.
pub struct DockerEnvironment {
    compose_file: PathBuf,
    project_name: String,
    started_services: Vec<String>,
}

impl DockerEnvironment {
    /// Create a new Docker environment
    ///
    /// Uses the default docker-compose.yml in the project root
    pub fn new() -> Result<Self> {
        let compose_file = std::env::current_dir()
            .context("Failed to get current directory")?
            .join("docker-compose.yml");

        if !compose_file.exists() {
            anyhow::bail!("docker-compose.yml not found at {:?}", compose_file);
        }

        Ok(Self {
            compose_file,
            project_name: "fuji-test".to_string(),
            started_services: Vec::new(),
        })
    }

    /// Start specified Docker Compose services
    ///
    /// # Arguments
    /// * `services` - List of service names to start (e.g., ["nfs-server", "smb-server"])
    ///
    /// # Example
    /// ```no_run
    /// # use anyhow::Result;
    /// # async fn example() -> Result<()> {
    /// let mut docker = DockerEnvironment::new()?;
    /// docker.start_services(&["nfs-server", "smb-server"]).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn start_services(&mut self, services: &[&str]) -> Result<()> {
        let mut args = vec![
            "-f",
            self.compose_file.to_str().unwrap(),
            "-p",
            &self.project_name,
            "up",
            "-d",
        ];

        args.extend(services.iter().copied());

        let output = Command::new("docker")
            .arg("compose")
            .args(&args)
            .output()
            .await
            .context("Failed to execute docker compose up")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to start Docker services: {}", stderr);
        }

        // Track started services for cleanup
        self.started_services
            .extend(services.iter().map(|s| s.to_string()));

        Ok(())
    }

    /// Wait for a service to become healthy
    ///
    /// Polls the service health check until it passes or timeout is reached
    ///
    /// # Arguments
    /// * `service` - Service name to wait for
    /// * `timeout_duration` - Maximum time to wait
    pub async fn wait_for_service(&self, service: &str, timeout_duration: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_secs(2);

        loop {
            if self.is_service_healthy(service).await? {
                eprintln!(
                    "✓ Service '{}' is healthy ({}s)",
                    service,
                    start.elapsed().as_secs()
                );
                return Ok(());
            }

            if start.elapsed() >= timeout_duration {
                // Get logs on timeout for debugging
                if let Ok(logs) = self.get_logs(service).await {
                    eprintln!("Service '{}' logs:\n{}", service, logs);
                }
                anyhow::bail!(
                    "Service '{}' did not become healthy within {:?}",
                    service,
                    timeout_duration
                );
            }

            sleep(poll_interval).await;
        }
    }

    /// Check if a service is healthy
    ///
    /// Returns true if the service health check passes
    pub async fn is_service_healthy(&self, service: &str) -> Result<bool> {
        let output = Command::new("docker")
            .arg("compose")
            .args([
                "-f",
                self.compose_file.to_str().unwrap(),
                "-p",
                &self.project_name,
                "ps",
                "--format",
                "json",
                service,
            ])
            .output()
            .await
            .context("Failed to check service status")?;

        if !output.status.success() {
            return Ok(false);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Check if service is running and healthy
        // docker compose ps --format json returns JSON with State and Health fields
        Ok(stdout.contains("\"State\":\"running\"")
            && (stdout.contains("\"Health\":\"healthy\"") || !stdout.contains("\"Health\"")))
    }

    /// Stop a specific service
    pub async fn stop_service(&self, service: &str) -> Result<()> {
        let output = Command::new("docker")
            .arg("compose")
            .args([
                "-f",
                self.compose_file.to_str().unwrap(),
                "-p",
                &self.project_name,
                "stop",
                service,
            ])
            .output()
            .await
            .context("Failed to stop service")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to stop service '{}': {}", service, stderr);
        }

        Ok(())
    }

    /// Get logs from a service
    ///
    /// Useful for debugging test failures
    pub async fn get_logs(&self, service: &str) -> Result<String> {
        let output = Command::new("docker")
            .arg("compose")
            .args([
                "-f",
                self.compose_file.to_str().unwrap(),
                "-p",
                &self.project_name,
                "logs",
                "--tail=100",
                service,
            ])
            .output()
            .await
            .context("Failed to get service logs")?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Execute a command inside a running service container
    ///
    /// # Arguments
    /// * `service` - Service name
    /// * `cmd` - Command and arguments to execute
    pub async fn exec(&self, service: &str, cmd: &[&str]) -> Result<std::process::Output> {
        let mut args = vec![
            "compose",
            "-f",
            self.compose_file.to_str().unwrap(),
            "-p",
            &self.project_name,
            "exec",
            "-T", // Disable TTY allocation
            service,
        ];

        args.extend(cmd.iter().copied());

        let output = Command::new("docker")
            .args(&args)
            .output()
            .await
            .context("Failed to execute command in container")?;

        Ok(output)
    }
}

impl Drop for DockerEnvironment {
    /// Cleanup: Stop and remove containers
    ///
    /// Uses best-effort cleanup - errors are logged but don't panic
    fn drop(&mut self) {
        if self.started_services.is_empty() {
            return;
        }

        eprintln!("Cleaning up Docker services...");

        // Use blocking version for Drop
        let result = std::process::Command::new("docker")
            .arg("compose")
            .args([
                "-f",
                self.compose_file.to_str().unwrap(),
                "-p",
                &self.project_name,
                "down",
                "-v", // Remove volumes
            ])
            .output();

        match result {
            Ok(output) if output.status.success() => {
                eprintln!("✓ Docker services cleaned up");
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!("Warning: Docker cleanup failed: {}", stderr);
            }
            Err(e) => {
                eprintln!("Warning: Failed to run docker compose down: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_docker_environment_lifecycle() -> Result<()> {
        let mut docker = DockerEnvironment::new()?;

        // Start NFS server
        docker.start_services(&["nfs-server"]).await?;

        // Wait for it to be healthy
        docker
            .wait_for_service("nfs-server", Duration::from_secs(30))
            .await?;

        // Check it's healthy
        assert!(docker.is_service_healthy("nfs-server").await?);

        // Get logs
        let logs = docker.get_logs("nfs-server").await?;
        assert!(!logs.is_empty());

        // Cleanup happens via Drop
        Ok(())
    }
}
