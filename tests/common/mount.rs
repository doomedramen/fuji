//! TestMount helper for managing mount operations in tests

#![allow(dead_code)]

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::daemon::TestDaemon;
use super::filesystem::{read_file, write_file};

/// Helper for managing mount operations in tests
///
/// Provides RAII-style mount management with automatic unmount on drop.
pub struct TestMount {
    pub mount_id: String,
    mount_point: PathBuf,
    pub url: String,
    daemon: Arc<TestDaemon>,
    auto_unmount: bool,
}

impl TestMount {
    /// Mount a share via the daemon
    ///
    /// # Arguments
    /// * `daemon` - Daemon instance to use
    /// * `url` - Mount URL (e.g., "nfs://server/export")
    /// * `options` - Optional mount options
    ///
    /// # Example
    /// ```no_run
    /// # use anyhow::Result;
    /// # use std::sync::Arc;
    /// # use common::{TestDaemon, TestMount};
    /// # async fn example(daemon: Arc<TestDaemon>) -> Result<()> {
    /// let mount = TestMount::mount(daemon, "nfs://server/export", None).await?;
    /// // Mount automatically unmounted on drop
    /// # Ok(())
    /// # }
    /// ```
    pub async fn mount(
        daemon: Arc<TestDaemon>,
        url: &str,
        options: Option<Vec<String>>,
    ) -> Result<Self> {
        // Mount via daemon
        let mount_id = daemon
            .mount(url, options)
            .await
            .with_context(|| format!("Failed to mount {}", url))?;

        // Derive mount point from mount ID
        // Fuji uses /mnt/fuji/<mount-id> by default
        let mount_point = PathBuf::from("/mnt/fuji").join(&mount_id);

        // Wait a moment for mount to be established
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Verify mount point exists
        if !mount_point.exists() {
            anyhow::bail!(
                "Mount point {:?} does not exist after mounting {}",
                mount_point,
                url
            );
        }

        Ok(Self {
            mount_id,
            mount_point,
            url: url.to_string(),
            daemon,
            auto_unmount: true,
        })
    }

    /// Get the mount point path
    pub fn mount_point(&self) -> &Path {
        &self.mount_point
    }

    /// Get the mount ID
    pub fn mount_id(&self) -> &str {
        &self.mount_id
    }

    /// Check if mount is accessible
    ///
    /// Verifies mount point exists and is readable
    pub async fn verify_accessible(&self) -> Result<()> {
        if !self.mount_point.exists() {
            anyhow::bail!("Mount point {:?} does not exist", self.mount_point);
        }

        // Try to list directory
        let mut entries = tokio::fs::read_dir(&self.mount_point)
            .await
            .with_context(|| format!("Failed to read mount point {:?}", self.mount_point))?;

        // Read at least one entry to verify access
        match entries.next_entry().await {
            Ok(_) => Ok(()),
            Err(e) => anyhow::bail!("Failed to access mount point: {}", e),
        }
    }

    /// Write a test file to the mount
    ///
    /// Returns the full path to the created file
    pub async fn write_test_file(&self, name: &str, content: &[u8]) -> Result<PathBuf> {
        let file_path = self.mount_point.join(name);

        write_file(&file_path, content)
            .await
            .with_context(|| format!("Failed to write test file {:?}", file_path))?;

        Ok(file_path)
    }

    /// Read a test file from the mount
    pub async fn read_test_file(&self, path: &Path) -> Result<Vec<u8>> {
        read_file(path)
            .await
            .with_context(|| format!("Failed to read test file {:?}", path))
    }

    /// Disable automatic unmount on drop
    ///
    /// Useful when you want to keep the mount after the test
    pub fn keep_mounted(mut self) -> Self {
        self.auto_unmount = false;
        self
    }

    /// Disable automatic unmount on drop (by reference)
    ///
    /// Useful when you want to keep the mount after the test
    pub fn disable_auto_unmount(&mut self) {
        self.auto_unmount = false;
    }

    /// Manually unmount the share
    pub async fn unmount(mut self) -> Result<()> {
        self.auto_unmount = false; // Prevent double unmount in Drop
        self.do_unmount(false).await
    }

    /// Force unmount the share
    pub async fn force_unmount(mut self) -> Result<()> {
        self.auto_unmount = false;
        self.do_unmount(true).await
    }

    /// Internal unmount implementation
    async fn do_unmount(&self, force: bool) -> Result<()> {
        self.daemon
            .unmount(&self.mount_id, force)
            .await
            .with_context(|| format!("Failed to unmount {}", self.mount_id))
    }
}

impl Drop for TestMount {
    /// Cleanup: Unmount the share
    ///
    /// Uses best-effort cleanup - errors are logged but don't panic
    fn drop(&mut self) {
        if !self.auto_unmount {
            return;
        }

        eprintln!("Cleaning up mount: {}", self.mount_id);

        // Use blocking runtime to unmount
        let runtime = tokio::runtime::Runtime::new();
        if let Ok(rt) = runtime {
            let result = rt.block_on(self.do_unmount(true));

            match result {
                Ok(_) => {
                    eprintln!("✓ Mount {} unmounted", self.mount_id);
                }
                Err(e) => {
                    eprintln!("Warning: Failed to unmount {}: {}", self.mount_id, e);
                }
            }
        } else {
            eprintln!("Warning: Failed to create runtime for cleanup");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires daemon and Docker
    async fn test_mount_lifecycle() -> Result<()> {
        use super::super::docker::DockerEnvironment;

        // Start Docker NFS server
        let mut docker = DockerEnvironment::new()?;
        docker.start_services(&["nfs-server"]).await?;
        docker
            .wait_for_service("nfs-server", std::time::Duration::from_secs(30))
            .await?;

        // Start daemon
        let daemon = TestDaemon::start().await?;

        // Mount NFS share
        let mount = TestMount::mount(daemon.clone(), "nfs://nfs-server/exports/data", None).await?;

        // Verify mount is accessible
        mount.verify_accessible().await?;

        // Write and read test file
        let test_file = mount
            .write_test_file("test.txt", b"Hello from test")
            .await?;
        let content = mount.read_test_file(&test_file).await?;
        assert_eq!(content, b"Hello from test");

        // Cleanup happens via Drop
        Ok(())
    }
}
