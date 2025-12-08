// Allow dead code - persistence layer for future use
#![allow(dead_code)]

//! Mount state persistence using SQLite
//!
//! Provides persistent storage for mount states that survives daemon restarts.

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, Row, params};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use crate::mount::{MountConfig, MountStatus, MountType};

/// Mount state persistence manager
pub struct PersistenceManager {
    /// Database connection
    connection: Arc<RwLock<Connection>>,
    /// Database file path
    #[allow(dead_code)]
    db_path: PathBuf,
}

/// Persisted mount state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedMountState {
    /// Mount ID
    pub id: String,
    /// Mount URL
    pub url: String,
    /// Mount point path
    pub mount_point: String,
    /// Mount type as JSON
    pub mount_type: String,
    /// Current status
    pub status: String,
    /// Whether enabled
    pub enabled: bool,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated timestamp
    pub updated_at: DateTime<Utc>,
    /// Last connected timestamp
    pub last_connected: Option<DateTime<Utc>>,
    /// Reconnection attempts
    pub reconnect_attempts: u32,
    /// Additional metadata as JSON
    pub metadata: String,
    /// Health check summary (optional)
    pub health_check_summary: Option<String>,
}

#[allow(dead_code)]
impl PersistenceManager {
    /// Create a new persistence manager
    pub fn new() -> Result<Self> {
        // Determine database path
        let db_path = Self::get_database_path()?;

        // Open/create database
        let connection = Connection::open(&db_path).context("Failed to open database")?;

        let db_path_clone = db_path.clone();
        let manager = Self {
            #[allow(clippy::arc_with_non_send_sync)]
            #[allow(clippy::arc_with_non_send_sync)]
            connection: Arc::new(RwLock::new(connection)),
            db_path,
        };

        info!(
            "Persistence manager created with database at {:?}",
            db_path_clone
        );
        Ok(manager)
    }

    /// Initialize the persistence manager (async version)
    pub async fn initialize(&self) -> Result<()> {
        self.initialize_schema().await
    }

    /// Get the database file path
    fn get_database_path() -> Result<PathBuf> {
        let mut path = dirs::runtime_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("fuji");

        // Create directory if it doesn't exist
        std::fs::create_dir_all(&path).context("Failed to create runtime directory")?;

        path.push("mounts.db");
        Ok(path)
    }

    /// Initialize database schema
    async fn initialize_schema(&self) -> Result<()> {
        let conn = self.connection.write().await;

        // Create mounts table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS mounts (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                mount_point TEXT NOT NULL,
                mount_type TEXT NOT NULL,
                status TEXT NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_connected TEXT,
                reconnect_attempts INTEGER NOT NULL DEFAULT 0,
                metadata TEXT
            )
            "#,
            [],
        )?;

        // Create health_checks table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS health_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mount_id TEXT NOT NULL,
                check_type TEXT NOT NULL,
                status TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                response_time_ms INTEGER,
                message TEXT,
                metadata TEXT,
                FOREIGN KEY (mount_id) REFERENCES mounts (id) ON DELETE CASCADE
            )
            "#,
            [],
        )?;

        // Create indices
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_health_checks_mount_id ON health_checks (mount_id)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_health_checks_timestamp ON health_checks (timestamp)",
            [],
        )?;

        // Run migrations if needed
        self.run_migrations(&conn)?;

        Ok(())
    }

    /// Run database migrations
    fn run_migrations(&self, conn: &Connection) -> Result<()> {
        // Check if migrations table exists
        let exists: bool = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'",
            )
            .map_err(|e| anyhow!("Failed to check migrations table: {}", e))?
            .exists([])
            .unwrap_or(false);

        if !exists {
            // Create migrations table
            conn.execute(
                "CREATE TABLE schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                )",
                [],
            )?;
        }

        // Get current migration version
        let current_version: i32 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        // Apply migrations if needed
        if current_version < 1 {
            info!("Applying migration 1");
            // Migration 1: Add health_check_summary to mounts table
            // Check if column already exists to avoid duplicate column error
            let column_exists: bool = conn
                .prepare("SELECT health_check_summary FROM mounts LIMIT 1")
                .is_ok();

            if !column_exists {
                conn.execute(
                    "ALTER TABLE mounts ADD COLUMN health_check_summary TEXT",
                    [],
                )?;
            }

            conn.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (1, ?)",
                params![Utc::now().to_rfc3339()],
            )?;
        }

        Ok(())
    }

    /// Save a mount state to the database
    pub async fn save_mount_state(&self, mount_config: &MountConfig) -> Result<()> {
        let conn = self.connection.read().await;

        let mount_type_json = serde_json::to_string(&mount_config.mount_type)
            .context("Failed to serialize mount type")?;

        let metadata_json = serde_json::to_string(&mount_config.metadata)
            .context("Failed to serialize metadata")?;

        conn.execute(
            r#"
            INSERT OR REPLACE INTO mounts (
                id, url, mount_point, mount_type, status, enabled,
                created_at, updated_at, last_connected, reconnect_attempts, metadata, health_check_summary
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            params![
                mount_config.id,
                mount_config.url,
                mount_config.mount_point.to_string_lossy(),
                mount_type_json,
                mount_config.status.to_string(),
                mount_config.enabled,
                mount_config.created_at.to_rfc3339(),
                mount_config.updated_at.to_rfc3339(),
                mount_config.last_connected.map(|dt| dt.to_rfc3339()),
                mount_config.reconnect_attempts,
                metadata_json,
                "" // Default empty health_check_summary
            ],
        )?;

        debug!("Saved mount state for {}", mount_config.id);
        Ok(())
    }

    /// Load a mount state from the database
    pub async fn load_mount_state(&self, mount_id: &str) -> Result<Option<PersistedMountState>> {
        let conn = self.connection.read().await;

        let result = conn.query_row(
            "SELECT * FROM mounts WHERE id = ?",
            params![mount_id],
            Self::row_to_persisted_state,
        );

        match result {
            Ok(state) => Ok(Some(state)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(anyhow!("Failed to load mount state: {}", e)),
        }
    }

    /// Load all mount states from the database
    pub async fn load_all_mount_states(&self) -> Result<Vec<PersistedMountState>> {
        let conn = self.connection.read().await;

        let mut stmt = conn.prepare("SELECT * FROM mounts ORDER BY created_at")?;

        let rows = stmt.query_map([], Self::row_to_persisted_state)?;

        let mut states = Vec::new();
        for row in rows {
            states.push(row?);
        }

        debug!("Loaded {} mount states from database", states.len());
        Ok(states)
    }

    /// Delete a mount state from the database
    pub async fn delete_mount_state(&self, mount_id: &str) -> Result<()> {
        let conn = self.connection.read().await;

        conn.execute("DELETE FROM mounts WHERE id = ?", params![mount_id])?;

        info!("Deleted mount state for {}", mount_id);
        Ok(())
    }

    /// Save a health check result
    pub async fn save_health_check(
        &self,
        mount_id: &str,
        check_type: &str,
        status: &str,
        response_time_ms: u64,
        message: Option<&str>,
        metadata: &std::collections::HashMap<String, String>,
    ) -> Result<()> {
        let conn = self.connection.read().await;

        let metadata_json = serde_json::to_string(metadata)?;

        conn.execute(
            r#"
            INSERT INTO health_checks (
                mount_id, check_type, status, timestamp, response_time_ms, message, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
            params![
                mount_id,
                check_type,
                status,
                Utc::now().to_rfc3339(),
                response_time_ms as i64,
                message,
                metadata_json
            ],
        )?;

        debug!(
            "Saved health check result for {} check_type={}",
            mount_id, check_type
        );
        Ok(())
    }

    /// Get recent health check results for a mount
    pub async fn get_health_checks(
        &self,
        mount_id: &str,
        limit: Option<i64>,
    ) -> Result<Vec<HealthCheckRecord>> {
        let conn = self.connection.read().await;

        let limit_clause = if let Some(limit) = limit {
            format!(" LIMIT {}", limit)
        } else {
            String::new()
        };

        let mut stmt = conn.prepare(&format!(
            r#"
            SELECT * FROM health_checks
            WHERE mount_id = ?
            ORDER BY timestamp DESC{}
            "#,
            limit_clause
        ))?;

        let rows = stmt.query_map(params![mount_id], Self::row_to_health_check)?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }

        Ok(records)
    }

    /// Convert a PersistedMountState to MountConfig
    pub fn state_to_config(&self, state: &PersistedMountState) -> Option<MountConfig> {
        // Deserialize mount type
        let mount_type: MountType = match serde_json::from_str(&state.mount_type) {
            Ok(mt) => mt,
            Err(e) => {
                error!("Failed to deserialize mount type for {}: {}", state.id, e);
                return None;
            }
        };

        // Deserialize metadata
        let metadata: std::collections::HashMap<String, String> =
            match serde_json::from_str(&state.metadata) {
                Ok(m) => m,
                Err(e) => {
                    error!("Failed to deserialize metadata for {}: {}", state.id, e);
                    std::collections::HashMap::new()
                }
            };

        // Parse mount point
        let mount_point = PathBuf::from(&state.mount_point);

        // Parse status
        let status = match state.status.as_str() {
            "Active" => MountStatus::Active,
            "Reconnecting" => MountStatus::Reconnecting,
            "Failed" => MountStatus::Failed,
            "Disabled" => MountStatus::Disabled,
            _ => MountStatus::Disabled,
        };

        // Use timestamps directly
        let created_at = state.created_at;
        let updated_at = state.updated_at;

        let last_connected = state.last_connected;

        Some(MountConfig {
            id: state.id.clone(),
            url: state.url.clone(),
            mount_point,
            mount_type,
            enabled: state.enabled,
            status,
            created_at,
            updated_at,
            last_connected,
            reconnect_attempts: state.reconnect_attempts,
            metadata,
        })
    }

    /// Convert a database row to PersistedMountState
    fn row_to_persisted_state(row: &Row) -> rusqlite::Result<PersistedMountState> {
        Ok(PersistedMountState {
            id: row.get(0)?,
            url: row.get(1)?,
            mount_point: row.get(2)?,
            mount_type: row.get(3)?,
            status: row.get(4)?,
            enabled: row.get(5)?,
            created_at: row.get(6)?,
            updated_at: row.get(7)?,
            last_connected: row.get(8)?,
            reconnect_attempts: row.get(9)?,
            metadata: row.get(10)?,
            health_check_summary: row.get(11)?,
        })
    }

    /// Convert a database row to HealthCheckRecord
    fn row_to_health_check(row: &Row) -> rusqlite::Result<HealthCheckRecord> {
        Ok(HealthCheckRecord {
            id: row.get(0)?,
            mount_id: row.get(1)?,
            check_type: row.get(2)?,
            status: row.get(3)?,
            timestamp: row.get(4)?,
            response_time_ms: row.get(5)?,
            message: row.get(6)?,
            metadata: row.get(7)?,
        })
    }

    /// Cleanup old health check records
    pub async fn cleanup_old_health_checks(&self, days: i64) -> Result<usize> {
        let conn = self.connection.read().await;

        let cutoff = (Utc::now() - chrono::Duration::days(days)).to_rfc3339();

        let result = conn.execute(
            "DELETE FROM health_checks WHERE timestamp < ?",
            params![cutoff],
        )?;

        if result > 0 {
            info!("Cleaned up {} old health check records", result);
        }

        Ok(result)
    }
}

/// Health check record
#[derive(Debug, Clone)]
pub struct HealthCheckRecord {
    /// Record ID
    pub id: i64,
    /// Mount ID
    pub mount_id: String,
    /// Check type
    pub check_type: String,
    /// Status
    pub status: String,
    /// Timestamp
    pub timestamp: String,
    /// Response time in milliseconds
    pub response_time_ms: i64,
    /// Optional message
    pub message: Option<String>,
    /// Additional metadata
    pub metadata: String,
}

impl Default for PersistenceManager {
    fn default() -> Self {
        Self::new().expect("Failed to create persistence manager")
    }
}

// SAFETY: PersistenceManager is safe to send across threads because:
// 1. Arc<RwLock<Connection>> provides thread-safe access to the SQLite connection
// 2. All methods use proper async locking
// 3. PathBuf is Send + Sync
unsafe impl Send for PersistenceManager {}
unsafe impl Sync for PersistenceManager {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_persistence_creation() {
        let manager = PersistenceManager::new();
        assert!(manager.is_ok());

        // Test initialization
        let manager = manager.unwrap();
        assert!(manager.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_mount_state_persistence() {
        let manager = PersistenceManager::new().unwrap();
        manager.initialize().await.unwrap();

        // Create test mount config
        let config = MountConfig::new(
            "nfs://example.com/share".to_string(),
            MountType::Nfs {
                host: "example.com".to_string(),
                share: "/share".to_string(),
                options: vec![],
            },
            "/mnt/test".into(),
        );

        // Save state
        assert!(manager.save_mount_state(&config).await.is_ok());

        // Load state
        let loaded = manager.load_mount_state(&config.id).await.unwrap();
        assert!(loaded.is_some());

        let loaded_state = loaded.unwrap();
        assert_eq!(loaded_state.id, config.id);
        assert_eq!(loaded_state.url, config.url);
        assert_eq!(loaded_state.enabled, config.enabled);

        // Delete state
        assert!(manager.delete_mount_state(&config.id).await.is_ok());

        // Verify deletion
        let deleted = manager.load_mount_state(&config.id).await.unwrap();
        assert!(deleted.is_none());
    }
}
