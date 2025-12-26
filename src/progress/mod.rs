//! Progress reporting for long-running operations

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{RwLock, watch};
use tracing::debug;

/// Progress phase for operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProgressPhase {
    /// Operation is starting
    Starting {
        message: String,
    },
    /// Performing validation
    Validating {
        message: String,
        progress: f32, // 0.0 to 0.2
    },
    /// Preparing mount point
    Preparing {
        message: String,
        progress: f32, // 0.2 to 0.4
    },
    /// Executing mount command
    Executing {
        message: String,
        progress: f32, // 0.4 to 0.9
    },
    /// Verifying mount
    Verifying {
        message: String,
        progress: f32, // 0.9 to 0.95
    },
    /// Operation completed successfully
    Completed {
        message: String,
        duration_ms: u64,
    },
    /// Operation failed
    Failed {
        message: String,
        error: String,
        duration_ms: u64,
    },
}

impl ProgressPhase {
    /// Get the progress percentage (0.0 to 1.0)
    #[allow(dead_code)]
    #[must_use]
    pub const fn progress(&self) -> f32 {
        match self {
            Self::Starting {
                ..
            } => 0.0,
            Self::Validating {
                progress,
                ..
            } => *progress,
            Self::Preparing {
                progress,
                ..
            } => *progress,
            Self::Executing {
                progress,
                ..
            } => *progress,
            Self::Verifying {
                progress,
                ..
            } => *progress,
            Self::Completed {
                ..
            } => 1.0,
            Self::Failed {
                ..
            } => 1.0,
        }
    }

    /// Get the message for this phase
    #[allow(dead_code)]
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Starting {
                message,
            } => message,
            Self::Validating {
                message,
                ..
            } => message,
            Self::Preparing {
                message,
                ..
            } => message,
            Self::Executing {
                message,
                ..
            } => message,
            Self::Verifying {
                message,
                ..
            } => message,
            Self::Completed {
                message,
                ..
            } => message,
            Self::Failed {
                message,
                ..
            } => message,
        }
    }

    /// Check if the operation is finished
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        matches!(self, Self::Completed { .. } | Self::Failed { .. })
    }

    /// Check if the operation succeeded
    #[allow(dead_code)]
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Completed { .. })
    }
}

/// Progress information for an operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressInfo {
    /// Operation ID
    pub operation_id: String,
    /// Operation type (mount, unmount, etc.)
    pub operation_type: String,
    /// Target (URL or mount point)
    pub target: String,
    /// Current phase
    pub phase: ProgressPhase,
    /// When the operation started
    pub started_at: DateTime<Utc>,
    /// Optional estimated duration in milliseconds
    pub estimated_duration_ms: Option<u64>,
}

/// Progress reporter for tracking operation progress
pub struct ProgressReporter {
    /// Unique operation ID
    operation_id: String,
    /// Operation type
    operation_type: String,
    /// Target (URL or mount point)
    target: String,
    /// Progress state
    state: Arc<RwLock<ProgressState>>,
    /// Channel sender for progress updates
    tx: watch::Sender<ProgressInfo>,
    /// When the operation started
    started_at: DateTime<Utc>,
}

/// Internal progress state
struct ProgressState {
    /// Current phase
    phase: ProgressPhase,
}

impl ProgressReporter {
    /// Create a new progress reporter
    #[must_use]
    pub fn new(
        operation_type: String,
        target: String,
        estimated_duration_ms: Option<u64>,
    ) -> (Self, watch::Receiver<ProgressInfo>) {
        let operation_id = uuid::Uuid::new_v4().to_string();
        let started_at = Utc::now();

        let (tx, rx) = watch::channel(ProgressInfo {
            operation_id: operation_id.clone(),
            operation_type: operation_type.clone(),
            target: target.clone(),
            phase: ProgressPhase::Starting {
                message: format!("Starting {operation_type}..."),
            },
            started_at,
            estimated_duration_ms,
        });

        let state = Arc::new(RwLock::new(ProgressState {
            phase: ProgressPhase::Starting {
                message: format!("Starting {operation_type}..."),
            },
        }));

        let reporter = Self {
            operation_id,
            operation_type,
            target,
            state,
            tx,
            started_at,
        };

        (reporter, rx)
    }

    /// Update the progress phase
    pub async fn update_phase(&self, phase: ProgressPhase) {
        let mut state = self.state.write().await;
        state.phase = phase.clone();

        let progress_info = ProgressInfo {
            operation_id: self.operation_id.clone(),
            operation_type: self.operation_type.clone(),
            target: self.target.clone(),
            phase,
            started_at: self.started_at,
            estimated_duration_ms: None,
        };

        // Send update to all listeners
        if let Err(e) = self.tx.send(progress_info) {
            debug!("Failed to send progress update: {}", e);
        }
    }

    /// Update progress with a custom message (validates progress value)
    pub async fn update_progress(&self, phase_name: &str, message: &str, progress: f32) {
        let phase = match phase_name {
            "validating" => ProgressPhase::Validating {
                message: message.to_string(),
                progress: progress.clamp(0.0, 0.2),
            },
            "preparing" => ProgressPhase::Preparing {
                message: message.to_string(),
                progress: progress.clamp(0.0, 1.0).mul_add(0.2, 0.2),
            },
            "executing" => ProgressPhase::Executing {
                message: message.to_string(),
                progress: progress.clamp(0.0, 1.0).mul_add(0.5, 0.4),
            },
            "verifying" => ProgressPhase::Verifying {
                message: message.to_string(),
                progress: progress.clamp(0.0, 1.0).mul_add(0.05, 0.9),
            },
            _ => return,
        };

        self.update_phase(phase).await;
    }

    /// Mark the operation as completed successfully
    pub async fn complete(&self, message: &str) {
        let duration =
            Utc::now().timestamp_millis() as u64 - self.started_at.timestamp_millis() as u64;
        self.update_phase(ProgressPhase::Completed {
            message: message.to_string(),
            duration_ms: duration,
        })
        .await;
    }

    /// Mark the operation as failed
    pub async fn fail(&self, error: &str) {
        let duration =
            Utc::now().timestamp_millis() as u64 - self.started_at.timestamp_millis() as u64;
        self.update_phase(ProgressPhase::Failed {
            message: "Operation failed".to_string(),
            error: error.to_string(),
            duration_ms: duration,
        })
        .await;
    }

    /// Get the current progress info
    pub async fn current_progress(&self) -> ProgressInfo {
        let state = self.state.read().await;
        ProgressInfo {
            operation_id: self.operation_id.clone(),
            operation_type: self.operation_type.clone(),
            target: self.target.clone(),
            phase: state.phase.clone(),
            started_at: self.started_at,
            estimated_duration_ms: None,
        }
    }
}

/// Manager for tracking multiple operations
pub struct ProgressManager {
    /// Active operations
    operations: Arc<RwLock<std::collections::HashMap<String, ProgressInfo>>>,
}

impl Default for ProgressManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressManager {
    /// Create a new progress manager
    #[must_use]
    pub fn new() -> Self {
        Self {
            operations: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Register a new operation
    pub async fn register_operation(&self, info: ProgressInfo) {
        let mut ops = self.operations.write().await;
        ops.insert(info.operation_id.clone(), info);
    }

    /// Update an operation's progress
    #[allow(dead_code)]
    pub async fn update_operation(&self, operation_id: &str, info: ProgressInfo) {
        let mut ops = self.operations.write().await;
        ops.insert(operation_id.to_string(), info);
    }

    /// Get all active operations
    #[allow(dead_code)]
    pub async fn get_active_operations(&self) -> Vec<ProgressInfo> {
        let ops = self.operations.read().await;
        ops.values()
            .filter(|info| !info.phase.is_finished())
            .cloned()
            .collect()
    }

    /// Get operations for a specific target
    #[allow(dead_code)]
    pub async fn get_operations_for_target(&self, target: &str) -> Vec<ProgressInfo> {
        let ops = self.operations.read().await;
        ops.values()
            .filter(|info| info.target == target)
            .cloned()
            .collect()
    }

    /// Clean up finished operations older than the specified duration
    pub async fn cleanup_finished(&self, max_age: chrono::Duration) {
        let mut ops = self.operations.write().await;
        let now = Utc::now();
        ops.retain(|_, info| !info.phase.is_finished() || (now - info.started_at) < max_age);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_progress_reporter() {
        let (reporter, rx) = ProgressReporter::new(
            "mount".to_string(),
            "nfs://server/share".to_string(),
            Some(5000),
        );

        // Check initial state
        let initial = reporter.current_progress().await;
        assert!(matches!(initial.phase, ProgressPhase::Starting { .. }));
        assert_eq!(initial.phase.progress(), 0.0);

        // Update progress
        reporter
            .update_progress("validating", "Checking URL...", 0.5)
            .await;
        let update = rx.borrow().clone();
        assert!(matches!(update.phase, ProgressPhase::Validating { .. }));
        assert!(update.phase.progress() > 0.0);

        // Complete the operation
        reporter.complete("Mounted successfully").await;
        let completed = rx.borrow().clone();
        assert!(matches!(completed.phase, ProgressPhase::Completed { .. }));
        assert!(completed.phase.is_success());
    }

    #[tokio::test]
    async fn test_progress_manager() {
        let manager = ProgressManager::new();

        // Register an operation
        let info = ProgressInfo {
            operation_id: "op-1".to_string(),
            operation_type: "mount".to_string(),
            target: "nfs://server/share".to_string(),
            phase: ProgressPhase::Starting {
                message: "Starting mount...".to_string(),
            },
            started_at: Utc::now(),
            estimated_duration_ms: Some(5000),
        };

        manager.register_operation(info.clone()).await;

        // Get active operations
        let active = manager.get_active_operations().await;
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].operation_id, "op-1");

        // Get operations for target
        let target_ops = manager
            .get_operations_for_target("nfs://server/share")
            .await;
        assert_eq!(target_ops.len(), 1);
    }

    #[test]
    fn test_progress_phase_progress() {
        assert_eq!(
            ProgressPhase::Starting {
                message: "Test".to_string()
            }
            .progress(),
            0.0
        );
        assert_eq!(
            ProgressPhase::Validating {
                message: "Test".to_string(),
                progress: 0.1
            }
            .progress(),
            0.1
        );
        assert_eq!(
            ProgressPhase::Preparing {
                message: "Test".to_string(),
                progress: 0.3
            }
            .progress(),
            0.3
        );
        assert_eq!(
            ProgressPhase::Executing {
                message: "Test".to_string(),
                progress: 0.5
            }
            .progress(),
            0.5
        );
        assert_eq!(
            ProgressPhase::Verifying {
                message: "Test".to_string(),
                progress: 0.95
            }
            .progress(),
            0.95
        );
        assert_eq!(
            ProgressPhase::Completed {
                message: "Test".to_string(),
                duration_ms: 1000
            }
            .progress(),
            1.0
        );
        assert_eq!(
            ProgressPhase::Failed {
                message: "Test".to_string(),
                error: "Error".to_string(),
                duration_ms: 1000
            }
            .progress(),
            1.0
        );
    }
}
