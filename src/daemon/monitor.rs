//! Mount monitoring and health tracking

use crate::mount::MountState;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Mount health monitor
pub struct MountMonitor {
    /// Health states for each mount
    health_states: Arc<RwLock<HashMap<String, MountState>>>,
}

impl Default for MountMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl MountMonitor {
    /// Create a new mount monitor
    pub fn new() -> Self {
        Self {
            health_states: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Update health state for a mount
    pub async fn update_health(&self, mount_id: &str, state: MountState) {
        let mut states = self.health_states.write().await;
        states.insert(mount_id.to_string(), state);
    }

    /// Get health score for a mount (0-100)
    pub async fn get_health_score(&self, mount_id: &str) -> Option<u8> {
        let states = self.health_states.read().await;
        states.get(mount_id).map(|s| s.health_score)
    }

    /// Get all health states
    pub async fn get_all_health(&self) -> HashMap<String, MountState> {
        let states = self.health_states.read().await;
        states.clone()
    }
}
