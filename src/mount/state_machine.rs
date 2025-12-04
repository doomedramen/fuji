//! Mount state machine implementation
//!
//! Provides a state machine for managing mount lifecycle with proper state transitions
//! and notifications.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

/// Mount states in the lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MountState {
    /// Mount is not mounted
    Unmounted,
    /// Currently attempting to mount
    Mounting,
    /// Successfully mounted and active
    Mounted,
    /// Mount operation failed
    Failed,
    /// Currently attempting to unmount
    Unmounting,
}

impl std::fmt::Display for MountState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MountState::Unmounted => write!(f, "Unmounted"),
            MountState::Mounting => write!(f, "Mounting"),
            MountState::Mounted => write!(f, "Mounted"),
            MountState::Failed => write!(f, "Failed"),
            MountState::Unmounting => write!(f, "Unmounting"),
        }
    }
}

/// State transition event
#[derive(Debug, Clone)]
pub struct StateTransition {
    /// Mount ID
    pub mount_id: String,
    /// Previous state
    pub from_state: MountState,
    /// New state
    pub to_state: MountState,
    /// Timestamp of transition
    pub timestamp: DateTime<Utc>,
    /// Optional reason for transition
    pub reason: Option<String>,
    /// Optional error details
    pub error: Option<String>,
}

/// Mount state machine
pub struct MountStateMachine {
    /// Current state
    state: Arc<RwLock<MountState>>,
    /// Mount ID
    mount_id: String,
    /// State change notification sender
    notification_sender: broadcast::Sender<StateTransition>,
    /// State history
    history: Arc<RwLock<Vec<StateTransition>>>,
    /// Maximum history entries to keep
    max_history: usize,
}

impl MountStateMachine {
    /// Create a new mount state machine
    pub fn new(mount_id: String) -> (Self, broadcast::Receiver<StateTransition>) {
        let (notification_sender, notification_receiver) = broadcast::channel(100);

        let machine = Self {
            state: Arc::new(RwLock::new(MountState::Unmounted)),
            mount_id,
            notification_sender,
            history: Arc::new(RwLock::new(Vec::new())),
            max_history: 100,
        };

        (machine, notification_receiver)
    }

    /// Get current state
    pub async fn get_state(&self) -> MountState {
        *self.state.read().await
    }

    /// Check if state allows transition to new state
    fn can_transition(from: MountState, to: MountState) -> bool {
        use MountState::*;

        match (from, to) {
            // Same state - no transition needed
            (s, t) if s == t => true,

            // Valid transitions
            (Unmounted, Mounting) => true,
            (Mounting, Mounted) => true,
            (Mounting, Failed) => true,
            (Mounted, Unmounting) => true,
            (Mounted, Failed) => true,
            (Failed, Mounting) => true,  // Retry
            (Failed, Unmounted) => true, // Reset
            (Unmounting, Unmounted) => true,
            (Unmounting, Failed) => true,

            // Invalid transitions
            _ => false,
        }
    }

    /// Transition to a new state
    pub async fn transition(
        &self,
        new_state: MountState,
        reason: Option<String>,
        error: Option<String>,
    ) -> Result<()> {
        let current_state = *self.state.read().await;

        // Check if transition is valid
        if !Self::can_transition(current_state, new_state) {
            warn!(
                "Invalid state transition for mount {}: {} -> {}",
                self.mount_id, current_state, new_state
            );
            return Err(anyhow!(
                "Invalid state transition: {} -> {}",
                current_state,
                new_state
            ));
        }

        // Update state
        {
            let mut state = self.state.write().await;
            *state = new_state;
        }

        // Create transition event
        let transition = StateTransition {
            mount_id: self.mount_id.clone(),
            from_state: current_state,
            to_state: new_state,
            timestamp: Utc::now(),
            reason,
            error,
        };

        // Add to history
        {
            let mut history = self.history.write().await;
            history.push(transition.clone());

            // Trim history if too long
            if history.len() > self.max_history {
                history.remove(0);
            }
        }

        // Send notification
        if let Err(e) = self.notification_sender.send(transition.clone()) {
            error!("Failed to send state transition notification: {}", e);
        }

        info!(
            "Mount {} transitioned: {} -> {}",
            self.mount_id, current_state, new_state
        );

        debug!("State transition details: {:?}", transition);

        Ok(())
    }

    /// Transition with just a reason
    pub async fn transition_with_reason(&self, new_state: MountState, reason: &str) -> Result<()> {
        self.transition(new_state, Some(reason.to_string()), None)
            .await
    }

    /// Transition with an error
    pub async fn transition_with_error(&self, new_state: MountState, error: &str) -> Result<()> {
        self.transition(
            new_state,
            Some(format!("Error: {}", error)),
            Some(error.to_string()),
        )
        .await
    }

    /// Check if mount is in a terminal state
    pub async fn is_terminal(&self) -> bool {
        let state = *self.state.read().await;
        matches!(
            state,
            MountState::Mounted | MountState::Failed | MountState::Unmounted
        )
    }

    /// Check if mount is active (mounted or mounting)
    pub async fn is_active(&self) -> bool {
        let state = *self.state.read().await;
        matches!(state, MountState::Mounted | MountState::Mounting)
    }

    /// Get state history
    pub async fn get_history(&self) -> Vec<StateTransition> {
        self.history.read().await.clone()
    }

    /// Get last N state transitions
    pub async fn get_last_n(&self, n: usize) -> Vec<StateTransition> {
        let history = self.history.read().await;
        let len = history.len();
        if len <= n {
            history.clone()
        } else {
            history[len - n..].to_vec()
        }
    }

    /// Get time spent in current state
    pub async fn time_in_state(&self) -> chrono::Duration {
        let history = self.history.read().await;
        if let Some(last) = history.last() {
            Utc::now() - last.timestamp
        } else {
            // No history, assume we started in unmounted state at creation time
            chrono::Duration::zero()
        }
    }

    /// Reset to unmounted state
    pub async fn reset(&self) -> Result<()> {
        self.transition_with_reason(MountState::Unmounted, "Resetting mount state")
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_state_transitions() {
        let (machine, mut _receiver) = MountStateMachine::new("test-mount".to_string());

        // Initial state should be Unmounted
        assert_eq!(machine.get_state().await, MountState::Unmounted);

        // Valid transition: Unmounted -> Mounting
        machine
            .transition_with_reason(MountState::Mounting, "Starting mount")
            .await
            .unwrap();
        assert_eq!(machine.get_state().await, MountState::Mounting);

        // Valid transition: Mounting -> Mounted
        machine
            .transition_with_reason(MountState::Mounted, "Mount successful")
            .await
            .unwrap();
        assert_eq!(machine.get_state().await, MountState::Mounted);

        // Valid transition: Mounted -> Unmounting
        machine
            .transition_with_reason(MountState::Unmounting, "Starting unmount")
            .await
            .unwrap();
        assert_eq!(machine.get_state().await, MountState::Unmounting);

        // Valid transition: Unmounting -> Unmounted
        machine
            .transition_with_reason(MountState::Unmounted, "Unmount complete")
            .await
            .unwrap();
        assert_eq!(machine.get_state().await, MountState::Unmounted);
    }

    #[tokio::test]
    async fn test_invalid_transitions() {
        let (machine, mut _receiver) = MountStateMachine::new("test-mount".to_string());

        // Invalid transition: Unmounted -> Mounted (should go through Mounting)
        let result = machine
            .transition_with_reason(MountState::Mounted, "Direct mount")
            .await;
        assert!(result.is_err());
        assert_eq!(machine.get_state().await, MountState::Unmounted);

        // Invalid transition: Mounted -> Mounting (should go through Unmounting first)
        machine
            .transition_with_reason(MountState::Mounting, "Initial mount")
            .await
            .unwrap();
        machine
            .transition_with_reason(MountState::Mounted, "Mount complete")
            .await
            .unwrap();

        let result = machine
            .transition_with_reason(MountState::Mounting, "Remounting")
            .await;
        assert!(result.is_err());
        assert_eq!(machine.get_state().await, MountState::Mounted);
    }

    #[tokio::test]
    async fn test_state_notifications() {
        let (machine, mut receiver) = MountStateMachine::new("test-mount".to_string());

        // Make a transition
        machine
            .transition_with_reason(MountState::Mounting, "Test notification")
            .await
            .unwrap();

        // Should receive notification
        let transition = receiver.recv().await.unwrap();
        assert_eq!(transition.mount_id, "test-mount");
        assert_eq!(transition.from_state, MountState::Unmounted);
        assert_eq!(transition.to_state, MountState::Mounting);
        assert_eq!(transition.reason, Some("Test notification".to_string()));
    }

    #[tokio::test]
    async fn test_state_history() {
        let (machine, _receiver) = MountStateMachine::new("test-mount".to_string());

        // Make several transitions
        machine
            .transition_with_reason(MountState::Mounting, "1")
            .await
            .unwrap();
        sleep(Duration::from_millis(10)).await;

        machine
            .transition_with_reason(MountState::Mounted, "2")
            .await
            .unwrap();
        sleep(Duration::from_millis(10)).await;

        machine
            .transition_with_reason(MountState::Unmounting, "3")
            .await
            .unwrap();

        // Check history
        let history = machine.get_history().await;
        assert_eq!(history.len(), 3);

        // Check last 2 transitions
        let last_2 = machine.get_last_n(2).await;
        assert_eq!(last_2.len(), 2);
        assert_eq!(last_2[0].reason, Some("2".to_string()));
        assert_eq!(last_2[1].reason, Some("3".to_string()));
    }

    #[tokio::test]
    async fn test_time_in_state() {
        let (machine, _receiver) = MountStateMachine::new("test-mount".to_string());

        // Initial time should be zero (no history)
        assert_eq!(machine.time_in_state().await.num_milliseconds(), 0);

        machine
            .transition_with_reason(MountState::Mounting, "Start")
            .await
            .unwrap();

        // Wait a bit
        sleep(Duration::from_millis(50)).await;

        let time = machine.time_in_state().await;
        assert!(time.num_milliseconds() >= 40); // Allow some tolerance
    }
}
