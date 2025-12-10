//! Unit tests for progress reporting

use fuji::progress::{ProgressManager, ProgressPhase, ProgressReporter};

#[tokio::test]
async fn test_progress_reporter_creation() {
    let (reporter, _rx) = ProgressReporter::new(
        "mount".to_string(),
        "nfs://server/share".to_string(),
        Some(5000),
    );

    let progress = reporter.current_progress().await;
    assert_eq!(progress.operation_type, "mount");
    assert_eq!(progress.target, "nfs://server/share");
    assert!(matches!(progress.phase, ProgressPhase::Starting { .. }));
    assert_eq!(progress.phase.progress(), 0.0);
}

#[tokio::test]
async fn test_progress_updates() {
    let (reporter, rx) =
        ProgressReporter::new("mount".to_string(), "nfs://server/share".to_string(), None);

    // Update to validating
    reporter
        .update_progress("validating", "Checking URL...", 0.5)
        .await;
    let update = rx.borrow().clone();
    assert!(matches!(update.phase, ProgressPhase::Validating { .. }));
    assert!(update.phase.progress() >= 0.0 && update.phase.progress() <= 0.2);

    // Update to preparing
    reporter
        .update_progress("preparing", "Creating mount point...", 0.5)
        .await;
    let update = rx.borrow().clone();
    assert!(matches!(update.phase, ProgressPhase::Preparing { .. }));
    assert!(update.phase.progress() >= 0.2 && update.phase.progress() <= 0.4);

    // Update to executing
    reporter
        .update_progress("executing", "Running mount command...", 0.5)
        .await;
    let update = rx.borrow().clone();
    assert!(matches!(update.phase, ProgressPhase::Executing { .. }));
    assert!(update.phase.progress() >= 0.4 && update.phase.progress() <= 0.9);

    // Update to verifying
    reporter
        .update_progress("verifying", "Verifying mount...", 0.5)
        .await;
    let update = rx.borrow().clone();
    assert!(matches!(update.phase, ProgressPhase::Verifying { .. }));
    assert!(update.phase.progress() >= 0.9 && update.phase.progress() <= 0.95);
}

#[tokio::test]
async fn test_progress_completion() {
    let (reporter, _rx) =
        ProgressReporter::new("mount".to_string(), "nfs://server/share".to_string(), None);

    // Complete the operation
    reporter.complete("Mount successful").await;

    let progress = reporter.current_progress().await;
    assert!(matches!(progress.phase, ProgressPhase::Completed { .. }));
    assert!(progress.phase.is_success());
    assert!(progress.phase.is_finished());
    assert_eq!(progress.phase.progress(), 1.0);
}

#[tokio::test]
async fn test_progress_failure() {
    let (reporter, _rx) =
        ProgressReporter::new("mount".to_string(), "nfs://server/share".to_string(), None);

    // Fail the operation
    reporter.fail("Network error").await;

    let progress = reporter.current_progress().await;
    assert!(matches!(progress.phase, ProgressPhase::Failed { .. }));
    assert!(!progress.phase.is_success());
    assert!(progress.phase.is_finished());
    assert_eq!(progress.phase.progress(), 1.0);
}

#[tokio::test]
async fn test_progress_manager() {
    let manager = ProgressManager::new();

    // Register multiple operations
    let (reporter1, _rx1) = ProgressReporter::new(
        "mount".to_string(),
        "nfs://server1/share".to_string(),
        Some(5000),
    );
    let (reporter2, _rx2) = ProgressReporter::new(
        "mount".to_string(),
        "nfs://server2/share".to_string(),
        Some(8000),
    );

    manager
        .register_operation(reporter1.current_progress().await)
        .await;
    manager
        .register_operation(reporter2.current_progress().await)
        .await;

    // Check active operations
    let active = manager.get_active_operations().await;
    assert_eq!(active.len(), 2);

    // Complete one operation
    reporter1.complete("Mount successful").await;
    manager
        .update_operation(
            &reporter1.current_progress().await.operation_id,
            reporter1.current_progress().await,
        )
        .await;

    // Check active operations again
    let active = manager.get_active_operations().await;
    assert_eq!(active.len(), 1);

    // Get operations for a specific target
    let target_ops = manager
        .get_operations_for_target("nfs://server1/share")
        .await;
    assert_eq!(target_ops.len(), 1);
    assert!(target_ops[0].phase.is_finished());
}

#[tokio::test]
async fn test_progress_phase_properties() {
    let phase = ProgressPhase::Starting {
        message: "Starting...".to_string(),
    };
    assert_eq!(phase.progress(), 0.0);
    assert!(!phase.is_finished());
    assert_eq!(phase.message(), "Starting...");

    let phase = ProgressPhase::Completed {
        message: "Done".to_string(),
        duration_ms: 1000,
    };
    assert_eq!(phase.progress(), 1.0);
    assert!(phase.is_finished());
    assert!(phase.is_success());

    let phase = ProgressPhase::Failed {
        message: "Failed".to_string(),
        error: "Error".to_string(),
        duration_ms: 500,
    };
    assert_eq!(phase.progress(), 1.0);
    assert!(phase.is_finished());
    assert!(!phase.is_success());
}
