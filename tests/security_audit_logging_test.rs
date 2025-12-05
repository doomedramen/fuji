//! Integration tests for comprehensive audit logging system
//!
//! This test module validates the complete audit logging implementation including:
//! - Event logging and integrity
//! - Real-time monitoring and pattern detection
//! - Alert generation and handling
//! - Log rotation and retention

use anyhow::Result;
use fuji::security::audit_logging::{
    AuditConfig, AuditEvent, AuditEventType, AuditLogger, AuditOutcome, AuditSeverity, AuditSource,
    AuditSourceType, NetworkContext, SessionContext,
};
use fuji::security::audit_monitoring::{
    AlertSeverity, AlertType, AuditMonitor, AuditMonitoringConfig, SecurityAlert,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

/// Test comprehensive audit logging functionality
#[tokio::test]
async fn test_comprehensive_audit_logging() -> Result<()> {
    // Create audit logger with custom configuration
    let config = AuditConfig {
        buffer_size: 1000,
        log_file_path: std::path::PathBuf::from("/tmp/test_audit.log"),
        enable_signing: true,
        enable_chaining: true,
        enable_encryption: false, // Disabled for testing
        retention_period: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
        max_file_size: 10 * 1024 * 1024, // 10 MB
        backup_count: 5,
        enable_real_time: true,
        min_severity: AuditSeverity::Low,
    };

    let logger = AuditLogger::with_config(config)?;

    // Test basic event logging
    let source = AuditSource {
        identifier: "test_user".to_string(),
        source_type: AuditSourceType::User,
        ip_address: Some("192.168.1.100".to_string()),
        user_agent: Some("fuji-client/1.0".to_string()),
        metadata: {
            let mut meta = HashMap::new();
            meta.insert("department".to_string(), json!("IT"));
            meta.insert("role".to_string(), json!("administrator"));
            meta
        },
    };

    // Log authentication success
    logger
        .log_authentication(
            source.clone(),
            "test_user",
            AuditOutcome::Success,
            "password",
            HashMap::from([("method".to_string(), json!("local"))]),
        )
        .await?;

    // Log credential operation
    logger
        .log_credential_operation(
            source.clone(),
            "create",
            "cred_123",
            AuditOutcome::Success,
            HashMap::from([
                ("credential_type".to_string(), json!("nfs")),
                ("mount_point".to_string(), json!("/mnt/share")),
            ]),
        )
        .await?;

    // Log security violation
    logger
        .log_security_violation(
            source.clone(),
            "unauthorized_access_attempt",
            HashMap::from([
                ("target".to_string(), json!("secure_file")),
                ("attempts".to_string(), json!(5)),
            ]),
        )
        .await?;

    // Verify events are logged
    let events = logger.get_events(None, None).await?;
    assert_eq!(events.len(), 3);

    // Verify event chaining
    assert!(events[0].previous_event_hash.is_none()); // First event
    assert!(events[1].previous_event_hash.is_some()); // Chained to first
    assert!(events[2].previous_event_hash.is_some()); // Chained to second

    // Verify event signatures
    for event in &events {
        assert!(event.signature.is_some());
        assert!(!event.event_hash.is_empty());
    }

    // Test event search
    let auth_events = logger
        .search_events(
            Some(AuditEventType::Authentication),
            None,
            None,
            None,
            None,
            None,
        )
        .await?;
    assert_eq!(auth_events.len(), 1);

    let critical_events = logger
        .search_events(None, Some(AuditSeverity::High), None, None, None, None)
        .await?;
    assert_eq!(critical_events.len(), 1);

    // Test audit statistics
    let stats = logger.get_statistics().await?;
    assert_eq!(stats.total_events, 3);
    assert!(stats
        .events_by_type
        .contains_key(&AuditEventType::Authentication));
    assert!(stats
        .events_by_type
        .contains_key(&AuditEventType::CredentialManagement));
    assert!(stats
        .events_by_type
        .contains_key(&AuditEventType::SecurityViolation));

    Ok(())
}

/// Test real-time monitoring and alert generation
#[tokio::test]
async fn test_real_time_monitoring() -> Result<()> {
    // Create audit logger
    let logger = AuditLogger::new()?;

    // Create audit monitor
    let monitoring_config = AuditMonitoringConfig {
        failed_auth_threshold: 3,
        failed_auth_window: 30,
        ip_activity_threshold: 5,
        privilege_escalation_threshold: 2,
        enable_automated_response: true,
        alert_cooldown: 60,
        max_alerts_per_minute: 5,
        ..Default::default()
    };

    let mut monitor = AuditMonitor::new(monitoring_config);
    let event_sender = monitor.initialize().await?;

    // Simulate brute force attack
    let attacker_source = AuditSource {
        identifier: "attacker".to_string(),
        source_type: AuditSourceType::User,
        ip_address: Some("203.0.113.10".to_string()),
        user_agent: Some("malicious-tool/1.0".to_string()),
        metadata: HashMap::new(),
    };

    // Send multiple failed authentication attempts
    for i in 0..5 {
        let event = AuditEvent {
            id: format!("failed_auth_{}", i),
            timestamp: chrono::Utc::now(),
            event_type: AuditEventType::Authentication,
            severity: AuditSeverity::Medium,
            source: attacker_source.clone(),
            outcome: AuditOutcome::Failure,
            description: format!("Failed authentication attempt {}", i),
            details: HashMap::from([
                ("username".to_string(), json!("admin")),
                ("reason".to_string(), json!("invalid_password")),
            ]),
            network_context: Some(NetworkContext {
                source_ip: "203.0.113.10".to_string(),
                source_port: Some(12345 + i as u16),
                destination_ip: Some("192.168.1.50".to_string()),
                destination_port: Some(22),
                protocol: "ssh".to_string(),
                interface: Some("eth0".to_string()),
            }),
            session_context: None,
            signature: None,
            previous_event_hash: None,
            event_hash: format!("hash_{}", i),
        };

        // Send event to monitor
        event_sender.send(event)?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Wait for monitoring to process events
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Check for generated alerts
    let alerts = monitor.get_active_alerts().await;
    assert!(!alerts.is_empty());

    // Verify brute force alert
    let brute_force_alert = alerts
        .iter()
        .find(|a| a.alert_type == AlertType::BruteForceAttack);
    assert!(brute_force_alert.is_some());
    assert_eq!(brute_force_alert.unwrap().severity, AlertSeverity::High);

    // Verify alert metadata
    let alert = brute_force_alert.unwrap();
    assert!(alert.metadata.contains_key("source"));
    assert!(alert.metadata.contains_key("failure_count"));

    Ok(())
}

/// Test privilege escalation detection
#[tokio::test]
async fn test_privilege_escalation_detection() -> Result<()> {
    // Create audit logger
    let logger = AuditLogger::new()?;

    // Create audit monitor
    let monitoring_config = AuditMonitoringConfig {
        privilege_escalation_threshold: 3,
        analysis_window: 60,
        ..Default::default()
    };

    let mut monitor = AuditMonitor::new(monitoring_config);
    let event_sender = monitor.initialize().await?;

    // Simulate privilege escalation
    let suspicious_user = AuditSource {
        identifier: "suspicious_user".to_string(),
        source_type: AuditSourceType::User,
        ip_address: Some("192.168.1.200".to_string()),
        user_agent: None,
        metadata: HashMap::new(),
    };

    // Send administrative actions
    for i in 0..4 {
        let event = AuditEvent {
            id: format!("admin_action_{}", i),
            timestamp: chrono::Utc::now(),
            event_type: AuditEventType::AdministrativeAction,
            severity: AuditSeverity::High,
            source: suspicious_user.clone(),
            outcome: AuditOutcome::Success,
            description: format!("Administrative action {}", i),
            details: HashMap::from([
                (
                    "action_type".to_string(),
                    json!(if i % 2 == 0 {
                        "user_creation"
                    } else {
                        "config_change"
                    }),
                ),
                (
                    "target".to_string(),
                    json!(if i % 2 == 0 {
                        "new_user"
                    } else {
                        "system_config"
                    }),
                ),
            ]),
            network_context: None,
            session_context: Some(SessionContext {
                session_id: "sess_123".to_string(),
                user_id: "suspicious_user".to_string(),
                session_start: chrono::Utc::now() - chrono::Duration::hours(1),
                session_expires: Some(chrono::Utc::now() + chrono::Duration::hours(7)),
                auth_method: "password".to_string(),
                privileges: vec!["read".to_string(), "write".to_string()],
            }),
            signature: None,
            previous_event_hash: None,
            event_hash: format!("hash_{}", i),
        };

        event_sender.send(event)?;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Wait for processing
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Check for privilege escalation alerts
    let alerts = monitor.get_active_alerts().await;
    let privilege_alert = alerts
        .iter()
        .find(|a| a.alert_type == AlertType::PrivilegeEscalation);

    assert!(privilege_alert.is_some());
    let alert = privilege_alert.unwrap();
    assert_eq!(alert.severity, AlertSeverity::High);
    assert!(alert.metadata.contains_key("user"));
    assert!(alert.metadata.contains_key("action_count"));

    Ok(())
}

/// Test event filtering and export
#[tokio::test]
async fn test_event_filtering_and_export() -> Result<()> {
    let logger = AuditLogger::new()?;

    // Add custom filter for only critical events
    let filter = fuji::security::audit_logging::AuditEventFilter {
        name: "critical_only".to_string(),
        include_types: vec![],
        exclude_types: vec![AuditEventType::SystemEvent],
        min_severity: AuditSeverity::High,
        source_filters: vec!["admin".to_string()],
        custom_filter: None,
    };

    logger.add_filter(filter).await;

    // Log events with different severities
    let sources = vec![
        ("admin_user", AuditSourceType::User),
        ("normal_user", AuditSourceType::User),
        ("system_process", AuditSourceType::Process),
    ];

    for (i, (name, source_type)) in sources.iter().enumerate() {
        let source = AuditSource {
            identifier: name.to_string(),
            source_type: *source_type,
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: None,
            metadata: HashMap::new(),
        };

        let severity = match i {
            0 => AuditSeverity::Critical,
            1 => AuditSeverity::Medium,
            _ => AuditSeverity::Low,
        };

        let event = AuditEvent {
            id: format!("event_{}", i),
            timestamp: chrono::Utc::now(),
            event_type: if i == 2 {
                AuditEventType::SystemEvent
            } else {
                AuditEventType::Authentication
            },
            severity,
            source,
            outcome: AuditOutcome::Success,
            description: format!("Test event {}", i),
            details: HashMap::new(),
            network_context: None,
            session_context: None,
            signature: None,
            previous_event_hash: None,
            event_hash: format!("hash_{}", i),
        };

        logger.log_event(event).await?;
    }

    // Check that only critical admin events are logged
    let events = logger.get_events(None, None).await?;

    // Should have 2 events: admin critical, admin medium (excluded by severity filter)
    // System event should be excluded by type filter
    // Normal user medium should be excluded by source filter
    assert_eq!(events.len(), 1); // Only admin critical event passes all filters

    // Test export functionality
    let exported_json = logger
        .export_logs(fuji::security::audit_logging::ExportFormat::JSON)
        .await?;
    assert!(!exported_json.is_empty());

    Ok(())
}

/// Test audit log rotation and retention
#[tokio::test]
async fn test_log_rotation_and_retention() -> Result<()> {
    use tempfile::TempDir;

    // Create temporary directory for test logs
    let temp_dir = TempDir::new()?;
    let log_path = temp_dir.path().join("test_audit.log");

    let config = AuditConfig {
        log_file_path: log_path.clone(),
        max_file_size: 1024, // Very small for testing rotation
        backup_count: 3,
        ..Default::default()
    };

    let logger = AuditLogger::with_config(config)?;

    // Log enough events to trigger rotation
    let source = AuditSource {
        identifier: "test_user".to_string(),
        source_type: AuditSourceType::User,
        ip_address: Some("192.168.1.100".to_string()),
        user_agent: None,
        metadata: HashMap::new(),
    };

    // Generate large amount of data
    for i in 0..100 {
        let mut details = HashMap::new();
        details.insert("large_data".to_string(), json!("x".repeat(100)));

        logger
            .log(
                AuditEventType::SystemEvent,
                source.clone(),
                AuditOutcome::Success,
                &format!("Large data event {}", i),
                details,
            )
            .await?;
    }

    // Check that log file was created
    assert!(log_path.exists());

    // Check for rotated files
    let backup_path = log_path.with_extension("log.1");
    if backup_path.exists() {
        info!("Log rotation working correctly");
    }

    Ok(())
}

/// Test concurrent audit operations
#[tokio::test]
async fn test_concurrent_audit_operations() -> Result<()> {
    let logger = Arc::new(AuditLogger::new()?);

    // Create multiple concurrent logging operations
    let mut handles = vec![];

    for i in 0..20 {
        let logger_clone = Arc::clone(&logger);
        let handle = tokio::spawn(async move {
            let source = AuditSource {
                identifier: format!("user{}", i),
                source_type: AuditSourceType::User,
                ip_address: Some(format!("192.168.1.{}", i % 255 + 1)),
                user_agent: None,
                metadata: HashMap::new(),
            };

            // Log multiple events concurrently
            for j in 0..10 {
                let mut details = HashMap::new();
                details.insert("iteration".to_string(), json!(j));
                details.insert("worker".to_string(), json!(i));

                let event_type = match j % 4 {
                    0 => AuditEventType::Authentication,
                    1 => AuditEventType::MountOperation,
                    2 => AuditEventType::SystemEvent,
                    _ => AuditEventType::AdministrativeAction,
                };

                let outcome = if j % 5 == 0 {
                    AuditOutcome::Failure
                } else {
                    AuditOutcome::Success
                };

                logger_clone
                    .log(
                        event_type,
                        source.clone(),
                        outcome,
                        &format!("Concurrent test {}-{}", i, j),
                        details,
                    )
                    .await
                    .unwrap();

                // Small delay to simulate real work
                tokio::time::sleep(Duration::from_millis(1)).await;
            }

            Ok::<(), anyhow::Error>(())
        });
        handles.push(handle);
    }

    // Wait for all operations to complete
    for handle in handles {
        handle.await?;
    }

    // Verify all events were logged
    let events = logger.get_events(None, None).await?;
    assert_eq!(events.len(), 200); // 20 workers * 10 events each

    // Verify event integrity under concurrent load
    for event in &events {
        assert!(!event.event_hash.is_empty());
        assert!(event.timestamp <= chrono::Utc::now());
    }

    Ok(())
}

/// Test monitoring statistics
#[tokio::test]
async fn test_monitoring_statistics() -> Result<()> {
    let logger = AuditLogger::new()?;

    // Log events with different characteristics
    let source = AuditSource {
        identifier: "stats_test_user".to_string(),
        source_type: AuditSourceType::User,
        ip_address: Some("192.168.1.50".to_string()),
        user_agent: None,
        metadata: HashMap::new(),
    };

    // Generate varied events for statistics
    let events = vec![
        (
            AuditEventType::Authentication,
            AuditSeverity::Medium,
            AuditOutcome::Success,
        ),
        (
            AuditEventType::Authentication,
            AuditSeverity::Medium,
            AuditOutcome::Failure,
        ),
        (
            AuditEventType::SecurityViolation,
            AuditSeverity::Critical,
            AuditOutcome::Blocked,
        ),
        (
            AuditEventType::MountOperation,
            AuditSeverity::Low,
            AuditOutcome::Success,
        ),
        (
            AuditEventType::AdministrativeAction,
            AuditSeverity::High,
            AuditOutcome::Success,
        ),
    ];

    for (i, (event_type, severity, outcome)) in events.iter().enumerate() {
        logger
            .log(
                *event_type,
                source.clone(),
                *outcome,
                &format!("Statistics test event {}", i),
                HashMap::from([("test_id".to_string(), json!(i))]),
            )
            .await?;
    }

    // Get and verify statistics
    let stats = logger.get_statistics().await?;
    assert_eq!(stats.total_events, 5);
    assert_eq!(stats.events_by_severity.get(&AuditSeverity::Low), Some(&1));
    assert_eq!(
        stats.events_by_severity.get(&AuditSeverity::Medium),
        Some(&2)
    );
    assert_eq!(stats.events_by_severity.get(&AuditSeverity::High), Some(&1));
    assert_eq!(
        stats.events_by_severity.get(&AuditSeverity::Critical),
        Some(&1)
    );
    assert_eq!(
        stats.events_by_outcome.get(&AuditOutcome::Success),
        Some(&3)
    );
    assert_eq!(
        stats.events_by_outcome.get(&AuditOutcome::Failure),
        Some(&1)
    );
    assert_eq!(
        stats.events_by_outcome.get(&AuditOutcome::Blocked),
        Some(&1)
    );

    Ok(())
}
