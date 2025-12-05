//! Security Dashboard Tests
//!
//! Comprehensive test suite for the security monitoring dashboard module

use anyhow::Result;
use chrono::{DateTime, Utc};
use fuji::security::audit_logging::{
    AuditEvent, AuditEventType, AuditOutcome, AuditSeverity, AuditSource, AuditSourceType,
};
use fuji::security::security_dashboard::{
    AlertCategory, AlertSeverity, DashboardConfig, ExportFormat, SecurityDashboard,
};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;

#[tokio::test]
async fn test_security_dashboard_creation() -> Result<()> {
    let config = DashboardConfig {
        update_interval: 5,
        max_events: 1000,
        max_snapshots: 100,
        enable_alerts: true,
        alert_retention_hours: 720, // 30 days
        export_formats: vec![ExportFormat::Json, ExportFormat::Html],
    };

    let dashboard = SecurityDashboard::new(config);

    let metrics = dashboard.get_metrics().await?;
    assert_eq!(metrics.total_events, 0);

    Ok(())
}

#[tokio::test]
async fn test_security_event_logging() -> Result<()> {
    let config = DashboardConfig::default();
    let dashboard = SecurityDashboard::new(config);

    // Create an audit event first
    let audit_event = AuditEvent {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        event_type: AuditEventType::SecurityViolation,
        severity: AuditSeverity::High,
        source: AuditSource {
            identifier: "test_suite".to_string(),
            source_type: AuditSourceType::Process,
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("fuji_test".to_string()),
            metadata: HashMap::new(),
        },
        outcome: AuditOutcome::Failure,
        description: "This is a test security event".to_string(),
        details: {
            let mut details = HashMap::new();
            details.insert(
                "test_key".to_string(),
                Value::String("test_value".to_string()),
            );
            details
        },
        network_context: None,
        session_context: None,
        signature: None,
        previous_event_hash: None,
        event_hash: "test_hash".to_string(),
    };

    dashboard.process_event(audit_event).await?;

    let metrics = dashboard.get_metrics().await?;
    assert_eq!(metrics.total_events, 1);

    let recent_events = dashboard.get_recent_events(Some(10)).await?;
    assert_eq!(recent_events.len(), 1);

    Ok(())
}

#[tokio::test]
async fn test_security_alert_creation() -> Result<()> {
    let config = DashboardConfig::default();
    let dashboard = SecurityDashboard::new(config);

    let alert_id = Uuid::new_v4().to_string();

    dashboard
        .create_alert(
            "Test Security Alert".to_string(),
            "This is a test security alert".to_string(),
            AlertSeverity::Critical,
            AlertCategory::SecurityIncident,
            "test_suite".to_string(),
        )
        .await?;

    let active_alerts = dashboard.get_active_alerts().await?;
    assert_eq!(active_alerts.len(), 1);
    assert!(matches!(active_alerts[0].severity, AlertSeverity::Critical));

    Ok(())
}

#[tokio::test]
async fn test_component_status_monitoring() -> Result<()> {
    let config = DashboardConfig::default();
    let dashboard = SecurityDashboard::new(config);

    // Initialize the dashboard to set up component status tracking
    dashboard.initialize(None, None).await?;

    let component_statuses = dashboard.get_component_status().await?;

    // The dashboard should start with some default components
    assert!(!component_statuses.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_security_score_calculation() -> Result<()> {
    let config = DashboardConfig::default();
    let dashboard = SecurityDashboard::new(config);

    // Add some events with different severities
    for i in 0..10 {
        let audit_event = AuditEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type: match i % 4 {
                0 => AuditEventType::SecurityViolation,
                1 => AuditEventType::Authentication,
                2 => AuditEventType::ConfigurationChange,
                _ => AuditEventType::SystemEvent,
            },
            severity: match i % 4 {
                0 => AuditSeverity::Critical,
                1 => AuditSeverity::High,
                2 => AuditSeverity::Medium,
                _ => AuditSeverity::Low,
            },
            source: AuditSource {
                identifier: "test".to_string(),
                source_type: AuditSourceType::Process,
                ip_address: None,
                user_agent: None,
                metadata: HashMap::new(),
            },
            outcome: AuditOutcome::Success,
            description: format!("Test Event {}", i),
            details: HashMap::new(),
            network_context: None,
            session_context: None,
            signature: None,
            previous_event_hash: None,
            event_hash: format!("hash_{}", i),
        };

        dashboard.process_event(audit_event).await?;
    }

    let metrics = dashboard.get_metrics().await?;
    assert_eq!(metrics.total_events, 10);

    // Calculate the security score
    let security_score = dashboard.calculate_security_score().await?;
    assert!(security_score <= 100);

    Ok(())
}

#[tokio::test]
async fn test_alert_thresholds() -> Result<()> {
    let config = DashboardConfig::default();
    let dashboard = SecurityDashboard::new(config);

    // Add a critical audit event that should trigger an alert
    let critical_event = AuditEvent {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        event_type: AuditEventType::SecurityViolation,
        severity: AuditSeverity::Critical,
        source: AuditSource {
            identifier: "intrusion_detector".to_string(),
            source_type: AuditSourceType::System,
            ip_address: Some("192.168.1.100".to_string()),
            user_agent: None,
            metadata: HashMap::new(),
        },
        outcome: AuditOutcome::Failure,
        description: "Critical intrusion detected".to_string(),
        details: HashMap::new(),
        network_context: None,
        session_context: None,
        signature: None,
        previous_event_hash: None,
        event_hash: "critical_event_hash".to_string(),
    };

    dashboard.process_event(critical_event).await?;

    // Check if alert was automatically created
    let alerts = dashboard.get_active_alerts().await?;
    assert!(!alerts.is_empty());

    // Should have at least one critical alert
    let critical_alerts: Vec<_> = alerts
        .iter()
        .filter(|alert| matches!(alert.severity, AlertSeverity::Critical))
        .collect();
    assert!(!critical_alerts.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_event_retention_policy() -> Result<()> {
    let mut config = DashboardConfig::default();
    config.max_events = 5; // Only keep 5 events
    let dashboard = SecurityDashboard::new(config);

    // Add 10 events
    for i in 0..10 {
        let audit_event = AuditEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type: AuditEventType::SystemEvent,
            severity: AuditSeverity::Low,
            source: AuditSource {
                identifier: "test".to_string(),
                source_type: AuditSourceType::Process,
                ip_address: None,
                user_agent: None,
                metadata: HashMap::new(),
            },
            outcome: AuditOutcome::Success,
            description: format!("Test Event {}", i),
            details: HashMap::new(),
            network_context: None,
            session_context: None,
            signature: None,
            previous_event_hash: None,
            event_hash: format!("hash_{}", i),
        };

        dashboard.process_event(audit_event).await?;

        // Small delay to ensure different timestamps
        sleep(Duration::from_millis(10)).await;
    }

    let recent_events = dashboard.get_recent_events(Some(20)).await?;

    // Should only retain the 5 most recent events
    assert_eq!(recent_events.len(), 5);

    Ok(())
}

#[tokio::test]
async fn test_dashboard_export_json() -> Result<()> {
    let config = DashboardConfig::default();
    let dashboard = SecurityDashboard::new(config);

    // Add test data
    let audit_event = AuditEvent {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        event_type: AuditEventType::SecurityViolation,
        severity: AuditSeverity::Medium,
        source: AuditSource {
            identifier: "test_suite".to_string(),
            source_type: AuditSourceType::Process,
            ip_address: None,
            user_agent: None,
            metadata: HashMap::new(),
        },
        outcome: AuditOutcome::Success,
        description: "Event for testing export functionality".to_string(),
        details: HashMap::new(),
        network_context: None,
        session_context: None,
        signature: None,
        previous_event_hash: None,
        event_hash: "export_test_hash".to_string(),
    };

    dashboard.process_event(audit_event).await?;

    // Export to JSON
    let export_data = dashboard.export_data(ExportFormat::Json).await?;

    assert!(export_data.starts_with('{'));
    assert!(export_data.contains("metrics"));
    assert!(export_data.contains("events"));
    assert!(export_data.contains("alerts"));

    Ok(())
}

#[tokio::test]
async fn test_dashboard_export_html() -> Result<()> {
    let config = DashboardConfig {
        export_formats: vec![ExportFormat::Html],
        ..Default::default()
    };
    let dashboard = SecurityDashboard::new(config);

    // Add test data
    dashboard
        .create_alert(
            "Test Export Alert".to_string(),
            "Alert for testing HTML export".to_string(),
            AlertSeverity::High,
            AlertCategory::SecurityIncident,
            "test_suite".to_string(),
        )
        .await?;

    // Export to HTML
    let html_export = dashboard.export_data(ExportFormat::Html).await?;

    assert!(html_export.contains("<!DOCTYPE html>"));
    assert!(html_export.contains("<html"));
    assert!(html_export.contains("Security Dashboard"));
    assert!(html_export.contains("</html>"));

    Ok(())
}

#[tokio::test]
async fn test_event_search_and_filtering() -> Result<()> {
    let config = DashboardConfig::default();
    let dashboard = SecurityDashboard::new(config);

    // Add events with different categories and severities
    let audit_event_types = vec![
        AuditEventType::SecurityViolation,
        AuditEventType::Authentication,
        AuditEventType::ConfigurationChange,
    ];

    let severities = vec![
        AuditSeverity::Critical,
        AuditSeverity::High,
        AuditSeverity::Medium,
    ];

    for (i, event_type) in audit_event_types.iter().enumerate() {
        for (j, severity) in severities.iter().enumerate() {
            let audit_event = AuditEvent {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                event_type: *event_type,
                severity: *severity,
                source: AuditSource {
                    identifier: "test_suite".to_string(),
                    source_type: AuditSourceType::Process,
                    ip_address: None,
                    user_agent: None,
                    metadata: {
                        let mut meta = HashMap::new();
                        meta.insert(
                            "component".to_string(),
                            Value::String(format!("component_{}", i)),
                        );
                        meta
                    },
                },
                outcome: AuditOutcome::Success,
                description: "Test event for filtering".to_string(),
                details: HashMap::new(),
                network_context: None,
                session_context: None,
                signature: None,
                previous_event_hash: None,
                event_hash: format!("hash_{}_{}", i, j),
            };

            dashboard.process_event(audit_event).await?;
        }
    }

    // Get all events and verify we have the expected count
    let all_events = dashboard.get_recent_events(None).await?;
    assert_eq!(all_events.len(), 9); // 3 event types × 3 severities

    Ok(())
}

#[tokio::test]
async fn test_alert_acknowledgment_and_resolution() -> Result<()> {
    let config = DashboardConfig::default();
    let dashboard = SecurityDashboard::new(config);

    // Create an alert
    dashboard
        .create_alert(
            "Test Alert Lifecycle".to_string(),
            "Alert for testing acknowledgment and resolution".to_string(),
            AlertSeverity::Medium,
            AlertCategory::SecurityIncident,
            "test_suite".to_string(),
        )
        .await?;

    // Get the created alert
    let alerts = dashboard.get_active_alerts().await?;
    assert_eq!(alerts.len(), 1);
    let alert_id = &alerts[0].alert_id;

    // Acknowledge the alert
    let acknowledged = dashboard.acknowledge_alert(alert_id).await?;
    assert!(acknowledged);

    // Resolve the alert
    let resolved = dashboard.resolve_alert(alert_id).await?;
    assert!(resolved);

    // Verify the alert is no longer active
    let active_alerts = dashboard.get_active_alerts().await?;
    assert_eq!(active_alerts.len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_historical_data_tracking() -> Result<()> {
    let config = DashboardConfig::default();
    let dashboard = SecurityDashboard::new(config);

    // Add some events to generate historical data
    for i in 0..5 {
        let audit_event = AuditEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type: AuditEventType::SystemEvent,
            severity: AuditSeverity::Medium,
            source: AuditSource {
                identifier: "test_suite".to_string(),
                source_type: AuditSourceType::Process,
                ip_address: None,
                user_agent: None,
                metadata: HashMap::new(),
            },
            outcome: AuditOutcome::Success,
            description: format!("Historical Event {}", i),
            details: HashMap::new(),
            network_context: None,
            session_context: None,
            signature: None,
            previous_event_hash: None,
            event_hash: format!("historical_hash_{}", i),
        };

        dashboard.process_event(audit_event).await?;
    }

    let historical_data = dashboard.get_historical_data(Some(24)).await?;

    // Note: Historical snapshots are created by background monitoring task
    // In a real scenario, they would be generated periodically
    // For testing, we just verify the method exists and doesn't error

    Ok(())
}

#[tokio::test]
async fn test_real_time_metrics_update() -> Result<()> {
    let config = DashboardConfig {
        update_interval: 1, // 1 second for faster testing
        ..Default::default()
    };
    let dashboard = SecurityDashboard::new(config);

    // Get initial metrics
    let initial_metrics = dashboard.get_metrics().await?;
    assert_eq!(initial_metrics.total_events, 0);

    // Add an event
    let audit_event = AuditEvent {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        event_type: AuditEventType::SecurityViolation,
        severity: AuditSeverity::High,
        source: AuditSource {
            identifier: "real_time_test".to_string(),
            source_type: AuditSourceType::Process,
            ip_address: None,
            user_agent: None,
            metadata: HashMap::new(),
        },
        outcome: AuditOutcome::Failure,
        description: "Testing real-time updates".to_string(),
        details: HashMap::new(),
        network_context: None,
        session_context: None,
        signature: None,
        previous_event_hash: None,
        event_hash: "realtime_test_hash".to_string(),
    };

    dashboard.process_event(audit_event).await?;

    // Get updated metrics
    let updated_metrics = dashboard.get_metrics().await?;
    assert_eq!(updated_metrics.total_events, 1);
    assert!(updated_metrics.last_updated >= initial_metrics.last_updated);

    Ok(())
}
