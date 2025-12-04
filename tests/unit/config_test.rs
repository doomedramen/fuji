//! Unit tests for configuration management

use fuji::config::Config;
use fuji::platform::Platform;
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_config_creation() {
    let platform = fuji::platform::get_platform();
    let config = Config::new(platform);

    // Check default values
    assert_eq!(config.version, "1.0");
    assert!(config.daemon.poll_interval >= 1);
    assert!(config.daemon.health_check_interval >= 1);
}

#[test]
fn test_config_validation() {
    let platform = fuji::platform::get_platform();
    let mut config = Config::new(platform);

    // Valid config should pass validation
    assert!(config.validate().is_ok());

    // Test invalid poll interval
    config.daemon.poll_interval = 0;
    assert!(config.validate().is_err());
}

#[test]
fn test_config_serialization() {
    let platform = fuji::platform::get_platform();
    let config = Config::new(platform);

    // Test serialization
    let serialized = serde_yaml::to_string(&config).unwrap();
    let deserialized: Config = serde_yaml::from_str(&serialized).unwrap();

    assert_eq!(config.version, deserialized.version);
    assert_eq!(
        config.daemon.poll_interval,
        deserialized.daemon.poll_interval
    );
}

#[test]
fn test_config_get_set() {
    let platform = fuji::platform::get_platform();
    let mut config = Config::new(platform);

    // Test getting non-existent key
    assert!(config.get("non_existent").is_none());

    // Test setting and getting
    config.set("test_key", "test_value").unwrap();
    assert_eq!(config.get("test_key"), Some("test_value".to_string()));

    // Test nested key
    config.set("daemon.poll_interval", "30s").unwrap();
    assert_eq!(config.get("daemon.poll_interval"), Some("30s".to_string()));
}

#[test]
fn test_config_list() {
    let platform = fuji::platform::get_platform();
    let mut config = Config::new(platform);

    // Add some test values
    config.set("test.key1", "value1").unwrap();
    config.set("test.key2", "value2").unwrap();
    config.set("other_key", "value3").unwrap();

    // List all keys
    let keys = config.list();
    assert!(keys.len() >= 3);
    assert!(keys.contains(&"test.key1".to_string()));
    assert!(keys.contains(&"test.key2".to_string()));
    assert!(keys.contains(&"other_key".to_string()));
}

#[test]
fn test_config_file_operations() {
    let platform = fuji::platform::get_platform();
    let config = Config::new(platform);
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test_config.toml");

    // Save config
    config.save_to_file(&config_path).unwrap();

    // Load config
    let loaded_config = Config::load_from_file(&config_path, platform).unwrap();

    assert_eq!(config.version, loaded_config.version);
    assert_eq!(
        config.daemon.poll_interval,
        loaded_config.daemon.poll_interval
    );
}

#[test]
fn test_config_merge() {
    let platform = fuji::platform::get_platform();
    let mut config1 = Config::new(platform.clone());
    let mut config2 = Config::new(platform);

    // Set different values
    config1.set("key1", "value1").unwrap();
    config1.set("key2", "value2").unwrap();
    config2.set("key2", "new_value2").unwrap();
    config2.set("key3", "value3").unwrap();

    // Merge config2 into config1
    config1.merge(&config2).unwrap();

    assert_eq!(config1.get("key1"), Some("value1".to_string()));
    assert_eq!(config1.get("key2"), Some("new_value2".to_string()));
    assert_eq!(config1.get("key3"), Some("value3".to_string()));
}

#[test]
fn test_config_defaults() {
    let platform = fuji::platform::get_platform();
    let config = Config::new(platform);

    // Check default daemon settings
    assert_eq!(config.daemon.poll_interval, 5);
    assert_eq!(config.daemon.health_check_interval, 30);
    assert_eq!(config.daemon.max_retries, 3);
    assert!(config.daemon.auto_mount);

    // Check default reconnection settings
    assert_eq!(config.reconnection.max_retries, 5);
    assert_eq!(config.reconnection.initial_delay, 1000);
    assert_eq!(config.reconnection.max_delay, 60000);

    // Check default logging settings
    assert_eq!(config.logging.level, "info");
    assert!(config.logging.file.is_none());
    assert_eq!(config.logging.format, "json");
}

#[test]
fn test_config_type_conversions() {
    let platform = fuji::platform::get_platform();
    let mut config = Config::new(platform);

    // Test setting different types
    config.set("string_key", "string_value").unwrap();
    config.set("number_key", "42").unwrap();
    config.set("float_key", "3.14").unwrap();
    config.set("bool_key", "true").unwrap();

    // Getting should return strings
    assert_eq!(config.get("string_key"), Some("string_value".to_string()));
    assert_eq!(config.get("number_key"), Some("42".to_string()));
    assert_eq!(config.get("float_key"), Some("3.14".to_string()));
    assert_eq!(config.get("bool_key"), Some("true".to_string()));
}

#[test]
fn test_config_reset() {
    let platform = fuji::platform::get_platform();
    let mut config = Config::new(platform);

    // Modify some values
    config.set("daemon.poll_interval", "60").unwrap();
    config.set("test_key", "test_value").unwrap();

    // Reset to defaults
    config.reset("daemon.poll_interval").unwrap();

    // Should be back to default
    assert_eq!(config.get("daemon.poll_interval"), Some("5".to_string()));
    // Test key should remain unchanged
    assert_eq!(config.get("test_key"), Some("test_value".to_string()));
}

#[test]
fn test_config_metadata() {
    let platform = fuji::platform::get_platform();
    let config = Config::new(platform);

    // Config should have creation time
    assert!(config.created_at.le(&chrono::Utc::now()));

    // Config should have version
    assert!(!config.version.is_empty());
}

#[test]
fn test_config_conflict_detection() {
    let platform = fuji::platform::get_platform();
    let mut config = Config::new(platform);

    // Create a simple conflict by modifying same key
    let original = config.get("daemon.poll_interval").unwrap();

    // Simulate conflict detection
    config.set("daemon.poll_interval", "10").unwrap();
    let modified = config.get("daemon.poll_interval").unwrap();

    // Values should be different (simulating conflict)
    assert_ne!(original, modified);
}

#[test]
fn test_config_path_operations() {
    let platform = fuji::platform::get_platform();
    let config = Config::new(platform);
    let temp_dir = TempDir::new().unwrap();

    // Test operations with non-existent file
    let non_existent = temp_dir.path().join("non_existent.toml");
    assert!(Config::load_from_file(&non_existent, platform).is_ok());

    // Test with invalid TOML
    let invalid_toml = temp_dir.path().join("invalid.toml");
    std::fs::write(&invalid_toml, "invalid toml content").unwrap();
    assert!(Config::load_from_file(&invalid_toml, platform).is_err());
}
