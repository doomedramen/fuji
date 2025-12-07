//! Unit tests for configuration management

use fuji::config::Config;

use tempfile::TempDir;

#[test]
fn test_config_creation() {
    let _platform = fuji::platform::get_platform();
    let config = Config::default();

    // Check default values
    assert_eq!(config.version, "1.0");
    assert_eq!(config.global.health_check_interval_secs, 30);
    assert_eq!(config.global.log_level, "info");
}

#[test]
fn test_config_validation() {
    let _platform = fuji::platform::get_platform();
    let config = Config::default();

    // Valid config should pass validation
    assert!(config.validate_config().is_ok());
}

#[test]
fn test_config_serialization() {
    let _platform = fuji::platform::get_platform();
    let config = Config::default();

    // Test serialization
    let serialized = toml::to_string_pretty(&config).unwrap();
    let deserialized: Config = toml::from_str(&serialized).unwrap();

    assert_eq!(config.version, deserialized.version);
    assert_eq!(
        config.global.health_check_interval_secs,
        deserialized.global.health_check_interval_secs
    );
}

#[test]
fn test_config_defaults() {
    let config = Config::default();

    // Check default version
    assert_eq!(config.version, "1.0");

    // Check default reconnection settings
    assert_eq!(config.reconnection.max_retries, 5);
    assert_eq!(config.reconnection.initial_delay_ms, 1000);
    assert_eq!(config.reconnection.max_delay_ms, 60000);
    assert_eq!(config.reconnection.backoff_multiplier, 2.0);

    // Check default global settings
    assert_eq!(config.global.health_check_interval_secs, 30);
    assert_eq!(config.global.log_level, "info");
    assert!(config.global.auto_mount);
}

#[tokio::test]
async fn test_config_file_operations() {
    let config = Config::default();
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test_config.toml");

    // Save config using TOML directly
    let content = toml::to_string_pretty(&config).unwrap();
    std::fs::write(&config_path, content).unwrap();

    // Load config using TOML directly
    let loaded_content = std::fs::read_to_string(&config_path).unwrap();
    let loaded_config: Config = toml::from_str(&loaded_content).unwrap();

    assert_eq!(config.version, loaded_config.version);
    assert_eq!(
        config.global.health_check_interval_secs,
        loaded_config.global.health_check_interval_secs
    );
}
