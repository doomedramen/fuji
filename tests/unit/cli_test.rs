//! Unit tests for CLI argument parsing and command handling
//!
//! Tests command-line interface functionality, argument validation,
//! and error handling for various CLI commands.

use fuji::cli::{Cli, Commands, ConfigCommands, DaemonCommands, MountCommands};
use clap::Parser;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_cli_no_arguments() {
    let args = vec!["fuji"];
    let cli = Cli::try_parse_from(args);

    // Should parse successfully with no subcommand
    assert!(cli.is_ok());
    let cli = cli.unwrap();

    // Default values should be set
    assert_eq!(cli.verbose, 0);
    assert_eq!(cli.quiet, false);
    assert_eq!(cli.config_file, PathBuf::from("config.toml"));
    assert_eq!(cli.log_file, None);
    assert!(cli.daemon_home.is_none());
}

#[test]
fn test_cli_verbose_flags() {
    let args = vec!["fuji", "-v", "-v", "-v"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();
    assert_eq!(cli.verbose, 3);
}

#[test]
fn test_cli_quiet_flag() {
    let args = vec!["fuji", "--quiet"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();
    assert!(cli.quiet);
}

#[test]
fn test_cli_config_file_argument() {
    let custom_config = "/etc/fuji/custom.toml";
    let args = vec!["fuji", "--config", custom_config];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();
    assert_eq!(cli.config_file, PathBuf::from(custom_config));
}

#[test]
fn test_cli_log_file_argument() {
    let log_file = "/var/log/fuji.log";
    let args = vec!["fuji", "--log-file", log_file];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();
    assert_eq!(cli.log_file, Some(PathBuf::from(log_file)));
}

#[test]
fn test_cli_daemon_home_argument() {
    let daemon_home = "/custom/daemon/path";
    let args = vec!["fuji", "--daemon-home", daemon_home];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();
    assert_eq!(cli.daemon_home, Some(PathBuf::from(daemon_home)));
}

#[test]
fn test_mount_command_parsing() {
    let args = vec!["fuji", "mount", "nfs://server.example.com/export", "/mnt/point"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Mount(mount_cmd) = cli.command {
        assert_eq!(mount_cmd.url, "nfs://server.example.com/export");
        assert_eq!(mount_cmd.mount_point, PathBuf::from("/mnt/point"));
        assert_eq!(mount_cmd.read_only, false);
        assert_eq!(mount_cmd.allow_other, false);
        assert_eq!(mount_cmd.options.len(), 0);
    } else {
        panic!("Expected mount command");
    }
}

#[test]
fn test_mount_command_with_options() {
    let args = vec![
        "fuji", "mount",
        "nfs://server.example.com/export",
        "/mnt/point",
        "--read-only",
        "--allow-other",
        "--option", "debug",
        "--option", "uid=1000"
    ];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Mount(mount_cmd) = cli.command {
        assert!(mount_cmd.read_only);
        assert!(mount_cmd.allow_other);
        assert!(mount_cmd.options.len(), 2);
        assert!(mount_cmd.options.contains(&"debug".to_string()));
        assert!(mount_cmd.options.contains(&"uid=1000".to_string()));
    } else {
        panic!("Expected mount command");
    }
}

#[test]
fn test_unmount_command_parsing() {
    let args = vec!["fuji", "unmount", "/mnt/point", "--force"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Unmount(unmount_cmd) = cli.command {
        assert_eq!(unmount_cmd.mount_point, PathBuf::from("/mnt/point"));
        assert!(unmount_cmd.force);
        assert_eq!(unmount_cmd.lazy, false);
    } else {
        panic!("Expected unmount command");
    }
}

#[test]
fn test_unmount_command_with_lazy() {
    let args = vec!["fuji", "unmount", "/mnt/point", "--lazy"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Unmount(unmount_cmd) = cli.command {
        assert!(!unmount_cmd.force);
        assert!(unmount_cmd.lazy);
    } else {
        panic!("Expected unmount command");
    }
}

#[test]
fn test_daemon_start_command() {
    let args = vec!["fuji", "daemon", "start", "--no-automount"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Daemon(DaemonCommands::Start { no_automount, foreground }) = cli.command {
        assert!(no_automount);
        assert!(!foreground);
    } else {
        panic!("Expected daemon start command");
    }
}

#[test]
fn test_daemon_start_with_foreground() {
    let args = vec!["fuji", "daemon", "start", "--foreground"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Daemon(DaemonCommands::Start { no_automount, foreground }) = cli.command {
        assert!(!no_automount);
        assert!(foreground);
    } else {
        panic!("Expected daemon start command");
    }
}

#[test]
fn test_daemon_stop_command() {
    let args = vec!["fuji", "daemon", "stop", "--force"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Daemon(DaemonCommands::Stop { force }) = cli.command {
        assert!(force);
    } else {
        panic!("Expected daemon stop command");
    }
}

#[test]
fn test_daemon_restart_command() {
    let args = vec!["fuji", "daemon", "restart"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Daemon(DaemonCommands::Restart) = cli.command {
        // Restart command has no additional arguments
        assert!(true);
    } else {
        panic!("Expected daemon restart command");
    }
}

#[test]
fn test_daemon_status_command() {
    let args = vec!["fuji", "daemon", "status"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Daemon(DaemonCommands::Status) = cli.command {
        // Status command has no additional arguments
        assert!(true);
    } else {
        panic!("Expected daemon status command");
    }
}

#[test]
fn test_config_list_command() {
    let args = vec!["fuji", "config", "list"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Config(ConfigCommands::List { pattern }) = cli.command {
        assert!(pattern.is_none());
    } else {
        panic!("Expected config list command");
    }
}

#[test]
fn test_config_list_with_pattern() {
    let args = vec!["fuji", "config", "list", "--pattern", "daemon.*"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Config(ConfigCommands::List { pattern }) = cli.command {
        assert_eq!(pattern, Some("daemon.*".to_string()));
    } else {
        panic!("Expected config list command with pattern");
    }
}

#[test]
fn test_config_get_command() {
    let args = vec!["fuji", "config", "get", "daemon.poll_interval"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Config(ConfigCommands::Get { key }) = cli.command {
        assert_eq!(key, "daemon.poll_interval");
    } else {
        panic!("Expected config get command");
    }
}

#[test]
fn test_config_set_command() {
    let args = vec!["fuji", "config", "set", "daemon.poll_interval", "30s"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Config(ConfigCommands::Set { key, value }) = cli.command {
        assert_eq!(key, "daemon.poll_interval");
        assert_eq!(value, "30s");
    } else {
        panic!("Expected config set command");
    }
}

#[test]
fn test_config_reset_command() {
    let args = vec!["fuji", "config", "reset", "daemon.poll_interval"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Config(ConfigCommands::Reset { key }) = cli.command {
        assert_eq!(key, "daemon.poll_interval");
    } else {
        panic!("Expected config reset command");
    }
}

#[test]
fn test_config_show_command() {
    let args = vec!["fuji", "config", "show", "--format", "json"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Config(ConfigCommands::Show { format }) = cli.command {
        assert_eq!(format, "json");
    } else {
        panic!("Expected config show command");
    }
}

#[test]
fn test_list_command() {
    let args = vec!["fuji", "list", "--all", "--format", "table"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::List { all, format, status } = cli.command {
        assert!(all);
        assert_eq!(format, "table");
        assert!(status.is_none());
    } else {
        panic!("Expected list command");
    }
}

#[test]
fn test_list_command_with_status_filter() {
    let args = vec!["fuji", "list", "--status", "mounted"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::List { all, format, status } = cli.command {
        assert!(!all);
        assert_eq!(format, "table"); // default format
        assert_eq!(status, Some("mounted".to_string()));
    } else {
        panic!("Expected list command with status filter");
    }
}

#[test]
fn test_status_command() {
    let args = vec!["fuji", "status", "--json"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Status { json } = cli.command {
        assert!(json);
    } else {
        panic!("Expected status command");
    }
}

#[test]
fn test_health_command() {
    let args = vec!["fuji", "health", "--detailed"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Health { detailed } = cli.command {
        assert!(detailed);
    } else {
        panic!("Expected health command");
    }
}

#[test]
fn test_validate_command() {
    let config_file = "/etc/fuji/test.toml";
    let args = vec!["fuji", "validate", "--config", config_file];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Validate { config } = cli.command {
        assert_eq!(config, Some(PathBuf::from(config_file)));
    } else {
        panic!("Expected validate command");
    }
}

#[test]
fn test_completion_command() {
    let args = vec!["fuji", "completion", "bash"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Completion { shell } = cli.command {
        assert_eq!(shell, "bash");
    } else {
        panic!("Expected completion command");
    }
}

#[test]
fn test_cli_error_handling() {
    // Test invalid command
    let args = vec!["fuji", "invalid-command"];
    let cli = Cli::try_parse_from(args);
    assert!(cli.is_err());

    // Test missing required arguments for mount
    let args = vec!["fuji", "mount", "nfs://server.example.com/export"];
    let cli = Cli::try_parse_from(args);
    assert!(cli.is_err());

    // Test invalid option for config list
    let args = vec!["fuji", "config", "list", "--invalid"];
    let cli = Cli::try_parse_from(args);
    assert!(cli.is_err());
}

#[test]
fn test_cli_help_message() {
    let args = vec!["fuji", "--help"];
    let cli = Cli::try_parse_from(args);

    // Help should cause graceful exit
    assert!(cli.is_err());

    // Test subcommand help
    let args = vec!["fuji", "mount", "--help"];
    let cli = Cli::try_parse_from(args);
    assert!(cli.is_err());
}

#[test]
fn test_cli_version_flag() {
    let args = vec!["fuji", "--version"];
    let cli = Cli::try_parse_from(args);

    // Version should cause graceful exit
    assert!(cli.is_err());
}

#[test]
fn test_cli_environment_variable_substitution() {
    // This would require the CLI to support environment variable substitution
    // Implementation depends on the actual CLI design

    let args = vec!["fuji", "--config", "$HOME/.config/fuji/config.toml"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();
    // Note: Environment variable substitution would be handled by application logic,
    // not by clap parsing itself
}

#[test]
fn test_cli_with_temporary_files() {
    // Test with temporary directory paths
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test_config.toml");
    let log_path = temp_dir.path().join("test.log");

    let args = vec![
        "fuji",
        "--config", config_path.to_str().unwrap(),
        "--log-file", log_path.to_str().unwrap(),
        "--daemon-home", temp_dir.path().to_str().unwrap()
    ];

    let cli = Cli::try_parse_from(args);
    assert!(cli.is_ok());

    let cli = cli.unwrap();
    assert_eq!(cli.config_file, config_path);
    assert_eq!(cli.log_file, Some(log_path));
    assert_eq!(cli.daemon_home, Some(temp_dir.path().to_path_buf()));
}

#[test]
fn test_cli_url_validation_in_mount() {
    // Test various URL formats for mount command
    let valid_urls = vec![
        ("nfs://server.example.com/export", "/mnt/nfs"),
        ("smb://server.example.com/share", "/mnt/smb"),
        ("sshfs://user@server.example.com/path", "/mnt/ssh"),
        ("nfs://192.168.1.100/export", "/mnt/nfs"),
    ];

    for (url, mount_point) in valid_urls {
        let args = vec!["fuji", "mount", url, mount_point];
        let cli = Cli::try_parse_from(args);

        assert!(cli.is_ok(), "Should accept URL: {}", url);
    }

    // Test invalid URLs (these should still parse, validation happens later)
    let invalid_urls = vec![
        ("not-a-url", "/mnt/test"),
        ("", "/mnt/test"),
        ("ftp://server.example.com/file", "/mnt/test"), // Unsupported protocol
    ];

    for (url, mount_point) in invalid_urls {
        let args = vec!["fuji", "mount", url, mount_point];
        let cli = Cli::try_parse_from(args);

        // CLI parsing should still succeed, URL validation happens in application logic
        assert!(cli.is_ok(), "CLI parsing should succeed for: {}", url);
    }
}

#[test]
fn test_cli_multiple_global_flags() {
    // Test multiple global flags together
    let args = vec![
        "fuji",
        "-vv",           // verbosity level 2
        "--quiet",       // quiet flag
        "--config", "/etc/fuji.toml",
        "--log-file", "/var/log/fuji.log",
        "--daemon-home", "/var/lib/fuji",
        "status",        // command
        "--json",        // command-specific flag
    ];

    let cli = Cli::try_parse_from(args);
    assert!(cli.is_ok());

    let cli = cli.unwrap();
    assert_eq!(cli.verbose, 2);
    assert!(cli.quiet);
    assert_eq!(cli.config_file, PathBuf::from("/etc/fuji.toml"));
    assert_eq!(cli.log_file, Some(PathBuf::from("/var/log/fuji.log")));
    assert_eq!(cli.daemon_home, Some(PathBuf::from("/var/lib/fuji")));

    if let Commands::Status { json } = cli.command {
        assert!(json);
    } else {
        panic!("Expected status command");
    }
}

#[cfg(test)]
mod stress_tests {
    use super::*;

    #[test]
    fn test_cli_long_arguments() {
        // Test with very long argument values
        let long_path = "/".to_string() + &"a".repeat(1000);
        let long_option = "option_".to_string() + &"x".repeat(500);

        let args = vec![
            "fuji",
            "--config", &long_path,
            "--log-file", &long_path,
            "mount",
            "nfs://server.example.com/export",
            "/mnt/point",
            "--option", &long_option,
        ];

        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_many_options() {
        // Test with many options
        let mut args = vec!["fuji"];

        // Add many verbosity flags
        for _ in 0..50 {
            args.push("-v");
        }

        args.extend(vec!["status", "--json"]);

        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());

        let cli = cli.unwrap();
        assert_eq!(cli.verbose, 50);
    }

    #[test]
    fn test_cli_unicode_arguments() {
        // Test with Unicode characters
        let unicode_path = "/mnt/测试目录";
        let unicode_option = "选项=值";

        let args = vec![
            "fuji",
            "mount",
            "nfs://server.example.com/export",
            unicode_path,
            "--option", unicode_option,
        ];

        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());

        let cli = cli.unwrap();
        if let Commands::Mount(mount_cmd) = cli.command {
            assert_eq!(mount_cmd.mount_point, PathBuf::from(unicode_path));
            assert!(mount_cmd.options.contains(&unicode_option.to_string()));
        } else {
            panic!("Expected mount command");
        }
    }
}