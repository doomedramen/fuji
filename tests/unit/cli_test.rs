//! Unit tests for CLI argument parsing and command handling
//!
//! Tests command-line interface functionality, argument validation,
//! and error handling for various CLI commands.

use clap::Parser;
use fuji::cli::{Cli, Commands, ConfigCommand, DaemonCommand};

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
fn test_mount_command_parsing() {
    let args = vec![
        "fuji",
        "mount",
        "nfs://server.example.com/export",
        "--mount-point",
        "/mnt/point",
    ];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Mount {
        url,
        mount_point,
        options,
        disable,
        dry_run,
        progress,
    } = cli.command
    {
        assert_eq!(url, "nfs://server.example.com/export");
        assert_eq!(mount_point, Some("/mnt/point".to_string()));
        assert_eq!(options, None);
        assert!(!disable);
        assert!(!dry_run);
        assert!(!progress);
    } else {
        panic!("Expected mount command");
    }
}

#[test]
fn test_mount_command_with_options() {
    let args = vec![
        "fuji",
        "mount",
        "nfs://server.example.com/export",
        "--mount-point",
        "/mnt/point",
        "--disable",
        "--dry-run",
        "--progress",
        "--options",
        "debug,uid=1000",
    ];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Mount {
        url,
        mount_point,
        options,
        disable,
        dry_run,
        progress,
    } = cli.command
    {
        assert_eq!(url, "nfs://server.example.com/export");
        assert_eq!(mount_point, Some("/mnt/point".to_string()));
        assert!(disable);
        assert!(dry_run);
        assert!(progress);
        assert_eq!(options, Some(vec!["debug,uid=1000".to_string()]));
    } else {
        panic!("Expected mount command");
    }
}

#[test]
fn test_unmount_command_parsing() {
    let args = vec!["fuji", "unmount", "mount_id_123", "--force"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Unmount {
        mount_id,
        force,
    } = cli.command
    {
        assert_eq!(mount_id, "mount_id_123");
        assert!(force);
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

    if let Commands::Daemon {
        command,
    } = cli.command
    {
        if let DaemonCommand::Start {
            no_automount,
        } = command
        {
            assert!(no_automount);
        } else {
            panic!("Expected daemon start command");
        }
    } else {
        panic!("Expected daemon command");
    }
}

#[test]
fn test_daemon_stop_command() {
    let args = vec!["fuji", "daemon", "stop"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Daemon {
        command,
    } = cli.command
    {
        if let DaemonCommand::Stop = command {
            // Stop command parsed correctly
        } else {
            panic!("Expected daemon stop command");
        }
    } else {
        panic!("Expected daemon command");
    }
}

#[test]
fn test_daemon_logs_command() {
    let args = vec!["fuji", "daemon", "logs", "--lines", "50"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Daemon {
        command,
    } = cli.command
    {
        if let DaemonCommand::Logs {
            lines,
        } = command
        {
            assert_eq!(lines, Some(50));
        } else {
            panic!("Expected daemon logs command");
        }
    } else {
        panic!("Expected daemon command");
    }
}

#[test]
fn test_config_list_command() {
    let args = vec!["fuji", "config", "list"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Config {
        command,
    } = cli.command
    {
        if let ConfigCommand::List {
            json,
        } = command
        {
            assert!(!json);
        } else {
            panic!("Expected config list command");
        }
    } else {
        panic!("Expected config command");
    }
}

#[test]
fn test_config_list_json_command() {
    let args = vec!["fuji", "config", "list", "--json"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Config {
        command,
    } = cli.command
    {
        if let ConfigCommand::List {
            json,
        } = command
        {
            assert!(json);
        } else {
            panic!("Expected config list command with json");
        }
    } else {
        panic!("Expected config command");
    }
}

#[test]
fn test_config_get_command() {
    let args = vec!["fuji", "config", "get", "daemon.mount_dir"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Config {
        command,
    } = cli.command
    {
        if let ConfigCommand::Get {
            key,
            json,
        } = command
        {
            assert_eq!(key, "daemon.mount_dir");
            assert!(!json);
        } else {
            panic!("Expected config get command");
        }
    } else {
        panic!("Expected config command");
    }
}

#[test]
fn test_config_set_command() {
    let args = vec!["fuji", "config", "set", "daemon.mount_dir", "/mnt/fuji"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Config {
        command,
    } = cli.command
    {
        if let ConfigCommand::Set {
            key,
            value,
        } = command
        {
            assert_eq!(key, "daemon.mount_dir");
            assert_eq!(value, "/mnt/fuji");
        } else {
            panic!("Expected config set command");
        }
    } else {
        panic!("Expected config command");
    }
}

#[test]
fn test_config_show_command() {
    let args = vec!["fuji", "config", "show", "--json"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Config {
        command,
    } = cli.command
    {
        if let ConfigCommand::Show {
            json,
        } = command
        {
            assert!(json);
        } else {
            panic!("Expected config show command");
        }
    } else {
        panic!("Expected config command");
    }
}

#[test]
fn test_list_command() {
    let args = vec!["fuji", "list", "--json"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::List {
        enabled,
        disabled,
        filter_point,
        filter_url,
        filter_type,
        json,
    } = cli.command
    {
        assert!(!enabled);
        assert!(!disabled);
        assert!(filter_point.is_none());
        assert!(filter_url.is_none());
        assert!(filter_type.is_none());
        assert!(json);
    } else {
        panic!("Expected list command");
    }
}

#[test]
fn test_list_command_with_filters() {
    let args = vec!["fuji", "list", "--enabled", "--filter-type", "nfs"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::List {
        enabled,
        disabled,
        filter_point,
        filter_url,
        filter_type,
        json,
    } = cli.command
    {
        assert!(enabled);
        assert!(!disabled);
        assert!(filter_point.is_none());
        assert!(filter_url.is_none());
        assert_eq!(filter_type, Some("nfs".to_string()));
        assert!(!json);
    } else {
        panic!("Expected list command with filters");
    }
}

#[test]
fn test_status_command() {
    let args = vec!["fuji", "status", "--json", "--watch", "--verbose"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Status {
        verbose,
        watch,
        filter_point,
        filter_url,
        filter_type,
        filter_status,
        json,
    } = cli.command
    {
        assert!(verbose);
        assert!(watch);
        assert!(filter_point.is_none());
        assert!(filter_url.is_none());
        assert!(filter_type.is_none());
        assert!(filter_status.is_none());
        assert!(json);
    } else {
        panic!("Expected status command");
    }
}

#[test]
fn test_doctor_command() {
    let args = vec!["fuji", "doctor"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Doctor = cli.command {
        // Doctor command parsed correctly
    } else {
        panic!("Expected doctor command");
    }
}

#[test]
fn test_discover_command() {
    let args = vec!["fuji", "discover", "nfs://192.168.1.1/"];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Discover {
        url,
    } = cli.command
    {
        assert_eq!(url, "nfs://192.168.1.1/");
    } else {
        panic!("Expected discover command");
    }
}

#[test]
fn test_batch_command() {
    let args = vec![
        "fuji",
        "batch",
        "operations.json",
        "--continue-on-error",
        "--dry-run",
    ];
    let cli = Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    if let Commands::Batch {
        file,
        continue_on_error,
        dry_run,
    } = cli.command
    {
        assert_eq!(file, "operations.json");
        assert!(continue_on_error);
        assert!(dry_run);
    } else {
        panic!("Expected batch command");
    }
}
