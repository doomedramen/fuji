//! Tests for the service command

use std::fs;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_service_command_help() {
    // Test that the service command exists and shows help
    let output = Command::new("cargo")
        .args(&["run", "--bin", "fuji", "--", "service", "--help"])
        .output()
        .expect("Failed to execute fuji service --help");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Service management"));
    assert!(stdout.contains("Generate a systemd service file"));
}

#[test]
fn test_service_generate_help() {
    // Test that the service generate subcommand shows help
    let output = Command::new("cargo")
        .args(&[
            "run", "--bin", "fuji", "--", "service", "generate", "--help",
        ])
        .output()
        .expect("Failed to execute fuji service generate --help");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Generate a systemd service file"));
    assert!(stdout.contains("--output"));
    assert!(stdout.contains("--user"));
    assert!(stdout.contains("--name"));
    assert!(stdout.contains("--work-dir"));
}

#[test]
fn test_service_generate_to_file() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("fuji-daemon.service");

    // Run fuji service generate with custom options
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "fuji",
            "--",
            "service",
            "generate",
            "--output",
            output_path.to_str().unwrap(),
            "--user",
            "testuser",
            "--name",
            "test-fuji",
            "--work-dir",
            "/opt/fuji",
        ])
        .output()
        .expect("Failed to execute fuji service generate");

    assert!(output.status.success());

    // Check that file was created
    assert!(output_path.exists());

    // Read and verify content
    let content = fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("Description=Fuji Network File System Manager"));
    assert!(content.contains("User=testuser"));
    assert!(content.contains("Group=testuser"));
    assert!(content.contains("WorkingDirectory=/opt/fuji"));
    assert!(content.contains("Type=simple"));
    assert!(content.contains("ExecStart="));
    assert!(content.contains("daemon start"));
}

#[test]
fn test_service_generate_to_stdout() {
    // Run fuji service generate and capture stdout
    let output = Command::new("cargo")
        .args(&["run", "--bin", "fuji", "--", "service", "generate"])
        .output()
        .expect("Failed to execute fuji service generate");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();

    // Verify the service file is output to stdout
    assert!(stdout.contains("[Unit]"));
    assert!(stdout.contains("[Service]"));
    assert!(stdout.contains("[Install]"));
    assert!(stdout.contains("Description=Fuji Network File System Manager"));
    assert!(stdout.contains("Type=simple"));
    assert!(stdout.contains("ExecStart="));
}

#[test]
fn test_service_file_format() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("format-test.service");

    // Generate a service file with specific options
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "fuji",
            "--",
            "service",
            "generate",
            "--output",
            output_path.to_str().unwrap(),
            "--user",
            "formatuser",
            "--work-dir",
            "/test/dir",
        ])
        .output()
        .expect("Failed to execute fuji service generate");

    assert!(output.status.success());

    let content = fs::read_to_string(&output_path).unwrap();

    // Verify systemd service file structure
    assert!(content.starts_with("[Unit]"));
    assert!(content.contains("\n[Service]\n"));
    assert!(content.contains("\n[Install]\n"));

    // Verify required sections
    assert!(content.contains("Description="));
    assert!(content.contains("After="));
    assert!(content.contains("Type="));
    assert!(content.contains("ExecStart="));
    assert!(content.contains("Restart="));
    assert!(content.contains("User="));
    assert!(content.contains("WantedBy="));

    // Verify security settings (relaxed for mount operations)
    assert!(content.contains("NoNewPrivileges=false"));
    assert!(content.contains("PrivateTmp=false"));
    assert!(content.contains("ProtectSystem=false"));
    assert!(content.contains("ProtectHome=false"));
    assert!(content.contains("AmbientCapabilities=CAP_SYS_ADMIN"));
    assert!(content.contains("CapabilityBoundingSet=CAP_SYS_ADMIN"));
    assert!(content.contains("Environment=HOME="));

    // Verify custom options are applied
    assert!(content.contains("User=formatuser"));
    assert!(content.contains("Group=formatuser"));
    assert!(content.contains("WorkingDirectory=/test/dir"));
}
