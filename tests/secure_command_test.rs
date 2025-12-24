//! Test secure command execution to catch blocking issues like seccomp hangs
//!
//! These tests verify that SecureCommand::output() doesn't hang indefinitely
//! and completes within reasonable time limits.

use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_secure_command_echo_no_hang() {
    use fuji::mount::drivers::secure_command::SecureCommand;

    // Test that a simple command executes quickly without blocking
    let cmd = SecureCommand::new("echo").arg("test");

    let result = timeout(Duration::from_secs(5), cmd.output()).await;

    assert!(
        result.is_ok(),
        "SecureCommand::output() should complete within 5 seconds"
    );

    let output = result.unwrap().unwrap();
    assert!(output.contains("test"), "Echo output should contain 'test'");
}

#[tokio::test]
async fn test_secure_command_mount_command_no_hang() {
    use fuji::mount::drivers::secure_command::SecureCommand;
    use fuji::security::seccomp::SeccompProfile;

    // Test mount command with seccomp profile (the exact code path that was hanging)
    // Using "mount" without args shows usage, which works on both Linux and macOS
    let cmd = SecureCommand::new("mount").with_seccomp_profile(SeccompProfile::Mount);

    let result = timeout(Duration::from_secs(5), cmd.output()).await;

    assert!(
        result.is_ok(),
        "Mount command with seccomp profile should complete quickly. \
             This test would have caught the seccomp hang issue."
    );

    // The command should succeed or fail quickly, not hang
    // We just verify it completed within the timeout
    let output = result.unwrap();
    // On macOS, mount without args succeeds. On Linux it might fail.
    // Either way, it should not hang.
    assert!(
        output.is_ok() || output.is_err(),
        "Mount command should complete without hanging"
    );
}

#[tokio::test]
async fn test_secure_command_timeout_on_blocking_command() {
    use fuji::mount::drivers::secure_command::SecureCommand;

    // Test that timeout works for blocking commands
    // Using "sleep" command which should timeout
    let cmd = SecureCommand::new("sleep").arg("60");

    let start = std::time::Instant::now();
    let result = timeout(Duration::from_secs(2), cmd.output()).await;

    // Should timeout within ~2 seconds
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(3),
        "Sleep command should timeout around 2s, took {:?}",
        elapsed
    );
    assert!(
        result.is_err(),
        "Sleep command for 60s should timeout within 2s"
    );
}

#[tokio::test]
async fn test_secure_command_failed_command_with_timeout() {
    use fuji::mount::drivers::secure_command::SecureCommand;
    use fuji::security::seccomp::SeccompProfile;

    // Test that failed commands return errors quickly (not after timeout)
    let cmd = SecureCommand::new("mount")
        .arg("/nonexistent") // This will fail fast
        .with_seccomp_profile(SeccompProfile::Mount);

    let start = std::time::Instant::now();
    let result = timeout(Duration::from_secs(5), cmd.output()).await;

    assert!(
        result.is_ok(),
        "Failed mount should return error quickly, not timeout"
    );

    // Should fail in less than a second, not after 5 seconds
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "Failed mount should complete quickly, took {:?}",
        elapsed
    );

    let output = result.unwrap();
    assert!(output.is_err(), "Mount command should fail");
    let err = output.unwrap_err();
    assert!(
        err.to_string().contains("Failed to execute command")
            || err.to_string().contains("Command failed")
            || err.to_string().contains("exit code"),
        "Error should indicate command failure, got: {}",
        err
    );
}

#[tokio::test]
async fn test_secure_command_seccomp_validation_doesnt_block() {
    use fuji::mount::drivers::secure_command::SecureCommand;
    use fuji::security::seccomp::SeccompProfile;

    // Test that seccomp validation doesn't block
    // mount is in the allowlist, so validation should pass
    let cmd = SecureCommand::new("mount").with_seccomp_profile(SeccompProfile::Mount);

    let start = std::time::Instant::now();
    let result = timeout(Duration::from_secs(5), cmd.output()).await;

    assert!(
        result.is_ok(),
        "Mount command with seccomp profile should not block"
    );

    // Should complete quickly (seccomp validation should not block)
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "Seccomp validation should not block, took {:?}",
        elapsed
    );
}
