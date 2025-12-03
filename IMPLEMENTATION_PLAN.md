# Fuji MVP Implementation Plan

## Overview
This document outlines the detailed implementation plan for the Fuji Network File System Mount Manager MVP.

## Current State
- Rust implementation is more complete with basic daemon functionality, socket communication, and platform-specific mounting for Linux
- TypeScript implementation is incomplete with only basic structure
- Missing key MVP features like configuration persistence, proper mount point organization, and automatic reconnection

## Implementation Tasks

### 1. TOML Configuration Persistence for Mounts

**Current State**: Config.rs only handles paths for socket and configuration, but doesn't store mount configurations.

**Implementation Details**:
- Add a MountConfig struct to store:
  - URL of the network share
  - Mount point path
  - Enabled status (true/false)
  - Created at timestamp
  - Updated at timestamp
  - Optional alias
- Add TOML dependency to Cargo.toml
- Implement TOML serialization/deserialization for mount configurations
- Add methods to Config to save, load, and update mount configurations
- Store configurations in ~/.config/fuji/mounts.toml
- Handle configuration file creation with proper permissions

**Files to Modify**:
- Cargo.toml (add TOML dependency)
- src/config.rs (add mount configuration structures and methods)

### 2. Daemon Auto-Mount on Startup

**Current State**: Daemon starts but doesn't automatically mount previously configured shares.

**Implementation Details**:
- Modify daemon initialization to load mount configurations from TOML
- Add logic to mount all enabled shares on daemon startup
- Implement staggered mounting (1-second delay between mounts) to avoid overwhelming the network
- Add a `--no-automount` flag to skip automatic mounting
- Handle mount failures gracefully without stopping the daemon startup

**Files to Modify**:
- src/main.rs (add --no-automount flag)
- src/daemon.rs (add auto-mount logic)

### 3. Improve Mount Point Organization

**Current State**: Mount points are created in temporary directories with UUID names.

**Implementation Details**:
- Implement mount point organization under `/mnt/fuji/`
- Use the naming convention `{hostname}_{protocol}/share`
- Create the necessary directory structure with proper permissions
- Handle special characters in hostnames
- Update platform mounting logic to use the new organization
- Clean up old mount points on startup

**Files to Modify**:
- src/platform.rs (update mount point creation logic)
- src/daemon.rs (update mount point management)

### 4. Basic Exponential Backoff for Reconnection

**Current State**: No reconnection logic is implemented.

**Implementation Details**:
- Add a connection monitoring system to track mount health
- Implement exponential backoff algorithm:
  - Initial retry after 1 second
  - Double the delay after each failure, up to a maximum of 60 seconds
  - Reset delay after successful connection
- Add configuration options for reconnection settings
- Integrate monitoring into the main daemon loop
- Log reconnection attempts

**Files to Modify**:
- src/daemon.rs (add monitoring and reconnection logic)
- src/config.rs (add reconnection configuration)

### 5. Add Detach Option for Daemon Start

**Current State**: Daemon can only be started in the foreground.

**Implementation Details**:
- Modify the daemon start command to support a `-d/--detach` flag
- Implement proper daemonization with forking and session management
- Add PID file management for tracking the daemon process
- Ensure proper signal handling for graceful shutdown
- Add daemon status checking to prevent multiple instances

**Files to Modify**:
- src/main.rs (add detach flag)
- src/daemon.rs (add daemonization logic)

### 6. Implement Mount State Persistence

**Current State**: Mounts are tracked in memory but not persisted between daemon restarts.

**Implementation Details**:
- Add enabled/disabled state to mount configurations
- Update the mount/unmount commands to modify the state
- Ensure state changes are persisted to the TOML configuration
- Add logic to respect the enabled state when auto-mounting
- Implement enable/disable commands

**Files to Modify**:
- src/config.rs (add state persistence)
- src/main.rs (add enable/disable commands)
- src/daemon.rs (update mount/unmount logic)

### 7. Improve Error Handling and User Feedback

**Current State**: Basic error handling exists but could be more user-friendly.

**Implementation Details**:
- Enhance error messages to be more actionable
- Add specific error codes for different failure scenarios
- Implement better feedback for long-running operations
- Add guidance when the daemon isn't running
- Improve error messages for common issues (network problems, permission issues, etc.)

**Files to Modify**:
- src/error.rs (add more specific error types)
- src/daemon.rs (improve error responses)
- src/main.rs (improve CLI error handling)

### 8. Add Proper Mount Naming Convention

**Current State**: Mounts use UUIDs as identifiers.

**Implementation Details**:
- Implement the naming convention `{hostname}_{protocol}` for mount IDs
- Add logic to parse URLs and extract hostnames
- Handle special cases and conflicts in naming
- Update all commands to work with the new naming scheme
- Add support for user-defined aliases

**Files to Modify**:
- src/daemon.rs (update mount ID generation)
- src/platform.rs (update URL parsing)
- src/main.rs (update command handling)

### 9. Implement Connection Monitoring and Automatic Reconnection

**Current State**: No monitoring or reconnection logic exists.

**Implementation Details**:
- Add periodic health checks for active mounts (every 30 seconds)
- Implement automatic reconnection when a connection is lost
- Add logging for reconnection attempts
- Provide user feedback when mounts are reconnected
- Implement a way to check if a mount is still accessible

**Files to Modify**:
- src/daemon.rs (add monitoring and reconnection logic)
- src/platform.rs (add mount health check)

### 10. Add Integration Tests for MVP Features

**Current State**: Basic integration tests exist but don't cover MVP features.

**Implementation Details**:
- Expand integration tests to cover all MVP features
- Add tests for configuration persistence
- Test auto-mount behavior on daemon restart
- Test reconnection logic with simulated network failures
- Test all new commands and options

**Files to Modify**:
- tests/integration_tests.rs (expand test coverage)

### 11. Update Documentation for MVP Implementation

**Current State**: README exists but doesn't reflect MVP features.

**Implementation Details**:
- Update README to reflect MVP capabilities
- Add examples for all MVP commands
- Document the configuration file format
- Add troubleshooting guidance for common issues
- Update man pages if they exist

**Files to Modify**:
- README.md (update for MVP features)

## Implementation Order

1. TOML Configuration Persistence for Mounts
2. Mount Point Organization and Naming Convention
3. Daemon Auto-Mount on Startup
4. Mount State Persistence
5. Detach Option for Daemon Start
6. Connection Monitoring and Automatic Reconnection
7. Basic Exponential Backoff for Reconnection
8. Error Handling and User Feedback
9. Integration Tests
10. Documentation Updates

## Testing Strategy

Each feature will be tested with:
- Unit tests for individual components
- Integration tests for end-to-end functionality
- Manual testing with real NFS/SMB servers
- Error scenario testing

## Success Criteria

The MVP will be considered complete when:
1. A user can start the daemon in detached mode
2. Previously configured mounts are automatically restored on daemon startup
3. Mounts are organized under /mnt/fuji/ with proper naming
4. Lost connections are automatically reconnected with exponential backoff
5. Mount state persists between daemon restarts
6. All commands provide clear, actionable feedback
7. All features are covered by integration tests
8. Documentation is updated to reflect MVP capabilities