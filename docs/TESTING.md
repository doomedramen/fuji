# Testing Fuji

This document describes how to test Fuji, including unit tests, integration tests, and manual testing.

## Prerequisites

- Docker and Docker Compose
- Linux environment (for integration tests)
- Rust toolchain

## Running Tests

### Unit Tests

```bash
# Run all unit tests
cargo test

# Run with logging
RUST_LOG=debug cargo test
```

### Integration Tests

The integration tests use Docker containers to create real NFS and SMB servers for testing.

#### Option 1: Run with the script

```bash
# Run all integration tests with setup/teardown
./scripts/run-integration-tests.sh
```

#### Option 2: Run manually

```bash
# Start test servers
docker-compose up -d nfs-server smb-server

# Wait for servers to be ready
sleep 10

# Run integration tests
RUST_LOG=debug cargo test --test integration_tests

# Cleanup
docker-compose down -v
```

### Manual Testing

#### Quick Start

1. Build Fuji:
```bash
cargo build --release
```

2. Start the daemon:
```bash
# In terminal 1
./target/release/fuji daemon start
```

3. In another terminal, test mounting:
```bash
# Mount an NFS share
./target/release/fuji mount nfs://your-server/path/to/share

# Check status
./target/release/fuji status

# Unmount
./target/release/fuji unmount server_nfs

# Stop daemon
./target/release/fuji daemon stop
```

## Test Environment

### Docker Containers

The test environment includes:

1. **NFS Server** (Alpine Linux)
   - Exports `/exports/data` (read-write)
   - Exports `/exports/media` (read-only)
   - Exports `/exports/iso` (read-write)
   - Runs standard NFS daemon

2. **SMB Server** (Samba)
   - Shares: `data`, `media`, `public`
   - Test user: `testuser` / `testpass`
   - Guest access for `public` share

3. **Debian Test Client**
   - Builds Fuji from source
   - Runs tests against both servers
   - Has all necessary mount tools installed

### Test Scenarios Covered

1. **Basic Mount Operations**
   - Mount NFS share
   - Mount SMB share
   - Verify mount point creation
   - Test file access

2. **Configuration Persistence**
   - Mount shares and check configuration
   - Stop and restart daemon
   - Verify auto-mount on startup

3. **Error Handling**
   - Invalid URLs
   - Unreachable servers
   - Permission denied
   - Mount point conflicts

4. **Daemon Lifecycle**
   - Start in foreground
   - Start detached
   - Graceful shutdown
   - Clean unmount on exit

5. **Connection Monitoring**
   - Simulate network failure
   - Verify reconnection attempts
   - Check exponential backoff

## Debugging Tests

### Enabling Debug Logging

```bash
RUST_LOG=debug cargo test
RUST_LOG=trace cargo test  # Very verbose
```

### Checking Container Status

```bash
# See container status
docker-compose ps

# View logs
docker-compose logs nfs-server
docker-compose logs smb-server
docker-compose logs debian-test
```

### Manual Inspection

```bash
# Enter test container
docker-compose exec debian-test /bin/bash

# Check mounts
mount | grep fuji

# Check NFS exports
showmount -e nfs-server

# Check SMB shares
smbclient -L smb-server -U testuser%testpass
```

## Test Coverage Requirements

The MVP must have tests covering:

- [ ] All CLI commands work as specified
- [ ] Unix socket communication works
- [ ] NFS mounts work with real servers
- [ ] Configuration persists across restarts
- [ ] Auto-mount on daemon startup works
- [ ] Daemon handles graceful shutdown
- [ ] Error handling provides clear messages
- [ ] Mount points are created correctly
- [ ] Clean unmounting and cleanup

## Platform-Specific Testing

### Linux

- Primary development platform
- Full feature testing

### macOS

- Basic functionality testing
- Daemon behavior in macOS
- Note: Some features require special permissions

## Performance Testing

### Test Scenarios

1. Multiple simultaneous mounts
2. Large file transfers
3. Long-running stability
4. Resource usage monitoring

### Example Load Test

```bash
# Mount multiple shares
for i in {1..10}; do
  ./target/release/fuji mount nfs://server/share$i &
done
wait

# Monitor performance
./target/release/fuji status --verbose --watch
```

## Troubleshooting

### Common Issues

1. **Permission denied errors**
   - Ensure running with sufficient privileges
   - Check mount directory permissions

2. **Docker container failures**
   - Verify Docker is running
   - Check port conflicts (2049, 445, 139)

3. **Mount failures**
   - Check server connectivity
   - Verify share exists
   - Check firewall settings

4. **Daemon won't start**
   - Check socket file permissions
   - Verify no other daemon instance
   - Check PID file location

### Cleaning Up Test State

```bash
# Remove all mount points
sudo umount -l /mnt/fuji/*
sudo rm -rf /mnt/fuji/*

# Remove configuration
rm -rf ~/.config/fuji/mounts.toml
rm -rf /tmp/fuji/

# Remove Docker resources
docker-compose down -v --remove-orphans
docker system prune -f
```