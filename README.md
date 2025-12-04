# Fuji - Network File System Mount Manager
/📁/🗻
A daemon-based tool that manages network file system mounts automatically. The CLI communicates with a background daemon that handles all mounting operations, connection monitoring, and automatic reconnection.

## MVP Features

- **Daemon-based architecture**: Long-running daemon process that manages mounts
- **Unix socket communication**: Efficient communication between CLI and daemon
- **NFS support**: Mount NFS (Network File System) shares
- **Automatic reconnection**: Exponential backoff for reconnection attempts
- **Configuration persistence**: TOML-based configuration that persists across daemon restarts
- **Mount state persistence**: Enabled/disabled state maintained across restarts
- **Connection monitoring**: Periodic health checks and automatic reconnection
- **Detached daemon mode**: Option to run daemon in background
- **Improved error handling**: User-friendly error messages with actionable suggestions

## Prerequisites

- Rust 1.75+
- Linux system (for mount operations)
- Docker (for integration tests)
- nfs-common package (for NFS mounting)
- cifs-utils package (for SMB mounting)

## Building

```bash
cargo build --release
```

## Installation

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y nfs-common cifs-utils

# Build and install
cargo build --release
sudo cp target/release/fuji /usr/local/bin/
```

## Usage

### Starting the Daemon

```bash
# Start the daemon in foreground
fuji daemon start

# Start the daemon in background (detached mode)
fuji daemon start -d
# or
fuji daemon start --detach

# Check daemon status
fuji status

# Stop the daemon
fuji daemon stop
```

### Auto-mount on Startup

When the daemon starts, it automatically mounts all enabled shares from the configuration. Previously active mounts are restored without needing to run mount commands again. Mount attempts are staggered to avoid overwhelming the network.

### Mounting File Systems

```bash
# Mount an NFS share
fuji mount nfs://192.168.1.1/export

# Mount an SMB share
fuji mount smb://server/share

# Mount with CIFS protocol
fuji mount cifs://server/share
```

### Unmounting File Systems

```bash
# Unmount by ID (get ID from status command)
fuji unmount <mount-id>
```

When unmounting, the daemon marks the mount as disabled in the configuration but preserves the entry for future re-enabling.

### Checking Status

```bash
# Show daemon and mount status
fuji status
```

### Mount Point Organization

All mounts are organized under `/mnt/fuji/` with the naming convention `{hostname}_{protocol}/share`. For example:
- `nfs://192.168.1.1/data` → `/mnt/fuji/192.168.1.1_nfs/data`

### Automatic Reconnection

The daemon monitors all active mounts and automatically attempts to reconnect lost connections using exponential backoff:
- Initial delay: 1 second
- Maximum retries: 5 attempts
- Backoff multiplier: 2.0x
- Maximum delay: 60 seconds

## Docker Integration Tests

The project includes comprehensive integration tests using Docker Compose with real NFS and SMB servers.

### Running Integration Tests

```bash
# Build and run the complete test environment
docker-compose up --build

# Or run specific services
docker-compose up nfs-server smb-server
docker-compose up debian-test
```

### Test Environment

The docker-compose setup includes:

1. **NFS Server**: Alpine-based NFS server exporting `/exports`
2. **SMB Server**: Samba server with public share
3. **Debian Test Container**: Builds and tests the Fuji application

The test container:
- Builds the Rust application
- Starts the Fuji daemon
- Tests NFS mounting to `nfs://nfs-server/exports`
- Tests SMB mounting to `smb://smb-server/public`
- Verifies mount status and cleanup

## Architecture

```
┌─────────────┐    Unix Socket    ┌─────────────┐
│   CLI       │ ◄────────────────► │   Daemon    │
└─────────────┘                    └─────────────┘
                                        │
                                        ▼
                                ┌─────────────┐
                                │  Platform   │
                                │  (Linux)    │
                                └─────────────┘
                                        │
                                        ▼
                                ┌─────────────┐
                                │  System     │
                                │  Mount      │
                                │  Commands   │
                                └─────────────┘
```

### Components

- **CLI**: Command-line interface that communicates with the daemon
- **Daemon**: Background process that manages mounts and handles requests
- **Platform**: Linux-specific mounting implementation
- **System Integration**: Uses system mount/umount commands

## Configuration

The application stores mount configurations in TOML format. Configuration paths are checked in the following order:

1. `~/.config/fuji/mounts.toml`
2. `/etc/fuji/mounts.toml`
3. `/tmp/fuji/mounts.toml`

Socket paths are checked in this order:

1. `/run/fuji.sock`
2. `/tmp/fuji.sock`
3. `$XDG_RUNTIME_DIR/fuji.sock`

### Configuration Format

```toml
[mounts]
"192.168.1.1_nfs" = { id = "192.168.1.1_nfs", url = "nfs://192.168.1.1/data", mount_point = "/mnt/fuji/192.168.1.1_nfs/data", enabled = true, created_at = "2023-12-02T13:30:00Z", updated_at = "2023-12-02T13:30:00Z" }

[reconnection]
max_retries = 5
initial_delay_ms = 1000
max_delay_ms = 60000
backoff_multiplier = 2.0
```

## Error Handling

The application provides detailed error messages for common issues:

- Missing dependencies (nfs-common, cifs-utils)
- Invalid URLs
- Permission issues
- Network connectivity problems
- Mount failures

## Development

### Running Tests

```bash
# Run unit tests
cargo test

# Run integration tests (requires privileges)
cargo test --test integration_tests

# Run with logging
RUST_LOG=debug cargo test
```

### Code Structure

```
src/
├── main.rs          # CLI entry point
├── cli.rs           # CLI logic
├── daemon.rs        # Daemon implementation
├── config.rs        # Configuration management
├── platform.rs      # Platform-specific mounting
└── error.rs         # Error types

tests/
└── integration_tests.rs  # Comprehensive integration tests

docker-compose.yml         # Test environment
Dockerfile.debian         # Debian test container
```

## License

This project is licensed under the ISC License.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Troubleshooting

### Common Issues

**Daemon fails to start**
- Check if socket path is writable
- Verify no other daemon instance is running
- Check logs with `RUST_LOG=debug fuji daemon start`

**Mount operations fail**
- Verify nfs-common and cifs-utils are installed
- Check network connectivity to server
- Verify server is exporting shares
- Check permissions

**Integration tests fail**
- Ensure Docker is running
- Verify privileged mode for containers
- Check that ports 2049 (NFS) and 445 (SMB) are available

### Debug Mode

Enable debug logging:

```bash
RUST_LOG=debug fuji daemon start
RUST_LOG=debug fuji status
