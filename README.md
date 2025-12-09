# Fuji
> /📁/🗻

A daemon-based network file system mount manager for Linux and macOS.

## Features

- **Multi-protocol**: NFS, SMB/CIFS support
- **Persistent**: Mounts survive daemon restarts
- **Auto-reconnect**: Exponential backoff for lost connections
- **Secure**: Encrypted credentials, audit logging, sandboxed processes
- **Multi-instance**: Cluster support with automatic configuration synchronization

## Installation

### Homebrew (macOS)

```bash
brew tap doomedramen/fuji
brew install fuji
```

### From Source

```bash
# Dependencies (Debian/Ubuntu)
sudo apt-get install nfs-common cifs-utils

# Build
cargo build --release
sudo cp target/release/fuji /usr/local/bin/
```

## Quick Start

```bash
# Start daemon
fuji daemon start -d

# Mount shares
fuji mount nfs://server/export
fuji mount smb://server/share

# Check status
fuji status

# Unmount
fuji unmount <mount-id>

# Stop daemon
fuji daemon stop
```

## Cluster Mode

Fuji supports clustering multiple instances for automatic configuration synchronization:

### Setting up a Cluster

```bash
# On the first node, generate an invitation
fuji cluster info

# This will output something like:
# Cluster invitation: eyJ2ZXJzaW9uIjoiMS4wIiw...
# Share this with other nodes to join the cluster

# On other nodes, join the cluster
fuji cluster join <invitation-string>

# Check cluster status
fuji cluster status

# View sync history
fuji cluster history

# Force synchronization
fuji cluster sync-force

# Leave the cluster
fuji cluster leave
```

### Cluster Features

- **Automatic Sync**: Configurations synchronize every 5 minutes (configurable)
- **Conflict Resolution**: Timestamp-based with deterministic tie-breaking
- **Fault Tolerant**: Continues working even if some nodes go down
- **Secure**: Pre-shared key authentication for cluster communication

Mounts are organized under `/mnt/fuji/{hostname}_{protocol}/path`.

## Command Reference

### Mount Management
```bash
# Mount a network share
fuji mount <url> [--mount-point <path>] [--options <opts>]

# Unmount by ID
fuji unmount <mount-id>

# List all configured mounts
fuji list

# List active mounts
fuji status [--json]
```

### Daemon Management
```bash
# Start daemon
fuji daemon start [-d]  # -d for foreground

# Stop daemon
fuji daemon stop

# Restart daemon
fuji daemon restart

# Check daemon health
fuji doctor
```

### Cluster Management
```bash
# Generate cluster invitation
fuji cluster info

# Join cluster
fuji cluster join <invitation>

# Show cluster status
fuji cluster status

# Show sync history
fuji cluster history

# Force synchronization
fuji cluster sync-force

# Leave cluster
fuji cluster leave
```

### Configuration
```bash
# Show configuration
fuji config [--json]

# Get configuration value
fuji config get <key>

# Set configuration value
fuji config set <key> <value>

# Delete configuration value
fuji config delete <key>

# Reset configuration
fuji config reset [--force]

# Edit configuration in editor
fuji config edit
```

### Batch Operations
```bash
# Execute batch file
fuji batch <file> [--dry-run] [--continue-on-error]
```

## Configuration

Config locations (checked in order):
- `~/.config/fuji/mounts.toml`
- `/etc/fuji/mounts.toml`

Socket locations:
- `/run/fuji.sock`
- `/tmp/fuji.sock`

## Development

```bash
# Run tests
cargo test

# Integration tests (requires Docker)
docker-compose up --build
```

## License

ISC License
