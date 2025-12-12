# Fuji
> /📁/🗻

A daemon-based network file system mount manager for Linux (Debian/Ubuntu and other distributions).

## Features

- **Multi-protocol**: NFS, SMB/CIFS support
- **Persistent**: Mounts survive daemon restarts
- **Auto-reconnect**: Exponential backoff for lost connections
- **Secure**: Encrypted credentials, audit logging, sandboxed processes
- **Multi-instance**: Cluster support with automatic configuration synchronization

## Installation

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

### Using DevContainers (Recommended)

For consistent development environment across platforms, you can use Dev Containers either with VS Code or via the command-line interface.

#### Using with VS Code:
1. Install the "Dev Containers" extension in VS Code
2. Open the command palette (`Ctrl+Shift+P` or `Cmd+Shift+P`)
3. Select "Dev Containers: Reopen in Container"
4. The container will build with all necessary dependencies

#### Using with Dev Container CLI:
1. Install the `devcontainer` CLI by following the [official installation guide](https://github.com/devcontainers/cli#installation)
2. From your project directory, run:
```bash
devcontainer up --workspace-folder .
# Or to connect to the running container:
devcontainer exec --workspace-folder . bash
```

Once inside the container, you can run:
```bash
# Build the project
make build

# Run all tests
make test

# Run integration tests (with NFS/SMB test servers)
make test-integration

# Run CI checks locally
make ci
```

Alternatively, you can use the compose-based devcontainer which includes NFS/SMB test servers (works with both VS Code and CLI):
1. Using VS Code: Command Palette → "Dev Containers: Reopen in Container..." → Select docker-compose file → Choose `.devcontainer/docker-compose.devcontainer.json`
2. Using CLI: `devcontainer up --config .devcontainer/docker-compose.devcontainer.json --workspace-folder .`

When using the compose-based devcontainer (with NFS/SMB test servers), run integration tests directly without starting additional docker services:
```bash
# Run integration tests (the NFS/SMB servers are already running in the container environment)
cargo test integration_tests --all-features
```

## License

ISC License
