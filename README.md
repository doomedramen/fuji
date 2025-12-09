# Fuji
> /📁/🗻

A daemon-based network file system mount manager for Linux and macOS.

## Features

- **Multi-protocol**: NFS, SMB/CIFS support
- **Persistent**: Mounts survive daemon restarts
- **Auto-reconnect**: Exponential backoff for lost connections
- **Secure**: Encrypted credentials, audit logging, sandboxed processes

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

Mounts are organized under `/mnt/fuji/{hostname}_{protocol}/path`.

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
