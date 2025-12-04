# Fuji - Enterprise Network File System Mount Manager
/📁/🗻🔒
A production-ready, security-hardened daemon-based tool that manages network file system mounts automatically. Fuji provides enterprise-grade security with comprehensive audit logging, encrypted credential storage, and advanced monitoring capabilities.

## 🚀 Core Features

- **Daemon-based architecture**: Long-running daemon process that manages mounts
- **Unix socket communication**: Secure, efficient communication between CLI and daemon
- **Multi-protocol support**: Mount NFS, SMB/CIFS, and other network file systems
- **Automatic reconnection**: Intelligent exponential backoff for reconnection attempts
- **Configuration persistence**: TOML-based configuration that persists across daemon restarts
- **Mount state persistence**: Enabled/disabled state maintained across restarts
- **Connection monitoring**: Periodic health checks and automatic reconnection
- **Detached daemon mode**: Option to run daemon in background
- **Improved error handling**: User-friendly error messages with actionable suggestions

## 🛡️ Enterprise Security Features

### 🔐 Advanced Authentication & Credential Management
- **Hardware-backed credential storage** with HSM support
- **Encrypted credential files** using AES-256-GCM and ChaCha20-Poly1305
- **Multiple credential providers**: Environment variables, encrypted files, system keyring
- **Automatic key rotation** and secure credential lifecycle management
- **Zero-knowledge architecture**: Credentials never exposed in plain text

### 📊 Comprehensive Audit Logging
- **Tamper-evident audit trails** with cryptographic event chaining
- **Real-time security monitoring** and threat detection
- **Multiple audit event types**: Authentication, mount operations, configuration changes
- **Event severity classification** and automated alerting
- **Export capabilities** to JSON, CSV, Syslog, and CEF formats
- **Log rotation and retention** with configurable policies

### 🔒 Process Isolation & Sandboxing
- **Seccomp filtering** with comprehensive system call blacklisting
- **Namespace isolation** for filesystem and network separation
- **Resource limits** with CPU, memory, and file descriptor constraints
- **Privilege separation** and secure process spawning
- **Container-ready security** for deployment in restricted environments

### 🚨 Advanced Threat Protection
- **Intrusion detection** with pattern recognition and anomaly detection
- **Real-time monitoring** of authentication attempts and mount operations
- **Automated response** to security threats and suspicious activities
- **Connection limiting** and rate-based protection against attacks
- **Runtime integrity checks** for code and data verification

### 🔧 Secure Configuration Management
- **Encrypted configuration files** with secure key management
- **Configuration validation** and security policy enforcement
- **Secure update mechanisms** with code signing verification
- **Audit trail for all configuration changes**
- **Role-based access control** for administrative operations

### 🌐 Network Security
- **Encrypted communications** between CLI and daemon
- **Secure socket authentication** with mutual TLS support
- **Network isolation** and firewall-friendly operation
- **Comprehensive monitoring** of network connections and data transfers

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

# Show detailed daemon health information
fuji health

# Show security audit statistics
fuji audit stats
```

### 🔐 Security Management

```bash
# Store encrypted credentials for a mount
fuji credentials store nfs://server/share --username user --password pass

# List stored credentials
fuji credentials list

# Rotate credential encryption keys
fuji credentials rotate

# Create encrypted credential backup
fuji credentials backup --output backup.enc

# Restore credentials from backup
fuji credentials restore --input backup.enc
```

### 📊 Security Monitoring

```bash
# View recent security events
fuji audit events --last 24h --severity high

# Export audit logs
fuji audit export --format json --output audit.json

# Monitor for security threats in real-time
fuji monitor --alerts

# Generate security report
fuji security report --format csv --output security_report.csv
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

## 🏗️ Secure Architecture

```
┌─────────────┐  Secure Socket  ┌─────────────┐
│   CLI       │ ◄──────────────► │   Daemon    │
│ (Client)    │  (TLS/Auth)     │ (Sandboxed) │
└─────────────┘                └─────────────┘
         │                               │
         ▼                               ▼
┌─────────────┐                ┌─────────────┐
│ Credentials │                │   Security  │
│  Manager    │                │  Monitor    │
│ (HSM/Keyring)│               │ (Audit/IDs) │
└─────────────┘                └─────────────┘
                                        │
                                        ▼
                                ┌─────────────┐
                                │   Security  │
                                │   Layer     │
                                │ (Seccomp/    │
                                │  Namespaces) │
                                └─────────────┘
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

### 🔧 Security Components

- **CLI**: Secure client with encrypted communication
- **Daemon**: Sandboxed background process with privilege separation
- **Security Monitor**: Real-time intrusion detection and threat response
- **Credential Manager**: Hardware-backed secure credential storage
- **Security Layer**: Seccomp filtering, namespace isolation, resource limits
- **Platform**: Linux-specific secure mounting implementation
- **Audit System**: Comprehensive logging and event tracking

### 🛡️ Protection Mechanisms

- **Process Isolation**: Each component runs in isolated namespaces
- **System Call Filtering**: Seccomp BPF profiles restrict dangerous operations
- **Resource Constraints**: CPU, memory, and file descriptor limits
- **Secure Communication**: Mutual TLS authentication between components
- **Audit Trail**: Cryptographically signed event chain for tamper evidence
- **Threat Detection**: Pattern recognition for common attack vectors

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
├── main.rs                 # CLI entry point
├── cli.rs                  # CLI logic and command handling
├── daemon.rs               # Core daemon implementation
├── config.rs               # Configuration management and persistence
├── platform/               # Platform-specific implementations
│   ├── mod.rs             # Platform abstraction
│   ├── linux.rs           # Linux-specific mounting
│   └── mount_drivers/     # Filesystem driver implementations
├── security/               # 🔒 Comprehensive security framework
│   ├── mod.rs             # Security module coordinator
│   ├── audit_logging.rs   # Tamper-evident audit logging
│   ├── audit_monitoring.rs # Real-time threat detection
│   ├── authentication.rs  # Multi-factor authentication
│   ├── credential_backup.rs # Secure credential backup/restore
│   ├── encryption.rs      # Advanced encryption algorithms
│   ├── file_provider.rs   # Encrypted file credential storage
│   ├── hardware_credential_provider.rs # HSM integration
│   ├── key_derivation.rs  # Secure key derivation functions
│   ├── keyring_provider.rs # System keyring integration
│   ├── path_security.rs   # Advanced path validation
│   ├── permissions.rs     # Permission management system
│   ├── resource_limits.rs # Resource constraint enforcement
│   ├── seccomp.rs         # System call filtering
│   └── secure_socket.rs   # Encrypted socket communication
├── monitoring/             # Health and performance monitoring
│   ├── health.rs          # Health check system
│   └── metrics.rs         # Performance metrics
├── network/               # Network communication layer
│   ├── socket.rs          # Secure socket implementation
│   └── protocol.rs        # Communication protocol
└── error.rs               # Comprehensive error handling

tests/
├── integration_tests.rs          # Core integration tests
├── security/                    # 🔒 Security-focused test suite
│   ├── security_audit_logging_test.rs
│   ├── security_credential_storage_test.rs
│   ├── security_encryption_improvements.rs
│   ├── security_path_traversal.rs
│   └── security_command_injection.rs
├── unit/                        # Unit test modules
│   ├── mount_options_test.rs
│   ├── config_test.rs
│   ├── monitoring_test.rs
│   ├── platform_test.rs
│   ├── cli_test.rs
│   ├── mount_drivers_test.rs
│   └── daemon_error_test.rs
└── connection_limits_test.rs     # Connection security tests

docker-compose.yml              # Complete test environment
Dockerfile.debian              # Security-hardened test container
```

## 🔒 Security Testing

### Running Security Tests

```bash
# Run comprehensive security test suite
cargo test --test security_audit_logging_test
cargo test --test security_credential_storage_test
cargo test --test security_path_traversal
cargo test --test security_command_injection

# Run tests with security auditing enabled
RUST_LOG=debug FUJI_SECURITY_AUDIT=1 cargo test

# Test credential security features
cargo test --test security_encryption_improvements

# Generate security coverage report
./scripts/generate-security-coverage.sh
```

### Security Validation

The project includes extensive security testing covering:

- **Command Injection Prevention**: Validates all user input sanitization
- **Path Traversal Protection**: Tests filesystem access controls
- **Cryptographic Security**: Validates encryption key management and algorithms
- **Credential Storage Security**: Tests encrypted credential persistence
- **Audit Logging Integrity**: Verifies tamper-evident audit trails
- **Resource Limit Enforcement**: Tests protection against resource exhaustion
- **Seccomp Filtering**: Validates system call restriction mechanisms
- **Connection Security**: Tests encrypted communication protocols

### Security Best Practices

✅ **Input Validation**: All user input is rigorously validated and sanitized
✅ **Least Privilege**: Components run with minimal required permissions
✅ **Defense in Depth**: Multiple layers of security controls
✅ **Fail Secure**: System defaults to secure state on errors
✅ **Audit Everything**: Comprehensive logging of all security-relevant events
✅ **Regular Updates**: Security patches and updates applied promptly
✅ **Zero Trust**: No implicit trust in network communications
✅ **Secure Defaults**: Secure configuration out of the box

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
