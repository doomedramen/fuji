# Fuji Project Specification

## Overview

Fuji is a sophisticated daemon-based network file system mount manager designed for Linux systems. It provides persistent, secure, and clustered management of network file system mounts with support for NFS, SMB/CIFS, and SSHFS protocols. The project is implemented in Rust with a focus on security, reliability, and enterprise-grade features.

## Architecture

Fuji follows a client-server architecture where:

- **CLI Client**: Provides command-line interface for user interaction
- **Daemon Process**: Runs in background managing mounts, monitoring, and cluster operations
- **Unix Socket Communication**: Secure IPC between CLI and daemon
- **Cluster Networking**: TCP-based communication between cluster nodes

## CLI Commands

### Mount Management

#### `mount <url> [options]`
Mounts a network share at a specified or auto-generated mount point. The command validates the URL format, checks for conflicts with existing mounts, and securely creates the mount point if it doesn't exist.

**Arguments:**
- `url`: Network share URL in format `protocol://host/share/path` (e.g., nfs://192.168.1.1/data, smb://server/share)

**Options:**
- `-m, --mount-point <PATH>`: Custom mount point location. If not specified, auto-generates under default mount directory (/mnt/fuji or platform-specific)
- `-O, --options <OPTIONS>`: Mount-specific options passed to underlying mount command (e.g., "rw,soft,timeo=30" for NFS)
- `-d, --disable`: Create mount entry in configuration but don't activate it immediately
- `--dry-run`: Preview what would happen without executing the mount operation
- `--progress`: Show real-time progress during mount operation

**Behavior:**
- Validates mount point path using enhanced path security validator
- Checks for existing mounts at the same location
- Creates parent directories if needed with secure permissions
- Stores encrypted credentials if authentication required
- Updates mount status to Active on success, Failed on error
- Returns mount ID for future operations

#### `unmount <mount-id> [options]`
Unmounts an active mount and updates its status. Attempts graceful unmount first, then forced unmount if necessary.

**Arguments:**
- `mount-id`: Unique identifier of the mount to unmount (format: numeric ID)

**Options:**
- `-f, --force`: Force unmount even if in use or if graceful unmount fails

**Behavior:**
- Validates mount exists and is in Active state
- Attempts platform-specific unmount command (umount on Unix)
- Updates mount status to Disabled on success
- Preserves mount configuration for future remounting
- Returns error if mount not found or already unmounted

#### `remount <mount-id>`
Forces reconnection of a mount by performing an unmount followed by a mount operation with the same configuration. Useful for recovering from network issues.

**Arguments:**
- `mount-id`: Mount identifier to remount

**Behavior:**
- Validates mount exists in configuration
- If currently active, performs unmount first
- Reuses original mount options and credentials
- Updates mount status to InProgress during operation
- Resets reconnection attempt counter on success

#### `enable <mount-id>` / `disable <mount-id>`
Changes the enabled state of a mount without removing it from configuration. Disabled mounts are ignored during auto-mount operations.

**Arguments:**
- `mount-id`: Mount identifier to enable/disable

**Behavior:**
- Enable: Marks mount as enabled for auto-mounting
- Disable: Marks mount as disabled; unmounts if currently active
- Preserves all mount configuration and credentials
- Updates mount status accordingly

#### `remove <mount-id>`
Completely removes a mount from configuration. This is a destructive operation that cannot be undone.

**Arguments:**
- `mount-id`: Mount identifier to remove

**Behavior:**
- Auto-unmounts if currently active
- Removes all stored configuration and credentials
- Deletes mount point directory if empty
- Removes mount from all cluster nodes if in cluster mode
- Returns error if mount doesn't exist

### Information Commands

#### `status [options]`
Displays current status of all mounts with real-time health information and visual indicators.

**Options:**
- `-v, --verbose`: Shows detailed information including health scores, last connected time, reconnection attempts, error messages, and mount options
- `-w, --watch`: Continuous monitoring mode that refreshes every 2 seconds. Press Ctrl+C to stop. Shows live status changes with animated transitions
- `--filter-point <REGEX>`: Filter mounts by mount point pattern using regular expressions
- `--filter-url <REGEX>`: Filter mounts by URL pattern using regular expressions
- `--filter-type <TYPE>`: Filter by protocol type (nfs, smb, sshfs)
- `--filter-status <STATUS>`: Filter by status (Active, Reconnecting, Failed, Disabled, InProgress, Error)
- `-j, --json`: Output in machine-readable JSON format with full metadata

**Display Features:**
- Color-coded status indicators: 🟢 Active, 🟡 Reconnecting/InProgress, 🔴 Failed/Error, ⚫ Disabled
- Health scores from 0-100 for active mounts
- Connection uptime and last attempt timestamps
- Automatic column sizing for terminal width

#### `list [options]`
Lists all configured mounts regardless of current state, showing stored configuration without runtime status.

**Options:**
- `--enabled`: Show only enabled mounts (those that will auto-mount)
- `--disabled`: Show only disabled mounts (those ignored during auto-mount)
- `--filter-point <REGEX>`: Filter by mount point path pattern
- `--filter-url <REGEX>`: Filter by server URL pattern
- `--filter-type <TYPE>`: Filter by protocol type
- `-j, --json`: Output in JSON format for automation

**Information Displayed:**
- Mount ID (numeric identifier)
- Server URL with protocol
- Mount point path
- Creation timestamp
- Current enabled/disabled state
- Mount type and options

#### `discover <url>`
Discovers available shares on a server by querying the server's export list or share listing.

**Arguments:**
- `url`: Server URL for discovery (e.g., nfs://192.168.1.1, smb://server)

**Behavior:**
- For NFS: Uses `showmount -e` command to list exported shares
- For SMB: Uses `smbclient -L` to list available shares
- Requires network connectivity to target server
- May require authentication credentials depending on server configuration
- Returns list of share names and paths that can be used with mount command

### Daemon Management

#### `daemon start [options]`
Starts the Fuji daemon process in the background. The daemon manages all mount operations, monitoring, and cluster synchronization.

**Options:**
- `--no-automount`: Skip auto-mounting of enabled shares on startup. Mounts must be manually started
- `--disable-resource-limits`: Disable resource limit monitoring (note: this feature is permanently disabled in current implementation)

**Startup Process:**
- Checks for existing daemon instance via PID file
- Loads configuration from platform-specific locations
- Initializes security components with high-security profile
- Sets up signal handlers for graceful shutdown (SIGINT, SIGTERM)
- Writes PID file to prevent multiple instances
- Optionally daemonizes (detaches from terminal)
- Starts Unix socket server for CLI communication
- Begins monitoring loop and cluster operations if configured

#### `daemon stop`
Stops the running daemon gracefully through socket communication.

**Behavior:**
- Sends shutdown signal to daemon via Unix socket
- Waits for daemon to complete operations
- Removes socket and PID files
- Returns error if daemon not running

#### `daemon logs [lines?]`
Displays recent daemon log entries with optional line limit.

**Arguments:**
- `lines`: Optional number of lines to show (default: 50, all: 0)

**Behavior:**
- Reads from primary log file location
- Shows timestamps, log levels, and messages
- Supports log rotation if configured
- Can be combined with system log tools (journalctl on Linux)

### Configuration Management

#### `config show [-j]`
Displays the complete current configuration in human-readable or JSON format.

**Options:**
- `-j, --json`: Output in structured JSON format for programmatic use

**Behavior:**
- Shows all configuration sections including global settings, resource limits, reconnection policy, and cluster configuration
- Includes current effective values and defaults
- Shows configuration file location and last modified time

#### `config get <key> [-j]`
Retrieves a specific configuration value using dot notation for nested keys.

**Arguments:**
- `key`: Configuration key path (e.g., "global.health_check_interval_secs", "reconnection.max_retries")

**Options:**
- `-j, --json`: Output in JSON format

**Examples:**
- `fuji config get global.health_check_interval_secs` - Returns: 30
- `fuji config get reconnection.backoff_multiplier` - Returns: 2.0

#### `config set <key> <value>`
Sets a configuration value with validation and atomic save.

**Arguments:**
- `key`: Configuration key path using dot notation
- `value`: New configuration value (must be valid type for the key)

**Behavior:**
- Validates value type and range
- Performs atomic write using temporary file
- Triggers configuration reload in daemon
- Updates cluster nodes if in cluster mode

#### `config list [-j]`
Lists all available configuration keys with their current values and descriptions.

**Options:**
- `-j, --json`: Output in JSON format including type information

**Behavior:**
- Shows hierarchical structure of configuration
- Includes default values where applicable
- Provides brief descriptions for each setting

#### `config reset [-f]`
Resets configuration to factory defaults, backing up current configuration.

**Options:**
- `-f, --force`: Skip confirmation prompt

**Behavior:**
- Creates backup of current configuration
- Resets all values to hardcoded defaults
- Requires daemon restart for full effect
- Warning: This removes all custom mount configurations

#### `config edit`
Opens the configuration file in the system's default editor for manual editing.

**Behavior:**
- Launches $EDITOR or fallback editor
- Validates syntax on save
- Shows line numbers for error reporting
- Automatically reloads configuration in daemon

### Service Management

#### `service generate [options]`
Generates a systemd service file for system integration, allowing Fuji to run as a system service.

**Options:**
- `-o, --output <PATH>`: Output file path (default: stdout)
- `-n, --name <NAME>`: Service name (default: fuji)
- `-u, --user <USER>`: User to run service as (default: root)
- `--work-dir <DIR>`: Working directory for the daemon

**Generated Service Features:**
- Restart policy on failure
- Proper PID file handling
- Log redirection to journal
- Dependency on network-online.target
- Type=forking for daemon process

**Installation:**
```bash
fuji service generate -o /etc/systemd/system/fuji.service
systemctl daemon-reload
systemctl enable fuji
systemctl start fuji
```

### Cluster Management

#### `cluster info`
Displays cluster information including node ID, peer list, and generates a join invitation token.

**Behavior:**
- Shows current cluster membership status
- Displays instance ID and node identifiers
- Generates signed invitation with expiration (default 24 hours)
- Shows cluster port and network configuration
- Lists connected/disconnected peers

#### `cluster join <invitation>`
Joins an existing cluster using a cryptographically signed invitation token.

**Arguments:**
- `invitation`: Signed invitation string from existing cluster member

**Join Process:**
- Validates signature and expiration
- Extracts cluster metadata and peer list
- Establishes TCP connections to cluster members
- Synchronizes existing mount configurations
- Begins participation in cluster operations

#### `cluster status`
Shows detailed cluster member status and synchronization state.

**Information Displayed:**
- Local node status (Connected, Disconnected, Suspended)
- Peer node statuses and last seen times
- Synchronization queue status
- Network connectivity status
- Cluster-wide configuration version

#### `cluster leave`
Leaves the current cluster gracefully, notifying all peers of the departure.

**Behavior:**
- Sends departure notification to all peers
- Closes cluster TCP connections
- Stops cluster synchronization
- Preserves local configuration
- Can rejoin later with new invitation

#### `cluster history`
Displays historical log of cluster synchronization events and configuration changes.

**Information Includes:**
- Sync operation timestamps
- Conflict resolutions
- Node join/leave events
- Configuration version changes
- Error conditions and recovery

#### `cluster sync-force`
Forces immediate synchronization with all cluster members, bypassing the normal sync interval.

**Behavior:**
- Initiates sync operation immediately
- Bypasses 60-second sync interval check
- Useful after manual configuration changes
- May cause temporary service disruption

### Utility Commands

#### `doctor`
Performs comprehensive system health checks and provides diagnostic information with suggested fixes.

**Checks Performed:**
- Binary availability in PATH
- System dependencies (mount utilities, network tools)
- Configuration directory permissions
- Runtime directory access
- Mount directory permissions
- Network connectivity tests
- Privilege escalation capabilities
- Daemon status check
- systemd service availability
- Log directory accessibility
- SUID/SGID binary verification

**Output Format:**
- Color-coded results (✓ Pass, ✗ Fail, ⚠ Warning)
- Detailed error messages
- Suggested remediation steps
- System information summary

#### `batch <file> [options]`
Executes multiple operations from a JSON or YAML configuration file for automation and bulk operations.

**Arguments:**
- `file`: Path to batch configuration file

**Options:**
- `-c, --continue-on-error`: Continue executing remaining operations after errors
- `--dry-run`: Preview operations without executing

**Batch File Format:**
```yaml
operations:
  - type: mount
    url: nfs://server/share
    options: "rw,soft"
  - type: wait
    seconds: 5
  - type: enable
    mount_id: 1
  - type: echo
    message: "Operations complete"
```

**Supported Operations:**
- mount: Mount a share
- unmount: Unmount a share
- enable: Enable a mount
- disable: Disable a mount
- remove: Remove a mount
- wait: Pause execution
- echo: Display message

## Daemon Lifecycle

### 1. Initialization Phase

The daemon initialization follows a carefully ordered sequence to ensure reliable startup:

#### 1.1 Platform Detection and Path Setup
- Detects operating system (Linux, macOS, BSD)
- Sets up platform-specific paths:
  - **Linux**: Config `/etc/fuji/mounts.toml`, Socket `$XDG_RUNTIME_DIR/fuji.sock` or `/tmp/fuji.sock`
  - **macOS**: Config `~/Library/Application Support/fuji/mounts.toml`, Socket `/tmp/fuji.sock`
  - **Runtime Directory**: Creates if doesn't exist with appropriate permissions

#### 1.2 Single Instance Check
- Reads PID file from `{socket_path}.pid`
- Validates if process with PID exists and is Fuji
- Exits with error if daemon already running
- Creates new PID file with current process ID

#### 1.3 Configuration Loading
- Loads TOML configuration file with defaults:
  ```toml
  [global]
  health_check_interval_secs = 30
  log_level = "info"
  auto_mount = true

  [reconnection]
  max_retries = 5
  initial_delay_ms = 1000
  max_delay_ms = 60000
  backoff_multiplier = 2.0
  ```
- Validates configuration structure and values
- Creates default configuration if none exists

#### 1.4 Security Component Initialization
- **Path Security Validator**: Initializes with High security profile
  - Enables symlink attack detection
  - Sets dangerous file detection
  - Configures mount boundary enforcement
- **Resource Limits Manager**: Currently permanently disabled but initialized
- **Mount Registry**: Registers all configured mount points for monitoring

#### 1.5 Cluster Initialization (if enabled)
- **Instance Manager**: Generates unique instance ID using system information
- **Cluster State**: Loads peer list and status information
- **TCP Transport**: Initializes on port 10080 (configurable)
- **Sync Coordinator**: Sets up synchronization state machine

#### 1.6 Signal Handler Setup
- Registers handlers for SIGINT and SIGTERM
- Configures graceful shutdown behavior
- Sets up cleanup routines

#### 1.7 Daemonization (optional)
- Forks process if not running in foreground
- Detaches from terminal
- Sets up proper file descriptor handling
- Writes parent exit status

### 2. Main Event Loop

The daemon runs three concurrent Tokio tasks:

#### 2.1 Socket Server Task
**Purpose**: Handle CLI communication and command processing

**Operations**:
- Listens on Unix domain socket with connection limit (max 100)
- Implements rate limiting (10 requests per second per client)
- Accepts JSON-encoded requests:
  - Mount requests with URL and options
  - Unmount requests with mount ID
  - Status queries with filters
  - List operations
  - Configuration changes
- Routes requests to appropriate handlers
- Sends JSON responses with success/error status
- Maintains connection state and timeout handling

**Security Features**:
- Socket permissions restricted to owner
- Connection validation and authentication
- Request size limits to prevent DoS
- Timeout on idle connections (30 seconds)

#### 2.2 Monitoring Loop Task
**Interval**: Every 30 seconds (configurable via `global.health_check_interval_secs`)

**Startup Operations** (first run only):
- If `auto_mount=true`: Attempts to mount all enabled shares
- Tracks initial mount attempts and failures

**Regular Operations**:
- **Health Check Execution** for each active mount:
  1. Validates mount point exists (-50 penalty if missing)
  2. Checks directory readability (-30 penalty if unreadable)
  3. Performs protocol-specific network checks:
     - NFS: Ping host with 1-second timeout (-20 if unreachable)
     - SMB: Check port 445 connectivity (-20 if closed)
  4. Tests file write capability in mount (-25 if fails)
  5. Calculates health score (0-100) based on results
- **Reconnection Attempts** for failed mounts:
  - Checks if enough time has passed since last attempt
  - Uses exponential backoff: `delay = 1000ms × 2^attempts`
  - Maximum delay capped at 60 seconds
  - Maximum retry count: 5 (configurable)
- **Path Security Validation**:
  - Scans for symlink attacks
  - Checks for dangerous files in mount points
  - Validates mount boundaries
  - Logs security events and violations

#### 2.3 Cluster Operations Task (if enabled)
**Continuous Operations**:
- **Peer Connection Management**:
  - Maintains TCP connections to all cluster peers
  - Handles connection failures and reconnections
  - Monitors peer health via heartbeat messages (10-second interval)
- **Message Handling**:
  - Processes incoming cluster messages
  - Routes to sync coordinator or state manager
  - Handles protocol-specific message types
- **Synchronization Coordination**:
  - Monitors configuration changes
  - Initiates sync operations when needed
  - Manages conflict resolution

**Periodic Operations** (every 60 seconds):
- **Sync Coordinator Check**:
  - Evaluates if synchronization is needed
  - Initiates sync if timeout expired or changes detected
  - Manages pending sync queue

### 3. Shutdown Process

The daemon shutdown sequence ensures clean termination:

#### 3.1 Signal Reception
- Catches SIGINT or SIGTERM from signal handler
- Sets internal shutdown flag
- Stops accepting new connections

#### 3.2 Graceful Termination
- **Socket Server**: Stops accepting new connections, finishes existing requests
- **Monitoring Loop**: Complements current health check cycle
- **Cluster Operations**: Sends departure notifications to peers, closes connections

#### 3.3 Mount Cleanup
- Iterates through all active mounts
- Attempts graceful unmount for each
- Forces unmount if graceful fails
- Updates mount states to Disabled

#### 3.4 Resource Cleanup
- Removes Unix socket file
- Removes PID file
- Closes all file descriptors
- Releases memory allocations
- Exits with success status

#### 3.5 Error Handling During Shutdown
- Logs any cleanup failures
- Continues with remaining cleanup steps
- Forces exit if cleanup hangs (after 30 seconds)

### 4. Error Handling and Recovery

#### 4.1 Mount Operation Failures
- Updates mount status to Failed with error message
- Increments retry counter
- Schedules reconnection attempt with backoff
- Continues monitoring other mounts

#### 4.2 Network Issues
- Cluster connections: Automatic reconnection with exponential backoff
- Socket server: Continues running, logs connection errors
- Health checks: Marks mounts as Failed, continues attempts

#### 4.3 Configuration Errors
- Validates on load, exits if invalid
- Atomic saves prevent corruption
- Backups created before major changes
- Can reset to defaults if corrupted

#### 4.4 Resource Exhaustion
- Connection limits prevent socket exhaustion
- Rate limiting prevents command floods
- Memory usage monitored and limited
- File descriptor limits enforced

## Clustering System

### Architecture
The clustering system provides multi-node coordination with:

- **Instance Manager**: Generates unique instance IDs and manages node identity
- **Cluster State**: Tracks peer information, status, and sync metadata
- **TCP Transport**: Handles reliable message delivery between nodes
- **Sync Coordinator**: Orchestrates distributed configuration synchronization

### Node Discovery
Nodes join clusters through signed invitations containing:
- Digital signature verification
- Pre-shared key authentication
- Expiration timestamp validation
- Cluster metadata

Once verified, nodes establish bidirectional TCP connections for ongoing communication.

### Synchronization Algorithm
1. **Periodic Checks**: Coordinator checks every 60 seconds if sync is needed
2. **Sync Initiation**: Sends sync requests to all healthy peers
3. **Response Collection**: Gathers configurations within timeout window
4. **Merge Operation**: Resolves conflicts using priority-based rules
5. **Distribution**: Broadcasts merged configuration to all nodes
6. **Completion**: Confirms sync completion across cluster

### Fault Tolerance
- Automatic reconnection on connection loss
- Configurable retry backoff mechanisms
- Peer timeout detection and status tracking
- Graceful degradation when peers unavailable
- Persistent configuration storage for recovery

## Security Features

### Encryption and Credential Management
- **Algorithms**: ChaCha20-Poly1305 (default), AES-256-GCM
- **Key Derivation**: PBKDF2 with minimum 60,000 iterations
- **Storage Providers**: System keyring, encrypted files, environment variables
- **Forward Secrecy**: Support for perfect forward secrecy

### System Call Filtering
- **Seccomp Integration**: Linux seccomp BPF filters for syscall restriction
- **Security Profiles**: Minimal, Network, FileSystem, Mount, Daemon profiles
- **Violation Tracking**: Syscall counting and security event logging
- **Platform Adaptation**: Fallback validation for non-Linux systems

### Path Security
- **Runtime Validation**: Continuous monitoring of mounted paths
- **Symlink Protection**: Depth limits and dangerous file detection
- **Mount Boundary Enforcement**: Prevents escape from mount points
- **Security Profiles**: Minimal, Standard, High, Maximum security levels

### Command Security
- **Allowlist Validation**: Strict validation of mount commands
- **Injection Prevention**: Path sanitization and secure argument escaping
- **Secure Execution**: Wrapped system commands with security validation

## Mount System

### Protocol Support
- **NFS**: Network File System with auto-discovery and secure mounting
- **SMB/CIFS**: Windows file sharing with domain authentication support
- **SSHFS**: SSH-based filesystem with key authentication

### Mount Lifecycle
1. **Configuration**: Mount definitions stored with metadata
2. **Validation**: Security and dependency validation
3. **Execution**: Secure mount command execution
4. **Monitoring**: Continuous health and integrity checks
5. **State Management**: State machine tracking mount status transitions
6. **Recovery**: Automatic reconnection with exponential backoff

### Mount States
- **Active**: Successfully mounted and operational
- **Reconnecting**: Attempting to restore connection
- **Failed**: Mount operation failed
- **Disabled**: Configured but not active
- **InProgress**: Currently mounting or unmounting
- **Error**: Error condition requiring intervention

## Monitoring and Health Checks

### System Monitoring
- Resource usage tracking (CPU, memory, network)
- Failed mount detection and reporting
- Cluster status and synchronization monitoring
- Security event logging and alerting

### Mount Health Checks
- **File Access Tests**: Read/write verification to mount points
- **Network Connectivity**: Host pings and port availability checks
- **Protocol Validation**: Native filesystem health verification
- **Status Scoring**: Health score calculation based on multiple metrics

### Security Monitoring
- Real-time security event logging
- Integrity verification of mounted filesystems
- Seccomp violation detection and reporting
- Path security validation and alerting

## Configuration System

### Configuration Sources
- System-wide configuration files
- User-specific configuration
- Environment variables
- Command-line arguments
- Cluster-synchronized settings

### Validation
- Schema-based configuration validation
- Security policy enforcement
- Dependency verification
- Platform-specific adaptation

### Persistence
- Atomic configuration updates
- Backup and rollback support
- Cluster-wide synchronization
- Migration support for version upgrades

## Platform Support

### Linux
- Full feature support including seccomp filtering
- Systemd integration
- Native NFS and SMB utilities
- Complete security framework

### macOS
- Adapted security measures
- Launch integration support
- Native file system utilities
- Partial seccomp emulation

## Development and Testing

### Test Coverage
- Unit tests for all major components
- Integration tests with Docker
- Security tests (injection, traversal, etc.)
- Performance benchmarks
- Cluster synchronization tests

### Build System
- Cargo-based build system
- Feature flags for optional components
- Cross-compilation support
- Dependency vulnerability scanning