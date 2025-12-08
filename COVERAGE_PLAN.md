# Test Coverage Improvement Plan

**Current Coverage**: 34.39% (3,545/10,307 lines)
**Target Coverage**: 70% (7,214 lines needed)
**Gap**: ~3,669 additional lines to cover

---

## Priority Modules

### Tier 1: Zero Coverage - High Priority

| Module | Lines | Test Type | Notes |
|--------|-------|-----------|-------|
| `src/cli/mod.rs` | 547 | Unit + Integration | CLI argument parsing, command dispatch |
| `src/daemon/mod.rs` | 478 | Integration + Mock | Daemon lifecycle, mount operations |
| `src/mount/drivers/smb.rs` | 141 | Unit | URL parsing, credential handling |
| `src/mount/drivers/sshfs.rs` | 132 | Unit | URL parsing, SSH options |
| `src/mount/drivers/nfs.rs` | 125 | Unit | URL parsing, NFS options |

### Tier 2: Zero Coverage - Medium Priority

| Module | Lines | Test Type | Notes |
|--------|-------|-----------|-------|
| `src/security/security_dashboard.rs` | 509 | Unit + Mock | Metrics aggregation, alerts |
| `src/security/keyring_provider.rs` | 75 | Mock-based | Platform credential storage |
| `src/security/mod.rs` | 44 | Unit | Credential manager coordination |
| `src/daemon/monitor.rs` | 26 | Unit | Health state tracking |
| `src/socket/protocol.rs` | 4 | Unit | Request/Response serialization |

### Tier 3: Low Coverage (8-20%)

| Module | Current | Lines | Priority |
|--------|---------|-------|----------|
| `src/config/mod.rs` | 8% | 148 | HIGH - Easy win |
| `src/security/error.rs` | 9% | 189 | MEDIUM |
| `src/security/process_isolation.rs` | 10% | 244 | LOW - Linux only |
| `src/monitoring/health_checks.rs` | 11% | 154 | HIGH |
| `src/platform/linux.rs` | 16% | 166 | LOW - Linux only |
| `src/security/resource_limits.rs` | 20% | 217 | MEDIUM |

---

## Implementation Phases

### Phase 1: Quick Wins (Target: 40% coverage)

**Estimated gain**: +600 lines covered

1. **Expand `tests/unit/config_test.rs`**
   - Config creation and defaults
   - Serialization/deserialization
   - Validation logic
   - File I/O with tempfile

2. **Add mount driver URL parsing tests**
   - NFS URL formats (`nfs://host/path`)
   - SMB URL formats with credentials (`smb://user:pass@host/share`)
   - SSHFS URL formats (`ssh://`, `sshfs://`, `sftp://`)
   - Invalid URL handling

3. **Add `tests/unit/daemon_monitor_test.rs`**
   - Health state updates
   - Health retrieval by mount_id
   - Unhealthy mount detection

4. **Add `tests/unit/socket_protocol_test.rs`**
   - Request enum serialization
   - Response enum serialization

### Phase 2: Core Modules (Target: 55% coverage)

**Estimated gain**: +1,500 lines covered

1. **Expand `tests/unit/cli_test.rs`**
   - Mount command argument parsing
   - Unmount command parsing
   - Status/list command parsing
   - Credential subcommand parsing
   - Output format handling

2. **Add `tests/unit/health_checks_test.rs`**
   - Health check result creation
   - Timeout enforcement
   - Concurrent health checks
   - Semaphore permit management

3. **Expand `tests/unit/security_error_test.rs`**
   - Error variant creation
   - Display message formatting
   - Error cause chain
   - From trait implementations

4. **Add `tests/unit/resource_limits_test.rs`**
   - Config validation and defaults
   - Threshold comparison
   - Alert generation
   - History management

### Phase 3: Integration & Daemon (Target: 70% coverage)

**Estimated gain**: +1,500 lines covered

1. **Add `tests/unit/daemon_test.rs`**
   - Daemon initialization
   - Mount state transitions
   - Reconnection logic
   - Shutdown coordination

2. **Add `tests/unit/security_dashboard_test.rs`**
   - Dashboard initialization
   - Metrics aggregation
   - Alert threshold enforcement
   - Event deque management
   - Export format generation

3. **Add `tests/unit/keyring_provider_test.rs`**
   - Entry creation (mocked)
   - Credential serialization
   - Error handling
   - Platform fallback behavior

4. **Expand integration tests**
   - Mount lifecycle with Docker services
   - Multi-mount scenarios
   - Error recovery paths

---

## Test Patterns

### Unit Tests (Pure Logic)
```rust
#[test]
fn test_nfs_url_parsing() {
    let url = "nfs://server.example.com/exports/data";
    let result = NfsHandler::parse_url(url);
    assert!(result.is_ok());
    let config = result.unwrap();
    assert_eq!(config.host, "server.example.com");
    assert_eq!(config.path, "/exports/data");
}
```

### Async Tests (Tokio Runtime)
```rust
#[tokio::test]
async fn test_health_check_timeout() {
    let check = HealthCheck::new(Duration::from_millis(100));
    let result = check.run_with_timeout(slow_operation()).await;
    assert!(result.is_err());
}
```

### Mock-Based Tests (System Calls)
```rust
#[test]
fn test_keyring_store_with_mock() {
    let mock_keyring = MockKeyring::new();
    mock_keyring.expect_set_password()
        .returning(|_, _, _| Ok(()));

    let provider = KeyringProvider::new(mock_keyring);
    let result = provider.store("mount-1", &creds);
    assert!(result.is_ok());
}
```

---

## Running Coverage Locally

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Run coverage with HTML report
cargo tarpaulin --lib --output-dir target/coverage --out Html

# Run coverage with threshold check
cargo tarpaulin --lib --fail-under 70

# Run coverage for specific test
cargo tarpaulin --lib --test config_test
```

---

## Platform Considerations

- **Linux-only modules**: `process_isolation.rs`, `platform/linux.rs` - Test on Linux CI only
- **macOS modules**: `platform/macos.rs` - Test on macOS CI
- **Cross-platform**: Most modules work on both platforms

---

## Notes

- Focus on testable code paths first (pure functions, data transformations)
- Use `#[cfg(test)]` modules for test helpers within source files
- Mock external dependencies (keyring, file system, network)
- Add `#[ignore]` to tests requiring special setup (Docker, root privileges)
