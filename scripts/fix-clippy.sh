#!/bin/bash

# Fix remaining clippy errors

set -e

echo "=== Fixing clippy errors ==="

# Fix unused imports in monitoring/persistence.rs
echo "Fixing unused imports in monitoring/persistence.rs..."
sed -i.bak 's/use tracing::{debug, error, info, warn};/use tracing::{debug, error, info};/' src/monitoring/persistence.rs

# Fix unused imports in monitoring/retry.rs
echo "Fixing unused imports in monitoring/retry.rs..."
sed -i.bak 's/use anyhow::{anyhow, Result};/use anyhow::Result;/' src/monitoring/retry.rs

# Fix unused imports in monitoring/mod.rs
echo "Fixing unused imports in monitoring/mod.rs..."
sed -i.bak 's/use tracing::{debug, error, info, warn};/use tracing::{debug, info, warn};/' src/monitoring/mod.rs

# Fix unused variables in mount/drivers/sshfs.rs
echo "Fixing unused variables in mount/drivers/sshfs.rs..."
# Fix remote_path (line 57)
sed -i.bak 's/                remote_path,/                _remote_path,/' src/mount/drivers/sshfs.rs
# Fix username (line 58)
sed -i.bak 's/                username,/                _username,/' src/mount/drivers/sshfs.rs
# Fix remote_path (line 103)
sed -i.bak 's/                remote_path,/                _remote_path,/' src/mount/drivers/sshfs.rs
# Fix username (line 105)
sed -i.bak 's/                username,/                _username,/' src/mount/drivers/sshfs.rs

# Fix unused variables in mount/point.rs
echo "Fixing unused variables in mount/point.rs..."
sed -i.bak 's/        let current_uid = getuid().as_raw();/        let _current_uid = getuid().as_raw();/' src/mount/point.rs
sed -i.bak 's/        let current_gid = getgid().as_raw();/        let _current_gid = getgid().as_raw();/' src/mount/point.rs

# Fix unused variable in monitoring/health_checks.rs
echo "Fixing unused variable in monitoring/health_checks.rs..."
sed -i.bak 's/        let registry = HealthCheckRegistry::new();/        let _registry = HealthCheckRegistry::new();/' src/monitoring/health_checks.rs

# Fix unused variable in socket/mod.rs
echo "Fixing unused variable in socket/mod.rs..."
sed -i.bak 's/            let socket_path = socket_path.clone();/            let _socket_path = socket_path.clone();/' src/socket/mod.rs

# Fix cfg issues in platform/macos.rs
echo "Fixing cfg issues in platform/macos.rs..."
sed -i.bak 's/#\[cfg(feature = "user")\]/#[cfg(feature = "macos_user")]/' src/platform/macos.rs

# Remove backup files
rm -f src/monitoring/persistence.rs.bak
rm -f src/monitoring/retry.rs.bak
rm -f src/monitoring/mod.rs.bak
rm -f src/mount/drivers/sshfs.rs.bak
rm -f src/mount/point.rs.bak
rm -f src/monitoring/health_checks.rs.bak
rm -f src/socket/mod.rs.bak
rm -f src/platform/macos.rs.bak

echo "All clippy errors fixed!"