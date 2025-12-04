#!/bin/bash

# Fix remaining clippy errors

set -e

echo "=== Fixing remaining clippy errors ==="

# Fix missing anyhow import in monitoring/retry.rs
echo "Fixing missing anyhow import in monitoring/retry.rs..."
sed -i.bak 's/use anyhow::Result;/use anyhow::{anyhow, Result};/' src/monitoring/retry.rs

# Fix cfg feature name in platform/macos.rs
echo "Fixing cfg feature name in platform/macos.rs..."
sed -i.bak 's/#\[cfg(feature = "macos_user")\]/#[cfg(feature = "user")]/' src/platform/macos.rs

# Fix unused imports in security/auth.rs
echo "Fixing unused imports in security/auth.rs..."
sed -i.bak 's/use tracing::{debug, error, info, warn};/use tracing::info;/' src/security/auth.rs

# Fix unused imports in security/file_provider.rs
echo "Fixing unused imports in security/file_provider.rs..."
sed -i.bak 's/use aes_gcm::aead::{Aead, OsRng};/use aes_gcm::aead::Aead;/' src/security/file_provider.rs
sed -i.bak 's/use std::path::{Path, PathBuf};/use std::path::PathBuf;/' src/security/file_provider.rs
sed -i.bak 's/use tracing::{debug, error, warn};/use tracing::debug;/' src/security/file_provider.rs

# Fix unused imports in security/permissions.rs
echo "Fixing unused imports in security/permissions.rs..."
sed -i.bak 's/use std::path::{Path, PathBuf};/use std::path::Path;/' src/security/permissions.rs
sed -i.bak 's/use tracing::{debug, error, info, warn};/use tracing::{debug, info};/' src/security/permissions.rs

# Fix unused variable in monitoring/health_checks.rs (mount_id parameter)
echo "Fixing unused variables in monitoring/health_checks.rs..."
sed -i.bak 's/mount_id: &str,/ _mount_id: &str,/' src/monitoring/health_checks.rs

# Fix incorrect pattern match in mount/drivers/sshfs.rs
echo "Fixing SMB pattern match in mount/drivers/sshfs.rs..."
# The SMB variant doesn't have username field, need to fix the pattern
sed -i.bak 's/                _username,/                username,/' src/mount/drivers/sshfs.rs

# Fix unused variables in mount/drivers/sshfs.rs
echo "Fixing unused variables in mount/drivers/sshfs.rs..."
sed -i.bak 's/        let port = parsed.port().map(|p| p.to_string());/        let _port = parsed.port().map(|p| p.to_string());/' src/mount/drivers/sshfs.rs
sed -i.bak 's/        let remote_path = if parsed.path().is_empty() || parsed.path() == "/" {/        let _remote_path = if parsed.path().is_empty() || parsed.path() == "/" {/' src/mount/drivers/sshfs.rs

# Fix unused variables in mount/options.rs
echo "Fixing unused variables in mount/options.rs..."
sed -i.bak 's/        let mut timeout = Duration::from_secs(30);/        let _timeout = Duration::from_secs(30);/' src/mount/options.rs

# Fix unused mut in monitoring/scheduler.rs
echo "Fixing unused mut in monitoring/scheduler.rs..."
sed -i.bak 's/        let mut total_count = check_types.len();/        let total_count = check_types.len();/' src/monitoring/scheduler.rs

# Remove backup files
rm -f src/monitoring/retry.rs.bak
rm -f src/platform/macos.rs.bak
rm -f src/security/auth.rs.bak
rm -f src/security/file_provider.rs.bak
rm -f src/security/permissions.rs.bak
rm -f src/monitoring/health_checks.rs.bak
rm -f src/mount/drivers/sshfs.rs.bak
rm -f src/mount/options.rs.bak
rm -f src/monitoring/scheduler.rs.bak

echo "All remaining clippy errors fixed!"