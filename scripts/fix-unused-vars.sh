#!/bin/bash

# Fix unused variables in the codebase

set -e

echo "=== Fixing unused variables ==="

# Fix unused variables by prefixing with underscore
# Note: This is a semi-automated process - please review changes

# List of files with unused variables
files=(
    "src/cli/mod.rs:368"
    "src/cli/mod.rs:1049"
    "src/daemon/mod.rs:228"
    "src/daemon/mod.rs:267"
    "src/daemon/mod.rs:270"
    "src/daemon/mod.rs:102"
    "src/daemon/mod.rs:109"
    "src/daemon/mod.rs:127"
    "src/monitoring/scheduler.rs:248"
    "src/monitoring/retry.rs:228"
    "src/monitoring/dependency.rs:248"
    "src/monitoring/dependency.rs:243"
    "src/security/file_provider.rs:109"
    "src/mount/drivers/sshfs.rs:55"
    "src/mount/drivers/sshfs.rs:58"
    "src/mount/drivers/sshfs.rs:103"
    "src/mount/point.rs:308"
    "src/mount/point.rs:309"
    "src/monitoring/health_checks.rs:57"
    "src/monitoring/health_checks.rs:171"
    "src/monitoring/health_checks.rs:247"
    "src/monitoring/health_checks.rs:376"
    "src/socket/mod.rs:181"
)

echo "Found ${#files[@]} files with unused variables"
echo ""
echo "Please manually review and fix these unused variables by:"
echo "1. Prefixing them with underscore if they're intentionally unused"
echo "2. Using them if they should be used"
echo "3. Removing them if they're unnecessary"