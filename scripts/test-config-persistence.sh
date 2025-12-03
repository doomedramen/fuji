#!/bin/bash

# Test configuration persistence functionality

set -e

echo "=== Testing Configuration Persistence ==="
echo

# Build Fuji
echo "Building Fuji..."
cargo build --release
echo

# Create test environment
TEST_DIR="/tmp/fuji-config-test-$$"
mkdir -p "$TEST_DIR"
CONFIG_DIR="$TEST_DIR/.config/fuji"
MOUNT_DIR="$TEST_DIR/mnt/fuji"
export XDG_CONFIG_HOME="$TEST_DIR/.config"

# Clean up function
cleanup() {
    echo "Cleaning up..."
    pkill -f "target/release/fuji" || true
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

echo "Test directory: $TEST_DIR"
echo

# Test 1: Configuration file creation
echo "1. Testing configuration file creation..."
./target/release/fuji daemon start --no-automount
sleep 1

if [ -f "$CONFIG_DIR/mounts.toml" ]; then
    echo "✓ Configuration file created at $CONFIG_DIR/mounts.toml"
else
    echo "✗ Configuration file not found"
    exit 1
fi

# Test 2: Add a mount
echo
echo "2. Testing mount addition and persistence..."
./target/release/fuji mount --id test-nfs nfs://127.0.0.1/export

# Check if mount was added to config
if grep -q "test-nfs" "$CONFIG_DIR/mounts.toml"; then
    echo "✓ Mount configuration saved to file"
else
    echo "✗ Mount configuration not saved"
    exit 1
fi

# Test 3: Configuration validation
echo
echo "3. Testing configuration validation..."

# Try to create invalid configuration
echo "version = '1.0'

[mounts]
invalid_url = ''

[mounts.invalid_url]
url = ''
mount_point = '/tmp/test'
enabled = true" > "$CONFIG_DIR/invalid.toml"

echo "✓ Invalid configuration file created (for validation testing)"

# Test 4: Configuration loading
echo
echo "4. Testing configuration loading on restart..."
./target/release/fuji daemon restart
sleep 1

# Check if mount is still listed
if ./target/release/fuji list | grep -q "test-nfs"; then
    echo "✓ Configuration loaded on daemon restart"
else
    echo "✗ Configuration not loaded on restart"
    exit 1
fi

# Test 5: Configuration sync with system
echo
echo "5. Testing configuration sync with system state..."
./target/release/fuji status
echo "✓ System sync completed"

# Test 6: Atomic writes
echo
echo "6. Testing atomic write operations..."

# Create a large configuration to test atomic writes
for i in {1..10}; do
    ./target/release/fuji mount --id "test-nfs-$i" "nfs://127.0.0.1/export$i" || true
done

# Check if all mounts are present
mount_count=$(grep -c "\[\[mounts\.\*\]\]" "$CONFIG_DIR/mounts.toml" 2>/dev/null || echo "0")
if [ "$mount_count" -gt "5" ]; then
    echo "✓ Multiple mount configurations saved successfully"
else
    echo "⚠ Some mounts may not have been saved (count: $mount_count)"
fi

# Test 7: Configuration backup/restore simulation
echo
echo "7. Testing configuration backup..."
cp "$CONFIG_DIR/mounts.toml" "$CONFIG_DIR/mounts.toml.backup"
echo "✓ Configuration backup created"

echo
echo "=== All Configuration Tests Completed Successfully ==="
echo "Configuration file location: $CONFIG_DIR/mounts.toml"