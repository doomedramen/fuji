#!/bin/bash

echo "=== Testing Health Monitoring Integration ==="
echo

# Stop any existing daemon
pkill -f "fuji daemon" 2>/dev/null || true
sleep 1

# Start the daemon
echo "Starting Fuji daemon..."
./target/release/fuji daemon start --no-automount
sleep 2

# Check daemon is running
if ./target/release/fuji status >/dev/null 2>&1; then
    echo "✓ Daemon is running"
else
    echo "✗ Daemon failed to start"
    exit 1
fi

# Test health command
echo
echo "Testing health command..."
./target/release/fuji health --verbose

# Test mounting with health check registration
echo
echo "Testing NFS mount (this will fail in test environment but should register health checks)..."
./target/release/fuji mount nfs://test-server.example.com/export /tmp/nfs-test 2>&1 | head -5

# Check if health checks are being tracked
echo
echo "Checking health status after mount attempt..."
./target/release/fuji health --json | jq . 2>/dev/null || ./target/release/fuji health

# Test status command to see mount states
echo
echo "Checking mount status..."
./target/release/fuji status --verbose

# Clean up
echo
echo "Cleaning up..."
./target/release/fuji daemon stop
sleep 1

# Verify daemon stopped
if ! ./target/release/fuji status >/dev/null 2>&1; then
    echo "✓ Daemon stopped successfully"
else
    echo "✗ Daemon is still running"
    exit 1
fi

echo
echo "=== Health monitoring integration test complete ==="