#!/bin/bash
set -e

echo "=========================================="
echo "Fuji SMB Integration Test - Debian"
echo "=========================================="
echo ""

# Kill any existing daemon
echo "1. Stopping any existing daemon..."
/app/target/release/fuji daemon stop 2>/dev/null || true
sleep 2
echo "✓ Cleaned up"
echo ""

# Start daemon
echo "2. Starting Fuji daemon..."
/app/target/release/fuji daemon start --no-automount &
DAEMON_PID=$!
sleep 3
echo "✓ Daemon started (PID: $DAEMON_PID)"
echo ""

# Check status
echo "3. Checking daemon status..."
/app/target/release/fuji status
echo ""

# Discover SMB shares
echo "4. Discovering SMB shares..."
timeout 10 /app/target/release/fuji discover smb://testuser:testpass@smb-server || echo "Note: Discovery may timeout"
echo ""

# Mount SMB share
echo "5. Mounting SMB share (smb://testuser:testpass@smb-server/data)..."
/app/target/release/fuji mount smb://testuser:testpass@smb-server/data
sleep 2
echo "✓ Mount command completed"
echo ""

# Check mount status
echo "6. Checking mount status..."
/app/target/release/fuji status
echo ""

# List mounted directory
echo "7. Listing mounted directory..."
ls -la /mnt/fuji/smb-server_smb/data/ || ls -la /mnt/fuji/smb-server_smb_data/
echo ""

# List all mounts
echo "8. Listing all mounts..."
/app/target/release/fuji list
echo ""

# Unmount
echo "9. Unmounting SMB share..."
/app/target/release/fuji unmount smb-server_smb_data
echo "✓ Unmount completed"
echo ""

# Stop daemon
echo "10. Stopping daemon..."
/app/target/release/fuji daemon stop
echo "✓ Daemon stopped"
echo ""

echo "=========================================="
echo "✓ SMB tests passed successfully!"
echo "=========================================="
