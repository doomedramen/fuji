#!/bin/bash
set -e

echo "=========================================="
echo "Fuji Mount Persistence Test - Debian"
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

# Create two mounts for testing
echo "3. Creating mounts..."
echo "  - Mounting NFS share..."
/app/target/release/fuji mount nfs://nfs-server/exports/data
sleep 1

echo "  - Mounting SMB share..."
/app/target/release/fuji mount smb://testuser:testpass@smb-server/media
sleep 1
echo "✓ Both mounts created"
echo ""

# Check status
echo "4. Checking mount status..."
/app/target/release/fuji status
echo ""

# Stop daemon (but keep mounts)
echo "5. Stopping daemon (keeping mounts)..."
/app/target/release/fuji daemon stop
sleep 3
echo "✓ Daemon stopped"
echo ""

# Verify mounts still exist in filesystem
echo "6. Verifying mounts still exist..."
echo "  NFS mount: $(mount | grep nfs-server | head -1 | awk '{print $3}')"
echo "  SMB mount: $(mount | grep cifs | head -1 | awk '{print $3}')"
echo ""

# Restart daemon
echo "7. Restarting daemon..."
/app/target/release/fuji daemon start --no-automount &
DAEMON_PID2=$!
sleep 3
echo "✓ Daemon restarted (PID: $DAEMON_PID2)"
echo ""

# Check if daemon detected existing mounts
echo "8. Checking if daemon restored mount state..."
/app/target/release/fuji status
echo ""

# Test functionality with restored mounts
echo "9. Testing functionality..."
echo "  Reading from NFS mount..."
cat /mnt/fuji/nfs-server_nfs/exports/data/test.txt || echo "Note: test.txt not found"

echo "  Listing SMB mount..."
ls /mnt/fuji/smb-server_smb/media/
echo ""

# Clean up
echo "10. Cleaning up..."
/app/target/release/fuji unmount nfs-server_nfs_exports_data
/app/target/release/fuji unmount smb-server_smb_media
/app/target/release/fuji daemon stop
echo "✓ All cleaned up"
echo ""

echo "=========================================="
echo "✓ Persistence test completed!"
echo "=========================================="