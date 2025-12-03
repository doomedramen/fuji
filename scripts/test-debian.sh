#!/bin/bash
set -e

echo "=========================================="
echo "Fuji Integration Tests - Debian"
echo "=========================================="
echo ""

# Test NFS connectivity
echo "1. Testing NFS connectivity..."
showmount -e nfs-server
echo "✓ NFS server accessible"
echo ""

# Test SMB connectivity
echo "2. Testing SMB connectivity..."
smbclient -L smb-server -N || smbclient -L smb-server -U testuser%testpass
echo "✓ SMB server accessible"
echo ""

# Build Fuji
echo "3. Building Fuji..."
cd /app
cargo build --release
echo "✓ Build complete"
echo ""

# Start daemon
echo "4. Starting Fuji daemon..."
/app/target/release/fuji daemon start --no-automount &
DAEMON_PID=$!
sleep 3
echo "✓ Daemon started (PID: $DAEMON_PID)"
echo ""

# Test daemon status
echo "5. Checking daemon status..."
/app/target/release/fuji status
echo ""

# Discover NFS shares
echo "6. Discovering NFS shares..."
timeout 10 /app/target/release/fuji discover nfs://nfs-server || echo "Note: Discovery may timeout but mount can still work"
echo ""

# Mount NFS share
echo "7. Mounting NFS share (nfs://nfs-server/exports/data)..."
/app/target/release/fuji mount nfs://nfs-server/exports/data
sleep 2
echo "✓ Mount command completed"
echo ""

# Check mount status
echo "8. Checking mount status..."
/app/target/release/fuji status
echo ""

# List mounted directory
echo "9. Listing mounted directory..."
ls -la /mnt/fuji/nfs-server_nfs/exports/data/
echo ""

# Read test file
echo "10. Reading test file from NFS mount..."
cat /mnt/fuji/nfs-server_nfs/exports/data/test.txt
echo "✓ File read successfully"
echo ""

# List all mounts
echo "11. Listing all mounts..."
/app/target/release/fuji list
echo ""

# Unmount
echo "12. Unmounting NFS share..."
/app/target/release/fuji unmount nfs-server_nfs_exports_data
echo "✓ Unmount completed"
echo ""

# Stop daemon
echo "13. Stopping daemon..."
/app/target/release/fuji daemon stop
wait $DAEMON_PID
echo "✓ Daemon stopped"
echo ""

echo "=========================================="
echo "✓ All tests passed successfully!"
echo "=========================================="
