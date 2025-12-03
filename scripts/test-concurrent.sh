#!/bin/bash
set -e

echo "=========================================="
echo "Fuji Concurrent Operations Test - Debian"
echo "=========================================="
echo ""

# Kill any existing daemon
echo "1. Starting daemon..."
/app/target/release/fuji daemon stop 2>/dev/null || true
sleep 2
/app/target/release/fuji daemon start --no-automount &
DAEMON_PID=$!
sleep 3
echo "✓ Daemon started (PID: $DAEMON_PID)"
echo ""

# Create a script for concurrent mount operations
cat > /tmp/concurrent_mount.sh << 'EOF'
#!/bin/bash
set -e
MOUNT_ID=$1
SHARE=$2
/app/target/release/fuji mount nfs://nfs-server/exports/${SHARE} &
sleep 0.1
/app/target/release/fuji mount smb://testuser:testpass@smb-server/${SHARE} &
wait
echo "Concurrent mounts for ${SHARE} completed"
EOF
chmod +x /tmp/concurrent_mount.sh

# Test 2: Concurrent mount operations
echo "2. Testing concurrent mount operations..."
echo "Launching 5 concurrent mount pairs (NFS + SMB each)..."

# Create 5 different shares to mount
for i in {1..5}; do
    /tmp/concurrent_mount.sh $i data &
done

# Wait for all to complete
wait
sleep 3

# Check results
echo ""
echo "Checking mount status after concurrent operations..."
/app/target/release/fuji status
echo ""

# Count mounts
MOUNT_COUNT=$(/app/target/release/fuji list 2>/dev/null | grep -E "(nfs-server|smb-server)" | wc -l)
echo "Total mounts created: $MOUNT_COUNT"
if [ "$MOUNT_COUNT" -ge 10 ]; then
    echo "✅ Concurrent mounts successful"
else
    echo "❌ Expected at least 10 mounts, got $MOUNT_COUNT"
fi
echo ""

# Test 3: Concurrent unmount operations
echo "3. Testing concurrent unmount operations..."

# Get list of mount IDs
MOUNT_IDS=$(/app/target/release/fuji list 2>/dev/null | grep -E "(nfs-server|smb-server)" | awk '{print $1}')

# Unmount all concurrently
echo "$MOUNT_IDS" | xargs -I {} -P 10 /app/target/release/fuji unmount {} 2>/dev/null || true
sleep 3

# Check if all unmounted
REMAINING=$(/app/target/release/fuji list 2>/dev/null | grep -E "(nfs-server|smb-server)" | wc -l)
if [ "$REMAINING" -eq 0 ]; then
    echo "✅ Concurrent unmounts successful"
else
    echo "⚠️  $REMAINING mounts still remaining"
fi
echo ""

# Test 4: Mixed concurrent operations
echo "4. Testing mixed concurrent operations (mount/unmount/status)..."
echo "Launching mixed operations..."

# Create mounts and immediately query status
for i in {1..3}; do
    {
        /app/target/release/fuji mount nfs://nfs-server/exports/data &
        sleep 0.1
        /app/target/release/fuji status >/dev/null &
        sleep 0.1
        /app/target/release/fuji mount smb://testuser:testpass@smb-server/media &
        sleep 0.1
        /app/target/release/fuji list >/dev/null &
        sleep 0.1
        MOUNT_ID=$(fuji list 2>/dev/null | tail -1 | awk '{print $1}' || echo "")
        if [ -n "$MOUNT_ID" ]; then
            /app/target/release/fuji unmount "$MOUNT_ID" &
        fi
    } &
done

wait
sleep 2
echo "✅ Mixed operations completed"
echo ""

# Test 5: Rapid command succession
echo "5. Testing rapid command succession..."
echo "Sending 50 rapid status commands..."

for i in {1..50}; do
    /app/target/release/fuji status >/dev/null 2>&1 &
done

wait
echo "✅ Rapid commands completed"
echo ""

# Check daemon is still responsive
echo "6. Checking daemon responsiveness after stress test..."
if /app/target/release/fuji status >/dev/null 2>&1; then
    echo "✅ Daemon responsive"
else
    echo "❌ Daemon unresponsive"
fi
echo ""

# Test 6: Resource cleanup
echo "7. Cleaning up any remaining mounts..."
/app/target/release/fuji list 2>/dev/null | grep -E "(nfs-server|smb-server)" | awk '{print $1}' | xargs -I {} /app/target/release/fuji unmount {} 2>/dev/null || true
/app/target/release/fuji daemon stop
echo "✓ Cleanup complete"
echo ""

echo "=========================================="
echo "✓ Concurrent operations test completed!"
echo "=========================================="