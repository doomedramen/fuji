#!/bin/bash
set -e

echo "=========================================="
echo "Fuji Stress Test - Debian"
echo "=========================================="
echo ""

# Configuration
STRESS_DURATION=${1:-30}  # Default 30 seconds
MAX_CONCURRENT=${2:-50}   # Default 50 concurrent operations

echo "Stress test configuration:"
echo "  Duration: ${STRESS_DURATION}s"
echo "  Max concurrent: ${MAX_CONCURRENT}"
echo ""

# Clean up
echo "1. Cleaning up..."
/app/target/release/fuji daemon stop 2>/dev/null || true
umount -l /mnt/fuji/* 2>/dev/null || true
rm -rf /mnt/fuji/*
sleep 2
echo "✓ Cleaned up"
echo ""

# Start daemon
echo "2. Starting daemon..."
/app/target/release/fuji daemon start --no-automount &
DAEMON_PID=$!
sleep 3
echo "✓ Daemon started (PID: $DAEMON_PID)"
echo ""

# Test 3: Stress test with continuous operations
echo "3. Running stress test for ${STRESS_DURATION} seconds..."

# Create a background process to continuously issue commands
(
    END_TIME=$(($(date +%s) + STRESS_DURATION))
    OPERATIONS=0
    ERRORS=0

    while [ $(date +%s) -lt $END_TIME ]; do
        # Random operation selection
        OP=$((RANDOM % 4))
        case $OP in
            0)  # Status command
                if /app/target/release/fuji status >/dev/null 2>&1; then
                    : # Success
                else
                    ERRORS=$((ERRORS + 1))
                fi
                ;;
            1)  # List command
                if /app/target/release/fuji list >/dev/null 2>&1; then
                    : # Success
                else
                    ERRORS=$((ERRORS + 1))
                fi
                ;;
            2)  # Mount attempt (will likely fail - that's ok)
                /app/target/release/fuji mount nfs://stress.test.local/export >/dev/null 2>&1 || :
                ;;
            3)  # Discovery attempt
                /app/target/release/fuji discover nfs://nfs-server >/dev/null 2>&1 || :
                ;;
        esac

        OPERATIONS=$((OPERATIONS + 1))

        # Small random delay
        usleep $((RANDOM % 10000))  # 0-10ms
    done

    echo "Stress test completed:"
    echo "  Total operations: $OPERATIONS"
    echo "  Errors: $ERRORS"
    echo "  Success rate: $(( (OPERATIONS - ERRORS) * 100 / OPERATIONS ))%"
) &
STRESS_PID=$!

# Run concurrent commands in parallel
echo "4. Launching $MAX_CONCURRENT concurrent commands..."
for i in $(seq 1 $MAX_CONCURRENT); do
    {
        # Each process does 10 operations
        for j in $(seq 1 10); do
            /app/target/release/fuji status >/dev/null 2>&1 &
            sleep 0.1
            /app/target/release/fuji list >/dev/null 2>&1 &
            wait
        done
        echo "Process $i completed"
    } &
done

# Wait for all background jobs
wait $STRESS_PID
wait

echo "✓ Stress test completed"
echo ""

# Test 5: Memory usage check
echo "5. Checking daemon memory usage..."
if ps -p $DAEMON_PID -o pid,vsz,rss,pmem,etime,cmd 2>/dev/null; then
    MEMORY_KB=$(ps -p $DAEMON_PID -o rss= 2>/dev/null || echo "0")
    echo "  Memory usage: ${MEMORY_KB} KB"
    if [ "$MEMORY_KB" -gt 50000 ]; then
        echo "  ⚠️  High memory usage detected"
    else
        echo "  ✓ Memory usage acceptable"
    fi
else
    echo "  ❌ Daemon not running (may have crashed)"
fi
echo ""

# Test 6: File descriptor count
echo "6. Checking file descriptor usage..."
if [ -d "/proc/$DAEMON_PID" ]; then
    FD_COUNT=$(ls /proc/$DAEMON_PID/fd 2>/dev/null | wc -l)
    echo "  Open file descriptors: $FD_COUNT"
    if [ "$FD_COUNT" -gt 100 ]; then
        echo "  ⚠️  High file descriptor count"
    else
        echo "  ✓ File descriptor count acceptable"
    fi
fi
echo ""

# Test 7: Create many mounts
echo "7. Testing with many simultaneous mounts..."
MOUNT_COUNT=0
MAX_MOUNTS=20

for i in $(seq 1 $MAX_MOUNTS); do
    # Try to mount (these will fail since they don't exist, but that's ok)
    if /app/target/release/fuji mount nfs://nfs-server/exports/data >/dev/null 2>&1; then
        MOUNT_COUNT=$((MOUNT_COUNT + 1))
    fi
    # For SMB
    if /app/target/release/fuji mount smb://testuser:testpass@smb-server/media$i >/dev/null 2>&1; then
        MOUNT_COUNT=$((MOUNT_COUNT + 1))
    fi
done

echo "  Successfully created $MOUNT_COUNT mounts"
if [ "$MOUNT_COUNT" -gt 0 ]; then
    echo "  Current mount count: $(/app/target/release/fuji list 2>/dev/null | grep -E "(nfs-server|smb-server)" | wc -l)"
fi
echo ""

# Test 8: Rapid mount/unmount cycle
echo "8. Testing rapid mount/unmount cycle..."
for i in {1..5}; do
    echo "  Cycle $i..."

    # Mount
    if /app/target/release/fuji mount nfs://nfs-server/exports/data >/dev/null 2>&1; then
        sleep 0.1
        # Unmount immediately
        /app/target/release/fuji unmount nfs-server_nfs_exports_data >/dev/null 2>&1 || true
    fi

    # SMB
    if /app/target/release/fuji mount smb://testuser:testpass@smb-server/media >/dev/null 2>&1; then
        sleep 0.1
        /app/target/release/fuji unmount smb-server_smb_media >/dev/null 2>&1 || true
    fi
done
echo "✓ Rapid cycles completed"
echo ""

# Final checks
echo "9. Final daemon health check..."
if /app/target/release/fuji status >/dev/null 2>&1; then
    echo "✓ Daemon still responsive"

    # Count any remaining mounts
    REMAINING_MOUNTS=$(/app/target/release/fuji list 2>/dev/null | wc -l)
    if [ "$REMAINING_MOUNTS" -gt 0 ]; then
        echo "  Remaining mounts: $REMAINING_MOUNTS"
    fi
else
    echo "❌ Daemon not responding"
fi
echo ""

# Cleanup
echo "10. Cleaning up..."
/app/target/release/fuji list 2>/dev/null | grep -E "(nfs-server|smb-server)" | awk '{print $1}' | xargs -I {} /app/target/release/fuji unmount {} 2>/dev/null || true
/app/target/release/fuji daemon stop
umount -l /mnt/fuji/* 2>/dev/null || true
echo "✓ Cleanup complete"
echo ""

echo "=========================================="
echo "✓ Stress testing completed!"
echo "=========================================="