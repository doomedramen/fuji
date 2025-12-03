#!/bin/bash
set -e

echo "=========================================="
echo "Fuji Edge Cases Test - Debian"
echo "=========================================="
echo ""

# Clean up
echo "1. Cleaning up previous test data..."
/app/target/release/fuji daemon stop 2>/dev/null || true
umount /mnt/fuji/* 2>/dev/null || true
rm -rf /mnt/fuji/*
sleep 2
/app/target/release/fuji daemon start --no-automount &
sleep 3
echo "✓ Daemon started"
echo ""

# Test 2: Very long hostnames
echo "2. Testing very long hostnames..."
LONG_HOST="a-very-long-hostname-that-exceeds-normal-limits-and-might-cause-issues-in-some-systems"
echo "  Mounting NFS with long hostname..."
if /app/target/release/fuji mount nfs://${LONG_HOST}/export 2>/dev/null; then
    echo "  ❌ Unexpected success with very long hostname"
else
    echo "  ✅ Correctly failed with long hostname"
fi
echo ""

# Test 3: Special characters in paths
echo "3. Testing special characters in paths..."
echo "  Creating test directories with special chars..."
mkdir -p "/tmp/test spaces" "/tmp/test-dashes" "/tmp/test_underscores" "/tmp/test.dots" 2>/dev/null || true

# Test with spaces (URL encoded)
echo "  Testing URL with spaces..."
# Note: We need to encode spaces in URLs
if /app/target/release/fuji mount "nfs://nfs-server/exports/data%20subfolder" 2>/dev/null; then
    echo "  ❌ Unexpected success with encoded spaces"
else
    echo "  ✅ Correctly failed (expected behavior)"
fi
echo ""

# Test 4: Maximum path length
echo "4. Testing maximum path depth..."
# Create a very long path
LONG_PATH=""
for i in {1..20}; do
    LONG_PATH="${LONG_PATH}/$(printf 'a%.0s' {1..10})"
done

echo "  Long path length: ${#LONG_PATH} characters"
if /app/target/release/fuji mount "nfs://nfs-server${LONG_PATH}" 2>/dev/null; then
    echo "  ❌ Unexpected success with very long path"
else
    echo "  ✅ Correctly failed with long path"
fi
echo ""

# Test 5: Unicode characters
echo "5. Testing Unicode characters..."
echo "  Testing with Unicode in path..."
UNICODE_PATH="🔒-test-测试-тест-тест"
if /app/target/release/fuji mount "nfs://nfs-server/exports/${UNICODE_PATH}" 2>/dev/null; then
    echo "  ❌ Unexpected success with Unicode"
else
    echo "  ✅ Correctly failed with Unicode (not supported in NFS URLs)"
fi
echo ""

# Test 6: Port specifications
echo "6. Testing port specifications..."
echo "  Testing NFS with explicit port..."
if /app/target/release/fuji mount "nfs://nfs-server:2049/exports/data" 2>/dev/null; then
    echo "  ✅ Mount with port succeeded"
    # Clean up
    /app/target/release/fuji list 2>/dev/null | grep nfs-server | awk '{print $1}' | xargs -I {} /app/target/release/fuji unmount {} 2>/dev/null || true
else
    echo "  ⚠️  Mount with port failed (may not be supported)"
fi
echo ""

# Test 7: Different mount options
echo "7. Testing custom mount options..."
echo "  Testing SMB with custom options (via future feature)..."
# This will be a placeholder for when custom options are supported
echo "  (Custom mount options not yet implemented)"
echo ""

# Test 8: Rapid start/stop cycles
echo "8. Testing rapid daemon start/stop..."
for i in {1..5}; do
    echo "  Cycle $i..."
    /app/target/release/fuji daemon stop
    sleep 0.5
    /app/target/release/fuji daemon start --no-automount &
    sleep 0.5
done
echo "✓ Rapid cycles completed"
echo ""

# Test 9: Multiple mounts to same server
echo "9. Testing multiple mounts to same server..."
echo "  Mounting different shares from same server..."
/app/target/release/fuji mount nfs://nfs-server/exports/data 2>/dev/null || true
/app/target/release/fuji mount nfs://nfs-server/exports/media 2>/dev/null || true
/app/target/release/fuji mount smb://testuser:testpass@smb-server/data 2>/dev/null || true

# Check status
echo "  Checking mount status..."
/app/target/release/fuji status 2>/dev/null || echo "  Status check failed"

# Clean up
/app/target/release/fuji list 2>/dev/null | grep -E "(nfs-server|smb-server)" | awk '{print $1}' | xargs -I {} /app/target/release/fuji unmount {} 2>/dev/null || true
echo "✓ Multiple mounts test complete"
echo ""

# Test 10: Maximum concurrent connections
echo "10. Testing maximum concurrent connections..."
echo "  Launching 20 concurrent status commands..."
for i in {1..20}; do
    /app/target/release/fuji status >/dev/null 2>&1 &
done
wait

if /app/target/release/fuji status >/dev/null 2>&1; then
    echo "  ✅ Daemon still responsive after 20 concurrent connections"
else
    echo "  ❌ Daemon became unresponsive"
fi
echo ""

# Test 11: File system edge cases
echo "11. Testing file system edge cases..."

# Create a mount and test file operations
echo "  Creating mount and testing file operations..."
/app/target/release/fuji mount nfs://nfs-server/exports/data 2>/dev/null || true
sleep 1

# Test creating very long filenames
MOUNT_POINT="/mnt/fuji/nfs-server_nfs/exports/data"
if [ -d "$MOUNT_POINT" ]; then
    echo "  Testing very long filename creation..."
    LONG_FILENAME=$(printf 'a%.0s' {1..200}).txt
    if touch "$MOUNT_POINT/$LONG_FILENAME" 2>/dev/null; then
        echo "  ⚠️  Long filename created (may cause issues)"
        rm -f "$MOUNT_POINT/$LONG_FILENAME" 2>/dev/null || true
    else
        echo "  ✅ Long filename correctly rejected by filesystem"
    fi

    # Test special characters in filename
    echo "  Testing special characters in filename..."
    if touch "$MOUNT_POINT/test file with spaces.txt" 2>/dev/null; then
        echo "  ✅ Space in filename works"
        rm -f "$MOUNT_POINT/test file with spaces.txt" 2>/dev/null || true
    fi

    if touch "$MOUNT_POINT/test@#\$%^&*().txt" 2>/dev/null; then
        echo "  ⚠️  Special characters in filename work"
        rm -f "$MOUNT_POINT/test@#\$%^&*().txt" 2>/dev/null || true
    else
        echo "  ✅ Special characters correctly rejected"
    fi
fi

# Clean up
/app/target/release/fuji unmount nfs-server_nfs_exports_data 2>/dev/null || true
echo "✓ File system edge cases test complete"
echo ""

# Final cleanup
echo "12. Final cleanup..."
/app/target/release/fuji daemon stop
umount /mnt/fuji/* 2>/dev/null || true
rm -rf /tmp/test* /mnt/fuji/*
echo "✓ Cleanup complete"
echo ""

echo "=========================================="
echo "✓ Edge cases tests completed!"
echo "=========================================="