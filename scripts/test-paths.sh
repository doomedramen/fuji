#!/bin/bash
set -e

echo "=========================================="
echo "Fuji Path Location Test - Debian"
echo "=========================================="
echo ""

# Clean up any existing mounts
echo "1. Cleaning up any existing mounts/dirs..."
umount /mnt/fuji/* 2>/dev/null || true
rm -rf /tmp/fuji /run/fuji /run/user/*/fuji 2>/dev/null || true
echo "✓ Cleanup complete"
echo ""

# Test as root (system daemon)
echo "2. Testing paths as root (system daemon)..."
echo "Starting daemon as root..."
/app/target/release/fuji daemon stop 2>/dev/null || true
sleep 2
/app/target/release/fuji daemon start --no-automount &
sleep 3

# Check where files were created
echo ""
echo "Checking file locations (root):"
echo "  Socket: $(find /run /tmp -name fuji.sock 2>/dev/null || echo 'Not found')"
echo "  PID file: $(find /run /tmp -name fuji.pid 2>/dev/null || echo 'Not found')"

# Check if /run/fuji was created
if [ -d "/run/fuji" ]; then
    echo "  ✅ /run/fuji directory created"
    ls -la /run/fuji/
else
    echo "  ❌ /run/fuji directory not found"
fi

# Stop daemon
/app/target/release/fuji daemon stop
echo ""
echo "✓ Root daemon test complete"
echo ""

# Test as non-root user if possible
if id -u fuji >/dev/null 2>&1; then
    echo "3. Testing paths as non-root user (fuji)..."
    echo "Starting daemon as user fuji..."
    sudo -u fuji /app/target/release/fuji daemon start --no-automount &
    sleep 3

    echo ""
    echo "Checking file locations (user fuji):"
    echo "  Socket: $(sudo -u fuji find /tmp /home/fuji -name fuji.sock 2>/dev/null || echo 'Not found')"
    echo "  PID file: $(sudo -u fuji find /tmp /home/fuji -name fuji.pid 2>/dev/null || echo 'Not found')"

    # Stop daemon
    sudo -u fuji /app/target/release/fuji daemon stop
    echo "✓ User daemon test complete"
    echo ""
else
    echo "3. Skipping non-root test (user 'fuji' not available)"
    echo ""
fi

# Test with XDG_RUNTIME_DIR
echo "4. Testing with XDG_RUNTIME_DIR set..."
export XDG_RUNTIME_DIR="/tmp/test-runtime"
mkdir -p $XDG_RUNTIME_DIR
chmod 700 $XDG_RUNTIME_DIR

/app/target/release/fuji daemon start --no-automount &
sleep 3

echo ""
echo "Checking file locations (with XDG_RUNTIME_DIR):"
echo "  XDG_RUNTIME_DIR: $XDG_RUNTIME_DIR"
echo "  Socket: $(find $XDG_RUNTIME_DIR -name fuji.sock 2>/dev/null || echo 'Not found')"
echo "  PID file: $(find $XDG_RUNTIME_DIR -name fuji.pid 2>/dev/null || echo 'Not found')"

# Stop daemon
/app/target/release/fuji daemon stop
echo "✓ XDG_RUNTIME_DIR test complete"
echo ""

# Test mount directory
echo "5. Testing mount directory creation..."
rm -rf /mnt/fuji 2>/dev/null || true
/app/target/release/fuji daemon start --no-automount &
sleep 2
/app/target/release/fuji daemon stop

if [ -d "/mnt/fuji" ]; then
    echo "✅ /mnt/fuji created successfully"
else
    echo "⚠️  /mnt/fuji not created (may be permission issue)"
fi
echo ""

# Clean up
echo "6. Final cleanup..."
umount /mnt/fuji/* 2>/dev/null || true
rm -rf /tmp/fuji /run/fuji /tmp/test-runtime 2>/dev/null || true
echo "✓ Cleanup complete"
echo ""

echo "=========================================="
echo "✓ Path location tests completed!"
echo "=========================================="