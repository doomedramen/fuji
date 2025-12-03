#!/bin/bash
set -e

echo "=========================================="
echo "Fuji Error Handling Test Suite - Debian"
echo "=========================================="
echo ""

# Function to run command and capture expected failure
test_error() {
    local test_name="$1"
    local command="$2"
    local expected_pattern="$3"

    echo "Testing: $test_name"
    echo "  Command: $command"

    if output=$($command 2>&1); then
        echo "  ❌ UNEXPECTED SUCCESS: Command should have failed"
        echo "  Output: $output"
        return 1
    else
        exit_code=$?
        if echo "$output" | grep -qE "$expected_pattern"; then
            echo "  ✅ Expected error caught (exit code: $exit_code)"
            echo "  Pattern matched: $expected_pattern"
        else
            echo "  ❌ Unexpected error message:"
            echo "  $output"
            return 1
        fi
    fi
    echo ""
}

# Kill any existing daemon
echo "1. Starting clean daemon environment..."
/app/target/release/fuji daemon stop 2>/dev/null || true
sleep 2
/app/target/release/fuji daemon start --no-automount &
sleep 3
echo "✓ Daemon started"
echo ""

# Test 2: Invalid URLs
echo "2. Testing invalid URL handling..."
test_error "Invalid protocol" \
    "/app/target/release/fuji mount http://example.com/path" \
    "Invalid scheme|protocol"

test_error "Missing host" \
    "/app/target/release/fuji mount nfs:///path" \
    "No host specified"

test_error "SMB without share" \
    "/app/target/release/fuji mount smb://testuser:pass@server" \
    "requires a share name"

test_error "Malformed URL" \
    "/app/target/release/fuji mount not-a-url" \
    "Failed to parse|Invalid URL"

echo ""

# Test 3: Unreachable servers
echo "3. Testing unreachable servers..."
test_error "Invalid NFS server" \
    "/app/target/release/fuji mount nfs://nonexistent-server.example.com/export" \
    "No route to host|Host not found|Connection refused|Timed out"

test_error "Invalid SMB server" \
    "/app/target/release/fuji mount smb://user:pass@nonexistent-server.example.com/share" \
    "Connection refused|Host not found|No route to host"

echo ""

# Test 4: Invalid mount IDs
echo "4. Testing invalid mount operations..."
test_error "Unmount non-existent mount" \
    "/app/target/release/fuji unmount nonexistent_mount_id" \
    "not found|Mount .* not found"

echo ""

# Test 5: Invalid discover operations
echo "5. Testing invalid discover operations..."
test_error "Discover invalid protocol" \
    "/app/target/release/fuji discover ftp://server" \
    "Invalid scheme|protocol"

test_error "Discover nonexistent host" \
    "/app/target/release/fuji discover nfs://nonexistent.example.com" \
    "Connection refused|Host not found|Timed out"

echo ""

# Test 6: Duplicate mount attempts
echo "6. Testing duplicate mount attempts..."
echo "Creating initial mount..."
/app/target/release/fuji mount nfs://nfs-server/exports/data >/dev/null 2>&1 || true
sleep 1

test_error "Mount same share twice" \
    "/app/target/release/fuji mount nfs://nfs-server/exports/data" \
    "already exists|already mounted|mount point.*busy"

# Clean up
/app/target/release/fuji unmount nfs-server_nfs_exports_data >/dev/null 2>&1 || true
echo ""

# Test 7: Permission issues (simulate)
echo "7. Testing mount point permission scenarios..."
echo "Creating a conflicting directory..."
mkdir -p /tmp/fuji/nfs-server_nfs 2>/dev/null || true
chmod 000 /tmp/fuji/nfs-server_nfs 2>/dev/null || true

test_error "Mount with permission issue" \
    "/app/target/release/fuji mount nfs://nfs-server/exports/data" \
    "Permission denied"

# Clean up
chmod 755 /tmp/fuji/nfs-server_nfs 2>/dev/null || true
rm -rf /tmp/fuji/nfs-server_nfs 2>/dev/null || true
echo ""

# Test 8: Daemon not running scenarios
echo "8. Testing daemon communication errors..."
echo "Stopping daemon..."
/app/target/release/fuji daemon stop
sleep 2

test_error "Command without daemon" \
    "/app/target/release/fuji status" \
    "Could not connect|No such file or directory"

echo ""

# Test 9: Resource exhaustion simulation
echo "9. Testing resource handling..."
echo "Starting daemon..."
/app/target/release/fuji daemon start --no-automount &
sleep 3

# Create multiple mounts to test limits
echo "Creating multiple mounts..."
for i in {1..10}; do
    /app/target/release/fuji mount nfs://nfs-server/exports/data >/dev/null 2>&1 || true &
done
wait
sleep 2

# Check if daemon is still responsive
echo "Checking daemon responsiveness after multiple operations..."
if /app/target/release/fuji status >/dev/null 2>&1; then
    echo "✅ Daemon still responsive"
else
    echo "❌ Daemon became unresponsive"
fi

# Clean up all mounts
/app/target/release/fuji list 2>/dev/null | grep -E "nfs-server_nfs_exports_data-[0-9]+" | awk '{print $1}' | xargs -I {} /app/target/release/fuji unmount {} 2>/dev/null || true
/app/target/release/fuji daemon stop
echo ""

echo "=========================================="
echo "✓ Error handling tests completed!"
echo "=========================================="