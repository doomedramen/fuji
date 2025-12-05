#!/bin/bash

echo "🔧 Comprehensive serde import fixes for Fuji security modules..."

# List of files that need serde imports based on compilation errors
FILES=(
    "src/security/credential_backup.rs"
    "src/security/pki.rs"
    "src/security/security_dashboard.rs"
    "src/security/audit_monitoring.rs"
    "src/security/audit_monitoring_simple.rs"
    "src/security/audit_logging.rs"
    "src/security/encryption.rs"
    "src/security/file_provider.rs"
    "src/security/hardware_credential_provider.rs"
    "src/security/key_derivation.rs"
    "src/security/secure_updates.rs"
    "src/security/intrusion_detection.rs"
    "src/security/runtime_integrity.rs"
    "src/security/vulnerability_scanner.rs"
    "src/security/security_policy.rs"
)

# Function to add serde imports if missing
add_serde_import() {
    local file="$1"
    echo "Processing $file..."

    # Check if file exists
    if [[ ! -f "$file" ]]; then
        echo "  ⚠️  File not found: $file"
        return
    fi

    # Check if serde imports are already present
    if grep -q "use serde::{Deserialize, Serialize}" "$file"; then
        echo "  ✓ Serde imports already present"
        return
    fi

    # Check if file has any serde derive macros
    if grep -q "#\[derive.*Serialize.*\]" "$file" || grep -q "#\[derive.*Deserialize.*\]" "$file" || grep -q "#\[serde" "$file"; then
        echo "  📝 Adding serde imports..."

        # Find the last use statement before the first non-use line
        # Insert after the last use statement
        awk '
            /^use / { in_use = 1; print; next }
            in_use && !/^use / && !/^$/ && !/^\/\// && !/^\/\*/ {
                print "use serde::{Deserialize, Serialize};"
                in_use = 0
                print
                next
            }
            { print }
        ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"

        echo "  ✅ Added serde imports"
    else
        echo "  ℹ️  No serde usage detected"
    fi
}

# Process each file
for file in "${FILES[@]}"; do
    add_serde_import "$file"
done

echo ""
echo "🔍 Running cargo check to see remaining issues..."

# Check for any remaining compilation errors
cargo check 2>&1 | head -50

echo ""
echo "✅ Comprehensive serde import fixes completed!"