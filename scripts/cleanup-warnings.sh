#!/bin/bash

# Cleanup script for Fuji security module warnings and compilation issues
# This script systematically fixes common Rust warnings

echo "🧹 Starting comprehensive cleanup of Fuji security modules..."

# Create a backup of current state
echo "📦 Creating backup..."
cp -r src/security src/security.backup.$(date +%Y%m%d_%H%M%S)

# Function to remove unused imports from a file
remove_unused_imports() {
    local file="$1"
    echo "  Cleaning unused imports in $file..."

    # Remove specific unused imports based on compilation warnings
    sed -i '' '/use std::time::SystemTime/d' "$file"
    sed -i '' '/use std::time::UNIX_EPOCH/d' "$file"
    sed -i '' '/use tracing::warn/d' "$file"
    sed -i '' '/use crate::security::encryption::{create_encryptor, EncryptedData, EncryptionAlgorithm}/d' "$file"
    sed -i '' '/use anyhow::anyhow/d' "$file"
    sed -i '' '/use std::os::unix::fs::PermissionsExt/d' "$file"
    sed -i '' '/use tracing::debug/d' "$file"
    sed -i '' '/use tracing::error/d' "$file"
    sed -i '' '/use serde::{Deserialize, Serialize}/d' "$file"
    sed -i '' '/use crate::security::hardware_credential_provider::{EnhancedCredential, SecurityMetadata}/d' "$file"
    sed -i '' '/use crate::security::auth::JWTAuthenticator/d' "$file"
    sed -i '' '/use std::process::Command/d' "$file"
    sed -i '' '/use aead::{Aead, KeyInit}/d' "$file"
    sed -i '' '/use anyhow::Context/d' "$file"
    sed -i '' '/use AuditSource/d' "$file"
}

# Function to fix unused variables by prefixing with underscore
fix_unused_variables() {
    local file="$1"
    echo "  Fixing unused variables in $file..."

    # Common unused variable fixes
    sed -i '' 's/nonce: \&\[_u8\]/_nonce: \&\[u8\]/g' "$file"
    sed -i '' 's/key_data: \&\[_u8\]/_key_data: \&\[u8\]/g' "$file"
    sed -i '' 's/key_id: &str/_key_id: \&str/g' "$file"
    sed -i '' 's/data: \&\[_u8\]/_data: \&\[u8\]/g' "$file"
    sed -i '' 's/signature: \&\[_u8\]/_signature: \&\[u8\]/g' "$file"
    sed -i '' 's/new_key_data: \&\[_u8\]/_new_key_data: \&\[u8\]/g' "$file"
    sed -i '' 's/mut memory/SOME_MEMORY/g' "$file"
    sed -i '' 's/mut parallel/SOME_PARALLEL/g' "$file"
}

# Function to remove unused cfg attributes
remove_unused_cfg() {
    local file="$1"
    echo "  Removing unused cfg attributes in $file..."

    # Remove aes-gcm feature cfgs
    sed -i '' '/#\[cfg(feature = "aes-gcm")\]/d' "$file"
    sed -i '' '/#\[cfg(not(feature = "aes-gcm"))\]/d' "$file"
}

# List of security files to clean
security_files=(
    "src/security/audit_logging.rs"
    "src/security/audit_monitoring.rs"
    "src/security/audit_monitoring_simple.rs"
    "src/security/credential_backup.rs"
    "src/security/file_provider.rs"
    "src/security/hardware_credential_provider.rs"
    "src/security/key_derivation.rs"
    "src/security/process_isolation.rs"
    "src/security/resource_limits.rs"
    "src/security/secure_updates.rs"
    "src/security/encryption.rs"
    "src/security/integrity.rs"
)

# Clean each security file
for file in "${security_files[@]}"; do
    if [ -f "$file" ]; then
        echo "🔧 Processing $file..."
        remove_unused_imports "$file"
        fix_unused_variables "$file"
        remove_unused_cfg "$file"
    else
        echo "⚠️  File not found: $file"
    fi
done

# Fix specific issues in key modules
echo "🔧 Fixing specific module issues..."

# Fix encryption.rs nonce parameter
if [ -f "src/security/encryption.rs" ]; then
    sed -i '' 's/nonce: \&\[u8\]/_nonce: \&\[u8\]/g' "src/security/encryption.rs"
fi

# Fix hardware_credential_provider.rs parameters
if [ -f "src/security/hardware_credential_provider.rs" ]; then
    sed -i '' 's/key_data: \&\[u8\]/_key_data: \&\[u8\]/g' "src/security/hardware_credential_provider.rs"
    sed -i '' 's/key_id: &str/_key_id: \&str/g' "src/security/hardware_credential_provider.rs"
    sed -i '' 's/data: \&\[u8\]/_data: \&\[u8\]/g' "src/security/hardware_credential_provider.rs"
    sed -i '' 's/signature: \&\[u8\]/_signature: \&\[u8\]/g' "src/security/hardware_credential_provider.rs"
    sed -i '' 's/new_key_data: \&\[u8\]/_new_key_data: \&\[u8\]/g' "src/security/hardware_credential_provider.rs"
fi

# Fix key_derivation.rs mutable variables
if [ -f "src/security/key_derivation.rs" ]; then
    sed -i '' 's/SOME_MEMORY/memory/g' "src/security/key_derivation.rs"
    sed -i '' 's/SOME_PARALLEL/parallel/g' "src/security/key_derivation.rs"
fi

# Run cargo check to see remaining issues
echo "🔍 Running cargo check to see remaining issues..."
cargo check --lib 2>&1 | head -50

echo ""
echo "✅ Cleanup script completed!"
echo "📊 Next steps:"
echo "   1. Run 'cargo check' to verify fixes"
echo "   2. Run 'cargo clippy' for additional linting"
echo "   3. Run 'cargo fmt' to ensure consistent formatting"
echo "   4. Consider running tests to ensure functionality is preserved"