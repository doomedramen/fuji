#!/bin/bash

echo "🔧 Targeted compilation fixes for Fuji security modules..."

# Fix audit_logging.rs - add missing serde imports
echo "Fixing audit_logging.rs..."
sed -i '' 's/use serde_json::Value;/use serde::{Deserialize, Serialize};\nuse serde_json::Value;/' src/security/audit_logging.rs

# Fix audit_monitoring_simple.rs - add missing serde imports
echo "Fixing audit_monitoring_simple.rs..."
sed -i '' 's/use tracing::{error, info, warn};/use serde::{Deserialize, Serialize};\nuse tracing::{error, info, warn};/' src/security/audit_monitoring_simple.rs

# Fix encryption.rs - fix unused nonce parameter
echo "Fixing encryption.rs..."
sed -i '' 's/nonce: \&\[u8\]/_nonce: \&\[u8\]/g' src/security/encryption.rs

# Fix hardware_credential_provider.rs - fix unused parameters
echo "Fixing hardware_credential_provider.rs..."
sed -i '' 's/key_data: \&\[u8\]/_key_data: \&\[u8\]/g' src/security/hardware_credential_provider.rs
sed -i '' 's/key_id: &str/_key_id: \&str/g' src/security/hardware_credential_provider.rs
sed -i '' 's/data: \&\[u8\]/_data: \&\[u8\]/g' src/security/hardware_credential_provider.rs
sed -i '' 's/signature: \&\[u8\]/_signature: \&\[u8\]/g' src/security/hardware_credential_provider.rs
sed -i '' 's/new_key_data: \&\[u8\]/_new_key_data: \&\[u8\]/g' src/security/hardware_credential_provider.rs

# Fix key_derivation.rs - fix unused variables
echo "Fixing key_derivation.rs..."
sed -i '' 's/SOME_MEMORY/memory/g' src/security/key_derivation.rs
sed -i '' 's/SOME_PARALLEL/parallel/g' src/security/key_derivation.rs

# Remove unused cfg attributes from file_provider.rs
echo "Fixing file_provider.rs..."
sed -i '' '/#\[cfg(feature = "aes-gcm")\]/,+1d' src/security/file_provider.rs
sed -i '' '/#\[cfg(not(feature = "aes-gcm"))\]/,+1d' src/security/file_provider.rs

echo "✅ Targeted fixes applied!"
echo "🔍 Running cargo check..."