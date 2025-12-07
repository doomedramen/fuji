//! JWT-based authentication for socket access
//!
//! Provides JWT token generation and validation for secure socket communication.

use crate::{
    security::{IntoSecurityError, SecurityError, SecurityResult},
    security_auth_error, security_crypto_error, security_validation_error,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration as StdDuration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::info;

/// JWT claims for Fuji authentication
#[derive(Debug, Serialize, Deserialize)]
pub struct FujiClaims {
    /// Subject (user identifier)
    pub sub: String,
    /// Issued at
    pub iat: u64,
    /// Expiration time
    pub exp: u64,
    /// Issuer (fuji daemon)
    pub iss: String,
    /// Mount permissions
    pub mounts: HashSet<String>,
    /// User roles
    pub roles: HashSet<String>,
}

/// JWT authenticator for socket authentication
pub struct JWTAuthenticator {
    /// Ed25519 key pair for signing
    #[allow(dead_code)]
    key_pair: Ed25519KeyPair,
    /// PKCS#8 encoded key pair bytes for encoding
    key_pair_bytes: Vec<u8>,
    /// Public key for verification (derived from key_pair)
    #[allow(dead_code)]
    public_key: UnparsedPublicKey<[u8; 32]>,
    /// Raw public key bytes
    public_key_array: [u8; 32],
    /// Token expiration duration
    expiration: StdDuration,
    /// Issuer identifier
    issuer: String,
    /// Revoked tokens
    revoked_tokens: RwLock<HashSet<String>>,
}

#[allow(dead_code)]
impl JWTAuthenticator {
    /// Create a new JWT authenticator with a new key pair
    pub fn new() -> SecurityResult<Self> {
        // Generate a new Ed25519 key pair
        let rng = ring::rand::SystemRandom::new();
        let key_pair_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| security_crypto_error!("key_pair_generation", e))?;

        let key_pair_bytes_vec = key_pair_bytes.as_ref().to_vec();
        let key_pair = Ed25519KeyPair::from_pkcs8(key_pair_bytes.as_ref())
            .map_err(|e| security_crypto_error!("key_pair_parsing", e))?;

        // Extract public key
        let public_key_bytes = key_pair.public_key().as_ref();
        let mut public_key_array = [0u8; 32];
        public_key_array.copy_from_slice(&public_key_bytes[..32]);
        let public_key = UnparsedPublicKey::new(&ring::signature::ED25519, public_key_array);

        Ok(Self {
            key_pair,
            key_pair_bytes: key_pair_bytes_vec,
            public_key,
            public_key_array,
            expiration: StdDuration::from_secs(3600), // 1 hour default
            issuer: "fuji-daemon".to_string(),
            revoked_tokens: RwLock::new(HashSet::new()),
        })
    }

    /// Create authenticator from existing key pair
    /// Note: This requires the original PKCS#8 encoded bytes for signing
    pub fn from_key_pair_with_bytes(
        key_pair: Ed25519KeyPair,
        key_pair_bytes: Vec<u8>,
    ) -> SecurityResult<Self> {
        let public_key_bytes = key_pair.public_key().as_ref();
        let mut public_key_array = [0u8; 32];
        public_key_array.copy_from_slice(&public_key_bytes[..32]);
        let public_key = UnparsedPublicKey::new(&ring::signature::ED25519, public_key_array);

        Ok(Self {
            key_pair,
            key_pair_bytes,
            public_key,
            public_key_array,
            expiration: StdDuration::from_secs(3600),
            issuer: "fuji-daemon".to_string(),
            revoked_tokens: RwLock::new(HashSet::new()),
        })
    }

    /// Set token expiration duration
    pub fn with_expiration(mut self, expiration: StdDuration) -> Self {
        self.expiration = expiration;
        self
    }

    /// Set issuer identifier
    pub fn with_issuer(mut self, issuer: String) -> Self {
        self.issuer = issuer;
        self
    }

    /// Generate a JWT token for the given user
    pub fn generate_token(
        &self,
        user_id: &str,
        mounts: HashSet<String>,
        roles: HashSet<String>,
    ) -> SecurityResult<String> {
        // Validate input parameters
        if user_id.is_empty() {
            return Err(security_validation_error!(
                "user_id",
                "User ID cannot be empty"
            ));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .with_security_context("Failed to get current time")?;

        let claims = FujiClaims {
            sub: user_id.to_string(),
            iat: now.as_secs(),
            exp: (now + self.expiration).as_secs(),
            iss: self.issuer.clone(),
            mounts,
            roles,
        };

        let header = Header::new(Algorithm::EdDSA);
        // For EdDSA, we need to use the PKCS#8 encoded private key
        let encoding_key = EncodingKey::from_ed_der(&self.key_pair_bytes);

        encode(&header, &claims, &encoding_key)
            .map_err(|e| security_crypto_error!("jwt_encoding", e))
    }

    /// Validate a JWT token
    pub fn validate_token(&self, token: &str) -> SecurityResult<FujiClaims> {
        // Validate input
        if token.is_empty() {
            return Err(security_auth_error!("Token cannot be empty"));
        }

        // Check if token is revoked
        {
            let revoked = self
                .revoked_tokens
                .try_read()
                .map_err(|_| SecurityError::System {
                    component: "revoked_tokens_store".to_string(),
                    reason: "Failed to acquire read lock for revoked tokens".to_string(),
                    source: None,
                })?;
            if revoked.contains(token) {
                return Err(security_auth_error!("Token has been revoked"));
            }
        }

        // Decode and validate token
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.issuer]);

        let decoding_key = DecodingKey::from_ed_der(&self.public_key_array);

        let token_data = decode::<FujiClaims>(token, &decoding_key, &validation)
            .map_err(|e| security_auth_error!("Invalid JWT token: {}", e))?;

        Ok(token_data.claims)
    }

    /// Revoke a token
    pub async fn revoke_token(&self, token: String) -> SecurityResult<()> {
        if token.is_empty() {
            return Err(security_validation_error!(
                "token",
                "Cannot revoke empty token"
            ));
        }

        let mut revoked = self.revoked_tokens.write().await;
        revoked.insert(token);
        Ok(())
    }

    /// Get public key for external verification
    pub fn get_public_key(&self) -> &[u8] {
        &self.public_key_array
    }

    /// Check if user has permission to access a mount
    pub fn has_mount_permission(&self, claims: &FujiClaims, mount_id: &str) -> bool {
        // Check explicit mount permissions
        if claims.mounts.contains(mount_id) {
            return true;
        }

        // Check role-based permissions
        if claims.roles.contains("admin") || claims.roles.contains("root") {
            return true;
        }

        false
    }

    /// Clean up expired revoked tokens
    pub async fn cleanup_expired_tokens(&self) -> SecurityResult<usize> {
        let mut revoked = self.revoked_tokens.write().await;

        let mut to_remove = Vec::new();

        for token in revoked.iter() {
            // Try to decode token to check expiration
            if let Ok(decoded) = validate_token_structure(token) {
                if let Some(exp) = decoded.claims.get("exp") {
                    if let Some(exp_val) = exp.as_u64() {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .with_security_context("Failed to get current time for cleanup")?
                            .as_secs();

                        if exp_val < now {
                            to_remove.push(token.clone());
                        }
                    }
                }
            } else {
                // Invalid token, remove it
                to_remove.push(token.clone());
            }
        }

        let count = to_remove.len();
        for token in to_remove {
            revoked.remove(&token);
        }

        if count > 0 {
            info!("Cleaned up {} expired/invalid revoked tokens", count);
        }

        Ok(count)
    }
}

/// Helper to validate token structure without full verification
fn validate_token_structure(
    token: &str,
) -> SecurityResult<jsonwebtoken::TokenData<serde_json::Value>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(security_validation_error!(
            "token_structure",
            "JWT token must have 3 parts separated by dots",
            format!("{} parts found", parts.len())
        ));
    }

    // Try to decode the payload
    let payload = parts[1];
    let decoded = URL_SAFE_NO_PAD.decode(payload).map_err(|_| {
        security_validation_error!(
            "token_payload",
            "Invalid base64url encoding in token payload"
        )
    })?;

    let claims: serde_json::Value = serde_json::from_slice(&decoded).map_err(|e| {
        security_validation_error!(
            "token_claims",
            format!("Invalid JSON in token claims: {}", e)
        )
    })?;

    Ok(jsonwebtoken::TokenData {
        header: Header::default(),
        claims,
    })
}

impl Default for JWTAuthenticator {
    fn default() -> Self {
        Self::new().unwrap_or_else(|e| {
            panic!("Failed to create JWT authenticator: {}", e);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_jwt_generation_and_validation() {
        let auth = JWTAuthenticator::new().unwrap();

        let mut mounts = HashSet::new();
        mounts.insert("test-mount".to_string());

        let mut roles = HashSet::new();
        roles.insert("user".to_string());

        // Generate token
        let token = auth
            .generate_token("testuser", mounts.clone(), roles.clone())
            .unwrap();
        assert!(!token.is_empty());

        // Validate token
        let claims = auth.validate_token(&token).unwrap();
        assert_eq!(claims.sub, "testuser");
        assert_eq!(claims.mounts, mounts);
        assert_eq!(claims.roles, roles);
        assert_eq!(claims.iss, "fuji-daemon");
    }

    #[test]
    fn test_jwt_permission_check() {
        let auth = JWTAuthenticator::new().unwrap();

        let mut mounts = HashSet::new();
        mounts.insert("mount-1".to_string());

        let mut roles = HashSet::new();
        roles.insert("admin".to_string());

        let claims = FujiClaims {
            sub: "user".to_string(),
            iat: 0,
            exp: u64::MAX,
            iss: "test".to_string(),
            mounts: mounts.clone(),
            roles: roles.clone(),
        };

        // Should have permission for mount-1
        assert!(auth.has_mount_permission(&claims, "mount-1"));

        // Admin should have permission for any mount
        assert!(auth.has_mount_permission(&claims, "any-mount"));

        // Remove admin role
        let mut claims = claims;
        claims.roles.remove("admin");

        // Should only have permission for mount-1
        assert!(auth.has_mount_permission(&claims, "mount-1"));
        assert!(!auth.has_mount_permission(&claims, "other-mount"));
    }

    #[tokio::test]
    async fn test_token_revocation() {
        let auth = JWTAuthenticator::new().unwrap();

        let token = auth
            .generate_token("user", HashSet::new(), HashSet::new())
            .unwrap();

        // Token should be valid initially
        assert!(auth.validate_token(&token).is_ok());

        // Revoke the token
        auth.revoke_token(token.clone()).await.unwrap();

        // Token should now be invalid
        assert!(auth.validate_token(&token).is_err());
    }

    #[test]
    fn test_invalid_token() {
        let auth = JWTAuthenticator::new().unwrap();

        // Invalid token should fail validation
        let result = auth.validate_token("invalid.token.here");
        assert!(result.is_err());

        // Empty token should fail
        let result = auth.validate_token("");
        assert!(result.is_err());

        // Malformed base64 should fail
        let result = auth.validate_token("a.b.c");
        assert!(result.is_err());
    }
}
