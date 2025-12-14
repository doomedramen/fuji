//! Integration tests for improved encryption implementation
//!
//! Tests the enhanced security features including:
//! - Proper random HKDF salt generation
//! - Salt quality validation
//! - Improved key separation

use fuji::security::file_provider::FileCredentialProvider;
use fuji::security::{Credential, CredentialManager, CredentialProvider};
use std::collections::HashMap;
use tempfile::TempDir;
use tokio::fs;

#[tokio::test]
async fn test_encryption_with_random_hkdf_salt() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test_encryption.enc");

    // Create two providers with the same master key source
    std::env::set_var("TEST_FUJI_DIFFERENT_KEY", "test-key-same");
    let provider1 = FileCredentialProvider::with_path(file_path.clone()).unwrap();
    let provider2 = FileCredentialProvider::with_path(file_path).unwrap();

    let credential = Credential {
        username: "testuser".to_string(),
        password: "testpass".to_string(),
        domain: Some("TESTDOMAIN".to_string()),
        metadata: Default::default(),
    };

    // Store credential with first provider
    provider1
        .store_credential("test-mount", &credential)
        .await
        .unwrap();

    // Should be able to retrieve with second provider (same master key)
    let retrieved = provider2.get_credential("test-mount").await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().username, "testuser");
}

#[tokio::test]
async fn test_salt_quality_validation() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test_salt_validation.enc");

    // Create a provider and store a credential
    let provider = FileCredentialProvider::with_path(file_path.clone()).unwrap();

    let credential = Credential {
        username: "testuser".to_string(),
        password: "testpass".to_string(),
        domain: None,
        metadata: Default::default(),
    };

    provider
        .store_credential("test-mount", &credential)
        .await
        .unwrap();

    // Read the encrypted file
    let contents = fs::read_to_string(&file_path).await.unwrap();
    let store: serde_json::Value = serde_json::from_str(&contents).unwrap();

    // Verify salts are base64 encoded and have reasonable length
    let pbkdf2_salt = store["pbkdf2_salt"].as_str().unwrap();
    let hkdf_salt = store["hkdf_salt"].as_str().unwrap();

    // Should be proper base64 (divisible by 4, valid chars)
    assert!(pbkdf2_salt.len() % 4 == 0);
    assert!(hkdf_salt.len() % 4 == 0);
    assert!(
        pbkdf2_salt
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    );
    assert!(
        hkdf_salt
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    );

    // Should be reasonable length for 32-byte salts when base64 encoded
    assert_eq!(pbkdf2_salt.len(), 44); // 32 bytes = 44 base64 chars
    assert_eq!(hkdf_salt.len(), 44); // 32 bytes = 44 base64 chars
}

#[tokio::test]
async fn test_improved_key_separation() {
    let temp_dir = TempDir::new().unwrap();
    let file_path1 = temp_dir.path().join("test_key_sep1.enc");
    let file_path2 = temp_dir.path().join("test_key_sep2.enc");

    // Use same master key for both providers
    std::env::set_var("TEST_FUJI_DIFFERENT_KEY", "key-separation-test");
    let provider1 = FileCredentialProvider::with_path(file_path1.clone()).unwrap();
    let provider2 = FileCredentialProvider::with_path(file_path2.clone()).unwrap();

    let credential = Credential {
        username: "testuser".to_string(),
        password: "testpass".to_string(),
        domain: None,
        metadata: Default::default(),
    };

    // Store same credential in both files
    provider1
        .store_credential("test-mount", &credential)
        .await
        .unwrap();
    provider2
        .store_credential("test-mount", &credential)
        .await
        .unwrap();

    // Read both encrypted files
    let contents1 = fs::read_to_string(&file_path1).await.unwrap();
    let contents2 = fs::read_to_string(&file_path2).await.unwrap();

    let store1: serde_json::Value = serde_json::from_str(&contents1).unwrap();
    let store2: serde_json::Value = serde_json::from_str(&contents2).unwrap();

    // Even with same master key and credential, encrypted data should be different
    // due to random salts and nonces
    let encrypted1 = store1["encrypted_data"]["ciphertext"].as_str().unwrap();
    let encrypted2 = store2["encrypted_data"]["ciphertext"].as_str().unwrap();

    assert_ne!(
        encrypted1, encrypted2,
        "Encrypted data should be different due to random salts/nonces"
    );

    // But salts should also be different (random generation)
    let salt1 = store1["pbkdf2_salt"].as_str().unwrap();
    let salt2 = store2["pbkdf2_salt"].as_str().unwrap();
    assert_ne!(salt1, salt2, "PBKDF2 salts should be random and different");

    let nonce1 = store1["encrypted_data"]["nonce"].as_str().unwrap();
    let nonce2 = store2["encrypted_data"]["nonce"].as_str().unwrap();
    assert_ne!(nonce1, nonce2, "Nonces should be random and different");
}

#[tokio::test]
async fn test_stronger_encryption_context() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test_context.enc");

    let provider = FileCredentialProvider::with_aes256_gcm(file_path.clone()).unwrap();

    let credential = Credential {
        username: "testuser".to_string(),
        password: "testpass".to_string(),
        domain: None,
        metadata: Default::default(),
    };

    provider
        .store_credential("test-mount", &credential)
        .await
        .unwrap();

    // Read and verify the encrypted store contains proper metadata
    let contents = fs::read_to_string(&file_path).await.unwrap();
    let store: serde_json::Value = serde_json::from_str(&contents).unwrap();

    // Verify metadata indicates encryption version and algorithm
    let metadata = &store["metadata"];
    assert_eq!(metadata["algorithm"], "AES-256-GCM");
    assert_eq!(metadata["kdf"], "PBKDF2-HMAC-SHA256");
    assert_eq!(metadata["prf"], "HKDF-SHA256");

    // Verify PBKDF2 iterations are strong
    assert!(store["pbkdf2_iterations"].as_u64().unwrap() >= 120000);
}

#[tokio::test]
async fn test_credential_manager_encryption_integration() {
    let temp_dir = TempDir::new().unwrap();
    let config_dir = temp_dir.path().join("config");
    std::fs::create_dir_all(&config_dir).unwrap();

    // Set environment to use our test config directory
    std::env::set_var("HOME", temp_dir.path());

    let credential_manager = CredentialManager::new();

    let credential = Credential {
        username: "manager-test".to_string(),
        password: "manager-pass".to_string(),
        domain: Some("TESTDOMAIN".to_string()),
        metadata: {
            let mut meta = HashMap::new();
            meta.insert("test".to_string(), "value".to_string());
            meta
        },
    };

    // Store and retrieve through credential manager
    credential_manager
        .store_credential("manager-test-mount", &credential)
        .await
        .unwrap();

    let retrieved = credential_manager
        .get_credential("manager-test-mount")
        .await
        .unwrap();
    assert!(retrieved.is_some());

    let retrieved_credential = retrieved.unwrap();
    assert_eq!(retrieved_credential.username, "manager-test");
    assert_eq!(retrieved_credential.password, "manager-pass");
    assert_eq!(retrieved_credential.domain, Some("TESTDOMAIN".to_string()));
    assert_eq!(
        retrieved_credential.metadata.get("test"),
        Some(&"value".to_string())
    );

    // Verify credential file was created with encryption
    // dirs::config_dir() returns $HOME/.config (not $HOME/config)
    let cred_file = temp_dir
        .path()
        .join(".config")
        .join("fuji")
        .join("credentials.enc");
    assert!(cred_file.exists());

    let contents = fs::read_to_string(&cred_file).await.unwrap();
    assert!(!contents.contains("manager-test")); // Should be encrypted, not plaintext
    assert!(!contents.contains("manager-pass")); // Password should not be visible
}
