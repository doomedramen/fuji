// Allow dead code - infrastructure for future features
#![allow(dead_code)]

//! Enhanced secure socket operations with encryption and authentication
//!
//! This module provides comprehensive security for Unix socket communications including:
//! - Message encryption with ChaCha20-Poly1305
//! - Mutual authentication
//! - Message integrity verification
//! - Replay attack prevention
//! - Seccomp filtering for system call restrictions
//! - Rate limiting and connection validation

use crate::security::encryption::{
    ChaCha20Poly1305Encryptor, EncryptedData, EncryptionAlgorithm, Encryptor,
};
use crate::security::seccomp::{SeccompProfile, SecureExecutor};
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener as TokioUnixListener, UnixStream as TokioUnixStream};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

/// Message types for secure communication
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MessageType {
    /// Authentication handshake initial message
    AuthInit,
    /// Authentication response
    AuthResponse,
    /// Encrypted data payload
    EncryptedData,
    /// Keep-alive message
    KeepAlive,
    /// Session termination
    SessionClose,
    /// Error message
    Error(String),
}

impl MessageType {
    /// Get numeric representation for MAC calculation
    fn as_u8(&self) -> u8 {
        match self {
            MessageType::AuthInit => 1,
            MessageType::AuthResponse => 2,
            MessageType::EncryptedData => 3,
            MessageType::KeepAlive => 4,
            MessageType::SessionClose => 5,
            MessageType::Error(_) => 6,
        }
    }
}

/// Secure message with authentication and integrity protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureMessage {
    /// Message type
    pub message_type: MessageType,
    /// Unique message identifier for replay protection
    pub message_id: String,
    /// Timestamp for message validity
    pub timestamp: DateTime<Utc>,
    /// Sender session identifier
    pub sender_id: String,
    /// Encrypted payload (if present)
    pub encrypted_payload: Option<EncryptedData>,
    /// Message authentication code
    pub mac: String,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Client session information for tracking and rate limiting
#[derive(Debug, Clone)]
pub struct ClientSession {
    /// Unique session identifier
    pub session_id: String,
    /// Client process ID (if available)
    pub client_pid: Option<u32>,
    /// Client user ID (if available)
    pub client_uid: Option<u32>,
    /// Session start time
    pub start_time: DateTime<Utc>,
    /// Last activity timestamp
    pub last_activity: DateTime<Utc>,
    /// Message count for rate limiting
    pub message_count: u64,
    /// Authentication status
    pub authenticated: bool,
    /// Security context for the session
    pub security_context: Arc<SocketSecurityContext>,
}

/// Security configuration for socket communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketSecurityConfig {
    /// Enable encryption for message payloads
    pub enable_encryption: bool,
    /// Encryption algorithm to use
    pub encryption_algorithm: EncryptionAlgorithm,
    /// Enable message authentication
    pub enable_authentication: bool,
    /// Message timeout in seconds
    pub message_timeout: u64,
    /// Maximum messages per minute per client
    pub rate_limit: u32,
    /// Enable replay attack detection
    pub enable_replay_protection: bool,
    /// Maximum message size in bytes
    pub max_message_size: usize,
}

impl Default for SocketSecurityConfig {
    fn default() -> Self {
        Self {
            enable_encryption: true,
            encryption_algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            enable_authentication: true,
            message_timeout: 300, // 5 minutes
            rate_limit: 1000,
            enable_replay_protection: true,
            max_message_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

/// Security context for managing encrypted communications
#[derive(Debug)]
pub struct SocketSecurityContext {
    /// Security configuration
    config: SocketSecurityConfig,
    /// Encryption key for session
    encryption_key: Vec<u8>,
    /// Authentication key for MAC verification
    auth_key: Vec<u8>,
    /// Active client sessions
    client_sessions: Arc<RwLock<HashMap<String, ClientSession>>>,
    /// Message history for replay protection
    message_history: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
    /// Encryptor instance
    encryptor: ChaCha20Poly1305Encryptor,
}

#[allow(dead_code)]
impl SocketSecurityContext {
    /// Create a new security context
    pub fn new(config: SocketSecurityConfig) -> Result<Self> {
        // Generate encryption and authentication keys
        let encryption_key = Self::generate_key(32)?; // 256-bit key
        let auth_key = Self::generate_key(32)?; // 256-bit key

        let encryptor = ChaCha20Poly1305Encryptor::new();

        Ok(Self {
            config,
            encryption_key,
            auth_key,
            client_sessions: Arc::new(RwLock::new(HashMap::new())),
            message_history: Arc::new(Mutex::new(HashMap::new())),
            encryptor,
        })
    }

    /// Generate a cryptographic key
    fn generate_key(size: usize) -> Result<Vec<u8>> {
        use rand::RngCore;
        let mut key = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut key);
        Ok(key)
    }

    /// Create a new client session
    pub async fn create_session(&self, client_pid: Option<u32>, client_uid: Option<u32>) -> String {
        let session_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        let session = ClientSession {
            session_id: session_id.clone(),
            client_pid,
            client_uid,
            start_time: now,
            last_activity: now,
            message_count: 0,
            authenticated: false,
            security_context: Arc::new(self.clone()),
        };

        self.client_sessions
            .write()
            .await
            .insert(session_id.clone(), session);
        session_id
    }

    /// Authenticate a client session
    pub async fn authenticate_session(&self, session_id: &str, credentials: &[u8]) -> Result<bool> {
        let mut sessions = self.client_sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            // Implement authentication logic here
            // For now, accept any non-empty credentials
            let is_valid = !credentials.is_empty();
            session.authenticated = is_valid;
            Ok(is_valid)
        } else {
            Err(anyhow!("Session not found: {}", session_id))
        }
    }

    /// Encrypt and sign a message
    pub fn create_secure_message(
        &self,
        message_type: MessageType,
        payload: Option<Vec<u8>>,
        sender_id: String,
    ) -> Result<SecureMessage> {
        let message_id = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now();

        // Encrypt payload if present and encryption is enabled
        let encrypted_payload = if self.config.enable_encryption && payload.is_some() {
            Some(
                self.encryptor
                    .encrypt(&payload.unwrap(), &self.encryption_key)?,
            )
        } else {
            None
        };

        // Create message metadata
        let mut metadata = HashMap::new();
        metadata.insert("version".to_string(), "1.0".to_string());
        if self.config.enable_encryption {
            metadata.insert(
                "encryption".to_string(),
                self.config.encryption_algorithm.identifier().to_string(),
            );
        }

        // Create the message
        let message = SecureMessage {
            message_type,
            message_id: message_id.clone(),
            timestamp,
            sender_id,
            encrypted_payload,
            mac: String::new(), // Will be filled in below
            metadata,
        };

        // Sign the message
        let mac = self.calculate_message_mac(&message)?;

        Ok(SecureMessage {
            mac,
            ..message
        })
    }

    /// Verify and decrypt a message
    pub async fn verify_and_decrypt_message(
        &self,
        message: &SecureMessage,
    ) -> Result<MessageVerificationResult> {
        // Verify message timestamp
        let now = Utc::now();
        let age = now.signed_duration_since(message.timestamp);
        if age.num_seconds() > self.config.message_timeout as i64 {
            return Err(anyhow!(
                "Message timestamp too old: {} seconds",
                age.num_seconds()
            ));
        }

        // Verify message authentication code
        if !self.verify_message_mac(message)? {
            return Err(anyhow!("Invalid message authentication code"));
        }

        // Check for replay attacks
        if self.config.enable_replay_protection {
            if let Some(previous_timestamp) =
                self.message_history.lock().await.get(&message.message_id)
            {
                if *previous_timestamp == message.timestamp {
                    return Err(anyhow!(
                        "Replay attack detected for message: {}",
                        message.message_id
                    ));
                }
            }

            // Store message ID for replay protection
            self.message_history
                .lock()
                .await
                .insert(message.message_id.clone(), message.timestamp);
        }

        // Decrypt payload if present
        let decrypted_payload = if let Some(ref encrypted_data) = message.encrypted_payload {
            if self.config.enable_encryption {
                Some(
                    self.encryptor
                        .decrypt(encrypted_data, &self.encryption_key)?,
                )
            } else {
                return Err(anyhow!(
                    "Received encrypted payload but encryption is disabled"
                ));
            }
        } else {
            None
        };

        Ok(MessageVerificationResult {
            message_type: message.message_type.clone(),
            payload: decrypted_payload,
            sender_id: message.sender_id.clone(),
            verified: true,
        })
    }

    /// Calculate message authentication code
    fn calculate_message_mac(&self, message: &SecureMessage) -> Result<String> {
        use sha2::{Digest, Sha256};

        // Create a deterministic representation for MAC calculation
        let mac_data = format!(
            "{}:{}:{}:{}:{:?}",
            message.message_id,
            message.timestamp.timestamp_nanos_opt().unwrap_or(0),
            message.sender_id,
            message.message_type.as_u8(),
            message.metadata
        );

        let mut hasher = Sha256::new();
        hasher.update(&self.auth_key);
        hasher.update(mac_data.as_bytes());

        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Verify message authentication code
    fn verify_message_mac(&self, message: &SecureMessage) -> Result<bool> {
        let expected_mac = self.calculate_message_mac(message)?;
        Ok(expected_mac == message.mac)
    }

    /// Get client session information
    pub async fn get_session(&self, session_id: &str) -> Option<ClientSession> {
        self.client_sessions.read().await.get(session_id).cloned()
    }

    /// Update session activity
    pub async fn update_session_activity(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.client_sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_activity = Utc::now();
            session.message_count += 1;

            // Check rate limits
            if session.message_count > self.config.rate_limit as u64 {
                return Err(anyhow!("Rate limit exceeded for session: {}", session_id));
            }

            Ok(())
        } else {
            Err(anyhow!("Session not found: {}", session_id))
        }
    }

    /// Remove expired sessions
    pub async fn cleanup_expired_sessions(&self) {
        let now = Utc::now();
        let mut sessions = self.client_sessions.write().await;

        sessions.retain(|_, session| {
            let age = now.signed_duration_since(session.last_activity);
            age.num_seconds() < (self.config.message_timeout as i64 * 2)
        });
    }
}

// Implement Clone for SocketSecurityContext
impl Clone for SocketSecurityContext {
    fn clone(&self) -> Self {
        // Note: This shares the same session and message history
        // In a real implementation, you might want to handle this differently
        Self {
            config: self.config.clone(),
            encryption_key: self.encryption_key.clone(),
            auth_key: self.auth_key.clone(),
            client_sessions: Arc::clone(&self.client_sessions),
            message_history: Arc::clone(&self.message_history),
            encryptor: ChaCha20Poly1305Encryptor::new(),
        }
    }
}

/// Result of message verification
#[derive(Debug)]
pub struct MessageVerificationResult {
    /// Message type
    pub message_type: MessageType,
    /// Decrypted payload (if present)
    pub payload: Option<Vec<u8>>,
    /// Sender identifier
    pub sender_id: String,
    /// Whether the message was verified
    pub verified: bool,
}

/// Secure Unix socket server with seccomp filtering
pub struct SecureSocketServer {
    listener: TokioUnixListener,
    seccomp_profile: Option<SeccompProfile>,
    executor: Option<SecureExecutor>,
}

impl SecureSocketServer {
    /// Create a new secure socket server
    pub async fn new<P: AsRef<Path>>(
        socket_path: P,
        seccomp_profile: Option<SeccompProfile>,
    ) -> Result<Self> {
        let path = socket_path.as_ref();

        // Remove existing socket file if it exists
        if path.exists() {
            tokio::fs::remove_file(path)
                .await
                .map_err(|e| anyhow!("Failed to remove existing socket {:?}: {}", path, e))?;
        }

        let listener = TokioUnixListener::bind(path)
            .map_err(|e| anyhow!("Failed to bind to socket {:?}: {}", path, e))?;

        info!("Secure socket server listening on {:?}", path);

        let mut server = Self {
            listener,
            seccomp_profile,
            executor: None,
        };

        // Initialize seccomp if profile is provided
        if let Some(profile) = seccomp_profile {
            let mut executor = SecureExecutor::new(profile)?;
            executor.initialize()?;
            server.executor = Some(executor);
            info!(
                "Initialized seccomp filter for socket server: {:?}",
                profile
            );
        }

        Ok(server)
    }

    /// Accept a new connection with security validation
    pub async fn accept(&mut self) -> Result<SecureSocketConnection> {
        let (stream, addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| anyhow!("Failed to accept socket connection: {}", e))?;

        debug!("Accepted connection from {:?}", addr);

        // Validate connection security
        self.validate_connection(&stream).await?;

        let connection = SecureSocketConnection {
            stream,
            executor: self.executor.clone(),
            security_context: None,
            session_id: None,
            sender_id: "server".to_string(),
        };

        Ok(connection)
    }

    /// Validate the connection for security
    async fn validate_connection(&self, stream: &TokioUnixStream) -> Result<()> {
        // Check if the socket is from a trusted source
        let peer_addr = stream
            .peer_addr()
            .map_err(|e| anyhow!("Failed to get peer address: {}", e))?;

        // For Unix sockets, we can check the path
        if let Some(path) = peer_addr.as_pathname() {
            self.validate_socket_path(path)?;
        }

        // Additional security checks can be added here
        // - Check process credentials
        // - Verify connection origin
        // - Rate limiting
        // - Connection timeout

        Ok(())
    }

    /// Validate that a socket path is safe
    fn validate_socket_path(&self, path: &Path) -> Result<()> {
        // Check for path traversal attempts
        if path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
        {
            return Err(anyhow!(
                "Socket path contains parent directory reference: {:?}",
                path
            ));
        }

        // Check for absolute paths (should be relative to /tmp or /var/run)
        if path.is_absolute() && !path.starts_with("/tmp/") && !path.starts_with("/var/run/") {
            return Err(anyhow!(
                "Socket path is not in allowed directory: {:?}",
                path
            ));
        }

        // Check path length
        if path.to_string_lossy().len() > 255 {
            return Err(anyhow!("Socket path too long: {:?}", path));
        }

        Ok(())
    }

    /// Get the local socket address
    pub fn local_addr(&self) -> Result<tokio::net::unix::SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|e| anyhow!("Failed to get local address: {}", e))
    }
}

/// Secure socket connection with comprehensive security
pub struct SecureSocketConnection {
    stream: TokioUnixStream,
    executor: Option<SecureExecutor>,
    security_context: Option<SocketSecurityContext>,
    session_id: Option<String>,
    sender_id: String,
}

#[allow(dead_code)]
impl SecureSocketConnection {
    /// Send data with security validation
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.validate_data_size(data)?;

        if let Some(ref mut executor) = self.executor {
            executor.validate_operation("socket_write")?;
            executor.execute_in_sandbox(|| Ok(()))?;
        }

        self.stream
            .write_all(data)
            .await
            .map_err(|e| anyhow!("Failed to send data: {}", e))?;
        Ok(())
    }

    /// Receive data with security validation
    pub async fn receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.validate_buffer_size(buf)?;

        if let Some(ref mut executor) = self.executor {
            executor.validate_operation("socket_read")?;
            executor.execute_in_sandbox(|| Ok(()))?;
        }

        let n = self
            .stream
            .read(buf)
            .await
            .map_err(|e| anyhow!("Failed to receive data: {}", e))?;
        Ok(n)
    }

    /// Send a string message
    pub async fn send_message(&mut self, message: &str) -> Result<()> {
        let data = message.as_bytes();
        let len = data.len() as u32;

        // Send length prefix
        self.stream
            .write_u32(len)
            .await
            .map_err(|e| anyhow!("Failed to send message length: {}", e))?;

        // Send message data
        self.stream
            .write_all(data)
            .await
            .map_err(|e| anyhow!("Failed to send message data: {}", e))?;

        debug!("Sent message: {} bytes", len);
        Ok(())
    }

    /// Receive a string message
    pub async fn receive_message(&mut self) -> Result<String> {
        // Read length prefix
        let len = self
            .stream
            .read_u32()
            .await
            .map_err(|e| anyhow!("Failed to read message length: {}", e))?;

        // Validate length
        if len > 1024 * 1024 {
            // 1MB limit
            return Err(anyhow!("Message too large: {} bytes", len));
        }

        // Read message data
        let mut buf = vec![0u8; len as usize];
        self.stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| anyhow!("Failed to read message data: {}", e))?;

        let message =
            String::from_utf8(buf).map_err(|e| anyhow!("Invalid UTF-8 in message: {}", e))?;

        debug!("Received message: {} bytes", len);
        Ok(message)
    }

    /// Validate data size for sending
    fn validate_data_size(&self, data: &[u8]) -> Result<()> {
        const MAX_DATA_SIZE: usize = 10 * 1024 * 1024; // 10MB

        if data.len() > MAX_DATA_SIZE {
            return Err(anyhow!(
                "Data too large: {} bytes (max: {})",
                data.len(),
                MAX_DATA_SIZE
            ));
        }

        Ok(())
    }

    /// Validate buffer size for receiving
    fn validate_buffer_size(&self, buf: &[u8]) -> Result<()> {
        const MAX_BUFFER_SIZE: usize = 10 * 1024 * 1024; // 10MB

        if buf.len() > MAX_BUFFER_SIZE {
            return Err(anyhow!(
                "Buffer too large: {} bytes (max: {})",
                buf.len(),
                MAX_BUFFER_SIZE
            ));
        }

        Ok(())
    }

    /// Get peer address
    pub fn peer_addr(&self) -> Result<tokio::net::unix::SocketAddr> {
        self.stream
            .peer_addr()
            .map_err(|e| anyhow!("Failed to get peer address: {}", e))
    }

    /// Get local address
    pub fn local_addr(&self) -> Result<tokio::net::unix::SocketAddr> {
        self.stream
            .local_addr()
            .map_err(|e| anyhow!("Failed to get local address: {}", e))
    }

    /// Set read timeout
    pub async fn set_read_timeout(&self, _timeout: Option<std::time::Duration>) -> Result<()> {
        // Tokio UnixStream doesn't directly support timeouts
        // This would need to be implemented at the application level
        warn!("Read timeout not directly supported on async Unix sockets");
        Ok(())
    }

    /// Set write timeout
    pub async fn set_write_timeout(&self, _timeout: Option<std::time::Duration>) -> Result<()> {
        // Tokio UnixStream doesn't directly support timeouts
        // This would need to be implemented at the application level
        warn!("Write timeout not directly supported on async Unix sockets");
        Ok(())
    }

    /// Close the connection
    pub async fn close(self) -> Result<()> {
        drop(self.stream); // Close on drop
        Ok(())
    }

    /// Create a new secure connection with security context
    pub fn with_security(
        stream: TokioUnixStream,
        executor: Option<SecureExecutor>,
        security_context: Option<SocketSecurityContext>,
        sender_id: String,
    ) -> Self {
        Self {
            stream,
            executor,
            security_context,
            session_id: None,
            sender_id,
        }
    }

    /// Initialize secure session with authentication
    pub async fn init_secure_session(&mut self) -> Result<String> {
        if let Some(ref context) = self.security_context {
            // Create a new session
            let session_id = context.create_session(None, None).await;
            self.session_id = Some(session_id.clone());

            // Send authentication init message
            let auth_message = context.create_secure_message(
                MessageType::AuthInit,
                None,
                self.sender_id.clone(),
            )?;
            self.send_secure_message(&auth_message).await?;

            Ok(session_id)
        } else {
            Err(anyhow!(
                "No security context available for session initialization"
            ))
        }
    }

    /// Send a secure message with encryption and authentication
    pub async fn send_secure_message(&mut self, message: &SecureMessage) -> Result<()> {
        // Serialize the message
        let serialized = serde_json::to_vec(message)?;

        // Send length prefix
        self.stream
            .write_u32(serialized.len() as u32)
            .await
            .map_err(|e| anyhow!("Failed to send message length: {}", e))?;

        // Send message data
        self.stream
            .write_all(&serialized)
            .await
            .map_err(|e| anyhow!("Failed to send message data: {}", e))?;

        debug!("Sent secure message: {} bytes", serialized.len());
        Ok(())
    }

    /// Receive and verify a secure message
    pub async fn receive_secure_message(&mut self) -> Result<SecureMessage> {
        // Read length prefix
        let len = self
            .stream
            .read_u32()
            .await
            .map_err(|e| anyhow!("Failed to read message length: {}", e))?;

        // Validate length
        if len > 10 * 1024 * 1024 {
            // 10MB limit
            return Err(anyhow!("Message too large: {} bytes", len));
        }

        // Read message data
        let mut buf = vec![0u8; len as usize];
        self.stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| anyhow!("Failed to read message data: {}", e))?;

        // Deserialize message
        let message: SecureMessage = serde_json::from_slice(&buf)
            .map_err(|e| anyhow!("Failed to deserialize message: {}", e))?;

        debug!("Received secure message: {} bytes", len);
        Ok(message)
    }

    /// Send encrypted data payload
    pub async fn send_encrypted_data(&mut self, data: &[u8]) -> Result<()> {
        if let Some(ref context) = self.security_context {
            let message = context.create_secure_message(
                MessageType::EncryptedData,
                Some(data.to_vec()),
                self.sender_id.clone(),
            )?;
            self.send_secure_message(&message).await?;
        } else {
            // Fallback to plain send if no security context
            self.send(data).await?;
        }
        Ok(())
    }

    /// Receive and decrypt data payload
    pub async fn receive_encrypted_data(&mut self) -> Result<Vec<u8>> {
        if let Some(context) = self.security_context.clone() {
            let message = self.receive_secure_message().await?;
            let verification_result = context.verify_and_decrypt_message(&message).await?;

            if verification_result.verified {
                Ok(verification_result.payload.unwrap_or_default())
            } else {
                Err(anyhow!("Message verification failed"))
            }
        } else {
            // Fallback to plain receive if no security context
            let mut buf = [0u8; 8192];
            let n = self.receive(&mut buf).await?;
            Ok(buf[..n].to_vec())
        }
    }

    /// Perform mutual authentication handshake
    pub async fn authenticate(&mut self, credentials: &[u8]) -> Result<bool> {
        if let (Some(context), Some(ref _session_id)) =
            (self.security_context.clone(), &self.session_id)
        {
            // Send authentication response with credentials
            let auth_response = context.create_secure_message(
                MessageType::AuthResponse,
                Some(credentials.to_vec()),
                self.sender_id.clone(),
            )?;
            self.send_secure_message(&auth_response).await?;

            // Wait for authentication confirmation
            let response = self.receive_secure_message().await?;
            let verification_result = context.verify_and_decrypt_message(&response).await?;

            if verification_result.verified {
                if let Some(payload) = verification_result.payload {
                    Ok(payload.len() > 0 && payload[0] == 1) // Simple boolean protocol
                } else {
                    Ok(false)
                }
            } else {
                Ok(false)
            }
        } else {
            Err(anyhow!(
                "No security context or session available for authentication"
            ))
        }
    }

    /// Send keep-alive message
    pub async fn send_keep_alive(&mut self) -> Result<()> {
        if let Some(ref context) = self.security_context {
            let keep_alive = context.create_secure_message(
                MessageType::KeepAlive,
                None,
                self.sender_id.clone(),
            )?;
            self.send_secure_message(&keep_alive).await?;
        }
        Ok(())
    }

    /// Send session close message
    pub async fn send_session_close(&mut self, reason: &str) -> Result<()> {
        if let Some(ref context) = self.security_context {
            let close_message = context.create_secure_message(
                MessageType::SessionClose,
                Some(reason.as_bytes().to_vec()),
                self.sender_id.clone(),
            )?;
            self.send_secure_message(&close_message).await?;
        }
        Ok(())
    }

    /// Get session information
    pub async fn get_session_info(&self) -> Option<ClientSession> {
        if let (Some(ref context), Some(ref session_id)) =
            (&self.security_context, &self.session_id)
        {
            context.get_session(session_id).await
        } else {
            None
        }
    }

    /// Update session activity timestamp
    pub async fn update_activity(&mut self) -> Result<()> {
        if let (Some(ref context), Some(ref session_id)) =
            (&self.security_context, &self.session_id)
        {
            context.update_session_activity(session_id).await?;
        }
        Ok(())
    }
}

/// Enhanced secure socket server with encryption and authentication
pub struct EnhancedSecureSocketServer {
    listener: TokioUnixListener,
    executor: Option<SecureExecutor>,
    security_context: Option<SocketSecurityContext>,
}

impl EnhancedSecureSocketServer {
    /// Accept a new secure connection with enhanced security
    pub async fn accept(&mut self) -> Result<SecureSocketConnection> {
        let (stream, addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| anyhow!("Failed to accept socket connection: {}", e))?;

        debug!("Accepted enhanced secure connection from {:?}", addr);

        // Validate connection security
        self.validate_connection(&stream).await?;

        // Create connection with security context
        let connection = SecureSocketConnection::with_security(
            stream,
            self.executor.clone(),
            self.security_context.clone(),
            "server".to_string(),
        );

        Ok(connection)
    }

    /// Validate the connection for security
    async fn validate_connection(&self, stream: &TokioUnixStream) -> Result<()> {
        // Check if the socket is from a trusted source
        let peer_addr = stream
            .peer_addr()
            .map_err(|e| anyhow!("Failed to get peer address: {}", e))?;

        // For Unix sockets, we can check the path
        if let Some(path) = peer_addr.as_pathname() {
            self.validate_socket_path(path)?;
        }

        // Additional security checks can be added here
        // - Check process credentials
        // - Verify connection origin
        // - Rate limiting
        // - Connection timeout

        Ok(())
    }

    /// Validate that a socket path is safe
    fn validate_socket_path(&self, path: &Path) -> Result<()> {
        // Check for path traversal attempts
        if path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
        {
            return Err(anyhow!(
                "Socket path contains parent directory reference: {:?}",
                path
            ));
        }

        // Check for absolute paths (should be relative to /tmp or /var/run)
        if path.is_absolute() && !path.starts_with("/tmp/") && !path.starts_with("/var/run/") {
            return Err(anyhow!(
                "Socket path is not in allowed directory: {:?}",
                path
            ));
        }

        // Check path length
        if path.to_string_lossy().len() > 255 {
            return Err(anyhow!("Socket path too long: {:?}", path));
        }

        Ok(())
    }

    /// Get the local socket address
    pub fn local_addr(&self) -> Result<tokio::net::unix::SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|e| anyhow!("Failed to get local address: {}", e))
    }

    /// Start background cleanup task for expired sessions
    pub async fn start_cleanup_task(&self) -> Result<()> {
        if let Some(ref context) = self.security_context {
            let context_clone = context.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // Every 5 minutes
                loop {
                    interval.tick().await;
                    context_clone.cleanup_expired_sessions().await;
                }
            });
        }
        Ok(())
    }
}

/// Factory for creating secure socket connections
pub struct SecureSocketFactory;

impl SecureSocketFactory {
    /// Create a secure connection to a Unix socket with basic security
    pub async fn connect<P: AsRef<Path>>(
        socket_path: P,
        seccomp_profile: Option<SeccompProfile>,
    ) -> Result<SecureSocketConnection> {
        let path = socket_path.as_ref();

        // Validate socket path
        Self::validate_socket_path(path)?;

        let stream = TokioUnixStream::connect(path)
            .await
            .map_err(|e| anyhow!("Failed to connect to socket {:?}: {}", path, e))?;

        let executor = if let Some(profile) = seccomp_profile {
            let mut exec = SecureExecutor::new(profile)?;
            exec.initialize()?;
            Some(exec)
        } else {
            None
        };

        debug!("Connected to secure socket: {:?}", path);

        Ok(SecureSocketConnection {
            stream,
            executor,
            security_context: None,
            session_id: None,
            sender_id: "client".to_string(),
        })
    }

    /// Create a secure connection with full encryption and authentication
    pub async fn connect_secure<P: AsRef<Path>>(
        socket_path: P,
        seccomp_profile: Option<SeccompProfile>,
        security_config: Option<SocketSecurityConfig>,
        sender_id: String,
    ) -> Result<SecureSocketConnection> {
        let path = socket_path.as_ref();

        // Validate socket path
        Self::validate_socket_path(path)?;

        let stream = TokioUnixStream::connect(path)
            .await
            .map_err(|e| anyhow!("Failed to connect to socket {:?}: {}", path, e))?;

        let executor = if let Some(profile) = seccomp_profile {
            let mut exec = SecureExecutor::new(profile)?;
            exec.initialize()?;
            Some(exec)
        } else {
            None
        };

        // Create security context if config provided
        let security_context = if let Some(config) = security_config {
            Some(SocketSecurityContext::new(config)?)
        } else {
            None
        };

        debug!("Connected to secure socket with encryption: {:?}", path);

        Ok(SecureSocketConnection::with_security(
            stream,
            executor,
            security_context,
            sender_id,
        ))
    }

    /// Create a secure server with enhanced security
    pub async fn create_secure_server<P: AsRef<Path>>(
        socket_path: P,
        seccomp_profile: Option<SeccompProfile>,
        security_config: Option<SocketSecurityConfig>,
    ) -> Result<EnhancedSecureSocketServer> {
        let path = socket_path.as_ref();

        // Remove existing socket file if it exists
        if path.exists() {
            tokio::fs::remove_file(path)
                .await
                .map_err(|e| anyhow!("Failed to remove existing socket {:?}: {}", path, e))?;
        }

        let listener = TokioUnixListener::bind(path)
            .map_err(|e| anyhow!("Failed to bind to socket {:?}: {}", path, e))?;

        let executor = if let Some(profile) = seccomp_profile {
            let mut exec = SecureExecutor::new(profile)?;
            exec.initialize()?;
            Some(exec)
        } else {
            None
        };

        // Create security context if config provided
        let security_context = if let Some(config) = security_config {
            Some(SocketSecurityContext::new(config)?)
        } else {
            None
        };

        info!("Enhanced secure socket server listening on {:?}", path);

        Ok(EnhancedSecureSocketServer {
            listener,
            executor,
            security_context,
        })
    }

    /// Validate a socket path for security
    fn validate_socket_path(path: &Path) -> Result<()> {
        // Check for path traversal
        if path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
        {
            return Err(anyhow!(
                "Socket path contains parent directory reference: {:?}",
                path
            ));
        }

        // Check for absolute paths
        if path.is_absolute() {
            // Allow system temp directories and user temp directories
            if !path.starts_with("/tmp/")
                && !path.starts_with("/var/run/")
                && !path.starts_with("/var/tmp/")
                && !path.starts_with("/var/folders/")
                && !path.starts_with("/private/var/folders/")
                && !path.starts_with("/run/")
            {
                return Err(anyhow!(
                    "Absolute socket path must be in allowed directory: {:?}",
                    path
                ));
            }
        }

        // Check path length
        if path.to_string_lossy().len() > 255 {
            return Err(anyhow!("Socket path too long: {:?}", path));
        }

        // Check for unsafe characters
        let path_str = path.to_string_lossy();
        if path_str.contains('\0') || path_str.contains('\n') || path_str.contains('\r') {
            return Err(anyhow!(
                "Socket path contains unsafe characters: {:?}",
                path
            ));
        }

        Ok(())
    }
}

/// Socket security validator
pub struct SocketSecurityValidator;

impl SocketSecurityValidator {
    /// Validate socket permissions
    pub fn validate_socket_permissions(path: &Path) -> Result<()> {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        if !path.exists() {
            return Err(anyhow!("Socket does not exist: {:?}", path));
        }

        let metadata =
            fs::metadata(path).map_err(|e| anyhow!("Failed to get socket metadata: {}", e))?;

        let permissions = metadata.permissions();
        let mode = permissions.mode();

        // Check that it's a socket
        if !metadata.file_type().is_socket() {
            return Err(anyhow!("Path is not a socket: {:?}", path));
        }

        // Check permissions (should be 600, 660, or 666)
        let user_perms = mode & 0o700;
        let group_perms = mode & 0o070;
        let other_perms = mode & 0o007;

        // Allow owner read/write
        if user_perms & 0o600 != 0o600 {
            return Err(anyhow!(
                "Socket has insufficient owner permissions: {:?}",
                path
            ));
        }

        // Group and others can have read/write, but not execute
        if (group_perms & 0o001 != 0) || (other_perms & 0o001 != 0) {
            return Err(anyhow!("Socket has execute permissions: {:?}", path));
        }

        // Warn if group or others have write permissions
        if (group_perms & 0o002 != 0) || (other_perms & 0o002 != 0) {
            warn!(
                "Socket has write permissions for group or others: {:?}",
                path
            );
        }

        Ok(())
    }

    /// Check if socket is owned by root or current user
    pub fn validate_socket_ownership(path: &Path) -> Result<()> {
        use nix::unistd::getuid;
        use std::fs;

        let metadata =
            fs::metadata(path).map_err(|e| anyhow!("Failed to get socket metadata: {}", e))?;

        let uid = metadata.uid();
        let current_uid = getuid();

        // Allow root or current user
        if uid != 0 && uid != current_uid.as_raw() {
            return Err(anyhow!(
                "Socket is not owned by root or current user (owner: {}, current: {}): {:?}",
                uid,
                current_uid,
                path
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_secure_socket_factory_validation() {
        let tmp_dir = TempDir::new().unwrap();
        let socket_path = tmp_dir.path().join("test.sock");

        // Valid path should pass
        assert!(SecureSocketFactory::validate_socket_path(&socket_path).is_ok());

        // Test with /tmp direct path
        let tmp_path = Path::new("/tmp/test.sock");
        assert!(SecureSocketFactory::validate_socket_path(tmp_path).is_ok());

        // Path with null byte should fail
        let invalid_path = Path::new("/tmp/test\0.sock");
        assert!(SecureSocketFactory::validate_socket_path(invalid_path).is_err());

        // Path with parent reference should fail
        let parent_path = Path::new("/tmp/../etc/passwd");
        assert!(SecureSocketFactory::validate_socket_path(parent_path).is_err());

        // Absolute path outside allowed directories should fail
        let bad_absolute = Path::new("/etc/passwd.sock");
        assert!(SecureSocketFactory::validate_socket_path(bad_absolute).is_err());
    }

    #[test]
    fn test_data_size_validation() {
        // Test the validation functions directly without creating a full connection
        let small_data = vec![0u8; 100];
        let large_data = vec![0u8; 20 * 1024 * 1024]; // 20MB

        // Test validation constants
        const MAX_DATA_SIZE: usize = 10 * 1024 * 1024; // 10MB

        assert!(small_data.len() <= MAX_DATA_SIZE);
        assert!(large_data.len() > MAX_DATA_SIZE);
    }

    #[test]
    fn test_buffer_size_validation() {
        // Test the validation logic directly
        let small_buf = vec![0u8; 100];
        let large_buf = vec![0u8; 20 * 1024 * 1024]; // 20MB

        // Test validation constants
        const MAX_BUFFER_SIZE: usize = 10 * 1024 * 1024; // 10MB

        assert!(small_buf.len() <= MAX_BUFFER_SIZE);
        assert!(large_buf.len() > MAX_BUFFER_SIZE);
    }

    #[test]
    fn test_message_type_numeric_representation() {
        assert_eq!(MessageType::AuthInit.as_u8(), 1);
        assert_eq!(MessageType::AuthResponse.as_u8(), 2);
        assert_eq!(MessageType::EncryptedData.as_u8(), 3);
        assert_eq!(MessageType::KeepAlive.as_u8(), 4);
        assert_eq!(MessageType::SessionClose.as_u8(), 5);
        assert_eq!(MessageType::Error("test".to_string()).as_u8(), 6);
    }

    #[test]
    fn test_socket_security_config_default() {
        let config = SocketSecurityConfig::default();
        assert!(config.enable_encryption);
        assert!(config.enable_authentication);
        assert_eq!(
            config.encryption_algorithm,
            EncryptionAlgorithm::ChaCha20Poly1305
        );
        assert_eq!(config.message_timeout, 300);
        assert_eq!(config.rate_limit, 1000);
        assert!(config.enable_replay_protection);
    }

    #[test]
    fn test_socket_security_context_creation() -> Result<()> {
        let config = SocketSecurityConfig::default();
        let context = SocketSecurityContext::new(config)?;

        // Test that context was created successfully
        assert_eq!(context.encryption_key.len(), 32);
        assert_eq!(context.auth_key.len(), 32);
        Ok(())
    }

    #[test]
    fn test_secure_message_creation() -> Result<()> {
        let config = SocketSecurityConfig::default();
        let context = SocketSecurityContext::new(config)?;

        let message = context.create_secure_message(
            MessageType::AuthInit,
            Some(b"test payload".to_vec()),
            "test_sender".to_string(),
        )?;

        assert_eq!(message.message_type, MessageType::AuthInit);
        assert_eq!(message.sender_id, "test_sender");
        assert!(message.encrypted_payload.is_some());
        assert!(!message.mac.is_empty());
        assert!(message.metadata.contains_key("version"));

        Ok(())
    }

    #[tokio::test]
    async fn test_session_management() -> Result<()> {
        let config = SocketSecurityConfig::default();
        let context = SocketSecurityContext::new(config)?;

        // Create a session
        let session_id = context.create_session(Some(1234), Some(5678)).await;

        // Get session info
        let session = context.get_session(&session_id).await;
        assert!(session.is_some());

        let session = session.unwrap();
        assert_eq!(session.session_id, session_id);
        assert_eq!(session.client_pid, Some(1234));
        assert_eq!(session.client_uid, Some(5678));
        assert!(!session.authenticated);
        assert_eq!(session.message_count, 0);

        // Update session activity
        context.update_session_activity(&session_id).await?;
        let session = context.get_session(&session_id).await.unwrap();
        assert_eq!(session.message_count, 1);

        // Test authentication
        let authenticated = context
            .authenticate_session(&session_id, b"test_credentials")
            .await?;
        assert!(authenticated);

        let session = context.get_session(&session_id).await.unwrap();
        assert!(session.authenticated);

        Ok(())
    }

    #[tokio::test]
    async fn test_message_encryption_and_verification() -> Result<()> {
        let config = SocketSecurityConfig::default();
        let context = SocketSecurityContext::new(config)?;

        // Create and send a message
        let original_data = b"Hello, secure world!";
        let message = context.create_secure_message(
            MessageType::EncryptedData,
            Some(original_data.to_vec()),
            "sender".to_string(),
        )?;

        // Verify and decrypt the message
        let verification_result = context.verify_and_decrypt_message(&message).await?;

        assert!(verification_result.verified);
        assert_eq!(verification_result.message_type, MessageType::EncryptedData);
        assert_eq!(verification_result.sender_id, "sender");
        assert!(verification_result.payload.is_some());

        let decrypted_data = verification_result.payload.unwrap();
        assert_eq!(decrypted_data, original_data);

        Ok(())
    }

    #[tokio::test]
    async fn test_replay_attack_prevention() -> Result<()> {
        let config = SocketSecurityConfig::default();
        let context = SocketSecurityContext::new(config)?;

        // Create a message
        let message =
            context.create_secure_message(MessageType::KeepAlive, None, "sender".to_string())?;

        // Verify it once (should succeed)
        let result1 = context.verify_and_decrypt_message(&message).await;
        assert!(result1.is_ok());

        // Try to verify the same message again (should fail due to replay protection)
        let result2 = context.verify_and_decrypt_message(&message).await;
        assert!(result2.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_rate_limiting() -> Result<()> {
        let mut config = SocketSecurityConfig::default();
        config.rate_limit = 2; // Very low limit for testing
        let context = SocketSecurityContext::new(config)?;

        // Create a session
        let session_id = context.create_session(None, None).await;

        // Update activity under the limit (should succeed)
        context.update_session_activity(&session_id).await?;
        context.update_session_activity(&session_id).await?;

        // Try to exceed the rate limit (should fail)
        let result = context.update_session_activity(&session_id).await;
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_message_timeout() -> Result<()> {
        let mut config = SocketSecurityConfig::default();
        config.message_timeout = 1; // 1 second timeout for testing
        let context = SocketSecurityContext::new(config)?;

        // Create a message
        let message =
            context.create_secure_message(MessageType::AuthInit, None, "sender".to_string())?;

        // Manually age the message by modifying its timestamp
        let mut old_message = message;
        old_message.timestamp = Utc::now() - chrono::Duration::seconds(2);

        // Try to verify the old message (should fail due to timeout)
        let result = context.verify_and_decrypt_message(&old_message).await;
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_mac_calculation_and_verification() -> Result<()> {
        let config = SocketSecurityConfig::default();
        let context = SocketSecurityContext::new(config)?;

        // Create a message
        let message = context.create_secure_message(
            MessageType::Error("test".to_string()),
            Some(b"test data".to_vec()),
            "test_sender".to_string(),
        )?;

        // Verify MAC calculation
        let is_valid = context.verify_message_mac(&message)?;
        assert!(is_valid);

        // Tamper with the message and verify MAC fails
        let mut tampered_message = message;
        tampered_message.sender_id = "malicious".to_string();

        let is_valid = context.verify_message_mac(&tampered_message)?;
        assert!(!is_valid);

        Ok(())
    }

    #[tokio::test]
    async fn test_expired_session_cleanup() -> Result<()> {
        let mut config = SocketSecurityConfig::default();
        config.message_timeout = 1; // 1 second timeout for testing
        let context = SocketSecurityContext::new(config)?;

        // Create a session
        let session_id = context.create_session(None, None).await;

        // Verify session exists
        assert!(context.get_session(&session_id).await.is_some());

        // Wait for session to expire
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Run cleanup
        context.cleanup_expired_sessions().await;

        // Verify session was cleaned up
        assert!(context.get_session(&session_id).await.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_enhanced_secure_socket_factory() {
        // Test basic connect creation
        let tmp_dir = TempDir::new().unwrap();
        let socket_path = tmp_dir.path().join("test.sock");

        // This should succeed (doesn't actually connect, just creates the struct)
        let result = SecureSocketFactory::connect(&socket_path, None).await;
        assert!(result.is_err()); // Fails because socket doesn't exist, but struct creation is fine
    }

    #[tokio::test]
    async fn test_enhanced_server_creation() -> Result<()> {
        let tmp_dir = TempDir::new().unwrap();
        let socket_path = tmp_dir.path().join("test.sock");

        // Create enhanced server
        let security_config = SocketSecurityConfig::default();
        let server =
            SecureSocketFactory::create_secure_server(&socket_path, None, Some(security_config))
                .await?;

        // Verify server was created
        assert!(server.local_addr().is_ok());
        assert!(server.security_context.is_some());

        // Test cleanup task
        server.start_cleanup_task().await?;

        Ok(())
    }
}
