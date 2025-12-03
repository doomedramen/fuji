use thiserror::Error;

#[derive(Error, Debug)]
pub enum FujiError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Nix error: {0}")]
    Nix(#[from] nix::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("Daemon not running")]
    DaemonNotRunning,

    #[error("Invalid command: {0}")]
    InvalidCommand(String),

    #[error("Mount operation failed: {0}")]
    MountFailed(String),

    #[error("Unmount operation failed: {0}")]
    UnmountFailed(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Platform not supported")]
    PlatformNotSupported,

    #[error("Socket error: {0}")]
    Socket(String),

    #[error("Command execution failed: {0}")]
    CommandFailed(String),

    #[error("Mount not found: {0}")]
    MountNotFound(String),

    #[error("Mount point already exists: {0}")]
    MountPointExists(String),

    #[error("Network unreachable: {0}")]
    NetworkUnreachable(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Server not responding: {0}")]
    ServerNotResponding(String),

    #[error("Invalid mount URL: {0}")]
    InvalidMountUrl(String),
}

pub type Result<T> = std::result::Result<T, FujiError>;
