//! Fuji - A network file system mount manager with daemon-based architecture
//!
//! This library provides the core functionality for mounting and managing network file systems.

pub mod cli;
pub mod cluster;
pub mod config;
pub mod daemon;
pub mod monitoring;
pub mod mount;
pub mod network;
pub mod platform;
pub mod security;
pub mod socket;
pub mod sync;

// Re-export main types for external use
pub use config::Config;
pub use mount::{MountConfig, MountType};
pub use platform::Platform;
