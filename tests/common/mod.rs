//! Shared test utilities for integration and E2E tests
//!
//! This module provides reusable components for testing Fuji:
//! - Docker environment management
//! - Daemon lifecycle management
//! - Mount operations with auto-cleanup
//! - File I/O verification helpers
//! - Custom assertions

#![allow(dead_code, unused_imports)]

pub mod assertions;
pub mod daemon;
pub mod docker;
pub mod filesystem;
pub mod mount;

// Re-export commonly used types for convenience
pub use assertions::*;
pub use daemon::TestDaemon;
pub use docker::DockerEnvironment;
pub use filesystem::*;
pub use mount::TestMount;
