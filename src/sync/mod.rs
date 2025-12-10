//! Configuration synchronization module for Fuji cluster

pub mod coordinator;
pub mod merge;
pub mod protocol;

// pub use coordinator::{PendingSync, SyncCoordinator};
// pub use merge::{ConfigMerger, ConflictResolutionStrategy, MergedConfig};
// pub use protocol::{
//     ConfigUpdate, ConflictResolution, ConflictType, Heartbeat, MountConflict, MountVersion,
//     NodeStatus, SyncComplete, SyncMessage, SyncRequest, SyncResponse, SyncResult,
// };
