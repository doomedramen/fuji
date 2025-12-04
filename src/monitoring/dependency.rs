//! Dependency graph management using petgraph
//!
//! Manages mount dependencies and provides ordered startup/shutdown sequences.

use anyhow::{anyhow, Context, Result};
use petgraph::{
    algo::toposort,
    graph::{DiGraph, NodeIndex},
    visit::EdgeRef,
    EdgeDirection::{Incoming, Outgoing},
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use crate::mount::MountConfig;

/// Dependency graph manager
pub struct DependencyGraph {
    /// Directed graph where nodes are mount IDs
    graph: Arc<RwLock<DiGraph<(), DependencyEdge>>>,
    /// Mount configurations indexed by node
    mounts: Arc<RwLock<HashMap<String, NodeIndex>>>,
    /// Reverse index from node to mount ID
    reverse_index: Arc<RwLock<HashMap<NodeIndex, String>>>,
}

/// Edge in the dependency graph
#[derive(Debug, Clone, Default)]
pub struct DependencyEdge {
    /// Type of dependency
    pub dependency_type: DependencyType,
    /// Optional metadata
    pub metadata: std::collections::HashMap<String, String>,
}

/// Types of dependencies between mounts
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyType {
    /// Hard dependency - dependent cannot work without this dependency
    Hard,
    /// Soft dependency - dependent prefers this dependency to be available
    Soft,
    /// Order preference - startup order preference but not required
    Order,
}

impl Default for DependencyType {
    fn default() -> Self {
        DependencyType::Soft
    }
}

/// Dependency validation result
#[derive(Debug, Clone)]
pub struct DependencyValidation {
    /// Whether validation passed
    pub valid: bool,
    /// Errors found
    pub errors: Vec<String>,
    /// Warnings found
    pub warnings: Vec<String>,
}

/// Startup/shutdown sequence
#[derive(Debug, Clone)]
pub struct Sequence {
    /// Ordered list of mount IDs
    pub mounts: Vec<String>,
    /// Groups of mounts that can be started in parallel
    pub parallel_groups: Vec<Vec<String>>,
}

impl DependencyGraph {
    /// Create a new dependency graph
    pub fn new() -> Self {
        Self {
            graph: Arc::new(RwLock::new(DiGraph::new())),
            mounts: Arc::new(RwLock::new(HashMap::new())),
            reverse_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a mount to the graph
    pub async fn add_mount(&self, mount_config: &MountConfig) -> Result<()> {
        let mount_id = mount_config.id.clone();

        let mut graph = self.graph.write().await;
        let mut mounts = self.mounts.write().await;
        let mut reverse_index = self.reverse_index.write().await;

        // Check if mount already exists
        if mounts.contains_key(&mount_id) {
            return Err(anyhow!(
                "Mount {} already exists in dependency graph",
                mount_id
            ));
        }

        // Add node to graph
        let node_index = graph.add_node(());

        // Update indexes
        mounts.insert(mount_id.clone(), node_index);
        reverse_index.insert(node_index, mount_id.clone());

        debug!("Added mount {} to dependency graph", mount_id);
        Ok(())
    }

    /// Remove a mount from the graph
    pub async fn remove_mount(&self, mount_id: &str) -> Result<()> {
        let mut graph = self.graph.write().await;
        let mut mounts = self.mounts.write().await;
        let mut reverse_index = self.reverse_index.write().await;

        // Get node index
        if let Some(node_index) = mounts.remove(mount_id) {
            // Remove from reverse index
            reverse_index.remove(&node_index);

            // Remove node from graph
            if graph.remove_node(node_index).is_none() {
                // Node might have dependencies, remove edges first
                let outgoing_edge_ids: Vec<_> = graph
                    .edges_directed(node_index, Outgoing)
                    .map(|edge| edge.id())
                    .collect();

                for edge_id in outgoing_edge_ids {
                    let _ = graph.remove_edge(edge_id);
                }

                // Now try removing the node again
                if graph.remove_node(node_index).is_none() {
                    error!("Failed to remove node {} from graph", node_index.index());
                }
            }

            info!("Removed mount {} from dependency graph", mount_id);
        }

        Ok(())
    }

    /// Add a dependency between mounts
    pub async fn add_dependency(
        &self,
        dependent_id: &str,
        dependency_id: &str,
        dependency_type: DependencyType,
        metadata: Option<std::collections::HashMap<String, String>>,
    ) -> Result<()> {
        let mut graph = self.graph.write().await;
        let mounts = self.mounts.read().await;

        // Get node indices
        let dependent_index = mounts
            .get(dependent_id)
            .ok_or_else(|| anyhow!("Dependent mount {} not found", dependent_id))?;
        let dependency_index = mounts
            .get(dependency_id)
            .ok_or_else(|| anyhow!("Dependency mount {} not found", dependency_id))?;

        // Create edge
        let edge = DependencyEdge {
            dependency_type: dependency_type.clone(),
            metadata: metadata.unwrap_or_default(),
        };

        graph.add_edge(*dependency_index, *dependent_index, edge);

        debug!(
            "Added dependency: {} -> {} ({:?})",
            dependent_id, dependency_id, dependency_type
        );
        Ok(())
    }

    /// Remove a dependency between mounts
    pub async fn remove_dependency(&self, dependent_id: &str, dependency_id: &str) -> Result<()> {
        let mut graph = self.graph.write().await;
        let mounts = self.mounts.read().await;

        // Get node indices
        let dependent_index = mounts
            .get(dependent_id)
            .ok_or_else(|| anyhow!("Dependent mount {} not found", dependent_id))?;
        let dependency_index = mounts
            .get(dependency_id)
            .ok_or_else(|| anyhow!("Dependency mount {} not found", dependency_id))?;

        // Find and remove edges
        let edge_ids: Vec<_> = graph
            .edges_connecting(*dependency_index, *dependent_index)
            .map(|edge| edge.id())
            .collect();

        for edge_id in edge_ids {
            if graph.remove_edge(edge_id).is_some() {
                debug!("Removed dependency: {} -> {}", dependent_id, dependency_id);
            }
        }

        Ok(())
    }

    /// Validate dependencies for a mount configuration
    pub fn validate_dependencies(
        &self,
        mount_config: &MountConfig,
    ) -> Result<DependencyValidation> {
        let mut validation = DependencyValidation {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        };

        // Check for self-dependency
        let mount_id = &mount_config.id;
        if let Some(dep_str) = mount_config.metadata.get("depends_on") {
            for dep_id in dep_str.split(',') {
                let dep_id = dep_id.trim();
                if dep_id == mount_id {
                    validation
                        .errors
                        .push(format!("Mount {} depends on itself", mount_id));
                    validation.valid = false;
                }
            }
        }

        // Validate that dependencies exist (will be checked at runtime)
        if let Some(dep_str) = mount_config.metadata.get("depends_on") {
            for dep_id in dep_str.split(',') {
                let dep_id = dep_id.trim();
                if dep_id.is_empty() {
                    continue;
                }
                // TODO: Check if dependency exists in the system
                debug!("Mount {} depends on {}", mount_id, dep_id);
            }
        }

        Ok(validation)
    }

    /// Get startup sequence (topological sort)
    pub async fn get_startup_sequence(&self) -> Result<Sequence> {
        let graph = self.graph.read().await;
        let _mounts = self.mounts.read().await;
        let reverse_index = self.reverse_index.read().await;

        // Perform topological sort
        let sorted_indices = toposort(&*graph, None).map_err(|_e| {
            anyhow!("Failed to sort dependencies: cycle detected in dependency graph")
        })?;

        // Convert indices to mount IDs
        let mount_ids: Vec<String> = sorted_indices
            .iter()
            .filter_map(|&index| reverse_index.get(&index).cloned())
            .collect();

        // Determine parallel groups
        let parallel_groups = self.determine_parallel_groups(&*graph, &mount_ids).await;

        Ok(Sequence {
            mounts: mount_ids,
            parallel_groups,
        })
    }

    /// Get shutdown sequence (reverse of startup)
    pub async fn get_shutdown_sequence(&self) -> Result<Sequence> {
        let startup = self.get_startup_sequence().await?;
        let mounts = startup.mounts.into_iter().rev().collect();
        let parallel_groups = startup.parallel_groups.into_iter().rev().collect();

        Ok(Sequence {
            mounts,
            parallel_groups,
        })
    }

    /// Determine which mounts can be started in parallel
    async fn determine_parallel_groups(
        &self,
        graph: &DiGraph<(), DependencyEdge>,
        mount_ids: &[String],
    ) -> Vec<Vec<String>> {
        let reverse_index = self.reverse_index.read().await;
        let mut groups = Vec::new();
        let mut processed = HashSet::new();

        for mount_id in mount_ids {
            if processed.contains(mount_id) {
                continue;
            }

            // Get dependencies
            let mut group = Vec::new();
            let mut to_check = vec![mount_id.clone()];
            let mut can_add = true;

            while let Some(current_id) = to_check.pop() {
                if processed.contains(&current_id) {
                    continue;
                }

                // Get node index - search reverse_index for the node
                let node_index = if let Some((idx, _)) =
                    reverse_index.iter().find(|(_, id)| *id == &current_id)
                {
                    *idx
                } else {
                    continue;
                };

                // Check incoming edges (dependencies)
                let mut has_unprocessed_deps = false;
                for edge in graph.edges_directed(node_index, petgraph::Direction::Incoming) {
                    let source_id = reverse_index
                        .get(&edge.source())
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string());
                    if !processed.contains(&source_id) {
                        has_unprocessed_deps = true;
                        break;
                    }
                }

                if has_unprocessed_deps {
                    can_add = false;
                } else {
                    group.push(current_id.clone());
                    processed.insert(current_id.clone());
                }
            }

            if can_add && !group.is_empty() {
                groups.push(group);
            }
        }

        groups
    }

    /// Get all dependencies for a mount
    pub async fn get_dependencies(&self, mount_id: &str) -> Result<Vec<String>> {
        let graph = self.graph.read().await;
        let mounts = self.mounts.read().await;
        let reverse_index = self.reverse_index.read().await;

        if let Some(node_index) = mounts.get(mount_id) {
            let dependencies: Vec<String> = graph
                .edges_directed(*node_index, Incoming)
                .map(|edge| {
                    reverse_index
                        .get(&edge.source())
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string())
                })
                .collect();

            Ok(dependencies)
        } else {
            Err(anyhow!("Mount {} not found in dependency graph", mount_id))
        }
    }

    /// Get all dependents (mounts that depend on this mount)
    pub async fn get_dependents(&self, mount_id: &str) -> Result<Vec<String>> {
        let graph = self.graph.read().await;
        let mounts = self.mounts.read().await;
        let reverse_index = self.reverse_index.read().await;

        if let Some(node_index) = mounts.get(mount_id) {
            let dependents: Vec<String> = graph
                .edges_directed(*node_index, Outgoing)
                .map(|edge| {
                    reverse_index
                        .get(&edge.target())
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string())
                })
                .collect();

            Ok(dependents)
        } else {
            Err(anyhow!("Mount {} not found in dependency graph", mount_id))
        }
    }

    /// Check for circular dependencies
    pub async fn check_circular_dependencies(&self) -> Vec<Vec<String>> {
        let graph = self.graph.read().await;
        let reverse_index = self.reverse_index.read().await;

        // Use DFS to find cycles
        let mut cycles = Vec::new();
        let mut visited = HashSet::new();
        let mut stack = Vec::new();

        for node_index in graph.node_indices() {
            if !visited.contains(&node_index) {
                if let Some(cycle) = self.dfs_find_cycle(
                    &*graph,
                    &reverse_index,
                    node_index,
                    &mut visited,
                    &mut stack,
                ) {
                    cycles.push(cycle);
                }
            }
        }

        cycles
    }

    /// DFS helper to find cycles
    fn dfs_find_cycle(
        &self,
        graph: &DiGraph<(), DependencyEdge>,
        reverse_index: &HashMap<NodeIndex, String>,
        node: NodeIndex,
        visited: &mut HashSet<NodeIndex>,
        stack: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        if stack.len() > 1000 {
            // Prevent infinite recursion
            return None;
        }

        if visited.contains(&node) {
            // Check if node is in current stack (cycle detected)
            if let Some(mount_id) = reverse_index.get(&node) {
                if let Some(pos) = stack.iter().position(|id| id == mount_id) {
                    return Some(stack[pos..].to_vec());
                }
            }
            return None;
        }

        visited.insert(node);
        if let Some(mount_id) = reverse_index.get(&node) {
            stack.push(mount_id.clone());
        }

        // Visit neighbors
        for neighbor in graph.neighbors(node) {
            if let Some(cycle) = self.dfs_find_cycle(graph, reverse_index, neighbor, visited, stack)
            {
                return Some(cycle);
            }
        }

        if let Some(_mount_id) = reverse_index.get(&node) {
            stack.pop();
        }

        None
    }

    /// Visualize the dependency graph as DOT format
    pub async fn visualize_dot(&self) -> String {
        let graph = self.graph.read().await;
        let reverse_index = self.reverse_index.read().await;

        let mut dot = String::from("digraph dependencies {\n");
        dot.push_str("  rankdir=LR;\n");

        // Add nodes
        for node_index in graph.node_indices() {
            if let Some(mount_id) = reverse_index.get(&node_index) {
                dot.push_str(&format!("  \"{}\";\n", mount_id));
            }
        }

        // Add edges
        for edge in graph.edge_references() {
            let source = reverse_index
                .get(&edge.source())
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let target = reverse_index
                .get(&edge.target())
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());

            let edge_style = match edge.weight().dependency_type {
                DependencyType::Hard => "style=solid",
                DependencyType::Soft => "style=dashed",
                DependencyType::Order => "style=dotted",
            };

            dot.push_str(&format!(
                "  \"{}\" -> \"{}\" [{}];\n",
                source, target, edge_style
            ));
        }

        dot.push_str("}\n");
        dot
    }

    /// Export dependency graph to Graphviz DOT file
    pub async fn export_dot_file(&self, file_path: &str) -> Result<()> {
        let dot_content = self.visualize_dot().await;
        std::fs::write(file_path, dot_content).context("Failed to write DOT file")?;
        info!("Exported dependency graph to {}", file_path);
        Ok(())
    }
}

impl Default for DependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dependency_graph_creation() {
        let graph = DependencyGraph::new();
        assert!(graph.mounts.read().await.is_empty());
    }

    #[tokio::test]
    async fn test_add_mount() {
        let graph = DependencyGraph::new();

        let config = MountConfig::new(
            "test://example.com/share".to_string(),
            crate::mount::MountType::NFS {
                host: "example.com".to_string(),
                share: "/share".to_string(),
                options: vec![],
            },
            "/mnt/test".into(),
        );

        assert!(graph.add_mount(&config).await.is_ok());
        assert!(graph
            .mounts
            .read()
            .await
            .contains_key("example.com_test_share"));
    }

    #[tokio::test]
    async fn test_dependencies() {
        let graph = DependencyGraph::new();

        // Add mounts
        let config1 = MountConfig::new(
            "nfs://example1.com/share".to_string(),
            crate::mount::MountType::NFS {
                host: "example1.com".to_string(),
                share: "/share".to_string(),
                options: vec![],
            },
            "/mnt/mount1".into(),
        );

        let config2 = MountConfig::new(
            "smb://example2.com/share".to_string(),
            crate::mount::MountType::SMB {
                host: "example2.com".to_string(),
                share: "share".to_string(),
                username: None,
                password: None,
                domain: None,
                options: vec![],
            },
            "/mnt/mount2".into(),
        );

        graph.add_mount(&config1).await.unwrap();
        graph.add_mount(&config2).await.unwrap();

        // Add dependency using generated IDs
        graph
            .add_dependency(
                "example2.com_smb_share",
                "example1.com_nfs_share",
                DependencyType::Hard,
                None,
            )
            .await
            .unwrap();

        // Check dependencies
        let deps = graph
            .get_dependencies("example2.com_smb_share")
            .await
            .unwrap();
        assert_eq!(deps, vec!["example1.com_nfs_share"]);

        let dependents = graph
            .get_dependents("example1.com_nfs_share")
            .await
            .unwrap();
        assert_eq!(dependents, vec!["example2.com_smb_share"]);
    }

    #[tokio::test]
    async fn test_startup_sequence() {
        let graph = DependencyGraph::new();

        // Create mounts with dependencies
        let config1 = MountConfig::new(
            "nfs://example1.com/share".to_string(),
            crate::mount::MountType::NFS {
                host: "example1.com".to_string(),
                share: "/share".to_string(),
                options: vec![],
            },
            "/mnt/m1".into(),
        );

        let config2 = MountConfig::new(
            "smb://example2.com/share".to_string(),
            crate::mount::MountType::SMB {
                host: "example2.com".to_string(),
                share: "share".to_string(),
                username: None,
                password: None,
                domain: None,
                options: vec![],
            },
            "/mnt/m2".into(),
        );

        let config3 = MountConfig::new(
            "nfs://example3.com/share".to_string(),
            crate::mount::MountType::NFS {
                host: "example3.com".to_string(),
                share: "/share".to_string(),
                options: vec![],
            },
            "/mnt/m3".into(),
        );

        graph.add_mount(&config1).await.unwrap();
        graph.add_mount(&config2).await.unwrap();
        graph.add_mount(&config3).await.unwrap();

        // Add dependencies: mount2 depends on mount1, mount3 depends on mount1
        // Use the generated IDs
        graph
            .add_dependency(
                "example2.com_smb_share",
                "example1.com_nfs_share",
                DependencyType::Hard,
                None,
            )
            .await
            .unwrap();
        graph
            .add_dependency(
                "example3.com_nfs_share",
                "example1.com_nfs_share",
                DependencyType::Soft,
                None,
            )
            .await
            .unwrap();

        // Get startup sequence
        let sequence = graph.get_startup_sequence().await.unwrap();

        // Since all three mounts are added with dependencies, example1.com_nfs_share should come first
        // as both other mounts depend on it
        assert_eq!(sequence.mounts[0], "example1.com_nfs_share");

        // The other two should come after (order between them doesn't matter)
        assert!(sequence
            .mounts
            .contains(&"example2.com_smb_share".to_string()));
        assert!(sequence
            .mounts
            .contains(&"example3.com_nfs_share".to_string()));

        // Verify that example1.com_nfs_share only appears once
        assert_eq!(
            sequence
                .mounts
                .iter()
                .filter(|&id| id == "example1.com_nfs_share")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn test_circular_dependency_detection() {
        let graph = DependencyGraph::new();

        // Create mounts
        let config1 = MountConfig::new(
            "mount1".to_string(),
            crate::mount::MountType::NFS {
                host: "example1.com".to_string(),
                share: "/share".to_string(),
                options: vec![],
            },
            "/mnt/m1".into(),
        );

        let config2 = MountConfig::new(
            "mount2".to_string(),
            crate::mount::MountType::SMB {
                host: "example2.com".to_string(),
                share: "share".to_string(),
                username: None,
                password: None,
                domain: None,
                options: vec![],
            },
            "/mnt/m2".into(),
        );

        let config3 = MountConfig::new(
            "mount3".to_string(),
            crate::mount::MountType::NFS {
                host: "example3.com".to_string(),
                share: "/share".to_string(),
                options: vec![],
            },
            "/mnt/m3".into(),
        );

        graph.add_mount(&config1).await.unwrap();
        graph.add_mount(&config2).await.unwrap();
        graph.add_mount(&config3).await.unwrap();

        // Add circular dependency: mount1 -> mount2 -> mount3 -> mount1
        graph
            .add_dependency("mount2", "mount1", DependencyType::Hard, None)
            .await
            .unwrap();
        graph
            .add_dependency("mount3", "mount2", DependencyType::Hard, None)
            .await
            .unwrap();
        graph
            .add_dependency("mount1", "mount3", DependencyType::Hard, None)
            .await
            .unwrap();

        // Check for circular dependencies
        let cycles = graph.check_circular_dependencies().await;
        assert!(!cycles.is_empty());

        // Cycle should contain all three mounts
        let cycle = &cycles[0];
        assert_eq!(cycle.len(), 3);
    }
}
