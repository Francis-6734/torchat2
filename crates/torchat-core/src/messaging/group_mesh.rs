//! Mesh topology management for decentralized groups.
//!
//! Implements peer selection and rotation for gossip mesh networks:
//! - Maintains 3-5 neighbor connections per group
//! - Random neighbor selection on join
//! - Periodic rotation for privacy and load balancing
//! - Blind membership mode (only know neighbors)
//! - Neighbor health tracking

use crate::error::{Error, Result};
use crate::protocol::GroupMember;
use crate::tor::TorConnection;
use rand::seq::SliceRandom;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Default number of neighbors to maintain.
pub const DEFAULT_NEIGHBOR_COUNT: usize = 5;

/// Minimum number of neighbors before requesting more.
pub const MIN_NEIGHBOR_COUNT: usize = 3;

/// Neighbor rotation interval (1 hour).
pub const ROTATION_INTERVAL: Duration = Duration::from_secs(3600);

/// Neighbor connection timeout (30 seconds).
pub const NEIGHBOR_TIMEOUT: Duration = Duration::from_secs(30);

/// Neighbor information and connection state.
#[derive(Debug, Clone)]
pub struct NeighborInfo {
    /// Member ID of the neighbor.
    pub member_id: [u8; 16],
    /// Onion address of the neighbor.
    pub onion_address: String,
    /// Member's public key.
    pub pubkey: [u8; 32],
    /// Last time we saw activity from this neighbor.
    pub last_seen: Instant,
    /// Number of messages received from this neighbor.
    pub message_count: u64,
    /// Is this a stable neighbor (kept across rotations).
    pub is_stable: bool,
}

impl NeighborInfo {
    /// Create a new neighbor info.
    pub fn new(member_id: [u8; 16], onion_address: String, pubkey: [u8; 32]) -> Self {
        Self {
            member_id,
            onion_address,
            pubkey,
            last_seen: Instant::now(),
            message_count: 0,
            is_stable: false,
        }
    }

    /// Check if neighbor is healthy (recently active).
    pub fn is_healthy(&self) -> bool {
        self.last_seen.elapsed() < NEIGHBOR_TIMEOUT
    }

    /// Update last seen timestamp.
    pub fn mark_seen(&mut self) {
        self.last_seen = Instant::now();
    }

    /// Increment message count.
    pub fn increment_messages(&mut self) {
        self.message_count = self.message_count.saturating_add(1);
    }
}

/// Mesh topology manager.
///
/// Manages neighbor connections for a group's gossip mesh network.
pub struct MeshTopology {
    /// Group ID this mesh belongs to.
    group_id: [u8; 32],
    /// Current neighbors (member_id -> info).
    neighbors: HashMap<[u8; 16], NeighborInfo>,
    /// Target number of neighbors to maintain.
    target_neighbor_count: usize,
    /// Last time we rotated neighbors.
    last_rotation: Instant,
    /// Rotation interval.
    rotation_interval: Duration,
}

impl MeshTopology {
    /// Create a new mesh topology manager.
    pub fn new(group_id: [u8; 32], target_neighbors: usize) -> Self {
        Self {
            group_id,
            neighbors: HashMap::new(),
            target_neighbor_count: target_neighbors.max(MIN_NEIGHBOR_COUNT),
            last_rotation: Instant::now(),
            rotation_interval: ROTATION_INTERVAL,
        }
    }

    /// Initialize neighbors from bootstrap member list.
    ///
    /// Randomly selects initial neighbors from the provided list.
    pub fn initialize_neighbors(&mut self, mut member_list: Vec<GroupMember>) {
        if member_list.is_empty() {
            warn!("Cannot initialize mesh with empty member list");
            return;
        }

        // Shuffle for random selection
        member_list.shuffle(&mut OsRng);

        // Select up to target_neighbor_count members
        for member in member_list.into_iter().take(self.target_neighbor_count) {
            if let Some(onion_address) = member.onion_address {
                let neighbor = NeighborInfo::new(
                    member.member_id,
                    onion_address,
                    member.pubkey,
                );

                self.neighbors.insert(member.member_id, neighbor);
                debug!(
                    member_id = ?member.member_id,
                    "Added initial neighbor to mesh"
                );
            }
        }

        info!(
            neighbor_count = self.neighbors.len(),
            "Initialized mesh topology"
        );
    }

    /// Add a specific neighbor to the mesh.
    pub fn add_neighbor(&mut self, member: GroupMember) {
        if let Some(onion_address) = member.onion_address {
            let neighbor = NeighborInfo::new(
                member.member_id,
                onion_address,
                member.pubkey,
            );

            self.neighbors.insert(member.member_id, neighbor);
            debug!(member_id = ?member.member_id, "Added neighbor to mesh");
        }
    }

    /// Remove a neighbor from the mesh.
    pub fn remove_neighbor(&mut self, member_id: &[u8; 16]) {
        if self.neighbors.remove(member_id).is_some() {
            debug!(member_id = ?member_id, "Removed neighbor from mesh");
        }
    }

    /// Get a neighbor by member ID.
    pub fn get_neighbor(&self, member_id: &[u8; 16]) -> Option<&NeighborInfo> {
        self.neighbors.get(member_id)
    }

    /// Get a mutable reference to a neighbor.
    pub fn get_neighbor_mut(&mut self, member_id: &[u8; 16]) -> Option<&mut NeighborInfo> {
        self.neighbors.get_mut(member_id)
    }

    /// Mark a neighbor as seen (update activity timestamp).
    pub fn mark_neighbor_seen(&mut self, member_id: &[u8; 16]) {
        if let Some(neighbor) = self.neighbors.get_mut(member_id) {
            neighbor.mark_seen();
        }
    }

    /// Increment message count for a neighbor.
    pub fn increment_neighbor_messages(&mut self, member_id: &[u8; 16]) {
        if let Some(neighbor) = self.neighbors.get_mut(member_id) {
            neighbor.increment_messages();
        }
    }

    /// Get all active neighbors (healthy within timeout).
    pub fn active_neighbors(&self) -> impl Iterator<Item = &NeighborInfo> {
        self.neighbors.values().filter(|n| n.is_healthy())
    }

    /// Get all neighbors regardless of health status.
    /// Use this for message forwarding since there's no heartbeat mechanism.
    pub fn all_neighbors(&self) -> impl Iterator<Item = &NeighborInfo> {
        self.neighbors.values()
    }

    /// Get all neighbor onion addresses.
    pub fn neighbor_addresses(&self) -> Vec<String> {
        self.neighbors.values().map(|n| n.onion_address.clone()).collect()
    }

    /// Get number of neighbors.
    pub fn neighbor_count(&self) -> usize {
        self.neighbors.len()
    }

    /// Check if we need more neighbors.
    pub fn needs_more_neighbors(&self) -> bool {
        self.neighbors.len() < MIN_NEIGHBOR_COUNT
    }

    /// Rotate neighbors for privacy and load balancing.
    ///
    /// Keeps the most active neighbors stable, rotates others.
    /// This prevents traffic analysis while maintaining connectivity.
    pub fn rotate_neighbors(&mut self, all_members: &[GroupMember]) {
        // Check if rotation is due
        if self.last_rotation.elapsed() < self.rotation_interval {
            return;
        }

        debug!("Starting neighbor rotation");

        // Determine how many stable neighbors to keep (half of target)
        let stable_count = self.target_neighbor_count / 2;

        // Sort neighbors by message count (most active first)
        let mut neighbor_vec: Vec<_> = self.neighbors.values().cloned().collect();
        neighbor_vec.sort_by(|a, b| b.message_count.cmp(&a.message_count));

        // Mark top N as stable
        self.neighbors.clear();
        for (i, neighbor) in neighbor_vec.iter().enumerate().take(stable_count) {
            let mut neighbor = neighbor.clone();
            neighbor.is_stable = i < stable_count;
            self.neighbors.insert(neighbor.member_id, neighbor);
        }

        // Add new random neighbors to reach target count
        let needed = self.target_neighbor_count.saturating_sub(self.neighbors.len());
        if needed > 0 {
            // Get candidates (members not currently neighbors)
            let current_ids: Vec<_> = self.neighbors.keys().copied().collect();
            let mut candidates: Vec<_> = all_members
                .iter()
                .filter(|m| !current_ids.contains(&m.member_id))
                .filter(|m| m.onion_address.is_some())
                .cloned()
                .collect();

            // Shuffle and add
            candidates.shuffle(&mut OsRng);
            for member in candidates.into_iter().take(needed) {
                if let Some(onion_address) = member.onion_address {
                    let neighbor = NeighborInfo::new(
                        member.member_id,
                        onion_address,
                        member.pubkey,
                    );
                    self.neighbors.insert(member.member_id, neighbor);
                }
            }
        }

        self.last_rotation = Instant::now();
        info!(
            neighbor_count = self.neighbors.len(),
            stable_count,
            "Rotated neighbors"
        );
    }

    /// Remove unhealthy neighbors.
    pub fn prune_unhealthy_neighbors(&mut self) {
        let before_count = self.neighbors.len();

        self.neighbors.retain(|_, neighbor| neighbor.is_healthy());

        let removed = before_count - self.neighbors.len();
        if removed > 0 {
            warn!(removed, "Pruned unhealthy neighbors from mesh");
        }
    }
}

/// Blind membership manager.
///
/// In blind mode, members only know their direct neighbors, not the full roster.
/// This provides stronger privacy guarantees against traffic analysis.
pub struct BlindMembershipManager {
    /// Our member ID.
    our_member_id: [u8; 16],
    /// Known neighbors (member_id -> member info).
    known_neighbors: HashMap<[u8; 16], GroupMember>,
    /// Last time we requested new neighbors.
    last_neighbor_request: Option<Instant>,
}

impl BlindMembershipManager {
    /// Create a new blind membership manager.
    pub fn new(our_member_id: [u8; 16]) -> Self {
        Self {
            our_member_id,
            known_neighbors: HashMap::new(),
            last_neighbor_request: None,
        }
    }

    /// Add a known neighbor.
    pub fn add_neighbor(&mut self, member: GroupMember) {
        self.known_neighbors.insert(member.member_id, member);
    }

    /// Remove a neighbor.
    pub fn remove_neighbor(&mut self, member_id: &[u8; 16]) {
        self.known_neighbors.remove(member_id);
    }

    /// Get all visible members (only neighbors in blind mode).
    pub fn get_visible_members(&self) -> Vec<GroupMember> {
        self.known_neighbors.values().cloned().collect()
    }

    /// Get neighbor count.
    pub fn neighbor_count(&self) -> usize {
        self.known_neighbors.len()
    }

    /// Check if we should request more neighbors.
    pub fn should_request_neighbors(&self) -> bool {
        // Request if we have too few neighbors
        if self.known_neighbors.len() < MIN_NEIGHBOR_COUNT {
            return true;
        }

        // Or if we haven't requested recently
        if let Some(last_request) = self.last_neighbor_request {
            last_request.elapsed() > Duration::from_secs(600) // 10 minutes
        } else {
            false
        }
    }

    /// Mark that we requested neighbors.
    pub fn mark_neighbor_request(&mut self) {
        self.last_neighbor_request = Some(Instant::now());
    }

    /// Get a random neighbor to request from.
    pub fn get_random_neighbor(&self) -> Option<&GroupMember> {
        let neighbors: Vec<_> = self.known_neighbors.values().collect();
        neighbors.choose(&mut OsRng).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_member(id: u8, onion: &str) -> GroupMember {
        GroupMember {
            member_id: [id; 16],
            onion_address: Some(onion.to_string()),
            pubkey: [id; 32],
            is_admin: false,
            joined_at: 0,
        }
    }

    #[test]
    fn test_mesh_initialization() {
        let group_id = [1u8; 32];
        let mut mesh = MeshTopology::new(group_id, 3);

        let members = vec![
            create_test_member(1, "peer1.onion"),
            create_test_member(2, "peer2.onion"),
            create_test_member(3, "peer3.onion"),
            create_test_member(4, "peer4.onion"),
            create_test_member(5, "peer5.onion"),
        ];

        mesh.initialize_neighbors(members);

        assert_eq!(mesh.neighbor_count(), 3);
    }

    #[test]
    fn test_add_remove_neighbor() {
        let group_id = [1u8; 32];
        let mut mesh = MeshTopology::new(group_id, 5);

        let member = create_test_member(1, "peer1.onion");
        mesh.add_neighbor(member.clone());

        assert_eq!(mesh.neighbor_count(), 1);
        assert!(mesh.get_neighbor(&[1u8; 16]).is_some());

        mesh.remove_neighbor(&[1u8; 16]);
        assert_eq!(mesh.neighbor_count(), 0);
    }

    #[test]
    fn test_needs_more_neighbors() {
        let group_id = [1u8; 32];
        let mut mesh = MeshTopology::new(group_id, 5);

        assert!(mesh.needs_more_neighbors());

        for i in 0..3 {
            mesh.add_neighbor(create_test_member(i, &format!("peer{}.onion", i)));
        }

        assert!(!mesh.needs_more_neighbors());
    }

    #[test]
    fn test_blind_membership() {
        let our_id = [1u8; 16];
        let mut blind_mgr = BlindMembershipManager::new(our_id);

        assert_eq!(blind_mgr.neighbor_count(), 0);

        blind_mgr.add_neighbor(create_test_member(2, "peer2.onion"));
        blind_mgr.add_neighbor(create_test_member(3, "peer3.onion"));

        assert_eq!(blind_mgr.neighbor_count(), 2);
        assert_eq!(blind_mgr.get_visible_members().len(), 2);

        blind_mgr.remove_neighbor(&[2u8; 16]);
        assert_eq!(blind_mgr.neighbor_count(), 1);
    }

    #[test]
    fn test_should_request_neighbors() {
        let our_id = [1u8; 16];
        let blind_mgr = BlindMembershipManager::new(our_id);

        // Should request when we have too few
        assert!(blind_mgr.should_request_neighbors());
    }
}
