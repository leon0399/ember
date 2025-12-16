//! Merkle DAG gap detection for message ordering.
//!
//! This module provides tools for detecting missing messages in the DAG
//! using content-addressed IDs (ContentId).

use std::collections::{HashMap, HashSet};

use crate::ContentId;

/// Result of processing an incoming message for DAG ordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GapResult {
    /// Message has complete ancestry (all parents known).
    Complete,
    /// Message is missing one or more parents.
    Gap {
        /// Content IDs of missing parent messages.
        missing: Vec<ContentId>,
    },
}

/// Information about an orphaned message (missing parent).
#[derive(Debug, Clone)]
pub struct OrphanInfo {
    /// The content_id of the missing parent.
    pub missing_parent: ContentId,
    /// Timestamp (ms) when this orphan was received.
    pub received_at_ms: u64,
}

/// Detects gaps in the message DAG from the receiver's perspective.
///
/// Tracks which messages have complete ancestry and which are "orphans"
/// waiting for their parent messages to arrive.
#[derive(Debug, Default)]
pub struct ReceiverGapDetector {
    /// Messages received with complete ancestry (all parents known).
    complete: HashSet<ContentId>,

    /// Messages missing their parent (content_id -> orphan info).
    orphans: HashMap<ContentId, OrphanInfo>,

    /// Index: missing parent -> orphans waiting for it.
    /// Enables O(1) lookup when resolving orphans instead of O(N) scan.
    waiting_on: HashMap<ContentId, Vec<ContentId>>,
}

impl ReceiverGapDetector {
    /// Create a new gap detector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Process an incoming message and determine if there are gaps.
    ///
    /// # Arguments
    /// * `content_id` - The content ID of the received message
    /// * `prev_self` - The sender's previous message (if any)
    /// * `received_at_ms` - Current timestamp in milliseconds
    ///
    /// # Returns
    /// `GapResult::Complete` if all parents are known, or `GapResult::Gap`
    /// with the list of missing parent IDs.
    pub fn on_receive(
        &mut self,
        content_id: ContentId,
        prev_self: Option<ContentId>,
        received_at_ms: u64,
    ) -> GapResult {
        match prev_self {
            None => {
                // First message from this sender, no parent needed
                self.complete.insert(content_id);
                self.try_resolve_orphans(content_id);
                GapResult::Complete
            }
            Some(parent_id) => {
                if self.complete.contains(&parent_id) {
                    // Parent exists and is complete
                    self.complete.insert(content_id);
                    self.try_resolve_orphans(content_id);
                    GapResult::Complete
                } else {
                    // Parent missing - this is an orphan
                    self.orphans.insert(
                        content_id,
                        OrphanInfo {
                            missing_parent: parent_id,
                            received_at_ms,
                        },
                    );
                    // Index for O(1) lookup when parent arrives
                    self.waiting_on.entry(parent_id).or_default().push(content_id);
                    GapResult::Gap {
                        missing: vec![parent_id],
                    }
                }
            }
        }
    }

    /// Mark a content_id as complete without checking parents.
    ///
    /// Use this for messages received through alternative means (e.g., resync)
    /// where we know the content is valid but don't have the parent chain.
    pub fn mark_complete(&mut self, content_id: ContentId) {
        self.complete.insert(content_id);
        self.try_resolve_orphans(content_id);
    }

    /// Check if a message is complete (has known ancestry).
    pub fn is_complete(&self, content_id: &ContentId) -> bool {
        self.complete.contains(content_id)
    }

    /// Check if a message is an orphan (missing parent).
    pub fn is_orphan(&self, content_id: &ContentId) -> bool {
        self.orphans.contains_key(content_id)
    }

    /// Get all orphaned messages.
    pub fn orphans(&self) -> impl Iterator<Item = (&ContentId, &OrphanInfo)> {
        self.orphans.iter()
    }

    /// Get the number of complete messages.
    pub fn complete_count(&self) -> usize {
        self.complete.len()
    }

    /// Get the number of orphaned messages.
    pub fn orphan_count(&self) -> usize {
        self.orphans.len()
    }

    /// Get all missing parent IDs (for requesting retransmission).
    pub fn missing_parents(&self) -> HashSet<ContentId> {
        self.orphans
            .values()
            .map(|info| info.missing_parent)
            .collect()
    }

    /// Try to resolve orphans when a new message becomes complete.
    ///
    /// Uses iterative approach with work queue to avoid stack overflow
    /// when resolving long chains of orphaned messages.
    /// Uses `waiting_on` index for O(1) lookup per resolution.
    fn try_resolve_orphans(&mut self, new_complete_id: ContentId) {
        let mut work_queue = vec![new_complete_id];

        while let Some(complete_id) = work_queue.pop() {
            // O(1) lookup: get orphans waiting for this message
            if let Some(waiting) = self.waiting_on.remove(&complete_id) {
                for child_id in waiting {
                    if self.orphans.remove(&child_id).is_some() {
                        self.complete.insert(child_id);
                        work_queue.push(child_id);
                    }
                }
            }
        }
    }

    /// Clear all tracking data.
    pub fn clear(&mut self) {
        self.complete.clear();
        self.orphans.clear();
        self.waiting_on.clear();
    }
}

/// Tracks sent messages and detects what the peer is missing.
///
/// When we receive a message from a peer, their `observed_heads` tells us
/// what they've seen from us. We can compare this to our sent messages
/// to determine what needs to be retransmitted.
///
/// # Multi-Head Support
///
/// This implementation tracks multiple heads (leaf nodes) to support:
/// - Multi-device: same user sending from phone + laptop creates forks
/// - Concurrent sends: race conditions can create parallel branches
///
/// Each head represents a leaf node in our sent message DAG. When a new
/// message is sent, its parent is removed from heads (no longer a leaf)
/// and the new message becomes a head.
#[derive(Debug, Default)]
pub struct SenderGapDetector {
    /// Messages we've sent, keyed by content_id.
    /// Value is the previous message's content_id (for chain traversal).
    sent: HashMap<ContentId, Option<ContentId>>,

    /// Current leaf nodes (heads) of our sent message DAG.
    /// Multiple heads occur with multi-device or concurrent sends.
    heads: HashSet<ContentId>,
}

impl SenderGapDetector {
    /// Create a new sender gap detector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that we sent a message.
    ///
    /// # Arguments
    /// * `content_id` - The content ID of the sent message
    /// * `prev_self` - Our previous message's content ID (if any)
    pub fn on_send(&mut self, content_id: ContentId, prev_self: Option<ContentId>) {
        self.sent.insert(content_id, prev_self);
        // Remove parent from heads (it's no longer a leaf node)
        if let Some(parent) = prev_self {
            self.heads.remove(&parent);
        }
        // Add new message as a head (leaf node)
        self.heads.insert(content_id);
    }

    /// Get one of our current heads (for use as prev_self in next message).
    ///
    /// Returns an arbitrary head if multiple exist. For single-device
    /// sequential sends, there's always exactly one head.
    pub fn head(&self) -> Option<ContentId> {
        self.heads.iter().next().copied()
    }

    /// Get all current heads (leaf nodes of our sent DAG).
    pub fn heads(&self) -> &HashSet<ContentId> {
        &self.heads
    }

    /// Determine which messages the peer is missing based on their observed_heads.
    ///
    /// # Arguments
    /// * `peer_observed` - The content IDs the peer has observed from us
    ///
    /// # Returns
    /// List of content IDs that need to be retransmitted, sorted for consistency.
    pub fn find_missing(&self, peer_observed: &[ContentId]) -> Vec<ContentId> {
        // If peer hasn't observed anything from us, they're missing everything
        if peer_observed.is_empty() {
            return self.all_sent_ordered();
        }

        // Filter to only messages we know about
        let seen: HashSet<ContentId> = peer_observed
            .iter()
            .filter(|id| self.sent.contains_key(*id))
            .copied()
            .collect();

        if seen.is_empty() {
            // Peer hasn't seen any of our messages
            return self.all_sent_ordered();
        }

        // Get all messages not seen by peer (accounting for ancestor chains)
        self.messages_not_seen(&seen)
    }

    /// Get all sent messages (traversing from all heads).
    ///
    /// Note: With multiple heads (forks), order is not strictly defined.
    /// Messages are collected via DFS from all heads, then reversed.
    fn all_sent_ordered(&self) -> Vec<ContentId> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut stack: Vec<ContentId> = self.heads.iter().copied().collect();

        // DFS from all heads (using stack with pop)
        while let Some(id) = stack.pop() {
            if visited.insert(id) {
                result.push(id);
                if let Some(Some(parent)) = self.sent.get(&id) {
                    stack.push(*parent);
                }
            }
        }

        // Reverse to get roughly oldest-first order
        result.reverse();
        result
    }

    /// Get messages the peer is missing given what they've seen.
    ///
    /// Returns all messages that are NOT ancestors of (or equal to) any seen message.
    fn messages_not_seen(&self, seen: &HashSet<ContentId>) -> Vec<ContentId> {
        // First, find all ancestors of seen messages (including seen themselves)
        let mut known_to_peer = seen.clone();
        let mut queue: Vec<ContentId> = seen.iter().copied().collect();

        while let Some(id) = queue.pop() {
            if let Some(Some(parent)) = self.sent.get(&id) {
                if known_to_peer.insert(*parent) {
                    queue.push(*parent);
                }
            }
        }

        // Now collect all messages NOT known to peer
        let mut result: Vec<ContentId> = self
            .sent
            .keys()
            .filter(|id| !known_to_peer.contains(*id))
            .copied()
            .collect();

        // Sort for consistent ordering (by byte value)
        result.sort();
        result
    }

    /// Get the number of sent messages being tracked.
    pub fn sent_count(&self) -> usize {
        self.sent.len()
    }

    /// Check if a content_id is known (we have record of sending it).
    ///
    /// Used to detect if peer saw messages we don't remember sending
    /// (indicates we lost state).
    pub fn is_known(&self, content_id: &ContentId) -> bool {
        self.sent.contains_key(content_id)
    }

    /// Clear all tracking data.
    pub fn clear(&mut self) {
        self.sent.clear();
        self.heads.clear();
    }
}

/// Per-conversation DAG state combining receiver and sender detection.
#[derive(Debug, Default)]
pub struct ConversationDag {
    /// Tracks gaps in messages we receive.
    pub receiver: ReceiverGapDetector,
    /// Tracks what peer is missing from us.
    pub sender: SenderGapDetector,
    /// Current epoch for this conversation.
    pub epoch: u16,
    /// The peer's current heads (leaf nodes of their sent DAG).
    /// Used to construct observed_heads when we send messages.
    /// Multiple heads occur with multi-device peers.
    peer_heads: HashSet<ContentId>,
}

impl ConversationDag {
    /// Create a new conversation DAG tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with a specific epoch.
    pub fn with_epoch(epoch: u16) -> Self {
        Self {
            receiver: ReceiverGapDetector::new(),
            sender: SenderGapDetector::new(),
            epoch,
            peer_heads: HashSet::new(),
        }
    }

    /// Increment the epoch (e.g., when clearing history).
    pub fn increment_epoch(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.receiver.clear();
        self.sender.clear();
        self.peer_heads.clear();
    }

    /// Reset peer tracking state when peer has advanced their epoch.
    ///
    /// Call this when receiving a message with a higher epoch than tracked.
    /// This indicates the peer intentionally cleared their history, so we
    /// reset our receiver and peer_heads without affecting our sender state.
    pub fn reset_for_peer_epoch(&mut self, new_epoch: u16) {
        self.epoch = new_epoch;
        self.receiver.clear();
        self.peer_heads.clear();
    }

    /// Update peer heads when receiving a message.
    ///
    /// Call this when receiving a complete (non-orphan) message from the peer.
    /// Removes the parent from heads (no longer a leaf) and adds the new message.
    ///
    /// # Arguments
    /// * `content_id` - The content ID of the received message
    /// * `prev_self` - The message's prev_self (peer's parent reference)
    pub fn update_peer_heads(&mut self, content_id: ContentId, prev_self: Option<ContentId>) {
        // Remove parent from heads (it's no longer a leaf node)
        if let Some(parent) = prev_self {
            self.peer_heads.remove(&parent);
        }
        // Add new message as a head
        self.peer_heads.insert(content_id);
    }

    /// Get all peer heads for observed_heads.
    ///
    /// Returns a vector of the peer's current head content_ids
    /// to include in our outgoing messages.
    pub fn observed_heads(&self) -> Vec<ContentId> {
        self.peer_heads.iter().copied().collect()
    }

    /// Check if we have received any messages from the peer.
    ///
    /// Returns true if we've seen at least one message from them.
    pub fn has_peer_history(&self) -> bool {
        !self.peer_heads.is_empty()
    }

    /// Check if any of the given content_ids are unknown to our sender tracker.
    ///
    /// This detects if the peer has seen messages from us that we don't remember
    /// sending (indicates we lost state).
    pub fn has_unknown_observed(&self, observed: &[ContentId]) -> bool {
        observed.iter().any(|id| !self.sender.is_known(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_id(n: u8) -> ContentId {
        [n, 0, 0, 0, 0, 0, 0, 0]
    }

    mod receiver_tests {
        use super::*;

        #[test]
        fn test_first_message_complete() {
            let mut detector = ReceiverGapDetector::new();
            let id = make_id(1);

            let result = detector.on_receive(id, None, 1000);

            assert_eq!(result, GapResult::Complete);
            assert!(detector.is_complete(&id));
            assert!(!detector.is_orphan(&id));
        }

        #[test]
        fn test_message_with_known_parent() {
            let mut detector = ReceiverGapDetector::new();
            let id1 = make_id(1);
            let id2 = make_id(2);

            detector.on_receive(id1, None, 1000);
            let result = detector.on_receive(id2, Some(id1), 2000);

            assert_eq!(result, GapResult::Complete);
            assert!(detector.is_complete(&id2));
        }

        #[test]
        fn test_message_with_missing_parent() {
            let mut detector = ReceiverGapDetector::new();
            let id1 = make_id(1);
            let id2 = make_id(2);

            // Receive id2 without id1
            let result = detector.on_receive(id2, Some(id1), 2000);

            assert_eq!(
                result,
                GapResult::Gap {
                    missing: vec![id1]
                }
            );
            assert!(detector.is_orphan(&id2));
            assert!(!detector.is_complete(&id2));
        }

        #[test]
        fn test_orphan_resolved_when_parent_arrives() {
            let mut detector = ReceiverGapDetector::new();
            let id1 = make_id(1);
            let id2 = make_id(2);

            // Receive id2 first (orphan)
            detector.on_receive(id2, Some(id1), 2000);
            assert!(detector.is_orphan(&id2));

            // Now receive id1
            detector.on_receive(id1, None, 1000);

            // id2 should now be complete
            assert!(detector.is_complete(&id1));
            assert!(detector.is_complete(&id2));
            assert!(!detector.is_orphan(&id2));
        }

        #[test]
        fn test_chain_of_orphans_resolved() {
            let mut detector = ReceiverGapDetector::new();
            let id1 = make_id(1);
            let id2 = make_id(2);
            let id3 = make_id(3);

            // Receive in reverse order
            detector.on_receive(id3, Some(id2), 3000);
            detector.on_receive(id2, Some(id1), 2000);

            assert!(detector.is_orphan(&id3));
            assert!(detector.is_orphan(&id2));

            // Receive the root
            detector.on_receive(id1, None, 1000);

            // All should be complete now
            assert!(detector.is_complete(&id1));
            assert!(detector.is_complete(&id2));
            assert!(detector.is_complete(&id3));
            assert_eq!(detector.orphan_count(), 0);
        }

        #[test]
        fn test_missing_parents() {
            let mut detector = ReceiverGapDetector::new();
            let id1 = make_id(1);
            let id2 = make_id(2);
            let id3 = make_id(3);

            detector.on_receive(id2, Some(id1), 2000);
            detector.on_receive(id3, Some(id1), 3000);

            let missing = detector.missing_parents();
            assert_eq!(missing.len(), 1);
            assert!(missing.contains(&id1));
        }
    }

    mod sender_tests {
        use super::*;

        #[test]
        fn test_send_tracking() {
            let mut detector = SenderGapDetector::new();
            let id1 = make_id(1);
            let id2 = make_id(2);

            detector.on_send(id1, None);
            detector.on_send(id2, Some(id1));

            assert_eq!(detector.head(), Some(id2));
            assert_eq!(detector.sent_count(), 2);
        }

        #[test]
        fn test_find_missing_all() {
            let mut detector = SenderGapDetector::new();
            let id1 = make_id(1);
            let id2 = make_id(2);

            detector.on_send(id1, None);
            detector.on_send(id2, Some(id1));

            // Peer has seen nothing
            let missing = detector.find_missing(&[]);
            assert_eq!(missing, vec![id1, id2]);
        }

        #[test]
        fn test_find_missing_partial() {
            let mut detector = SenderGapDetector::new();
            let id1 = make_id(1);
            let id2 = make_id(2);
            let id3 = make_id(3);

            detector.on_send(id1, None);
            detector.on_send(id2, Some(id1));
            detector.on_send(id3, Some(id2));

            // Peer has seen id1
            let missing = detector.find_missing(&[id1]);
            assert_eq!(missing, vec![id2, id3]);
        }

        #[test]
        fn test_find_missing_up_to_date() {
            let mut detector = SenderGapDetector::new();
            let id1 = make_id(1);
            let id2 = make_id(2);

            detector.on_send(id1, None);
            detector.on_send(id2, Some(id1));

            // Peer has seen our latest
            let missing = detector.find_missing(&[id2]);
            assert!(missing.is_empty());
        }

        #[test]
        fn test_find_missing_with_unknown_observed() {
            let mut detector = SenderGapDetector::new();
            let id1 = make_id(1);
            let id2 = make_id(2);
            let unknown = make_id(99);

            detector.on_send(id1, None);
            detector.on_send(id2, Some(id1));

            // Peer reports unknown ID (maybe from different conversation)
            let missing = detector.find_missing(&[unknown]);
            assert_eq!(missing, vec![id1, id2]);
        }

        #[test]
        fn test_multi_head_tracking() {
            let mut detector = SenderGapDetector::new();
            let id1 = make_id(1);
            let id2 = make_id(2);
            let id3 = make_id(3);

            // First message - single head
            detector.on_send(id1, None);
            assert_eq!(detector.heads().len(), 1);
            assert!(detector.heads().contains(&id1));

            // Fork: id2 and id3 both link to id1 (multi-device scenario)
            detector.on_send(id2, Some(id1));
            assert_eq!(detector.heads().len(), 1); // id1 removed, id2 added
            assert!(detector.heads().contains(&id2));

            detector.on_send(id3, Some(id1)); // Another child of id1
            // Note: id1 already removed, so this just adds id3
            assert_eq!(detector.heads().len(), 2); // Both id2 and id3 are heads
            assert!(detector.heads().contains(&id2));
            assert!(detector.heads().contains(&id3));
        }

        #[test]
        fn test_multi_head_find_missing() {
            let mut detector = SenderGapDetector::new();
            let id1 = make_id(1);
            let id2 = make_id(2);
            let id3 = make_id(3);

            // Create fork: id1 -> id2, id1 -> id3
            detector.on_send(id1, None);
            detector.on_send(id2, Some(id1));
            detector.on_send(id3, Some(id1));

            // Peer has seen id1 only - should get both branches
            let missing = detector.find_missing(&[id1]);
            assert_eq!(missing.len(), 2);
            assert!(missing.contains(&id2));
            assert!(missing.contains(&id3));

            // Peer has seen id2 - should only get id3
            let missing = detector.find_missing(&[id2]);
            assert_eq!(missing.len(), 1);
            assert!(missing.contains(&id3));

            // Peer has seen both heads - nothing missing
            let missing = detector.find_missing(&[id2, id3]);
            assert!(missing.is_empty());
        }
    }

    mod conversation_dag_tests {
        use super::*;

        #[test]
        fn test_epoch_increment() {
            let mut dag = ConversationDag::new();
            assert_eq!(dag.epoch, 0);

            dag.increment_epoch();
            assert_eq!(dag.epoch, 1);
        }

        #[test]
        fn test_epoch_clears_state() {
            let mut dag = ConversationDag::new();
            let id = make_id(1);

            dag.receiver.on_receive(id, None, 1000);
            dag.sender.on_send(id, None);
            dag.update_peer_heads(id, None);

            assert_eq!(dag.receiver.complete_count(), 1);
            assert_eq!(dag.sender.sent_count(), 1);
            assert_eq!(dag.observed_heads().len(), 1);

            dag.increment_epoch();

            assert_eq!(dag.receiver.complete_count(), 0);
            assert_eq!(dag.sender.sent_count(), 0);
            assert!(dag.observed_heads().is_empty());
        }

        #[test]
        fn test_peer_head_tracking() {
            let mut dag = ConversationDag::new();
            let id1 = make_id(1);
            let id2 = make_id(2);
            let id3 = make_id(3);

            // Initially no peer heads
            assert!(dag.observed_heads().is_empty());

            // First message from peer (no parent)
            dag.update_peer_heads(id1, None);
            assert_eq!(dag.observed_heads().len(), 1);
            assert!(dag.observed_heads().contains(&id1));

            // Second message links to first (linear chain)
            dag.update_peer_heads(id2, Some(id1));
            assert_eq!(dag.observed_heads().len(), 1);
            assert!(dag.observed_heads().contains(&id2));
            assert!(!dag.observed_heads().contains(&id1)); // id1 no longer a head

            // Third message also links to id1 (fork! multi-device scenario)
            dag.update_peer_heads(id3, Some(id1));
            // Now we have two heads: id2 and id3
            assert_eq!(dag.observed_heads().len(), 2);
            assert!(dag.observed_heads().contains(&id2));
            assert!(dag.observed_heads().contains(&id3));
        }

        #[test]
        fn test_detached_messages_always_complete() {
            let mut dag = ConversationDag::new();
            let id1 = make_id(1);
            let id2 = make_id(2);
            let id3 = make_id(3);

            // First linked message chain
            dag.receiver.on_receive(id1, None, 1000);
            dag.receiver.on_receive(id2, Some(id1), 2000);

            // Detached message (prev_self=None) arriving later - should be Complete
            let result = dag.receiver.on_receive(id3, None, 3000);
            assert_eq!(result, GapResult::Complete);
            assert!(dag.receiver.is_complete(&id3));
        }

        #[test]
        fn test_multiple_detached_messages() {
            let mut dag = ConversationDag::new();
            let id1 = make_id(1);
            let id2 = make_id(2);
            let id3 = make_id(3);

            // All detached messages (simulating constrained transport)
            let result1 = dag.receiver.on_receive(id1, None, 1000);
            let result2 = dag.receiver.on_receive(id2, None, 2000);
            let result3 = dag.receiver.on_receive(id3, None, 3000);

            // All should be complete - no gaps for detached messages
            assert_eq!(result1, GapResult::Complete);
            assert_eq!(result2, GapResult::Complete);
            assert_eq!(result3, GapResult::Complete);
            assert_eq!(dag.receiver.complete_count(), 3);
            assert_eq!(dag.receiver.orphan_count(), 0);
        }

        #[test]
        fn test_detached_interleaved_with_linked() {
            let mut dag = ConversationDag::new();
            let linked1 = make_id(1);
            let linked2 = make_id(2);
            let detached1 = make_id(10);
            let detached2 = make_id(11);

            // Linked chain
            dag.receiver.on_receive(linked1, None, 1000);

            // Detached message interleaved
            let result = dag.receiver.on_receive(detached1, None, 1500);
            assert_eq!(result, GapResult::Complete);

            // Continue linked chain
            dag.receiver.on_receive(linked2, Some(linked1), 2000);

            // Another detached message
            let result = dag.receiver.on_receive(detached2, None, 2500);
            assert_eq!(result, GapResult::Complete);

            // All should be complete
            assert!(dag.receiver.is_complete(&linked1));
            assert!(dag.receiver.is_complete(&linked2));
            assert!(dag.receiver.is_complete(&detached1));
            assert!(dag.receiver.is_complete(&detached2));
        }

        #[test]
        fn test_epoch_reset_allows_fresh_chain() {
            let mut dag = ConversationDag::with_epoch(0);
            let id1 = make_id(1);
            let id2 = make_id(2);
            let new_id1 = make_id(10);
            let new_id2 = make_id(11);

            // Build chain in epoch 0
            dag.receiver.on_receive(id1, None, 1000);
            dag.receiver.on_receive(id2, Some(id1), 2000);
            dag.sender.on_send(id1, None);
            dag.sender.on_send(id2, Some(id1));

            assert_eq!(dag.receiver.complete_count(), 2);
            assert_eq!(dag.sender.sent_count(), 2);

            // Increment epoch (simulating history clear)
            dag.increment_epoch();
            assert_eq!(dag.epoch, 1);

            // State should be cleared
            assert_eq!(dag.receiver.complete_count(), 0);
            assert_eq!(dag.sender.sent_count(), 0);
            assert!(dag.observed_heads().is_empty());

            // Old IDs should not be known
            assert!(!dag.receiver.is_complete(&id1));
            assert!(!dag.receiver.is_complete(&id2));

            // New chain in epoch 1 starts fresh
            let result = dag.receiver.on_receive(new_id1, None, 3000);
            assert_eq!(result, GapResult::Complete);

            let result = dag.receiver.on_receive(new_id2, Some(new_id1), 4000);
            assert_eq!(result, GapResult::Complete);
        }

        #[test]
        fn test_cross_epoch_message_creates_gap() {
            let mut dag = ConversationDag::with_epoch(0);
            let epoch0_id = make_id(1);
            let epoch1_id = make_id(2);

            // Message in epoch 0
            dag.receiver.on_receive(epoch0_id, None, 1000);

            // Increment epoch
            dag.increment_epoch();

            // Message referencing old epoch's message creates a gap
            // (because epoch0_id is no longer known after epoch increment)
            let result = dag.receiver.on_receive(epoch1_id, Some(epoch0_id), 2000);
            assert_eq!(
                result,
                GapResult::Gap {
                    missing: vec![epoch0_id]
                }
            );
            assert!(dag.receiver.is_orphan(&epoch1_id));
        }
    }
}
