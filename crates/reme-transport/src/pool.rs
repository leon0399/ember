//! Transport pool for managing multiple targets of the same type.
//!
//! A `TransportPool<T>` aggregates multiple transport targets and provides
//! different strategies for routing messages across them.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use futures::future::join_all;
use reme_message::{OuterEnvelope, TombstoneEnvelope};
use tracing::{debug, warn};

use crate::seen_cache::SharedSeenCache;
use crate::target::{HealthState, TargetId, TargetKind, TransportTarget};
use crate::{Transport, TransportError};

/// Strategy for selecting and routing to targets in a pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PoolStrategy {
    /// Broadcast to all targets, succeed if any succeeds.
    ///
    /// This is the default strategy for redundancy.
    #[default]
    Broadcast,

    /// Try targets in priority order, stop on first success.
    ///
    /// Useful when you want to prefer certain targets but fallback to others.
    PriorityFallback,

    /// Race all targets in parallel, return on first success.
    ///
    /// Similar to Broadcast but cancels remaining requests on first success.
    /// Provides lowest latency but may waste resources.
    Race,

    /// Round-robin across healthy targets.
    ///
    /// Distributes load evenly across targets.
    RoundRobin,

    /// Prefer the target with lowest average latency.
    ///
    /// Optimizes for speed by routing to the fastest target.
    FastestFirst,
}

/// Configuration for a transport pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Strategy for routing to targets.
    pub strategy: PoolStrategy,

    /// Whether to use the shared seen cache for deduplication.
    pub use_seen_cache: bool,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            strategy: PoolStrategy::Broadcast,
            use_seen_cache: true,
        }
    }
}

impl PoolConfig {
    /// Create a new pool config with the given strategy.
    pub fn with_strategy(strategy: PoolStrategy) -> Self {
        Self {
            strategy,
            ..Default::default()
        }
    }
}

/// A pool of transport targets of the same type.
///
/// The pool manages multiple targets and routes messages according to the
/// configured strategy. It also provides:
/// - Health-based filtering (skips unhealthy targets)
/// - Deduplication via shared seen cache
/// - Target management (add/remove at runtime)
pub struct TransportPool<T: TransportTarget> {
    targets: RwLock<Vec<Arc<T>>>,
    config: PoolConfig,
    seen_cache: Arc<SharedSeenCache>,
    round_robin_index: AtomicUsize,
}

impl<T: TransportTarget + 'static> TransportPool<T> {
    /// Create a new transport pool with default configuration.
    pub fn new() -> Self {
        Self::with_config(PoolConfig::default(), Arc::new(SharedSeenCache::with_defaults()))
    }

    /// Create a new transport pool with shared seen cache.
    pub fn with_seen_cache(seen_cache: Arc<SharedSeenCache>) -> Self {
        Self::with_config(PoolConfig::default(), seen_cache)
    }

    /// Create a new transport pool with configuration and seen cache.
    pub fn with_config(config: PoolConfig, seen_cache: Arc<SharedSeenCache>) -> Self {
        Self {
            targets: RwLock::new(Vec::new()),
            config,
            seen_cache,
            round_robin_index: AtomicUsize::new(0),
        }
    }

    /// Get a reference to the shared seen cache.
    pub fn seen_cache(&self) -> &Arc<SharedSeenCache> {
        &self.seen_cache
    }

    /// Add a target to the pool.
    pub fn add_target(&self, target: T) {
        let mut targets = self.targets.write().unwrap();
        targets.push(Arc::new(target));
    }

    /// Add an already-Arc'd target to the pool.
    pub fn add_arc_target(&self, target: Arc<T>) {
        let mut targets = self.targets.write().unwrap();
        targets.push(target);
    }

    /// Remove a target by ID.
    ///
    /// Returns true if a target was removed.
    pub fn remove_target(&self, id: &TargetId) -> bool {
        let mut targets = self.targets.write().unwrap();
        let before_len = targets.len();
        targets.retain(|t| t.id() != id);
        targets.len() < before_len
    }

    /// Get all targets.
    pub fn all_targets(&self) -> Vec<Arc<T>> {
        self.targets.read().unwrap().clone()
    }

    /// Get all healthy (available) targets.
    pub fn healthy_targets(&self) -> Vec<Arc<T>> {
        self.targets
            .read()
            .unwrap()
            .iter()
            .filter(|t| t.is_available())
            .cloned()
            .collect()
    }

    /// Get targets by kind.
    pub fn targets_by_kind(&self, kind: TargetKind) -> Vec<Arc<T>> {
        self.targets
            .read()
            .unwrap()
            .iter()
            .filter(|t| t.config().kind == kind)
            .cloned()
            .collect()
    }

    /// Get a target by ID.
    pub fn get_target(&self, id: &TargetId) -> Option<Arc<T>> {
        self.targets
            .read()
            .unwrap()
            .iter()
            .find(|t| t.id() == id)
            .cloned()
    }

    /// Get the number of targets in the pool.
    pub fn len(&self) -> usize {
        self.targets.read().unwrap().len()
    }

    /// Check if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.targets.read().unwrap().is_empty()
    }

    /// Check if any target is available.
    pub fn has_available(&self) -> bool {
        self.targets.read().unwrap().iter().any(|t| t.is_available())
    }

    /// Select targets based on current strategy.
    fn select_targets(&self) -> Vec<Arc<T>> {
        let all_targets = self.targets.read().unwrap();
        let available: Vec<_> = all_targets.iter().filter(|t| t.is_available()).cloned().collect();

        if available.is_empty() {
            // If no healthy targets, try all (circuit breaker may have recovered)
            return all_targets.clone();
        }

        match self.config.strategy {
            PoolStrategy::Broadcast | PoolStrategy::Race => available,
            PoolStrategy::PriorityFallback => {
                let mut sorted = available;
                sorted.sort_by_key(|t| std::cmp::Reverse(t.config().priority));
                sorted
            }
            PoolStrategy::RoundRobin => {
                if available.is_empty() {
                    return vec![];
                }
                let index = self.round_robin_index.fetch_add(1, Ordering::Relaxed) % available.len();
                vec![available[index].clone()]
            }
            PoolStrategy::FastestFirst => {
                let mut sorted = available;
                sorted.sort_by_key(|t| {
                    // Use health's avg_latency_ms if available
                    // This requires downcasting or a method on the trait
                    // For now, use priority as proxy (higher priority = preferred)
                    std::cmp::Reverse(t.config().priority)
                });
                vec![sorted.first().unwrap().clone()]
            }
        }
    }

    /// Submit a message using the pool strategy.
    pub async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        // Deduplication check
        if self.config.use_seen_cache && self.seen_cache.was_seen(&envelope.message_id) {
            debug!("Message {:?} already seen, skipping", envelope.message_id);
            return Ok(());
        }

        let targets = self.select_targets();
        if targets.is_empty() {
            return Err(TransportError::Network("No targets available".to_string()));
        }

        let result = match self.config.strategy {
            PoolStrategy::Broadcast => self.broadcast_message(&targets, envelope.clone()).await,
            PoolStrategy::Race => self.race_message(&targets, envelope.clone()).await,
            PoolStrategy::PriorityFallback => {
                self.priority_fallback_message(&targets, envelope.clone()).await
            }
            PoolStrategy::RoundRobin | PoolStrategy::FastestFirst => {
                // Single target selected
                targets[0].submit_message(envelope.clone()).await
            }
        };

        if result.is_ok() && self.config.use_seen_cache {
            self.seen_cache.mark(&envelope.message_id);
        }

        result
    }

    /// Submit a tombstone using the pool strategy.
    pub async fn submit_tombstone(
        &self,
        tombstone: TombstoneEnvelope,
    ) -> Result<(), TransportError> {
        let targets = self.select_targets();
        if targets.is_empty() {
            return Err(TransportError::Network("No targets available".to_string()));
        }

        match self.config.strategy {
            PoolStrategy::Broadcast => self.broadcast_tombstone(&targets, tombstone).await,
            PoolStrategy::Race => self.race_tombstone(&targets, tombstone).await,
            PoolStrategy::PriorityFallback => {
                self.priority_fallback_tombstone(&targets, tombstone).await
            }
            PoolStrategy::RoundRobin | PoolStrategy::FastestFirst => {
                targets[0].submit_tombstone(tombstone).await
            }
        }
    }

    /// Broadcast message to all targets, succeed if any succeeds.
    async fn broadcast_message(
        &self,
        targets: &[Arc<T>],
        envelope: OuterEnvelope,
    ) -> Result<(), TransportError> {
        let futures: Vec<_> = targets
            .iter()
            .map(|t| {
                let t = t.clone();
                let env = envelope.clone();
                async move { t.submit_message(env).await }
            })
            .collect();

        let results = join_all(futures).await;

        let mut last_error = None;
        let mut success_count = 0;

        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(()) => {
                    success_count += 1;
                }
                Err(e) => {
                    warn!("Target {} failed: {}", targets[i].id(), e);
                    last_error = Some(e);
                }
            }
        }

        if success_count > 0 {
            debug!("Message sent to {}/{} targets", success_count, targets.len());
            Ok(())
        } else {
            Err(last_error.unwrap_or(TransportError::Network("All targets failed".to_string())))
        }
    }

    /// Race message to all targets, return on first success.
    async fn race_message(
        &self,
        targets: &[Arc<T>],
        envelope: OuterEnvelope,
    ) -> Result<(), TransportError> {
        if targets.len() == 1 {
            return targets[0].submit_message(envelope).await;
        }

        // Create futures for all targets
        let futures: Vec<_> = targets
            .iter()
            .map(|t| {
                let t = t.clone();
                let env = envelope.clone();
                Box::pin(async move { t.submit_message(env).await })
            })
            .collect();

        // Use select_all to get first completion
        let (first_result, _index, remaining) = futures::future::select_all(futures).await;

        // Drop remaining futures (cancels them)
        drop(remaining);

        // If first succeeded, we're done
        if first_result.is_ok() {
            return first_result;
        }

        // First failed, but we cancelled others. Fall back to broadcast.
        self.broadcast_message(targets, envelope).await
    }

    /// Try targets in priority order, stop on first success.
    async fn priority_fallback_message(
        &self,
        targets: &[Arc<T>],
        envelope: OuterEnvelope,
    ) -> Result<(), TransportError> {
        let mut last_error = None;

        for target in targets {
            match target.submit_message(envelope.clone()).await {
                Ok(()) => {
                    debug!("Message sent via {}", target.id());
                    return Ok(());
                }
                Err(e) => {
                    warn!("Target {} failed, trying next: {}", target.id(), e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or(TransportError::Network("All targets failed".to_string())))
    }

    /// Broadcast tombstone to all targets.
    async fn broadcast_tombstone(
        &self,
        targets: &[Arc<T>],
        tombstone: TombstoneEnvelope,
    ) -> Result<(), TransportError> {
        let futures: Vec<_> = targets
            .iter()
            .map(|t| {
                let t = t.clone();
                let ts = tombstone.clone();
                async move { t.submit_tombstone(ts).await }
            })
            .collect();

        let results = join_all(futures).await;

        let mut last_error = None;
        let mut success_count = 0;

        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(()) => success_count += 1,
                Err(e) => {
                    warn!("Target {} failed: {}", targets[i].id(), e);
                    last_error = Some(e);
                }
            }
        }

        if success_count > 0 {
            Ok(())
        } else {
            Err(last_error.unwrap_or(TransportError::Network("All targets failed".to_string())))
        }
    }

    /// Race tombstone to all targets.
    async fn race_tombstone(
        &self,
        targets: &[Arc<T>],
        tombstone: TombstoneEnvelope,
    ) -> Result<(), TransportError> {
        if targets.len() == 1 {
            return targets[0].submit_tombstone(tombstone).await;
        }

        let futures: Vec<_> = targets
            .iter()
            .map(|t| {
                let t = t.clone();
                let ts = tombstone.clone();
                Box::pin(async move { t.submit_tombstone(ts).await })
            })
            .collect();

        let (first_result, _index, remaining) = futures::future::select_all(futures).await;
        drop(remaining);

        if first_result.is_ok() {
            return first_result;
        }

        self.broadcast_tombstone(targets, tombstone).await
    }

    /// Priority fallback for tombstone.
    async fn priority_fallback_tombstone(
        &self,
        targets: &[Arc<T>],
        tombstone: TombstoneEnvelope,
    ) -> Result<(), TransportError> {
        let mut last_error = None;

        for target in targets {
            match target.submit_tombstone(tombstone.clone()).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or(TransportError::Network("All targets failed".to_string())))
    }
}

impl<T: TransportTarget + 'static> Default for TransportPool<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Implement Transport trait for TransportPool to allow use with existing code.
#[async_trait]
impl<T: TransportTarget + 'static> Transport for TransportPool<T> {
    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        TransportPool::submit_message(self, envelope).await
    }

    async fn submit_tombstone(&self, tombstone: TombstoneEnvelope) -> Result<(), TransportError> {
        TransportPool::submit_tombstone(self, tombstone).await
    }
}

/// Summary of pool health status.
#[derive(Debug, Clone)]
pub struct PoolHealthSummary {
    /// Total number of targets.
    pub total: usize,
    /// Number of healthy targets.
    pub healthy: usize,
    /// Number of degraded targets.
    pub degraded: usize,
    /// Number of unhealthy targets.
    pub unhealthy: usize,
}

impl<T: TransportTarget> TransportPool<T> {
    /// Get a summary of pool health.
    pub fn health_summary(&self) -> PoolHealthSummary {
        let targets = self.targets.read().unwrap();
        let mut summary = PoolHealthSummary {
            total: targets.len(),
            healthy: 0,
            degraded: 0,
            unhealthy: 0,
        };

        for target in targets.iter() {
            match target.health() {
                HealthState::Healthy => summary.healthy += 1,
                HealthState::Degraded => summary.degraded += 1,
                HealthState::Unhealthy => summary.unhealthy += 1,
            }
        }

        summary
    }
}

// HTTP-specific pool methods for fetching messages
use crate::http::NodeSpec;
use crate::http_target::{HttpTarget, HttpTargetConfig};
use reme_message::{MessageID, RoutingKey};
use std::collections::HashMap;
use tracing::info;

impl TransportPool<HttpTarget> {
    /// Create a pool with a single HTTP target.
    ///
    /// This is a convenience constructor for simple setups and testing.
    pub fn single(url: impl Into<String>) -> Result<Self, TransportError> {
        let config = HttpTargetConfig::stable(url);
        let target = HttpTarget::new(config)?;
        let pool = Self::new();
        pool.add_target(target);
        Ok(pool)
    }

    /// Create a pool from a list of node specifications.
    ///
    /// This is a convenience constructor for migrating from the old `HttpTransport` API.
    /// Each node spec is converted to a stable HTTP target.
    ///
    /// # Example
    /// ```ignore
    /// let nodes = vec![
    ///     NodeSpec { url: "https://node1.example.com".into(), cert_pin: Some(pin) },
    ///     NodeSpec { url: "https://node2.example.com".into(), cert_pin: None },
    /// ];
    /// let pool = TransportPool::from_node_specs(nodes)?;
    /// ```
    pub fn from_node_specs(nodes: Vec<NodeSpec>) -> Result<Self, TransportError> {
        if nodes.is_empty() {
            return Err(TransportError::Network(
                "At least one node is required".to_string(),
            ));
        }

        let pool = Self::new();

        for node in nodes {
            let mut config = HttpTargetConfig::stable(&node.url);
            if let Some(pin) = node.cert_pin {
                config = config.with_cert_pin(pin);
            }

            // Log security warnings
            if node.url.starts_with("http://") {
                warn!(
                    "Node {} uses unencrypted HTTP - credentials and messages may be exposed",
                    &node.url
                );
            } else if node.url.starts_with("https://") && config.cert_pin.is_none() {
                warn!(
                    "Node {} has no certificate pin - vulnerable to MITM attacks",
                    &node.url
                );
            } else if config.cert_pin.is_some() {
                info!("Certificate pinning enabled for {}", &node.url);
            }

            let target = HttpTarget::new(config)?;
            pool.add_target(target);
        }

        Ok(pool)
    }
    /// Fetch messages once from all healthy targets and deduplicate.
    ///
    /// This method performs a single fetch operation from all available targets
    /// and returns unique messages (deduplicated by message_id).
    pub async fn fetch_once(
        &self,
        routing_key: &RoutingKey,
    ) -> Result<Vec<OuterEnvelope>, TransportError> {
        let targets = self.healthy_targets();
        if targets.is_empty() {
            // Try all targets if none are healthy (circuit breaker may have recovered)
            let all_targets = self.all_targets();
            if all_targets.is_empty() {
                return Err(TransportError::Network("No targets available".to_string()));
            }
            return self.fetch_from_targets(&all_targets, routing_key).await;
        }

        self.fetch_from_targets(&targets, routing_key).await
    }

    /// Fetch from a specific set of targets.
    async fn fetch_from_targets(
        &self,
        targets: &[Arc<HttpTarget>],
        routing_key: &RoutingKey,
    ) -> Result<Vec<OuterEnvelope>, TransportError> {
        // Fetch from all targets in parallel
        let futures: Vec<_> = targets
            .iter()
            .map(|t| {
                let t = t.clone();
                let rk = *routing_key;
                async move { t.fetch_once(&rk).await }
            })
            .collect();

        let results = join_all(futures).await;

        // Aggregate and deduplicate by message_id
        let mut messages_by_id: HashMap<MessageID, OuterEnvelope> = HashMap::new();
        let mut last_error = None;
        let mut success_count = 0;

        for result in results {
            match result {
                Ok(messages) => {
                    success_count += 1;
                    for msg in messages {
                        messages_by_id.insert(msg.message_id, msg);
                    }
                }
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        // If we got messages from at least one target, return them
        if success_count > 0 {
            let messages: Vec<_> = messages_by_id.into_values().collect();
            debug!(
                "Fetched {} unique messages from {}/{} targets",
                messages.len(),
                success_count,
                targets.len()
            );
            Ok(messages)
        } else {
            Err(last_error.unwrap_or(TransportError::Network("All targets failed".to_string())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_target::{HttpTarget, HttpTargetConfig};

    fn create_test_target(url: &str) -> HttpTarget {
        HttpTarget::new(HttpTargetConfig::stable(url)).unwrap()
    }

    #[test]
    fn test_pool_add_remove() {
        let pool: TransportPool<HttpTarget> = TransportPool::new();
        assert!(pool.is_empty());

        let target = create_test_target("http://localhost:1");
        let id = target.id().clone();
        pool.add_target(target);

        assert_eq!(pool.len(), 1);
        assert!(!pool.is_empty());
        assert!(pool.get_target(&id).is_some());

        assert!(pool.remove_target(&id));
        assert!(pool.is_empty());
        assert!(pool.get_target(&id).is_none());
    }

    #[test]
    fn test_pool_healthy_targets() {
        let pool: TransportPool<HttpTarget> = TransportPool::new();

        pool.add_target(create_test_target("http://localhost:1"));
        pool.add_target(create_test_target("http://localhost:2"));

        let healthy = pool.healthy_targets();
        assert_eq!(healthy.len(), 2);
    }

    #[test]
    fn test_pool_targets_by_kind() {
        let pool: TransportPool<HttpTarget> = TransportPool::new();

        pool.add_target(HttpTarget::new(HttpTargetConfig::stable("http://stable:1")).unwrap());
        pool.add_target(HttpTarget::new(HttpTargetConfig::ephemeral("http://ephemeral:1")).unwrap());
        pool.add_target(HttpTarget::new(HttpTargetConfig::stable("http://stable:2")).unwrap());

        let stable = pool.targets_by_kind(TargetKind::Stable);
        let ephemeral = pool.targets_by_kind(TargetKind::Ephemeral);

        assert_eq!(stable.len(), 2);
        assert_eq!(ephemeral.len(), 1);
    }

    #[test]
    fn test_pool_health_summary() {
        let pool: TransportPool<HttpTarget> = TransportPool::new();

        pool.add_target(create_test_target("http://localhost:1"));
        pool.add_target(create_test_target("http://localhost:2"));

        let summary = pool.health_summary();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.healthy, 2);
        assert_eq!(summary.degraded, 0);
        assert_eq!(summary.unhealthy, 0);
    }

    #[test]
    fn test_pool_config() {
        let config = PoolConfig::with_strategy(PoolStrategy::PriorityFallback);
        assert_eq!(config.strategy, PoolStrategy::PriorityFallback);
        assert!(config.use_seen_cache);
    }

    #[test]
    fn test_pool_has_available() {
        let pool: TransportPool<HttpTarget> = TransportPool::new();
        assert!(!pool.has_available());

        pool.add_target(create_test_target("http://localhost:1"));
        assert!(pool.has_available());
    }
}
