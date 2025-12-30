//! Unified transport registry for UI and management.
//!
//! The `TransportRegistry` provides a unified interface for:
//! - Querying transport state from any UI (TUI, native GUI, mobile, web)
//! - Adding ephemeral targets at runtime
//! - Managing target metadata not stored in transport layer
//!
//! This is the primary entry point for UI code to interact with transports.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::composite::CompositeTransport;
use crate::delivery::DeliveryTier;
use crate::http_target::{HttpTarget, HttpTargetConfig};
use crate::pool::TransportPool;
use crate::query::{HealthSummary, TargetSnapshot, TransportQuery};
use crate::target::{HealthState, TargetConfig, TargetId, TransportTarget};
use crate::TransportError;

#[cfg(feature = "mqtt")]
use crate::mqtt_target::MqttTarget;

/// Metadata for ephemeral targets added at runtime.
///
/// This tracks information not stored in the transport layer itself,
/// like when the target was added and any user-provided labels.
#[derive(Debug, Clone)]
pub struct EphemeralMeta {
    /// Target identifier.
    pub id: TargetId,
    /// User-provided label (if any).
    pub label: Option<String>,
    /// Whether this is an ephemeral (runtime-added) target.
    pub ephemeral: bool,
    /// Delivery tier (quorum vs direct).
    pub tier: DeliveryTier,
}

/// Unified transport registry for UI and management.
///
/// The registry aggregates targets from multiple sources:
/// - HTTP transport pool (stable and ephemeral targets)
/// - MQTT transport pool (stable and ephemeral targets)
/// - Composite transport (runtime-added transports)
///
/// It provides a consistent `TransportQuery` interface for all UI frontends.
pub struct TransportRegistry {
    /// HTTP transport pool.
    http_pool: Option<Arc<TransportPool<HttpTarget>>>,

    /// MQTT transport pool.
    #[cfg(feature = "mqtt")]
    mqtt_pool: Option<Arc<TransportPool<MqttTarget>>>,

    /// Composite transport for runtime-added transports.
    composite: Arc<CompositeTransport>,

    /// Metadata for ephemeral targets (not stored in transport layer).
    ephemeral_meta: RwLock<HashMap<TargetId, EphemeralMeta>>,
}

impl TransportRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            http_pool: None,
            #[cfg(feature = "mqtt")]
            mqtt_pool: None,
            composite: Arc::new(CompositeTransport::new()),
            ephemeral_meta: RwLock::new(HashMap::new()),
        }
    }

    /// Create a registry with the given composite transport.
    pub fn with_composite(composite: Arc<CompositeTransport>) -> Self {
        Self {
            http_pool: None,
            #[cfg(feature = "mqtt")]
            mqtt_pool: None,
            composite,
            ephemeral_meta: RwLock::new(HashMap::new()),
        }
    }

    /// Set the HTTP transport pool.
    pub fn set_http_pool(&mut self, pool: Arc<TransportPool<HttpTarget>>) {
        self.http_pool = Some(pool);
    }

    /// Set the MQTT transport pool.
    #[cfg(feature = "mqtt")]
    pub fn set_mqtt_pool(&mut self, pool: Arc<TransportPool<MqttTarget>>) {
        self.mqtt_pool = Some(pool);
    }

    /// Get the HTTP transport pool.
    pub fn http_pool(&self) -> Option<&Arc<TransportPool<HttpTarget>>> {
        self.http_pool.as_ref()
    }

    /// Get the MQTT transport pool.
    #[cfg(feature = "mqtt")]
    pub fn mqtt_pool(&self) -> Option<&Arc<TransportPool<MqttTarget>>> {
        self.mqtt_pool.as_ref()
    }

    /// Get the composite transport.
    pub fn composite(&self) -> &Arc<CompositeTransport> {
        &self.composite
    }

    /// Add an ephemeral HTTP target at runtime.
    ///
    /// Returns the target ID on success.
    pub async fn add_http_target(
        &self,
        url: impl Into<String>,
        label: Option<String>,
        tier: DeliveryTier,
    ) -> Result<TargetId, TransportError> {
        let url = url.into();
        let config =
            HttpTargetConfig::ephemeral(&url).with_request_timeout(Duration::from_secs(10));
        let target = HttpTarget::new(config)?;
        let id = target.id().clone();

        // Store metadata
        {
            let mut meta = self.ephemeral_meta.write().unwrap();
            meta.insert(
                id.clone(),
                EphemeralMeta {
                    id: id.clone(),
                    label: label.clone(),
                    ephemeral: true,
                    tier,
                },
            );
        }

        // Add to composite transport
        self.composite.add_transport(target).await;

        Ok(id)
    }

    /// Register an ephemeral target that was created externally.
    ///
    /// Use this for transports like MQTT where the transport is created
    /// and added to composite separately, but we still want to track
    /// it in the registry metadata.
    pub fn register_ephemeral(&self, id: TargetId, label: Option<String>, tier: DeliveryTier) {
        let mut meta = self.ephemeral_meta.write().unwrap();
        meta.insert(
            id.clone(),
            EphemeralMeta {
                id,
                label,
                ephemeral: true,
                tier,
            },
        );
    }

    /// Register a stable (non-ephemeral) target for display purposes.
    ///
    /// Use this for targets from config files that aren't in pools.
    pub fn register_stable(&self, id: TargetId, label: Option<String>, tier: DeliveryTier) {
        let mut meta = self.ephemeral_meta.write().unwrap();
        meta.insert(
            id.clone(),
            EphemeralMeta {
                id,
                label,
                ephemeral: false,
                tier,
            },
        );
    }

    /// Get metadata for an ephemeral target.
    pub fn get_ephemeral_meta(&self, id: &TargetId) -> Option<EphemeralMeta> {
        self.ephemeral_meta.read().unwrap().get(id).cloned()
    }

    /// List all ephemeral targets with their metadata.
    pub fn list_ephemeral(&self) -> Vec<EphemeralMeta> {
        self.ephemeral_meta
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    /// Get a combined list of all targets with tier and ephemeral metadata.
    ///
    /// This is the primary method for UI display, enriching snapshots with
    /// registry metadata.
    ///
    /// # Health State for Composite-Only Targets
    ///
    /// Targets that exist only in the composite transport (not in HTTP/MQTT pools)
    /// will have `HealthState::Unknown` since the registry does not track their
    /// health. These are typically send-only targets without active polling.
    pub fn list_all_targets(&self) -> Vec<EnrichedSnapshot> {
        let mut results = Vec::new();
        let meta = self.ephemeral_meta.read().unwrap();

        // Collect IDs from pool snapshots for O(1) duplicate checking
        let mut seen_ids: HashSet<TargetId> = HashSet::new();

        // Collect from HTTP pool
        if let Some(ref pool) = self.http_pool {
            for snapshot in TransportQuery::list_targets(pool.as_ref()) {
                seen_ids.insert(snapshot.id.clone());
                let ephemeral_meta = meta.get(&snapshot.id);
                results.push(EnrichedSnapshot {
                    snapshot,
                    tier: ephemeral_meta.map_or(DeliveryTier::Quorum, |m| m.tier),
                    ephemeral: ephemeral_meta.is_some_and(|m| m.ephemeral),
                    custom_label: ephemeral_meta.and_then(|m| m.label.clone()),
                });
            }
        }

        // Collect from MQTT pool
        #[cfg(feature = "mqtt")]
        if let Some(ref pool) = self.mqtt_pool {
            for snapshot in TransportQuery::list_targets(pool.as_ref()) {
                seen_ids.insert(snapshot.id.clone());
                let ephemeral_meta = meta.get(&snapshot.id);
                results.push(EnrichedSnapshot {
                    snapshot,
                    tier: ephemeral_meta.map_or(DeliveryTier::Quorum, |m| m.tier),
                    ephemeral: ephemeral_meta.is_some_and(|m| m.ephemeral),
                    custom_label: ephemeral_meta.and_then(|m| m.label.clone()),
                });
            }
        }

        // Add composite-only targets (in metadata but not in pools)
        // These are typically send-only targets without active health tracking
        for (id, emeta) in meta.iter() {
            // O(1) membership check
            if !seen_ids.contains(id) {
                // Create a synthetic snapshot for composite-only targets
                // Health is Unknown since we don't have active health tracking for these
                let snapshot = TargetSnapshot::from_config(
                    &TargetConfig::ephemeral(id.clone()),
                    HealthState::Unknown,
                    0,
                    0,
                    None,
                    None,
                );
                results.push(EnrichedSnapshot {
                    snapshot,
                    tier: emeta.tier,
                    ephemeral: emeta.ephemeral,
                    custom_label: emeta.label.clone(),
                });
            }
        }

        results
    }
}

impl Default for TransportRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Implement TransportQuery for unified access.
///
/// This implementation includes targets from all sources:
/// - HTTP pool targets (with health tracking)
/// - MQTT pool targets (with health tracking)
/// - Composite-only targets (from ephemeral_meta, without health tracking)
impl TransportQuery for TransportRegistry {
    fn list_targets(&self) -> Vec<TargetSnapshot> {
        let mut targets = Vec::new();
        let meta = self.ephemeral_meta.read().unwrap();

        // Collect IDs from pool snapshots for O(1) duplicate checking
        let mut seen_ids: HashSet<TargetId> = HashSet::new();

        // Collect from HTTP pool
        if let Some(ref pool) = self.http_pool {
            for snapshot in TransportQuery::list_targets(pool.as_ref()) {
                seen_ids.insert(snapshot.id.clone());
                targets.push(snapshot);
            }
        }

        // Collect from MQTT pool
        #[cfg(feature = "mqtt")]
        if let Some(ref pool) = self.mqtt_pool {
            for snapshot in TransportQuery::list_targets(pool.as_ref()) {
                seen_ids.insert(snapshot.id.clone());
                targets.push(snapshot);
            }
        }

        // Add composite-only targets (in metadata but not in pools)
        // These have HealthState::Unknown since we don't track their health
        for (id, emeta) in meta.iter() {
            if !seen_ids.contains(id) {
                let snapshot = TargetSnapshot::from_config(
                    &TargetConfig::ephemeral(id.clone()).with_label_opt(emeta.label.clone()),
                    HealthState::Unknown,
                    0,
                    0,
                    None,
                    None,
                );
                targets.push(snapshot);
            }
        }

        targets
    }

    fn health_summary(&self) -> HealthSummary {
        let mut summary = HealthSummary::new();
        let mut seen_ids: HashSet<TargetId> = HashSet::new();

        // Collect from HTTP pool
        if let Some(ref pool) = self.http_pool {
            for snapshot in TransportQuery::list_targets(pool.as_ref()) {
                seen_ids.insert(snapshot.id);
            }
            summary.merge(&TransportQuery::health_summary(pool.as_ref()));
        }

        // Collect from MQTT pool
        #[cfg(feature = "mqtt")]
        if let Some(ref pool) = self.mqtt_pool {
            for snapshot in TransportQuery::list_targets(pool.as_ref()) {
                seen_ids.insert(snapshot.id);
            }
            summary.merge(&TransportQuery::health_summary(pool.as_ref()));
        }

        // Count composite-only targets (in metadata but not in pools)
        let meta = self.ephemeral_meta.read().unwrap();
        let composite_only_count = meta.keys().filter(|id| !seen_ids.contains(*id)).count();
        if composite_only_count > 0 {
            summary.total += composite_only_count;
            summary.unknown += composite_only_count;
        }

        summary
    }

    fn has_available(&self) -> bool {
        let http_available = self.http_pool.as_ref().is_some_and(|p| p.has_available());

        #[cfg(feature = "mqtt")]
        let mqtt_available = self.mqtt_pool.as_ref().is_some_and(|p| p.has_available());
        #[cfg(not(feature = "mqtt"))]
        let mqtt_available = false;

        http_available || mqtt_available || !self.composite.is_empty()
    }
}

/// Enriched target snapshot with registry metadata.
///
/// This combines the transport-layer snapshot with registry metadata
/// like delivery tier and ephemeral status.
#[derive(Debug, Clone)]
pub struct EnrichedSnapshot {
    /// Base snapshot from transport layer.
    pub snapshot: TargetSnapshot,
    /// Delivery tier (quorum or direct).
    pub tier: DeliveryTier,
    /// Whether this target was added at runtime.
    pub ephemeral: bool,
    /// Custom label from registry (overrides snapshot label).
    pub custom_label: Option<String>,
}

impl EnrichedSnapshot {
    /// Get the display label, preferring custom label over snapshot label.
    pub fn display_label(&self) -> &str {
        self.custom_label
            .as_deref()
            .or(self.snapshot.label.as_deref())
            .unwrap_or(self.snapshot.id.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_new() {
        let registry = TransportRegistry::new();
        assert!(!registry.has_available());
        assert!(registry.list_targets().is_empty());
    }

    #[tokio::test]
    async fn test_add_http_target() {
        let registry = TransportRegistry::new();

        let id = registry
            .add_http_target(
                "http://localhost:23004",
                Some("Test".to_string()),
                DeliveryTier::Direct,
            )
            .await
            .unwrap();

        let meta = registry.get_ephemeral_meta(&id).unwrap();
        assert_eq!(meta.label, Some("Test".to_string()));
        assert!(meta.ephemeral);
        assert_eq!(meta.tier, DeliveryTier::Direct);
    }

    #[tokio::test]
    async fn test_list_ephemeral() {
        let registry = TransportRegistry::new();

        registry
            .add_http_target(
                "http://localhost:23004",
                Some("A".to_string()),
                DeliveryTier::Direct,
            )
            .await
            .unwrap();
        registry
            .add_http_target(
                "http://localhost:23005",
                Some("B".to_string()),
                DeliveryTier::Quorum,
            )
            .await
            .unwrap();

        let ephemeral = registry.list_ephemeral();
        assert_eq!(ephemeral.len(), 2);
    }

    #[test]
    fn test_enriched_snapshot_display_label() {
        let config = TargetConfig::stable(TargetId::http("https://example.com"));
        let snapshot = TargetSnapshot::from_config(&config, HealthState::Healthy, 0, 0, None, None);

        // No custom label - use snapshot
        let enriched = EnrichedSnapshot {
            snapshot: snapshot.clone(),
            tier: DeliveryTier::Quorum,
            ephemeral: false,
            custom_label: None,
        };
        assert!(enriched.display_label().contains("example.com"));

        // With custom label - use it
        let enriched_with_label = EnrichedSnapshot {
            snapshot,
            tier: DeliveryTier::Direct,
            ephemeral: true,
            custom_label: Some("My Server".to_string()),
        };
        assert_eq!(enriched_with_label.display_label(), "My Server");
    }

    #[tokio::test]
    async fn test_composite_targets_in_list_targets() {
        // Composite-only targets (added via add_http_target but not in pools)
        // should appear in list_targets() for consistency with has_available()
        let registry = TransportRegistry::new();

        // Initially empty
        assert!(registry.list_targets().is_empty());
        assert!(!registry.has_available());

        // Add an ephemeral target (goes to composite, not pool)
        let id = registry
            .add_http_target(
                "http://localhost:23006",
                Some("Composite Target".to_string()),
                DeliveryTier::Direct,
            )
            .await
            .unwrap();

        // Now list_targets() should include it
        let targets = registry.list_targets();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].id, id);
        assert_eq!(targets[0].health, HealthState::Unknown); // Composite targets have Unknown health
        assert_eq!(targets[0].label.as_deref(), Some("Composite Target"));

        // has_available() should be consistent
        assert!(registry.has_available());
    }

    #[tokio::test]
    async fn test_composite_targets_in_health_summary() {
        let registry = TransportRegistry::new();

        // Add two composite-only targets
        registry
            .add_http_target("http://localhost:23006", None, DeliveryTier::Direct)
            .await
            .unwrap();
        registry
            .add_http_target("http://localhost:23007", None, DeliveryTier::Quorum)
            .await
            .unwrap();

        // health_summary() should count them as unknown
        let summary = registry.health_summary();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.unknown, 2);
        assert_eq!(summary.healthy, 0);
        assert_eq!(summary.degraded, 0);
        assert_eq!(summary.unhealthy, 0);
    }

    #[tokio::test]
    async fn test_list_targets_has_available_consistency() {
        let registry = TransportRegistry::new();

        // Both should agree on emptiness
        assert!(registry.list_targets().is_empty());
        assert!(!registry.has_available());

        // Add a target
        registry
            .add_http_target("http://localhost:23008", None, DeliveryTier::Direct)
            .await
            .unwrap();

        // Both should agree on non-emptiness
        assert!(!registry.list_targets().is_empty());
        assert!(registry.has_available());

        // Count should match
        assert_eq!(registry.list_targets().len(), 1);
    }
}
