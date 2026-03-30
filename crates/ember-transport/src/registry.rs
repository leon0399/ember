//! Unified transport registry for UI and management.
//!
//! The `TransportRegistry` provides a read-only view of transport state,
//! aggregating pool information from the `TransportCoordinator` along with
//! metadata for display purposes.
//!
//! This is the primary entry point for UI code to query transport state.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use crate::coordinator::TransportCoordinator;
use crate::delivery::DeliveryTier;
use crate::http_target::HttpTarget;
use crate::pool::TransportPool;
use crate::query::{HealthSummary, TargetSnapshot, TransportQuery};
use crate::target::{HealthData, HealthState, TargetConfig, TargetId};

#[cfg(feature = "mqtt")]
use crate::mqtt_target::MqttTarget;

/// Metadata for targets tracked by the registry.
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

/// Read-only transport registry for UI and management.
///
/// The registry aggregates targets from multiple sources:
/// - HTTP transport pool (stable and ephemeral targets)
/// - MQTT transport pool (stable and ephemeral targets)
///
/// It provides a consistent `TransportQuery` interface for all UI frontends.
/// Target mutation is handled by the `TransportCoordinator`; the registry
/// only reads pool state and maintains display metadata.
pub struct TransportRegistry {
    /// HTTP transport pool (read from coordinator).
    http_pool: Option<Arc<TransportPool<HttpTarget>>>,

    /// MQTT transport pool (read from coordinator).
    #[cfg(feature = "mqtt")]
    mqtt_pool: Option<Arc<TransportPool<MqttTarget>>>,

    /// Metadata for targets (not stored in transport layer).
    target_meta: RwLock<HashMap<TargetId, EphemeralMeta>>,
}

impl TransportRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            http_pool: None,
            #[cfg(feature = "mqtt")]
            mqtt_pool: None,
            target_meta: RwLock::new(HashMap::new()),
        }
    }

    /// Create a registry that reads pool state from the coordinator.
    ///
    /// This is the preferred constructor. The registry becomes a read-only
    /// view over the coordinator's transport pools.
    pub fn with_coordinator(coordinator: &TransportCoordinator) -> Self {
        Self {
            http_pool: coordinator.http_pool().cloned(),
            #[cfg(feature = "mqtt")]
            mqtt_pool: coordinator.mqtt_pool().cloned(),
            target_meta: RwLock::new(HashMap::new()),
        }
    }

    /// Get the HTTP transport pool.
    pub const fn http_pool(&self) -> Option<&Arc<TransportPool<HttpTarget>>> {
        self.http_pool.as_ref()
    }

    /// Get the MQTT transport pool.
    #[cfg(feature = "mqtt")]
    pub const fn mqtt_pool(&self) -> Option<&Arc<TransportPool<MqttTarget>>> {
        self.mqtt_pool.as_ref()
    }

    /// Register an ephemeral target for display purposes.
    ///
    /// This records metadata (label, tier, ephemeral flag) for a target
    /// that was added to the coordinator at runtime.
    pub fn register_ephemeral(&self, id: TargetId, label: Option<String>, tier: DeliveryTier) {
        let Ok(mut meta) = self.target_meta.write() else {
            return;
        };
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
        let Ok(mut meta) = self.target_meta.write() else {
            return;
        };
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

    /// Remove metadata for a target (e.g. when a discovered peer is deregistered).
    pub fn remove_meta(&self, id: &TargetId) {
        if let Ok(mut meta) = self.target_meta.write() {
            meta.remove(id);
        }
    }

    /// Get metadata for a target.
    pub fn get_ephemeral_meta(&self, id: &TargetId) -> Option<EphemeralMeta> {
        self.target_meta.read().ok()?.get(id).cloned()
    }

    /// List all targets with metadata.
    pub fn list_ephemeral(&self) -> Vec<EphemeralMeta> {
        let Ok(meta) = self.target_meta.read() else {
            return Vec::new();
        };
        meta.values().cloned().collect()
    }

    /// Get a combined list of all targets with tier and ephemeral metadata.
    ///
    /// This is the primary method for UI display, enriching snapshots with
    /// registry metadata.
    ///
    /// # Health State for Metadata-Only Targets
    ///
    /// Targets that exist only in metadata (not in HTTP/MQTT pools)
    /// will have `HealthState::Unknown` since the registry does not track their
    /// health. These are typically send-only targets without active polling.
    pub fn list_all_targets(&self) -> Vec<EnrichedSnapshot> {
        let mut results = Vec::new();
        let Ok(meta) = self.target_meta.read() else {
            return results;
        };

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

        // Add metadata-only targets (not in pools)
        // These are typically send-only targets without active health tracking
        for (id, emeta) in meta.iter() {
            // O(1) membership check
            if !seen_ids.contains(id) {
                // Create a synthetic snapshot for metadata-only targets
                // Health is Unknown since we don't have active health tracking for these
                let snapshot = TargetSnapshot::from_config(
                    &TargetConfig::ephemeral(id.clone()),
                    &HealthData {
                        state: HealthState::Unknown,
                        ..HealthData::default()
                    },
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

/// Implement `TransportQuery` for unified access.
///
/// This implementation includes targets from all sources:
/// - HTTP pool targets (with health tracking)
/// - MQTT pool targets (with health tracking)
/// - Metadata-only targets (without health tracking)
impl TransportQuery for TransportRegistry {
    fn list_targets(&self) -> Vec<TargetSnapshot> {
        let mut targets = Vec::new();
        let Ok(meta) = self.target_meta.read() else {
            return targets;
        };

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

        // Add metadata-only targets (not in pools)
        // These have HealthState::Unknown since we don't track their health
        for (id, emeta) in meta.iter() {
            if !seen_ids.contains(id) {
                let snapshot = TargetSnapshot::from_config(
                    &TargetConfig::ephemeral(id.clone()).with_label_opt(emeta.label.clone()),
                    &HealthData {
                        state: HealthState::Unknown,
                        ..HealthData::default()
                    },
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

        // Count metadata-only targets (not in pools)
        let Ok(meta) = self.target_meta.read() else {
            return summary;
        };
        let metadata_only_count = meta.keys().filter(|id| !seen_ids.contains(*id)).count();
        if metadata_only_count > 0 {
            summary.total += metadata_only_count;
            summary.unknown += metadata_only_count;
        }

        summary
    }

    fn has_available(&self) -> bool {
        let http_available = self.http_pool.as_ref().is_some_and(|p| p.has_available());

        #[cfg(feature = "mqtt")]
        let mqtt_available = self.mqtt_pool.as_ref().is_some_and(|p| p.has_available());
        #[cfg(not(feature = "mqtt"))]
        let mqtt_available = false;

        // Metadata-only targets (e.g. LAN peers registered via discovery) have no
        // pool backing and report HealthState::Unknown. We still consider them
        // "available" because the coordinator routes sends through their ephemeral
        // HTTP connections directly.
        let has_meta_targets = self.target_meta.read().is_ok_and(|meta| !meta.is_empty());

        http_available || mqtt_available || has_meta_targets
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

    #[test]
    fn test_register_ephemeral() {
        let registry = TransportRegistry::new();
        let id = TargetId::http("http://localhost:23004");

        registry.register_ephemeral(id.clone(), Some("Test".to_string()), DeliveryTier::Direct);

        let meta = registry.get_ephemeral_meta(&id).unwrap();
        assert_eq!(meta.label, Some("Test".to_string()));
        assert!(meta.ephemeral);
        assert_eq!(meta.tier, DeliveryTier::Direct);
    }

    #[test]
    fn test_list_ephemeral() {
        let registry = TransportRegistry::new();

        registry.register_ephemeral(
            TargetId::http("http://localhost:23004"),
            Some("A".to_string()),
            DeliveryTier::Direct,
        );
        registry.register_ephemeral(
            TargetId::http("http://localhost:23005"),
            Some("B".to_string()),
            DeliveryTier::Quorum,
        );

        let ephemeral = registry.list_ephemeral();
        assert_eq!(ephemeral.len(), 2);
    }

    #[test]
    fn test_enriched_snapshot_display_label() {
        let config = TargetConfig::stable(TargetId::http("https://example.com"));
        let snapshot = TargetSnapshot::from_config(
            &config,
            &HealthData {
                state: HealthState::Healthy,
                ..HealthData::default()
            },
        );

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

    #[test]
    fn test_metadata_targets_in_list_targets() {
        // Metadata-only targets should appear in list_targets()
        // for consistency with has_available()
        let registry = TransportRegistry::new();

        // Initially empty
        assert!(registry.list_targets().is_empty());
        assert!(!registry.has_available());

        // Register a target (metadata only, no pool)
        let id = TargetId::http("http://localhost:23006");
        registry.register_ephemeral(
            id.clone(),
            Some("Meta Target".to_string()),
            DeliveryTier::Direct,
        );

        // Now list_targets() should include it
        let targets = registry.list_targets();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].id, id);
        assert_eq!(targets[0].health, HealthState::Unknown);

        // has_available() should be consistent
        assert!(registry.has_available());
    }

    #[test]
    fn test_metadata_targets_in_health_summary() {
        let registry = TransportRegistry::new();

        // Register two metadata-only targets
        registry.register_ephemeral(
            TargetId::http("http://localhost:23006"),
            None,
            DeliveryTier::Direct,
        );
        registry.register_ephemeral(
            TargetId::http("http://localhost:23007"),
            None,
            DeliveryTier::Quorum,
        );

        // health_summary() should count them as unknown
        let summary = registry.health_summary();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.unknown, 2);
        assert_eq!(summary.healthy, 0);
        assert_eq!(summary.degraded, 0);
        assert_eq!(summary.unhealthy, 0);
    }

    #[test]
    fn test_list_targets_has_available_consistency() {
        let registry = TransportRegistry::new();

        // Both should agree on emptiness
        assert!(registry.list_targets().is_empty());
        assert!(!registry.has_available());

        // Register a target
        registry.register_ephemeral(
            TargetId::http("http://localhost:23008"),
            None,
            DeliveryTier::Direct,
        );

        // Both should agree on non-emptiness
        assert!(!registry.list_targets().is_empty());
        assert!(registry.has_available());

        // Count should match
        assert_eq!(registry.list_targets().len(), 1);
    }
}
