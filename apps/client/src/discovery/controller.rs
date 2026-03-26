use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use base64::prelude::*;
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
use reme_discovery::{decode_txt, DiscoveryEvent, RawDiscoveredPeer};
use reme_encryption::build_identity_sign_data;
use reme_identity::PublicID;
use reme_transport::coordinator::TransportCoordinator;
use reme_transport::delivery::DeliveryTier;
use reme_transport::http_target::{HttpTarget, HttpTargetConfig};
use reme_transport::registry::TransportRegistry;
use reme_transport::target::TargetId;
use serde::Deserialize;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Max identity response body size (a valid response is ~120 bytes).
const MAX_IDENTITY_RESPONSE_BYTES: u64 = 4096;

/// Number of consecutive verification failures before a peer is removed.
const FAILURE_THRESHOLD: u8 = 2;

/// Tracks discovered LAN peers, verifies their identity, and registers them
/// as ephemeral HTTP targets in the [`TransportCoordinator`].
pub struct DiscoveryController {
    /// Maps `instance_name` to tracked peer state.
    peer_index: HashMap<String, PeerEntry>,
    /// Maps `PublicID` to the set of instance names belonging to that identity,
    /// enabling multi-device support (same identity on different devices).
    verified_peer_index: HashMap<PublicID, Vec<String>>,
    /// Maps `routing_key` to candidate public keys for quick contact lookup.
    contact_index: HashMap<[u8; 16], Vec<PublicID>>,
    /// Caches peers whose routing key didn't match any contact at discovery time.
    /// Keyed by mDNS instance name (consistent with `peer_index`).
    /// Stores the decoded routing key alongside the peer to avoid re-parsing TXT records.
    stranger_cache: HashMap<String, (RawDiscoveredPeer, [u8; 16])>,
    max_peers: usize,
    http_client: reqwest::Client,
    /// Registry for tracking ephemeral target metadata (tier, labels).
    registry: Arc<TransportRegistry>,
}

struct PeerEntry {
    verified_identity: PublicID,
    url: String,
    /// Routing key from TXT records at time of verification.
    routing_key: [u8; 16],
    /// Consecutive verification failures during periodic refresh.
    failure_count: u8,
}

#[derive(Deserialize)]
struct IdentityResponse {
    signature: String,
}

/// Configuration for spawning the discovery controller event loop.
pub struct SpawnConfig {
    /// Broadcast receiver for mDNS discovery events.
    pub events: broadcast::Receiver<DiscoveryEvent>,
    /// Transport coordinator for registering/deregistering HTTP targets.
    pub coordinator: Arc<TransportCoordinator>,
    /// Transport registry for tracking ephemeral target metadata.
    pub registry: Arc<TransportRegistry>,
    /// Initial contacts to track (public key + routing key).
    pub contacts: Vec<(PublicID, [u8; 16])>,
    /// Maximum number of peers to track simultaneously.
    pub max_peers: usize,
    /// Interval (in seconds) between periodic peer re-verification.
    pub refresh_interval_secs: u64,
    /// Cancellation token for graceful shutdown.
    pub cancel: CancellationToken,
    /// Channel receiver for dynamically-added contacts at runtime.
    pub contact_rx: mpsc::UnboundedReceiver<(PublicID, [u8; 16])>,
    /// Shared counter updated whenever peers are added or removed.
    pub peer_count: Arc<AtomicUsize>,
}

/// Spawn the discovery controller event loop.
///
/// Listens for [`DiscoveryEvent`]s and, for peers whose routing key matches
/// a known contact, verifies identity and registers them as ephemeral targets.
///
/// A periodic refresh timer re-verifies all tracked peers every
/// `refresh_interval_secs` seconds. Peers that fail verification twice in a row
/// are removed (ephemeral circuit breaker).
///
/// The `contact_rx` channel allows dynamic contact additions at runtime — when a
/// new contact is added via the TUI, the controller immediately starts tracking
/// its routing key for LAN discovery.
///
/// The `peer_count` atomic is updated whenever peers are added or removed,
/// allowing the TUI to display the current discovered peer count without polling.
pub fn spawn(config: SpawnConfig) -> JoinHandle<()> {
    let SpawnConfig {
        mut events,
        coordinator,
        registry,
        contacts,
        max_peers,
        refresh_interval_secs,
        cancel,
        mut contact_rx,
        peer_count,
    } = config;
    tokio::spawn(async move {
        let mut controller = match DiscoveryController::new(contacts, max_peers, registry) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to initialize discovery controller: {e}");
                return;
            }
        };

        let refresh_secs = refresh_interval_secs.max(30);
        if refresh_secs != refresh_interval_secs {
            warn!(
                requested = refresh_interval_secs,
                actual = refresh_secs,
                "refresh_interval_secs too low, clamping to 30"
            );
        }
        let mut refresh_timer = tokio::time::interval(std::time::Duration::from_secs(refresh_secs));
        // The first tick completes immediately; skip it so we don't
        // run refresh before any peers have been discovered.
        refresh_timer.tick().await;

        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                event = events.recv() => {
                    match event {
                        Ok(
                            DiscoveryEvent::PeerDiscovered(peer)
                            | DiscoveryEvent::PeerUpdated(peer),
                        ) => {
                            controller.handle_discovered(peer, &coordinator).await;
                            peer_count.store(controller.peer_index.len(), Ordering::Relaxed);
                        }
                        Ok(DiscoveryEvent::PeerLost(name)) => {
                            controller.handle_lost(&name, &coordinator);
                            peer_count.store(controller.peer_index.len(), Ordering::Relaxed);
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("Discovery controller lagged by {n} events");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                Some((pubkey, routing_key)) = contact_rx.recv() => {
                    let candidates = controller.contact_index.entry(routing_key).or_default();
                    if !candidates.contains(&pubkey) {
                        candidates.push(pubkey);
                    }
                    debug!(
                        pubkey = %hex::encode(pubkey.to_bytes()),
                        "Added new contact to discovery controller"
                    );

                    // Re-process any cached strangers whose routing key matches
                    // the newly added contact. Peers that fail verification are
                    // silently dropped (not re-cached) — they will be caught on
                    // the next mDNS re-announcement.
                    let cached_peers = controller.drain_matching_strangers(&routing_key);
                    for peer in cached_peers {
                        debug!(
                            instance = %peer.instance_name,
                            "Re-processing cached stranger for new contact"
                        );
                        controller.handle_discovered(peer, &coordinator).await;
                    }
                    peer_count.store(controller.peer_index.len(), Ordering::Relaxed);
                }
                _ = refresh_timer.tick() => {
                    controller.refresh_all_peers(&coordinator).await;
                    peer_count.store(controller.peer_index.len(), Ordering::Relaxed);
                }
            }
        }

        // Deregister all tracked peers on shutdown.
        for (name, entry) in controller.peer_index.drain() {
            let target_id = TargetId::http(&entry.url);
            coordinator.remove_http_target(&target_id);
            controller.registry.remove_meta(&target_id);
            debug!(instance = %name, "Deregistered peer on shutdown");
        }
        controller.verified_peer_index.clear();
        controller.stranger_cache.clear();
        peer_count.store(0, Ordering::Relaxed);

        info!("Discovery controller stopped");
    })
}

impl DiscoveryController {
    fn new(
        contacts: Vec<(PublicID, [u8; 16])>,
        max_peers: usize,
        registry: Arc<TransportRegistry>,
    ) -> Result<Self, reqwest::Error> {
        let max_peers = if max_peers == 0 {
            warn!("max_peers was 0, clamping to 1");
            1
        } else {
            max_peers
        };

        let mut contact_index: HashMap<[u8; 16], Vec<PublicID>> = HashMap::new();
        for (pubkey, routing_key) in contacts {
            contact_index.entry(routing_key).or_default().push(pubkey);
        }

        Ok(Self {
            peer_index: HashMap::new(),
            verified_peer_index: HashMap::new(),
            contact_index,
            stranger_cache: HashMap::new(),
            max_peers,
            http_client: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(2))
                .timeout(std::time::Duration::from_secs(5))
                .build()?,
            registry,
        })
    }

    /// Periodic refresh: re-verify every tracked peer. On failure, increment
    /// the failure counter; at [`FAILURE_THRESHOLD`] consecutive failures,
    /// remove the peer entirely (ephemeral circuit breaker). On success, reset
    /// the counter.
    async fn refresh_all_peers(&mut self, coordinator: &TransportCoordinator) {
        // Collect peer data first to avoid borrowing issues.
        let peers: Vec<(String, String, PublicID)> = self
            .peer_index
            .iter()
            .map(|(name, entry)| (name.clone(), entry.url.clone(), entry.verified_identity))
            .collect();

        if peers.is_empty() {
            return;
        }

        debug!(count = peers.len(), "Starting periodic peer refresh");

        let mut to_remove = Vec::new();

        for (name, url, identity) in &peers {
            let candidates = std::slice::from_ref(identity);
            let ok = match self.verify_peer_identity(url, candidates).await {
                Ok(Some(_)) => true,
                Ok(None) | Err(_) => false,
            };

            if ok {
                if let Some(entry) = self.peer_index.get_mut(name) {
                    if entry.failure_count > 0 {
                        debug!(instance = %name, "Peer refresh succeeded, resetting failure count");
                    }
                    entry.failure_count = 0;
                }
            } else if let Some(entry) = self.peer_index.get_mut(name) {
                entry.failure_count += 1;
                debug!(
                    instance = %name,
                    failures = entry.failure_count,
                    "Peer refresh verification failed"
                );
                if entry.failure_count >= FAILURE_THRESHOLD {
                    to_remove.push(name.clone());
                }
            }
        }

        for name in to_remove {
            info!(
                instance = %name,
                "Removing stale peer after {} consecutive verification failures",
                FAILURE_THRESHOLD
            );
            self.remove_peer(&name, coordinator);
        }
    }

    // This handler orchestrates validation, identity verification, and routing
    // for a single discovery event; keeping it in one function preserves the
    // control-flow context, so we suppress the length lint rather than splitting.
    #[allow(clippy::too_many_lines)]
    async fn handle_discovered(
        &mut self,
        peer: reme_discovery::RawDiscoveredPeer,
        coordinator: &TransportCoordinator,
    ) {
        let routing_key = match decode_txt(&peer.txt_records) {
            Ok(fields) => fields.routing_key,
            Err(e) => {
                warn!(
                    instance = %peer.instance_name,
                    "Failed to decode TXT records: {e}"
                );
                return;
            }
        };

        let Some(candidates) = self.contact_index.get(&routing_key) else {
            if self.stranger_cache.len() < self.max_peers {
                debug!(
                    instance = %peer.instance_name,
                    "Caching stranger (routing key not in contacts)"
                );
                self.stranger_cache
                    .insert(peer.instance_name.clone(), (peer, routing_key));
            } else {
                debug!(
                    instance = %peer.instance_name,
                    max = self.max_peers,
                    "Stranger cache full, dropping peer"
                );
            }
            return;
        };

        let is_update = self.peer_index.contains_key(&peer.instance_name);

        if !is_update && self.peer_index.len() >= self.max_peers {
            warn!(
                instance = %peer.instance_name,
                max = self.max_peers,
                "Peer limit reached, ignoring new peer"
            );
            return;
        }

        if peer.addresses.is_empty() {
            warn!(
                instance = %peer.instance_name,
                "No addresses in discovery event"
            );
            return;
        }

        // For updates where both the stored URL and TXT routing key still match,
        // skip re-verification entirely. If only the address matches but TXT
        // content changed (e.g. identity rotation), re-verify. (Fixes #105)
        if is_update {
            let Some(entry) = self.peer_index.get(&peer.instance_name) else {
                warn!(
                    instance = %peer.instance_name,
                    "PeerUpdated for unknown peer (possible mDNS race), skipping"
                );
                return;
            };
            let stored_url_still_valid = peer.addresses.iter().any(|&addr| {
                let candidate = format!("http://{}", SocketAddr::new(addr, peer.port));
                entry.url == candidate
            });
            let routing_key_unchanged = entry.routing_key == routing_key;
            if stored_url_still_valid && routing_key_unchanged {
                debug!(
                    instance = %peer.instance_name,
                    "Update with matching address and routing key, skipping re-verification"
                );
                return;
            }
        }

        // Try each address until identity verification succeeds.
        let mut result: Option<(PublicID, String)> = None;
        for &addr in &peer.addresses {
            let url = format!("http://{}", SocketAddr::new(addr, peer.port));
            match self.verify_peer_identity(&url, candidates).await {
                Ok(Some(pubkey)) => {
                    result = Some((pubkey, url));
                    break;
                }
                Ok(None) => {
                    debug!(
                        instance = %peer.instance_name,
                        addr = %addr,
                        "Identity verification: no candidate matched"
                    );
                }
                Err(e) => {
                    debug!(
                        instance = %peer.instance_name,
                        addr = %addr,
                        "Identity verification failed: {e}"
                    );
                }
            }
        }

        let Some((verified, url)) = result else {
            debug!(
                instance = %peer.instance_name,
                "No address passed identity verification"
            );
            return;
        };

        if is_update {
            self.handle_update(
                &peer.instance_name,
                &url,
                verified,
                routing_key,
                coordinator,
            );
        } else {
            self.handle_new(
                &peer.instance_name,
                &url,
                verified,
                routing_key,
                coordinator,
            );
        }
    }

    fn build_http_target(instance_name: &str, url: &str, verified: PublicID) -> Option<HttpTarget> {
        let config = HttpTargetConfig::ephemeral(url)
            .with_node_pubkey(verified)
            .with_label(format!("lan:{instance_name}"));

        match HttpTarget::new(config) {
            Ok(t) => Some(t),
            Err(e) => {
                warn!(instance = %instance_name, "Failed to create HTTP target: {e}");
                None
            }
        }
    }

    fn handle_new(
        &mut self,
        instance_name: &str,
        url: &str,
        verified: PublicID,
        routing_key: [u8; 16],
        coordinator: &TransportCoordinator,
    ) {
        let Some(target) = Self::build_http_target(instance_name, url, verified) else {
            return;
        };

        let target_id = TargetId::http(url);

        // TODO(#90): receipt-gated direct tier — currently a relay attacker who
        // passes identity verification can blackhole messages. Once #90 lands,
        // Direct tier will require a verified receipt before declaring success.
        // See also #27 / #32 for privacy-preserving fetch from ephemeral nodes.
        coordinator.add_http_target(target);

        // Register as ephemeral Direct target so UI/registry show correct tier (#106)
        self.registry.register_ephemeral(
            target_id,
            Some(format!("lan:{instance_name}")),
            DeliveryTier::Direct,
        );

        info!(
            instance = %instance_name,
            url = %url,
            "Registered discovered peer"
        );

        self.peer_index.insert(
            instance_name.to_owned(),
            PeerEntry {
                verified_identity: verified,
                url: url.to_owned(),
                routing_key,
                failure_count: 0,
            },
        );

        self.verified_peer_index
            .entry(verified)
            .or_default()
            .push(instance_name.to_owned());
    }

    fn handle_update(
        &mut self,
        instance_name: &str,
        url: &str,
        verified: PublicID,
        routing_key: [u8; 16],
        coordinator: &TransportCoordinator,
    ) {
        let Some(entry) = self.peer_index.get(instance_name) else {
            warn!(
                instance = %instance_name,
                "handle_update called for unknown peer (possible mDNS race), skipping"
            );
            return;
        };
        let address_changed = entry.url != url;
        let identity_changed = entry.verified_identity != verified;

        if !address_changed && !identity_changed {
            return;
        }

        let old_target_id = TargetId::http(&entry.url);
        let old_identity = entry.verified_identity;

        let Some(target) = Self::build_http_target(instance_name, url, verified) else {
            return;
        };

        coordinator.replace_http_target(&old_target_id, target);

        // Update registry metadata when address changes (#106)
        if address_changed {
            // Remove old target metadata, register new one
            self.registry.remove_meta(&old_target_id);
            self.registry.register_ephemeral(
                TargetId::http(url),
                Some(format!("lan:{instance_name}")),
                DeliveryTier::Direct,
            );
        }

        if address_changed {
            info!(
                instance = %instance_name,
                old_url = %entry.url,
                new_url = %url,
                "Updated discovered peer address"
            );
        } else {
            info!(
                instance = %instance_name,
                "Updated discovered peer identity"
            );
        }

        // If identity changed, update the verified_peer_index.
        if identity_changed {
            // Remove from old identity's instance list.
            if let Some(instances) = self.verified_peer_index.get_mut(&old_identity) {
                instances.retain(|n| n != instance_name);
                if instances.is_empty() {
                    self.verified_peer_index.remove(&old_identity);
                }
            }
            // Add to new identity's instance list.
            self.verified_peer_index
                .entry(verified)
                .or_default()
                .push(instance_name.to_owned());
        }

        // Update the entry in-place to avoid re-allocating the key.
        // Safety: this method takes `&mut self` so no concurrent removal is possible,
        // and no code path above removes from `peer_index`, so this lookup cannot fail
        // if the guard at the top of the function succeeded.
        let Some(entry) = self.peer_index.get_mut(instance_name) else {
            warn!(
                instance = %instance_name,
                "Peer entry vanished before in-place update (possible mDNS race), skipping"
            );
            return;
        };
        entry.verified_identity = verified;
        url.clone_into(&mut entry.url);
        entry.routing_key = routing_key;
        entry.failure_count = 0;
    }

    fn handle_lost(&mut self, instance_name: &str, coordinator: &TransportCoordinator) {
        self.stranger_cache.remove(instance_name);
        self.remove_peer(instance_name, coordinator);
    }

    /// Remove a peer from all indices and deregister its HTTP target.
    fn remove_peer(&mut self, instance_name: &str, coordinator: &TransportCoordinator) {
        if let Some(entry) = self.peer_index.remove(instance_name) {
            let target_id = TargetId::http(&entry.url);
            coordinator.remove_http_target(&target_id);
            self.registry.remove_meta(&target_id);

            // Remove from verified_peer_index.
            if let Some(instances) = self.verified_peer_index.get_mut(&entry.verified_identity) {
                instances.retain(|n| n != instance_name);
                if instances.is_empty() {
                    self.verified_peer_index.remove(&entry.verified_identity);
                }
            }

            info!(instance = %instance_name, "Removed peer");
        }
    }

    /// Remove and return all cached strangers whose routing key matches `target_rk`.
    fn drain_matching_strangers(&mut self, target_rk: &[u8; 16]) -> Vec<RawDiscoveredPeer> {
        let matching_keys: Vec<String> = self
            .stranger_cache
            .iter()
            .filter(|(_, (_, rk))| rk == target_rk)
            .map(|(name, _)| name.clone())
            .collect();

        matching_keys
            .into_iter()
            .filter_map(|name| self.stranger_cache.remove(&name))
            .map(|(peer, _)| peer)
            .collect()
    }

    // FIXME(SEC-3): channel binding not implemented — responder IP:port not in signed data
    async fn verify_peer_identity(
        &self,
        base_url: &str,
        candidates: &[PublicID],
    ) -> Result<Option<PublicID>, reqwest::Error> {
        let challenge: [u8; 32] = rand::random();
        let challenge_b64 = BASE64_STANDARD.encode(challenge);
        let challenge_encoded = percent_encode(challenge_b64.as_bytes(), NON_ALPHANUMERIC);

        let url = format!(
            "{}/api/v1/identity?challenge={}",
            base_url.trim_end_matches('/'),
            challenge_encoded
        );

        let mut resp = self.http_client.get(&url).send().await?;

        if !resp.status().is_success() {
            debug!(status = %resp.status(), "Identity challenge returned non-success");
            return Ok(None);
        }

        // Guard against oversized responses from malicious peers.
        // Stream the body incrementally so we never allocate more than the cap.
        // A malicious peer omitting Content-Length cannot force unbounded allocation.
        // Safe: MAX_IDENTITY_RESPONSE_BYTES is 4096, well within usize on any target.
        #[allow(clippy::cast_possible_truncation)]
        let max = MAX_IDENTITY_RESPONSE_BYTES as usize;
        let mut buf = Vec::with_capacity(max);
        while let Some(chunk) = resp.chunk().await? {
            if buf.len() + chunk.len() > max {
                debug!(
                    size = buf.len() + chunk.len(),
                    "Identity response too large, skipping"
                );
                return Ok(None);
            }
            buf.extend_from_slice(&chunk);
        }
        let Ok(body) = serde_json::from_slice::<IdentityResponse>(&buf) else {
            debug!("Failed to parse identity response");
            return Ok(None);
        };

        let Ok(sig_bytes) = BASE64_STANDARD.decode(&body.signature) else {
            debug!("Failed to base64-decode identity signature");
            return Ok(None);
        };
        let Ok(signature): Result<[u8; 64], _> = sig_bytes.try_into() else {
            debug!("Identity signature has wrong length (expected 64 bytes)");
            return Ok(None);
        };

        // Iterate ALL candidates to prevent timing-based information leakage
        // about which identity was matched or how many candidates exist.
        let mut matched: Option<PublicID> = None;
        for candidate in candidates {
            let sign_data = build_identity_sign_data(&challenge, &candidate.to_bytes());
            if candidate.verify_xeddsa(&sign_data, &signature) && matched.is_none() {
                matched = Some(*candidate);
            }
        }

        Ok(matched)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reme_identity::Identity;
    use reme_transport::coordinator::CoordinatorConfig;
    use std::net::IpAddr;
    use std::time::Instant;

    fn test_registry() -> Arc<TransportRegistry> {
        Arc::new(TransportRegistry::new())
    }

    #[test]
    fn socket_addr_formats_ipv6_with_brackets() {
        let addr: IpAddr = "::1".parse().unwrap();
        let sa = SocketAddr::new(addr, 8080);
        assert_eq!(format!("http://{sa}"), "http://[::1]:8080");
    }

    #[test]
    fn socket_addr_formats_ipv4() {
        let addr: IpAddr = "192.168.1.1".parse().unwrap();
        let sa = SocketAddr::new(addr, 8080);
        assert_eq!(format!("http://{sa}"), "http://192.168.1.1:8080");
    }

    #[test]
    fn controller_ignores_stranger_routing_key() {
        let identity = Identity::generate();
        let pubkey = *identity.public_id();
        let rk = pubkey.routing_key();
        let contacts = vec![(pubkey, *rk)];
        let controller = DiscoveryController::new(contacts, 256, test_registry()).unwrap();

        let stranger_rk = [0xFFu8; 16];
        assert!(!controller.contact_index.contains_key(&stranger_rk));
    }

    #[test]
    fn controller_contact_index_groups_by_routing_key() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let pk1 = *id1.public_id();
        let pk2 = *id2.public_id();

        let rk = [0xAA; 16];
        let contacts = vec![(pk1, rk), (pk2, rk)];
        let controller = DiscoveryController::new(contacts, 256, test_registry()).unwrap();

        let candidates = controller.contact_index.get(&rk).unwrap();
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn handle_lost_removes_peer() {
        let mut controller = DiscoveryController::new(vec![], 256, test_registry()).unwrap();
        let coordinator = TransportCoordinator::new(CoordinatorConfig::default());

        let peer_identity = *Identity::generate().public_id();
        controller.peer_index.insert(
            "test-peer".to_string(),
            PeerEntry {
                verified_identity: peer_identity,
                url: "http://192.168.1.50:23003".to_owned(),
                routing_key: [0xAA; 16],
                failure_count: 0,
            },
        );
        controller
            .verified_peer_index
            .entry(peer_identity)
            .or_default()
            .push("test-peer".to_string());

        assert!(controller.peer_index.contains_key("test-peer"));
        assert!(controller.verified_peer_index.contains_key(&peer_identity));
        controller.handle_lost("test-peer", &coordinator);
        assert!(!controller.peer_index.contains_key("test-peer"));
        assert!(!controller.verified_peer_index.contains_key(&peer_identity));
    }

    #[test]
    fn handle_lost_noop_for_unknown_peer() {
        let mut controller = DiscoveryController::new(vec![], 256, test_registry()).unwrap();
        let coordinator = TransportCoordinator::new(CoordinatorConfig::default());

        controller.handle_lost("nonexistent", &coordinator);
    }

    #[test]
    fn verified_peer_index_tracks_multi_device() {
        let mut controller = DiscoveryController::new(vec![], 256, test_registry()).unwrap();
        let coordinator = TransportCoordinator::new(CoordinatorConfig::default());
        let peer_identity = *Identity::generate().public_id();

        // Simulate two devices with the same identity.
        let rk = [0xBB; 16];
        controller.handle_new(
            "device-a",
            "http://192.168.1.10:23003",
            peer_identity,
            rk,
            &coordinator,
        );
        controller.handle_new(
            "device-b",
            "http://192.168.1.11:23003",
            peer_identity,
            rk,
            &coordinator,
        );

        let instances = controller.verified_peer_index.get(&peer_identity).unwrap();
        assert_eq!(instances.len(), 2);
        assert!(instances.contains(&"device-a".to_string()));
        assert!(instances.contains(&"device-b".to_string()));

        // Remove one device; the identity should still be tracked.
        controller.handle_lost("device-a", &coordinator);
        let instances = controller.verified_peer_index.get(&peer_identity).unwrap();
        assert_eq!(instances.len(), 1);
        assert!(instances.contains(&"device-b".to_string()));

        // Remove the last device; the identity entry should be cleaned up.
        controller.handle_lost("device-b", &coordinator);
        assert!(!controller.verified_peer_index.contains_key(&peer_identity));
    }

    #[test]
    fn handle_update_noop_for_unknown_peer() {
        let mut controller = DiscoveryController::new(vec![], 256, test_registry()).unwrap();
        let coordinator = TransportCoordinator::new(CoordinatorConfig::default());
        let peer_identity = *Identity::generate().public_id();

        // Calling handle_update for a peer not in peer_index must not panic
        // and must not mutate any indices.
        controller.handle_update(
            "nonexistent",
            "http://192.168.1.99:23003",
            peer_identity,
            [0xDD; 16],
            &coordinator,
        );

        assert!(controller.peer_index.is_empty());
        assert!(controller.verified_peer_index.is_empty());
    }

    fn make_stranger_peer(instance_name: &str, rk: &[u8; 16]) -> RawDiscoveredPeer {
        RawDiscoveredPeer {
            instance_name: instance_name.to_string(),
            addresses: vec!["192.168.1.50".parse().unwrap()],
            port: 23003,
            txt_records: reme_discovery::encode_txt(rk, 23003),
            discovered_at: Instant::now(),
        }
    }

    #[tokio::test]
    async fn handle_discovered_caches_stranger() {
        let mut controller = DiscoveryController::new(vec![], 256, test_registry()).unwrap();
        let coordinator = TransportCoordinator::new(CoordinatorConfig::default());

        let rk = [0xAAu8; 16];
        let peer = make_stranger_peer("stranger-peer", &rk);

        controller.handle_discovered(peer, &coordinator).await;

        assert_eq!(controller.stranger_cache.len(), 1);
        assert!(controller.stranger_cache.contains_key("stranger-peer"));
        assert!(controller.peer_index.is_empty());
    }

    #[tokio::test]
    async fn peer_lost_cleans_stranger_cache() {
        let mut controller = DiscoveryController::new(vec![], 256, test_registry()).unwrap();
        let coordinator = TransportCoordinator::new(CoordinatorConfig::default());

        let rk = [0xAAu8; 16];
        let peer = make_stranger_peer("will-be-lost", &rk);

        controller.handle_discovered(peer, &coordinator).await;
        assert_eq!(controller.stranger_cache.len(), 1);

        controller.handle_lost("will-be-lost", &coordinator);
        assert!(controller.stranger_cache.is_empty());
    }

    #[test]
    fn drain_matching_strangers_returns_matches() {
        let mut controller = DiscoveryController::new(vec![], 256, test_registry()).unwrap();

        let rk = [0xBBu8; 16];
        let peer = make_stranger_peer("cached-stranger", &rk);
        let name = peer.instance_name.clone();
        controller.stranger_cache.insert(name, (peer, rk));

        let matches = controller.drain_matching_strangers(&rk);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].instance_name, "cached-stranger");
        assert!(controller.stranger_cache.is_empty());
    }

    #[test]
    fn drain_matching_strangers_ignores_non_matches() {
        let mut controller = DiscoveryController::new(vec![], 256, test_registry()).unwrap();

        let rk_a = [0xAAu8; 16];
        let rk_b = [0xBBu8; 16];
        let peer = make_stranger_peer("other-stranger", &rk_a);
        let name = peer.instance_name.clone();
        controller.stranger_cache.insert(name, (peer, rk_a));

        let matches = controller.drain_matching_strangers(&rk_b);
        assert!(matches.is_empty());
        assert_eq!(controller.stranger_cache.len(), 1);
    }

    #[tokio::test]
    async fn stranger_cache_respects_max_peers() {
        let mut controller = DiscoveryController::new(vec![], 2, test_registry()).unwrap();
        let coordinator = TransportCoordinator::new(CoordinatorConfig::default());

        for i in 0..3u8 {
            let mut rk = [0u8; 16];
            rk[0] = i;
            let peer = make_stranger_peer(&format!("stranger-{i}"), &rk);
            controller.handle_discovered(peer, &coordinator).await;
        }

        assert_eq!(controller.stranger_cache.len(), 2);
    }

    #[test]
    fn failure_count_starts_at_zero() {
        let mut controller = DiscoveryController::new(vec![], 256, test_registry()).unwrap();
        let coordinator = TransportCoordinator::new(CoordinatorConfig::default());
        let peer_identity = *Identity::generate().public_id();

        controller.handle_new(
            "peer-1",
            "http://192.168.1.10:23003",
            peer_identity,
            [0xCC; 16],
            &coordinator,
        );
        assert_eq!(controller.peer_index["peer-1"].failure_count, 0);
    }
}
