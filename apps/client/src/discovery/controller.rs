use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use base64::prelude::*;
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
use reme_discovery::{decode_txt, DiscoveryEvent};
use reme_encryption::build_identity_sign_data;
use reme_identity::PublicID;
use reme_transport::coordinator::TransportCoordinator;
use reme_transport::http_target::{HttpTarget, HttpTargetConfig};
use reme_transport::target::TargetId;
use serde::Deserialize;
use tokio::sync::broadcast;
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
    max_peers: usize,
    http_client: reqwest::Client,
}

struct PeerEntry {
    verified_identity: PublicID,
    url: String,
    /// Consecutive verification failures during periodic refresh.
    failure_count: u8,
}

#[derive(Deserialize)]
struct IdentityResponse {
    signature: String,
}

/// Spawn the discovery controller event loop.
///
/// Listens for [`DiscoveryEvent`]s and, for peers whose routing key matches
/// a known contact, verifies identity and registers them as ephemeral targets.
///
/// A periodic refresh timer re-verifies all tracked peers every
/// `refresh_interval_secs` seconds. Peers that fail verification twice in a row
/// are removed (ephemeral circuit breaker).
pub fn spawn(
    mut events: broadcast::Receiver<DiscoveryEvent>,
    coordinator: Arc<TransportCoordinator>,
    contacts: Vec<(PublicID, [u8; 16])>,
    max_peers: usize,
    refresh_interval_secs: u64,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut controller = match DiscoveryController::new(contacts, max_peers) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to initialize discovery controller: {e}");
                return;
            }
        };

        let mut refresh_timer =
            tokio::time::interval(std::time::Duration::from_secs(refresh_interval_secs));
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
                        }
                        Ok(DiscoveryEvent::PeerLost(name)) => {
                            controller.handle_lost(&name, &coordinator);
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("Discovery controller lagged by {n} events");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = refresh_timer.tick() => {
                    controller.refresh_all_peers(&coordinator).await;
                }
            }
        }

        // Deregister all tracked peers on shutdown.
        for (name, entry) in controller.peer_index.drain() {
            coordinator.remove_http_target(&TargetId::http(&entry.url));
            debug!(instance = %name, "Deregistered peer on shutdown");
        }
        controller.verified_peer_index.clear();

        info!("Discovery controller stopped");
    })
}

impl DiscoveryController {
    fn new(contacts: Vec<(PublicID, [u8; 16])>, max_peers: usize) -> Result<Self, reqwest::Error> {
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
            max_peers,
            http_client: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(2))
                .timeout(std::time::Duration::from_secs(5))
                .build()?,
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
            debug!(
                instance = %peer.instance_name,
                "Ignoring stranger (routing key not in contacts)"
            );
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

        // For updates where the stored URL still matches one of the new addresses,
        // skip re-verification entirely.
        if is_update {
            let entry = &self.peer_index[&peer.instance_name];
            let stored_url_still_valid = peer.addresses.iter().any(|&addr| {
                let candidate = format!("http://{}", SocketAddr::new(addr, peer.port));
                entry.url == candidate
            });
            if stored_url_still_valid {
                debug!(
                    instance = %peer.instance_name,
                    "Update with matching address, skipping re-verification"
                );
                return;
            }
        }

        // Try each address until identity verification succeeds.
        let mut verified = None;
        let mut working_url = None;
        for &addr in &peer.addresses {
            let url = format!("http://{}", SocketAddr::new(addr, peer.port));
            match self.verify_peer_identity(&url, candidates).await {
                Ok(Some(pubkey)) => {
                    verified = Some(pubkey);
                    working_url = Some(url);
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

        let (Some(verified), Some(url)) = (verified, working_url) else {
            debug!(
                instance = %peer.instance_name,
                "No address passed identity verification"
            );
            return;
        };

        if is_update {
            self.handle_update(&peer.instance_name, &url, verified, coordinator);
        } else {
            self.handle_new(&peer.instance_name, &url, verified, coordinator);
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
        coordinator: &TransportCoordinator,
    ) {
        let Some(target) = Self::build_http_target(instance_name, url, verified) else {
            return;
        };

        // TODO(#90): receipt-gated direct tier — currently a relay attacker who
        // passes identity verification can blackhole messages. Once #90 lands,
        // Direct tier will require a verified receipt before declaring success.
        // See also #27 / #32 for privacy-preserving fetch from ephemeral nodes.
        coordinator.add_http_target(target);

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
        coordinator: &TransportCoordinator,
    ) {
        let entry = self
            .peer_index
            .get(instance_name)
            .expect("invariant: is_update implies entry exists");
        let address_changed = entry.url != url;
        let identity_changed = entry.verified_identity != verified;
        let old_target_id = TargetId::http(&entry.url);
        let old_identity = entry.verified_identity;

        if !address_changed && !identity_changed {
            return;
        }

        let Some(target) = Self::build_http_target(instance_name, url, verified) else {
            return;
        };

        coordinator.replace_http_target(&old_target_id, target);

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

        self.peer_index.insert(
            instance_name.to_owned(),
            PeerEntry {
                verified_identity: verified,
                url: url.to_owned(),
                failure_count: 0,
            },
        );
    }

    fn handle_lost(&mut self, instance_name: &str, coordinator: &TransportCoordinator) {
        self.remove_peer(instance_name, coordinator);
    }

    /// Remove a peer from all indices and deregister its HTTP target.
    fn remove_peer(&mut self, instance_name: &str, coordinator: &TransportCoordinator) {
        if let Some(entry) = self.peer_index.remove(instance_name) {
            coordinator.remove_http_target(&TargetId::http(&entry.url));

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
        let mut buf = Vec::with_capacity(max.min(4096));
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
        let bytes = buf;

        let Ok(body) = serde_json::from_slice::<IdentityResponse>(&bytes) else {
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
        let controller = DiscoveryController::new(contacts, 256).unwrap();

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
        let controller = DiscoveryController::new(contacts, 256).unwrap();

        let candidates = controller.contact_index.get(&rk).unwrap();
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn handle_lost_removes_peer() {
        let mut controller = DiscoveryController::new(vec![], 256).unwrap();
        let coordinator = TransportCoordinator::new(CoordinatorConfig::default());

        let peer_identity = *Identity::generate().public_id();
        controller.peer_index.insert(
            "test-peer".to_string(),
            PeerEntry {
                verified_identity: peer_identity,
                url: "http://192.168.1.50:23003".to_owned(),
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
        let mut controller = DiscoveryController::new(vec![], 256).unwrap();
        let coordinator = TransportCoordinator::new(CoordinatorConfig::default());

        controller.handle_lost("nonexistent", &coordinator);
    }

    #[test]
    fn verified_peer_index_tracks_multi_device() {
        let mut controller = DiscoveryController::new(vec![], 256).unwrap();
        let coordinator = TransportCoordinator::new(CoordinatorConfig::default());
        let peer_identity = *Identity::generate().public_id();

        // Simulate two devices with the same identity.
        controller.handle_new(
            "device-a",
            "http://192.168.1.10:23003",
            peer_identity,
            &coordinator,
        );
        controller.handle_new(
            "device-b",
            "http://192.168.1.11:23003",
            peer_identity,
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
    fn failure_count_starts_at_zero() {
        let mut controller = DiscoveryController::new(vec![], 256).unwrap();
        let coordinator = TransportCoordinator::new(CoordinatorConfig::default());
        let peer_identity = *Identity::generate().public_id();

        controller.handle_new(
            "peer-1",
            "http://192.168.1.10:23003",
            peer_identity,
            &coordinator,
        );
        assert_eq!(controller.peer_index["peer-1"].failure_count, 0);
    }
}
