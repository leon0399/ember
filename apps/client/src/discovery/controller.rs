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

/// Tracks discovered LAN peers, verifies their identity, and registers them
/// as ephemeral HTTP targets in the [`TransportCoordinator`].
pub struct DiscoveryController {
    /// Maps `instance_name` to tracked peer state.
    peer_index: HashMap<String, PeerEntry>,
    /// Maps `routing_key` to candidate public keys for quick contact lookup.
    contact_index: HashMap<[u8; 16], Vec<PublicID>>,
    max_peers: usize,
    http_client: reqwest::Client,
}

struct PeerEntry {
    target_id: TargetId,
    verified_identity: PublicID,
    url: String,
}

#[derive(Deserialize)]
struct IdentityResponse {
    signature: String,
}

/// Spawn the discovery controller event loop.
///
/// Listens for [`DiscoveryEvent`]s and, for peers whose routing key matches
/// a known contact, verifies identity and registers them as ephemeral targets.
pub fn spawn(
    mut events: broadcast::Receiver<DiscoveryEvent>,
    coordinator: Arc<TransportCoordinator>,
    contacts: Vec<(PublicID, [u8; 16])>,
    max_peers: usize,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut controller = DiscoveryController::new(contacts, max_peers);

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
            }
        }

        // Deregister all tracked peers on shutdown.
        for (name, entry) in &controller.peer_index {
            coordinator.remove_http_target(&entry.target_id);
            debug!(instance = %name, "Deregistered peer on shutdown");
        }
        controller.peer_index.clear();

        info!("Discovery controller stopped");
    })
}

impl DiscoveryController {
    fn new(contacts: Vec<(PublicID, [u8; 16])>, max_peers: usize) -> Self {
        let max_peers = max_peers.max(1); // Clamp to at least 1
        let mut contact_index: HashMap<[u8; 16], Vec<PublicID>> = HashMap::new();
        for (pubkey, routing_key) in contacts {
            contact_index.entry(routing_key).or_default().push(pubkey);
        }

        Self {
            peer_index: HashMap::new(),
            contact_index,
            max_peers,
            http_client: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(2))
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("failed to build reqwest client"),
        }
    }

    async fn handle_discovered(
        &mut self,
        peer: reme_discovery::RawDiscoveredPeer,
        coordinator: &TransportCoordinator,
    ) {
        let (routing_key, _txt_port, _version) = match decode_txt(&peer.txt_records) {
            Ok(decoded) => decoded,
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

        let target_id = TargetId::http(url);
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
                target_id,
                verified_identity: verified,
                url: url.to_owned(),
            },
        );
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
        let old_target_id = entry.target_id.clone();

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

        self.peer_index.insert(
            instance_name.to_owned(),
            PeerEntry {
                target_id: TargetId::http(url),
                verified_identity: verified,
                url: url.to_owned(),
            },
        );
    }

    fn handle_lost(&mut self, instance_name: &str, coordinator: &TransportCoordinator) {
        if let Some(entry) = self.peer_index.remove(instance_name) {
            coordinator.remove_http_target(&entry.target_id);
            info!(instance = %instance_name, "Removed lost peer");
        }
    }

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
            return Ok(None);
        };
        let Ok(signature): Result<[u8; 64], _> = sig_bytes.try_into() else {
            return Ok(None);
        };

        for candidate in candidates {
            let sign_data = build_identity_sign_data(&challenge, &candidate.to_bytes());
            if candidate.verify_xeddsa(&sign_data, &signature) {
                return Ok(Some(*candidate));
            }
        }

        Ok(None)
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
        let controller = DiscoveryController::new(contacts, 256);

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
        let controller = DiscoveryController::new(contacts, 256);

        let candidates = controller.contact_index.get(&rk).unwrap();
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn handle_lost_removes_peer() {
        let mut controller = DiscoveryController::new(vec![], 256);
        let coordinator = TransportCoordinator::new(CoordinatorConfig::default());

        let peer_identity = *Identity::generate().public_id();
        controller.peer_index.insert(
            "test-peer".to_string(),
            PeerEntry {
                target_id: TargetId::http("http://192.168.1.50:23003"),
                verified_identity: peer_identity,
                url: "http://192.168.1.50:23003".to_owned(),
            },
        );

        assert!(controller.peer_index.contains_key("test-peer"));
        controller.handle_lost("test-peer", &coordinator);
        assert!(!controller.peer_index.contains_key("test-peer"));
    }

    #[test]
    fn handle_lost_noop_for_unknown_peer() {
        let mut controller = DiscoveryController::new(vec![], 256);
        let coordinator = TransportCoordinator::new(CoordinatorConfig::default());

        controller.handle_lost("nonexistent", &coordinator);
    }
}
