use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
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

const MAX_PEERS: usize = 256;

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
    verified_identity: Option<PublicID>,
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
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut controller = DiscoveryController::new(contacts);

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

        info!("Discovery controller stopped");
    })
}

impl DiscoveryController {
    fn new(contacts: Vec<(PublicID, [u8; 16])>) -> Self {
        let mut contact_index: HashMap<[u8; 16], Vec<PublicID>> = HashMap::new();
        for (pubkey, routing_key) in contacts {
            contact_index.entry(routing_key).or_default().push(pubkey);
        }

        Self {
            peer_index: HashMap::new(),
            contact_index,
            max_peers: MAX_PEERS,
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
                "Peer limit reached ({MAX_PEERS}), ignoring new peer"
            );
            return;
        }

        let Some(&addr) = peer.addresses.first() else {
            warn!(
                instance = %peer.instance_name,
                "No addresses in discovery event"
            );
            return;
        };

        let url = format!("http://{}", SocketAddr::new(addr, peer.port));

        let verified = match self.verify_peer_identity(&url, candidates).await {
            Ok(Some(pubkey)) => Some(pubkey),
            Ok(None) => {
                debug!(
                    instance = %peer.instance_name,
                    "Identity verification: no candidate matched"
                );
                return;
            }
            Err(e) => {
                debug!(
                    instance = %peer.instance_name,
                    "Identity verification failed: {e}"
                );
                return;
            }
        };

        if is_update {
            self.handle_update(&peer.instance_name, &url, verified, coordinator);
        } else {
            self.handle_new(&peer.instance_name, &url, verified, coordinator);
        }
    }

    fn build_http_target(
        instance_name: &str,
        url: &str,
        verified: Option<PublicID>,
    ) -> Option<HttpTarget> {
        let config = HttpTargetConfig::ephemeral(url)
            .with_node_pubkey_opt(verified)
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
        verified: Option<PublicID>,
        coordinator: &TransportCoordinator,
    ) {
        let Some(target) = Self::build_http_target(instance_name, url, verified) else {
            return;
        };

        let target_id = TargetId::http(url);
        coordinator.add_http_target(target);

        info!(
            instance = %instance_name,
            url = %url,
            verified = verified.is_some(),
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
        verified: Option<PublicID>,
        coordinator: &TransportCoordinator,
    ) {
        let entry = self
            .peer_index
            .get(instance_name)
            .expect("invariant: is_update implies entry exists");
        let address_changed = entry.url != url;
        let old_target_id = entry.target_id.clone();

        if address_changed {
            let Some(target) = Self::build_http_target(instance_name, url, verified) else {
                return;
            };

            coordinator.replace_http_target(&old_target_id, target);

            info!(
                instance = %instance_name,
                old_url = %entry.url,
                new_url = %url,
                "Updated discovered peer address"
            );
        }

        let target_id = if address_changed {
            TargetId::http(url)
        } else {
            old_target_id
        };

        self.peer_index.insert(
            instance_name.to_owned(),
            PeerEntry {
                target_id,
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

        let resp = self.http_client.get(&url).send().await?;

        if !resp.status().is_success() {
            debug!(status = %resp.status(), "Identity challenge returned non-success");
            return Ok(None);
        }

        let body: IdentityResponse = resp.json().await?;

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
        let controller = DiscoveryController::new(contacts);

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
        let controller = DiscoveryController::new(contacts);

        let candidates = controller.contact_index.get(&rk).unwrap();
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn handle_lost_removes_peer() {
        let mut controller = DiscoveryController::new(vec![]);
        let coordinator = TransportCoordinator::new(CoordinatorConfig::default());

        controller.peer_index.insert(
            "test-peer".to_string(),
            PeerEntry {
                target_id: TargetId::http("http://192.168.1.50:23003"),
                verified_identity: None,
                url: "http://192.168.1.50:23003".to_owned(),
            },
        );

        assert!(controller.peer_index.contains_key("test-peer"));
        controller.handle_lost("test-peer", &coordinator);
        assert!(!controller.peer_index.contains_key("test-peer"));
    }

    #[test]
    fn handle_lost_noop_for_unknown_peer() {
        let mut controller = DiscoveryController::new(vec![]);
        let coordinator = TransportCoordinator::new(CoordinatorConfig::default());

        controller.handle_lost("nonexistent", &coordinator);
    }
}
