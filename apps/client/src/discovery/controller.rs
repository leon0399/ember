use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use base64::prelude::*;
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
use reme_discovery::{decode_txt, DiscoveryEvent, RawDiscoveredPeer};
use reme_encryption::build_identity_sign_data;
use reme_identity::PublicID;
use reme_node_core::now_secs_i64;
use reme_storage::Storage;
use reme_transport::coordinator::TransportCoordinator;
use reme_transport::delivery::DeliveryTier;
use reme_transport::http_target::{HttpTarget, HttpTargetConfig};
use reme_transport::registry::TransportRegistry;
use reme_transport::target::TargetId;
use serde::Deserialize;
use tokio::sync::{broadcast, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Max identity response body size (a valid response is ~120 bytes).
const MAX_IDENTITY_RESPONSE_BYTES: u64 = 4096;

/// Result type for a single peer refresh verification.
type RefreshResult = (String, Result<Option<PublicID>, reqwest::Error>);

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
    storage: Arc<Storage>,
}

struct PeerEntry {
    verified_identity: PublicID,
    url: String,
    /// Routing key from TXT records at time of verification.
    routing_key: [u8; 16],
    /// Consecutive verification failures during periodic refresh.
    failure_count: u8,
}

/// Parameters for registering or updating a verified peer.
struct VerifiedPeerInfo<'a> {
    instance_name: &'a str,
    url: &'a str,
    verified: PublicID,
    routing_key: [u8; 16],
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
    /// Shared storage for persisting verification state.
    pub storage: Arc<Storage>,
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
        storage,
        contacts,
        max_peers,
        refresh_interval_secs,
        cancel,
        mut contact_rx,
        peer_count,
    } = config;
    tokio::spawn(async move {
        let mut controller = match DiscoveryController::new(contacts, max_peers, registry, storage)
        {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to initialize discovery controller: {e}");
                return;
            }
        };

        let refresh_secs = clamp_refresh_interval(refresh_interval_secs);
        let mut refresh_timer = tokio::time::interval(std::time::Duration::from_secs(refresh_secs));
        refresh_timer.tick().await; // skip first immediate tick

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
                        other => {
                            controller.handle_event(other, &coordinator);
                        }
                    }
                    peer_count.store(controller.peer_index.len(), Ordering::Relaxed);
                }
                Some((pubkey, routing_key)) = contact_rx.recv() => {
                    controller.add_runtime_contact(pubkey, routing_key, &coordinator).await;
                    peer_count.store(controller.peer_index.len(), Ordering::Relaxed);
                }
                _ = refresh_timer.tick() => {
                    controller.refresh_all_peers(&coordinator).await;
                    peer_count.store(controller.peer_index.len(), Ordering::Relaxed);
                }
            }
        }

        controller.deregister_all(&coordinator);
        peer_count.store(0, Ordering::Relaxed);
        info!("Discovery controller stopped");
    })
}

/// Clamp refresh interval to a minimum of 30 seconds, warning if clamped.
fn clamp_refresh_interval(requested: u64) -> u64 {
    let clamped = requested.max(30);
    if clamped != requested {
        warn!(
            requested,
            actual = clamped,
            "refresh_interval_secs too low, clamping to 30"
        );
    }
    clamped
}

/// Perform identity challenge-response verification against a single peer.
///
/// Takes owned arguments so it can be used in spawned tasks.
// FIXME(SEC-3): channel binding not implemented — responder IP:port not in signed data
async fn verify_identity(
    http_client: reqwest::Client,
    base_url: String,
    candidates: Vec<PublicID>,
) -> Result<Option<PublicID>, reqwest::Error> {
    let challenge: [u8; 32] = rand::random();
    let challenge_b64 = BASE64_STANDARD.encode(challenge);
    let challenge_encoded = percent_encode(challenge_b64.as_bytes(), NON_ALPHANUMERIC);

    let url = format!(
        "{}/api/v1/identity?challenge={}",
        base_url.trim_end_matches('/'),
        challenge_encoded
    );

    let resp = http_client.get(&url).send().await?;
    let Some(signature) = read_identity_signature(resp).await? else {
        return Ok(None);
    };

    Ok(find_matching_candidate(&challenge, &signature, &candidates))
}

/// Read an HTTP response body with size limit.
///
/// Returns `Ok(None)` if the response is non-success or body exceeds `MAX_IDENTITY_RESPONSE_BYTES`.
async fn read_bounded_response(
    mut resp: reqwest::Response,
) -> Result<Option<Vec<u8>>, reqwest::Error> {
    if !resp.status().is_success() {
        debug!("Identity challenge returned non-success: {}", resp.status());
        return Ok(None);
    }

    read_bounded_body(&mut resp).await
}

/// Read response body chunks up to the size limit.
async fn read_bounded_body(
    resp: &mut reqwest::Response,
) -> Result<Option<Vec<u8>>, reqwest::Error> {
    #[allow(clippy::cast_possible_truncation)]
    let max = MAX_IDENTITY_RESPONSE_BYTES as usize;
    let mut buf = Vec::with_capacity(max);
    while let Some(chunk) = resp.chunk().await? {
        if buf.len() + chunk.len() > max {
            debug!("Identity response too large, skipping");
            return Ok(None);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(Some(buf))
}

/// Parse a 64-byte signature from an identity response JSON body.
fn parse_signature_from_body(buf: &[u8]) -> Option<[u8; 64]> {
    let body = serde_json::from_slice::<IdentityResponse>(buf).ok()?;
    let sig_bytes = BASE64_STANDARD.decode(&body.signature).ok()?;
    sig_bytes.try_into().ok()
}

/// Read and validate the identity response, extracting the 64-byte signature.
async fn read_identity_signature(
    resp: reqwest::Response,
) -> Result<Option<[u8; 64]>, reqwest::Error> {
    let Some(buf) = read_bounded_response(resp).await? else {
        return Ok(None);
    };
    Ok(parse_signature_from_body(&buf))
}

/// Find the first candidate whose `XEdDSA` signature matches the challenge.
/// Constant-time iteration: always checks all candidates to avoid
/// timing side-channels that could reveal which public keys are being tested.
fn find_matching_candidate(
    challenge: &[u8; 32],
    signature: &[u8; 64],
    candidates: &[PublicID],
) -> Option<PublicID> {
    let mut matched: Option<PublicID> = None;
    for candidate in candidates {
        let sign_data = build_identity_sign_data(challenge, &candidate.to_bytes());
        if candidate.verify_xeddsa(&sign_data, signature) && matched.is_none() {
            matched = Some(*candidate);
        }
    }
    matched
}

/// Extract routing key from peer TXT records, logging on failure.
fn extract_routing_key(peer: &reme_discovery::RawDiscoveredPeer) -> Option<[u8; 16]> {
    match decode_txt(&peer.txt_records) {
        Ok(fields) => Some(fields.routing_key),
        Err(e) => {
            warn!(
                "Failed to decode TXT records for {}: {e}",
                peer.instance_name
            );
            None
        }
    }
}

fn log_peer_limit_reached(max_peers: usize, instance_name: &str) {
    warn!("Peer limit reached (max={max_peers}), ignoring {instance_name}");
}

fn log_no_addresses(instance_name: &str) {
    warn!("No addresses in discovery event for {instance_name}");
}

fn log_no_match(instance_name: &str, addr: std::net::IpAddr) {
    debug!("No candidate matched for {instance_name} at {addr}");
}

fn log_verify_error(instance_name: &str, addr: std::net::IpAddr, e: &reqwest::Error) {
    debug!("Verification failed for {instance_name} at {addr}: {e}");
}

impl DiscoveryController {
    fn new(
        contacts: Vec<(PublicID, [u8; 16])>,
        max_peers: usize,
        registry: Arc<TransportRegistry>,
        storage: Arc<Storage>,
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
            storage,
        })
    }

    /// Handle non-async broadcast events (`PeerLost`, errors).
    ///
    /// PeerDiscovered/PeerUpdated are handled directly in the spawn loop
    /// because they require async identity verification.
    fn handle_event(
        &mut self,
        event: Result<DiscoveryEvent, broadcast::error::RecvError>,
        coordinator: &TransportCoordinator,
    ) {
        match event {
            Ok(DiscoveryEvent::PeerLost(name)) => {
                self.handle_lost(&name, coordinator);
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!("Discovery controller lagged by {n} events");
            }
            _ => {}
        }
    }

    /// Add a runtime contact and re-process cached strangers that match.
    async fn add_runtime_contact(
        &mut self,
        pubkey: PublicID,
        routing_key: [u8; 16],
        coordinator: &TransportCoordinator,
    ) {
        self.register_contact(pubkey, routing_key);
        self.reprocess_strangers_for_key(&routing_key, coordinator)
            .await;
    }

    /// Register a contact in the index if not already present.
    fn register_contact(&mut self, pubkey: PublicID, routing_key: [u8; 16]) {
        let candidates = self.contact_index.entry(routing_key).or_default();
        if !candidates.contains(&pubkey) {
            candidates.push(pubkey);
        }
        debug!(
            "Added new contact to discovery controller: {}",
            hex::encode(pubkey.to_bytes())
        );
    }

    /// Re-process cached strangers whose routing key matches the given key.
    async fn reprocess_strangers_for_key(
        &mut self,
        routing_key: &[u8; 16],
        coordinator: &TransportCoordinator,
    ) {
        let cached_peers = self.drain_matching_strangers(routing_key);
        for peer in cached_peers {
            debug!(
                "Re-processing cached stranger for new contact: {}",
                peer.instance_name
            );
            self.handle_discovered(peer, coordinator).await;
        }
    }

    /// Deregister all tracked peers (used during shutdown).
    fn deregister_all(&mut self, coordinator: &TransportCoordinator) {
        for (name, entry) in self.peer_index.drain() {
            let target_id = TargetId::http(&entry.url);
            coordinator.remove_http_target(&target_id);
            self.registry.remove_meta(&target_id);
            debug!("Deregistered peer {name} on shutdown");
        }
        self.verified_peer_index.clear();
        self.stranger_cache.clear();
    }

    /// Periodic refresh: re-verify every tracked peer concurrently using
    /// [`JoinSet`]. On failure, increment the failure counter; at
    /// [`FAILURE_THRESHOLD`] consecutive failures, remove the peer entirely
    /// (ephemeral circuit breaker). On success, reset the counter.
    async fn refresh_all_peers(&mut self, coordinator: &TransportCoordinator) {
        let peers: Vec<(String, String, PublicID)> = self
            .peer_index
            .iter()
            .map(|(name, entry)| (name.clone(), entry.url.clone(), entry.verified_identity))
            .collect();

        if peers.is_empty() {
            return;
        }

        debug!("Starting periodic peer refresh ({} peers)", peers.len());

        let mut set = self.spawn_refresh_tasks(peers);
        let to_remove = self.collect_refresh_results(&mut set).await;
        self.remove_stale_peers(to_remove, coordinator);
    }

    /// Spawn concurrent verification tasks for all tracked peers.
    fn spawn_refresh_tasks(
        &self,
        peers: Vec<(String, String, PublicID)>,
    ) -> JoinSet<RefreshResult> {
        let mut set = JoinSet::new();
        for (name, url, identity) in peers {
            let client = self.http_client.clone();
            set.spawn(async move { (name, verify_identity(client, url, vec![identity]).await) });
        }
        set
    }

    /// Remove peers that exceeded the failure threshold.
    fn remove_stale_peers(&mut self, to_remove: Vec<String>, coordinator: &TransportCoordinator) {
        for name in to_remove {
            info!("Removing stale peer {name} after {FAILURE_THRESHOLD} consecutive failures");
            self.remove_peer(&name, coordinator);
        }
    }

    /// Collect results from a concurrent peer refresh, updating failure counters.
    /// Returns names of peers that should be removed.
    async fn collect_refresh_results(&mut self, set: &mut JoinSet<RefreshResult>) -> Vec<String> {
        let mut to_remove = Vec::new();
        while let Some(res) = set.join_next().await {
            match res {
                Ok((name, Ok(Some(verified)))) => {
                    self.record_refresh_success(&name);
                    self.persist_verified_contact(&verified).await;
                }
                Ok((name, Ok(None) | Err(_))) => {
                    if self.record_refresh_failure(&name) {
                        to_remove.push(name);
                    }
                }
                Err(e) => warn!("Peer refresh task panicked: {e}"),
            }
        }
        to_remove
    }

    /// Record a successful refresh for a peer, resetting its failure count.
    fn record_refresh_success(&mut self, name: &str) {
        if let Some(entry) = self.peer_index.get_mut(name) {
            if entry.failure_count > 0 {
                debug!("Peer refresh succeeded for {name}, resetting failure count");
            }
            entry.failure_count = 0;
        }
    }

    /// Record a refresh failure. Returns `true` if the peer should be removed.
    fn record_refresh_failure(&mut self, name: &str) -> bool {
        let Some(entry) = self.peer_index.get_mut(name) else {
            return false;
        };
        entry.failure_count += 1;
        debug!(
            "Peer refresh verification failed for {name} (failures: {})",
            entry.failure_count
        );
        entry.failure_count >= FAILURE_THRESHOLD
    }

    /// Handle a discovered or updated peer from mDNS events.
    async fn handle_discovered(
        &mut self,
        peer: reme_discovery::RawDiscoveredPeer,
        coordinator: &TransportCoordinator,
    ) {
        let Some(routing_key) = extract_routing_key(&peer) else {
            return;
        };

        let Some(candidates) = self.contact_index.get(&routing_key) else {
            self.cache_stranger(peer, routing_key);
            return;
        };

        if !self.should_process_peer(&peer, routing_key, candidates) {
            return;
        }

        if let Some((verified, url)) = self.verify_any_address(&peer, candidates).await {
            self.register_verified_peer(
                &VerifiedPeerInfo {
                    instance_name: &peer.instance_name,
                    url: &url,
                    verified,
                    routing_key,
                },
                coordinator,
            );
            self.persist_verified_contact(&verified).await;
        }
    }

    async fn persist_verified_contact(&self, public_id: &PublicID) {
        let public_id = *public_id;

        if let Err(error) = self.persist_verified_contact_impl(public_id).await {
            warn!("Verified peer {public_id} but failed to persist trust state: {error}");
        }
    }

    async fn persist_verified_contact_impl(&self, public_id: PublicID) -> Result<(), String> {
        let storage = Arc::clone(&self.storage);

        tokio::task::spawn_blocking(move || storage.mark_contact_verified(&public_id, now_secs_i64()))
            .await
            .map_err(|error| format!("persistence task failed: {error}"))?
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Register or update a verified peer in indices and coordinator.
    fn register_verified_peer(
        &mut self,
        info: &VerifiedPeerInfo<'_>,
        coordinator: &TransportCoordinator,
    ) {
        if self.peer_index.contains_key(info.instance_name) {
            self.handle_update_impl(info, coordinator);
        } else {
            self.handle_new_impl(info, coordinator);
        }
    }

    /// Cache a peer whose routing key doesn't match any known contact.
    fn cache_stranger(&mut self, peer: reme_discovery::RawDiscoveredPeer, routing_key: [u8; 16]) {
        let is_known = self.stranger_cache.contains_key(&peer.instance_name);

        if !is_known && !self.has_stranger_capacity() {
            debug!(
                "Stranger cache full (max={}), dropping {}",
                self.max_peers, peer.instance_name
            );
            return;
        }

        self.insert_stranger(peer, routing_key, is_known);
    }

    /// Whether the stranger cache has room for a new entry.
    fn has_stranger_capacity(&self) -> bool {
        self.stranger_cache.len() < self.max_peers
    }

    /// Insert a peer into the stranger cache.
    fn insert_stranger(
        &mut self,
        peer: reme_discovery::RawDiscoveredPeer,
        routing_key: [u8; 16],
        is_update: bool,
    ) {
        debug!(
            "Caching stranger {} (update={})",
            peer.instance_name, is_update
        );
        self.stranger_cache
            .insert(peer.instance_name.clone(), (peer, routing_key));
    }

    /// Check whether a discovered peer should proceed to identity verification.
    ///
    /// Returns `false` if the peer should be skipped (limit reached, no addresses,
    /// or is an update with unchanged address+routing key).
    fn should_process_peer(
        &self,
        peer: &reme_discovery::RawDiscoveredPeer,
        routing_key: [u8; 16],
        _candidates: &[PublicID],
    ) -> bool {
        let is_update = self.peer_index.contains_key(&peer.instance_name);

        if !is_update && self.is_at_peer_limit() {
            log_peer_limit_reached(self.max_peers, &peer.instance_name);
            return false;
        }

        if peer.addresses.is_empty() {
            log_no_addresses(&peer.instance_name);
            return false;
        }

        !is_update || self.needs_reverification(peer, routing_key)
    }

    /// Whether the peer index is at capacity.
    fn is_at_peer_limit(&self) -> bool {
        self.peer_index.len() >= self.max_peers
    }

    /// Check if an already-tracked peer needs re-verification (address or TXT changed).
    fn needs_reverification(
        &self,
        peer: &reme_discovery::RawDiscoveredPeer,
        routing_key: [u8; 16],
    ) -> bool {
        let Some(entry) = self.peer_index.get(&peer.instance_name) else {
            return false;
        };
        let stored_url_still_valid = peer.addresses.iter().any(|&addr| {
            let candidate = format!("http://{}", SocketAddr::new(addr, peer.port));
            entry.url == candidate
        });
        if stored_url_still_valid && entry.routing_key == routing_key {
            debug!(
                "Update unchanged for {}, skipping re-verification",
                peer.instance_name
            );
            return false;
        }
        true
    }

    /// Try each address in the peer until identity verification succeeds.
    async fn verify_any_address(
        &self,
        peer: &reme_discovery::RawDiscoveredPeer,
        candidates: &[PublicID],
    ) -> Option<(PublicID, String)> {
        for &addr in &peer.addresses {
            let url = format!("http://{}", SocketAddr::new(addr, peer.port));
            match self.verify_peer_identity(&url, candidates).await {
                Ok(Some(pubkey)) => return Some((pubkey, url)),
                Ok(None) => log_no_match(&peer.instance_name, addr),
                Err(e) => log_verify_error(&peer.instance_name, addr, &e),
            }
        }
        None
    }

    fn build_http_target(instance_name: &str, url: &str, verified: PublicID) -> Option<HttpTarget> {
        let config = HttpTargetConfig::ephemeral(url)
            .with_node_pubkey(verified)
            .with_label(format!("lan:{instance_name}"));

        match HttpTarget::new(config) {
            Ok(t) => Some(t),
            Err(e) => {
                warn!("Failed to create HTTP target for {instance_name}: {e}");
                None
            }
        }
    }

    fn handle_new_impl(&mut self, info: &VerifiedPeerInfo<'_>, coordinator: &TransportCoordinator) {
        let Some(target) = Self::build_http_target(info.instance_name, info.url, info.verified)
        else {
            return;
        };

        let target_id = TargetId::http(info.url);

        // TODO(#90): receipt-gated direct tier — currently a relay attacker who
        // passes identity verification can blackhole messages. Once #90 lands,
        // Direct tier will require a verified receipt before declaring success.
        coordinator.add_http_target(target);

        self.registry.register_ephemeral(
            target_id,
            Some(format!("lan:{}", info.instance_name)),
            DeliveryTier::Direct,
        );

        info!(
            "Registered discovered peer {} at {}",
            info.instance_name, info.url
        );

        self.peer_index.insert(
            info.instance_name.to_owned(),
            PeerEntry {
                verified_identity: info.verified,
                url: info.url.to_owned(),
                routing_key: info.routing_key,
                failure_count: 0,
            },
        );

        self.verified_peer_index
            .entry(info.verified)
            .or_default()
            .push(info.instance_name.to_owned());
    }

    fn handle_update_impl(
        &mut self,
        info: &VerifiedPeerInfo<'_>,
        coordinator: &TransportCoordinator,
    ) {
        let Some(entry) = self.peer_index.get(info.instance_name) else {
            warn!(
                "handle_update for unknown peer {}, skipping",
                info.instance_name
            );
            return;
        };
        let address_changed = entry.url != info.url;
        let identity_changed = entry.verified_identity != info.verified;

        if !address_changed && !identity_changed {
            return;
        }

        let old_target_id = TargetId::http(&entry.url);
        let old_identity = entry.verified_identity;

        let Some(target) = Self::build_http_target(info.instance_name, info.url, info.verified)
        else {
            return;
        };

        coordinator.replace_http_target(&old_target_id, target);
        self.apply_update_registry(info, &old_target_id, address_changed);
        self.update_verified_index_on_identity_change(
            info.instance_name,
            old_identity,
            info.verified,
            identity_changed,
        );
        self.finalize_peer_entry(info);
    }

    /// Update registry metadata and log address/identity changes.
    fn apply_update_registry(
        &self,
        info: &VerifiedPeerInfo<'_>,
        old_target_id: &TargetId,
        address_changed: bool,
    ) {
        if address_changed {
            self.replace_registry_entry(info, old_target_id);
        } else {
            info!("Updated peer {} identity", info.instance_name);
        }
    }

    /// Replace registry entry when a peer's address changes.
    fn replace_registry_entry(&self, info: &VerifiedPeerInfo<'_>, old_target_id: &TargetId) {
        self.registry.remove_meta(old_target_id);
        self.registry.register_ephemeral(
            TargetId::http(info.url),
            Some(format!("lan:{}", info.instance_name)),
            DeliveryTier::Direct,
        );
        info!(
            "Updated peer {} address to {}",
            info.instance_name, info.url
        );
    }

    /// Write verified peer data into the `peer_index` entry.
    fn finalize_peer_entry(&mut self, info: &VerifiedPeerInfo<'_>) {
        let Some(entry) = self.peer_index.get_mut(info.instance_name) else {
            warn!("Peer entry vanished before update: {}", info.instance_name);
            return;
        };
        entry.verified_identity = info.verified;
        info.url.clone_into(&mut entry.url);
        entry.routing_key = info.routing_key;
        entry.failure_count = 0;
    }

    /// Update the verified peer index when a peer's identity changes.
    fn update_verified_index_on_identity_change(
        &mut self,
        instance_name: &str,
        old_identity: PublicID,
        new_identity: PublicID,
        changed: bool,
    ) {
        if !changed {
            return;
        }
        if let Some(instances) = self.verified_peer_index.get_mut(&old_identity) {
            instances.retain(|n| n != instance_name);
            if instances.is_empty() {
                self.verified_peer_index.remove(&old_identity);
            }
        }
        self.verified_peer_index
            .entry(new_identity)
            .or_default()
            .push(instance_name.to_owned());
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

            info!("Removed peer {instance_name}");
        }
    }

    /// Remove and return all cached strangers whose routing key matches `target_rk`.
    fn drain_matching_strangers(&mut self, target_rk: &[u8; 16]) -> Vec<RawDiscoveredPeer> {
        let mut matched = Vec::new();
        self.stranger_cache.retain(|_, (peer, rk)| {
            if rk == target_rk {
                matched.push(peer.clone());
                false
            } else {
                true
            }
        });
        matched
    }

    async fn verify_peer_identity(
        &self,
        base_url: &str,
        candidates: &[PublicID],
    ) -> Result<Option<PublicID>, reqwest::Error> {
        verify_identity(
            self.http_client.clone(),
            base_url.to_owned(),
            candidates.to_vec(),
        )
        .await
    }
}

/// Test-only wrappers that accept the old 5-arg signature for backward compat.
#[cfg(test)]
impl DiscoveryController {
    #[allow(clippy::too_many_arguments)]
    fn handle_new(
        &mut self,
        instance_name: &str,
        url: &str,
        verified: PublicID,
        routing_key: [u8; 16],
        coordinator: &TransportCoordinator,
    ) {
        let info = VerifiedPeerInfo {
            instance_name,
            url,
            verified,
            routing_key,
        };
        self.handle_new_impl(&info, coordinator);
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_update(
        &mut self,
        instance_name: &str,
        url: &str,
        verified: PublicID,
        routing_key: [u8; 16],
        coordinator: &TransportCoordinator,
    ) {
        let info = VerifiedPeerInfo {
            instance_name,
            url,
            verified,
            routing_key,
        };
        self.handle_update_impl(&info, coordinator);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reme_identity::Identity;
    use reme_storage::TrustLevel;
    use reme_transport::coordinator::CoordinatorConfig;
    use std::net::IpAddr;
    use std::time::Instant;

    fn test_registry() -> Arc<TransportRegistry> {
        Arc::new(TransportRegistry::new())
    }

    fn test_storage() -> Arc<Storage> {
        Arc::new(Storage::in_memory().unwrap())
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
        let contacts = vec![(pubkey, *rk.as_bytes())];
        let controller =
            DiscoveryController::new(contacts, 256, test_registry(), test_storage()).unwrap();

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
        let controller =
            DiscoveryController::new(contacts, 256, test_registry(), test_storage()).unwrap();

        let candidates = controller.contact_index.get(&rk).unwrap();
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn handle_lost_removes_peer() {
        let mut controller =
            DiscoveryController::new(vec![], 256, test_registry(), test_storage()).unwrap();
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
        let mut controller =
            DiscoveryController::new(vec![], 256, test_registry(), test_storage()).unwrap();
        let coordinator = TransportCoordinator::new(CoordinatorConfig::default());

        controller.handle_lost("nonexistent", &coordinator);
    }

    #[tokio::test]
    async fn verification_persists_verified_contact_state() {
        let storage = test_storage();
        let identity = Identity::generate();
        let pubkey = *identity.public_id();

        storage
            .create_contact(identity.public_id(), None, TrustLevel::Known)
            .unwrap();

        let controller = DiscoveryController::new(
            vec![(pubkey, *pubkey.routing_key().as_bytes())],
            256,
            test_registry(),
            Arc::clone(&storage),
        )
        .unwrap();

        controller.persist_verified_contact(&pubkey).await;

        let contact = storage.get_contact(&pubkey).unwrap();
        assert_eq!(contact.trust_level, TrustLevel::Verified);
        assert!(contact.verified_at.is_some());
    }

    #[test]
    fn verified_peer_index_tracks_multi_device() {
        let mut controller =
            DiscoveryController::new(vec![], 256, test_registry(), test_storage()).unwrap();
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
        let mut controller =
            DiscoveryController::new(vec![], 256, test_registry(), test_storage()).unwrap();
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
        let mut controller =
            DiscoveryController::new(vec![], 256, test_registry(), test_storage()).unwrap();
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
        let mut controller =
            DiscoveryController::new(vec![], 256, test_registry(), test_storage()).unwrap();
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
        let mut controller =
            DiscoveryController::new(vec![], 256, test_registry(), test_storage()).unwrap();

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
        let mut controller =
            DiscoveryController::new(vec![], 256, test_registry(), test_storage()).unwrap();

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
        let mut controller =
            DiscoveryController::new(vec![], 2, test_registry(), test_storage()).unwrap();
        let coordinator = TransportCoordinator::new(CoordinatorConfig::default());

        for i in 0..3u8 {
            let mut rk = [0u8; 16];
            rk[0] = i;
            let peer = make_stranger_peer(&format!("stranger-{i}"), &rk);
            controller.handle_discovered(peer, &coordinator).await;
        }

        assert_eq!(controller.stranger_cache.len(), 2);
    }

    #[tokio::test]
    async fn stranger_cache_allows_updates_when_full() {
        let mut controller =
            DiscoveryController::new(vec![], 2, test_registry(), test_storage()).unwrap();
        let coordinator = TransportCoordinator::new(CoordinatorConfig::default());

        // Fill cache to capacity.
        let rk_a = [0xAAu8; 16];
        let rk_b = [0xBBu8; 16];
        let peer_a = make_stranger_peer("stranger-a", &rk_a);
        let peer_b = make_stranger_peer("stranger-b", &rk_b);
        controller.handle_discovered(peer_a, &coordinator).await;
        controller.handle_discovered(peer_b, &coordinator).await;
        assert_eq!(controller.stranger_cache.len(), 2);

        // Update existing entry with new address — should succeed despite full cache.
        let updated = RawDiscoveredPeer {
            instance_name: "stranger-a".to_string(),
            addresses: vec!["192.168.1.99".parse().unwrap()],
            port: 9999,
            txt_records: reme_discovery::encode_txt(&rk_a, 9999),
            discovered_at: Instant::now(),
        };
        controller.handle_discovered(updated, &coordinator).await;
        assert_eq!(controller.stranger_cache.len(), 2);

        // Verify the cached entry was updated (new port in TXT).
        let (cached_peer, _) = &controller.stranger_cache["stranger-a"];
        assert_eq!(cached_peer.port, 9999);
    }

    #[test]
    fn failure_count_starts_at_zero() {
        let mut controller =
            DiscoveryController::new(vec![], 256, test_registry(), test_storage()).unwrap();
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
