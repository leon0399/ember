//! Non-interactive CLI send command.
//!
//! Encrypts and enqueues a message for delivery, optionally attempting
//! delivery immediately using the configured transports.

use crate::config::{AppConfig, SendArgs};
use crate::identity;
use ember_config::{ParsedHttpPeer, ParsedMqttPeer};
use ember_core::{Client, ClientError};
use ember_identity::{Identity, PublicID};
use ember_message::{Content, TextContent};
use ember_outbox::{OutboxConfig, TransportRetryPolicy};
use ember_storage::Storage;
use ember_transport::{
    http_target::{HttpTarget, HttpTargetConfig},
    mqtt_target::{MqttTarget, MqttTargetConfig},
    target::TargetKind,
    CoordinatorConfig, TransportCoordinator, TransportPool,
};
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

type HttpPool = Arc<TransportPool<HttpTarget>>;

/// Run the `send` subcommand.
pub async fn run_send(
    config: &AppConfig,
    args: &SendArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    // Require an existing identity (non-interactive).
    let identity_path = config.data_dir.join("identity.ember");
    if !identity_path.exists() {
        return Err("No identity found. Run `ember` first to create one.".into());
    }
    let identity = identity::load_existing(&identity_path)?;

    // Parse recipient
    let recipient = parse_public_id(&args.to)?;

    // Ensure data directory + storage
    fs::create_dir_all(&config.data_dir)?;
    let db_path = config.data_dir.join("messages.db");
    let db_path_str = db_path.to_str().ok_or("Invalid database path (non-UTF8)")?;
    let storage = Arc::new(Storage::open(db_path_str)?);

    // Build outbox configuration from app config
    let outbox_config = build_outbox_config(config);

    if args.no_deliver {
        // Offline path: enqueue only, no transport attempts.
        enqueue_without_delivery(&recipient, identity, storage, outbox_config, &args.text)?;
        println!("Enqueued message for {}", args.to);
        return Ok(());
    }

    let coordinator = build_coordinator(config).await?;
    if !coordinator.has_transports() {
        return Err("No transports configured. Add HTTP nodes and/or MQTT brokers.".into());
    }

    // Create client with transport coordinator
    let mut client = Client::with_config(
        identity,
        coordinator.clone(),
        Arc::clone(&storage),
        outbox_config,
    );
    client.set_tiered_config(config.delivery.clone().into());

    // Configure retry policy (HTTP + MQTT share the same defaults today)
    let retry_policy = TransportRetryPolicy {
        initial_delay: Duration::from_secs(config.outbox.retry_initial_delay_secs),
        max_delay: Duration::from_secs(config.outbox.retry_max_delay_secs),
        ..TransportRetryPolicy::default()
    };
    client.set_transport_policy("http:", retry_policy.clone());
    client.set_transport_policy("mqtt:", retry_policy);

    // Ensure contact exists (idempotent)
    let _ = client.add_contact(&recipient, None)?;

    let (message_id, phase) = client.send_text_tiered(&recipient, &args.text).await?;
    println!(
        "Sent message {} ({})",
        hex::encode(message_id.as_bytes()),
        format_delivery_phase(&phase)
    );
    Ok(())
}

/// Enqueue a message without attempting delivery (offline/sneakernet).
fn enqueue_without_delivery(
    recipient: &PublicID,
    identity: Identity,
    storage: Arc<Storage>,
    outbox_config: OutboxConfig,
    text: &str,
) -> Result<(), ClientError> {
    let client = Client::with_config(
        identity,
        Arc::new(TransportCoordinator::with_defaults()),
        storage,
        outbox_config,
    );
    let _ = client.add_contact(recipient, None)?;
    let content = Content::Text(TextContent {
        body: text.to_string(),
    });
    let _ = client.prepare_message(recipient, content, false)?;
    Ok(())
}

/// Build outbox configuration from app config.
fn build_outbox_config(config: &AppConfig) -> OutboxConfig {
    let ttl_ms = if config.outbox.ttl_days == 0 {
        None
    } else {
        Some(config.outbox.ttl_days * 24 * 60 * 60 * 1000)
    };

    OutboxConfig {
        default_ttl_ms: ttl_ms,
        attempt_timeout_ms: config.outbox.attempt_timeout_secs * 1000,
        ..OutboxConfig::default()
    }
}

/// Build the transport coordinator from configured peers.
async fn build_coordinator(
    config: &AppConfig,
) -> Result<Arc<TransportCoordinator>, Box<dyn std::error::Error>> {
    let parsed_http_peers: Vec<ParsedHttpPeer> = config
        .peers
        .http
        .iter()
        .map(|peer| ParsedHttpPeer::try_from(peer.clone()))
        .collect::<Result<_, _>>()?;
    let parsed_mqtt_peers: Vec<ParsedMqttPeer> = config
        .peers
        .mqtt
        .iter()
        .map(|peer| ParsedMqttPeer::try_from(peer.clone()))
        .collect::<Result<_, _>>()?;

    let mut coordinator = TransportCoordinator::new(CoordinatorConfig {
        poll_interval: Duration::from_secs(2),
        ..CoordinatorConfig::default()
    });

    if let Some(http) = build_http_pool(&parsed_http_peers)? {
        coordinator.set_http_pool_arc(http);
    } else {
        coordinator.set_http_pool(TransportPool::new());
    }

    let mqtt_pool = build_mqtt_pool(&parsed_mqtt_peers).await;
    coordinator.set_mqtt_pool_arc(mqtt_pool);

    add_direct_peers(&config.direct_peers, &coordinator);

    Ok(Arc::new(coordinator))
}

/// Build the HTTP transport pool from parsed peer configurations.
fn build_http_pool(
    parsed_peers: &[ParsedHttpPeer],
) -> Result<Option<HttpPool>, Box<dyn std::error::Error>> {
    if parsed_peers.is_empty() {
        return Ok(None);
    }

    let pool = TransportPool::new();
    for peer in parsed_peers {
        let target = build_http_target_from_config(peer)?;
        pool.add_target(target);
    }
    Ok(Some(Arc::new(pool)))
}

/// Build a single HTTP target from a parsed peer configuration.
fn build_http_target_from_config(
    peer: &ParsedHttpPeer,
) -> Result<HttpTarget, Box<dyn std::error::Error>> {
    let mut config = HttpTargetConfig::stable(&peer.url);

    if let Some(ref pin) = peer.cert_pin {
        match ember_transport::CertPin::parse(&pin.to_pin_string()) {
            Ok(transport_pin) => config = config.with_cert_pin(transport_pin),
            Err(e) => {
                warn!(url = %peer.url, error = %e, "Certificate pin conversion failed - this is a bug");
            }
        }
    }

    if let Some(ref label) = peer.common.label {
        config = config.with_label(label.clone());
    }

    config = config.with_priority(clamp_priority(peer.common.priority, &peer.url));
    config = config.with_node_pubkey_opt(peer.node_pubkey);

    if let Some((username, password)) = &peer.auth {
        config = config.with_auth(username, password);
    }

    Ok(HttpTarget::new(config)?)
}

/// Clamp a u16 priority to u8 range, warning on truncation.
fn clamp_priority(priority: u16, url: &str) -> u8 {
    if priority > 255 {
        warn!(url = %url, configured = priority, "Priority exceeds 255, clamping");
        255
    } else {
        #[allow(clippy::cast_possible_truncation)]
        {
            priority as u8
        }
    }
}

/// Add direct peers as ephemeral HTTP targets.
fn add_direct_peers(peers: &[crate::config::DirectPeerConfig], coordinator: &TransportCoordinator) {
    for peer in peers {
        if let Some(target) = build_direct_peer_target(peer) {
            log_direct_peer_added(&peer.address, peer.name.as_deref());
            coordinator.add_http_target(target);
        }
    }
}

/// Build an [`HttpTarget`] from a [`DirectPeerConfig`], parsing and wiring
/// the optional `public_id` into `node_pubkey`.
fn build_direct_peer_target(peer: &crate::config::DirectPeerConfig) -> Option<HttpTarget> {
    let Ok(node_pubkey) = parse_direct_peer_pubkey(peer) else {
        return None;
    };

    let target_config = HttpTargetConfig::new(&peer.address, TargetKind::Ephemeral)
        .with_label(peer.name.as_deref().unwrap_or(&peer.address))
        .with_node_pubkey_opt(node_pubkey);

    match HttpTarget::new(target_config) {
        Ok(t) => Some(t),
        Err(e) => {
            warn!("Failed to add direct peer {}: {e}", peer.address);
            None
        }
    }
}

/// Parse the optional `public_id` field from a [`DirectPeerConfig`] into a [`PublicID`].
fn parse_direct_peer_pubkey(
    peer: &crate::config::DirectPeerConfig,
) -> Result<Option<PublicID>, ()> {
    let Some(id_str) = peer.public_id.as_deref() else {
        return Ok(None);
    };

    match ember_config::parse_node_pubkey(id_str) {
        Ok(pk) => Ok(Some(pk)),
        Err(e) => {
            warn!(
                "Skipping direct peer {}: invalid public_id: {e}",
                peer.address
            );
            Err(())
        }
    }
}

/// Log successful direct peer addition.
fn log_direct_peer_added(address: &str, name: Option<&str>) {
    info!(
        "Added direct peer: {} ({})",
        address,
        name.unwrap_or("unnamed")
    );
}

/// Build the MQTT transport pool, connecting configured brokers in parallel.
async fn build_mqtt_pool(parsed_peers: &[ParsedMqttPeer]) -> Arc<TransportPool<MqttTarget>> {
    let pool = TransportPool::new();
    connect_mqtt_peers(&pool, parsed_peers).await;
    Arc::new(pool)
}

/// Spawn parallel MQTT connection tasks and collect results into the pool.
async fn connect_mqtt_peers(pool: &TransportPool<MqttTarget>, parsed_peers: &[ParsedMqttPeer]) {
    if parsed_peers.is_empty() {
        return;
    }

    let mut join_set = spawn_mqtt_connections(parsed_peers);
    collect_mqtt_results(pool, &mut join_set).await;
}

/// Spawn MQTT connection tasks for all configured peers.
fn spawn_mqtt_connections(
    parsed_peers: &[ParsedMqttPeer],
) -> tokio::task::JoinSet<(String, Result<MqttTarget, ember_transport::TransportError>)> {
    let mut join_set = tokio::task::JoinSet::new();
    for parsed_peer in parsed_peers.iter().cloned() {
        join_set.spawn(async move {
            let config = build_mqtt_target_config(&parsed_peer);
            (parsed_peer.url.clone(), MqttTarget::connect(config).await)
        });
    }
    join_set
}

/// Collect MQTT connection results into the pool.
async fn collect_mqtt_results(
    pool: &TransportPool<MqttTarget>,
    join_set: &mut tokio::task::JoinSet<(
        String,
        Result<MqttTarget, ember_transport::TransportError>,
    )>,
) {
    while let Some(result) = join_set.join_next().await {
        handle_mqtt_join_result(pool, result);
    }
}

/// Handle a single MQTT connection join result.
fn handle_mqtt_join_result(
    pool: &TransportPool<MqttTarget>,
    result: Result<
        (String, Result<MqttTarget, ember_transport::TransportError>),
        tokio::task::JoinError,
    >,
) {
    let Ok((url, connect_result)) = result else {
        warn!("MQTT connection task panicked");
        return;
    };
    log_mqtt_connect_result(pool, &url, connect_result);
}

/// Log and apply the result of an MQTT connection attempt.
fn log_mqtt_connect_result(
    pool: &TransportPool<MqttTarget>,
    url: &str,
    result: Result<MqttTarget, ember_transport::TransportError>,
) {
    match result {
        Ok(target) => pool.add_target(target),
        Err(e) => warn!(broker = %url, error = %e, "Failed to connect to MQTT broker"),
    }
}

/// Build MQTT target config from parsed peer configuration.
fn build_mqtt_target_config(peer: &ParsedMqttPeer) -> MqttTargetConfig {
    let config = MqttTargetConfig::new(&peer.url)
        .with_priority(clamp_priority(peer.common.priority, &peer.url));
    apply_mqtt_optional_fields(config, peer)
}

/// Apply optional fields to an MQTT target config.
fn apply_mqtt_optional_fields(
    mut config: MqttTargetConfig,
    peer: &ParsedMqttPeer,
) -> MqttTargetConfig {
    if let Some(ref client_id) = peer.client_id {
        config = config.with_client_id(client_id);
    }
    if let Some(ref auth) = peer.auth {
        config = config.with_auth(&auth.0, &auth.1);
    }
    if let Some(ref label) = peer.common.label {
        config = config.with_label(label);
    }
    if let Some(ref prefix) = peer.topic_prefix {
        config = config.with_topic_prefix(prefix);
    }
    config
}

/// Parse a hex-encoded public ID string.
fn parse_public_id(hex_str: &str) -> Result<PublicID, Box<dyn std::error::Error>> {
    if hex_str.len() != 64 {
        return Err(format!(
            "Invalid public ID: expected 64 hex characters, got {}",
            hex_str.len()
        )
        .into());
    }
    let bytes =
        hex::decode(hex_str).map_err(|e| format!("Invalid public ID: bad hex encoding: {e}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "hex::decode of 64-char hex string did not produce 32 bytes")?;
    PublicID::try_from_bytes(&bytes)
        .map_err(|_| "Invalid public ID: rejected as low-order point".into())
}

/// Format a tiered delivery phase for human-friendly output.
const fn format_delivery_phase(phase: &ember_outbox::TieredDeliveryPhase) -> &'static str {
    match phase {
        ember_outbox::TieredDeliveryPhase::Urgent => "queued for delivery",
        ember_outbox::TieredDeliveryPhase::Distributed { .. } => "delivered (quorum)",
        ember_outbox::TieredDeliveryPhase::Confirmed { .. } => "acknowledged",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ember_outbox::OutboxStore;
    use rand::RngCore;

    fn temp_dir() -> std::path::PathBuf {
        let mut rng = rand::rng();
        let mut suffix = [0u8; 8];
        rng.fill_bytes(&mut suffix);
        let base = std::env::temp_dir();
        base.join(format!("ember-send-{}", hex::encode(suffix)))
    }

    fn write_identity(path: &std::path::Path) {
        fs::create_dir_all(path).unwrap();
        let identity = Identity::generate();
        let data = ember_identity::save_identity(&identity, None).unwrap();
        fs::write(path.join("identity.ember"), data).unwrap();
    }

    #[tokio::test]
    #[allow(clippy::field_reassign_with_default)]
    async fn test_no_deliver_enqueues_outbox() {
        let data_dir = temp_dir();
        write_identity(&data_dir);

        let recipient = Identity::generate();
        let args = SendArgs {
            to: hex::encode(recipient.public_id().to_bytes()),
            text: "hello".to_string(),
            no_deliver: true,
        };

        let mut config = AppConfig::default();
        config.data_dir = data_dir.clone();
        config.peers.http.clear();
        config.peers.mqtt.clear();
        config.direct_peers.clear();

        run_send(&config, &args).await.unwrap();

        let storage = Storage::open(data_dir.join("messages.db").to_str().unwrap()).unwrap();
        let pending = storage.outbox_get_pending().unwrap();
        assert_eq!(pending.len(), 1);

        fs::remove_dir_all(&data_dir).ok();
    }

    #[tokio::test]
    #[allow(clippy::field_reassign_with_default)]
    async fn test_missing_identity_errors() {
        let data_dir = temp_dir();
        let recipient = Identity::generate();
        let args = SendArgs {
            to: hex::encode(recipient.public_id().to_bytes()),
            text: "hi".to_string(),
            no_deliver: true,
        };
        let mut config = AppConfig::default();
        config.data_dir = data_dir.clone();
        config.peers.http.clear();
        config.peers.mqtt.clear();
        config.direct_peers.clear();

        let err = run_send(&config, &args).await.unwrap_err();
        assert!(err.to_string().contains("No identity"));

        fs::remove_dir_all(&data_dir).ok();
    }
}
