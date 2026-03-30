pub mod controller;

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use crate::config::AppConfig;
use reme_discovery::mdns_sd::MdnsSdBackend;
use reme_discovery::DiscoveryBackend as _;
use reme_identity::{Identity, PublicID};
use reme_storage::{Storage, TrustLevel};
use reme_transport::coordinator::TransportCoordinator;
use reme_transport::registry::TransportRegistry;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Consolidated discovery subsystem state.
///
/// Groups the mDNS backend, cancellation token, and controller task handle
/// that were previously stored as three separate `Option` fields in `App`.
pub struct DiscoveryState {
    pub backend: Arc<MdnsSdBackend>,
    pub cancel: CancellationToken,
    pub controller_task: Option<JoinHandle<()>>,
    /// Channel for dynamically adding contacts to the controller at runtime.
    pub contact_tx: Option<mpsc::UnboundedSender<(PublicID, [u8; 16])>>,
    /// Shared counter of currently discovered (verified) LAN peers.
    pub peer_count: Arc<AtomicUsize>,
}

/// Result of attempting to initialize the discovery subsystem.
pub enum InitResult {
    /// Discovery is disabled in config.
    Disabled,
    /// mDNS backend failed to initialize (discovery was enabled).
    Failed(String),
    /// Successfully initialized.
    Ok(DiscoveryState),
}

/// Initialize the LAN discovery subsystem.
///
/// Creates the mDNS-SD backend, optionally spawns the discovery controller
/// (when `auto_direct_known_contacts` is enabled), and starts advertising
/// if an HTTP server bind address is configured.
///
/// Returns [`InitResult`] distinguishing disabled, failed, and success cases.
pub async fn initialize(
    config: &AppConfig,
    identity: &Identity,
    storage: Arc<Storage>,
    coordinator: Arc<TransportCoordinator>,
    registry: Arc<TransportRegistry>,
) -> InitResult {
    if !config.lan_discovery.enabled {
        return InitResult::Disabled;
    }

    let backend = match create_mdns_backend() {
        Ok(b) => b,
        Err(reason) => return InitResult::Failed(reason),
    };

    let state = build_discovery_state(config, storage, &backend, coordinator, registry);
    start_advertising_if_configured(config, identity, &backend).await;

    info!("LAN discovery enabled");
    InitResult::Ok(finalize_state(backend, state))
}

/// Attempt to create the mDNS-SD backend.
fn create_mdns_backend() -> Result<MdnsSdBackend, String> {
    MdnsSdBackend::new().map_err(|e| {
        warn!("Failed to initialize mDNS backend: {e}. LAN discovery disabled.");
        format!("{e}")
    })
}

/// Partial discovery state before finalizing with the backend.
struct PartialDiscoveryState {
    cancel: CancellationToken,
    controller_task: Option<tokio::task::JoinHandle<()>>,
    contact_tx: Option<mpsc::UnboundedSender<(PublicID, [u8; 16])>>,
    peer_count: Arc<AtomicUsize>,
}

/// Build partial discovery state (controller + peer count + cancel token).
fn build_discovery_state(
    config: &AppConfig,
    storage: Arc<Storage>,
    backend: &MdnsSdBackend,
    coordinator: Arc<TransportCoordinator>,
    registry: Arc<TransportRegistry>,
) -> PartialDiscoveryState {
    let peer_count = Arc::new(AtomicUsize::new(0));
    let cancel = CancellationToken::new();

    let (controller_task, contact_tx) = spawn_controller(
        config,
        storage,
        backend,
        ControllerDeps {
            coordinator,
            registry,
            peer_count: peer_count.clone(),
        },
        &cancel,
    );

    PartialDiscoveryState {
        cancel,
        controller_task,
        contact_tx,
        peer_count,
    }
}

/// Finalize discovery state from backend and partial state.
fn finalize_state(backend: MdnsSdBackend, state: PartialDiscoveryState) -> DiscoveryState {
    DiscoveryState {
        backend: Arc::new(backend),
        cancel: state.cancel,
        controller_task: state.controller_task,
        contact_tx: state.contact_tx,
        peer_count: state.peer_count,
    }
}

/// Result of spawning the discovery controller.
type ControllerHandles = (
    Option<JoinHandle<()>>,
    Option<mpsc::UnboundedSender<(PublicID, [u8; 16])>>,
);

struct ControllerDeps {
    coordinator: Arc<TransportCoordinator>,
    registry: Arc<TransportRegistry>,
    peer_count: Arc<AtomicUsize>,
}

/// Spawn the discovery controller if `auto_direct_known_contacts` is enabled.
fn spawn_controller(
    config: &AppConfig,
    storage: Arc<Storage>,
    backend: &MdnsSdBackend,
    deps: ControllerDeps,
    cancel: &CancellationToken,
) -> ControllerHandles {
    let ControllerDeps {
        coordinator,
        registry,
        peer_count,
    } = deps;
    if !config.lan_discovery.auto_direct_known_contacts {
        info!("LAN discovery active but direct delivery disabled (auto_direct_known_contacts = false)");
        return (None, None);
    }

    let contacts = load_contacts_for_discovery(storage.as_ref());
    let events = backend.subscribe();
    let (contact_tx, contact_rx) = mpsc::unbounded_channel();
    let task = controller::spawn(controller::SpawnConfig {
        events,
        coordinator,
        registry,
        storage,
        contacts,
        max_peers: config.lan_discovery.max_peers,
        refresh_interval_secs: config.lan_discovery.refresh_interval_secs,
        cancel: cancel.clone(),
        contact_rx,
        peer_count,
    });
    (Some(task), Some(contact_tx))
}

/// Load contacts from storage, mapping to (`PublicID`, `routing_key`) pairs.
fn load_contacts_for_discovery(storage: &Storage) -> Vec<(PublicID, [u8; 16])> {
    storage
        .list_contacts_with_min_trust(TrustLevel::Known)
        .unwrap_or_else(|e| {
            warn!("Failed to load contacts for discovery: {e}");
            Vec::new()
        })
        .into_iter()
        .map(|contact| (contact.public_id, *contact.routing_key.as_bytes()))
        .collect()
}

/// Start mDNS advertising if the embedded node has an HTTP bind address.
async fn start_advertising_if_configured(
    config: &AppConfig,
    identity: &Identity,
    backend: &MdnsSdBackend,
) {
    let Some(http_bind) = config
        .embedded_node
        .http_bind
        .as_ref()
        .filter(|_| config.embedded_node.enabled)
    else {
        return;
    };

    let port: u16 = http_bind
        .parse::<std::net::SocketAddr>()
        .map(|a| a.port())
        .unwrap_or(23004);

    let our_rk: [u8; 16] = identity.public_id().routing_key().into();
    let txt = reme_discovery::encode_txt(&our_rk, port);
    let spec = reme_discovery::AdvertisementSpec {
        txt_records: txt,
        ..reme_discovery::AdvertisementSpec::new(port, our_rk)
    };

    if let Err(e) = backend.start_advertising(spec).await {
        warn!("Failed to start mDNS advertising: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::load_contacts_for_discovery;
    use reme_identity::Identity;
    use reme_storage::{Storage, TrustLevel};

    #[test]
    fn load_contacts_for_discovery_filters_out_strangers() {
        let storage = Storage::in_memory().unwrap();
        let stranger = Identity::generate();
        let known = Identity::generate();

        storage
            .create_contact(stranger.public_id(), Some("Stranger"), TrustLevel::Stranger)
            .unwrap();
        storage
            .create_contact(known.public_id(), Some("Known"), TrustLevel::Known)
            .unwrap();

        let contacts = load_contacts_for_discovery(&storage);
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].0, *known.public_id());
        assert_eq!(contacts[0].1, *known.public_id().routing_key().as_bytes());
    }
}
