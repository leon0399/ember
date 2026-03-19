use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// A peer discovered via mDNS/DNS-SD or another discovery backend.
#[derive(Debug, Clone)]
pub struct RawDiscoveredPeer {
    /// The DNS-SD service instance name (unique per advertisement).
    pub instance_name: String,
    /// Resolved IP addresses from A/AAAA records.
    ///
    /// These are bare IPs — combine with [`port`](Self::port) (from the SRV
    /// record) to get connectable `SocketAddr`s.
    pub addresses: Vec<IpAddr>,
    /// The port advertised in the SRV record (authoritative).
    pub port: u16,
    /// TXT record key-value pairs.
    pub txt_records: HashMap<String, String>,
    /// When this peer was first seen.
    pub discovered_at: Instant,
}

/// Events emitted by a discovery backend.
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// A new peer appeared on the network.
    PeerDiscovered(RawDiscoveredPeer),
    /// An existing peer's records changed (e.g., new address or TXT update).
    PeerUpdated(RawDiscoveredPeer),
    /// A previously-discovered peer is no longer reachable.
    /// The payload is the service instance name.
    PeerLost(String),
}

/// Parameters for advertising this node's presence on the local network.
#[derive(Debug, Clone)]
pub struct AdvertisementSpec {
    /// DNS-SD service type, e.g. `"_reme._tcp.local."`.
    pub service_type: String,
    /// Port to advertise in the SRV record.
    pub port: u16,
    /// TXT record key-value pairs to publish alongside the service.
    pub txt_records: HashMap<String, String>,
}

/// Default service type for reme mDNS advertisements.
pub const DEFAULT_SERVICE_TYPE: &str = "_reme._tcp.local.";

/// Channel capacity for discovery event broadcast channels.
///
/// Used by both the fake and mDNS-SD backends, which are behind different
/// feature gates — so this may appear unused in some feature combinations.
#[allow(dead_code)]
pub(crate) const DISCOVERY_CHANNEL_CAPACITY: usize = 128;

impl AdvertisementSpec {
    /// Create a new advertisement spec with the given port and default service type.
    pub fn new(port: u16) -> Self {
        Self {
            service_type: DEFAULT_SERVICE_TYPE.to_owned(),
            port,
            txt_records: HashMap::new(),
        }
    }
}

/// Errors returned by discovery operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DiscoveryError {
    /// Failed to bind to a network interface or multicast group.
    #[error("failed to bind: {0}")]
    BindFailed(String),

    /// `start_advertising` was called while already advertising.
    #[error("already advertising")]
    AlreadyAdvertising,

    /// `stop_advertising` was called when not advertising.
    #[error("not currently advertising")]
    NotAdvertising,

    /// Catch-all for backend-specific failures.
    #[error("backend error: {0}")]
    BackendError(String),
}
