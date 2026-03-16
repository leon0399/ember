use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

/// A peer discovered via mDNS/DNS-SD or another discovery backend.
#[derive(Debug, Clone)]
pub struct RawDiscoveredPeer {
    /// The DNS-SD service instance name (unique per advertisement).
    pub instance_name: String,
    /// Resolved socket addresses for this peer.
    pub addresses: Vec<SocketAddr>,
    /// The port advertised in the SRV record.
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

impl Default for AdvertisementSpec {
    fn default() -> Self {
        Self {
            service_type: "_reme._tcp.local.".to_owned(),
            port: 0,
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
