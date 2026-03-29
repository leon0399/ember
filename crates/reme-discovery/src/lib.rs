#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
pub mod backend;
#[cfg(any(test, feature = "test-utils"))]
pub mod fake;
#[cfg(feature = "mdns-sd")]
pub mod mdns_sd;
pub mod txt;
pub mod types;

pub use backend::DiscoveryBackend;
pub use txt::{decode_txt, encode_txt, RoutingKey, TxtError, TxtFields};
pub use types::{
    AdvertisementSpec, DiscoveryError, DiscoveryEvent, RawDiscoveredPeer, DEFAULT_SERVICE_TYPE,
};
