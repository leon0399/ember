pub mod backend;
pub mod fake;
#[cfg(feature = "mdns-sd")]
pub mod mdns_sd;
pub mod txt;
pub mod types;

pub use backend::DiscoveryBackend;
pub use txt::{decode_txt, encode_txt, RoutingKey, TxtError};
pub use types::{
    AdvertisementSpec, DiscoveryError, DiscoveryEvent, RawDiscoveredPeer, DEFAULT_SERVICE_TYPE,
};
