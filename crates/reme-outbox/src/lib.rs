//! reme-outbox: Client-side outbox for resilient message delivery
//!
//! This crate provides:
//! - Persistent tracking of outgoing messages until delivery confirmation
//! - Per-transport attempt tracking with configurable retry policies
//! - DAG-based implicit confirmation via peer's `observed_heads`
//! - Extensible confirmation model for future ZK receipts, P2P ACKs

pub mod config;
pub mod state;
pub mod store;

pub use config::*;
pub use state::*;
pub use store::*;
