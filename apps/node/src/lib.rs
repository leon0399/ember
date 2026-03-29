#![allow(clippy::print_stdout, clippy::print_stderr)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cognitive_complexity
    )
)]
//! Branch Messenger Mailbox Node Library
//!
//! This library exposes the node components for use in testing and embedding.

pub mod api;
pub mod cleanup;
pub mod config;
pub mod export;
pub mod import;
pub mod mqtt_bridge;
pub mod node_identity;
pub mod rate_limit;
pub mod replication;
pub mod signed_headers;

// Re-export core types from reme-node-core for backwards compatibility
pub use reme_node_core::{
    MailboxStore, NodeError, NodeResult, PersistentMailboxStore, PersistentStoreConfig,
    PersistentStoreStats,
};
