//! Core embedded node functionality for resilient messenger.
//!
//! This crate provides the core node logic that can be embedded in the client
//! or used standalone. It handles:
//!
//! - Message storage in mailboxes
//! - Replication to peer nodes
//! - Push notifications to the client via channels
//!
//! ## Architecture
//!
//! The embedded node communicates with the client via tokio channels:
//! - `NodeRequest`: Client → Node (with oneshot response channel)
//! - `NodeEvent`: Node → Client (async push for incoming messages)
//!
//! ## Example
//!
//! ```ignore
//! use reme_node_core::{start_embedded_node, EmbeddedNodeConfig};
//! use std::sync::Arc;
//!
//! // Create storage (implements MailboxStorage)
//! let storage = Arc::new(my_storage);
//!
//! // Configure the node
//! let config = EmbeddedNodeConfig {
//!     peers: vec!["http://peer1:3000".to_string()],
//!     ..Default::default()
//! };
//!
//! // Start the embedded node
//! let handle = start_embedded_node(storage, config).await?;
//!
//! // Send messages via handle.request_tx
//! // Receive events via handle.event_rx
//!
//! // Shutdown gracefully
//! handle.shutdown().await?;
//! ```

pub mod http;
pub mod node;
pub mod replication;
pub mod storage;

// Re-export channel types from reme-transport (canonical location)
pub use reme_transport::{
    NodeError, NodeEvent, NodeRequest, EVENT_CHANNEL_SIZE, REQUEST_CHANNEL_SIZE,
};

// Re-export main types for convenience
pub use node::{start_embedded_node, EmbeddedNode, EmbeddedNodeConfig, EmbeddedNodeHandle};
pub use replication::{ReplicationClient, FROM_NODE_HEADER};
pub use storage::{MailboxStorage, StorageError};
