#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! reme-node-core: Core mailbox node functionality
//!
//! This crate provides the core logic for mailbox nodes, shared between:
//! - Standalone node application (`apps/node`)
//! - Embedded node in client application
//!
//! # Architecture
//!
//! The crate is organized into:
//! - [`error`]: Error types for node operations
//! - [`mailbox_store`]: Storage trait and `SQLite` implementation
//! - [`request`]: Request and event types for embedded node communication
//! - [`embedded`]: Embedded node for in-process mailbox functionality
//!
//! # Standalone Node Example
//!
//! ```ignore
//! use reme_node_core::{MailboxStore, PersistentMailboxStore, PersistentStoreConfig};
//!
//! // Create a persistent mailbox store
//! let config = PersistentStoreConfig::default();
//! let store = PersistentMailboxStore::open("mailbox.db", config)?;
//!
//! // Enqueue a message (routing_key passed by value)
//! store.enqueue(routing_key, envelope)?;
//!
//! // Fetch messages for a routing key
//! let messages = store.fetch(&routing_key)?;
//! ```
//!
//! # Embedded Node Example
//!
//! ```ignore
//! use reme_node_core::{EmbeddedNode, PersistentMailboxStore, PersistentStoreConfig};
//!
//! // Create mailbox store
//! let config = PersistentStoreConfig::default();
//! let store = PersistentMailboxStore::in_memory(config)?;
//!
//! // Create and run embedded node
//! let (node, handle, _event_rx) = EmbeddedNode::new(store);
//! tokio::spawn(async move { node.run().await });
//!
//! // Use handle to interact with node
//! handle.submit_message(envelope).await?;
//! ```

pub mod embedded;
pub mod error;
pub mod mailbox_store;
pub mod request;
pub mod time;

pub use embedded::*;
pub use error::*;
pub use mailbox_store::*;
pub use request::*;
pub use time::*;
