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
//! - [`mailbox_store`]: Storage trait and SQLite implementation
//!
//! # Example
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

pub mod error;
pub mod mailbox_store;

pub use error::*;
pub use mailbox_store::*;
