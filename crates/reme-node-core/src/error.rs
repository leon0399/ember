//! Error types for node operations

use thiserror::Error;

/// Errors from node operations
#[derive(Debug, Error)]
pub enum NodeError {
    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// Lock poisoned
    #[error("Lock poisoned")]
    LockPoisoned,

    /// Mailbox full
    #[error("Mailbox full")]
    MailboxFull,

    /// Invalid message format
    #[error("Invalid message: {0}")]
    InvalidMessage(String),
}

/// Result type for node operations
pub type NodeResult<T> = Result<T, NodeError>;
