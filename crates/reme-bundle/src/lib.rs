//! `.reme` bundle format — versioned, checksummed container for `WirePayload` frames.
//!
//! # Wire Format
//!
//! ```text
//! [magic: 4 bytes "REME"]
//! [format_version: u8]       // 1
//! [flags: u8]                // reserved, 0 for now
//! [frame_count: u32 LE]     // number of WirePayload frames
//! [frames: repeated]
//!   [frame_len: u32 LE]     // byte length of this frame
//!   [frame: WirePayload bytes]
//! [checksum: 32 bytes]       // BLAKE3 hash of all preceding bytes
//! ```

mod error;
mod reader;
mod writer;

pub use error::BundleError;
pub use reader::BundleReader;
pub use writer::BundleWriter;

/// Magic bytes at the start of every `.reme` bundle.
pub const MAGIC: &[u8; 4] = b"REME";

/// Current format version.
pub const FORMAT_VERSION: u8 = 1;

/// Maximum allowed frame size (16 MiB). Prevents memory exhaustion from corrupt files.
pub const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;
