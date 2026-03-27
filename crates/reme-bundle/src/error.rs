use std::io;

/// Errors that can occur when reading or writing `.reme` bundles.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BundleError {
    #[error("invalid magic bytes: expected REME")]
    InvalidMagic,

    #[error("unsupported format version: {version}")]
    UnsupportedVersion { version: u8 },

    #[error("checksum mismatch")]
    ChecksumMismatch,

    #[error("incomplete read: consumed {read} of {total} frames before verifying checksum")]
    IncompleteRead { read: u32, total: u32 },

    #[error("frame too large: {size} bytes (max {max})")]
    FrameTooLarge { size: u32, max: u32 },

    #[error(transparent)]
    Io(#[from] io::Error),
}
