#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! `.ember` bundle format — versioned, checksummed container for `WirePayload` frames.
//!
//! # Wire Format
//!
//! ```text
//! [magic: 4 bytes "EMBR"]
//! [format_version: u8]       // 1
//! [flags: u8]                // reserved, 0 for now
//! [frame_count: u32 LE]     // number of WirePayload frames
//! [frames: repeated]
//!   [frame_len: u32 LE]     // byte length of this frame
//!   [frame: WirePayload bytes]
//! [checksum: 32 bytes]       // BLAKE3 hash of all preceding bytes
//! ```

pub mod body;
mod error;
mod reader;
mod writer;

pub use body::{encode_body, parse_body, BodyParseError};
pub use error::BundleError;
pub use reader::BundleReader;
pub use writer::BundleWriter;

/// Magic bytes at the start of every `.ember` bundle.
pub const MAGIC: &[u8; 4] = b"EMBR";

/// Current format version.
pub const FORMAT_VERSION: u8 = 1;

/// Maximum allowed frame size (16 MiB). Prevents memory exhaustion from corrupt files.
pub const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use crate::reader::BundleReader;
    use crate::writer::BundleWriter;

    #[test]
    fn round_trip_varied_frame_sizes() {
        let frames: Vec<Vec<u8>> = (0_u8..100)
            .map(|i| vec![i; usize::from(i) * 10 + 1])
            .collect();

        let mut buf = Vec::new();
        let mut writer = BundleWriter::new(&mut buf);
        for frame in &frames {
            writer.write_frame(frame).unwrap();
        }
        writer.finish().unwrap();

        let mut reader = BundleReader::open(&buf[..]).unwrap();
        assert_eq!(reader.frame_count(), 100);

        for expected in &frames {
            let actual = reader.next_frame().unwrap().unwrap();
            assert_eq!(&actual, expected);
        }
        assert!(reader.next_frame().unwrap().is_none());
        reader.verify_checksum().unwrap();
    }

    #[test]
    fn round_trip_empty_frames() {
        let mut buf = Vec::new();
        let mut writer = BundleWriter::new(&mut buf);
        writer.write_frame(b"").unwrap();
        writer.write_frame(b"").unwrap();
        writer.finish().unwrap();

        let mut reader = BundleReader::open(&buf[..]).unwrap();
        assert_eq!(reader.frame_count(), 2);
        assert_eq!(reader.next_frame().unwrap().unwrap(), b"");
        assert_eq!(reader.next_frame().unwrap().unwrap(), b"");
        assert!(reader.next_frame().unwrap().is_none());
        reader.verify_checksum().unwrap();
    }

    #[test]
    fn round_trip_large_bundle() {
        let frame = vec![0xAB_u8; 100];

        let mut buf = Vec::new();
        let mut writer = BundleWriter::new(&mut buf);
        for _ in 0..10_000 {
            writer.write_frame(&frame).unwrap();
        }
        writer.finish().unwrap();

        let mut reader = BundleReader::open(&buf[..]).unwrap();
        assert_eq!(reader.frame_count(), 10_000);

        for _ in 0..10_000 {
            let f = reader.next_frame().unwrap().unwrap();
            assert_eq!(f.len(), 100);
        }
        assert!(reader.next_frame().unwrap().is_none());
        reader.verify_checksum().unwrap();
    }

    #[test]
    fn corrupted_frame_data_detected_by_checksum() {
        let mut buf = Vec::new();
        let mut writer = BundleWriter::new(&mut buf);
        writer.write_frame(b"secret data").unwrap();
        writer.finish().unwrap();

        // Corrupt a byte in the frame data area
        // Layout: header(10) + frame_len(4) + frame("secret data" = 11 bytes)
        // So frame bytes start at offset 14. Corrupt offset 18.
        buf[18] ^= 0xFF;

        let mut reader = BundleReader::open(&buf[..]).unwrap();
        let _frame = reader.next_frame().unwrap(); // reads corrupted data fine
        let err = reader.verify_checksum().unwrap_err();
        assert!(matches!(err, crate::BundleError::ChecksumMismatch));
    }
}
