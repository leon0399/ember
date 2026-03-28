use std::fmt;
use std::io::Read;

use crate::{BundleError, FORMAT_VERSION, MAGIC, MAX_FRAME_SIZE};

/// Reads and validates a `.reme` bundle from any `Read` source.
///
/// Call [`BundleReader::open`] to validate the header, then iterate frames with
/// [`BundleReader::next_frame`], and finally call [`BundleReader::verify_checksum`]
/// to confirm the BLAKE3 integrity hash.
pub struct BundleReader<R: Read> {
    inner: R,
    // blake3::Hasher does not implement Debug, so Debug is implemented manually below.
    hasher: blake3::Hasher,
    frame_count: u32,
    frames_read: u32,
}

impl<R: Read + fmt::Debug> fmt::Debug for BundleReader<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BundleReader")
            .field("inner", &self.inner)
            .field("frame_count", &self.frame_count)
            .field("frames_read", &self.frames_read)
            .finish_non_exhaustive()
    }
}

impl<R: Read> BundleReader<R> {
    /// Open a bundle, validating the magic bytes and format version.
    ///
    /// Reads the 10-byte header (`magic[4] + version[1] + flags[1] + frame_count[4]`)
    /// and returns an error if the magic is wrong or the version is unsupported.
    pub fn open(mut reader: R) -> Result<Self, BundleError> {
        let mut hasher = blake3::Hasher::new();

        let mut header = [0u8; 10];
        reader.read_exact(&mut header)?;
        hasher.update(&header);

        if &header[0..4] != MAGIC {
            return Err(BundleError::InvalidMagic);
        }

        let version = header[4];
        if version != FORMAT_VERSION {
            return Err(BundleError::UnsupportedVersion { version });
        }

        // header[5] is reserved flags — accepted but ignored.
        let frame_count = u32::from_le_bytes([header[6], header[7], header[8], header[9]]);

        Ok(Self {
            inner: reader,
            hasher,
            frame_count,
            frames_read: 0,
        })
    }

    /// Total number of frames declared in the bundle header.
    pub fn frame_count(&self) -> u32 {
        self.frame_count
    }

    /// Read the next frame. Returns `None` when all declared frames have been read.
    ///
    /// Each frame is prefixed with a 4-byte little-endian length. Frames larger than
    /// [`MAX_FRAME_SIZE`] are rejected with [`BundleError::FrameTooLarge`].
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, BundleError> {
        if self.frames_read >= self.frame_count {
            return Ok(None);
        }

        let mut len_buf = [0u8; 4];
        self.inner.read_exact(&mut len_buf)?;
        self.hasher.update(&len_buf);

        let frame_len = u32::from_le_bytes(len_buf);
        if frame_len > MAX_FRAME_SIZE {
            return Err(BundleError::FrameTooLarge {
                size: frame_len,
                max: MAX_FRAME_SIZE,
            });
        }

        let mut frame = vec![0u8; frame_len as usize];
        self.inner.read_exact(&mut frame)?;
        self.hasher.update(&frame);

        self.frames_read += 1;
        Ok(Some(frame))
    }

    /// Read all frames and verify the checksum in one call.
    ///
    /// Convenience method that collects all frames into a `Vec`, then verifies
    /// the BLAKE3 checksum. Returns the collected frames on success.
    pub fn read_all_verified(mut self) -> Result<Vec<Vec<u8>>, BundleError> {
        let mut frames = Vec::new();
        while let Some(frame) = self.next_frame()? {
            frames.push(frame);
        }
        self.verify_checksum()?;
        Ok(frames)
    }

    /// Verify the BLAKE3 checksum after all frames have been read.
    ///
    /// All frames must be consumed via [`next_frame`](Self::next_frame) before calling
    /// this method. Returns [`BundleError::IncompleteRead`] if frames remain unconsumed,
    /// [`BundleError::ChecksumMismatch`] if the hash does not match, or
    /// [`BundleError::TrailingData`] if extra bytes follow the checksum.
    pub fn verify_checksum(mut self) -> Result<(), BundleError> {
        if self.frames_read != self.frame_count {
            return Err(BundleError::IncompleteRead {
                read: self.frames_read,
                total: self.frame_count,
            });
        }

        let mut stored_checksum = [0u8; 32];
        self.inner.read_exact(&mut stored_checksum)?;

        let computed = self.hasher.finalize();
        if computed.as_bytes() != &stored_checksum {
            return Err(BundleError::ChecksumMismatch);
        }

        // Reject trailing data — a valid bundle must end exactly after the checksum.
        let mut probe = [0u8; 1];
        match self.inner.read(&mut probe) {
            Ok(0) | Err(_) => Ok(()),
            Ok(_) => Err(BundleError::TrailingData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::BundleWriter;

    fn make_bundle(frames: &[&[u8]]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut writer = BundleWriter::new(&mut buf);
        for frame in frames {
            writer.write_frame(frame).unwrap();
        }
        writer.finish().unwrap();
        buf
    }

    #[test]
    fn read_empty_bundle() {
        let data = make_bundle(&[]);
        let mut reader = BundleReader::open(&data[..]).unwrap();
        assert_eq!(reader.frame_count(), 0);
        assert!(reader.next_frame().unwrap().is_none());
        reader.verify_checksum().unwrap();
    }

    #[test]
    fn read_single_frame() {
        let data = make_bundle(&[b"hello"]);
        let mut reader = BundleReader::open(&data[..]).unwrap();
        assert_eq!(reader.frame_count(), 1);
        let frame = reader.next_frame().unwrap().unwrap();
        assert_eq!(frame, b"hello");
        assert!(reader.next_frame().unwrap().is_none());
        reader.verify_checksum().unwrap();
    }

    #[test]
    fn read_multiple_frames() {
        let data = make_bundle(&[b"aaa", b"bbb", b"ccc"]);
        let mut reader = BundleReader::open(&data[..]).unwrap();
        assert_eq!(reader.frame_count(), 3);
        assert_eq!(reader.next_frame().unwrap().unwrap(), b"aaa");
        assert_eq!(reader.next_frame().unwrap().unwrap(), b"bbb");
        assert_eq!(reader.next_frame().unwrap().unwrap(), b"ccc");
        assert!(reader.next_frame().unwrap().is_none());
        reader.verify_checksum().unwrap();
    }

    #[test]
    fn invalid_magic() {
        let mut data = make_bundle(&[]);
        data[0] = b'X';
        let err = BundleReader::open(&data[..]).unwrap_err();
        assert!(matches!(err, BundleError::InvalidMagic));
    }

    #[test]
    fn unsupported_version() {
        let mut data = make_bundle(&[]);
        data[4] = 99;
        let err = BundleReader::open(&data[..]).unwrap_err();
        assert!(matches!(
            err,
            BundleError::UnsupportedVersion { version: 99 }
        ));
    }

    #[test]
    fn corrupted_checksum() {
        let mut data = make_bundle(&[b"hello"]);
        let last = data.len() - 1;
        data[last] ^= 0xFF;
        let mut reader = BundleReader::open(&data[..]).unwrap();
        let _frame = reader.next_frame().unwrap();
        let err = reader.verify_checksum().unwrap_err();
        assert!(matches!(err, BundleError::ChecksumMismatch));
    }

    #[test]
    fn trailing_data_rejected() {
        let mut data = make_bundle(&[b"hello"]);
        data.push(0xFF); // append junk after checksum
        let mut reader = BundleReader::open(&data[..]).unwrap();
        let _frame = reader.next_frame().unwrap();
        let err = reader.verify_checksum().unwrap_err();
        assert!(matches!(err, BundleError::TrailingData));
    }

    #[test]
    fn verify_checksum_before_all_frames_consumed() {
        let data = make_bundle(&[b"aaa", b"bbb"]);
        let mut reader = BundleReader::open(&data[..]).unwrap();
        let _frame = reader.next_frame().unwrap(); // read only 1 of 2
        let err = reader.verify_checksum().unwrap_err();
        assert!(matches!(
            err,
            BundleError::IncompleteRead { read: 1, total: 2 }
        ));
    }

    #[test]
    fn truncated_file() {
        let data = make_bundle(&[b"hello"]);
        // Truncate just after the frame-length prefix so the frame body read fails.
        // Layout: header(10) + frame_len(4) + frame(5) + checksum(32) = 51 bytes.
        // Cutting at 15 leaves header + len_buf + 1 byte of frame; reading the full 5-byte
        // frame body triggers an UnexpectedEof wrapped in BundleError::Io.
        let truncated = &data[..15];
        let mut reader = BundleReader::open(truncated).unwrap();
        let err = reader.next_frame().unwrap_err();
        assert!(matches!(err, BundleError::Io(_)));
    }
}
