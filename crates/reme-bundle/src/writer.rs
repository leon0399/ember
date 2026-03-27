use std::io::Write;

use crate::{BundleError, FORMAT_VERSION, MAGIC, MAX_FRAME_SIZE};

/// Writes a `.reme` bundle to an underlying [`Write`] implementation.
///
/// Frames are buffered in memory and the complete bundle — header, frames, and
/// BLAKE3 checksum — is flushed atomically when [`finish`](BundleWriter::finish)
/// is called.  This allows the header's `frame_count` field to be filled in
/// before any bytes are written to the underlying writer.
pub struct BundleWriter<W: Write> {
    inner: W,
    frames: Vec<Vec<u8>>,
}

impl<W: Write> BundleWriter<W> {
    /// Create a new `BundleWriter` that writes the finished bundle into `writer`.
    pub fn new(writer: W) -> Self {
        Self {
            inner: writer,
            frames: Vec::new(),
        }
    }

    /// Buffer a single wire-payload frame.
    ///
    /// Returns [`BundleError::FrameTooLarge`] if the payload exceeds
    /// [`MAX_FRAME_SIZE`].
    pub fn write_frame(&mut self, wire_payload: &[u8]) -> Result<(), BundleError> {
        let len = u32::try_from(wire_payload.len()).map_err(|_| BundleError::FrameTooLarge {
            size: u32::MAX,
            max: MAX_FRAME_SIZE,
        })?;
        if len > MAX_FRAME_SIZE {
            return Err(BundleError::FrameTooLarge {
                size: len,
                max: MAX_FRAME_SIZE,
            });
        }
        self.frames.push(wire_payload.to_vec());
        Ok(())
    }

    /// Serialise all buffered frames to the underlying writer and append the
    /// BLAKE3 checksum.
    ///
    /// Consumes `self`.  After this call the underlying writer contains a
    /// complete, valid `.reme` bundle.
    pub fn finish(mut self) -> Result<(), BundleError> {
        let mut hasher = blake3::Hasher::new();

        // Frames are individually validated to fit in u32 by write_frame, so
        // their count also fits in u32 unless Vec itself somehow holds >4B items,
        // which is not a realistic condition.
        let frame_count = u32::try_from(self.frames.len())
            .expect("frame count overflows u32; more than 4 billion frames were buffered");

        // Write header
        let header = Self::build_header(frame_count);
        hasher.update(&header);
        self.inner.write_all(&header)?;

        // Write frames
        for frame in &self.frames {
            // len was validated ≤ MAX_FRAME_SIZE (u32) in write_frame
            let len_bytes = u32::try_from(frame.len())
                .expect("frame len no longer fits in u32 after validation")
                .to_le_bytes();
            hasher.update(&len_bytes);
            self.inner.write_all(&len_bytes)?;
            hasher.update(frame);
            self.inner.write_all(frame)?;
        }

        // Write checksum
        let checksum = hasher.finalize();
        self.inner.write_all(checksum.as_bytes())?;

        Ok(())
    }

    fn build_header(frame_count: u32) -> [u8; 10] {
        let mut header = [0u8; 10];
        header[0..4].copy_from_slice(MAGIC);
        header[4] = FORMAT_VERSION;
        header[5] = 0; // flags (reserved)
        header[6..10].copy_from_slice(&frame_count.to_le_bytes());
        header
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_empty_bundle() {
        let mut buf = Vec::new();
        let writer = BundleWriter::new(&mut buf);
        writer.finish().unwrap();

        // magic(4) + version(1) + flags(1) + count(4) + checksum(32) = 42
        assert_eq!(buf.len(), 42);
        assert_eq!(&buf[0..4], b"REME");
        assert_eq!(buf[4], 1);
        assert_eq!(buf[5], 0);
        assert_eq!(u32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]), 0);
    }

    #[test]
    fn write_single_frame() {
        let mut buf = Vec::new();
        let mut writer = BundleWriter::new(&mut buf);
        writer.write_frame(b"hello").unwrap();
        writer.finish().unwrap();

        // header(10) + frame_len(4) + frame(5) + checksum(32) = 51
        assert_eq!(buf.len(), 51);
        assert_eq!(u32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]), 1);
        assert_eq!(u32::from_le_bytes([buf[10], buf[11], buf[12], buf[13]]), 5);
        assert_eq!(&buf[14..19], b"hello");
    }

    #[test]
    fn write_multiple_frames() {
        let mut buf = Vec::new();
        let mut writer = BundleWriter::new(&mut buf);
        writer.write_frame(b"aaa").unwrap();
        writer.write_frame(b"bbb").unwrap();
        writer.write_frame(b"ccc").unwrap();
        writer.finish().unwrap();

        assert_eq!(u32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]), 3);
    }
}
