//! Bundle body encoding for HTTP submit API.
//!
//! Wire format: `[count: u32 LE][frame_len: u32 LE][frame bytes]...`
//! Same framing as the `.reme` file format but without the file-level
//! header (magic, version, flags, checksum).

/// Errors from parsing a bundle body.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BodyParseError {
    #[error("body too short: need at least 4 bytes for frame count")]
    TooShort,

    #[error("frame count is zero")]
    EmptyBundle,

    #[error("too many frames: {count} exceeds max {max}")]
    TooManyFrames { count: u32, max: u32 },

    #[error("truncated: frame {index} declares {declared} bytes but only {available} remain")]
    Truncated {
        index: u32,
        declared: u32,
        available: usize,
    },

    #[error("frame {index} too large: {size} bytes (max {max})")]
    FrameTooLarge { index: u32, size: u32, max: u32 },

    #[error("trailing data: {extra} bytes after last frame")]
    TrailingData { extra: usize },
}

/// Encode frames into the bundle body wire format.
///
/// # Panics
///
/// Panics if `frames` is empty. Use at least one frame.
pub fn encode_body(frames: &[&[u8]]) -> Vec<u8> {
    assert!(
        !frames.is_empty(),
        "encode_body requires at least one frame"
    );
    let total_size = 4 + frames.iter().map(|f| 4 + f.len()).sum::<usize>();
    let mut buf = Vec::with_capacity(total_size);

    #[allow(clippy::cast_possible_truncation)]
    let count = frames.len() as u32;
    buf.extend_from_slice(&count.to_le_bytes());

    for frame in frames {
        #[allow(clippy::cast_possible_truncation)]
        let len = frame.len() as u32;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(frame);
    }

    buf
}

/// Parse a bundle body into individual frames.
pub fn parse_body(bytes: &[u8], max_frames: u32) -> Result<Vec<Vec<u8>>, BodyParseError> {
    if bytes.len() < 4 {
        return Err(BodyParseError::TooShort);
    }

    let count = u32::from_le_bytes(bytes[..4].try_into().expect("slice is exactly 4 bytes"));
    if count == 0 {
        return Err(BodyParseError::EmptyBundle);
    }
    if count > max_frames {
        return Err(BodyParseError::TooManyFrames {
            count,
            max: max_frames,
        });
    }

    let mut offset = 4;
    let mut frames = Vec::with_capacity(count as usize);

    for i in 0..count {
        if offset + 4 > bytes.len() {
            return Err(BodyParseError::Truncated {
                index: i,
                declared: 0,
                available: bytes.len().saturating_sub(offset),
            });
        }
        let frame_len = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("slice is exactly 4 bytes"),
        );
        offset += 4;

        if frame_len > crate::MAX_FRAME_SIZE {
            return Err(BodyParseError::FrameTooLarge {
                index: i,
                size: frame_len,
                max: crate::MAX_FRAME_SIZE,
            });
        }

        let frame_len_usize = frame_len as usize;
        if offset + frame_len_usize > bytes.len() {
            return Err(BodyParseError::Truncated {
                index: i,
                declared: frame_len,
                available: bytes.len().saturating_sub(offset),
            });
        }
        frames.push(bytes[offset..offset + frame_len_usize].to_vec());
        offset += frame_len_usize;
    }

    if offset != bytes.len() {
        return Err(BodyParseError::TrailingData {
            extra: bytes.len() - offset,
        });
    }

    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_single_frame() {
        let encoded = encode_body(&[b"hello"]);
        let frames = parse_body(&encoded, 100).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], b"hello");
    }

    #[test]
    fn round_trip_multiple_frames() {
        let encoded = encode_body(&[b"aaa", b"bbb", b"ccc"]);
        let frames = parse_body(&encoded, 100).unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0], b"aaa");
        assert_eq!(frames[1], b"bbb");
        assert_eq!(frames[2], b"ccc");
    }

    #[test]
    fn round_trip_empty_frame() {
        let encoded = encode_body(&[b""]);
        let frames = parse_body(&encoded, 100).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], b"");
    }

    #[test]
    fn parse_empty_body_fails() {
        assert!(parse_body(b"", 100).is_err());
    }

    #[test]
    fn parse_zero_count_fails() {
        let body = 0_u32.to_le_bytes();
        assert!(parse_body(&body, 100).is_err());
    }

    #[test]
    fn parse_exceeds_max_frames() {
        let encoded = encode_body(&[b"a", b"b", b"c"]);
        let err = parse_body(&encoded, 2).unwrap_err();
        assert!(matches!(
            err,
            BodyParseError::TooManyFrames { count: 3, max: 2 }
        ));
    }

    #[test]
    fn parse_truncated_body() {
        let encoded = encode_body(&[b"hello"]);
        let truncated = &encoded[..6];
        assert!(matches!(
            parse_body(truncated, 100).unwrap_err(),
            BodyParseError::Truncated { .. }
        ));
    }
}
