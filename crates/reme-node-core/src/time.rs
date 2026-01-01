//! Timestamp utilities for `SQLite` storage.
//!
//! `SQLite` uses `i64` for INTEGER columns, while Rust typically uses `u64` for
//! Unix timestamps. This module provides safe conversion utilities.
//!
//! # Safety Rationale
//!
//! Unix timestamps (seconds since 1970-01-01) will not exceed `i64::MAX`
//! (~9.2 quintillion) until approximately year 292 billion. Even millisecond
//! timestamps are safe until year 292 million. Therefore, these conversions
//! are always safe for any practical timestamp value.
//!
//! We use explicit conversion functions rather than raw `as` casts to:
//! 1. Document the safety reasoning in one place
//! 2. Satisfy clippy's `cast_possible_wrap` lint
//! 3. Make the conversion intent explicit in calling code

// Allow cast lints in this module - the whole purpose is safe timestamp casting
#![allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Convert a `u64` timestamp to `i64` for SQLite storage.
///
/// # Panics
///
/// Panics if the value exceeds `i64::MAX`. This cannot happen for any
/// practical Unix timestamp (would require year 292+ billion for seconds,
/// or year 292+ million for milliseconds).
#[inline]
pub fn timestamp_to_i64(value: u64) -> i64 {
    debug_assert!(
        value <= i64::MAX as u64,
        "timestamp overflow: {value} exceeds i64::MAX"
    );
    value as i64
}

/// Convert an optional `u64` timestamp to optional `i64` for SQLite storage.
#[inline]
pub fn timestamp_opt_to_i64(value: Option<u64>) -> Option<i64> {
    value.map(timestamp_to_i64)
}

/// Convert an `i64` from SQLite back to `u64`.
///
/// # Panics
///
/// Panics if the value is negative. SQLite timestamps stored via this module
/// should never be negative.
#[inline]
pub fn i64_to_timestamp(value: i64) -> u64 {
    debug_assert!(value >= 0, "negative timestamp from database: {value}");
    value as u64
}

/// Convert an optional `i64` from SQLite back to optional `u64`.
#[inline]
pub fn i64_to_timestamp_opt(value: Option<i64>) -> Option<u64> {
    value.map(i64_to_timestamp)
}

/// Get the current Unix timestamp in seconds as `i64` for SQLite.
#[inline]
pub fn now_secs_i64() -> i64 {
    timestamp_to_i64(now_secs())
}

/// Get the current Unix timestamp in seconds as `u64`.
#[inline]
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Get the current Unix timestamp in milliseconds as `i64` for SQLite.
#[inline]
pub fn now_ms_i64() -> i64 {
    timestamp_to_i64(now_ms())
}

/// Get the current Unix timestamp in milliseconds as `u64`.
#[inline]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_conversion_roundtrip() {
        let values = [0u64, 1, 1000, 1_700_000_000, i64::MAX as u64];
        for v in values {
            let i = timestamp_to_i64(v);
            let back = i64_to_timestamp(i);
            assert_eq!(v, back);
        }
    }

    #[test]
    fn test_now_functions() {
        let secs = now_secs();
        let secs_i64 = now_secs_i64();
        assert_eq!(secs as i64, secs_i64);

        let ms = now_ms();
        let ms_i64 = now_ms_i64();
        assert_eq!(ms as i64, ms_i64);

        // Sanity check: timestamp should be after 2024
        assert!(secs > 1_700_000_000);
        assert!(ms > 1_700_000_000_000);
    }

    #[test]
    fn test_optional_conversions() {
        assert_eq!(timestamp_opt_to_i64(None), None);
        assert_eq!(timestamp_opt_to_i64(Some(1000)), Some(1000i64));

        assert_eq!(i64_to_timestamp_opt(None), None);
        assert_eq!(i64_to_timestamp_opt(Some(1000i64)), Some(1000u64));
    }
}
