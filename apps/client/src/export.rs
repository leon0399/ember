//! Export pending outbox messages to a `.reme` bundle file.
//!
//! This is a read-only offline operation — no network, no transport.
//! Opens storage directly and writes through [`BundleWriter`].

use crate::config::{AppConfig, ExportArgs};
use reme_bundle::BundleWriter;
use reme_identity::PublicID;
use reme_message::wire::WirePayload;
use reme_message::OuterEnvelope;
use reme_outbox::store::OutboxStore;
use reme_outbox::PendingMessage;
use reme_storage::Storage;
use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Run the export subcommand.
pub fn run_export(config: &AppConfig, args: &ExportArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Check output path
    if args.file.exists() && !args.force {
        return Err(format!(
            "Output file '{}' already exists. Use --force to overwrite.",
            args.file.display()
        )
        .into());
    }

    // Parse --to filter
    let recipient_filter = args.to.as_deref().map(parse_public_id).transpose()?;

    // Parse --since filter
    let since_ms = args.since.as_deref().map(parse_since).transpose()?;

    // Open storage
    let db_path = config.data_dir.join("messages.db");
    if !db_path.exists() {
        eprintln!("Nothing to export (no database found).");
        return Ok(());
    }
    let storage = Storage::open(db_path.to_str().ok_or("Invalid database path (non-UTF8)")?)?;

    // Query outbox
    let messages = query_messages(&storage, recipient_filter.as_ref(), args.include_sent)?;

    // Apply in-memory filters
    let filtered = apply_filters(messages, since_ms, args.limit);

    if filtered.is_empty() {
        // If --force and file exists, remove the stale file
        if args.force && args.file.exists() {
            fs::remove_file(&args.file)?;
        }
        eprintln!("Nothing to export.");
        return Ok(());
    }

    // Encode and write bundle
    let count = write_bundle(&args.file, &filtered)?;

    eprintln!("Exported {count} messages to {}", args.file.display());
    Ok(())
}

/// Parse a hex-encoded public ID string.
fn parse_public_id(hex_str: &str) -> Result<PublicID, Box<dyn std::error::Error>> {
    if hex_str.len() != 64 {
        return Err(format!(
            "Invalid public ID: expected 64 hex characters, got {}",
            hex_str.len()
        )
        .into());
    }
    let bytes =
        hex::decode(hex_str).map_err(|e| format!("Invalid public ID: bad hex encoding: {e}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .expect("64 hex chars always decode to 32 bytes");
    PublicID::try_from_bytes(&bytes)
        .map_err(|_| "Invalid public ID: rejected as low-order point".into())
}

/// Parse a `--since` duration string into epoch milliseconds cutoff.
#[allow(clippy::cast_possible_truncation)] // u128 millis won't exceed u64 in practice
fn parse_since(since_str: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let duration: Duration = humantime::parse_duration(since_str)
        .map_err(|e| format!("Invalid --since duration '{since_str}': {e}"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "System time is before the Unix epoch; check your system clock")?
        .as_millis() as u64;
    Ok(now.saturating_sub(duration.as_millis() as u64))
}

/// Query messages from storage based on filters.
fn query_messages(
    storage: &Storage,
    recipient: Option<&PublicID>,
    include_sent: bool,
) -> Result<Vec<PendingMessage>, Box<dyn std::error::Error>> {
    Ok(match (recipient, include_sent) {
        (Some(r), true) => storage.outbox_get_all_for_recipient(r)?,
        (Some(r), false) => storage.outbox_get_for_recipient(r)?,
        (None, true) => storage.outbox_get_all()?,
        (None, false) => storage.outbox_get_pending()?,
    })
}

/// Apply `--since` and `--limit` filters.
fn apply_filters(
    messages: Vec<PendingMessage>,
    since_ms: Option<u64>,
    limit: Option<usize>,
) -> Vec<PendingMessage> {
    let mut filtered: Vec<PendingMessage> = messages
        .into_iter()
        .filter(|m| since_ms.is_none_or(|cutoff| m.created_at_ms >= cutoff))
        .collect();

    // Messages are already ordered by created_at_ms ASC from storage
    if let Some(n) = limit {
        filtered.truncate(n);
    }

    filtered
}

/// Encode messages as [`WirePayload`] frames and write a bundle.
fn write_bundle(
    path: &std::path::Path,
    messages: &[PendingMessage],
) -> Result<usize, Box<dyn std::error::Error>> {
    let file = fs::File::create(path)?;
    let mut writer = BundleWriter::new(file);

    let mut count = 0;
    for msg in messages {
        match encode_message(msg) {
            Ok(frame) => {
                writer.write_frame(&frame)?;
                count += 1;
            }
            Err(e) => {
                eprintln!(
                    "Warning: skipping message {}: {e}",
                    hex::encode(msg.id.as_bytes())
                );
            }
        }
    }

    writer.finish()?;
    Ok(count)
}

/// Encode a single [`PendingMessage`] as a [`WirePayload`] frame.
fn encode_message(msg: &PendingMessage) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let envelope: OuterEnvelope = postcard::from_bytes(&msg.envelope_bytes)
        .map_err(|e| format!("Failed to deserialize envelope: {e}"))?;
    let wire = WirePayload::Message(envelope);
    Ok(wire
        .encode()
        .map_err(|e| format!("Failed to encode WirePayload: {e}"))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_public_id_valid() {
        // 32 bytes = 64 hex chars
        let hex = "a".repeat(64);
        let result = parse_public_id(&hex);
        // May fail due to low-order check, but should parse hex correctly
        assert!(result.is_ok() || result.unwrap_err().to_string().contains("low-order"));
    }

    #[test]
    fn test_parse_public_id_invalid_hex() {
        // 64 chars but invalid hex
        let result = parse_public_id(&"zz".repeat(32));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("bad hex encoding"));
    }

    #[test]
    fn test_parse_public_id_wrong_length() {
        let result = parse_public_id("aabb");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expected 64 hex characters"));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    fn test_parse_since_valid() {
        let result = parse_since("24h");
        assert!(result.is_ok());
        let cutoff = result.unwrap();
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        // cutoff should be ~24h ago (within 1 second tolerance)
        let expected = now_ms - 24 * 3600 * 1000;
        assert!((cutoff as i64 - expected as i64).unsigned_abs() < 1000);
    }

    #[test]
    fn test_parse_since_invalid() {
        let result = parse_since("not-a-duration");
        assert!(result.is_err());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_apply_filters_since() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let old_msg = make_test_pending(now - 48 * 3600 * 1000); // 48h ago
        let new_msg = make_test_pending(now - 1000); // 1s ago

        let cutoff = now - 24 * 3600 * 1000; // 24h ago
        let filtered = apply_filters(vec![old_msg, new_msg], Some(cutoff), None);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_apply_filters_limit() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let msgs: Vec<_> = (0..10).map(|i| make_test_pending(now + i)).collect();
        let filtered = apply_filters(msgs, None, Some(3));
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_apply_filters_combined() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let old = make_test_pending(now - 48 * 3600 * 1000);
        let recent: Vec<_> = (0..5).map(|i| make_test_pending(now - 1000 + i)).collect();

        let mut all = vec![old];
        all.extend(recent);

        let cutoff = now - 24 * 3600 * 1000;
        let filtered = apply_filters(all, Some(cutoff), Some(3));
        assert_eq!(filtered.len(), 3);
    }

    fn make_test_pending(created_at_ms: u64) -> PendingMessage {
        use reme_message::MessageID;
        use std::collections::HashSet;

        PendingMessage {
            id: MessageID::new(),
            recipient: PublicID::try_from_bytes(&[7u8; 32]).unwrap(),
            content_id: [0u8; 8],
            envelope_bytes: Vec::new(),
            inner_bytes: Vec::new(),
            created_at_ms,
            expires_at_ms: None,
            expired_at_ms: None,
            attempts: Vec::new(),
            next_retry_at_ms: None,
            confirmation: None,
            successful_targets: HashSet::new(),
            tiered_phase: reme_outbox::TieredDeliveryPhase::Urgent,
        }
    }

    /// Integration test: insert messages into real Storage, export to bundle,
    /// read back with `BundleReader`, verify checksum and frame contents.
    #[test]
    fn test_export_round_trip_with_storage() {
        use reme_bundle::BundleReader;
        use reme_identity::Identity;
        use reme_message::{MessageID, OuterEnvelope};
        use std::io::Cursor;
        // Create in-memory storage
        let storage = Storage::open(":memory:").unwrap();

        // Create a valid OuterEnvelope and serialize it
        let bob = Identity::generate();
        let routing_key = bob.public_id().routing_key();
        let envelope = OuterEnvelope::new(routing_key, None, [0u8; 32], [0u8; 16], vec![0u8; 64]);
        let envelope_bytes = postcard::to_allocvec(&envelope).unwrap();

        // Insert 3 messages into outbox
        let recipient = bob.public_id();
        for _ in 0..3 {
            storage
                .outbox_enqueue(
                    recipient,
                    [1u8; 8],
                    MessageID::new(),
                    &envelope_bytes,
                    b"inner",
                    None,
                )
                .unwrap();
        }

        // Query and export
        let messages = query_messages(&storage, None, false).unwrap();
        assert_eq!(messages.len(), 3);

        let out_path =
            std::env::temp_dir().join(format!("reme-test-export-{}.reme", std::process::id()));
        let count = write_bundle(&out_path, &messages).unwrap();
        assert_eq!(count, 3);

        // Read back with BundleReader
        let bundle_bytes = std::fs::read(&out_path).unwrap();
        let _ = std::fs::remove_file(&out_path); // cleanup
        let mut reader = BundleReader::open(Cursor::new(&bundle_bytes)).unwrap();
        assert_eq!(reader.frame_count(), 3);

        // Verify each frame decodes as WirePayload::Message
        let mut frame_count = 0;
        while let Some(frame) = reader.next_frame().unwrap() {
            let payload = WirePayload::decode(&frame).unwrap();
            assert!(matches!(payload, WirePayload::Message(_)));
            frame_count += 1;
        }
        assert_eq!(frame_count, 3);

        // Verify checksum (must consume all frames first)
        let mut reader2 = BundleReader::open(Cursor::new(&bundle_bytes)).unwrap();
        while reader2.next_frame().unwrap().is_some() {}
        reader2.verify_checksum().unwrap();
    }
}
