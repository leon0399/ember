//! Import messages from a `.reme` bundle file.
//!
//! Reads a bundle, decodes each frame, and processes self-addressed messages
//! via `Client::process_message_local`. Messages for other routing keys are
//! skipped. Duplicate messages are deduplicated and counted in the summary.
//! Conflicting duplicates (same ID, different content) emit a warning.

use crate::config::{AppConfig, ImportArgs};
use reme_bundle::BundleReader;
use reme_core::{Client, ClientError};
use reme_message::wire::WirePayload;
use reme_message::OuterEnvelope;
use reme_message::SignedAckTombstone;
use reme_storage::Storage;
use reme_transport::{Transport, TransportError};
use std::fs::File;
use std::sync::Arc;

/// No-op transport for offline import (Client requires a transport but import never sends).
struct NoopTransport;

#[async_trait::async_trait]
impl Transport for NoopTransport {
    async fn submit_message(&self, _: OuterEnvelope) -> Result<(), TransportError> {
        Ok(())
    }
    async fn submit_ack_tombstone(&self, _: SignedAckTombstone) -> Result<(), TransportError> {
        Ok(())
    }
}

/// Import summary counters.
#[derive(Default)]
struct ImportSummary {
    imported: usize,
    duplicates: usize,
    skipped_not_for_us: usize,
    skipped_tombstones: usize,
    errors: usize,
}

/// Run the import subcommand.
pub fn run_import(config: &AppConfig, args: &ImportArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Check input file exists
    if !args.file.exists() {
        return Err(format!("Bundle file '{}' not found.", args.file.display()).into());
    }

    // Load identity
    let identity_path = config.data_dir.join("identity.reme");
    if !identity_path.exists() {
        return Err("No identity found. Run `reme` first to create one.".into());
    }
    let identity = crate::identity::load_existing(&identity_path)?;

    // Read and verify bundle (before any DB writes)
    let frames = read_bundle(&args.file)?;

    if frames.is_empty() {
        eprintln!("Nothing to import (empty bundle).");
        return Ok(());
    }

    // Open storage and create client
    std::fs::create_dir_all(&config.data_dir)?;
    let db_path = config.data_dir.join("messages.db");
    let storage = Storage::open(db_path.to_str().ok_or("Invalid database path (non-UTF8)")?)?;
    let client = Client::new(identity, Arc::new(NoopTransport), storage);

    // Process each frame
    let summary = process_frames(&client, &frames);

    // Print summary
    print_summary(&summary);

    Ok(())
}

/// Read all frames from a bundle file and verify checksum.
fn read_bundle(path: &std::path::Path) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let mut reader = BundleReader::open(file)?;

    let mut frames = Vec::new();
    while let Some(frame) = reader.next_frame()? {
        frames.push(frame);
    }

    reader.verify_checksum()?;
    Ok(frames)
}

/// Process decoded frames through the client.
fn process_frames<T: Transport>(client: &Client<T>, frames: &[Vec<u8>]) -> ImportSummary {
    let mut summary = ImportSummary::default();

    for (i, frame) in frames.iter().enumerate() {
        match WirePayload::decode(frame) {
            Ok(WirePayload::Message(envelope)) => {
                process_message(client, &envelope, i, &mut summary);
            }
            Ok(WirePayload::AckTombstone(_)) => {
                summary.skipped_tombstones += 1;
            }
            Err(e) => {
                eprintln!("Warning: frame {i}: failed to decode WirePayload: {e}");
                summary.errors += 1;
            }
        }
    }

    summary
}

/// Process a single message envelope.
fn process_message<T: Transport>(
    client: &Client<T>,
    envelope: &OuterEnvelope,
    frame_index: usize,
    summary: &mut ImportSummary,
) {
    match client.process_message_local(envelope) {
        Ok(processed) if processed.is_duplicate => {
            summary.duplicates += 1;
        }
        Ok(_) => {
            summary.imported += 1;
        }
        Err(ClientError::WrongRecipient) => {
            summary.skipped_not_for_us += 1;
        }
        Err(ClientError::ConflictingDuplicate(id)) => {
            eprintln!(
                "Warning: frame {frame_index}: conflicting duplicate for message {}",
                hex::encode(id.as_bytes())
            );
            summary.errors += 1;
        }
        Err(e) => {
            eprintln!("Warning: frame {frame_index}: {e}");
            summary.errors += 1;
        }
    }
}

/// Print the import summary to stderr.
fn print_summary(s: &ImportSummary) {
    let total = s.imported + s.duplicates + s.skipped_not_for_us + s.skipped_tombstones + s.errors;

    if s.imported == 0 && s.duplicates == 0 && s.errors == 0 {
        eprintln!("No messages for this identity ({total} frames processed).");
        return;
    }

    let mut parts = vec![format!("{} imported", s.imported)];
    if s.duplicates > 0 {
        parts.push(format!("{} duplicates", s.duplicates));
    }
    if s.skipped_not_for_us > 0 {
        parts.push(format!("{} not for us", s.skipped_not_for_us));
    }
    if s.skipped_tombstones > 0 {
        parts.push(format!("{} tombstones skipped", s.skipped_tombstones));
    }
    if s.errors > 0 {
        parts.push(format!("{} errors", s.errors));
    }
    eprintln!("Import complete: {}", parts.join(", "));
}

#[cfg(test)]
mod tests {
    use super::*;
    use reme_bundle::BundleWriter;
    use reme_identity::Identity;
    use reme_message::MessageID;
    use reme_message::OuterEnvelope;
    use std::io::Cursor;

    fn make_test_envelope(identity: &Identity) -> OuterEnvelope {
        let routing_key = identity.public_id().routing_key();
        OuterEnvelope::new(routing_key, None, [0u8; 32], [0u8; 16], vec![0u8; 64])
    }

    fn make_bundle_bytes(envelopes: &[&OuterEnvelope]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut writer = BundleWriter::new(&mut buf);
        for env in envelopes {
            let wire = WirePayload::Message((*env).clone());
            let frame = wire.encode().unwrap();
            writer.write_frame(&frame).unwrap();
        }
        writer.finish().unwrap();
        buf
    }

    fn read_frames_from_bytes(data: &[u8]) -> Vec<Vec<u8>> {
        let mut reader = BundleReader::open(Cursor::new(data)).unwrap();
        let mut frames = Vec::new();
        while let Some(f) = reader.next_frame().unwrap() {
            frames.push(f);
        }
        reader.verify_checksum().unwrap();
        frames
    }

    #[test]
    fn test_read_bundle_and_verify() {
        let alice = Identity::generate();
        let env = make_test_envelope(&alice);
        let bundle = make_bundle_bytes(&[&env]);

        let frames = read_frames_from_bytes(&bundle);

        assert_eq!(frames.len(), 1);
        let payload = WirePayload::decode(&frames[0]).unwrap();
        assert!(matches!(payload, WirePayload::Message(_)));
    }

    #[test]
    fn test_import_self_addressed_messages() {
        let alice = Identity::generate();
        let env1 = make_test_envelope(&alice);
        let env2 = make_test_envelope(&alice);

        let storage = Storage::open(":memory:").unwrap();
        let client = Client::new(alice, Arc::new(NoopTransport), storage);

        let frames_data = make_bundle_bytes(&[&env1, &env2]);
        let frames = read_frames_from_bytes(&frames_data);

        let summary = process_frames(&client, &frames);
        // These are dummy envelopes with zero ephemeral key -- decryption will fail
        // but the routing key check passes, so they count as errors not "not for us"
        assert_eq!(summary.skipped_not_for_us, 0);
    }

    #[test]
    fn test_import_wrong_recipient_skipped() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        // Create envelope for bob
        let env = make_test_envelope(&bob);

        let storage = Storage::open(":memory:").unwrap();
        let client = Client::new(alice, Arc::new(NoopTransport), storage);

        let frames_data = make_bundle_bytes(&[&env]);
        let frames = read_frames_from_bytes(&frames_data);

        let summary = process_frames(&client, &frames);
        assert_eq!(summary.skipped_not_for_us, 1);
        assert_eq!(summary.imported, 0);
    }

    #[test]
    fn test_import_idempotent() {
        let alice = Identity::generate();
        let env = make_test_envelope(&alice);

        let storage = Storage::open(":memory:").unwrap();
        let client = Client::new(alice, Arc::new(NoopTransport), storage);

        let frames_data = make_bundle_bytes(&[&env]);

        // Import twice
        for _ in 0..2 {
            let frames = read_frames_from_bytes(&frames_data);
            let _summary = process_frames(&client, &frames);
        }
        // Should not panic or error -- idempotent
    }

    #[test]
    fn test_tombstone_frames_skipped() {
        let alice = Identity::generate();
        let tombstone = SignedAckTombstone::new(
            MessageID::new(),
            [42u8; 16],
            &alice.x25519_secret().to_bytes(),
        );
        let wire = WirePayload::AckTombstone(tombstone);
        let frame = wire.encode().unwrap();

        let mut buf = Vec::new();
        let mut writer = BundleWriter::new(&mut buf);
        writer.write_frame(&frame).unwrap();
        writer.finish().unwrap();

        let frames = read_frames_from_bytes(&buf);

        let storage = Storage::open(":memory:").unwrap();
        let client = Client::new(alice, Arc::new(NoopTransport), storage);

        let summary = process_frames(&client, &frames);
        assert_eq!(summary.skipped_tombstones, 1);
        assert_eq!(summary.imported, 0);
    }
}
