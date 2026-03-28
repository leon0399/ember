//! Node import: read a `.reme` bundle and store envelopes / apply tombstones.
//!
//! Messages are stored via `MailboxStore::enqueue` (INSERT OR IGNORE = idempotent).
//! Tombstones are verified against the stored `ack_hash` before deletion.

use crate::config::{ImportArgs, NodeConfig};
use reme_bundle::BundleReader;
use reme_message::wire::WirePayload;
use reme_node_core::{MailboxStore, PersistentMailboxStore};
use std::fs::File;

#[derive(Default)]
struct ImportSummary {
    stored: usize,
    duplicates: usize,
    tombstones_applied: usize,
    tombstones_skipped: usize,
    errors: usize,
}

pub fn run_import(
    _config: &NodeConfig,
    store: &PersistentMailboxStore,
    args: &ImportArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    if !args.file.exists() {
        return Err(format!("Bundle file '{}' not found.", args.file.display()).into());
    }

    // Read and verify bundle
    let frames = read_bundle(&args.file)?;
    if frames.is_empty() {
        eprintln!("Nothing to import (empty bundle).");
        return Ok(());
    }

    let mut summary = ImportSummary::default();
    for (i, frame) in frames.iter().enumerate() {
        match WirePayload::decode(frame) {
            Ok(WirePayload::Message(envelope)) => {
                // Check for duplicate first
                match store.has_message(&envelope.routing_key, &envelope.message_id) {
                    Ok(true) => {
                        summary.duplicates += 1;
                        continue;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        eprintln!("Warning: frame {i}: duplicate check failed: {e}");
                        summary.errors += 1;
                        continue;
                    }
                }
                match store.enqueue(envelope.routing_key, envelope) {
                    Ok(()) => summary.stored += 1,
                    Err(e) => {
                        eprintln!("Warning: frame {i}: failed to store: {e}");
                        summary.errors += 1;
                    }
                }
            }
            Ok(WirePayload::AckTombstone(tombstone)) => {
                match store.get_ack_hash(&tombstone.message_id) {
                    Ok(Some(ack_hash)) => {
                        if tombstone.verify_authorization(&ack_hash) {
                            match store.delete_message(&tombstone.message_id) {
                                Ok(_) => summary.tombstones_applied += 1,
                                Err(e) => {
                                    eprintln!("Warning: frame {i}: tombstone delete failed: {e}");
                                    summary.errors += 1;
                                }
                            }
                        } else {
                            eprintln!("Warning: frame {i}: tombstone authorization failed");
                            summary.errors += 1;
                        }
                    }
                    Ok(None) => {
                        // Message not found or already deleted -- skip silently
                        summary.tombstones_skipped += 1;
                    }
                    Err(e) => {
                        eprintln!("Warning: frame {i}: tombstone lookup failed: {e}");
                        summary.errors += 1;
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: frame {i}: failed to decode: {e}");
                summary.errors += 1;
            }
        }
    }

    print_summary(&summary);
    Ok(())
}

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

fn print_summary(s: &ImportSummary) {
    let mut parts = Vec::new();
    if s.stored > 0 {
        parts.push(format!("{} stored", s.stored));
    }
    if s.duplicates > 0 {
        parts.push(format!("{} duplicates skipped", s.duplicates));
    }
    if s.tombstones_applied > 0 {
        parts.push(format!("{} tombstones applied", s.tombstones_applied));
    }
    if s.tombstones_skipped > 0 {
        parts.push(format!(
            "{} tombstones skipped (not found)",
            s.tombstones_skipped
        ));
    }
    if s.errors > 0 {
        parts.push(format!("{} errors", s.errors));
    }
    if parts.is_empty() {
        eprintln!("Nothing to import.");
    } else {
        eprintln!("Import complete: {}", parts.join(", "));
    }
}
