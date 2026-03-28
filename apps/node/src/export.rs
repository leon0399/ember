//! Node export: dump mailbox messages to a `.reme` bundle file.
//!
//! Unlike client export, the node never decrypts — it stores opaque envelopes
//! and writes them directly as `WirePayload::Message` frames.
//!
//! Tombstones are not exported because the node applies them immediately on
//! receipt (deleting the target message). There is no pending-tombstone store.

use crate::config::{ExportArgs, NodeConfig};
use reme_bundle::BundleWriter;
use reme_identity::RoutingKey;
use reme_message::wire::WirePayload;
use reme_node_core::PersistentMailboxStore;
use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn run_export(
    _config: &NodeConfig,
    store: &PersistentMailboxStore,
    args: &ExportArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check output path
    if args.file.exists() && !args.force {
        return Err(format!(
            "Output file '{}' already exists. Use --force to overwrite.",
            args.file.display()
        )
        .into());
    }

    // Parse --routing-key filter
    let routing_key_filter = args
        .routing_key
        .as_deref()
        .map(parse_routing_key)
        .transpose()?;

    // Parse --since filter
    let since_secs = args.since.as_deref().map(parse_since).transpose()?;

    // Query messages
    let envelopes = store.export_messages(routing_key_filter.as_ref(), since_secs, args.limit)?;

    if envelopes.is_empty() {
        if args.force && args.file.exists() {
            fs::remove_file(&args.file)?;
        }
        eprintln!("Nothing to export.");
        return Ok(());
    }

    // Write bundle
    let file = fs::File::create(&args.file)?;
    let mut writer = BundleWriter::new(file);
    let mut skipped = 0usize;
    for env in &envelopes {
        match WirePayload::Message(env.clone()).encode() {
            Ok(frame) => writer.write_frame(&frame)?,
            Err(e) => {
                eprintln!("Warning: skipping message: {e}");
                skipped += 1;
            }
        }
    }
    writer.finish()?;

    let count = envelopes.len() - skipped;
    eprintln!("Exported {count} messages to {}", args.file.display());
    Ok(())
}

fn parse_routing_key(hex_str: &str) -> Result<RoutingKey, Box<dyn std::error::Error>> {
    if hex_str.len() != 32 {
        return Err(format!(
            "Invalid routing key: expected 32 hex characters (16 bytes), got {}",
            hex_str.len()
        )
        .into());
    }
    let bytes =
        hex::decode(hex_str).map_err(|e| format!("Invalid routing key: bad hex encoding: {e}"))?;
    let bytes: [u8; 16] = bytes
        .try_into()
        .expect("32 hex chars always decode to 16 bytes");
    Ok(RoutingKey::from_bytes(bytes))
}

#[allow(clippy::cast_possible_wrap)] // now is always small enough for i64
fn parse_since(since_str: &str) -> Result<i64, Box<dyn std::error::Error>> {
    let duration: Duration = humantime::parse_duration(since_str)
        .map_err(|e| format!("Invalid --since duration '{since_str}': {e}"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "System time before Unix epoch")?
        .as_secs();
    Ok(now.saturating_sub(duration.as_secs()) as i64)
}
