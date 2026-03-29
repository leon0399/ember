#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_const_for_fn
)]
//! Golden reference tests for postcard wire format.
//!
//! These tests assert the exact byte encoding of each wire type.
//! If any test fails, it means the wire format changed — which is a
//! breaking change that must be intentional and documented.
//!
//! To regenerate golden bytes after an intentional format change,
//! run with `-- --nocapture` to print the new encodings, then
//! update the constants below.

use reme_identity::{PublicID, RoutingKey};
use reme_message::tombstone::SignedAckTombstone;
use reme_message::wire::{WirePayload, WireType};
use reme_message::{
    Content, InnerEnvelope, MessageID, OuterEnvelope, ReceiptContent, ReceiptKind, TextContent,
    CURRENT_VERSION,
};

// ============================================
// Deterministic test data
// ============================================

/// Fixed 32-byte public key (not a real key — just deterministic bytes for encoding tests)
const TEST_PUBKEY: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
];

/// Fixed 16-byte routing key
const TEST_ROUTING_KEY: [u8; 16] = [
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
];

/// Fixed 16-byte message ID
const TEST_MESSAGE_ID: [u8; 16] = [
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
];

/// Fixed 32-byte ephemeral key
const TEST_EPHEMERAL_KEY: [u8; 32] = [
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
];

/// Fixed 16-byte ack hash
const TEST_ACK_HASH: [u8; 16] = [
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
];

/// Fixed 16-byte ack secret
const TEST_ACK_SECRET: [u8; 16] = [
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
];

/// Fixed 64-byte signature (all 0x42)
const TEST_SIGNATURE: [u8; 64] = [0x42; 64];

// ============================================
// Helper: construct deterministic instances
// ============================================

fn make_outer_envelope(ciphertext: &[u8]) -> OuterEnvelope {
    OuterEnvelope {
        version: CURRENT_VERSION,
        routing_key: RoutingKey::from(TEST_ROUTING_KEY),
        timestamp_hours: 480_000, // ~2024-10 in hours since epoch
        ttl_hours: Some(168),     // 1 week
        message_id: MessageID::from_bytes(TEST_MESSAGE_ID),
        ephemeral_key: TEST_EPHEMERAL_KEY,
        ack_hash: TEST_ACK_HASH,
        inner_ciphertext: ciphertext.to_vec(),
    }
}

fn make_inner_text(body: &str) -> InnerEnvelope {
    InnerEnvelope {
        from: PublicID::from_bytes_unchecked(&TEST_PUBKEY),
        created_at_ms: 1_700_000_000_000, // 2023-11-14T22:13:20Z
        content: Content::Text(TextContent {
            body: body.to_string(),
        }),
        prev_self: None,
        observed_heads: Vec::new(),
        epoch: 0,
        flags: 0,
    }
}

fn make_inner_receipt() -> InnerEnvelope {
    InnerEnvelope {
        from: PublicID::from_bytes_unchecked(&TEST_PUBKEY),
        created_at_ms: 1_700_000_000_000,
        content: Content::Receipt(ReceiptContent {
            target_message_id: MessageID::from_bytes(TEST_MESSAGE_ID),
            kind: ReceiptKind::Delivered,
        }),
        prev_self: None,
        observed_heads: Vec::new(),
        epoch: 0,
        flags: 0,
    }
}

fn make_inner_with_dag() -> InnerEnvelope {
    InnerEnvelope {
        from: PublicID::from_bytes_unchecked(&TEST_PUBKEY),
        created_at_ms: 1_700_000_000_000,
        content: Content::Text(TextContent {
            body: "dag".to_string(),
        }),
        prev_self: Some([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
        observed_heads: vec![
            [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18],
            [0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28],
        ],
        epoch: 7,
        flags: 0,
    }
}

fn make_tombstone() -> SignedAckTombstone {
    SignedAckTombstone {
        message_id: MessageID::from_bytes(TEST_MESSAGE_ID),
        ack_secret: TEST_ACK_SECRET,
        signature: TEST_SIGNATURE,
    }
}

/// Print hex of bytes (for regenerating golden constants)
fn hex_dump(label: &str, bytes: &[u8]) {
    print!("const {label}: &[u8] = &[");
    for (i, b) in bytes.iter().enumerate() {
        if i % 16 == 0 {
            print!("\n    ");
        }
        print!("0x{b:02X}, ");
    }
    println!("\n];");
    println!("// length: {}", bytes.len());
}

// ============================================
// Golden byte constants
//
// To regenerate: run `cargo test -p reme-message --test golden_wire_format -- golden_generate --nocapture`
// ============================================

/// `Version { major: 0, minor: 0 }` — 2 raw bytes, no framing
const GOLDEN_VERSION: &[u8] = &[0x00, 0x00];

/// `OuterEnvelope` with 4-byte ciphertext `[0xDE, 0xAD, 0xBE, 0xEF]`
#[rustfmt::skip]
const GOLDEN_OUTER_ENVELOPE: &[u8] = &[
    // version (2 bytes)
    0x00, 0x00,
    // routing_key (16 bytes)
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    // timestamp_hours: 480_000 as varint
    0x80, 0xA6, 0x1D,
    // ttl_hours: Some(168) — 0x01 (Some) + 168 as varint
    0x01, 0xA8, 0x01,
    // message_id (16 bytes)
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    // ephemeral_key (32 bytes)
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    // ack_hash (16 bytes)
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    // inner_ciphertext: length varint (4) + 4 bytes
    0x04, 0xDE, 0xAD, 0xBE, 0xEF,
];

/// `InnerEnvelope` with `Content::Text("hi")`
#[rustfmt::skip]
const GOLDEN_INNER_TEXT: &[u8] = &[
    // from: PublicID (32 bytes)
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    // created_at_ms: 1_700_000_000_000 as varint
    0x80, 0xD0, 0x95, 0xFF, 0xBC, 0x31,
    // Content::Text variant index (0) as varint
    0x00,
    // TextContent.body: length varint (2) + "hi"
    0x02, 0x68, 0x69,
    // prev_self: None (0x00)
    0x00,
    // observed_heads: empty vec, length varint (0)
    0x00,
    // epoch: 0 as varint
    0x00,
    // flags: 0
    0x00,
];

/// `InnerEnvelope` with `Content::Receipt(Delivered)`
#[rustfmt::skip]
const GOLDEN_INNER_RECEIPT: &[u8] = &[
    // from: PublicID (32 bytes)
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    // created_at_ms: 1_700_000_000_000 as varint
    0x80, 0xD0, 0x95, 0xFF, 0xBC, 0x31,
    // Content::Receipt variant index (1) as varint
    0x01,
    // target_message_id (16 bytes)
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    // ReceiptKind::Delivered variant index (0)
    0x00,
    // prev_self: None
    0x00,
    // observed_heads: empty
    0x00,
    // epoch: 0
    0x00,
    // flags: 0
    0x00,
];

/// `InnerEnvelope` with DAG fields populated
#[rustfmt::skip]
const GOLDEN_INNER_WITH_DAG: &[u8] = &[
    // from: PublicID (32 bytes)
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    // created_at_ms
    0x80, 0xD0, 0x95, 0xFF, 0xBC, 0x31,
    // Content::Text("dag")
    0x00, 0x03, 0x64, 0x61, 0x67,
    // prev_self: Some([01..08])
    0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    // observed_heads: 2 entries
    0x02,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    // epoch: 7
    0x07,
    // flags: 0
    0x00,
];

/// `SignedAckTombstone` (96 bytes: 16 + 16 + 64)
#[rustfmt::skip]
const GOLDEN_TOMBSTONE: &[u8] = &[
    // message_id (16 bytes)
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    // ack_secret (16 bytes)
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
    // signature (64 bytes as two [u8; 32] halves — postcard tuple encoding, no length prefix)
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
];

// ============================================
// Generator test — run with --nocapture to print golden bytes
// ============================================

/// Run with: `cargo test -p reme-message --test golden_wire_format golden_generate -- --ignored --nocapture`
#[test]
#[ignore = "generator helper — prints golden bytes, does not assert"]
fn golden_generate() {
    println!("\n=== Golden byte generator (copy into constants above) ===\n");

    let version_bytes = postcard::to_allocvec(&CURRENT_VERSION).unwrap();
    hex_dump("GOLDEN_VERSION", &version_bytes);

    let outer = make_outer_envelope(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let outer_bytes = postcard::to_allocvec(&outer).unwrap();
    hex_dump("GOLDEN_OUTER_ENVELOPE", &outer_bytes);

    let inner_text = make_inner_text("hi");
    let inner_text_bytes = postcard::to_allocvec(&inner_text).unwrap();
    hex_dump("GOLDEN_INNER_TEXT", &inner_text_bytes);

    let inner_receipt = make_inner_receipt();
    let inner_receipt_bytes = postcard::to_allocvec(&inner_receipt).unwrap();
    hex_dump("GOLDEN_INNER_RECEIPT", &inner_receipt_bytes);

    let inner_dag = make_inner_with_dag();
    let inner_dag_bytes = postcard::to_allocvec(&inner_dag).unwrap();
    hex_dump("GOLDEN_INNER_WITH_DAG", &inner_dag_bytes);

    let tombstone = make_tombstone();
    let tombstone_bytes = postcard::to_allocvec(&tombstone).unwrap();
    hex_dump("GOLDEN_TOMBSTONE", &tombstone_bytes);
}

// ============================================
// Encoding stability tests
// ============================================

#[test]
fn golden_version_encoding() {
    let bytes = postcard::to_allocvec(&CURRENT_VERSION).unwrap();
    assert_eq!(bytes, GOLDEN_VERSION, "Version encoding changed");
}

#[test]
fn golden_outer_envelope_encoding() {
    let outer = make_outer_envelope(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let bytes = postcard::to_allocvec(&outer).unwrap();
    assert_eq!(
        bytes, GOLDEN_OUTER_ENVELOPE,
        "OuterEnvelope encoding changed"
    );
}

#[test]
fn golden_inner_text_encoding() {
    let inner = make_inner_text("hi");
    let bytes = postcard::to_allocvec(&inner).unwrap();
    assert_eq!(
        bytes, GOLDEN_INNER_TEXT,
        "InnerEnvelope (text) encoding changed"
    );
}

#[test]
fn golden_inner_receipt_encoding() {
    let inner = make_inner_receipt();
    let bytes = postcard::to_allocvec(&inner).unwrap();
    assert_eq!(
        bytes, GOLDEN_INNER_RECEIPT,
        "InnerEnvelope (receipt) encoding changed"
    );
}

#[test]
fn golden_inner_with_dag_encoding() {
    let inner = make_inner_with_dag();
    let bytes = postcard::to_allocvec(&inner).unwrap();
    assert_eq!(
        bytes, GOLDEN_INNER_WITH_DAG,
        "InnerEnvelope (with DAG) encoding changed"
    );
}

#[test]
fn golden_tombstone_encoding() {
    let tombstone = make_tombstone();
    let bytes = postcard::to_allocvec(&tombstone).unwrap();
    assert_eq!(
        bytes, GOLDEN_TOMBSTONE,
        "SignedAckTombstone encoding changed"
    );
}

// ============================================
// Decoding stability tests — golden bytes decode to expected values
// ============================================

#[test]
fn golden_outer_envelope_decodes() {
    let outer: OuterEnvelope = postcard::from_bytes(GOLDEN_OUTER_ENVELOPE).unwrap();

    assert_eq!(outer.version, CURRENT_VERSION);
    assert_eq!(*outer.routing_key, TEST_ROUTING_KEY);
    assert_eq!(outer.timestamp_hours, 480_000);
    assert_eq!(outer.ttl_hours, Some(168));
    assert_eq!(*outer.message_id.as_bytes(), TEST_MESSAGE_ID);
    assert_eq!(outer.ephemeral_key, TEST_EPHEMERAL_KEY);
    assert_eq!(outer.ack_hash, TEST_ACK_HASH);
    assert_eq!(outer.inner_ciphertext, &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn golden_inner_text_decodes() {
    let inner: InnerEnvelope = postcard::from_bytes(GOLDEN_INNER_TEXT).unwrap();

    assert_eq!(inner.from.to_bytes(), TEST_PUBKEY);
    assert_eq!(inner.created_at_ms, 1_700_000_000_000);
    match &inner.content {
        Content::Text(t) => assert_eq!(t.body, "hi"),
        other => panic!("Expected Text, got {other:?}"),
    }
    assert_eq!(inner.prev_self, None);
    assert!(inner.observed_heads.is_empty());
    assert_eq!(inner.epoch, 0);
    assert_eq!(inner.flags, 0);
}

#[test]
fn golden_inner_receipt_decodes() {
    let inner: InnerEnvelope = postcard::from_bytes(GOLDEN_INNER_RECEIPT).unwrap();

    match &inner.content {
        Content::Receipt(r) => {
            assert_eq!(*r.target_message_id.as_bytes(), TEST_MESSAGE_ID);
            assert!(matches!(r.kind, ReceiptKind::Delivered));
        }
        other => panic!("Expected Receipt, got {other:?}"),
    }
}

#[test]
fn golden_inner_dag_decodes() {
    let inner: InnerEnvelope = postcard::from_bytes(GOLDEN_INNER_WITH_DAG).unwrap();

    assert_eq!(
        inner.prev_self,
        Some([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    );
    assert_eq!(inner.observed_heads.len(), 2);
    assert_eq!(
        inner.observed_heads[0],
        [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
    );
    assert_eq!(
        inner.observed_heads[1],
        [0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28]
    );
    assert_eq!(inner.epoch, 7);
}

#[test]
fn golden_tombstone_decodes() {
    let tombstone: SignedAckTombstone = postcard::from_bytes(GOLDEN_TOMBSTONE).unwrap();

    assert_eq!(*tombstone.message_id.as_bytes(), TEST_MESSAGE_ID);
    assert_eq!(tombstone.ack_secret, TEST_ACK_SECRET);
    assert_eq!(tombstone.signature, TEST_SIGNATURE);
}

// ============================================
// Wire framing tests — type discriminator + payload
// ============================================

#[test]
fn golden_wire_message_framing() {
    let outer = make_outer_envelope(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let payload = WirePayload::Message(outer);
    let wire_bytes = payload.encode().unwrap();

    // First byte is the type discriminator
    assert_eq!(wire_bytes[0], WireType::Message as u8);
    assert_eq!(wire_bytes[0], 0x00);

    // Remaining bytes are the postcard-encoded OuterEnvelope
    assert_eq!(&wire_bytes[1..], GOLDEN_OUTER_ENVELOPE);

    // Roundtrip through WirePayload::decode
    let decoded = WirePayload::decode(&wire_bytes).unwrap();
    match decoded {
        WirePayload::Message(e) => {
            assert_eq!(*e.message_id.as_bytes(), TEST_MESSAGE_ID);
            assert_eq!(e.inner_ciphertext, &[0xDE, 0xAD, 0xBE, 0xEF]);
        }
        WirePayload::AckTombstone(_) => panic!("Expected Message"),
    }
}

#[test]
fn golden_wire_tombstone_framing() {
    let tombstone = make_tombstone();
    let payload = WirePayload::AckTombstone(tombstone);
    let wire_bytes = payload.encode().unwrap();

    // First byte is the type discriminator
    assert_eq!(wire_bytes[0], WireType::AckTombstone as u8);
    assert_eq!(wire_bytes[0], 0x02);

    // Remaining bytes are the postcard-encoded tombstone
    assert_eq!(&wire_bytes[1..], GOLDEN_TOMBSTONE);

    // Total: 1 discriminator + 96 tombstone = 97
    assert_eq!(wire_bytes.len(), 97);

    // Roundtrip
    let decoded = WirePayload::decode(&wire_bytes).unwrap();
    match decoded {
        WirePayload::AckTombstone(t) => {
            assert_eq!(*t.message_id.as_bytes(), TEST_MESSAGE_ID);
            assert_eq!(t.ack_secret, TEST_ACK_SECRET);
        }
        WirePayload::Message(_) => panic!("Expected AckTombstone"),
    }
}

// ============================================
// Size stability tests
// ============================================

#[test]
fn golden_sizes() {
    // Version: 2 bytes (two u8s, no varint overhead)
    assert_eq!(GOLDEN_VERSION.len(), 2);

    // Tombstone: exactly 96 bytes (16 + 16 + 64)
    assert_eq!(GOLDEN_TOMBSTONE.len(), 96);

    // OuterEnvelope with 4-byte ciphertext: fixed overhead check
    // 2 (version) + 16 (routing_key) + 3 (timestamp varint) + 3 (ttl option+varint)
    // + 16 (message_id) + 32 (ephemeral) + 16 (ack_hash) + 1 (ciphertext len) + 4 (ciphertext)
    // = 93 bytes
    assert_eq!(GOLDEN_OUTER_ENVELOPE.len(), 93);
}

// ============================================
// Compatibility scenarios
//
// These tests verify that field variants and edge cases
// that a "stored" or "in-transit" message might use will
// continue to decode correctly after code changes.
// ============================================

/// `OuterEnvelope` with `ttl_hours: None` — older clients or configs
/// that don't set TTL should still decode.
#[test]
fn compat_outer_envelope_no_ttl() {
    let outer = OuterEnvelope {
        version: CURRENT_VERSION,
        routing_key: RoutingKey::from(TEST_ROUTING_KEY),
        timestamp_hours: 480_000,
        ttl_hours: None,
        message_id: MessageID::from_bytes(TEST_MESSAGE_ID),
        ephemeral_key: TEST_EPHEMERAL_KEY,
        ack_hash: TEST_ACK_HASH,
        inner_ciphertext: vec![0xFF],
    };

    let bytes = postcard::to_allocvec(&outer).unwrap();
    let decoded: OuterEnvelope = postcard::from_bytes(&bytes).unwrap();

    assert_eq!(decoded.ttl_hours, None);
    assert_eq!(decoded.inner_ciphertext, &[0xFF]);

    // None encodes as 0x00 (1 byte) vs Some(168) as 0x01 0xA8 0x01 (3 bytes)
    assert!(bytes.len() < GOLDEN_OUTER_ENVELOPE.len());
}

/// `ReceiptKind::Read` variant — the golden tests only cover `Delivered`.
#[test]
fn compat_receipt_read_variant() {
    let inner = InnerEnvelope {
        from: PublicID::from_bytes_unchecked(&TEST_PUBKEY),
        created_at_ms: 1_700_000_000_000,
        content: Content::Receipt(ReceiptContent {
            target_message_id: MessageID::from_bytes(TEST_MESSAGE_ID),
            kind: ReceiptKind::Read,
        }),
        prev_self: None,
        observed_heads: Vec::new(),
        epoch: 0,
        flags: 0,
    };

    let bytes = postcard::to_allocvec(&inner).unwrap();
    let decoded: InnerEnvelope = postcard::from_bytes(&bytes).unwrap();

    match &decoded.content {
        Content::Receipt(r) => {
            assert!(matches!(r.kind, ReceiptKind::Read));
            assert_eq!(*r.target_message_id.as_bytes(), TEST_MESSAGE_ID);
        }
        other => panic!("Expected Receipt, got {other:?}"),
    }
}

/// Detached message (`FLAG_DETACHED`) — used on BLE/LoRa constrained transports.
/// These have no DAG linkage but must still roundtrip.
#[test]
fn compat_detached_message() {
    let inner = InnerEnvelope {
        from: PublicID::from_bytes_unchecked(&TEST_PUBKEY),
        created_at_ms: 1_700_000_000_000,
        content: Content::Text(TextContent {
            body: "ble".to_string(),
        }),
        prev_self: None,
        observed_heads: Vec::new(),
        epoch: 0,
        flags: reme_message::FLAG_DETACHED,
    };

    let bytes = postcard::to_allocvec(&inner).unwrap();
    let decoded: InnerEnvelope = postcard::from_bytes(&bytes).unwrap();

    assert!(decoded.is_detached());
    assert_eq!(decoded.flags, reme_message::FLAG_DETACHED);
}

/// Empty ciphertext — edge case for `OuterEnvelope` with zero-length payload.
#[test]
fn compat_empty_ciphertext() {
    let outer = make_outer_envelope(&[]);
    let bytes = postcard::to_allocvec(&outer).unwrap();
    let decoded: OuterEnvelope = postcard::from_bytes(&bytes).unwrap();

    assert!(decoded.inner_ciphertext.is_empty());
}

/// Large ciphertext — varint length encoding must handle multi-byte lengths.
#[test]
fn compat_large_ciphertext() {
    let big_payload = vec![0xAB; 1024];
    let outer = make_outer_envelope(&big_payload);
    let bytes = postcard::to_allocvec(&outer).unwrap();
    let decoded: OuterEnvelope = postcard::from_bytes(&bytes).unwrap();

    assert_eq!(decoded.inner_ciphertext.len(), 1024);
    assert_eq!(decoded.inner_ciphertext, big_payload);
}

/// `postcard::from_bytes` does NOT reject trailing bytes — it reads what
/// it needs and ignores the rest. This is known postcard behavior.
/// Wire-level framing (`WirePayload`) handles length boundaries instead.
#[test]
fn compat_from_bytes_ignores_trailing() {
    let mut bytes = GOLDEN_OUTER_ENVELOPE.to_vec();
    bytes.push(0x00); // append garbage

    // postcard succeeds — it consumed only what it needed
    let decoded: OuterEnvelope = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(*decoded.message_id.as_bytes(), TEST_MESSAGE_ID);
}

/// `WirePayload::decode` rejects unknown type discriminators.
#[test]
fn compat_rejects_unknown_wire_type() {
    let mut bytes = vec![0x03]; // unknown discriminator
    bytes.extend_from_slice(GOLDEN_TOMBSTONE);

    let result = WirePayload::decode(&bytes);
    assert!(result.is_err());
}

/// `WirePayload::decode` rejects the removed V1 tombstone type (0x01).
#[test]
fn compat_rejects_v1_tombstone_type() {
    let mut bytes = vec![0x01]; // removed V1 type
    bytes.extend_from_slice(GOLDEN_TOMBSTONE);

    let result = WirePayload::decode(&bytes);
    assert!(result.is_err());
}
