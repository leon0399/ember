use std::collections::HashMap;

use reme_message::{MessageID, OuterEnvelope};
use tracing::warn;

#[derive(Default)]
pub struct EnvelopeAccumulator {
    by_id: HashMap<MessageID, Vec<OuterEnvelope>>,
    order: Vec<MessageID>,
}

/// Merge envelopes from multiple sources, preserving all distinct variants
/// per `message_id`.
///
/// When two envelopes share a `message_id` but differ in content,
/// all distinct copies are kept. The caller (decryption layer) will
/// naturally reject tampered copies.
pub fn merge_envelopes(
    accumulated: &mut EnvelopeAccumulator,
    incoming: Vec<OuterEnvelope>,
    source_label: &str,
) {
    for envelope in incoming {
        let variants = accumulated
            .by_id
            .entry(envelope.message_id)
            .or_insert_with(|| {
                accumulated.order.push(envelope.message_id);
                Vec::new()
            });

        if variants.iter().any(|v| v == &envelope) {
            continue;
        }

        if !variants.is_empty() {
            warn!(
                message_id = ?envelope.message_id,
                source = source_label,
                existing_variants = variants.len(),
                "Conflicting envelope: same message_id, different content. \
                 Preserving all variants for client-side resolution.",
            );
        }

        variants.push(envelope);
    }
}

/// Flatten the accumulated map into a single `Vec` of all distinct envelopes.
pub fn flatten_variants(mut accumulator: EnvelopeAccumulator) -> Vec<OuterEnvelope> {
    let mut flattened = Vec::new();

    for message_id in accumulator.order {
        if let Some(variants) = accumulator.by_id.remove(&message_id) {
            flattened.extend(variants);
        }
    }

    flattened
}

#[cfg(test)]
mod tests {
    use super::*;
    use reme_identity::RoutingKey;

    fn make_envelope_with_id(message_id: MessageID, ciphertext: Vec<u8>) -> OuterEnvelope {
        let mut env = OuterEnvelope::new(
            RoutingKey::from([0u8; 16]),
            None,
            [0u8; 32],
            [0u8; 16],
            ciphertext,
        );
        env.message_id = message_id;
        env
    }

    #[test]
    fn test_identical_envelopes_deduplicated() {
        let id = MessageID::from_bytes([1; 16]);
        let env1 = make_envelope_with_id(id, vec![0xAA; 50]);
        let env2 = env1.clone();

        let mut map = EnvelopeAccumulator::default();
        merge_envelopes(&mut map, vec![env1], "node-a");
        merge_envelopes(&mut map, vec![env2], "node-b");

        let result = flatten_variants(map);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_conflicting_envelopes_preserved() {
        let id = MessageID::from_bytes([1; 16]);
        let env1 = make_envelope_with_id(id, vec![0xAA; 50]);
        let env2 = make_envelope_with_id(id, vec![0xBB; 50]);
        let expected = vec![env1.clone(), env2.clone()];

        let mut map = EnvelopeAccumulator::default();
        merge_envelopes(&mut map, vec![env1], "node-a");
        merge_envelopes(&mut map, vec![env2], "node-b");

        let result = flatten_variants(map);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_different_message_ids_preserved() {
        let env1 = make_envelope_with_id(MessageID::from_bytes([1; 16]), vec![0xAA; 50]);
        let env2 = make_envelope_with_id(MessageID::from_bytes([2; 16]), vec![0xBB; 50]);

        let mut map = EnvelopeAccumulator::default();
        merge_envelopes(&mut map, vec![env1, env2], "node-a");

        let result = flatten_variants(map);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].message_id, MessageID::from_bytes([1; 16]));
        assert_eq!(result[1].message_id, MessageID::from_bytes([2; 16]));
    }

    #[test]
    fn test_flatten_empty() {
        let map = EnvelopeAccumulator::default();
        let result = flatten_variants(map);
        assert!(result.is_empty());
    }
}
