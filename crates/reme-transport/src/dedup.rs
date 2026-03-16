use std::collections::HashMap;

use reme_message::{MessageID, OuterEnvelope};
use tracing::warn;

/// Merge envelopes from multiple sources, preserving all distinct variants
/// per `message_id`.
///
/// When two envelopes share a `message_id` but differ in content,
/// all distinct copies are kept. The caller (decryption layer) will
/// naturally reject tampered copies.
pub fn merge_envelopes(
    accumulated: &mut HashMap<MessageID, Vec<OuterEnvelope>>,
    incoming: Vec<OuterEnvelope>,
    source_label: &str,
) {
    for envelope in incoming {
        let variants = accumulated.entry(envelope.message_id).or_default();

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
pub fn flatten_variants(map: HashMap<MessageID, Vec<OuterEnvelope>>) -> Vec<OuterEnvelope> {
    map.into_values().flatten().collect()
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

        let mut map = HashMap::new();
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

        let mut map = HashMap::new();
        merge_envelopes(&mut map, vec![env1], "node-a");
        merge_envelopes(&mut map, vec![env2], "node-b");

        let result = flatten_variants(map);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].message_id, result[1].message_id);
    }

    #[test]
    fn test_different_message_ids_preserved() {
        let env1 = make_envelope_with_id(MessageID::from_bytes([1; 16]), vec![0xAA; 50]);
        let env2 = make_envelope_with_id(MessageID::from_bytes([2; 16]), vec![0xBB; 50]);

        let mut map = HashMap::new();
        merge_envelopes(&mut map, vec![env1, env2], "node-a");

        let result = flatten_variants(map);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_flatten_empty() {
        let map: HashMap<MessageID, Vec<OuterEnvelope>> = HashMap::new();
        let result = flatten_variants(map);
        assert!(result.is_empty());
    }
}
