use base64::prelude::*;
use ember_message::{OuterEnvelope, WirePayload};

use crate::TransportError;

/// Decode base64-encoded `WirePayload` blobs from a fetch response.
///
/// Non-message payloads (e.g. tombstones) are silently skipped, matching
/// the server-side filter that only stores `WirePayload::Message` envelopes.
pub fn decode_fetch_payloads(payloads: Vec<String>) -> Result<Vec<OuterEnvelope>, TransportError> {
    let mut envelopes = Vec::with_capacity(payloads.len());
    for blob in payloads {
        let wire_bytes = BASE64_STANDARD
            .decode(&blob)
            .map_err(|e| TransportError::Serialization(format!("base64 decode: {e}")))?;

        let payload = WirePayload::decode(&wire_bytes)
            .map_err(|e| TransportError::Serialization(format!("wire decode: {e}")))?;

        if let WirePayload::Message(envelope) = payload {
            envelopes.push(envelope);
        }
    }
    Ok(envelopes)
}

pub fn validate_next_cursor(
    next_cursor: &str,
    previous_cursor: Option<i64>,
) -> Result<i64, TransportError> {
    let parsed = next_cursor.parse::<i64>().map_err(|_| {
        TransportError::ServerError(
            "Paginated fetch response returned an invalid next_cursor".to_string(),
        )
    })?;

    if parsed <= 0 {
        return Err(TransportError::ServerError(
            "Paginated fetch response returned an invalid next_cursor".to_string(),
        ));
    }

    if previous_cursor.is_some_and(|previous| parsed <= previous) {
        return Err(TransportError::ServerError(
            "Paginated fetch response returned a non-advancing next_cursor".to_string(),
        ));
    }

    Ok(parsed)
}
