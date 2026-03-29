use std::collections::HashMap;

/// A 16-byte routing key (truncated BLAKE3 hash of a `PublicID`).
///
/// Defined here as a type alias so `reme-discovery` stays independent of
/// `reme-message` / `reme-identity`.
pub type RoutingKey = [u8; 16];

/// Structured fields decoded from a TXT record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtFields {
    /// The routing key identifying the peer.
    pub routing_key: RoutingKey,
    /// The port advertised in the TXT record.
    pub port: u16,
    /// The protocol version.
    pub version: u8,
    /// Optional capability tokens (e.g., "relay", "store").
    pub caps: Option<Vec<String>>,
}

// TXT record key names — shared between encode and decode.
const TXT_KEY_VERSION: &str = "v";
const TXT_KEY_ROUTING_KEY: &str = "rk";
const TXT_KEY_PORT: &str = "port";
const TXT_KEY_CAPS: &str = "caps";

/// Errors that occur when parsing TXT records.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TxtError {
    /// A required TXT key is absent.
    #[error("missing TXT field: {0}")]
    MissingField(String),

    /// The `v` field contains an unsupported version string.
    #[error("invalid version: {0}")]
    InvalidVersion(String),

    /// The `rk` field is not valid hex or has the wrong length.
    #[error("invalid routing key: {0}")]
    InvalidRoutingKey(String),

    /// The `port` field cannot be parsed as a `u16`.
    #[error("invalid port: {0}")]
    InvalidPort(String),
}

/// Encode discovery-relevant fields into a TXT record map.
///
/// Produces keys: `v` (protocol version), `rk` (hex-encoded routing key),
/// `port` (decimal port number), and optionally `caps` (comma-separated capability tokens).
///
/// Note: the `port` value here is redundant with the port contained in the
/// corresponding SRV record and/or [`RawDiscoveredPeer`] metadata. Callers
/// should treat the SRV/peer port as authoritative in the presence of any
/// conflict, and may ignore the TXT `port` entirely once the SRV record has
/// been resolved.
pub fn encode_txt(
    routing_key: &RoutingKey,
    port: u16,
    caps: Option<&[String]>,
) -> HashMap<String, String> {
    let mut txt = HashMap::from([
        (TXT_KEY_VERSION.to_owned(), "1".to_owned()),
        (TXT_KEY_ROUTING_KEY.to_owned(), hex::encode(routing_key)),
        (TXT_KEY_PORT.to_owned(), port.to_string()),
    ]);

    if let Some(cap_list) = caps {
        if !cap_list.is_empty() {
            txt.insert(TXT_KEY_CAPS.to_owned(), cap_list.join(","));
        }
    }

    txt
}

/// Decode a TXT record map back into structured fields.
///
/// Returns a [`TxtFields`] struct or a [`TxtError`] describing what went
/// wrong.
///
/// Although this function parses and returns the TXT `port` field, it is
/// recommended that higher-level discovery code prefer the port obtained
/// from the SRV record or [`RawDiscoveredPeer`] when both are available
/// (i.e. "SRV/peer port wins; TXT `port` may be ignored").
pub fn decode_txt(records: &HashMap<String, String>) -> Result<TxtFields, TxtError> {
    // --- version ---
    let v_str = records
        .get(TXT_KEY_VERSION)
        .ok_or_else(|| TxtError::MissingField(TXT_KEY_VERSION.to_owned()))?;
    let version: u8 = v_str
        .parse()
        .map_err(|_| TxtError::InvalidVersion(v_str.clone()))?;
    if version != 1 {
        return Err(TxtError::InvalidVersion(v_str.clone()));
    }

    // --- routing key ---
    let rk_str = records
        .get(TXT_KEY_ROUTING_KEY)
        .ok_or_else(|| TxtError::MissingField(TXT_KEY_ROUTING_KEY.to_owned()))?;
    let rk_bytes = hex::decode(rk_str).map_err(|_| TxtError::InvalidRoutingKey(rk_str.clone()))?;
    let routing_key: RoutingKey = rk_bytes.try_into().map_err(|bytes: Vec<u8>| {
        TxtError::InvalidRoutingKey(format!("expected 16 bytes, got {}", bytes.len()))
    })?;

    // --- port ---
    let port_str = records
        .get(TXT_KEY_PORT)
        .ok_or_else(|| TxtError::MissingField(TXT_KEY_PORT.to_owned()))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| TxtError::InvalidPort(port_str.clone()))?;

    // --- caps (optional) ---
    let caps = records.get(TXT_KEY_CAPS).map(|caps_str| {
        caps_str
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect::<Vec<String>>()
    });

    Ok(TxtFields {
        routing_key,
        port,
        version,
        caps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let rk: RoutingKey = [
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc,
            0xba, 0x98,
        ];
        let port = 8443;

        let txt = encode_txt(&rk, port, None);
        let fields = decode_txt(&txt).unwrap();

        assert_eq!(fields.routing_key, rk);
        assert_eq!(fields.port, port);
        assert_eq!(fields.version, 1);
        assert_eq!(fields.caps, None);
    }

    #[test]
    fn round_trip_zero_port() {
        let rk = [0u8; 16];
        let txt = encode_txt(&rk, 0, None);
        let fields = decode_txt(&txt).unwrap();

        assert_eq!(fields.routing_key, rk);
        assert_eq!(fields.port, 0);
        assert_eq!(fields.version, 1);
        assert_eq!(fields.caps, None);
    }

    #[test]
    fn missing_version_field() {
        let mut txt = HashMap::new();
        txt.insert("rk".to_owned(), "00".repeat(16));
        txt.insert("port".to_owned(), "443".to_owned());

        assert_eq!(
            decode_txt(&txt).unwrap_err(),
            TxtError::MissingField("v".to_owned()),
        );
    }

    #[test]
    fn missing_routing_key_field() {
        let mut txt = HashMap::new();
        txt.insert("v".to_owned(), "1".to_owned());
        txt.insert("port".to_owned(), "443".to_owned());

        assert_eq!(
            decode_txt(&txt).unwrap_err(),
            TxtError::MissingField("rk".to_owned()),
        );
    }

    #[test]
    fn missing_port_field() {
        let mut txt = HashMap::new();
        txt.insert("v".to_owned(), "1".to_owned());
        txt.insert("rk".to_owned(), "00".repeat(16));

        assert_eq!(
            decode_txt(&txt).unwrap_err(),
            TxtError::MissingField("port".to_owned()),
        );
    }

    #[test]
    fn invalid_version() {
        let mut txt = HashMap::new();
        txt.insert("v".to_owned(), "not_a_number".to_owned());
        txt.insert("rk".to_owned(), "00".repeat(16));
        txt.insert("port".to_owned(), "443".to_owned());

        assert_eq!(
            decode_txt(&txt).unwrap_err(),
            TxtError::InvalidVersion("not_a_number".to_owned()),
        );
    }

    #[test]
    fn invalid_routing_key_bad_hex() {
        let mut txt = HashMap::new();
        txt.insert("v".to_owned(), "1".to_owned());
        txt.insert("rk".to_owned(), "zzzz".to_owned());
        txt.insert("port".to_owned(), "443".to_owned());

        assert_eq!(
            decode_txt(&txt).unwrap_err(),
            TxtError::InvalidRoutingKey("zzzz".to_owned()),
        );
    }

    #[test]
    fn invalid_routing_key_wrong_length() {
        let mut txt = HashMap::new();
        txt.insert("v".to_owned(), "1".to_owned());
        // Valid hex but only 8 bytes instead of 16
        txt.insert("rk".to_owned(), "00".repeat(8));
        txt.insert("port".to_owned(), "443".to_owned());

        assert_eq!(
            decode_txt(&txt).unwrap_err(),
            TxtError::InvalidRoutingKey("expected 16 bytes, got 8".to_owned()),
        );
    }

    #[test]
    fn invalid_port() {
        let mut txt = HashMap::new();
        txt.insert("v".to_owned(), "1".to_owned());
        txt.insert("rk".to_owned(), "00".repeat(16));
        txt.insert("port".to_owned(), "99999".to_owned());

        assert_eq!(
            decode_txt(&txt).unwrap_err(),
            TxtError::InvalidPort("99999".to_owned()),
        );
    }

    #[test]
    fn version_256_overflows_u8() {
        let mut txt = HashMap::new();
        txt.insert("v".to_owned(), "256".to_owned());
        txt.insert("rk".to_owned(), "00".repeat(16));
        txt.insert("port".to_owned(), "443".to_owned());

        assert_eq!(
            decode_txt(&txt).unwrap_err(),
            TxtError::InvalidVersion("256".to_owned()),
        );
    }

    #[test]
    fn unsupported_version_2_is_rejected() {
        let mut txt = HashMap::new();
        txt.insert("v".to_owned(), "2".to_owned());
        txt.insert("rk".to_owned(), "00".repeat(16));
        txt.insert("port".to_owned(), "443".to_owned());

        assert_eq!(
            decode_txt(&txt).unwrap_err(),
            TxtError::InvalidVersion("2".to_owned()),
        );
    }

    #[test]
    fn round_trip_with_caps() {
        let rk = [0xaa; 16];
        let caps = vec!["relay".to_owned(), "store".to_owned()];

        let txt = encode_txt(&rk, 3000, Some(&caps));
        let fields = decode_txt(&txt).unwrap();

        assert_eq!(fields.routing_key, rk);
        assert_eq!(fields.port, 3000);
        assert_eq!(fields.version, 1);
        assert_eq!(fields.caps, Some(caps));
    }

    #[test]
    fn caps_field_is_optional() {
        let rk = [0xbb; 16];
        let txt = encode_txt(&rk, 4000, None);
        let fields = decode_txt(&txt).unwrap();

        assert_eq!(fields.caps, None);
    }

    #[test]
    fn caps_empty_list_omitted() {
        let rk = [0xcc; 16];
        let empty_caps: Vec<String> = vec![];
        let txt = encode_txt(&rk, 5000, Some(&empty_caps));

        // Empty caps should not add a caps field
        assert!(!txt.contains_key("caps"));

        let fields = decode_txt(&txt).unwrap();
        assert_eq!(fields.caps, None);
    }

    #[test]
    fn caps_whitespace_trimmed() {
        let mut txt = HashMap::new();
        txt.insert("v".to_owned(), "1".to_owned());
        txt.insert("rk".to_owned(), "00".repeat(16));
        txt.insert("port".to_owned(), "3000".to_owned());
        txt.insert("caps".to_owned(), " relay , store , forward ".to_owned());

        let fields = decode_txt(&txt).unwrap();
        assert_eq!(
            fields.caps,
            Some(vec![
                "relay".to_owned(),
                "store".to_owned(),
                "forward".to_owned()
            ])
        );
    }
}
