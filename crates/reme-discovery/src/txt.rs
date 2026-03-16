use std::collections::HashMap;

/// A 16-byte routing key (truncated BLAKE3 hash of a `PublicID`).
///
/// Defined here as a type alias so `reme-discovery` stays independent of
/// `reme-message` / `reme-identity`.
pub type RoutingKey = [u8; 16];

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
/// `port` (decimal port number).
pub fn encode_txt(routing_key: &RoutingKey, port: u16, version: u8) -> HashMap<String, String> {
    let mut map = HashMap::with_capacity(3);
    map.insert("v".to_owned(), version.to_string());
    map.insert("rk".to_owned(), hex::encode(routing_key));
    map.insert("port".to_owned(), port.to_string());
    map
}

/// Decode a TXT record map back into structured fields.
///
/// Returns `(routing_key, port, version)` or a [`TxtError`] describing what
/// went wrong.
pub fn decode_txt(records: &HashMap<String, String>) -> Result<(RoutingKey, u16, u8), TxtError> {
    // --- version ---
    let v_str = records
        .get("v")
        .ok_or_else(|| TxtError::MissingField("v".to_owned()))?;
    let version: u8 = v_str
        .parse()
        .map_err(|_| TxtError::InvalidVersion(v_str.clone()))?;

    // --- routing key ---
    let rk_str = records
        .get("rk")
        .ok_or_else(|| TxtError::MissingField("rk".to_owned()))?;
    let rk_bytes = hex::decode(rk_str).map_err(|_| TxtError::InvalidRoutingKey(rk_str.clone()))?;
    let routing_key: RoutingKey = rk_bytes
        .try_into()
        .map_err(|_| TxtError::InvalidRoutingKey(format!("expected 16 bytes, got {rk_str}")))?;

    // --- port ---
    let port_str = records
        .get("port")
        .ok_or_else(|| TxtError::MissingField("port".to_owned()))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| TxtError::InvalidPort(port_str.clone()))?;

    Ok((routing_key, port, version))
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
        let version = 1;

        let txt = encode_txt(&rk, port, version);
        let (decoded_rk, decoded_port, decoded_version) = decode_txt(&txt).unwrap();

        assert_eq!(decoded_rk, rk);
        assert_eq!(decoded_port, port);
        assert_eq!(decoded_version, version);
    }

    #[test]
    fn round_trip_zero_port() {
        let rk = [0u8; 16];
        let txt = encode_txt(&rk, 0, 0);
        let (decoded_rk, decoded_port, decoded_version) = decode_txt(&txt).unwrap();

        assert_eq!(decoded_rk, rk);
        assert_eq!(decoded_port, 0);
        assert_eq!(decoded_version, 0);
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

        let err = decode_txt(&txt).unwrap_err();
        assert!(matches!(err, TxtError::InvalidRoutingKey(_)));
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
}
