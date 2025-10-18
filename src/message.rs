use crate::core::encoding::{Address, encode_addr};
use crate::core::error::Result;
use base64::Engine;

/// Create message bytes for raw signing
/// Format: encode_addr(None, address) || timestamp_millis (8 bytes BE) || body
pub fn create_message_bytes(address: Address, timestamp_millis: u64, body: &[u8]) -> Vec<u8> {
    [
        encode_addr(None, address).as_slice(),
        &timestamp_millis.to_be_bytes(),
        body,
    ]
    .concat()
}

/// Create base64-encoded JSON identity header for SPF authentication
pub fn create_identity_header(
    address: &str,
    timestamp_millis: u64,
    signature_type: &str,
    signature: &str,
) -> Result<String> {
    let identity = serde_json::json!({
        "entity": {
            "entity_type": "external_address",
            "addr": address
        },
        "timestamp_millis": timestamp_millis,
        "signature": {
            "signature_type": signature_type,
            "value": signature
        }
    });

    Ok(base64::engine::general_purpose::STANDARD.encode(identity.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_message_bytes_format() {
        let address = Address([1u8; 20]);
        let timestamp = 1234567890u64;
        let body = b"test body";

        let message = create_message_bytes(address, timestamp, body);

        // Message should be: encoded_addr (33) + timestamp (8) + body
        assert_eq!(message.len(), 33 + 8 + body.len());
    }

    #[test]
    fn test_create_message_bytes_deterministic() {
        let address = Address([1u8; 20]);
        let timestamp = 1234567890u64;
        let body = b"test body";

        let message1 = create_message_bytes(address, timestamp, body);
        let message2 = create_message_bytes(address, timestamp, body);

        assert_eq!(message1, message2);
    }

    #[test]
    fn test_create_message_bytes_different_address() {
        let address1 = Address([1u8; 20]);
        let address2 = Address([2u8; 20]);
        let timestamp = 1234567890u64;
        let body = b"test";

        let message1 = create_message_bytes(address1, timestamp, body);
        let message2 = create_message_bytes(address2, timestamp, body);

        assert_ne!(message1, message2);
    }

    #[test]
    fn test_create_message_bytes_timestamp_included() {
        let address = Address([1u8; 20]);
        let timestamp = 0x0102030405060708u64;
        let body = b"";

        let message = create_message_bytes(address, timestamp, body);

        // Timestamp should be at bytes 33..41 in big-endian format
        let timestamp_bytes = &message[33..41];
        assert_eq!(
            timestamp_bytes,
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn test_create_identity_header_format() {
        let address = "0x1234567890123456789012345678901234567890";
        let timestamp = 1234567890u64;
        let signature_type = "illegal";
        let signature = "0xabcdef";

        let header = create_identity_header(address, timestamp, signature_type, signature).unwrap();

        // Should be base64 encoded
        assert!(!header.is_empty());
        // Decode and verify it's valid JSON
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&header)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&decoded).unwrap();

        // Verify structure
        assert_eq!(json["entity"]["entity_type"], "external_address");
        assert_eq!(json["entity"]["addr"], address);
        assert_eq!(json["timestamp_millis"], timestamp);
        assert_eq!(json["signature"]["signature_type"], "illegal");
        assert_eq!(json["signature"]["value"], signature);
    }

    #[test]
    fn test_create_identity_header_base64() {
        let address = "0x1234567890123456789012345678901234567890";
        let timestamp = 1234567890u64;
        let signature_type = "illegal";
        let signature = "0xabcdef";

        let header = create_identity_header(address, timestamp, signature_type, signature).unwrap();

        // Should be valid base64
        assert!(
            base64::engine::general_purpose::STANDARD
                .decode(&header)
                .is_ok()
        );
    }

    #[test]
    fn test_create_identity_header_fields() {
        let address = "0xtest";
        let timestamp = 999u64;
        let signature_type = "illegal";
        let signature = "0xsig";

        let header = create_identity_header(address, timestamp, signature_type, signature).unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&header)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&decoded).unwrap();

        // All fields should be present
        assert!(json.get("entity").is_some());
        assert!(json.get("timestamp_millis").is_some());
        assert!(json.get("signature").is_some());
        assert!(json["entity"].get("entity_type").is_some());
        assert!(json["entity"].get("addr").is_some());
        assert!(json["signature"].get("signature_type").is_some());
        assert!(json["signature"].get("value").is_some());
    }

    #[test]
    fn test_create_identity_header_deterministic() {
        let address = "0x1234567890123456789012345678901234567890";
        let timestamp = 1234567890u64;
        let signature_type = "illegal";
        let signature = "0xabcdef";

        let header1 =
            create_identity_header(address, timestamp, signature_type, signature).unwrap();
        let header2 =
            create_identity_header(address, timestamp, signature_type, signature).unwrap();

        assert_eq!(header1, header2);
    }
}
