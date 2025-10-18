use crate::{eip712_types::*, message};
use alloy::{
    primitives::{FixedBytes, keccak256},
    signers::{Signer, local::PrivateKeySigner},
    sol_types::SolStruct,
};
use anyhow::Result;
use k256::ecdsa::SigningKey;
use std::time::{SystemTime, UNIX_EPOCH};

/// Parse a private key from hex string (with or without 0x prefix)
pub fn parse_private_key(private_key: &str) -> Result<PrivateKeySigner> {
    let key = private_key.trim_start_matches("0x");
    let signer = key.parse::<PrivateKeySigner>()?;
    Ok(signer)
}

/// Get current timestamp in milliseconds since Unix epoch
pub fn get_timestamp_millis() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system time error: {}", e))?;

    let millis = duration.as_millis();

    // Check for overflow before conversion
    millis
        .try_into()
        .map_err(|_| anyhow::anyhow!("timestamp overflow: value exceeds u64::MAX"))
}

/// Helper: Sign an EIP-712 message and create identity header
async fn sign_and_create_header<T: SolStruct>(
    signer: &PrivateKeySigner,
    message: T,
    timestamp: u64,
) -> Result<String> {
    // Sign the EIP-712 hash (this is what the default sign_typed_data does internally)
    let signature = signer
        .sign_hash(&message.eip712_signing_hash(&AUTH_DOMAIN))
        .await?;

    // Note: signature should NOT have 0x prefix (matching testnet-starter)
    let sig_str = hex::encode(signature.as_bytes());
    let addr_str = format!("0x{}", hex::encode(signer.address().as_slice()));

    Ok(message::create_identity_header(
        &addr_str, timestamp, "eip_712", &sig_str,
    )?)
}

/// Helper: Sign message bytes using raw ECDSA and create identity header
///
/// This is the low-level signing method used for decryption requests,
/// ACL changes, and program runs. It uses k256's sign_recoverable to match
/// the server's verification pattern, which differs from EIP-712 signing.
pub(super) async fn sign_raw_ecdsa_and_create_header(
    signer: &PrivateKeySigner,
    message_bytes: &[u8],
    timestamp: u64,
) -> Result<String> {
    // Extract k256 SigningKey from alloy PrivateKeySigner
    let key_bytes: [u8; 32] = signer.credential().to_bytes().into();
    let k256_key = SigningKey::from_bytes(&key_bytes.into())?;

    // Sign with k256's sign_recoverable
    // This internally hashes with SHA-256 via DigestPrimitive
    let (sig, recid) = k256_key
        .sign_recoverable(message_bytes)
        .map_err(|e| anyhow::anyhow!("k256 signing failed: {}", e))?;

    // Encode signature: 64 bytes (r, s) + 1 byte (recovery ID 0-3)
    let sig_bytes = [sig.to_bytes().as_slice(), &[recid.to_byte()]].concat();

    // Create identity header with raw_ecdsa signature type
    let sig_str = hex::encode(sig_bytes);
    let addr_str = format!("0x{}", hex::encode(signer.address().as_slice()));

    Ok(message::create_identity_header(
        &addr_str,
        timestamp,
        "raw_ecdsa",
        &sig_str,
    )?)
}

/// Create authentication header for ciphertext upload
pub async fn create_ciphertext_upload_auth_header(
    signer: &PrivateKeySigner,
    ciphertext_bytes: &[u8],
) -> Result<String> {
    let address = signer.address();
    let timestamp = get_timestamp_millis()?;

    let message = CiphertextUploadAuthentication {
        entity: address,
        timestampMillis: timestamp,
        ciphertextHash: keccak256(ciphertext_bytes),
    };

    sign_and_create_header(signer, message, timestamp).await
}

/// Create authentication header for ciphertext download
pub async fn create_ciphertext_download_auth_header(signer: &PrivateKeySigner) -> Result<String> {
    let address = signer.address();
    let timestamp = get_timestamp_millis()?;

    let message = CiphertextDownloadAuthentication {
        entity: address,
        timestampMillis: timestamp,
    };

    sign_and_create_header(signer, message, timestamp).await
}

/// Create authentication header for decryption request
/// Uses raw ECDSA signing with k256 to match server's verification pattern
pub async fn create_decryption_auth_header(
    signer: &PrivateKeySigner,
    ciphertext_id: &str,
) -> Result<String> {
    let address_alloy = signer.address();
    let timestamp = get_timestamp_millis()?;

    // Convert alloy Address to our internal Address type
    let address = crate::core::encoding::Address::try_from_slice(address_alloy.as_slice())?;

    // The request body is the hex string as ASCII bytes (not decoded)
    // This must match what decrypt.rs sends: ciphertext_id_clean.as_bytes()
    let ciphertext_id_clean = ciphertext_id.trim_start_matches("0x");
    let request_body = ciphertext_id_clean.as_bytes();

    // Create message bytes: encode_addr(None, address) || timestamp_millis || request_body
    let message_bytes = message::create_message_bytes(address, timestamp, request_body);

    sign_raw_ecdsa_and_create_header(signer, &message_bytes, timestamp).await
}

/// Create authentication header for access control changes
/// Uses raw ECDSA signing to match TypeScript PrivateKeySigner behavior
pub async fn create_access_change_auth_header(
    signer: &PrivateKeySigner,
    request_body: &[u8],
) -> Result<String> {
    let address_alloy = signer.address();
    let timestamp = get_timestamp_millis()?;

    // Convert alloy Address to our internal Address type
    let address = crate::core::encoding::Address::try_from_slice(address_alloy.as_slice())?;

    // Create message bytes: encode_addr(None, address) || timestamp_millis || request_body
    let message_bytes = message::create_message_bytes(address, timestamp, request_body);

    sign_raw_ecdsa_and_create_header(signer, &message_bytes, timestamp).await
}

/// Create authentication header for reencryption request
pub async fn create_reencryption_auth_header(
    signer: &PrivateKeySigner,
    otp_hash: FixedBytes<32>,
) -> Result<String> {
    let address = signer.address();
    let timestamp = get_timestamp_millis()?;

    let message = ReencryptionAuthentication {
        entity: address,
        timestampMillis: timestamp,
        oneTimePadHash: otp_hash,
    };

    sign_and_create_header(signer, message, timestamp).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_private_key_with_prefix() {
        let key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(parse_private_key(key).is_ok());
    }

    #[test]
    fn test_parse_private_key_without_prefix() {
        let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(parse_private_key(key).is_ok());
    }

    #[test]
    fn test_get_timestamp_millis() {
        let timestamp = get_timestamp_millis().unwrap();
        assert!(timestamp > 0);
        // Timestamp should be reasonable (after year 2000, before year 3000)
        assert!(timestamp > 946684800000); // Jan 1, 2000
        assert!(timestamp < 32503680000000); // Jan 1, 3000
    }
}
