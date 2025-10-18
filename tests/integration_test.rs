#![cfg(feature = "integration-tests")]

mod common;

use base64::Engine;
use common::test_utils;

#[tokio::test]
async fn test_client_initialization() {
    let endpoint = common::get_test_endpoint();

    // Fetch public key from endpoint
    let public_key_bytes = spf_client::cli::fetch_public_key(&endpoint).await;
    assert!(public_key_bytes.is_ok(), "Failed to fetch public key");

    // Try to initialize the client (may already be initialized by other tests)
    let result = spf_client::client::initialize_with_public_key(&public_key_bytes.unwrap());

    // Should succeed OR already be initialized
    if let Err(e) = &result {
        // Only acceptable error is ClientAlreadyInitialized
        assert!(
            matches!(
                e,
                spf_client::core::error::SpfError::ClientAlreadyInitialized
            ),
            "Unexpected error: {:?}",
            e
        );
    }

    // Should be able to get the public key
    let pk = spf_client::client::get_public_key();
    assert!(pk.is_ok());
}

#[tokio::test]
async fn test_encrypt_unsigned_value() {
    common::ensure_initialized().await;

    // Test encrypting an unsigned value
    let value = 42u64;
    let bits = 16u8;

    let result = spf_client::encrypt_unsigned(value, bits);
    assert!(
        result.is_ok(),
        "Failed to encrypt unsigned value: {:?}",
        result
    );

    let ciphertext_bytes = result.unwrap();
    assert!(!ciphertext_bytes.is_empty());
}

#[tokio::test]
async fn test_encrypt_signed_value() {
    common::ensure_initialized().await;

    // Test encrypting a signed value
    let value = -42i64;
    let bits = 16u8;

    let result = spf_client::encrypt_signed(value, bits);
    assert!(
        result.is_ok(),
        "Failed to encrypt signed value: {:?}",
        result
    );

    let ciphertext_bytes = result.unwrap();
    assert!(!ciphertext_bytes.is_empty());
}

#[tokio::test]
async fn test_derive_ciphertext_id() {
    common::ensure_initialized().await;

    // Encrypt a value and derive its ID
    let value = 100u64;
    let bits = 32u8;

    let ciphertext_bytes = spf_client::encrypt_unsigned(value, bits).unwrap();
    let ct_id = spf_client::core::utils::derive_ciphertext_id(&ciphertext_bytes);

    // Should be a valid hex ID
    assert!(test_utils::is_valid_id_format(&ct_id));
}

#[tokio::test]
async fn test_generate_otp() {
    common::ensure_initialized().await;

    // Generate OTP keypair
    let result = spf_client::generate_otp();
    assert!(result.is_ok(), "Failed to generate OTP: {:?}", result);

    let (public_otp, secret_otp) = result.unwrap();
    assert!(!public_otp.is_empty());
    assert!(!secret_otp.is_empty());

    // Public and secret should be different
    assert_ne!(public_otp, secret_otp);
}

#[tokio::test]
async fn test_otp_sizes() {
    common::ensure_initialized().await;

    let public_size = spf_client::public_otp_size();
    let secret_size = spf_client::secret_otp_size();

    // Sizes should be positive
    assert!(public_size > 0);
    assert!(secret_size > 0);

    // Generate actual OTP and verify sizes
    let (public_otp, secret_otp) = spf_client::generate_otp().unwrap();
    assert_eq!(public_otp.len(), public_size as usize);
    assert_eq!(secret_otp.len(), secret_size as usize);
}

#[tokio::test]
async fn test_encryption_deterministic() {
    common::ensure_initialized().await;

    // Encrypting the same value twice should produce different ciphertexts
    // (due to randomness in FHE encryption)
    let value = 42u64;
    let bits = 16u8;

    let ct1 = spf_client::encrypt_unsigned(value, bits).unwrap();
    let ct2 = spf_client::encrypt_unsigned(value, bits).unwrap();

    // Ciphertexts should be different (probabilistic encryption)
    assert_ne!(ct1, ct2);

    // But their IDs should also be different
    let id1 = spf_client::core::utils::derive_ciphertext_id(&ct1);
    let id2 = spf_client::core::utils::derive_ciphertext_id(&ct2);
    assert_ne!(id1, id2);
}

#[tokio::test]
async fn test_encrypt_boundary_values() {
    common::ensure_initialized().await;

    // Test 8-bit boundaries
    assert!(spf_client::encrypt_unsigned(0, 8).is_ok());
    assert!(spf_client::encrypt_unsigned(255, 8).is_ok());
    assert!(spf_client::encrypt_unsigned(256, 8).is_err()); // Out of range

    // Test 16-bit boundaries
    assert!(spf_client::encrypt_unsigned(0, 16).is_ok());
    assert!(spf_client::encrypt_unsigned(65535, 16).is_ok());
    assert!(spf_client::encrypt_unsigned(65536, 16).is_err()); // Out of range

    // Test signed 8-bit boundaries
    assert!(spf_client::encrypt_signed(-128, 8).is_ok());
    assert!(spf_client::encrypt_signed(127, 8).is_ok());
    assert!(spf_client::encrypt_signed(-129, 8).is_err()); // Out of range
    assert!(spf_client::encrypt_signed(128, 8).is_err()); // Out of range
}

#[tokio::test]
async fn test_invalid_bit_widths() {
    common::ensure_initialized().await;

    // Only 8, 16, 32, 64 are valid
    let invalid_widths = [1, 4, 7, 9, 15, 31, 63, 128];

    for width in invalid_widths {
        let result = spf_client::encrypt_unsigned(42, width);
        assert!(result.is_err());
        match result {
            Err(spf_client::core::error::SpfError::InvalidBitWidth { width: w }) => {
                assert_eq!(w, width);
            }
            _ => panic!("Expected InvalidBitWidth error for width {}", width),
        }
    }
}

#[tokio::test]
async fn test_message_bytes_creation() {
    use spf_client::core::encoding::Address;
    use spf_client::message::create_message_bytes;

    let address = Address([1u8; 20]);
    let timestamp = 1234567890u64;
    let body = b"test message";

    let message = create_message_bytes(address, timestamp, body);

    // Message should have correct length: 33 (encoded addr) + 8 (timestamp) + body length
    assert_eq!(message.len(), 33 + 8 + body.len());
}

#[tokio::test]
async fn test_identity_header_creation() {
    use spf_client::message::create_identity_header;

    let address = "0x1234567890123456789012345678901234567890";
    let timestamp = 1234567890u64;
    let signature_type = "eip_712";
    let signature = "0xabcdef";

    let header = create_identity_header(address, timestamp, signature_type, signature).unwrap();

    // Should be base64 encoded
    assert!(!header.is_empty());

    // Should be valid base64
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&header)
        .unwrap();

    // Should be valid JSON
    let json: serde_json::Value = serde_json::from_slice(&decoded).unwrap();

    // Should have correct structure
    assert_eq!(json["entity"]["entity_type"], "external_address");
    assert_eq!(json["entity"]["addr"], address);
    assert_eq!(json["timestamp_millis"], timestamp);
    assert_eq!(json["signature"]["signature_type"], "eip_712");
    assert_eq!(json["signature"]["value"], signature);
}

#[tokio::test]
async fn test_encoding_functions() {
    use spf_client::core::encoding::{AccessType, Address, encode_access, encode_addr};

    let address = Address([0xAB; 20]);

    // Test encoding addresses with and without chain_id
    let encoded_none = encode_addr(None, address);
    assert_eq!(encoded_none.len(), 33);

    let encoded_with_chain = encode_addr(Some(1), address);
    assert_eq!(encoded_with_chain.len(), 33);

    // Different chain IDs should produce different encodings
    assert_ne!(encoded_none, encoded_with_chain);

    // Test encoding with AccessType
    let encoded_admin = encode_access(AccessType::Admin {
        chain_id: Some(1),
        addr: address,
    })
    .unwrap();
    assert!(encoded_admin.len() > 33);

    let encoded_decrypt = encode_access(AccessType::Decrypt {
        chain_id: Some(1),
        addr: address,
    })
    .unwrap();
    assert!(encoded_decrypt.len() > 33);

    // Different access types should produce different encodings
    assert_ne!(encoded_admin, encoded_decrypt);
}

#[tokio::test]
async fn test_program_id_derivation() {
    use spf_client::core::utils::derive_program_id;

    // Create some fake ELF bytes
    let elf_bytes = vec![0x7F, b'E', b'L', b'F', 0, 0, 0, 0];

    let program_id = derive_program_id(&elf_bytes);

    // Should be a valid hex ID
    assert!(test_utils::is_valid_id_format(&program_id));
}

#[tokio::test]
async fn test_result_id_derivation() {
    use spf_client::core::utils::derive_result_id;

    let run_handle = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // Derive result IDs for different indices
    let id0 = derive_result_id(run_handle, 0).unwrap();
    let id1 = derive_result_id(run_handle, 1).unwrap();
    let id2 = derive_result_id(run_handle, 2).unwrap();

    // All should be valid IDs
    assert!(test_utils::is_valid_id_format(&id0));
    assert!(test_utils::is_valid_id_format(&id1));
    assert!(test_utils::is_valid_id_format(&id2));

    // All should be different
    assert_ne!(id0, id1);
    assert_ne!(id1, id2);
    assert_ne!(id0, id2);
}

// End-to-End Round Trip Test
#[tokio::test]
async fn test_full_roundtrip_encrypt_upload_decrypt() {
    use alloy::signers::local::PrivateKeySigner;
    use spf_client::cli;

    common::ensure_initialized().await;

    let endpoint = common::get_test_endpoint();

    // Step 1: Generate a new keypair for this test
    let signer = PrivateKeySigner::random();
    let address = signer.address();
    let address_str = format!("0x{}", hex::encode(address.as_slice()));

    // Step 2: Encrypt a value locally
    let original_value = 42u64;
    let bits = 16u8;
    let ciphertext_bytes =
        spf_client::encrypt_unsigned(original_value, bits).expect("Failed to encrypt value");

    // Step 3: Upload ciphertext to service
    let ciphertext_id = cli::upload_ciphertext(&endpoint, ciphertext_bytes, &signer)
        .await
        .expect("Failed to upload ciphertext");

    // Step 4: Grant decrypt access to ourselves - returns NEW ciphertext ID
    let addr_parsed = spf_client::core::encoding::parse_address_hex(&address_str)
        .expect("Failed to parse address");

    let access = spf_client::core::encoding::AccessType::Decrypt {
        chain_id: None,
        addr: addr_parsed,
    };

    let new_ciphertext_id = cli::update_access_typed(&endpoint, &ciphertext_id, access, &signer)
        .await
        .expect("Failed to update access");

    // Step 5: Request decryption using the NEW ciphertext ID
    let decrypted_value = cli::decrypt_ciphertext(
        &endpoint,
        &new_ciphertext_id,
        &signer,
        bits,
        false, // unsigned
        1000,  // 1s poll interval
    )
    .await
    .expect("Failed to decrypt");

    assert_eq!(
        decrypted_value as u64, original_value,
        "Decrypted value doesn't match original"
    );
}

// ACL Check Tests
#[tokio::test]
async fn test_acl_check_admin_access() {
    use alloy::signers::local::PrivateKeySigner;
    use spf_client::cli;

    common::ensure_initialized().await;

    let endpoint = common::get_test_endpoint();

    // Step 1: Generate two wallets
    let wallet1 = PrivateKeySigner::random();
    let wallet2 = PrivateKeySigner::random();
    let wallet1_addr = format!("0x{}", hex::encode(wallet1.address().as_slice()));
    let wallet2_addr = format!("0x{}", hex::encode(wallet2.address().as_slice()));

    println!("Wallet1 address: {}", wallet1_addr);
    println!("Wallet2 address: {}", wallet2_addr);

    // Step 2: Encrypt and upload a ciphertext
    let ciphertext_bytes = spf_client::encrypt_unsigned(42u64, 16).expect("Failed to encrypt");
    println!("Uploading with wallet1...");
    let ct_id = cli::upload_ciphertext(&endpoint, ciphertext_bytes, &wallet1)
        .await
        .expect("Failed to upload ciphertext");
    println!("Upload successful, ciphertext ID: {}", ct_id);

    // Step 3: Grant admin access to wallet2 - returns NEW ciphertext ID
    let new_ct_id = cli::admin_access(&endpoint, &ct_id, &wallet2_addr, None, None, &wallet1)
        .await
        .expect("Failed to grant admin access");

    // Step 4: Check admin access for wallet2 using NEW ciphertext ID
    let result = cli::check_admin_access(&endpoint, &new_ct_id, &wallet2_addr, None)
        .await
        .expect("Failed to check admin access");

    match result {
        cli::AclCheckResult::Granted {
            signature,
            message,
            access_change: _,
        } => {
            assert!(!signature.is_empty(), "Signature should not be empty");
            assert_eq!(
                message.ciphertext_id, new_ct_id,
                "Ciphertext ID should match new ID"
            );
            assert_eq!(message.bit_width, 16, "Bit width should be 16");
        }
        cli::AclCheckResult::Denied { reason } => {
            panic!(
                "Access should be granted to wallet2, but was denied: {}",
                reason
            );
        }
    }

    // Step 5: Check admin access for wallet1 using NEW ciphertext ID
    // (uploader should still have admin access on the new version)
    let wallet1_addr = format!("0x{}", hex::encode(wallet1.address().as_slice()));
    let result = cli::check_admin_access(&endpoint, &new_ct_id, &wallet1_addr, None)
        .await
        .expect("Failed to check admin access");

    match result {
        cli::AclCheckResult::Granted { .. } => {
            // Expected - wallet1 uploaded the ciphertext so it has admin access
        }
        cli::AclCheckResult::Denied { reason } => {
            panic!(
                "Access should be granted to wallet1 (uploader), but was denied: {}",
                reason
            );
        }
    }

    // Step 6: Check admin access for wallet3 using NEW ciphertext ID
    // (should fail - never granted access)
    let wallet3 = PrivateKeySigner::random();
    let wallet3_addr = format!("0x{}", hex::encode(wallet3.address().as_slice()));
    let result = cli::check_admin_access(&endpoint, &new_ct_id, &wallet3_addr, None)
        .await
        .expect("Failed to check admin access");

    match result {
        cli::AclCheckResult::Granted { .. } => {
            panic!("Access should be denied for wallet3 (never granted)");
        }
        cli::AclCheckResult::Denied { reason: _ } => {
            // Expected - wallet3 was never granted access
        }
    }
}

#[tokio::test]
async fn test_acl_check_decrypt_access() {
    use alloy::signers::local::PrivateKeySigner;
    use spf_client::cli;

    common::ensure_initialized().await;

    let endpoint = common::get_test_endpoint();

    // Step 1: Generate two wallets
    let wallet1 = PrivateKeySigner::random();
    let wallet2 = PrivateKeySigner::random();
    let wallet2_addr = format!("0x{}", hex::encode(wallet2.address().as_slice()));

    // Step 2: Encrypt and upload a ciphertext
    let ciphertext_bytes = spf_client::encrypt_unsigned(123u64, 32).expect("Failed to encrypt");
    let ct_id = cli::upload_ciphertext(&endpoint, ciphertext_bytes, &wallet1)
        .await
        .expect("Failed to upload ciphertext");

    // Step 3: Grant decrypt access to wallet2 - returns NEW ciphertext ID
    let new_ct_id = cli::decrypt_access(&endpoint, &ct_id, &wallet2_addr, None, None, &wallet1)
        .await
        .expect("Failed to grant decrypt access");

    // Step 4: Check decrypt access for wallet2 using NEW ciphertext ID
    let result = cli::check_decrypt_access(&endpoint, &new_ct_id, &wallet2_addr, None)
        .await
        .expect("Failed to check decrypt access");

    match result {
        cli::AclCheckResult::Granted {
            signature,
            message,
            access_change: _,
        } => {
            assert!(!signature.is_empty(), "Signature should not be empty");
            assert_eq!(
                message.ciphertext_id, new_ct_id,
                "Ciphertext ID should match new ID"
            );
            assert_eq!(message.bit_width, 32, "Bit width should be 32");
        }
        cli::AclCheckResult::Denied { reason } => {
            panic!("Access should be granted, but was denied: {}", reason);
        }
    }
}
