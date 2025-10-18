#![cfg(feature = "integration-tests")]

//! End-to-end voting example test
//!
//! This test demonstrates the full SPF workflow:
//! 1. Upload a voting program
//! 2. Encrypt and upload vote ciphertexts
//! 3. Submit a run to tally the votes
//! 4. Wait for the run to complete
//! 5. Request decryption of the result
//! 6. Verify the result is correct

mod common;

use alloy::signers::local::PrivateKeySigner;
use spf_client::cli;
use std::fs;

/// Helper function to submit a program run to the SPF service
async fn submit_run(
    endpoint: &str,
    library_id: &str,
    program_name: &str,
    parameters: Vec<RunParameter>,
    signer: &PrivateKeySigner,
) -> anyhow::Result<String> {
    use alloy::sol_types::SolValue;
    use spf_client::core::encoding;

    // Convert parameters to the format needed for ABI encoding
    let metadata_and_payload: Vec<(
        alloy::primitives::U256,
        Vec<alloy::primitives::FixedBytes<32>>,
    )> = parameters
        .into_iter()
        .map(|p| {
            let metadata_bytes =
                encoding::parse_b256_hex(&p.metadata).expect("Invalid metadata hex");
            let metadata = alloy::primitives::U256::from_be_bytes(metadata_bytes.0);

            let payload: Vec<alloy::primitives::FixedBytes<32>> = p
                .payload
                .into_iter()
                .map(|hex_str| {
                    let bytes = encoding::parse_b256_hex(&hex_str).expect("Invalid payload hex");
                    alloy::primitives::FixedBytes::<32>::from_slice(&bytes.0)
                })
                .collect();

            (metadata, payload)
        })
        .collect();

    // Create SpfRun structure using alloy sol! macro inline
    alloy::sol! {
        struct SpfParameter {
            uint256 metaData;
            bytes32[] payload;
        }

        struct SpfRun {
            bytes32 spfLibrary;
            bytes32 program;
            SpfParameter[] parameters;
        }
    }

    let library_b256 = encoding::parse_b256_hex(library_id)?;
    let library_bytes = alloy::primitives::FixedBytes::<32>::from_slice(&library_b256.0);

    // Encode program name as bytes32 (ASCII, padded with zeros)
    let mut program_bytes = [0u8; 32];
    let name_bytes = program_name.as_bytes();
    if name_bytes.len() > 32 {
        anyhow::bail!("Program name too long (max 32 bytes)");
    }
    program_bytes[..name_bytes.len()].copy_from_slice(name_bytes);
    let program_b256 = alloy::primitives::FixedBytes::<32>::from_slice(&program_bytes);

    let spf_parameters: Vec<SpfParameter> = metadata_and_payload
        .into_iter()
        .map(|(metadata, payload)| SpfParameter {
            metaData: metadata,
            payload,
        })
        .collect();

    let spf_run = SpfRun {
        spfLibrary: library_bytes,
        program: program_b256,
        parameters: spf_parameters,
    };

    // ABI encode
    let run_bytes = spf_run.abi_encode();

    // Create auth header using raw signing (run submissions use k256 sign_recoverable)
    use k256::ecdsa::SigningKey;
    use spf_client::{cli::auth::get_timestamp_millis, core::encoding::Address, message};

    let address = Address::try_from_slice(signer.address().as_slice())?;
    let timestamp = get_timestamp_millis()?;
    let message_bytes = message::create_message_bytes(address, timestamp, &run_bytes);

    // Extract k256 SigningKey from alloy PrivateKeySigner
    let key_bytes: [u8; 32] = signer
        .credential()
        .to_bytes()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid private key length"))?;
    let k256_key = SigningKey::from_bytes(&key_bytes.into())?;

    // Sign with k256's sign_recoverable - matches server pattern exactly
    let (sig, recid) = k256_key
        .sign_recoverable(&message_bytes)
        .map_err(|e| anyhow::anyhow!("k256 signing failed: {}", e))?;

    // Encode signature: 64 bytes (r, s) + 1 byte (recovery ID 0-3)
    let sig_bytes = [sig.to_bytes().as_slice(), &[recid.to_byte()]].concat();

    let signature_hex = hex::encode(sig_bytes);
    let address_hex = format!("0x{}", hex::encode(signer.address().as_slice()));
    let auth_header =
        message::create_identity_header(&address_hex, timestamp, "raw_ecdsa", &signature_hex)?;

    let url = format!("{}/runs", endpoint);
    let client = cli::create_http_client(60)?;

    let response = client
        .post(&url)
        .header("spf-identity", auth_header)
        .body(run_bytes)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        anyhow::bail!("Run submission failed ({}): {}", status, error_text);
    }

    let mut run_handle: String = response.json().await?;

    // Ensure 0x prefix for consistency
    if !run_handle.starts_with("0x") {
        run_handle = format!("0x{}", run_handle);
    }

    Ok(run_handle)
}

/// Helper function to check run status
async fn check_run_status(endpoint: &str, run_handle: &str) -> anyhow::Result<RunStatus> {
    let handle = if run_handle.starts_with("0x") {
        &run_handle[2..]
    } else {
        run_handle
    };

    let url = format!("{}/runs/{}", endpoint, handle);
    let client = cli::create_http_client(30)?;

    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        anyhow::bail!("Status check failed ({}): {}", status, error_text);
    }

    let status: serde_json::Value = response.json().await?;

    let status_str = status
        .get("status")
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing status field"))?;

    Ok(match status_str {
        "success" => RunStatus::Success {
            payload: status.get("payload").cloned(),
        },
        "failed" => RunStatus::Failed {
            message: status
                .get("payload")
                .and_then(|p| p.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown error")
                .to_string(),
        },
        "pending" | "running" | "in_progress" => RunStatus::Pending,
        _ => anyhow::bail!("Unknown status: {}", status_str),
    })
}

/// Helper function to wait for run to complete
async fn wait_for_run(
    endpoint: &str,
    run_handle: &str,
    poll_interval_ms: u64,
    timeout_ms: u64,
) -> anyhow::Result<RunStatus> {
    let start = std::time::Instant::now();

    loop {
        if start.elapsed().as_millis() > timeout_ms as u128 {
            anyhow::bail!("Run timed out after {}ms", timeout_ms);
        }

        let status = check_run_status(endpoint, run_handle).await?;

        match &status {
            RunStatus::Success { .. } | RunStatus::Failed { .. } => {
                return Ok(status);
            }
            RunStatus::Pending => {
                // Continue polling
                tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval_ms)).await;
            }
        }
    }
}

#[derive(Debug, Clone)]
struct RunParameter {
    metadata: String,
    payload: Vec<String>,
}

#[derive(Debug)]
enum RunStatus {
    Pending,
    Success { payload: Option<serde_json::Value> },
    Failed { message: String },
}

/// Create metadata for a run parameter
/// Fills remaining bytes with 0xFF
fn create_metadata(bytes: &[u8]) -> String {
    let mut data = [0xFFu8; 32];
    for (i, &byte) in bytes.iter().enumerate() {
        if i < 32 {
            data[i] = byte;
        }
    }
    format!("0x{}", hex::encode(data))
}

/// Create a ciphertext array parameter (type 1)
fn create_ciphertext_array_parameter(ciphertext_ids: &[String]) -> RunParameter {
    RunParameter {
        metadata: create_metadata(&[0x01]),
        payload: ciphertext_ids.to_vec(),
    }
}

/// Create a plaintext parameter (type 3)
fn create_plaintext_parameter(bit_width: u8, value: u64) -> RunParameter {
    // Value goes in lower 16 bytes of bytes32 (big-endian)
    let mut payload_bytes = [0u8; 32];
    payload_bytes[24..32].copy_from_slice(&value.to_be_bytes());

    RunParameter {
        metadata: create_metadata(&[0x03, bit_width]),
        payload: vec![format!("0x{}", hex::encode(payload_bytes))],
    }
}

/// Create an output ciphertext array parameter (type 2)
fn create_output_ciphertext_array_parameter(bit_width: u8, size: u8) -> RunParameter {
    RunParameter {
        metadata: create_metadata(&[0x02, bit_width, size]),
        payload: vec![],
    }
}

#[tokio::test]
async fn test_voting_example_end_to_end() {
    common::ensure_initialized().await;

    let endpoint = common::get_test_endpoint();

    // Generate test wallet
    let wallet = PrivateKeySigner::random();
    let address = wallet.address();
    let address_str = format!("0x{}", hex::encode(address.as_slice()));

    println!("Test wallet address: {}", address_str);

    // Step 1: Upload voting program
    println!("\n=== Step 1: Upload voting program ===");
    let program_path = "typescript/test/fixtures/voting.spf";
    let program_bytes = fs::read(program_path).expect("Failed to read voting.spf");

    println!("Program size: {} bytes", program_bytes.len());

    let library_id = cli::upload_program(&endpoint, program_bytes)
        .await
        .expect("Failed to upload program");

    println!("Library ID: {}", library_id);
    assert!(library_id.starts_with("0x"));
    assert_eq!(library_id.len(), 66); // 0x + 64 hex chars

    // Step 2: Encrypt and upload votes
    println!("\n=== Step 2: Encrypt and upload votes ===");
    // Encrypt 4 votes: [1, -1, 1, 1] => sum = 2 > 0 => approved
    let vote_values = vec![1i64, -1i64, 1i64, 1i64];
    let bits = 8u8; // voting.c expects int8_t votes

    let mut vote_ciphertext_ids = Vec::new();

    for (i, &value) in vote_values.iter().enumerate() {
        let ciphertext_bytes = if value < 0 {
            spf_client::encrypt_signed(value, bits).expect("Failed to encrypt signed vote")
        } else {
            spf_client::encrypt_unsigned(value as u64, bits)
                .expect("Failed to encrypt unsigned vote")
        };

        let ciphertext_id = cli::upload_ciphertext(&endpoint, ciphertext_bytes, &wallet)
            .await
            .expect("Failed to upload ciphertext");

        println!("  Uploaded vote {}: {} -> {}", i, value, ciphertext_id);
        vote_ciphertext_ids.push(ciphertext_id);
    }

    assert_eq!(vote_ciphertext_ids.len(), 4);
    println!("Expected result: 1 + (-1) + 1 + 1 = 2 > 0 => approved");

    // Step 3: Submit voting run
    println!("\n=== Step 3: Submit voting run ===");
    let parameters = vec![
        // Parameter 0: Array of 4 encrypted votes
        create_ciphertext_array_parameter(&vote_ciphertext_ids),
        // Parameter 1: Number of votes (uint16_t)
        create_plaintext_parameter(16, 4),
        // Parameter 2: Output - didTheIssuePass (bool, single value)
        create_output_ciphertext_array_parameter(8, 1),
    ];

    println!("Submitting run with 4 encrypted votes...");
    let run_handle = submit_run(&endpoint, &library_id, "tally_votes", parameters, &wallet)
        .await
        .expect("Failed to submit run");

    println!("Run handle: {}", run_handle);
    assert!(run_handle.starts_with("0x"));
    assert_eq!(run_handle.len(), 66);

    // Step 4: Wait for run to complete
    println!("\n=== Step 4: Wait for run to complete ===");
    println!("Polling for run completion (this may take a while)...");

    let final_status = wait_for_run(&endpoint, &run_handle, 1000, 120000)
        .await
        .expect("Failed waiting for run");

    match &final_status {
        RunStatus::Success { payload } => {
            println!("Run completed successfully!");
            if let Some(p) = payload {
                if let Some(gas) = p.get("gas_usage") {
                    println!("  Gas usage: {}", gas);
                }
            }
        }
        RunStatus::Failed { message } => {
            panic!("Run failed: {}", message);
        }
        RunStatus::Pending => {
            panic!("Run still pending after timeout");
        }
    }

    // Step 5: Derive result ciphertext ID
    println!("\n=== Step 5: Derive result ciphertext ID ===");
    // Result ciphertext ID = keccak256(runHandle || outputIndex)
    let result_ciphertext_id = spf_client::core::utils::derive_result_id(&run_handle, 0)
        .expect("Failed to derive result ID");

    println!("Result ciphertext ID: {}", result_ciphertext_id);

    // Step 6: Grant ourselves decrypt access to the result
    println!("\n=== Step 6: Grant decrypt access ===");
    let addr_parsed = spf_client::core::encoding::parse_address_hex(&address_str)
        .expect("Failed to parse address");

    let access = spf_client::core::encoding::AccessType::Decrypt {
        chain_id: None,
        addr: addr_parsed,
    };

    cli::update_access_typed(&endpoint, &result_ciphertext_id, access, &wallet)
        .await
        .expect("Failed to update access");

    println!("Decrypt access granted");

    // Step 7: Request decryption and verify result
    println!("\n=== Step 7: Request decryption ===");
    let decrypted_value = cli::decrypt_ciphertext(
        &endpoint,
        &result_ciphertext_id,
        &wallet,
        8,     // bool is 8-bit
        false, // unsigned
        1000,  // 1s poll interval
    )
    .await
    .expect("Failed to decrypt result");

    println!("\n=== Result ===");
    println!("Decrypted vote result: {}", decrypted_value);
    println!("Expected: 1 (approved) since sum = 2 > 0");

    // Verify the vote passed (result should be 1)
    assert_eq!(
        decrypted_value, 1,
        "Vote should have passed (expected 1), got {}",
        decrypted_value
    );
}
