//! Run operations for executing FHE programs
//!
//! This module provides functionality to submit program runs to the SPF service,
//! check their status, and poll for completion.

use super::http::create_http_client;
use crate::{core::encoding::parse_b256_hex, message};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

// Parameter type tags for metadata encoding
const TAG_CIPHERTEXT: u8 = 0x00;
const TAG_CIPHERTEXT_ARRAY: u8 = 0x01;
const TAG_OUTPUT_CIPHERTEXT_ARRAY: u8 = 0x02;
const TAG_PLAINTEXT: u8 = 0x03;
const TAG_PLAINTEXT_ARRAY: u8 = 0x04;

/// Helper module for serializing u128 as u64 for JSON compatibility
mod u128_as_u64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(*value as u64)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Ok(value as u128)
    }
}

/// Helper module for serializing Vec<u128> as Vec<u64> for JSON compatibility
mod vec_u128_as_u64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(values: &[u128], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let u64_values: Vec<u64> = values.iter().map(|&v| v as u64).collect();
        u64_values.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u128>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let u64_values = Vec::<u64>::deserialize(deserializer)?;
        Ok(u64_values.into_iter().map(|v| v as u128).collect())
    }
}

/// JSON-serializable parameter definition for CLI
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RunParameterSpec {
    /// Single ciphertext parameter
    Ciphertext { id: String },
    /// Array of ciphertext parameters
    CiphertextArray { ids: Vec<String> },
    /// Output ciphertext array (result)
    OutputCiphertextArray { bit_width: u8, size: u8 },
    /// Single plaintext parameter
    Plaintext {
        bit_width: u8,
        #[serde(with = "u128_as_u64")]
        value: u128,
    },
    /// Array of plaintext parameters
    PlaintextArray {
        bit_width: u8,
        #[serde(with = "vec_u128_as_u64")]
        values: Vec<u128>,
    },
}

/// Internal representation of encoded parameters
#[derive(Debug, Clone)]
struct EncodedParameter {
    metadata: [u8; 32],
    payload: Vec<[u8; 32]>,
}

impl EncodedParameter {
    /// Convert to alloy types for ABI encoding
    fn to_alloy_types(
        &self,
    ) -> (
        alloy::primitives::U256,
        Vec<alloy::primitives::FixedBytes<32>>,
    ) {
        let metadata = alloy::primitives::U256::from_be_bytes(self.metadata);
        let payload: Vec<alloy::primitives::FixedBytes<32>> = self
            .payload
            .iter()
            .map(|bytes| alloy::primitives::FixedBytes::<32>::from_slice(bytes))
            .collect();
        (metadata, payload)
    }
}

/// Convert RunParameterSpec to EncodedParameter
fn encode_parameter(spec: &RunParameterSpec) -> Result<EncodedParameter> {
    use crate::core::encoding::create_meta_data;

    match spec {
        RunParameterSpec::Ciphertext { id } => {
            let ct_bytes = parse_b256_hex(id)?;
            Ok(EncodedParameter {
                metadata: create_meta_data(&[TAG_CIPHERTEXT])
                    .map_err(|e| anyhow!(e))?
                    .0,
                payload: vec![ct_bytes.0],
            })
        }
        RunParameterSpec::CiphertextArray { ids } => {
            let payload: Result<Vec<[u8; 32]>> = ids
                .iter()
                .map(|id| parse_b256_hex(id).map(|b| b.0).map_err(|e| anyhow!(e)))
                .collect();
            Ok(EncodedParameter {
                metadata: create_meta_data(&[TAG_CIPHERTEXT_ARRAY])
                    .map_err(|e| anyhow!(e))?
                    .0,
                payload: payload?,
            })
        }
        RunParameterSpec::OutputCiphertextArray { bit_width, size } => Ok(EncodedParameter {
            metadata: create_meta_data(&[TAG_OUTPUT_CIPHERTEXT_ARRAY, *bit_width, *size])
                .map_err(|e| anyhow!(e))?
                .0,
            payload: vec![],
        }),
        RunParameterSpec::Plaintext { bit_width, value } => {
            // Value goes in lower 16 bytes of bytes32 (big-endian)
            let mut payload_bytes = [0u8; 32];
            payload_bytes[16..32].copy_from_slice(&value.to_be_bytes());

            Ok(EncodedParameter {
                metadata: create_meta_data(&[TAG_PLAINTEXT, *bit_width])
                    .map_err(|e| anyhow!(e))?
                    .0,
                payload: vec![payload_bytes],
            })
        }
        RunParameterSpec::PlaintextArray { bit_width, values } => {
            let payload: Vec<[u8; 32]> = values
                .iter()
                .map(|value| {
                    let mut payload_bytes = [0u8; 32];
                    payload_bytes[16..32].copy_from_slice(&value.to_be_bytes());
                    payload_bytes
                })
                .collect();

            Ok(EncodedParameter {
                metadata: create_meta_data(&[TAG_PLAINTEXT_ARRAY, *bit_width])
                    .map_err(|e| anyhow!(e))?
                    .0,
                payload,
            })
        }
    }
}

/// Run status response
#[derive(Debug)]
pub enum RunStatus {
    Pending,
    Success { payload: Option<serde_json::Value> },
    Failed { message: String },
}

/// Submit a program run to the SPF service
///
/// # Arguments
/// * `endpoint` - SPF service endpoint URL
/// * `library_id` - Library identifier (program hash)
/// * `program_name` - Entry point name in the program
/// * `parameters` - JSON-encoded parameter specifications
/// * `signer` - Private key signer for authentication
///
/// # Returns
/// Run handle (32-byte hex string with 0x prefix)
pub async fn submit_run(
    endpoint: &str,
    library_id: &str,
    program_name: &str,
    parameters: &[RunParameterSpec],
    signer: &PrivateKeySigner,
) -> Result<String> {
    use alloy::sol_types::SolValue;

    // Parse library ID
    let library_b256 = parse_b256_hex(library_id)?;
    let library_bytes = alloy::primitives::FixedBytes::<32>::from_slice(&library_b256.0);

    // Encode program name as bytes32 (ASCII, padded with zeros)
    let mut program_bytes = [0u8; 32];
    let name_bytes = program_name.as_bytes();
    if name_bytes.len() > 32 {
        return Err(anyhow!("Program name too long (max 32 bytes)"));
    }
    program_bytes[..name_bytes.len()].copy_from_slice(name_bytes);
    let program_b256 = alloy::primitives::FixedBytes::<32>::from_slice(&program_bytes);

    // Encode parameters
    let encoded_params: Result<Vec<EncodedParameter>> =
        parameters.iter().map(encode_parameter).collect();
    let encoded_params = encoded_params?;

    // Convert to alloy types
    let alloy_params: Vec<(
        alloy::primitives::U256,
        Vec<alloy::primitives::FixedBytes<32>>,
    )> = encoded_params.iter().map(|p| p.to_alloy_types()).collect();

    // Define SpfRun structure using alloy sol! macro
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

    let spf_parameters: Vec<SpfParameter> = alloy_params
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

    // Create auth header using raw ECDSA signing
    let address_alloy = signer.address();
    let timestamp = super::auth::get_timestamp_millis()?;

    // Convert alloy Address to internal Address type
    let address = crate::core::encoding::Address::try_from_slice(address_alloy.as_slice())?;
    let message_bytes = message::create_message_bytes(address, timestamp, &run_bytes);

    // Use shared raw ECDSA signing helper
    let auth_header =
        super::auth::sign_raw_ecdsa_and_create_header(signer, &message_bytes, timestamp).await?;

    // Submit request
    let url = format!("{}/runs", endpoint);
    let client = create_http_client(60, endpoint)?;

    let response = client
        .post(&url)
        .header("spf-identity", auth_header)
        .body(run_bytes)
        .send()
        .await?;

    let response = super::http::check_response_status(response, "run submission").await?;
    let mut run_handle: String = response.json().await?;

    // Ensure 0x prefix
    if !run_handle.starts_with("0x") {
        run_handle = format!("0x{}", run_handle);
    }

    Ok(run_handle)
}

/// Check the status of a program run
///
/// # Arguments
/// * `endpoint` - SPF service endpoint URL
/// * `run_handle` - Run handle returned from submit_run
///
/// # Returns
/// RunStatus enum indicating pending, success, or failure
pub async fn check_run_status(endpoint: &str, run_handle: &str) -> Result<RunStatus> {
    let handle = run_handle.strip_prefix("0x").unwrap_or(run_handle);

    let url = format!("{}/runs/{}", endpoint, handle);
    let client = create_http_client(30, endpoint)?;

    let response = client.get(&url).send().await?;

    let response = super::http::check_response_status(response, "status check").await?;
    let status: serde_json::Value = response.json().await?;

    let status_str = status
        .get("status")
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow!("Missing status field"))?;

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
        _ => return Err(anyhow!("Unknown status: {}", status_str)),
    })
}

/// Poll for run completion with progress indication
///
/// # Arguments
/// * `endpoint` - SPF service endpoint URL
/// * `run_handle` - Run handle to poll
/// * `poll_interval_ms` - Milliseconds between status checks
/// * `timeout_ms` - Maximum time to wait before timing out
///
/// # Returns
/// Final RunStatus (Success or Failed)
pub async fn poll_run_result(
    endpoint: &str,
    run_handle: &str,
    poll_interval_ms: u64,
    timeout_ms: u64,
) -> Result<RunStatus> {
    use std::io::Write;

    let start = std::time::Instant::now();

    loop {
        if start.elapsed().as_millis() > timeout_ms as u128 {
            return Err(anyhow!("Run timed out after {}ms", timeout_ms));
        }

        let status = check_run_status(endpoint, run_handle).await?;

        match &status {
            RunStatus::Success { .. } | RunStatus::Failed { .. } => {
                // Clear progress line
                println!();
                return Ok(status);
            }
            RunStatus::Pending => {
                // Show progress indication
                print!(".");
                std::io::stdout().flush()?;
                tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval_ms)).await;
            }
        }
    }
}
