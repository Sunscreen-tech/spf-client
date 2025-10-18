use crate::core::encoding;
use alloy::primitives::{FixedBytes, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolValue;
use anyhow::Result;
use serde::{Deserialize, Serialize};

// Define SPF access control structures for ABI encoding
alloy::sol! {
    struct SpfAccessChange {
        uint256 metaData;
        bytes32[] payload;
    }

    struct SpfAccess {
        bytes32 ciphertext;
        SpfAccessChange[] changes;
    }
}

/// Resolve chain ID from optional chain/RPC parameters
///
/// - If neither provided: Returns None (web2 mode)
/// - If either provided: Queries RPC for chain ID and validates (web3 mode)
/// - If both provided: Uses custom RPC with specified chain
async fn resolve_chain_id(chain: Option<&str>, rpc_url: Option<&str>) -> Result<Option<u64>> {
    use super::chain::{query_and_validate_chain_id, resolve_rpc_and_chain};

    match (chain, rpc_url) {
        (None, None) => Ok(None),
        _ => {
            let (rpc_url_str, chain_obj) = resolve_rpc_and_chain(rpc_url, chain)?;
            Ok(Some(
                query_and_validate_chain_id(&rpc_url_str, &chain_obj).await?,
            ))
        }
    }
}

/// Generic helper for ACL grant operations (admin/decrypt only)
///
/// Consolidates common logic: parse address, resolve chain_id, build access type, update
async fn grant_access_generic(
    endpoint: &str,
    ciphertext_id: &str,
    address: &str,
    chain: Option<&str>,
    rpc_url: Option<&str>,
    signer: &PrivateKeySigner,
    build_access: impl FnOnce(Option<u64>, encoding::Address) -> encoding::AccessType,
) -> Result<String> {
    let addr = encoding::parse_address_hex(address)
        .map_err(|e| anyhow::anyhow!("invalid address: {}", e))?;

    let chain_id = resolve_chain_id(chain, rpc_url).await?;
    let access = build_access(chain_id, addr);

    update_access_typed(endpoint, ciphertext_id, access, signer).await
}

/// Grant Admin access to a ciphertext
///
/// If chain is provided, queries the chain ID from RPC.
/// Otherwise defaults to web2 mode (no chain_id).
///
/// # Returns
/// Returns a NEW ciphertext ID. This new ID references a version of the ciphertext
/// with the updated access permissions. You MUST use this new ID for all subsequent
/// operations (checking access, requesting decryption, etc.). Using the old ID will
/// result in "access denied" errors because the granted permissions only exist on
/// the new version.
pub async fn admin_access(
    endpoint: &str,
    ciphertext_id: &str,
    address: &str,
    chain: Option<&str>,
    rpc_url: Option<&str>,
    signer: &PrivateKeySigner,
) -> Result<String> {
    grant_access_generic(
        endpoint,
        ciphertext_id,
        address,
        chain,
        rpc_url,
        signer,
        |chain_id, addr| encoding::AccessType::Admin { chain_id, addr },
    )
    .await
}

/// Grant Decrypt access to a ciphertext
///
/// If chain is provided, queries the chain ID from RPC.
/// Otherwise defaults to web2 mode (no chain_id).
///
/// # Returns
/// Returns a NEW ciphertext ID. This new ID references a version of the ciphertext
/// with the updated access permissions. You MUST use this new ID for all subsequent
/// operations (checking access, requesting decryption, etc.). Using the old ID will
/// result in "access denied" errors because the granted permissions only exist on
/// the new version.
pub async fn decrypt_access(
    endpoint: &str,
    ciphertext_id: &str,
    address: &str,
    chain: Option<&str>,
    rpc_url: Option<&str>,
    signer: &PrivateKeySigner,
) -> Result<String> {
    grant_access_generic(
        endpoint,
        ciphertext_id,
        address,
        chain,
        rpc_url,
        signer,
        |chain_id, addr| encoding::AccessType::Decrypt { chain_id, addr },
    )
    .await
}

/// Grant Run access to a ciphertext
///
/// If library and entry_point are not provided, queries the executor for metadata
/// (assuming it implements ISpfSingleProgram interface).
/// Requires chain and/or rpc_url to query the executor.
///
/// # Returns
/// Returns a NEW ciphertext ID. This new ID references a version of the ciphertext
/// with the updated access permissions. You MUST use this new ID for all subsequent
/// operations (checking access, requesting decryption, etc.). Using the old ID will
/// result in "access denied" errors because the granted permissions only exist on
/// the new version.
#[allow(clippy::too_many_arguments)]
pub async fn run_access(
    endpoint: &str,
    ciphertext_id: &str,
    executor: &str,
    library: Option<&str>,
    entry_point: Option<&str>,
    chain: Option<&str>,
    rpc_url: Option<&str>,
    signer: &PrivateKeySigner,
) -> Result<String> {
    use super::chain::{parse_address, query_and_validate_chain_id, resolve_rpc_and_chain};
    use super::contract::{bytes32_to_string, query_contract_metadata};

    let executor_addr = parse_address(executor)?;

    // Get library hash, entry point, and chain ID
    let (lib, entry_point_str, chain_id) = match (library, entry_point) {
        (Some(lib_hash), Some(ep)) if !lib_hash.is_empty() && !ep.is_empty() => {
            // Manual specification - parse the provided values
            let lib_b256 = encoding::parse_b256_hex(lib_hash)
                .map_err(|e| anyhow::anyhow!("invalid library: {}", e))?;

            let chain_id = resolve_chain_id(chain, rpc_url).await?;

            (lib_b256, ep.to_string(), chain_id)
        }
        (None, None) => {
            // Automatic querying - fetch from executor (requires RPC)
            let (rpc_url_str, chain_obj) = resolve_rpc_and_chain(rpc_url, chain)?;
            let chain_id = query_and_validate_chain_id(&rpc_url_str, &chain_obj).await?;

            let (lib_hash, program_name) =
                query_contract_metadata(executor_addr, &rpc_url_str).await?;

            let program_name_str = bytes32_to_string(program_name);

            if program_name_str.is_empty() {
                anyhow::bail!("program name from executor is empty");
            }

            if !program_name_str.is_ascii() {
                anyhow::bail!(
                    "program name '{}' contains non-ASCII characters",
                    program_name_str
                );
            }

            (
                encoding::B256::try_from_slice(lib_hash.as_slice())
                    .map_err(|e| anyhow::anyhow!("invalid library hash from executor: {}", e))?,
                program_name_str,
                Some(chain_id),
            )
        }
        _ => {
            anyhow::bail!(
                "both --library and --entry-point must be provided together (and non-empty), or neither"
            );
        }
    };

    // Convert alloy Address to spf_client address type
    let addr = encoding::Address::try_from_slice(executor_addr.as_slice())
        .map_err(|e| anyhow::anyhow!("invalid executor address: {}", e))?;

    let access = encoding::AccessType::Run {
        chain_id,
        addr,
        lib,
        entry_point: entry_point_str,
    };

    update_access_typed(endpoint, ciphertext_id, access, signer).await
}

/// Update access control with typed AccessType (more type-safe)
///
/// # Returns
/// Returns a NEW ciphertext ID. This new ID references a version of the ciphertext
/// with the updated access permissions. You MUST use this new ID for all subsequent
/// operations. Using the old ID will result in "access denied" errors.
pub async fn update_access_typed(
    endpoint: &str,
    ciphertext_id: &str,
    access: encoding::AccessType,
    signer: &PrivateKeySigner,
) -> Result<String> {
    // Parse ciphertext ID
    let ct_id_b256 = encoding::parse_b256_hex(ciphertext_id)
        .map_err(|e| anyhow::anyhow!("invalid ciphertext ID: {}", e))?;
    let ct_id = FixedBytes::<32>::from_slice(ct_id_b256.as_slice());

    // Convert to SpfAccessChange for ABI encoding
    let change: encoding::SpfAccessChange = access
        .try_into()
        .map_err(|e| anyhow::anyhow!("invalid access configuration: {}", e))?;

    // Convert metadata
    let metadata = U256::from_be_bytes(change.meta_data.0);

    // Convert payload
    let payload: Vec<FixedBytes<32>> = change
        .payload
        .iter()
        .map(|b| FixedBytes::<32>::from_slice(&b.0))
        .collect();

    let spf_change = SpfAccessChange {
        metaData: metadata,
        payload,
    };

    // Create SpfAccess structure
    let spf_access = SpfAccess {
        ciphertext: ct_id,
        changes: vec![spf_change],
    };

    // ABI encode
    let access_bytes = spf_access.abi_encode();

    // Create auth header using raw_ecdsa with the ABI-encoded request body
    let auth_header = super::auth::create_access_change_auth_header(signer, &access_bytes).await?;

    let url = format!("{}/acl", endpoint);
    let client = super::http::create_http_client(30)?;

    let response = client
        .post(&url)
        .header("spf-identity", auth_header)
        .body(access_bytes)
        .send()
        .await?;

    let response = super::http::check_response_status(response, "access update").await?;
    let result_id: String = response.json().await?;
    Ok(crate::core::utils::ensure_hex_prefix(result_id))
}

// ============================================================================
// CHECK OPERATIONS (no authentication required)
// ============================================================================

/// ACL check response with discriminated status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "payload")]
#[serde(rename_all = "lowercase")]
pub enum AclCheckResponse {
    Success(AclCheckSuccess),
    Failure(String),
}

/// Success response payload from ACL check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclCheckSuccess {
    /// Signature proving access (65 bytes as 0x-prefixed hex string)
    pub signature: String,
    /// Message that was signed for EIP-191 verification
    pub msg: SpfCiphertextAccessConfirmation,
    /// Parsed and verified access change
    pub access_change: serde_json::Value,
}

/// Message signed by the server for ACL verification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpfCiphertextAccessConfirmation {
    /// Ciphertext ID (32 bytes as hex string with 0x prefix)
    pub ciphertext_id: String,
    /// Bit width of the ciphertext
    pub bit_width: u64,
    /// Access bytes that were verified (hex string)
    pub access: String,
}

/// High-level result of an ACL check operation
#[derive(Debug)]
pub enum AclCheckResult {
    /// Access is granted
    Granted {
        signature: String,
        message: SpfCiphertextAccessConfirmation,
        access_change: serde_json::Value,
    },
    /// Access is denied
    Denied { reason: String },
}

/// Helper to resolve chain ID from chain name (without RPC query)
///
/// Returns the chain ID for named chains (monad, sepolia).
/// For localhost, returns an error since the chain ID varies by local setup.
/// Use grant operations (which query RPC) for localhost chains.
fn resolve_chain_id_from_name(chain: &str) -> Result<u64> {
    use super::chain::Chain;

    let chain_obj = chain.parse::<Chain>()?;
    chain_obj.chain_id().ok_or_else(|| {
        anyhow::anyhow!(
            "cannot determine chain ID for localhost without RPC query; use grant operations for localhost which query the RPC"
        )
    })
}

/// Generic helper for ACL check operations
///
/// Consolidates common logic: parse address, resolve chain_id, build access type, check
async fn check_access_generic(
    endpoint: &str,
    ciphertext_id: &str,
    address: &str,
    chain: Option<&str>,
    build_access: impl FnOnce(Option<u64>, encoding::Address) -> Result<encoding::AccessType>,
) -> Result<AclCheckResult> {
    let addr = encoding::parse_address_hex(address)
        .map_err(|e| anyhow::anyhow!("invalid address: {}", e))?;

    let chain_id = if let Some(chain_name) = chain {
        Some(resolve_chain_id_from_name(chain_name)?)
    } else {
        None
    };

    let access = build_access(chain_id, addr)?;
    check_access(endpoint, ciphertext_id, access).await
}

/// Check Admin access to a ciphertext
///
/// Makes a request to the SPF network to verify admin access permissions.
/// Returns a result indicating whether access is granted or denied.
///
/// No authentication is required for this endpoint.
pub async fn check_admin_access(
    endpoint: &str,
    ciphertext_id: &str,
    address: &str,
    chain: Option<&str>,
) -> Result<AclCheckResult> {
    check_access_generic(endpoint, ciphertext_id, address, chain, |chain_id, addr| {
        Ok(encoding::AccessType::Admin { chain_id, addr })
    })
    .await
}

/// Check Decrypt access to a ciphertext
///
/// Makes a request to the SPF network to verify decrypt access permissions.
/// Returns a result indicating whether access is granted or denied.
///
/// No authentication is required for this endpoint.
pub async fn check_decrypt_access(
    endpoint: &str,
    ciphertext_id: &str,
    address: &str,
    chain: Option<&str>,
) -> Result<AclCheckResult> {
    check_access_generic(endpoint, ciphertext_id, address, chain, |chain_id, addr| {
        Ok(encoding::AccessType::Decrypt { chain_id, addr })
    })
    .await
}

/// Check Run access to a ciphertext
///
/// Makes a request to the SPF network to verify run access permissions.
/// Returns a result indicating whether access is granted or denied.
///
/// Requires library and entry_point parameters (cannot query from contract without auth).
///
/// No authentication is required for this endpoint.
pub async fn check_run_access(
    endpoint: &str,
    ciphertext_id: &str,
    address: &str,
    library: &str,
    entry_point: &str,
    chain: Option<&str>,
) -> Result<AclCheckResult> {
    let lib =
        encoding::parse_b256_hex(library).map_err(|e| anyhow::anyhow!("invalid library: {}", e))?;
    let entry_point_string = entry_point.to_string();

    check_access_generic(
        endpoint,
        ciphertext_id,
        address,
        chain,
        move |chain_id, addr| {
            Ok(encoding::AccessType::Run {
                chain_id,
                addr,
                lib,
                entry_point: entry_point_string,
            })
        },
    )
    .await
}

/// Internal helper: Make ACL check request (shared across all check operations)
async fn check_access(
    endpoint: &str,
    ciphertext_id: &str,
    access: encoding::AccessType,
) -> Result<AclCheckResult> {
    // Encode access bytes using existing encoding function
    let access_bytes = encoding::encode_access(access)
        .map_err(|e| anyhow::anyhow!("failed to encode access: {}", e))?;

    // Make POST request to /acl_check/{ciphertext_id}
    let url = format!("{}/acl_check/{}", endpoint, ciphertext_id);
    let client = super::http::create_http_client(30)?;

    let response = client
        .post(&url)
        .header("Content-Type", "application/octet-stream")
        .body(access_bytes)
        .send()
        .await?;

    // Both 200 (success) and 417 (failure) return valid JSON
    if response.status() != 200 && response.status() != 417 {
        let status = response.status();
        let error_text = response.text().await?;
        anyhow::bail!("ACL check request failed ({}): {}", status, error_text);
    }

    // Parse response
    let acl_response: AclCheckResponse = response.json().await?;

    // Convert to high-level result
    match acl_response {
        AclCheckResponse::Success(success) => Ok(AclCheckResult::Granted {
            signature: success.signature,
            message: success.msg,
            access_change: success.access_change,
        }),
        AclCheckResponse::Failure(reason) => Ok(AclCheckResult::Denied { reason }),
    }
}
