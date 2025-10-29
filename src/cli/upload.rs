use crate::core::utils;
use alloy::signers::local::PrivateKeySigner;
use anyhow::Result;

/// Upload ciphertext bytes to the SPF network
///
/// Returns the ciphertext ID
pub async fn upload_ciphertext(
    endpoint: &str,
    ciphertext_bytes: Vec<u8>,
    signer: &PrivateKeySigner,
) -> Result<String> {
    let auth_header =
        super::auth::create_ciphertext_upload_auth_header(signer, &ciphertext_bytes).await?;

    let url = format!("{}/ciphertexts", endpoint);
    let client = super::http::create_http_client(60, endpoint)?;

    let response = client
        .post(&url)
        .header("spf-identity", auth_header)
        .body(ciphertext_bytes)
        .send()
        .await?;

    let response = super::http::check_response_status(response, "ciphertext upload").await?;
    let ciphertext_id: String = response.json().await?;
    Ok(utils::ensure_hex_prefix(ciphertext_id))
}

/// Upload program bytes to the SPF network
///
/// Returns the program ID (derived locally)
pub async fn upload_program(endpoint: &str, program_bytes: Vec<u8>) -> Result<String> {
    // Derive program ID before sending
    let program_id = utils::derive_program_id(&program_bytes);

    let url = format!("{}/programs", endpoint);
    let client = super::http::create_http_client(60, endpoint)?;

    let response = client.post(&url).body(program_bytes).send().await?;

    let _response = super::http::check_response_status(response, "program upload").await?;

    Ok(program_id)
}
