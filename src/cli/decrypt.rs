use alloy::signers::local::PrivateKeySigner;
use anyhow::Result;

/// Request decryption for a ciphertext
///
/// Returns the decryption handle for polling
pub async fn request_decryption(
    endpoint: &str,
    ciphertext_id: &str,
    signer: &PrivateKeySigner,
) -> Result<String> {
    let ciphertext_id_clean = ciphertext_id.trim_start_matches("0x");
    let request_body = ciphertext_id_clean.as_bytes().to_vec();

    let auth_header = super::auth::create_decryption_auth_header(signer, ciphertext_id).await?;
    let client = super::http::create_http_client(30)?;

    let url = format!("{}/decryption", endpoint);
    let response = client
        .post(&url)
        .header("spf-identity", auth_header)
        .body(request_body)
        .send()
        .await?;

    let response = super::http::check_response_status(response, "decryption request").await?;
    let decrypt_handle: String = response.json().await?;
    Ok(decrypt_handle)
}

/// Poll for decryption result
///
/// Blocks until decryption completes or fails
pub async fn poll_decryption_result(
    endpoint: &str,
    decrypt_handle: &str,
    bit_width: u8,
    signed: bool,
    poll_interval: u64,
) -> Result<i64> {
    let client = super::http::create_http_client(30)?;

    loop {
        tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval)).await;

        let status_url = format!("{}/decryption/{}", endpoint, decrypt_handle);
        let status_response = client.get(&status_url).send().await?;

        let status_response =
            super::http::check_response_status(status_response, "status check").await?;
        let status: serde_json::Value = status_response.json().await?;

        match status.get("status").and_then(|s| s.as_str()) {
            Some("success") => {
                let value_array = status
                    .get("payload")
                    .and_then(|p| p.get("value"))
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| anyhow::anyhow!("missing or invalid value in payload"))?;

                let poly_bytes: Vec<u8> = value_array
                    .iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u8))
                    .collect();

                let value =
                    crate::core::crypto::parse_polynomial_to_value(&poly_bytes, bit_width, signed)?;

                return Ok(value);
            }
            Some("failed") => {
                let message = status
                    .get("payload")
                    .and_then(|p| p.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown error");
                anyhow::bail!("decryption failed: {}", message);
            }
            Some("pending") | Some("running") | Some("in_progress") => {
                continue;
            }
            _ => {
                anyhow::bail!("unknown status: {:?}", status);
            }
        }
    }
}

/// Request decryption and poll for result (convenience function)
pub async fn decrypt_ciphertext(
    endpoint: &str,
    ciphertext_id: &str,
    signer: &PrivateKeySigner,
    bit_width: u8,
    signed: bool,
    poll_interval: u64,
) -> Result<i64> {
    let handle = request_decryption(endpoint, ciphertext_id, signer).await?;
    poll_decryption_result(endpoint, &handle, bit_width, signed, poll_interval).await
}
