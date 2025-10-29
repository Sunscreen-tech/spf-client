use anyhow::Result;
use reqwest::IntoUrl;
use std::time::Duration;

fn is_ssl_localhost<U: IntoUrl>(endpoint: U) -> bool {
    if let Ok(u) = endpoint.into_url()
        && u.scheme() == "https"
        && [Some("localhost"), Some("127.0.0.1"), Some("[::1]")].contains(&u.host_str())
    {
        true
    } else {
        false
    }
}

/// Create an HTTP client with specified timeout
pub fn create_http_client(timeout_secs: u64, endpoint: &str) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(is_ssl_localhost(endpoint))
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {}", e))
}

/// Check HTTP response status and extract error text if unsuccessful
///
/// This helper consolidates the common pattern of checking response status
/// and extracting error text for better error messages.
pub async fn check_response_status(
    response: reqwest::Response,
    operation: &str,
) -> Result<reqwest::Response> {
    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        anyhow::bail!("{} failed ({}): {}", operation, status, error_text);
    }
    Ok(response)
}

/// Fetch public key from SPF endpoint
pub async fn fetch_public_key(endpoint: &str) -> Result<Vec<u8>> {
    let url = format!("{}/public_keys", endpoint);

    let client = create_http_client(30, endpoint)?;

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("HTTP request failed: {}", e))?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to fetch public key: HTTP {}", response.status());
    }

    let public_key_bytes = response
        .bytes()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read response: {}", e))?;

    Ok(public_key_bytes.to_vec())
}
