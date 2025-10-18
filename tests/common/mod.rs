use std::env;

/// Get the SPF service endpoint from environment variable or use default
pub fn get_test_endpoint() -> String {
    env::var("SPF_ENDPOINT").unwrap_or_else(|_| "http://localhost:8080".to_string())
}

/// Initialize the client for tests, ignoring if already initialized
/// This is safe because all tests use the same endpoint
pub async fn ensure_initialized() {
    let endpoint = get_test_endpoint();

    // Fetch public key from endpoint
    let public_key_bytes = match spf_client::cli::fetch_public_key(&endpoint).await {
        Ok(pk) => pk,
        Err(_) => return, // Ignore errors, may already be initialized
    };

    // Initialize with fetched public key
    let _ = spf_client::client::initialize_with_public_key(&public_key_bytes);
}

/// Common test utilities
pub mod test_utils {
    use spf_client::core::encoding::Address;

    /// Create a test address from a byte value
    #[allow(dead_code)]
    pub fn create_test_address(byte: u8) -> Address {
        Address([byte; 20])
    }

    /// Create a test address from hex string
    #[allow(dead_code)]
    pub fn parse_test_address(hex: &str) -> Result<Address, spf_client::core::error::SpfError> {
        spf_client::core::encoding::parse_address_hex(hex)
    }

    /// Verify a hex string is properly formatted (0x + 64 hex chars for 32 bytes)
    #[allow(dead_code)]
    pub fn is_valid_id_format(id: &str) -> bool {
        id.starts_with("0x") && id.len() == 66 && id[2..].chars().all(|c| c.is_ascii_hexdigit())
    }
}
