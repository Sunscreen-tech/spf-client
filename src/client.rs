use crate::core::error::{Result, SpfError};
use parasol_runtime::PublicKey;
use std::sync::OnceLock;

static PUBLIC_KEY: OnceLock<PublicKey> = OnceLock::new();

/// Initialize the global public key from deserialized bytes
///
/// The caller is responsible for fetching the public key bytes from the SPF endpoint
/// and passing them to this function. This keeps the library focused on cryptographic
/// operations without depending on HTTP clients.
pub fn initialize_with_public_key(public_key_bytes: &[u8]) -> Result<()> {
    let public_key: PublicKey = bincode::deserialize(public_key_bytes)?;

    PUBLIC_KEY
        .set(public_key)
        .map_err(|_| SpfError::ClientAlreadyInitialized)?;

    Ok(())
}

/// Get reference to the public key
pub fn get_public_key() -> Result<&'static PublicKey> {
    PUBLIC_KEY.get().ok_or(SpfError::ClientNotInitialized)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test public key getter error when not initialized
    // Note: These tests may fail if public key is initialized by other tests
    // Due to OnceLock being static, this may not work reliably if other tests run first
    #[test]
    fn test_get_public_key_not_initialized() {
        if PUBLIC_KEY.get().is_none() {
            let result = get_public_key();
            assert!(result.is_err());
            match result {
                Err(SpfError::ClientNotInitialized) => {}
                _ => panic!("Expected ClientNotInitialized error"),
            }
        }
    }

    // Note: Testing initialize_with_public_key requires creating valid PublicKey bytes,
    // which requires parasol_runtime setup. These tests should be in integration tests
    // where we can control the environment and ensure the state is properly managed.
}
