// CLI operations module - HTTP-aware operations for CLI and integration tests
// Only available for non-WASM targets

#[cfg(not(target_arch = "wasm32"))]
pub mod auth;

#[cfg(not(target_arch = "wasm32"))]
pub mod http;

#[cfg(not(target_arch = "wasm32"))]
pub mod upload;

#[cfg(not(target_arch = "wasm32"))]
pub mod decrypt;

#[cfg(not(target_arch = "wasm32"))]
pub mod acl;

#[cfg(not(target_arch = "wasm32"))]
pub mod chain;

#[cfg(not(target_arch = "wasm32"))]
pub mod contract;

#[cfg(not(target_arch = "wasm32"))]
pub mod run;

// Re-export commonly used functions for convenience
#[cfg(not(target_arch = "wasm32"))]
pub use auth::{get_timestamp_millis, parse_private_key};

#[cfg(not(target_arch = "wasm32"))]
pub use http::{create_http_client, fetch_public_key};

#[cfg(not(target_arch = "wasm32"))]
pub use upload::{upload_ciphertext, upload_program};

#[cfg(not(target_arch = "wasm32"))]
pub use decrypt::{decrypt_ciphertext, poll_decryption_result, request_decryption};

#[cfg(not(target_arch = "wasm32"))]
pub use acl::{
    AclCheckResponse, AclCheckResult, AclCheckSuccess, SpfCiphertextAccessConfirmation,
    admin_access, check_admin_access, check_decrypt_access, check_run_access, decrypt_access,
    run_access, update_access_typed,
};

#[cfg(not(target_arch = "wasm32"))]
pub use run::{RunParameterSpec, RunStatus, check_run_status, poll_run_result, submit_run};
