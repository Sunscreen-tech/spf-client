pub mod client;
pub mod core;
pub mod message;

#[cfg(target_arch = "wasm32")]
mod wasm;

#[cfg(target_arch = "wasm32")]
pub use wasm::*;

// Native (non-WASM) convenience functions
#[cfg(not(target_arch = "wasm32"))]
pub mod native {
    use crate::{
        client,
        core::{crypto, error::Result},
    };

    pub fn encrypt_unsigned(val: u64, bits: u8) -> Result<Vec<u8>> {
        let pk = client::get_public_key()?;
        crypto::encrypt_unsigned_core(val, bits, pk)
    }

    pub fn encrypt_signed(val: i64, bits: u8) -> Result<Vec<u8>> {
        let pk = client::get_public_key()?;
        crypto::encrypt_signed_core(val, bits, pk)
    }

    pub fn generate_otp() -> Result<(Vec<u8>, Vec<u8>)> {
        let pk = client::get_public_key()?;
        let keypair = crypto::generate_otp_core(pk)?;
        Ok((keypair.public_otp, keypair.secret_otp))
    }

    pub fn otp_decrypt_unsigned(poly_bytes: &[u8], secret_otp: &[u8], bits: u8) -> Result<u64> {
        crypto::otp_decrypt_unsigned_core(poly_bytes, secret_otp, bits)
    }

    pub fn otp_decrypt_signed(poly_bytes: &[u8], secret_otp: &[u8], bits: u8) -> Result<i64> {
        crypto::otp_decrypt_signed_core(poly_bytes, secret_otp, bits)
    }

    pub fn public_otp_size() -> u32 {
        crypto::public_otp_size()
    }

    pub fn secret_otp_size() -> u32 {
        crypto::secret_otp_size()
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use native::*;

// CLI operations module - HTTP-aware operations for CLI and integration tests
#[cfg(not(target_arch = "wasm32"))]
pub mod cli;

// EIP-712 type definitions for authentication
#[cfg(not(target_arch = "wasm32"))]
pub mod eip712_types;
