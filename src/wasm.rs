// WASM bindings for spf_client
// This module provides wasm-bindgen exports that wrap the library API

use wasm_bindgen::prelude::*;

use crate::{
    client,
    core::{crypto, encoding, error::SpfError, utils},
    message,
};

// Helper to convert SpfError to JsValue
fn to_js_error(err: SpfError) -> JsValue {
    JsValue::from_str(&err.to_string())
}

#[wasm_bindgen]
pub fn initialize_with_public_key(public_key_bytes: &[u8]) -> Result<(), JsValue> {
    client::initialize_with_public_key(public_key_bytes).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn encrypt_unsigned(val: u64, bits: u8) -> Result<Vec<u8>, JsValue> {
    let pk = client::get_public_key().map_err(to_js_error)?;
    crypto::encrypt_unsigned_core(val, bits, pk).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn encrypt_signed(val: i64, bits: u8) -> Result<Vec<u8>, JsValue> {
    let pk = client::get_public_key().map_err(to_js_error)?;
    crypto::encrypt_signed_core(val, bits, pk).map_err(to_js_error)
}

#[wasm_bindgen]
pub struct OtpKeypair {
    public_otp: Vec<u8>,
    secret_otp: Vec<u8>,
}

#[wasm_bindgen]
impl OtpKeypair {
    #[wasm_bindgen(getter)]
    pub fn public_otp(&self) -> Vec<u8> {
        self.public_otp.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn secret_otp(&self) -> Vec<u8> {
        self.secret_otp.clone()
    }
}

#[wasm_bindgen]
pub fn generate_otp() -> Result<OtpKeypair, JsValue> {
    let pk = client::get_public_key().map_err(to_js_error)?;
    let keypair = crypto::generate_otp_core(pk).map_err(to_js_error)?;

    Ok(OtpKeypair {
        public_otp: keypair.public_otp,
        secret_otp: keypair.secret_otp,
    })
}

#[wasm_bindgen]
pub fn otp_decrypt_unsigned(
    poly_bytes: &[u8],
    secret_otp: &[u8],
    bits: u8,
) -> Result<u64, JsValue> {
    crypto::otp_decrypt_unsigned_core(poly_bytes, secret_otp, bits).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn otp_decrypt_signed(poly_bytes: &[u8], secret_otp: &[u8], bits: u8) -> Result<i64, JsValue> {
    crypto::otp_decrypt_signed_core(poly_bytes, secret_otp, bits).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn public_otp_size() -> u32 {
    crypto::public_otp_size()
}

#[wasm_bindgen]
pub fn secret_otp_size() -> u32 {
    crypto::secret_otp_size()
}

#[wasm_bindgen]
pub fn create_message_to_sign(
    address: &str,
    timestamp_millis: f64,
    body: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let addr = encoding::parse_address_hex(address).map_err(to_js_error)?;
    let timestamp = timestamp_millis as u64;

    Ok(message::create_message_bytes(addr, timestamp, body))
}

#[wasm_bindgen]
pub fn create_identity_header(
    address: &str,
    timestamp_millis: f64,
    signature_type: &str,
    signature: &str,
) -> Result<String, JsValue> {
    let timestamp = timestamp_millis as u64;
    message::create_identity_header(address, timestamp, signature_type, signature)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn derive_ciphertext_id(ciphertext_bytes: &[u8]) -> String {
    utils::derive_ciphertext_id(ciphertext_bytes)
}

#[wasm_bindgen]
pub fn derive_program_id(elf_bytes: &[u8]) -> String {
    utils::derive_program_id(elf_bytes)
}

#[wasm_bindgen]
pub fn derive_result_id(run_handle: &str, index: u8) -> Result<String, JsValue> {
    utils::derive_result_id(run_handle, index).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn encode_program_name(name: &str) -> Result<String, JsValue> {
    let encoded = encoding::encode_program_name(name).map_err(to_js_error)?;
    Ok(format!("0x{}", hex::encode(encoded.as_slice())))
}

#[wasm_bindgen]
pub fn create_meta_data(bytes: &[u8]) -> Result<String, JsValue> {
    let meta = encoding::create_meta_data(bytes).map_err(to_js_error)?;
    Ok(format!("0x{}", hex::encode(meta.as_slice())))
}

#[wasm_bindgen]
pub fn encode_access_admin(address: &str, chain_id: Option<f64>) -> Result<Vec<u8>, JsValue> {
    let addr = encoding::parse_address_hex(address).map_err(to_js_error)?;
    let chain_id = chain_id.map(|c| c as u64);

    encoding::encode_access(encoding::AccessType::Admin { chain_id, addr }).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn encode_access_decrypt(address: &str, chain_id: Option<f64>) -> Result<Vec<u8>, JsValue> {
    let addr = encoding::parse_address_hex(address).map_err(to_js_error)?;
    let chain_id = chain_id.map(|c| c as u64);

    encoding::encode_access(encoding::AccessType::Decrypt { chain_id, addr }).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn encode_access_run(
    address: &str,
    chain_id: Option<f64>,
    library_hash: &str,
    entry_point: &str,
) -> Result<Vec<u8>, JsValue> {
    let addr = encoding::parse_address_hex(address).map_err(to_js_error)?;
    let lib = encoding::parse_b256_hex(library_hash).map_err(to_js_error)?;
    let chain_id = chain_id.map(|c| c as u64);

    encoding::encode_access(encoding::AccessType::Run {
        chain_id,
        addr,
        lib,
        entry_point: entry_point.to_string(),
    })
    .map_err(to_js_error)
}

#[wasm_bindgen]
pub fn parse_polynomial_to_value(
    poly_bytes: &[u8],
    bit_width: u8,
    signed: bool,
) -> Result<i64, JsValue> {
    crypto::parse_polynomial_to_value(poly_bytes, bit_width, signed).map_err(to_js_error)
}
