/**
 * Browser entry point for spf-client
 *
 * This module exports everything from the main client library
 * plus browser-specific WASM initialization functions.
 *
 * When imported in a browser environment (via conditional exports),
 * users get all the main functionality plus browser-compatible WASM loading.
 */

// Re-export everything from the main client
export * from '../spf-client.js';

// Re-export ACL module
export * from '../acl.js';

// Re-export browser-specific WASM functions
// These override the Node.js wasm-loader with browser implementations
// Re-export browser WASM loader functions
export {
  initialize,
  isInitialized,
  getWasmModule,
  preloadWasm,
  clearWasmCache,
  type OtpKeypair,
} from './wasm-loader.js';

// Re-export all WASM functions directly from WASM bindings
export {
  initialize_with_public_key,
  encrypt_unsigned,
  encrypt_signed,
  generate_otp,
  otp_decrypt_unsigned,
  otp_decrypt_signed,
  public_otp_size,
  secret_otp_size,
  create_message_to_sign,
  create_identity_header,
  derive_ciphertext_id,
  derive_program_id,
  derive_result_id,
  encode_program_name,
  create_meta_data,
  encode_access_admin,
  encode_access_decrypt,
  encode_access_run,
  parse_polynomial_to_value,
} from '../../wasm-bindings/spf_client.js';
