/**
 * Browser-specific WASM loader for bundler target
 *
 * This module handles WASM initialization for browser environments.
 * The bundler target (used by Vite, Webpack, etc.) automatically handles
 * WASM loading, so we don't need the manual fetch/init logic.
 */

import * as WasmModule from '../../wasm-bindings/spf_client.js';
import type { OtpKeypair } from '../../wasm-bindings/spf_client.js';
import { getPublicKey, clearPublicKeyCache } from '../public-key.js';
import {
  getEndpoint,
  setEndpoint,
  clearEndpoint,
  getCurrentEndpoint,
  getAuthSecret,
  setAuthSecret,
} from '../internal/endpoint-state.js';
import { asSpfAuthSecret } from '../spf-client.js';

let initialized = false;
let cachedPublicKeyBytes: Uint8Array | null = null;

/**
 * Initialize with SPF endpoint (fetches public key and initializes WASM)
 *
 * Note: With bundler target, WASM is already loaded by the bundler.
 * This function only handles the SPF-specific initialization (public key).
 */
export async function initialize(endpoint: string = "https://spf.sunscreen.tech", authSecret: string): Promise<void> {
  const currentEndpoint = getCurrentEndpoint();
  const currentAuthSecret = getAuthSecret();

  // If already initialized with the same endpoint, skip
  if (initialized && currentEndpoint === endpoint && authSecret === currentAuthSecret) {
    return;
  }

  // If initialized with different endpoint, caller must clear first
  if (initialized && currentEndpoint !== endpoint) {
    throw new Error(
      `WASM module already initialized with endpoint ${currentEndpoint}. ` +
      `Call clearWasmCache() before initializing with a different endpoint (${endpoint}).`
    );
  }

  try {
    // Set endpoint before fetching public key (getPublicKey uses getEndpoint)
    // Import asSpfEndpoint from spf-client
    const { asSpfEndpoint } = await import("../spf-client.js");
    setEndpoint(asSpfEndpoint(endpoint));
    setAuthSecret(asSpfAuthSecret(authSecret));

    // Fetch public key
    const publicKeyBytes = await getPublicKey();

    // Check if we already have a cached public key
    if (cachedPublicKeyBytes !== null) {
      // Compare the new public key with the cached one
      const cached = cachedPublicKeyBytes; // Local variable for type narrowing
      const isSameKey = publicKeyBytes.length === cached.length &&
        publicKeyBytes.every((byte, index) => byte === cached[index]);

      if (isSameKey) {
        // Same public key - just update endpoint, no need to reinitialize WASM
        // The WASM module is already initialized with this key
        initialized = true;
        return;
      } else {
        // Different public key - this requires page reload since WASM OnceLock can't be reset
        throw new Error(
          `Cannot switch to endpoint with different public key. ` +
          `The WASM module is already initialized with a different key. ` +
          `Please reload the page to use a different endpoint.`
        );
      }
    }

    // First time initialization - initialize WASM with the fetched public key bytes
    try {
      WasmModule.initialize_with_public_key(publicKeyBytes);
      cachedPublicKeyBytes = publicKeyBytes;
      initialized = true;
    } catch (error) {
      // If initialization fails due to already being initialized, check the error message
      const errorMsg = error instanceof Error ? error.message : String(error);
      if (errorMsg.includes("already initialized")) {
        throw new Error(
          `WASM module already initialized. Call clearWasmCache() before reinitializing.`
        );
      }
      throw error;
    }
  } catch (error) {
    // Reset endpoint on any initialization failure
    clearEndpoint();
    initialized = false;
    throw error;
  }
}

/**
 * Check if initialized with public key
 */
export function isInitialized(): boolean {
  return initialized;
}

/**
 * Get the WASM module (for compatibility with Node.js loader)
 * With bundler target, WASM is already loaded, just return the module
 */
export function getWasmModule(): typeof WasmModule {
  return WasmModule;
}

/**
 * Preload WASM module (for compatibility with Node.js loader)
 * With bundler target, WASM is already loaded, so this is a no-op
 */
export async function preloadWasm(): Promise<void> {
  // No-op: bundler already loaded WASM
  return Promise.resolve();
}

/**
 * Clear initialization state (allows reinitializing with different endpoint)
 */
export function clearWasmCache(): void {
  initialized = false;
  clearEndpoint();
  clearPublicKeyCache();
}

// Re-export getEndpoint from shared module
export { getEndpoint };

/**
 * Re-export all WASM functions directly
 * With bundler target, these are already initialized by the bundler
 */
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

export type { OtpKeypair };
