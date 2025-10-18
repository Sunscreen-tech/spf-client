/**
 * Configured secp256k1 instance with HMAC setup for Node.js
 *
 * This module MUST be imported instead of importing @noble/secp256k1 directly
 * to ensure HMAC is properly configured for secure random number generation.
 */
import * as secp256k1Module from "@noble/secp256k1";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";

// Configure HMAC for secp256k1 (required for Node.js)
secp256k1Module.etc.hmacSha256Sync = (key: Uint8Array, ...messages: Uint8Array[]) => {
  const h = hmac.create(sha256, key);
  messages.forEach((m) => h.update(m));
  return h.digest();
};

// Export the configured instance
export const secp = secp256k1Module;
export default secp256k1Module;
