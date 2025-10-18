/**
 * Crypto module - Lightweight replacements for ethers.js
 *
 * This module provides all the cryptographic primitives needed for SPF
 * using lightweight libraries (@noble/secp256k1, @noble/hashes, viem).
 */

// Utility functions
export {
  bytesToHex,
  hexToBytes,
  stringToBytes,
  concatBytes,
  numberToBeHex,
  keccak256,
} from "./utils.js";

// Signer interface and implementation
export {
  PrivateKeySigner,
} from "./signer.js";

export type {
  SpfSigner,
} from "./signer.js";

// ABI encoding
export {
  encodeSpfRunAbi,
  encodeSpfAccessAbi,
} from "./abi.js";

export type {
  SpfParameter,
  SpfRun,
  SpfAccess,
} from "./abi.js";
