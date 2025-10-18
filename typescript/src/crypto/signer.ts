import { secp as secp256k1 } from "./secp256k1-setup.js";
import { keccak_256 } from "@noble/hashes/sha3";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, stringToBytes } from "./utils.js";
import type { Address, Signature, Brand } from "../spf-client.js";

/**
 * Branded type for private keys
 *
 * Warning: Private keys are security-sensitive material. Never log, display,
 * or transmit private keys. Store them securely and clear them from memory
 * when no longer needed.
 *
 * Private keys are 32-byte hex strings (64 hex characters, optionally with 0x prefix).
 */
export type PrivateKey = Brand<string, "PrivateKey">;

/**
 * Create a PrivateKey from a string, normalizing to remove 0x prefix
 * @param value - String to convert to PrivateKey
 * @param validate - If true, validates format at runtime (default: true)
 * @throws {Error} If validate=true and format is invalid
 */
export function asPrivateKey(value: string, validate: boolean = true): PrivateKey {
  const cleanKey = value.startsWith("0x") ? value.slice(2) : value;
  if (validate && !isPrivateKey(value)) {
    throw new Error("Invalid private key format: must be 32-byte hex string (64 characters)");
  }
  return cleanKey as PrivateKey;
}

/**
 * Check if a string is a valid private key (32-byte hex, 64 characters, optionally with 0x prefix)
 */
export function isPrivateKey(value: string): value is PrivateKey {
  return /^(0x)?[0-9a-fA-F]{64}$/.test(value);
}

/**
 * Assert that a string is a valid private key, throwing error with helpful message if not
 * @param value - String to validate
 * @param name - Parameter name for error message (default: "value")
 * @throws {Error} If value is not a valid private key
 */
export function assertPrivateKey(value: string, name: string = "value"): asserts value is PrivateKey {
  if (!isPrivateKey(value)) {
    throw new Error(`${name} must be a valid private key (32-byte hex, 64 characters), got invalid format`);
  }
}

/**
 * Lightweight signer interface compatible with ethers.Signer
 *
 * This interface matches the subset of ethers.Signer API that SPF uses.
 * Both PrivateKeySigner and ethers.Signer implement this interface.
 */
export interface SpfSigner {
  /**
   * Get the Ethereum address for this signer
   * @returns Ethereum address with 0x prefix (checksummed)
   */
  getAddress(): Promise<Address> | Address;

  /**
   * Sign a message in raw
   *
   * @param message - Message to sign (Uint8Array or UTF-8 string)
   * @returns Promise resolving to signature hex string with 0x prefix
   */
  signRaw(message: Uint8Array | string): Promise<Signature>;
}

/**
 * Derive Ethereum address from secp256k1 public key
 *
 * @param publicKey - Uncompressed public key (65 bytes with 0x04 prefix)
 * @returns Ethereum address with 0x prefix (checksummed)
 */
function deriveAddress(publicKey: Uint8Array): Address {
  if (publicKey.length !== 65 || publicKey[0] !== 0x04) {
    throw new Error("Invalid public key format");
  }

  // Hash the public key without the 0x04 prefix
  const hash = keccak_256(publicKey.slice(1));

  // Take the last 20 bytes
  const addressBytes = hash.slice(-20);

  return toChecksumAddress(bytesToHex(addressBytes)) as Address;
}

/**
 * Convert address to EIP-55 checksum format
 *
 * @param address - Address hex string with 0x prefix
 * @returns Checksummed address
 */
function toChecksumAddress(address: string): string {
  const addr = address.toLowerCase().replace("0x", "");
  const hash = bytesToHex(keccak_256(stringToBytes(addr))).slice(2);

  let checksummed = "0x";
  for (let i = 0; i < addr.length; i++) {
    const char = addr[i];
    if (char === undefined) continue;

    const hashChar = hash[i];
    if (hashChar === undefined) continue;

    // If hash digit >= 8, uppercase the address character
    if (parseInt(hashChar, 16) >= 8) {
      checksummed += char.toUpperCase();
    } else {
      checksummed += char;
    }
  }

  return checksummed;
}

/**
 * Lightweight private key signer using @noble/secp256k1
 *
 * Implements raw message signing.
 */
export class PrivateKeySigner implements SpfSigner {
  private readonly privateKey: string;
  private readonly address: Address;

  /**
   * Create a signer from a private key
   *
   * Warning: Never log or display private keys. Store them securely.
   *
   * @param privateKey - Private key as hex string (with or without 0x prefix)
   * @throws {Error} If private key format is invalid
   */
  constructor(privateKey: PrivateKey) {
    // Clean and validate private key
    const cleanKey = privateKey.startsWith("0x")
      ? privateKey.slice(2)
      : privateKey;

    if (cleanKey.length !== 64) {
      throw new Error(`Invalid private key length: ${cleanKey.length}, expected 64`);
    }

    if (!/^[0-9a-fA-F]{64}$/.test(cleanKey)) {
      throw new Error("Invalid private key: must be hex string");
    }

    this.privateKey = cleanKey;

    // Derive address from public key
    const publicKey = secp256k1.getPublicKey(cleanKey, false);
    this.address = deriveAddress(publicKey);
  }

  /**
   * Create a random signer with a new private key
   *
   * @returns New PrivateKeySigner with random private key
   */
  static random(): PrivateKeySigner {
    const privateKey = secp256k1.utils.randomPrivateKey();
    return new PrivateKeySigner(asPrivateKey(bytesToHex(privateKey)));
  }

  /**
   * Get the Ethereum address for this signer
   *
   * @returns Ethereum address with 0x prefix (checksummed)
   */
  getAddress(): Address {
    return this.address;
  }

  /**
   * Sign a message in raw
   *
   * Supports both Uint8Array and string messages.
   * String messages are converted to UTF-8 bytes.
   *
   * @param message - Message to sign
   * @returns Promise resolving to signature hex string with 0x prefix
   */
  signRaw(message: Uint8Array | string): Promise<Signature> {
    const messageBytes =
      typeof message === "string" ? stringToBytes(message) : message;

    // Sign with recovery
    const signature = secp256k1.sign(sha256(messageBytes), this.privateKey);

    // Extract r, s, and recovery
    // noble/secp256k1 v2 returns signature with recoveryBit property
    const r = signature.r.toString(16).padStart(64, "0");
    const s = signature.s.toString(16).padStart(64, "0");
    const recovery = signature.recovery ?? 0;
    const v = recovery.toString(16).padStart(2, "0");

    return Promise.resolve(`0x${r}${s}${v}` as Signature);
  }
}
