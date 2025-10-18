import { keccak_256 } from "@noble/hashes/sha3";
import type { HexString } from "../spf-client.js";

/**
 * Convert bytes to hex string with 0x prefix
 */
export function bytesToHex(bytes: Uint8Array): string {
  return "0x" + Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Convert hex string (with or without 0x prefix) to bytes
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;

  if (cleanHex.length % 2 !== 0) {
    throw new Error("Invalid hex string: odd length");
  }

  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    const byte = parseInt(cleanHex.slice(i, i + 2), 16);
    if (isNaN(byte)) {
      throw new Error(`Invalid hex string at position ${i}: ${cleanHex.slice(i, i + 2)}`);
    }
    bytes[i / 2] = byte;
  }

  return bytes;
}

/**
 * Convert UTF-8 string to bytes using TextEncoder
 */
export function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Concatenate multiple byte arrays
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);

  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}

/**
 * Convert number or bigint to big-endian hex string with 0x prefix
 *
 * @param value - Number or bigint value
 * @param bytes - Number of bytes for output (will be padded/truncated)
 * @returns Hex string with 0x prefix
 */
export function numberToBeHex(value: number | bigint, bytes: number): HexString {
  let bigIntValue;
  if (value >= 0) {
    bigIntValue = BigInt(value);
  } else {
    // 2's complement for negative
    bigIntValue = BigInt(2 ** (bytes * 8)) + BigInt(value);
  }

  // Convert to hex without 0x prefix
  let hex = bigIntValue.toString(16);

  // Pad to exact byte length
  const targetLength = bytes * 2;
  if (hex.length < targetLength) {
    hex = hex.padStart(targetLength, "0");
  } else if (hex.length > targetLength) {
    // Truncate from left (keep lower bits)
    hex = hex.slice(-targetLength);
  }

  return ("0x" + hex) as HexString;
}

/**
 * Compute keccak256 hash of data
 *
 * @param data - Input data as Uint8Array
 * @returns Keccak256 hash as hex string with 0x prefix
 */
export function keccak256(data: Uint8Array): string {
  return bytesToHex(keccak_256(data));
}
