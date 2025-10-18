import { getWasmModule, isInitialized } from "@sunscreen/spf-client/spf-wasm-loader";
import type { BitWidth } from "./spf-client.js";

/**
 * Convert a bigint to number, throwing an error if the value is outside the safe integer range.
 *
 * JavaScript's Number type can only safely represent integers between Number.MIN_SAFE_INTEGER
 * and Number.MAX_SAFE_INTEGER (±2^53 - 1). Values outside this range will lose precision.
 *
 * @param value - The bigint value to convert
 * @returns The value as a number
 * @throws {Error} If the value is outside the safe integer range
 *
 * @example
 * ```typescript
 * const result = await waitForDecryption(handle, 16, false);  // bigint
 * const asNumber = toNumber(result);  // number (throws if unsafe)
 * ```
 */
export function toNumber(value: bigint): number {
  if (value < Number.MIN_SAFE_INTEGER || value > Number.MAX_SAFE_INTEGER) {
    throw new Error(
      `Value ${value} is outside the safe integer range ` +
      `(${Number.MIN_SAFE_INTEGER} to ${Number.MAX_SAFE_INTEGER})`
    );
  }
  return Number(value);
}

/**
 * Convert a bigint to number if it fits in the safe integer range, otherwise return the bigint.
 *
 * This is useful when you want to use number type for convenience when possible,
 * but preserve precision for large values.
 *
 * @param value - The bigint value to convert
 * @returns The value as number if it fits in safe range, otherwise bigint
 *
 * @example
 * ```typescript
 * const result = await waitForDecryption(handle, 64, false);  // bigint
 * const maybeNumber = toNumberIfSafe(result);  // number | bigint
 *
 * if (typeof maybeNumber === 'number') {
 *   console.log('Small value:', maybeNumber * 2);
 * } else {
 *   console.log('Large value:', maybeNumber * 2n);
 * }
 * ```
 */
export function toNumberIfSafe(value: bigint): number | bigint {
  if (value >= Number.MIN_SAFE_INTEGER && value <= Number.MAX_SAFE_INTEGER) {
    return Number(value);
  }
  return value;
}

/**
 * One-time pad keypair for local decryption
 */
export interface OtpKeypair {
  /** Public OTP (FHE-encrypted, sent to SPF for reencryption) */
  readonly publicOtp: Uint8Array;

  /** Secret OTP (kept locally for final decryption) */
  readonly secretOtp: Uint8Array;
}

/**
 * Validate that a value fits within the specified bit width.
 * @internal
 */
function validateValue(
  value: number | bigint,
  bitWidth: BitWidth,
  signed: boolean,
): void {
  const val = typeof value === "bigint" ? value : BigInt(value);

  if (signed) {
    // Signed range: -2^(bits-1) to 2^(bits-1) - 1
    const minValue = -(1n << BigInt(bitWidth - 1));
    const maxValue = (1n << BigInt(bitWidth - 1)) - 1n;

    if (val < minValue || val > maxValue) {
      throw new Error(
        `Signed value ${value} is out of range for ${bitWidth}-bit width (range: ${minValue} to ${maxValue})`,
      );
    }
  } else {
    // Unsigned range: 0 to 2^bits - 1
    if (val < 0n) {
      throw new Error(
        `Unsigned value ${value} must be non-negative (got ${value})`,
      );
    }

    const maxValue = (1n << BigInt(bitWidth)) - 1n;
    if (val > maxValue) {
      throw new Error(
        `Unsigned value ${value} exceeds maximum for ${bitWidth}-bit width (max: ${maxValue})`,
      );
    }
  }
}

/**
 * Encrypt a value under the SPF threshold network public key.
 *
 * Supports both signed and unsigned integers. The signed/unsigned interpretation
 * is automatically detected based on the value (negative values are treated as signed).
 *
 * @param value - The plaintext value to encrypt
 * @param bitWidth - The bit width (8, 16, 32, or 64)
 * @returns Promise resolving to bincode-serialized ciphertext bytes
 * @throws {Error} If encryption fails or parameters are invalid
 *
 * @example
 * ```typescript
 * // Encrypt unsigned value
 * const ct1 = await encryptValue(42, 16);
 *
 * // Encrypt signed value (negative)
 * const ct2 = await encryptValue(-1, 16);
 * ```
 */
export async function encryptValue(
  value: number | bigint,
  bitWidth: BitWidth,
): Promise<Uint8Array> {
  // Check WASM initialization
  if (!isInitialized()) {
    throw new Error(
      "SPF client not initialized. Call initialize(endpoint) before encrypting values."
    );
  }

  // Auto-detect signedness based on value
  const val = typeof value === "bigint" ? value : BigInt(value);
  const isSigned = val < 0n;

  // Validate value fits in bit width
  validateValue(value, bitWidth, isSigned);

  // Load WASM module (WASM manages public key internally)
  const wasm = await getWasmModule();

  try {
    if (isSigned) {
      return wasm.encrypt_signed(val, bitWidth);
    } else {
      return wasm.encrypt_unsigned(val, bitWidth);
    }
  } catch (error) {
    if (error instanceof Error) {
      error.message = `Encryption failed: ${error.message}`;
      throw error;
    }
    throw new Error(`Encryption failed: ${String(error)}`);
  }
}

/**
 * Encrypt multiple values as an array of ciphertexts.
 *
 * This is more efficient than calling encryptValue() multiple times
 * as it fetches the public key only once.
 *
 * @param values - Array of plaintext values
 * @param bitWidth - The bit width for all values
 * @returns Promise resolving to array of ciphertext bytes
 * @throws {Error} If any encryption fails
 *
 * @example
 * ```typescript
 * const votes = [1, -1, 1, 1];
 * const ciphertexts = await encryptValues(votes, 16);
 *
 * // Upload all ciphertexts
 * const ctIds = await Promise.all(
 *   ciphertexts.map(ct => uploadCiphertext(wallet, ct))
 * );
 * ```
 */
export async function encryptValues(
  values: readonly (number | bigint)[],
  bitWidth: BitWidth,
): Promise<Uint8Array[]> {
  // Encrypt all values (WASM manages public key internally)
  return Promise.all(
    values.map((value) => encryptValue(value, bitWidth)),
  );
}

/**
 * Generate a one-time pad keypair for local decryption.
 *
 * The OTP enables instant local decryption after SPF reencryption:
 * 1. Generate OTP keypair
 * 2. Request reencryption with public OTP
 * 3. Threshold decrypt the reencrypted ciphertext (returns OTP-encrypted polynomial)
 * 4. Locally decrypt with secret OTP (instant, no network)
 *
 * @param publicKey - Optional: SPF public key (fetched if not provided)
 * @returns Promise resolving to OTP keypair
 * @throws {Error} If OTP generation fails
 *
 * @example
 * ```typescript
 * const { publicOtp, secretOtp } = await generateOtp();
 *
 * // Use public OTP for reencryption (send to SPF)
 * const reencryptHandle = await requestReencryption(wallet, ciphertextId, publicOtp);
 *
 * // Later: decrypt with secret OTP (local)
 * const plaintext = await otpDecrypt(otpEncryptedPoly, secretOtp, 16);
 * ```
 */
export async function generateOtp(): Promise<OtpKeypair> {
  // Check WASM initialization
  if (!isInitialized()) {
    throw new Error(
      "SPF client not initialized. Call initialize(endpoint) before generating OTP."
    );
  }

  const wasm = await getWasmModule();

  try {
    const keypair = wasm.generate_otp();

    return {
      publicOtp: keypair.public_otp,
      secretOtp: keypair.secret_otp,
    };
  } catch (error) {
    if (error instanceof Error) {
      error.message = `OTP generation failed: ${error.message}`;
      throw error;
    }
    throw new Error(`OTP generation failed: ${String(error)}`);
  }
}

/**
 * Decrypt an OTP-encrypted polynomial using the secret OTP.
 *
 * This performs instant local decryption of a polynomial that was
 * encrypted under a one-time pad by the SPF threshold network.
 *
 * @param polyBytes - Bincode-serialized Polynomial<u64> from threshold decryption
 * @param secretOtp - The secret one-time pad bytes
 * @param bitWidth - The bit width of the original value
 * @param signed - Whether the value is signed
 * @returns Promise resolving to the decrypted value as bigint
 * @throws {Error} If OTP decryption fails
 *
 * @example
 * ```typescript
 * // After reencryption and threshold decryption
 * const otpEncryptedPoly = await waitForDecryption(decryptHandle);
 *
 * // Instant local decryption
 * const plaintext = await otpDecrypt(otpEncryptedPoly, secretOtp, 16, true);
 * console.log('Decrypted value:', plaintext);
 * ```
 */
export async function otpDecrypt(
  polyBytes: Uint8Array,
  secretOtp: Uint8Array,
  bitWidth: BitWidth,
  signed: boolean,
): Promise<bigint> {
  // Check WASM initialization
  if (!isInitialized()) {
    throw new Error(
      "SPF client not initialized. Call initialize(endpoint) before decrypting."
    );
  }

  const wasm = await getWasmModule();

  try {
    if (signed) {
      return wasm.otp_decrypt_signed(polyBytes, secretOtp, bitWidth);
    } else {
      return wasm.otp_decrypt_unsigned(polyBytes, secretOtp, bitWidth);
    }
  } catch (error) {
    if (error instanceof Error) {
      error.message = `OTP decryption failed: ${error.message}`;
      throw error;
    }
    throw new Error(`OTP decryption failed: ${String(error)}`);
  }
}
