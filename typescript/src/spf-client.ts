import type { Signer as EthersSigner, TypedDataField } from "ethers";
import { getWasmModule, getEndpoint } from "@sunscreen/spf-client/spf-wasm-loader";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  bytesToHex,
  hexToBytes,
  stringToBytes,
  keccak256,
  concatBytes,
  numberToBeHex,
  type SpfSigner,
  encodeSpfRunAbi,
} from "./crypto/index.js";
import {
  parseStringResponse,
  parseRunStatusResponse,
  parseDecryptionStatusResponseRaw,
  parseDecryptionStatusResponse,
  type DecryptionStatusRaw,
} from "./parsers.js";
import { validateParameterAuth } from "./validation.js";

/**
 * Union type supporting both lightweight SpfSigner and ethers.Signer
 * This maintains backward compatibility while allowing the use of lightweight signers
 */
export type AnySigner = SpfSigner | EthersSigner;

// Constants

export const SPF_BASE_URL = "https://spf.sunscreen.tech";

// Branded Types

/**
 * Unique symbol for creating branded types
 * @internal
 */
declare const __brand: unique symbol;

/**
 * Generic brand wrapper for creating nominal types
 *
 * This pattern creates "phantom types" that are structurally identical to the base type
 * but are nominally distinct, preventing accidental mixing of similar types.
 *
 * @internal
 */
export type Brand<T, TBrand extends string> = T & { readonly [__brand]: TBrand };

/**
 * Hex string template literal type with 0x prefix
 * Provides compile-time validation of hex format
 */
export type HexString = `0x${string}`;

/**
 * Branded type for library identifiers (program hashes)
 */
export type LibraryId = Brand<HexString, "LibraryId">;

/**
 * Branded type for ciphertext identifiers
 */
export type CiphertextId = Brand<HexString, "CiphertextId">;

/**
 * Branded type for run handles
 */
export type RunHandle = Brand<HexString, "RunHandle">;

/**
 * Branded type for decryption handles
 */
export type DecryptHandle = Brand<HexString, "DecryptHandle">;

/**
 * Branded type for reencryption handles
 */
export type ReencryptHandle = Brand<HexString, "ReencryptHandle">;

/**
 * Branded type for cryptographic signatures
 */
export type Signature = Brand<HexString, "Signature">;

/**
 * Branded type for SPF identity headers
 *
 * Identity headers are used for authentication in SPF API requests.
 * They contain entity information, timestamp, signature method, and cryptographic signature.
 * These are created via the createIdentityHeader() function and cannot be constructed manually.
 */
export type IdentityHeader = Brand<string, "IdentityHeader">;

/**
 * Branded type for Ethereum addresses
 *
 * Ethereum addresses are 20-byte hex strings with 0x prefix (42 characters total).
 * Addresses should be EIP-55 checksummed for display purposes.
 */
export type Address = Brand<HexString, "Address">;

/**
 * Branded type for FHE program names
 *
 * Program names are ASCII strings (max 32 bytes) that identify entry points in compiled FHE programs.
 * Names must contain only printable ASCII characters (0x20-0x7E).
 */
export type ProgramName = Brand<string, "ProgramName">;

/**
 * Branded type for SPF API endpoints
 *
 * Endpoints are valid HTTP or HTTPS URLs pointing to SPF service instances.
 */
export type SpfEndpoint = Brand<string, "SpfEndpoint">;

/**
 * Branded type for SPF parameter metadata
 *
 * Metadata is a 32-byte uint256 encoded as a hex string with 0x prefix (66 characters).
 * It encodes parameter type information for SPF operations.
 */
export type MetaData = Brand<HexString, "MetaData">;

/**
 * Branded type for encoded program names
 *
 * Encoded program names are bytes32 hex strings (0x prefix, 66 characters)
 * created by padding ASCII program names to 32 bytes.
 */
export type EncodedProgramName = Brand<HexString, "EncodedProgramName">;

/**
 * Branded type for bytes32 hex strings
 *
 * Generic 32-byte hex strings used throughout the SPF protocol.
 */
export type Bytes32 = Brand<HexString, "Bytes32">;

/**
 * Create a LibraryId from a string, normalizing to 0x prefix
 * @param value - String to convert to LibraryId
 * @param validate - If true, validates format at runtime (default: true)
 * @throws {Error} If validate=true and format is invalid
 */
export function asLibraryId(value: string, validate: boolean = true): LibraryId {
  const normalized = value.startsWith('0x') ? value : `0x${value}`;
  if (validate && !isLibraryId(normalized)) {
    throw new Error(`Invalid library ID format: ${value}`);
  }
  return normalized as LibraryId;
}

/**
 * Create a CiphertextId from a string, normalizing to 0x prefix
 * @param value - String to convert to CiphertextId
 * @param validate - If true, validates format at runtime (default: true)
 * @throws {Error} If validate=true and format is invalid
 */
export function asCiphertextId(value: string, validate: boolean = true): CiphertextId {
  const normalized = value.startsWith('0x') ? value : `0x${value}`;
  if (validate && !isCiphertextId(normalized)) {
    throw new Error(`Invalid ciphertext ID format: ${value}`);
  }
  return normalized as CiphertextId;
}

/**
 * Create a RunHandle from a string, normalizing to 0x prefix
 * @param value - String to convert to RunHandle
 * @param validate - If true, validates format at runtime (default: true)
 * @throws {Error} If validate=true and format is invalid
 */
export function asRunHandle(value: string, validate: boolean = true): RunHandle {
  const normalized = value.startsWith('0x') ? value : `0x${value}`;
  if (validate && !isRunHandle(normalized)) {
    throw new Error(`Invalid run handle format: ${value}`);
  }
  return normalized as RunHandle;
}

/**
 * Create a DecryptHandle from a string, normalizing to 0x prefix
 * @param value - String to convert to DecryptHandle
 * @param validate - If true, validates format at runtime (default: true)
 * @throws {Error} If validate=true and format is invalid
 */
export function asDecryptHandle(value: string, validate: boolean = true): DecryptHandle {
  const normalized = value.startsWith('0x') ? value : `0x${value}`;
  if (validate && !isDecryptHandle(normalized)) {
    throw new Error(`Invalid decrypt handle format: ${value}`);
  }
  return normalized as DecryptHandle;
}

/**
 * Create a ReencryptHandle from a string, normalizing to 0x prefix
 * @param value - String to convert to ReencryptHandle
 * @param validate - If true, validates format at runtime (default: true)
 * @throws {Error} If validate=true and format is invalid
 */
export function asReencryptHandle(value: string, validate: boolean = true): ReencryptHandle {
  const normalized = value.startsWith('0x') ? value : `0x${value}`;
  if (validate && !isReencryptHandle(normalized)) {
    throw new Error(`Invalid reencrypt handle format: ${value}`);
  }
  return normalized as ReencryptHandle;
}

/**
 * Create a Signature from a string, normalizing to 0x prefix
 * @param value - String to convert to Signature
 * @param validate - If true, validates format at runtime (default: true)
 * @throws {Error} If validate=true and format is invalid
 */
export function asSignature(value: string, validate: boolean = true): Signature {
  const normalized = value.startsWith('0x') ? value : `0x${value}`;
  if (validate && !isSignature(normalized)) {
    throw new Error(`Invalid signature format: ${value}`);
  }
  return normalized as Signature;
}

/**
 * Check if a string is a valid library ID (64 hex characters, optional 0x prefix)
 */
export function isLibraryId(value: string): value is LibraryId {
  return /^(0x)?[0-9a-fA-F]{64}$/.test(value);
}

/**
 * Check if a string is a valid ciphertext ID (64 hex characters, optional 0x prefix)
 */
export function isCiphertextId(value: string): value is CiphertextId {
  return /^(0x)?[0-9a-fA-F]{64}$/.test(value);
}

/**
 * Check if a string is a valid run handle (64 hex characters, optional 0x prefix)
 */
export function isRunHandle(value: string): value is RunHandle {
  return /^(0x)?[0-9a-fA-F]{64}$/.test(value);
}

/**
 * Check if a string is a valid decrypt handle (64 hex characters, optional 0x prefix)
 */
export function isDecryptHandle(value: string): value is DecryptHandle {
  return /^(0x)?[0-9a-fA-F]{64}$/.test(value);
}

/**
 * Check if a string is a valid reencrypt handle (64 hex characters, optional 0x prefix)
 */
export function isReencryptHandle(value: string): value is ReencryptHandle {
  return /^(0x)?[0-9a-fA-F]{64}$/.test(value);
}

/**
 * Check if a string is a valid ECDSA signature (130 hex characters, optional 0x prefix)
 */
export function isSignature(value: string): value is Signature {
  return /^(0x)?[0-9a-fA-F]{130}$/.test(value);
}

/**
 * Assert that a string is a valid library ID, throwing error with helpful message if not
 * @param value - String to validate
 * @param name - Parameter name for error message (default: "value")
 * @throws {Error} If value is not a valid library ID
 */
export function assertLibraryId(value: string, name: string = "value"): asserts value is LibraryId {
  if (!isLibraryId(value)) {
    throw new Error(`${name} must be a valid library ID (64 hex characters), got: ${value}`);
  }
}

/**
 * Assert that a string is a valid ciphertext ID, throwing error with helpful message if not
 * @param value - String to validate
 * @param name - Parameter name for error message (default: "value")
 * @throws {Error} If value is not a valid ciphertext ID
 */
export function assertCiphertextId(value: string, name: string = "value"): asserts value is CiphertextId {
  if (!isCiphertextId(value)) {
    throw new Error(`${name} must be a valid ciphertext ID (64 hex characters), got: ${value}`);
  }
}

/**
 * Assert that a string is a valid run handle, throwing error with helpful message if not
 * @param value - String to validate
 * @param name - Parameter name for error message (default: "value")
 * @throws {Error} If value is not a valid run handle
 */
export function assertRunHandle(value: string, name: string = "value"): asserts value is RunHandle {
  if (!isRunHandle(value)) {
    throw new Error(`${name} must be a valid run handle (64 hex characters), got: ${value}`);
  }
}

/**
 * Assert that a string is a valid decrypt handle, throwing error with helpful message if not
 * @param value - String to validate
 * @param name - Parameter name for error message (default: "value")
 * @throws {Error} If value is not a valid decrypt handle
 */
export function assertDecryptHandle(value: string, name: string = "value"): asserts value is DecryptHandle {
  if (!isDecryptHandle(value)) {
    throw new Error(`${name} must be a valid decrypt handle (64 hex characters), got: ${value}`);
  }
}

/**
 * Assert that a string is a valid reencrypt handle, throwing error with helpful message if not
 * @param value - String to validate
 * @param name - Parameter name for error message (default: "value")
 * @throws {Error} If value is not a valid reencrypt handle
 */
export function assertReencryptHandle(value: string, name: string = "value"): asserts value is ReencryptHandle {
  if (!isReencryptHandle(value)) {
    throw new Error(`${name} must be a valid reencrypt handle (64 hex characters), got: ${value}`);
  }
}

/**
 * Assert that a string is a valid ECDSA signature, throwing error with helpful message if not
 * @param value - String to validate
 * @param name - Parameter name for error message (default: "value")
 * @throws {Error} If value is not a valid signature
 */
export function assertSignature(value: string, name: string = "value"): asserts value is Signature {
  if (!isSignature(value)) {
    throw new Error(`${name} must be a valid ECDSA signature (130 hex characters), got: ${value}`);
  }
}

/**
 * Create an Address from a string, normalizing to 0x prefix
 *
 * Note: This function lowercases the address for consistency. While this loses
 * EIP-55 checksum information, it ensures addresses are stored in a canonical
 * format. For display purposes, you may want to re-apply EIP-55 checksumming.
 *
 * @param value - String to convert to Address
 * @param validate - If true, validates format at runtime (default: true)
 * @throws {Error} If validate=true and format is invalid
 */
export function asAddress(value: string, validate: boolean = true): Address {
  const normalized = value.startsWith('0x') ? value.toLowerCase() : `0x${value.toLowerCase()}`;
  if (validate && !isAddress(normalized)) {
    throw new Error(`Invalid Ethereum address format: ${value}`);
  }
  return normalized as Address;
}

/**
 * Check if a string is a valid Ethereum address (20-byte hex with 0x prefix, 42 characters total)
 */
export function isAddress(value: string): value is Address {
  return /^0x[0-9a-fA-F]{40}$/.test(value);
}

/**
 * Assert that a string is a valid Ethereum address, throwing error with helpful message if not
 * @param value - String to validate
 * @param name - Parameter name for error message (default: "value")
 * @throws {Error} If value is not a valid Ethereum address
 */
export function assertAddress(value: string, name: string = "value"): asserts value is Address {
  if (!isAddress(value)) {
    throw new Error(`${name} must be a valid Ethereum address (20-byte hex, 42 characters with 0x prefix), got: ${value}`);
  }
}

/**
 * Create a ProgramName from a string with validation
 * @param value - String to convert to ProgramName
 * @param validate - If true, validates format at runtime (default: true)
 * @throws {Error} If validate=true and format is invalid
 */
export function asProgramName(value: string, validate: boolean = true): ProgramName {
  if (validate && !isProgramName(value)) {
    const bytes = stringToBytes(value);
    throw new Error(
      `Invalid program name: must be printable ASCII (max 32 bytes). ` +
      `Got ${bytes.length} bytes${bytes.length > 32 ? " (too long)" : ""}`
    );
  }
  return value as ProgramName;
}

/**
 * Check if a string is a valid program name (printable ASCII, max 32 bytes)
 */
export function isProgramName(value: string): value is ProgramName {
  const bytes = stringToBytes(value);
  return bytes.length <= 32 && /^[\x20-\x7E]*$/.test(value);
}

/**
 * Assert that a string is a valid program name, throwing error with helpful message if not
 * @param value - String to validate
 * @param name - Parameter name for error message (default: "value")
 * @throws {Error} If value is not a valid program name
 */
export function assertProgramName(value: string, name: string = "value"): asserts value is ProgramName {
  if (!isProgramName(value)) {
    const bytes = stringToBytes(value);
    throw new Error(
      `${name} must be a valid program name (printable ASCII, max 32 bytes). ` +
      `Got ${bytes.length} bytes${bytes.length > 32 ? " (too long)" : ""}`
    );
  }
}

/**
 * Create a Bytes32 from a string, normalizing to 0x prefix
 * @param value - String to convert to Bytes32
 * @param validate - If true, validates format at runtime (default: true)
 * @throws {Error} If validate=true and format is invalid
 */
export function asBytes32(value: string, validate: boolean = true): Bytes32 {
  const normalized = value.startsWith('0x') ? value : `0x${value}`;
  if (validate && !isBytes32(normalized)) {
    throw new Error(`Invalid bytes32 format: ${value}`);
  }
  return normalized as Bytes32;
}

/**
 * Check if a string is a valid bytes32 (64 hex characters, optional 0x prefix)
 */
export function isBytes32(value: string): value is Bytes32 {
  return /^(0x)?[0-9a-fA-F]{64}$/.test(value);
}

/**
 * Create a MetaData from a string, normalizing to 0x prefix
 * @param value - String to convert to MetaData
 * @param validate - If true, validates format at runtime (default: true)
 * @throws {Error} If validate=true and format is invalid
 */
export function asMetaData(value: string, validate: boolean = true): MetaData {
  const normalized = value.startsWith('0x') ? value : `0x${value}`;
  if (validate && !isMetaData(normalized)) {
    throw new Error(`Invalid metadata format: ${value}`);
  }
  return normalized as MetaData;
}

/**
 * Check if a string is a valid MetaData (64 hex characters, optional 0x prefix)
 */
export function isMetaData(value: string): value is MetaData {
  return /^(0x)?[0-9a-fA-F]{64}$/.test(value);
}

/**
 * Create an SpfEndpoint from a string with URL validation
 * @param value - String to convert to SpfEndpoint
 * @param validate - If true, validates URL format at runtime (default: true)
 * @throws {Error} If validate=true and URL is invalid
 */
export function asSpfEndpoint(value: string, validate: boolean = true): SpfEndpoint {
  if (validate && !isSpfEndpoint(value)) {
    throw new Error(`Invalid SPF endpoint: must be a valid HTTP/HTTPS URL, got: ${value}`);
  }
  return value as SpfEndpoint;
}

/**
 * Check if a string is a valid SPF endpoint (valid HTTP/HTTPS URL)
 */
export function isSpfEndpoint(value: string): value is SpfEndpoint {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Assert that a string is a valid bytes32, throwing error with helpful message if not
 * @param value - String to validate
 * @param name - Parameter name for error message (default: "value")
 * @throws {Error} If value is not a valid bytes32
 */
export function assertBytes32(value: string, name: string = "value"): asserts value is Bytes32 {
  if (!isBytes32(value)) {
    throw new Error(`${name} must be a valid bytes32 (64 hex characters), got: ${value}`);
  }
}

/**
 * Assert that a string is a valid MetaData, throwing error with helpful message if not
 * @param value - String to validate
 * @param name - Parameter name for error message (default: "value")
 * @throws {Error} If value is not a valid MetaData
 */
export function assertMetaData(value: string, name: string = "value"): asserts value is MetaData {
  if (!isMetaData(value)) {
    throw new Error(`${name} must be a valid metadata (64 hex characters), got: ${value}`);
  }
}

/**
 * Assert that a string is a valid SPF endpoint, throwing error with helpful message if not
 * @param value - String to validate
 * @param name - Parameter name for error message (default: "value")
 * @throws {Error} If value is not a valid SPF endpoint
 */
export function assertSpfEndpoint(value: string, name: string = "value"): asserts value is SpfEndpoint {
  if (!isSpfEndpoint(value)) {
    throw new Error(`${name} must be a valid SPF endpoint (HTTP/HTTPS URL), got: ${value}`);
  }
}

// Type Definitions

/**
 * Supported bit widths for FHE operations
 */
export type BitWidth = 8 | 16 | 32 | 64;

/**
 * SpfParameter structure for encoding program parameters
 *
 * Parameters are used in SPF run and access control operations.
 * Metadata encodes the parameter type, and payload contains the parameter data.
 */
export interface SpfParameter {
  readonly metaData: MetaData;
  readonly payload: readonly Bytes32[];
}

/**
 * Base interface for SPF parameter authentication data
 *
 * This structure is used in EIP-712 typed data for authenticating program runs.
 * Each parameter type has specific requirements for which fields are populated.
 *
 * @internal
 */
interface ParameterAuthenticationBase {
  readonly paramType: string;
  readonly plaintextValuesIfAny: readonly HexString[];
  readonly ciphertextIdsIfAny: readonly Bytes32[];
  readonly additionalInfoIfAny?: string;
}

/**
 * Authentication data for a single ciphertext parameter
 *
 * Used when authenticating a program run that accepts a single encrypted value as input.
 * The ciphertext ID must exactly match the ID in the corresponding SpfParameter payload.
 *
 * @example
 * ```typescript
 * const [param, auth] = createCiphertextParameter(ciphertextId);
 * // auth.paramType === "Ciphertext"
 * // auth.ciphertextIdsIfAny.length === 1
 * // auth.plaintextValuesIfAny.length === 0
 * ```
 */
export interface CiphertextParameterAuth extends ParameterAuthenticationBase {
  readonly paramType: "Ciphertext";
  readonly plaintextValuesIfAny: readonly [];
  readonly ciphertextIdsIfAny: readonly [Bytes32];
}

/**
 * Authentication data for a ciphertext array parameter
 *
 * Used when authenticating a program run that accepts multiple encrypted values as input.
 * The ciphertext IDs must exactly match the IDs in the corresponding SpfParameter payload.
 *
 * @example
 * ```typescript
 * const ctIds = [ctId1, ctId2, ctId3];
 * const [param, auth] = createCiphertextArrayParameter(ctIds);
 * // auth.paramType === "CiphertextArray"
 * // auth.ciphertextIdsIfAny.length === 3
 * // auth.plaintextValuesIfAny.length === 0
 * ```
 */
export interface CiphertextArrayParameterAuth extends ParameterAuthenticationBase {
  readonly paramType: "CiphertextArray";
  readonly plaintextValuesIfAny: readonly [];
  readonly ciphertextIdsIfAny: readonly Bytes32[];
}

/**
 * Authentication data for an output ciphertext array parameter
 *
 * Used when authenticating a program run that declares output ciphertext slots.
 * The additionalInfoIfAny field contains metadata about the expected output type.
 *
 * @example
 * ```typescript
 * const [param, auth] = createOutputCiphertextArrayParameter(8, 1);
 * // auth.paramType === "OutputCiphertextArray"
 * // auth.ciphertextIdsIfAny.length === 0 (no inputs)
 * // auth.plaintextValuesIfAny.length === 0
 * // auth.additionalInfoIfAny === "int8_t[1]"
 * ```
 */
export interface OutputCiphertextArrayParameterAuth extends ParameterAuthenticationBase {
  readonly paramType: "OutputCiphertextArray";
  readonly plaintextValuesIfAny: readonly [];
  readonly ciphertextIdsIfAny: readonly [];
  readonly additionalInfoIfAny: string;
}

/**
 * Authentication data for a plaintext parameter
 *
 * Used when authenticating a program run that accepts a single plaintext value as input.
 * The plaintext value and type metadata must match the corresponding SpfParameter payload.
 *
 * @example
 * ```typescript
 * const [param, auth] = createPlaintextParameter(16, 42);
 * // auth.paramType === "Plaintext"
 * // auth.plaintextValuesIfAny.length === 1
 * // auth.ciphertextIdsIfAny.length === 0
 * // auth.additionalInfoIfAny === "uint16_t"
 * ```
 */
export interface PlaintextParameterAuth extends ParameterAuthenticationBase {
  readonly paramType: "Plaintext";
  readonly plaintextValuesIfAny: readonly [HexString];
  readonly ciphertextIdsIfAny: readonly [];
  readonly additionalInfoIfAny: string;
}

/**
 * Authentication data for a plaintext array parameter
 *
 * Used when authenticating a program run that accepts multiple plaintext values as input.
 * The plaintext values and type metadata must match the corresponding SpfParameter payload.
 *
 * @example
 * ```typescript
 * const values = [1, 2, 3];
 * const [param, auth] = createPlaintextArrayParameter(8, values);
 * // auth.paramType === "PlaintextArray"
 * // auth.plaintextValuesIfAny.length === 3
 * // auth.ciphertextIdsIfAny.length === 0
 * // auth.additionalInfoIfAny === "int8_t[3]"
 * ```
 */
export interface PlaintextArrayParameterAuth extends ParameterAuthenticationBase {
  readonly paramType: "PlaintextArray";
  readonly plaintextValuesIfAny: readonly HexString[];
  readonly ciphertextIdsIfAny: readonly [];
  readonly additionalInfoIfAny: string;
}

/**
 * Discriminated union of all parameter authentication types
 *
 * Use this type when accepting any parameter authentication data.
 * TypeScript can narrow the type based on the paramType discriminant.
 */
export type ParameterAuthentication =
  | CiphertextParameterAuth
  | CiphertextArrayParameterAuth
  | OutputCiphertextArrayParameterAuth
  | PlaintextParameterAuth
  | PlaintextArrayParameterAuth;

/**
 * SPF parameter bundled with authentication data for EIP-712 signing
 *
 * This type represents a parameter along with its authentication metadata,
 * used when submitting runs that require cryptographic verification.
 */
export type SpfParameterWithAuth = readonly [SpfParameter, ParameterAuthentication];

/**
 * Run status - pending, running, or in progress
 */
export type RunStatusPending = {
  readonly status: "pending" | "running" | "in_progress";
};

/**
 * Payload returned by successful run operations
 */
export interface RunPayload {
  /** Gas usage for the FHE program execution */
  readonly gas_usage?: bigint;
  /** Execution time in milliseconds */
  readonly execution_time?: number;
  /** Total cycle count for the program execution */
  readonly cycle_count?: bigint;
}

/**
 * Run status - success with payload
 */
export type RunStatusSuccess = {
  readonly status: "success";
  readonly payload?: RunPayload;
};

/**
 * Run status - failed with error
 */
export type RunStatusFailed = {
  readonly status: "failed";
  readonly payload?: { readonly message?: string };
};

/**
 * Discriminated union of all run statuses
 */
export type RunStatus = RunStatusPending | RunStatusSuccess | RunStatusFailed;

/**
 * Decryption status - pending, running, or in progress
 */
export type DecryptionStatusPending = {
  readonly status: "pending" | "running" | "in_progress";
};

/**
 * Decryption status - success with parsed plaintext value
 */
export type DecryptionStatusSuccess = {
  readonly status: "success";
  readonly payload: {
    readonly value: bigint;
  };
};

/**
 * Decryption status - failed with error message
 */
export type DecryptionStatusFailed = {
  readonly status: "failed";
  readonly payload?: {
    readonly message?: string;
  };
};

/**
 * Discriminated union of all decryption statuses
 */
export type DecryptionStatus =
  | DecryptionStatusPending
  | DecryptionStatusSuccess
  | DecryptionStatusFailed;

// Polling Configuration

/**
 * Configuration options for polling operations
 *
 * All fields are optional. Unspecified fields use values from POLL_DEFAULTS.
 * Polling uses exponential backoff: each interval is multiplied by backoffMultiplier
 * until it reaches maxIntervalMs.
 *
 * @example
 * ```typescript
 * // Fast polling for testing
 * const options = {
 *   initialIntervalMs: 10,
 *   backoffMultiplier: 2.0,
 *   maxIntervalMs: 1000
 * };
 * const status = await waitForRun(runHandle, undefined, options);
 * ```
 */
export interface PollingOptions {
  /** Initial interval between status checks in milliseconds */
  initialIntervalMs?: number;
  /** Exponential backoff multiplier (applied to interval after each check) */
  backoffMultiplier?: number;
  /** Maximum interval between checks in milliseconds */
  maxIntervalMs?: number;
}

/**
 * Valid status discriminants for polling operations
 *
 * All polling functions require status objects with a discriminant field
 * that can only be one of these literal values. This constraint enables
 * type-safe exhaustiveness checking at call sites.
 *
 * @internal
 */
type PollingStatus = "success" | "failed" | "pending" | "running" | "in_progress";

/**
 * Constraint for status objects used in polling operations
 *
 * Status types must have a readonly status field constrained to valid
 * polling status discriminants. This ensures compile-time safety by
 * preventing invalid status values from being passed to polling functions.
 *
 * @internal
 */
type PollingStatusConstraint = { readonly status: PollingStatus };

/**
 * Default polling configuration for async operations
 *
 * Used when no custom PollingOptions are provided. Values can be partially
 * overridden by passing a PollingOptions object to polling functions.
 */
export const POLL_DEFAULTS = {
  /** Initial interval between checks (60ms) */
  initialIntervalMs: 60,
  /** Exponential backoff multiplier */
  backoffMultiplier: 1.25,
  /** Maximum interval between checks (30s) */
  maxIntervalMs: 30000,
} as const;

// Internal Validation Functions

/**
 * Validate bit width at runtime
 * @internal
 */
function assertBitWidth(bitWidth: number): asserts bitWidth is BitWidth {
  if (
    bitWidth !== 8 &&
    bitWidth !== 16 &&
    bitWidth !== 32 &&
    bitWidth !== 64
  ) {
    throw new Error(
      `Invalid bit width: ${bitWidth}. Must be 8, 16, 32, or 64`,
    );
  }
}

// Internal Polling Functions

// Type Guards for Status Narrowing

/**
 * Type guard to check if status is success
 * Enables TypeScript to narrow generic status types
 * @internal
 */
function isSuccessStatus<TStatus extends { readonly status: string }>(
  status: TStatus
): status is Extract<TStatus, { status: "success" }> {
  return status.status === "success";
}

/**
 * Type guard to check if status is failed
 * Enables TypeScript to narrow generic status types
 * @internal
 */
function isFailedStatus<TStatus extends { readonly status: string }>(
  status: TStatus
): status is Extract<TStatus, { status: "failed" }> {
  return status.status === "failed";
}

/**
 * Type guard to check if status is terminal (success or failed)
 * Enables TypeScript to narrow generic status types
 * @internal
 */
function isTerminalStatus<TStatus extends { readonly status: string }>(
  status: TStatus
): status is Extract<TStatus, { status: "success" | "failed" }> {
  return status.status === "success" || status.status === "failed";
}

/**
 * Type guard to check if status is pending (any non-terminal status)
 * Enables TypeScript to narrow generic status types
 * @internal
 */
function isPendingStatus<TStatus extends { readonly status: string }>(
  status: TStatus
): status is Extract<TStatus, { status: "pending" | "running" | "in_progress" }> {
  return status.status === "pending" ||
         status.status === "running" ||
         status.status === "in_progress";
}

/**
 * Generic polling function that returns terminal status (success or failed)
 *
 * Polls with exponential backoff until operation completes or is aborted.
 * Returns both success and failed statuses without throwing.
 *
 * Uses custom type guards to enable TypeScript's exhaustiveness checking without type casts.
 * The PollingStatusConstraint ensures only valid status discriminants are accepted.
 *
 * @template TStatus - Discriminated union with status field constrained to PollingStatusConstraint
 * @param checkStatus - Function to check current status
 * @param signal - Optional AbortSignal for cancellation
 * @param operationName - Name for error messages
 * @param options - Optional polling configuration (defaults to POLL_DEFAULTS)
 * @returns Promise resolving to success or failed status
 * @throws Error only on abort
 * @internal
 */
async function pollForStatus<TStatus extends PollingStatusConstraint>(
  checkStatus: () => Promise<TStatus>,
  signal?: AbortSignal,
  operationName: string = "Operation",
  options?: PollingOptions
): Promise<Extract<TStatus, { status: "success" | "failed" }>> {
  const config = { ...POLL_DEFAULTS, ...options };
  let currentInterval: number = config.initialIntervalMs;

  while (true) {
    if (signal?.aborted) {
      throw signal.reason ?? new Error(`${operationName} aborted`);
    }

    const status = await checkStatus();

    // Type guard narrows to terminal statuses
    if (isTerminalStatus(status)) {
      return status;
    }

    // Type guard narrows to pending statuses
    if (isPendingStatus(status)) {
      // Continue polling with exponential backoff
      await new Promise(resolve => setTimeout(resolve, currentInterval));

      currentInterval = Math.min(
        currentInterval * config.backoffMultiplier,
        config.maxIntervalMs
      );
      continue;
    }

    // Exhaustiveness check - all known status values handled above
    // Note: TypeScript's control flow analysis cannot prove exhaustiveness for generic types
    // even with type guards, due to limitations in how generics interact with control flow.
    // The stricter constraint ensures only valid statuses are accepted at the call site.
    throw new Error(`Unhandled ${operationName} status: ${JSON.stringify(status as never)}`);
  }
}

/**
 * Generic polling function that extracts success value and throws on failure
 *
 * Polls with exponential backoff until operation succeeds, fails, or is aborted.
 * Extracts the success value using the provided function. Throws on failure or abort.
 *
 * **Abort timing**: The signal is checked before each polling iteration and before returning
 * the final result. Status check requests are fast (< 100ms typically), so abort is detected
 * within ~50-200ms in practice.
 *
 * Uses custom type guards to enable TypeScript's exhaustiveness checking without type casts.
 * The PollingStatusConstraint ensures only valid status discriminants are accepted.
 *
 * @template TStatus - Discriminated union with status field constrained to PollingStatusConstraint
 * @template TSuccess - Type of extracted success value
 * @param checkStatus - Function to check current status
 * @param extractSuccess - Function to extract value from success status
 * @param signal - Optional AbortSignal for cancellation
 * @param operationName - Name for error messages
 * @param options - Optional polling configuration (defaults to POLL_DEFAULTS)
 * @returns Promise resolving to extracted success value
 * @throws Error on failure or abort
 * @internal
 */
async function pollUntilComplete<
  TStatus extends PollingStatusConstraint,
  TSuccess
>(
  checkStatus: () => Promise<TStatus>,
  extractSuccess: (status: Extract<TStatus, { status: "success" }>) => TSuccess,
  signal?: AbortSignal,
  operationName: string = "Operation",
  options?: PollingOptions
): Promise<TSuccess> {
  const config = { ...POLL_DEFAULTS, ...options };
  let currentInterval: number = config.initialIntervalMs;

  while (true) {
    if (signal?.aborted) {
      throw signal.reason ?? new Error(`${operationName} aborted`);
    }

    const status = await checkStatus();

    // Type guard narrows to success
    if (isSuccessStatus(status)) {
      // Final abort check before returning (prevents race condition)
      if (signal?.aborted) {
        throw signal.reason ?? new Error(`${operationName} aborted`);
      }
      return extractSuccess(status);
    }

    // Type guard narrows to failed
    if (isFailedStatus(status)) {
      const message = (status as { payload?: { message?: string } }).payload?.message;
      throw new Error(
        `${operationName} failed${message ? `: ${message}` : ""}`
      );
    }

    // Type guard narrows to pending
    if (isPendingStatus(status)) {
      // Continue polling with exponential backoff
      await new Promise(resolve => setTimeout(resolve, currentInterval));

      currentInterval = Math.min(
        currentInterval * config.backoffMultiplier,
        config.maxIntervalMs
      );
      continue;
    }

    // Exhaustiveness check - all known status values handled above
    // Note: TypeScript's control flow analysis cannot prove exhaustiveness for generic types
    // even with type guards, due to limitations in how generics interact with control flow.
    // The stricter constraint ensures only valid statuses are accepted at the call site.
    throw new Error(`Unhandled ${operationName} status: ${JSON.stringify(status as never)}`);
  }
}

// Export internal polling utilities for package-internal use
export { pollForStatus, pollUntilComplete };

// Basic Utilities

/**
 * Create a metaData uint256 from an array of bytes
 *
 * Remaining bytes are filled with 0xFF. Used to encode parameter type information.
 *
 * @param bytes - Array of bytes to encode (first bytes of the uint256)
 * @returns Metadata as hex string with 0x prefix
 */
export function createMetaData(bytes: number[]): MetaData {
  const data = new Uint8Array(32);
  data.fill(0xff); // Fill with 0xFF

  // Set the provided bytes
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    if (byte !== undefined) {
      data[i] = byte;
    }
  }

  return bytesToHex(data) as MetaData;
}

/**
 * Encode a program name as bytes32
 *
 * Program names are ASCII strings padded to 32 bytes with zeros.
 *
 * @param programName - Program name (ASCII string, max 32 bytes)
 * @returns Hex-encoded bytes32 string with 0x prefix
 * @throws {Error} If program name is too long or contains non-ASCII characters
 */
export function encodeProgramName(programName: ProgramName): EncodedProgramName {
  const bytes = stringToBytes(programName);
  if (bytes.length > 32) {
    throw new Error("Program name too long (max 32 bytes)");
  }

  const padded = new Uint8Array(32);
  padded.set(bytes);
  return bytesToHex(padded) as EncodedProgramName;
}

/**
 * Derive library identifier from program bytes
 * Library ID is keccak256 hash of the program bytes
 */
export function deriveLibraryId(programBytes: Uint8Array): LibraryId {
  return asLibraryId(keccak256(programBytes));
}

/**
 * Derive ciphertext identifier from ciphertext bytes
 * Ciphertext ID is keccak256 hash of the ciphertext bytes
 */
export function deriveCiphertextId(ciphertextBytes: Uint8Array): CiphertextId {
  return asCiphertextId(keccak256(ciphertextBytes));
}

/**
 * Derive result ciphertext ID from run handle and output index
 */
export function deriveResultCiphertextId(
  runHandle: RunHandle,
  outputIndex: number,
): CiphertextId {
  const runHandleBytes = hexToBytes(runHandle);
  const indexByte = new Uint8Array([outputIndex]);
  const combined = concatBytes(runHandleBytes, indexByte);

  return asCiphertextId(keccak256(combined));
}

// Authentication

/**
 * Encode an external wallet address in the 33-byte SPF format
 *
 * @param address - Ethereum address (with 0x prefix)
 * @returns 33-byte encoded address for SPF protocol
 */
export function encodeExternalAddress(address: Address): Uint8Array {
  const encoded = new Uint8Array(33);

  // Byte 0: entity type (0x01 for external address)
  encoded[0] = 0x01;

  // Bytes 1-12: padding (zeros)
  // (already initialized to zeros)

  // Bytes 13-32: 20-byte address
  const addressBytes = hexToBytes(address);
  encoded.set(addressBytes, 13);

  return encoded;
}

/**
 * Create an 8-byte big-endian timestamp
 */
export function encodeTimestamp(timestampMillis: number): Uint8Array {
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  // Use setBigUint64 for proper 64-bit encoding
  view.setBigUint64(0, BigInt(timestampMillis), false); // false = big-endian
  return new Uint8Array(buffer);
}

/**
 * Create the message to sign for SPF authentication
 *
 * @param address - Ethereum address of the signer
 * @param timestampMillis - Current timestamp in milliseconds
 * @param requestBody - Request body bytes to sign
 * @returns Message bytes to be signed
 */
export async function createMessageToSign(
  address: Address,
  timestampMillis: number,
  requestBody: Uint8Array,
): Promise<Uint8Array> {
  const wasm = await getWasmModule();
  return wasm.create_message_to_sign(address, timestampMillis, requestBody);
}

/**
 * Create the SPF identity header for authentication
 *
 * Identity headers authenticate SPF API requests by proving ownership of an Ethereum address.
 * The header contains the entity (address), timestamp, signature method, and cryptographic signature.
 *
 * @param signer - Ethereum signer for authentication
 * @param requestBody - Request body bytes to sign if raw signature is used
 * @param eipTypes - Request EIP-712 type definition if EIP-712 signature is used
 * @param eipContent - Request EIP-712 content definition if EIP-712 signature is used
 * @returns Promise resolving to identity header for use in spf-identity HTTP header
 */
export async function createIdentityHeader(
  signer: AnySigner,
  requestBody: Uint8Array,
  eipTypes: Record<string, Array<TypedDataField>>,
  eipContent: Record<string, unknown>
): Promise<IdentityHeader> {
  const wasm = await getWasmModule();
  // Normalize address to Address (handles both SpfSigner and ethers.Signer)
  const address = asAddress(await signer.getAddress());
  const timestampMillis = Date.now();

  if ((signer as SpfSigner).signRaw) {
    // Create message to sign using WASM
    const message = await createMessageToSign(address, timestampMillis, requestBody);

    // Sign in raw
    const signature = await (signer as SpfSigner).signRaw(message);

    // Create identity header using WASM
    return wasm.create_identity_header(address, timestampMillis, "raw_ecdsa", signature) as IdentityHeader;
  }

  // Sign with EIP-712
  const signature = await (signer as EthersSigner).signTypedData(
    {
      name: "SPFIdentityHeader",
      version: "1",
    },
    eipTypes,
    {
      entity: address,
      timestampMillis: timestampMillis,
      ...eipContent,
    }
  );

  // Create identity header using WASM
  return wasm.create_identity_header(address, timestampMillis, "eip_712", signature) as IdentityHeader;
}

// SpfParameter Encoding

/**
 * Create a ciphertext parameter (type 0)
 *
 * @param ciphertextId - The ciphertext identifier (32-byte hex string)
 * @returns SpfParameter with type 0x00 metadata
 */
export function createCiphertextParameter(
  ciphertextId: CiphertextId,
): SpfParameterWithAuth {
  const param = {
    metaData: createMetaData([0x00]),
    payload: [asBytes32(ciphertextId)],
  };
  const auth: CiphertextParameterAuth = {
    paramType: "Ciphertext",
    plaintextValuesIfAny: [],
    ciphertextIdsIfAny: [asBytes32(ciphertextId)],
  };
  validateParameterAuth(auth);
  return [param, auth];
}

/**
 * Create a ciphertext array parameter (type 1)
 *
 * @param ciphertextIds - Array of ciphertext identifiers
 * @returns SpfParameter with type 0x01 metadata
 */
export function createCiphertextArrayParameter(
  ciphertextIds: readonly CiphertextId[],
): SpfParameterWithAuth {
  const param = {
    metaData: createMetaData([0x01]),
    payload: ciphertextIds.map(id => asBytes32(id)),
  };
  const auth: CiphertextArrayParameterAuth = {
    paramType: "CiphertextArray",
    plaintextValuesIfAny: [],
    ciphertextIdsIfAny: ciphertextIds.map(id => asBytes32(id)),
  };
  validateParameterAuth(auth);
  return [param, auth];
}

/**
 * Create an output ciphertext array parameter (type 2)
 *
 * @param bitWidth - Bit width (must be 8, 16, 32, or 64)
 * @param size - Array size (1-255)
 * @returns SpfParameter with type 0x02 metadata
 * @throws {Error} If bitWidth or size are invalid
 */
export function createOutputCiphertextArrayParameter(
  bitWidth: BitWidth,
  size: number,
): SpfParameterWithAuth {
  assertBitWidth(bitWidth);

  if (size < 1 || size > 255) {
    throw new Error("size must be between 1 and 255");
  }

  const param = {
    metaData: createMetaData([0x02, bitWidth, size]),
    payload: [],
  };
  const auth: OutputCiphertextArrayParameterAuth = {
    paramType: "OutputCiphertextArray",
    plaintextValuesIfAny: [],
    ciphertextIdsIfAny: [],
    additionalInfoIfAny: `BitWidth = ${bitWidth}, Size = ${size}`,
  };
  validateParameterAuth(auth);
  return [param, auth];
}

/**
 * Create a plaintext parameter (type 3)
 *
 * @param bitWidth - Bit width (must be 8, 16, 32, or 64)
 * @param value - Plaintext value
 * @returns SpfParameter with type 0x03 metadata
 * @throws {Error} If bitWidth is invalid
 */
export function createPlaintextParameter(
  bitWidth: BitWidth,
  value: number | bigint,
): SpfParameterWithAuth {
  assertBitWidth(bitWidth);

  // Value goes in lower 16 bytes of bytes32 (big-endian)
  const valueBytes32 = numberToBeHex(value, 32);

  const param = {
    metaData: createMetaData([0x03, bitWidth]),
    payload: [asBytes32(valueBytes32)],
  };
  const auth: PlaintextParameterAuth = {
    paramType: "Plaintext",
    plaintextValuesIfAny: [numberToBeHex(value, bitWidth / 8)],
    ciphertextIdsIfAny: [],
    additionalInfoIfAny: `BitWidth = ${bitWidth}`,
  };
  validateParameterAuth(auth);
  return [param, auth];
}

/**
 * Create a plaintext array parameter (type 4)
 *
 * @param bitWidth - Bit width (must be 8, 16, 32, or 64)
 * @param values - Array of plaintext values
 * @returns SpfParameter with type 0x04 metadata
 * @throws {Error} If bitWidth is invalid
 */
export function createPlaintextArrayParameter(
  bitWidth: BitWidth,
  values: readonly (number | bigint)[],
): SpfParameterWithAuth {
  assertBitWidth(bitWidth);

  const payload = values.map((value) => asBytes32(numberToBeHex(value, 32)));

  const param = {
    metaData: createMetaData([0x04, bitWidth]),
    payload,
  };
  const auth: PlaintextArrayParameterAuth = {
    paramType: "PlaintextArray",
    plaintextValuesIfAny: values.map(v => numberToBeHex(v, bitWidth / 8)),
    ciphertextIdsIfAny: [],
    additionalInfoIfAny: `BitWidth = ${bitWidth}`,
  };
  validateParameterAuth(auth);
  return [param, auth];
}

/**
 * Encode an SpfRun for submission to the SPF service
 *
 * @param libraryId - The library identifier (32-byte hex string)
 * @param programName - The program entry point name (ASCII, max 32 bytes)
 * @param parameters - Array of SpfParameter structures
 * @returns ABI-encoded SpfRun as hex string
 */
export function encodeSpfRun(
  libraryId: LibraryId,
  programName: ProgramName,
  parameters: readonly SpfParameter[],
): string {
  const spfRun = {
    spfLibrary: libraryId,
    program: encodeProgramName(programName),
    parameters: parameters.map((p) => ({
      metaData: p.metaData,
      payload: [...p.payload],
    })),
  };

  return encodeSpfRunAbi(spfRun);
}

// Program Operations

/**
 * Upload a compiled FHE program to SPF
 *
 * The program must be compiled with the Sunscreen LLVM compiler targeting
 * the parasol platform. The service computes and returns a library identifier
 * which is the keccak256 hash of the program bytes.
 *
 * @param programBytes - Binary program data (ELF format, .spf file)
 * @returns Promise resolving to the library identifier (hex string with 0x prefix)
 * @throws {Error} If the upload fails, response is invalid, or client not initialized
 *
 * @example
 * ```typescript
 * await initialize();
 * const programBytes = await fs.readFile("voting.spf");
 * const libraryId = await uploadProgram(new Uint8Array(programBytes));
 * console.log("Library ID:", libraryId);
 * ```
 */
export async function uploadProgram(
  programBytes: Uint8Array,
): Promise<LibraryId> {
  const endpoint = getEndpoint();
  const response = await fetch(`${endpoint}/programs`, {
    method: "POST",
    body: programBytes,
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Upload failed (${response.status}): ${error}`);
  }

  const libraryId = parseStringResponse(await response.json());
  return asLibraryId(libraryId);
}

/**
 * Download a program library from SPF
 *
 * @param libraryId - The library identifier
 * @returns Promise resolving to the program bytes
 * @throws {Error} If download fails or client not initialized
 */
export async function downloadProgram(
  libraryId: LibraryId,
): Promise<Uint8Array> {
  const endpoint = getEndpoint();
  const response = await fetch(`${endpoint}/programs/${libraryId}`);

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Download failed (${response.status}): ${error}`);
  }

  return new Uint8Array(await response.arrayBuffer());
}

// Run Operations

/**
 * Submit a run request to execute an FHE program
 *
 * @param signer - Ethereum signer for authentication
 * @param libraryId - The library identifier of the uploaded program
 * @param programName - The program entry point name
 * @param parameters_with_auth - Array of SpfParameter structures and their authentication data
 * @returns Promise resolving to the run handle (32-byte hex string with 0x prefix)
 * @throws {Error} If the request fails, response is invalid, or client not initialized
 *
 * @example
 * ```typescript
 * await initialize();
 * const parameters = [
 *   createCiphertextArrayParameter([vote1, vote2, vote3]),
 *   createPlaintextParameter(16, 3),
 *   createOutputCiphertextArrayParameter(16, 1),
 * ];
 * const runHandle = await submitRun(signer, libraryId, "binary_voting", parameters);
 * ```
 */
export async function submitRun(
  signer: AnySigner,
  libraryId: LibraryId,
  programName: ProgramName,
  parameters_with_auth: readonly SpfParameterWithAuth[],
): Promise<RunHandle> {
  const endpoint = getEndpoint();
  // Encode the SpfRun
  const encodedRun = encodeSpfRun(libraryId, programName, parameters_with_auth.map(([v]) => v));
  const runBytes = hexToBytes(encodedRun);

  // Create authentication header
  const identityHeader = await createIdentityHeader(
    signer,
    runBytes,
    {
      ProgramRunAuthentication: [
        { name: "entity", type: "address" },
        { name: "timestampMillis", type: "uint64" },
        { name: "libraryId", type: "bytes32" },
        { name: "programName", type: "string" },
        { name: "parameters", type: "ParameterEntry[]" },
      ],
      ParameterEntry: [
        { name: "paramType", type: "string" },
        { name: "plaintextValuesIfAny", type: "bytes[]" },
        { name: "ciphertextIdsIfAny", type: "bytes32[]" },
        { name: "additionalInfoIfAny", type: "string" },
      ],
    },
    {
      libraryId: libraryId,
      programName: programName,
      parameters: parameters_with_auth.map(([_, v]) => v),
    }  
  );

  // Submit request
  const response = await fetch(`${endpoint}/runs`, {
    method: "POST",
    headers: {
      "spf-identity": identityHeader,
    },
    body: runBytes,
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Run request failed (${response.status}): ${error}`);
  }

  const runHandle = parseStringResponse(await response.json());
  return asRunHandle(runHandle);
}

/**
 * Check the status of a program run
 *
 * Returns a discriminated union based on the run status. Use type narrowing
 * to access status-specific fields.
 *
 * @param runHandle - The run handle returned from submitRun
 * @returns Promise resolving to RunStatus discriminated union
 * @throws {Error} If the status check fails, response is invalid, or client not initialized
 *
 * @example
 * ```typescript
 * const status = await checkRunStatus(runHandle);
 * if (status.status === "success") {
 *   console.log("Gas usage:", status.payload?.gas_usage);
 * } else if (status.status === "failed") {
 *   console.error("Run failed:", status.payload?.message);
 * }
 * ```
 */
export async function checkRunStatus(
  runHandle: RunHandle,
): Promise<RunStatus> {
  const endpoint = getEndpoint();
  // Remove 0x prefix if present
  const handle = runHandle.startsWith("0x") ? runHandle.slice(2) : runHandle;

  const response = await fetch(`${endpoint}/runs/${handle}`);

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Status check failed (${response.status}): ${error}`);
  }

  return parseRunStatusResponse(await response.json());
}

/**
 * Wait for a run to complete by polling
 *
 * Polls with exponential backoff (60ms → 30s max by default) until the run completes
 * (success or failure). Use AbortController for timeout and cancellation control.
 *
 * **Abort timing**: The signal is checked before each polling iteration. Status check
 * requests are fast (< 100ms typically), so abort is detected within ~50-200ms in practice.
 *
 * @param runHandle - The run handle to wait for
 * @param signal - Optional AbortSignal to cancel the polling operation
 * @param options - Optional polling configuration (defaults to POLL_DEFAULTS)
 * @returns Promise resolving to final RunStatus (success or failed)
 * @throws {Error} If operation is aborted or client not initialized
 *
 * @example
 * ```typescript
 * // Poll until complete
 * const status = await waitForRun(runHandle);
 *
 * // With 60s timeout using AbortController
 * const controller = new AbortController();
 * const timeoutId = setTimeout(() => controller.abort(), 60000);
 * try {
 *   const status = await waitForRun(runHandle, controller.signal);
 * } finally {
 *   clearTimeout(timeoutId);
 * }
 *
 * // With custom polling (faster for testing)
 * const status = await waitForRun(runHandle, undefined, {
 *   initialIntervalMs: 10,
 *   maxIntervalMs: 1000
 * });
 * ```
 */
export async function waitForRun(
  runHandle: RunHandle,
  signal?: AbortSignal,
  options?: PollingOptions
): Promise<RunStatusSuccess | RunStatusFailed> {
  return pollForStatus(
    () => checkRunStatus(runHandle),
    signal,
    "Run",
    options
  );
}

// Ciphertext Operations

/**
 * Upload a ciphertext to SPF
 *
 * @param signer - Ethereum signer for authentication
 * @param ciphertextBytes - Binary ciphertext data
 * @returns Promise resolving to ciphertext identifier (keccak256 hash, hex with 0x prefix)
 * @throws {Error} If upload fails, response is invalid, or client not initialized
 */
export async function uploadCiphertext(
  signer: AnySigner,
  ciphertextBytes: Uint8Array,
): Promise<CiphertextId> {
  const endpoint = getEndpoint();
  // Create authentication header
  const identityHeader = await createIdentityHeader(
    signer,
    ciphertextBytes,
    {
      CiphertextUploadAuthentication: [
        { name: "entity", type: "address" },
        { name: "timestampMillis", type: "uint64" },
        { name: "ciphertextHash", type: "bytes32" },
      ],
    },
    {
      ciphertextHash: keccak_256(ciphertextBytes),
    }
  );

  // Submit request
  const response = await fetch(`${endpoint}/ciphertexts`, {
    method: "POST",
    headers: {
      "spf-identity": identityHeader,
    },
    body: ciphertextBytes,
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Ciphertext upload failed (${response.status}): ${error}`);
  }

  const ciphertextId = parseStringResponse(await response.json());
  return asCiphertextId(ciphertextId);
}

/**
 * Download a ciphertext from SPF (requires decrypt access)
 *
 * @param signer - Ethereum signer for authentication
 * @param ciphertextId - The ciphertext identifier
 * @returns Promise resolving to ciphertext bytes
 * @throws {Error} If download fails or client not initialized
 */
export async function downloadCiphertext(
  signer: AnySigner,
  ciphertextId: CiphertextId,
): Promise<Uint8Array> {
  const endpoint = getEndpoint();
  // Remove 0x prefix if present
  const id = ciphertextId.startsWith("0x") ? ciphertextId.slice(2) : ciphertextId;

  // Create authentication header with empty body
  const identityHeader = await createIdentityHeader(
    signer,
    new Uint8Array(0),
    {
      CiphertextDownloadAuthentication: [
        { name: "entity", type: "address" },
        { name: "timestampMillis", type: "uint64" },
      ],
    },
    {}
  );

  const response = await fetch(`${endpoint}/ciphertexts/${id}`, {
    method: "GET",
    headers: {
      "spf-identity": identityHeader,
    },
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Ciphertext download failed (${response.status}): ${error}`);
  }

  return new Uint8Array(await response.arrayBuffer());
}

// Decryption Operations

/**
 * Request threshold decryption of a ciphertext
 *
 * @param signer - Ethereum signer for authentication
 * @param ciphertextId - The ciphertext identifier
 * @returns Promise resolving to the decryption handle
 * @throws {Error} If request fails or client not initialized
 */
export async function requestDecryption(
  signer: AnySigner,
  ciphertextId: CiphertextId,
): Promise<DecryptHandle> {
  const endpoint = getEndpoint();
  // Remove 0x prefix if present
  const cleanId = ciphertextId.startsWith("0x")
    ? ciphertextId.slice(2)
    : ciphertextId;

  // Convert to UTF-8 bytes
  const requestBody = new TextEncoder().encode(cleanId);

  // Create authentication header
  const identityHeader = await createIdentityHeader(
    signer,
    requestBody,
    {
      DecryptionAuthentication: [
        { name: "entity", type: "address" },
        { name: "timestampMillis", type: "uint64" },
        { name: "ciphertextId", type: "bytes32" },
      ],
    },
    {
      "ciphertextId": hexToBytes(ciphertextId)
    }
  );

  // Submit request
  const response = await fetch(`${endpoint}/decryption`, {
    method: "POST",
    headers: {
      "spf-identity": identityHeader,
    },
    body: requestBody,
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Decryption request failed (${response.status}): ${error}`);
  }

  const decryptHandle = parseStringResponse(await response.json());
  return asDecryptHandle(decryptHandle);
}

/**
 * Check the status of a decryption request
 *
 * Returns a discriminated union based on the decryption status. When successful,
 * the polynomial result is automatically parsed to a plaintext bigint value.
 *
 * @param decryptHandle - The decrypt handle returned from requestDecryption
 * @param bitWidth - Bit width of the encrypted value (8, 16, 32, or 64)
 * @param signed - Whether the value is signed
 * @returns Promise resolving to DecryptionStatus discriminated union
 * @throws {Error} If status check fails, response is invalid, or client not initialized
 *
 * @example
 * ```typescript
 * const status = await checkDecryptionStatus(decryptHandle, 16, false);
 * if (status.status === "success") {
 *   console.log("Plaintext value:", status.payload.value);
 * } else if (status.status === "failed") {
 *   console.error("Decryption failed:", status.payload?.message);
 * }
 * ```
 */
export async function checkDecryptionStatus(
  decryptHandle: DecryptHandle,
  bitWidth: BitWidth,
  signed: boolean,
): Promise<DecryptionStatus> {
  const endpoint = getEndpoint();
  const response = await fetch(`${endpoint}/decryption/${decryptHandle}`);

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Status check failed (${response.status}): ${error}`);
  }

  return parseDecryptionStatusResponse(await response.json(), bitWidth, signed);
}

/**
 * Check decryption status and return raw polynomial bytes (for OTP workflow)
 * @internal
 */
async function checkDecryptionStatusRaw(
  decryptHandle: DecryptHandle,
): Promise<DecryptionStatusRaw> {
  const endpoint = getEndpoint();
  const response = await fetch(`${endpoint}/decryption/${decryptHandle}`);

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Status check failed (${response.status}): ${error}`);
  }

  return parseDecryptionStatusResponseRaw(await response.json());
}

/**
 * Get raw polynomial bytes from a completed threshold decryption for OTP decryption.
 *
 * This function is used in the OTP re-encryption workflow after requesting
 * threshold decryption of a reencrypted ciphertext. The returned polynomial bytes
 * are OTP-encrypted and must be decrypted locally using otpDecrypt().
 *
 * Polls with exponential backoff (60ms → 30s max by default) until decryption completes.
 * Use AbortController for timeout and cancellation control.
 *
 * **Abort timing**: The signal is checked before each polling iteration. Status check
 * requests are fast (< 100ms typically), so abort is detected within ~50-200ms in practice.
 *
 * @param decryptHandle - The decrypt handle from requestDecryption
 * @param signal - Optional AbortSignal to cancel the polling operation
 * @param options - Optional polling configuration (defaults to POLL_DEFAULTS)
 * @returns Promise resolving to raw polynomial bytes (OTP-encrypted)
 * @throws {Error} If decryption fails or operation is aborted
 *
 * @example
 * ```typescript
 * // Complete OTP re-encryption workflow
 * const { publicOtp, secretOtp } = await generateOtp();
 * const reencryptHandle = await requestReencryption(signer, ciphertextId, publicOtp);
 * const reencryptedCtId = await waitForReencryption(reencryptHandle);
 *
 * // Request threshold decryption of reencrypted ciphertext
 * const decryptHandle = await requestDecryption(signer, reencryptedCtId);
 *
 * // Poll until complete
 * const otpEncryptedPoly = await getPolynomialBytesForOtp(decryptHandle);
 *
 * // With 10s timeout using AbortController
 * const controller = new AbortController();
 * const timeoutId = setTimeout(() => controller.abort(), 10000);
 * try {
 *   const otpEncryptedPoly = await getPolynomialBytesForOtp(decryptHandle, controller.signal);
 * } finally {
 *   clearTimeout(timeoutId);
 * }
 *
 * // With custom polling (faster for testing)
 * const otpEncryptedPoly = await getPolynomialBytesForOtp(decryptHandle, undefined, {
 *   initialIntervalMs: 10,
 *   maxIntervalMs: 1000
 * });
 *
 * // Decrypt locally with secret OTP
 * const plaintext = await otpDecrypt(otpEncryptedPoly, secretOtp, 16, false);
 * console.log("Decrypted value:", plaintext);
 * ```
 */
export async function getPolynomialBytesForOtp(
  decryptHandle: DecryptHandle,
  signal?: AbortSignal,
  options?: PollingOptions
): Promise<Uint8Array> {
  return pollUntilComplete(
    () => checkDecryptionStatusRaw(decryptHandle),
    (status) => status.payload.polyBytes,
    signal,
    "Decryption",
    options
  );
}

/**
 * Wait for a decryption to complete by polling
 *
 * Polls with exponential backoff (60ms → 30s max by default) until the decryption completes
 * (success or failure). Use AbortController for timeout and cancellation control.
 * Automatically deserializes and parses the polynomial result into the final value.
 *
 * **Abort timing**: The signal is checked before each polling iteration. Status check
 * requests are fast (< 100ms typically), so abort is detected within ~50-200ms in practice.
 *
 * @param decryptHandle - The decrypt handle to wait for
 * @param bitWidth - Bit width of the encrypted value (8, 16, 32, or 64)
 * @param signed - Whether the value is signed
 * @param signal - Optional AbortSignal to cancel the polling operation
 * @param options - Optional polling configuration (defaults to POLL_DEFAULTS)
 * @returns Promise resolving to the decrypted plaintext value as bigint
 * @throws {Error} If decryption fails, operation is aborted, or client not initialized
 *
 * @example
 * ```typescript
 * // Poll until complete
 * const value = await waitForDecryption(decryptHandle, 16, false);
 *
 * // With 10s timeout using AbortController
 * const controller = new AbortController();
 * const timeoutId = setTimeout(() => controller.abort(), 10000);
 * try {
 *   const value = await waitForDecryption(decryptHandle, 16, true, controller.signal);
 * } finally {
 *   clearTimeout(timeoutId);
 * }
 *
 * // With custom polling (faster for testing)
 * const value = await waitForDecryption(decryptHandle, 16, false, undefined, {
 *   initialIntervalMs: 10,
 *   maxIntervalMs: 1000
 * });
 * ```
 */
export async function waitForDecryption(
  decryptHandle: DecryptHandle,
  bitWidth: BitWidth,
  signed: boolean,
  signal?: AbortSignal,
  options?: PollingOptions
): Promise<bigint> {
  return pollUntilComplete(
    () => checkDecryptionStatus(decryptHandle, bitWidth, signed),
    (status) => status.payload.value,
    signal,
    "Decryption",
    options
  );
}

// Encryption & OTP Functions

// Re-export encryption functions
export {
  encryptValue,
  encryptValues,
  generateOtp,
  otpDecrypt,
  toNumber,
  toNumberIfSafe,
  type OtpKeypair,
} from "./encryption.js";

// Re-export public key management
export { getPublicKey, clearPublicKeyCache } from "./public-key.js";

// Re-export reencryption functions
export {
  requestReencryption,
  checkReencryptionStatus,
  waitForReencryption,
  type ReencryptionStatus,
  type ReencryptionStatusPending,
  type ReencryptionStatusSuccess,
  type ReencryptionStatusFailed,
} from "./reencryption.js";

// Re-export WASM utilities
export { getWasmModule, preloadWasm, clearWasmCache, initialize, isInitialized } from "@sunscreen/spf-client/spf-wasm-loader";

// Re-export ACL check functions
export {
  checkCiphertextAccess,
  getCiphertextAccessSignature,
  type AccessType,
  type AclSignatureResponse,
} from "./acl-check.js";

// Re-export crypto utilities for advanced usage
export {
  PrivateKeySigner,
  type SpfSigner,
} from "./crypto/index.js";
