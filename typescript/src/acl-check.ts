import {
  getWasmModule,
  getEndpoint,
} from "@sunscreen/spf-client/spf-wasm-loader";
import {
  type CiphertextId,
  type Signature,
  type LibraryId,
  type ProgramName,
  asSignature,
} from "./spf-client.js";

/**
 * Access control type for ACL checks
 *
 * Specifies the type of access to check for a ciphertext.
 *
 * @param address - Address to check access for (required)
 */
export type AccessType =
  | { type: "admin"; chainId?: number; address: string }
  | { type: "decrypt"; chainId?: number; address: string }
  | {
      type: "run";
      chainId?: number;
      address: string;
      libraryHash: LibraryId;
      entryPoint: ProgramName;
    };

/**
 * Entity that can have access permissions.
 * Matches Rust's Entity enum from spf_contracts.
 *
 * - ExternalAddress: Off-chain external address (Web2 mode, no chain ID)
 * - EthereumContractAddress: On-chain Ethereum contract address (Web3 mode)
 *
 * @example
 * ```typescript
 * // External address (off-chain)
 * const external: Entity = {
 *   ExternalAddress: { addr: "0x1234..." }
 * };
 *
 * // Contract address (on-chain)
 * const contract: Entity = {
 *   EthereumContractAddress: {
 *     chain_id: 1,
 *     addr: "0x5678..."
 *   }
 * };
 * ```
 */
export type Entity =
  | { readonly ExternalAddress: { readonly addr: string } }
  | {
      readonly EthereumContractAddress: {
        /** Chain ID where the contract is deployed */
        readonly chain_id: number;
        /** Contract address as hex string */
        readonly addr: string;
      };
    };

/**
 * Type guard to check if an Entity is an ExternalAddress
 */
export function isExternalAddress(
  entity: Entity,
): entity is { readonly ExternalAddress: { readonly addr: string } } {
  return "ExternalAddress" in entity;
}

/**
 * Type guard to check if an Entity is an EthereumContractAddress
 */
export function isEthereumContractAddress(entity: Entity): entity is {
  readonly EthereumContractAddress: {
    readonly chain_id: number;
    readonly addr: string;
  };
} {
  return "EthereumContractAddress" in entity;
}

/**
 * Access change type representing different permission grants.
 * Matches Rust's AccessChange enum from spf_contracts.
 *
 * - NewAdmin: Grant administrative access to an entity
 * - NewDecrypt: Grant decryption access to an entity
 * - NewRun: Grant execution access for a specific program
 *           Tuple format: [Entity, LibraryHash, EntryPoint]
 *
 * @example
 * ```typescript
 * // Admin access
 * const admin: AccessChange = {
 *   NewAdmin: { ExternalAddress: { addr: "0x1234..." } }
 * };
 *
 * // Decrypt access
 * const decrypt: AccessChange = {
 *   NewDecrypt: { ExternalAddress: { addr: "0x5678..." } }
 * };
 *
 * // Run access with type guards
 * if (isNewRun(change)) {
 *   const [entity, libId, entryPoint] = change.NewRun;
 *   console.log(`Run access for program: ${entryPoint}`);
 * }
 * ```
 */
export type AccessChange =
  | { readonly NewAdmin: Entity }
  | { readonly NewDecrypt: Entity }
  | { readonly NewRun: readonly [Entity, LibraryId, ProgramName] };

/**
 * Type guard to check if an AccessChange grants admin access
 */
export function isNewAdmin(
  change: AccessChange,
): change is { readonly NewAdmin: Entity } {
  return "NewAdmin" in change;
}

/**
 * Type guard to check if an AccessChange grants decrypt access
 */
export function isNewDecrypt(
  change: AccessChange,
): change is { readonly NewDecrypt: Entity } {
  return "NewDecrypt" in change;
}

/**
 * Type guard to check if an AccessChange grants run access
 */
export function isNewRun(
  change: AccessChange,
): change is { readonly NewRun: readonly [Entity, LibraryId, ProgramName] } {
  return "NewRun" in change;
}

/**
 * Message that was signed for ACL verification
 */
export interface SpfCiphertextAccessConfirmation {
  /** Ciphertext ID (32 bytes as hex string with 0x prefix) */
  readonly ciphertextId: string;
  /** Bit width of the ciphertext (8, 16, 32, etc.) */
  readonly bitWidth: number;
  /** Access bytes that were verified */
  readonly access: string;
}

/**
 * Success response from ACL check
 */
export interface CheckAclSuccessResponse {
  readonly status: "success";
  readonly payload: {
    /** The signature proving access (130 hex chars with 0x prefix) */
    readonly signature: string;
    /** The message that was signed */
    readonly msg: SpfCiphertextAccessConfirmation;
    /**
     * The parsed access change that was verified.
     * Note: Uses snake_case to match server JSON response.
     */
    readonly access_change: AccessChange;
  };
}

/**
 * Failure response from ACL check
 */
export interface CheckAclFailureResponse {
  readonly status: "failure";
  readonly payload: string;
}

/**
 * Response from ACL check endpoint
 */
export type CheckAclResponse =
  | CheckAclSuccessResponse
  | CheckAclFailureResponse;

/**
 * ACL signature response with metadata
 *
 * @example
 * ```typescript
 * const { signature, message, accessChange } = await getCiphertextAccessSignature(
 *   signer,
 *   ctId,
 *   { type: "decrypt" }
 * );
 *
 * // Verify signature with message
 * console.log("Signature:", signature);
 * console.log("Ciphertext:", message.ciphertextId);
 * console.log("Bit width:", message.bitWidth);
 * console.log("Access bytes:", message.access);
 *
 * // Pattern match on access change
 * if (isNewDecrypt(accessChange)) {
 *   const entity = accessChange.NewDecrypt;
 *   if (isExternalAddress(entity)) {
 *     console.log("External address:", entity.ExternalAddress.addr);
 *   }
 * }
 * ```
 */
export interface AclSignatureResponse {
  /** The signature proving access (65 bytes as 0x-prefixed hex string) */
  readonly signature: Signature;
  /**
   * The message that was signed for EIP-191 verification.
   * Contains the access bytes in hexadecimal format (message.access).
   */
  readonly message: SpfCiphertextAccessConfirmation;
  /** The parsed and verified access change */
  readonly accessChange: AccessChange;
}

/**
 * Runtime validation for CheckAclResponse
 * Validates the structure of the API response before type assertion
 */
function isValidAclResponse(obj: unknown): obj is CheckAclResponse {
  if (typeof obj !== "object" || obj === null) {
    return false;
  }

  const response = obj as Record<string, unknown>;

  if (response["status"] === "success") {
    if (
      typeof response["payload"] !== "object" ||
      response["payload"] === null
    ) {
      return false;
    }
    const payload = response["payload"] as Record<string, unknown>;
    return (
      typeof payload["signature"] === "string" &&
      typeof payload["msg"] === "object" &&
      payload["msg"] !== null &&
      typeof payload["access_change"] === "object" &&
      payload["access_change"] !== null
    );
  }

  if (response["status"] === "failure") {
    return typeof response["payload"] === "string";
  }

  return false;
}

/**
 * Type guard to check if ACL response is successful
 */
function isAclSuccess(
  response: CheckAclResponse,
): response is CheckAclSuccessResponse {
  return response.status === "success";
}

/**
 * Type guard to check if ACL response is failure
 */
function isAclFailure(
  response: CheckAclResponse,
): response is CheckAclFailureResponse {
  return response.status === "failure";
}

/**
 * Exhaustiveness check helper
 */
function assertNever(value: never): never {
  throw new Error(`Unexpected value: ${JSON.stringify(value)}`);
}

/**
 * Encode access type to binary format
 */
async function encodeAccessType(
  accessType: AccessType,
): Promise<Uint8Array> {
  const wasm = await getWasmModule();

  switch (accessType.type) {
    case "admin":
      return wasm.encode_access_admin(accessType.address, accessType.chainId);

    case "decrypt":
      return wasm.encode_access_decrypt(accessType.address, accessType.chainId);

    case "run":
      return wasm.encode_access_run(
        accessType.address,
        accessType.chainId,
        accessType.libraryHash,
        accessType.entryPoint,
      );

    default:
      return assertNever(accessType);
  }
}

/**
 * Internal helper to make ACL check request and parse response
 */
async function makeAclCheckRequest(
  ciphertextId: CiphertextId,
  accessType: AccessType,
): Promise<CheckAclResponse> {
  const endpoint = getEndpoint();

  const accessBytes = await encodeAccessType(accessType);

  const url = `${endpoint}/acl_check/${ciphertextId}`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
    },
    body: accessBytes,
  });

  // Server returns 200 for success and 417 for failure, both with JSON body
  if (response.status !== 200 && response.status !== 417) {
    const error = await response.text();
    throw new Error(`ACL check failed (${response.status}): ${error}`);
  }

  const json = await response.json();

  // Runtime validation before type assertion
  if (!isValidAclResponse(json)) {
    throw new Error(`Invalid ACL response format: ${JSON.stringify(json)}`);
  }

  return json;
}

/**
 * Check if a wallet has access to a ciphertext.
 *
 * Makes a request to the SPF network to verify access permissions.
 * Returns true if access is granted, false otherwise.
 *
 * No authentication is required for this endpoint.
 *
 * @param ciphertextId - The ciphertext ID to check access for
 * @param accessType - The type of access to check (must include address field)
 * @returns Promise resolving to true if access granted, false if denied
 * @throws {Error} If client not initialized or request fails
 *
 * @example
 * ```typescript
 * await initialize();
 * const hasAccess = await checkCiphertextAccess(
 *   "0x1234...",
 *   { type: "decrypt", chainId: 1, address: "0xabc..." }
 * );
 *
 * if (hasAccess) {
 *   console.log("Access granted");
 * } else {
 *   console.log("Access denied");
 * }
 * ```
 */
export async function checkCiphertextAccess(
  ciphertextId: CiphertextId,
  accessType: AccessType,
): Promise<boolean> {
  const aclResponse = await makeAclCheckRequest(
    ciphertextId,
    accessType,
  );

  if (isAclFailure(aclResponse)) {
    return false;
  }

  if (isAclSuccess(aclResponse)) {
    return true;
  }

  return assertNever(aclResponse);
}

/**
 * Get an access signature and metadata for a ciphertext.
 *
 * Makes a request to the SPF network to verify access and retrieve
 * a signature proving access along with the message that was signed.
 *
 * No authentication is required for this endpoint.
 *
 * @param ciphertextId - The ciphertext ID to check access for
 * @param accessType - The type of access to check (must include address field)
 * @returns Promise resolving to signature and metadata
 * @throws {Error} If access is denied, request fails, or client not initialized
 *
 * @example
 * ```typescript
 * await initialize();
 * try {
 *   const { signature, ciphertextId, message, accessBytes } =
 *     await getCiphertextAccessSignature(
 *       "0x1234...",
 *       { type: "admin", chainId: 1, address: "0xabc..." }
 *     );
 *
 *   console.log("Access granted!");
 *   console.log("Signature:", signature);
 *   console.log("Bit width:", message.bitWidth);
 * } catch (error) {
 *   console.error("Access denied:", error);
 * }
 * ```
 */
export async function getCiphertextAccessSignature(
  ciphertextId: CiphertextId,
  accessType: AccessType,
): Promise<AclSignatureResponse> {
  const aclResponse = await makeAclCheckRequest(
    ciphertextId,
    accessType,
  );

  if (isAclFailure(aclResponse)) {
    throw new Error(`Access denied: ${aclResponse.payload}`);
  }

  if (isAclSuccess(aclResponse)) {
    const { signature, msg, access_change } = aclResponse.payload;

    return {
      signature: asSignature(signature),
      message: msg,
      accessChange: access_change,
    };
  }

  return assertNever(aclResponse);
}
