/**
 * Access Control List (ACL) API for SPF ciphertext permissions
 *
 * This module provides both simple and advanced APIs for managing ciphertext access control.
 *
 * ## Simple API (Recommended for Single Operations)
 *
 * For granting one permission at a time:
 *
 * ```typescript
 * import { allowAdmin, allowDecrypt, allowRun, asAddress } from '@sunscreen/spf-client';
 *
 * // Grant decrypt access to a wallet
 * await allowDecrypt(wallet, ciphertextId, asAddress(walletAddress));
 *
 * // Grant admin to another address
 * await allowAdmin(wallet, ciphertextId, asAddress(adminAddress));
 *
 * // Grant run access for a specific program
 * await allowRun(wallet, ciphertextId, asAddress(otherAddress), libraryId, asProgramName("program"));
 * ```
 *
 * ## Advanced API (For Batch Operations)
 *
 * For granting multiple permissions in a single transaction:
 *
 * ```typescript
 * import {
 *   updateAccess,
 *   addAdminAccess,
 *   allowDecryptAccess,
 *   allowRunAccess,
 *   asProgramName
 * } from '@sunscreen/spf-client';
 *
 * // Using PrivateKeySigner (getAddress() returns Address)
 * await updateAccess(signer, ciphertextId, [
 *   addAdminAccess(address1),
 *   allowDecryptAccess(address2),
 *   allowDecryptAccess(address3),
 *   allowRunAccess(address4, libraryId, asProgramName("program"))
 * ]);
 * ```
 *
 * @module acl
 */

import type {
  AnySigner,
  CiphertextId,
  LibraryId,
  ProgramName,
  Address,
  MetaData,
  Bytes32,
  SpfParameter,
} from "./spf-client.js";
import {
  createMetaData,
  createIdentityHeader,
  asCiphertextId,
  encodeProgramName,
  asBytes32,
} from "./spf-client.js";
import {
  hexToBytes,
  bytesToHex,
  encodeSpfAccessAbi,
} from "./crypto/index.js";
import { parseStringResponse } from "./parsers.js";
import { getEndpoint } from "./wasm-loader.js";
import { validateAccessChangeAuth } from "./validation.js";
import { getAuthSecret } from "./internal/endpoint-state.js";

/**
 * Base interface for ACL authentication data
 *
 * This structure is used in EIP-712 typed data for authenticating access control changes.
 * Each access type has specific requirements for which fields are populated.
 *
 * @internal
 */
interface AccessChangeAuthenticationBase {
  readonly accessType: string;
  readonly accessAssignee: Address;
  readonly chainIdIfAssigneeIsContractOrZero: number;
  readonly additionalInfoIfAny?: string;
}

/**
 * Authentication data for admin access grant
 *
 * Used when authenticating an access control change that grants admin permissions.
 * Admin access allows the assignee to modify access control for the ciphertext.
 *
 * @example
 * ```typescript
 * const [change, auth] = addAdminAccess(adminAddress);
 * // auth.accessType === "Admin"
 * // auth.accessAssignee === adminAddress
 * // auth.chainIdIfAssigneeIsContractOrZero === 0 (external)
 * // auth.additionalInfoIfAny === ""
 * ```
 */
export interface AdminAccessAuth extends AccessChangeAuthenticationBase {
  readonly accessType: "Admin";
  readonly additionalInfoIfAny?: never;
}

/**
 * Authentication data for run access grant
 *
 * Used when authenticating an access control change that grants run permissions.
 * Run access allows the assignee to execute a specific FHE program using this ciphertext.
 * The additionalInfoIfAny field contains program identification metadata.
 *
 * @example
 * ```typescript
 * const [change, auth] = allowRunAccess(executorAddress, libraryId, asProgramName("tally_votes"));
 * // auth.accessType === "Run"
 * // auth.accessAssignee === executorAddress
 * // auth.chainIdIfAssigneeIsContractOrZero === 0 (external)
 * // auth.additionalInfoIfAny === "Applies to program 'tally_votes' in library '0x...'"
 * ```
 */
export interface RunAccessAuth extends AccessChangeAuthenticationBase {
  readonly accessType: "Run";
  readonly additionalInfoIfAny: string;
}

/**
 * Authentication data for decrypt access grant
 *
 * Used when authenticating an access control change that grants decrypt permissions.
 * Decrypt access allows the assignee to request threshold decryption of this ciphertext.
 *
 * @example
 * ```typescript
 * const [change, auth] = allowDecryptAccess(decryptAddress);
 * // auth.accessType === "Decrypt"
 * // auth.accessAssignee === decryptAddress
 * // auth.chainIdIfAssigneeIsContractOrZero === 0 (external)
 * // auth.additionalInfoIfAny === ""
 * ```
 */
export interface DecryptAccessAuth extends AccessChangeAuthenticationBase {
  readonly accessType: "Decrypt";
  readonly additionalInfoIfAny?: never;
}

/**
 * Discriminated union of all access change authentication types
 *
 * Use this type when accepting any access change authentication data.
 * TypeScript can narrow the type based on the accessType discriminant.
 */
export type AccessChangeAuthentication =
  | AdminAccessAuth
  | RunAccessAuth
  | DecryptAccessAuth;

/**
 * SPF access change bundled with authentication data for EIP-712 signing
 *
 * This type represents an access control change along with its authentication metadata,
 * used when updating ciphertext permissions.
 */
export type SpfAccessChangeWithAuth = readonly [SpfParameter, AccessChangeAuthentication];

// Advanced API - Access Control Helper Functions

/**
 * Create metadata for an access change
 *
 * @param accessType - Access type code (0x00=admin, 0x01=run, 0x02=decrypt)
 * @param isExternal - Whether this is an external (off-chain) or on-chain access grant
 * @param chainId - Chain ID for on-chain access (ignored if isExternal=true, default: 0)
 * @returns Metadata encoding the access change type
 *
 * @remarks
 * When isExternal=false, chainId is encoded as 8-byte big-endian unsigned integer.
 * For off-chain (external) access, chainId parameter is ignored regardless of value.
 * Metadata format: [accessType, isExternal, chainId0, chainId1, ..., chainId7, ...]
 *
 * @internal
 */
function createAccessMetaData(
  accessType: number,
  isExternal: boolean,
  chainId: number = 0,
): MetaData {
  const bytes = [accessType, isExternal ? 0x01 : 0x00];

  if (!isExternal) {
    // Add chain ID as 8 bytes (big-endian)
    const chainIdBigInt = BigInt(chainId);
    for (let i = 7; i >= 0; i--) {
      bytes.push(Number((chainIdBigInt >> BigInt(i * 8)) & 0xffn));
    }
  }

  return createMetaData(bytes);
}

/**
 * Encode an address as bytes32 (address in high 20 bytes, zeros in low 12)
 *
 * @param address - Ethereum address to encode
 * @returns bytes32 hex string with address in high 20 bytes
 *
 * @internal
 */
function encodeAddressAsBytes32(address: Address): Bytes32 {
  const addressBytes = hexToBytes(address);
  const result = new Uint8Array(32);
  result.set(addressBytes, 0); // Address in bytes 0-19
  // Bytes 20-31 are already zeros
  return bytesToHex(result) as Bytes32;
}

/**
 * Create an access change to grant admin access to an address
 *
 * This function is part of the advanced API for batch operations.
 * For single admin grants, use the simple API: allowAdmin()
 *
 * @param address - Ethereum address to grant admin access
 * @param chainId - Optional chain ID for on-chain (contract) access
 * @returns SpfAccessChange parameter
 *
 * @example
 * ```typescript
 * // Batch operation (advanced API)
 * await updateAccess(signer, ctId, [
 *   addAdminAccess(adminAddress),
 *   allowDecryptAccess(decryptAddress)
 * ]);
 * ```
 */
export function addAdminAccess(
  address: Address,
  chainId?: number
): SpfAccessChangeWithAuth {
  const isExternal = chainId === undefined;
  const param = {
    metaData: createAccessMetaData(0x00, isExternal, chainId ?? 0),
    payload: [encodeAddressAsBytes32(address)],
  };
  const auth: AdminAccessAuth = {
    accessType: "Admin",
    accessAssignee: address,
    chainIdIfAssigneeIsContractOrZero: isExternal ? 0 : chainId!,
  };
  validateAccessChangeAuth(auth);
  return [param, auth];
}

/**
 * Create an access change to grant run access to an address for a specific program
 *
 * This function is part of the advanced API for batch operations.
 * For single run grants, use the simple API: allowRun()
 *
 * @param address - Ethereum address to grant run access
 * @param libraryId - The SPF library identifier
 * @param programName - The program name
 * @param chainId - Optional chain ID for on-chain (contract) access
 * @returns SpfAccessChange parameter
 *
 * @example
 * ```typescript
 * // Batch operation (advanced API)
 * await updateAccess(signer, ctId, [
 *   allowRunAccess(executorAddress, libraryId, asProgramName("program")),
 *   allowDecryptAccess(decryptAddress)
 * ]);
 * ```
 */
export function allowRunAccess(
  address: Address,
  libraryId: LibraryId,
  programName: ProgramName,
  chainId?: number
): SpfAccessChangeWithAuth {
  const isExternal = chainId === undefined;
  const param = {
    metaData: createAccessMetaData(0x01, isExternal, chainId ?? 0),
    payload: [
      encodeAddressAsBytes32(address),
      asBytes32(libraryId),
      asBytes32(encodeProgramName(programName)),
    ],
  };
  const auth: RunAccessAuth = {
    accessType: "Run",
    accessAssignee: address,
    chainIdIfAssigneeIsContractOrZero: isExternal ? 0 : chainId!,
    additionalInfoIfAny: `Applies to program '${programName}' in library '${libraryId}'`,
  };
  validateAccessChangeAuth(auth);
  return [param, auth];
}

/**
 * Create an access change to grant decrypt access to an address
 *
 * This function is part of the advanced API for batch operations.
 * For single decrypt grants, use the simple API: allowDecrypt()
 *
 * @param address - Ethereum address to grant decrypt access
 * @param chainId - Optional chain ID for on-chain (contract) access
 * @returns SpfAccessChange parameter
 *
 * @example
 * ```typescript
 * // Batch operation (advanced API)
 * await updateAccess(signer, ctId, [
 *   allowDecryptAccess(address1),
 *   allowDecryptAccess(address2)
 * ]);
 * ```
 */
export function allowDecryptAccess(
  address: Address,
  chainId?: number
): SpfAccessChangeWithAuth {
  const isExternal = chainId === undefined;
  const param = {
    metaData: createAccessMetaData(0x02, isExternal, chainId ?? 0),
    payload: [encodeAddressAsBytes32(address)],
  };
  const auth: DecryptAccessAuth = {
    accessType: "Decrypt",
    accessAssignee: address,
    chainIdIfAssigneeIsContractOrZero: isExternal ? 0 : chainId!,
  };
  validateAccessChangeAuth(auth);
  return [param, auth];
}

/**
 * Encode SpfAccess for submission to the ACL endpoint
 *
 * @param ciphertextId - The ciphertext identifier
 * @param changes - Array of access change parameters
 * @returns ABI-encoded SpfAccess as hex string
 *
 * @internal
 */
function encodeSpfAccess(
  ciphertextId: CiphertextId,
  changes: readonly SpfParameter[]
): string {
  const spfAccess = {
    ciphertext: ciphertextId,
    changes: changes.map((c) => ({
      metaData: c.metaData,
      payload: [...c.payload],
    })),
  };

  return encodeSpfAccessAbi(spfAccess);
}

/**
 * Update access control for a ciphertext (advanced API for batch operations)
 *
 * This function allows batch operations for efficiency. For single permission grants,
 * use the simple API: allowAdmin(), allowDecrypt(), or allowRun()
 *
 * @param signer - Ethereum signer for authentication
 * @param ciphertextId - The ciphertext identifier
 * @param changes_with_auth - Array of access change parameters and their authentication data
 * @returns Promise resolving to the new ciphertext ID
 * @throws {Error} If the access update fails, response is invalid, or client not initialized
 *
 * @example
 * ```typescript
 * // Batch operation (advanced API)
 * await initialize();
 * const changes = [
 *   addAdminAccess(adminAddress),
 *   allowDecryptAccess(decryptAddress1),
 *   allowDecryptAccess(decryptAddress2)
 * ];
 * await updateAccess(signer, ciphertextId, changes);
 * ```
 */
export async function updateAccess(
  signer: AnySigner,
  ciphertextId: CiphertextId,
  changes_with_auth: readonly SpfAccessChangeWithAuth[]
): Promise<CiphertextId> {
  const endpoint = getEndpoint();

  // Encode the SpfAccess
  const encodedAccess = encodeSpfAccess(
    ciphertextId,
    changes_with_auth.map(([v]) => v)
  );
  const accessBytes = hexToBytes(encodedAccess);

  // Create authentication header
  const identityHeader = await createIdentityHeader(
    signer,
    accessBytes,
    {
      AccessChangeAuthentication: [
        { name: "entity", type: "address" },
        { name: "timestampMillis", type: "uint64" },
        { name: "ciphertextId", type: "bytes32" },
        { name: "accessChanges", type: "AccessChangeEntry[]" },
      ],
      AccessChangeEntry: [
        { name: "accessType", type: "string" },
        { name: "accessAssignee", type: "address" },
        { name: "chainIdIfAssigneeIsContractOrZero", type: "uint64" },
        { name: "additionalInfoIfAny", type: "string" },
      ],
    },
    {
      ciphertextId: ciphertextId,
      accessChanges: changes_with_auth.map(([_, v]) => v),
    }
  );

  // Submit request
  const response = await fetch(`${endpoint}/acl`, {
    method: "POST",
    headers: {
      "spf-identity": identityHeader,
      "spf-auth": getAuthSecret()
    },
    body: accessBytes,
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Access update failed (${response.status}): ${error}`);
  }

  const resultId = parseStringResponse(await response.json());
  return asCiphertextId(resultId);
}

// Simple API - Convenience Wrapper Functions

/**
 * Grant admin access to an address for a ciphertext
 *
 * Admin access allows the address to modify access control for this ciphertext,
 * including granting additional permissions to other addresses.
 *
 * This is a convenience wrapper around updateAccess() for single admin grants.
 * For batch operations, use the advanced API: updateAccess(signer, ciphertextId, [changes])
 *
 * @param signer - Ethereum signer for authentication (must have admin access)
 * @param ciphertextId - The ciphertext identifier
 * @param address - Ethereum address to grant admin access
 * @param chainId - Optional chain ID for on-chain (contract) access
 * @returns Promise resolving to the new ciphertext ID
 * @throws {Error} If the access update fails or client not initialized
 *
 * @example
 * ```typescript
 * // Grant admin access to an address
 * const adminAddress = wallet2.getAddress();
 * const newCtId = await allowAdmin(wallet1, ctId, adminAddress);
 *
 * // Grant on-chain admin access for a smart contract on Ethereum mainnet
 * const contractAddress = asAddress("0x1234567890123456789012345678901234567890");
 * const newCtId = await allowAdmin(wallet1, ctId, contractAddress, 1);
 * ```
 */
export async function allowAdmin(
  signer: AnySigner,
  ciphertextId: CiphertextId,
  address: Address,
  chainId?: number
): Promise<CiphertextId> {
  return updateAccess(signer, ciphertextId, [
    addAdminAccess(address, chainId),
  ]);
}

/**
 * Grant decrypt access to an address for a ciphertext
 *
 * Decrypt access allows the address to request threshold decryption of this
 * ciphertext through the SPF network.
 *
 * This is a convenience wrapper around updateAccess() for single decrypt grants.
 * For batch operations, use the advanced API: updateAccess(signer, ciphertextId, [changes])
 *
 * @param signer - Ethereum signer for authentication (must have admin access)
 * @param ciphertextId - The ciphertext identifier
 * @param address - Ethereum address to grant decrypt access
 * @param chainId - Optional chain ID for on-chain (contract) access
 * @returns Promise resolving to the new ciphertext ID
 * @throws {Error} If the access update fails or client not initialized
 *
 * @example
 * ```typescript
 * // Grant decrypt access to an address
 * const decryptAddress = wallet2.getAddress();
 * const newCtId = await allowDecrypt(wallet1, ctId, decryptAddress);
 *
 * // Grant on-chain decrypt access for a smart contract
 * const contractAddress = asAddress("0x1234567890123456789012345678901234567890");
 * const newCtId = await allowDecrypt(wallet1, ctId, contractAddress, 1);
 * ```
 */
export async function allowDecrypt(
  signer: AnySigner,
  ciphertextId: CiphertextId,
  address: Address,
  chainId?: number
): Promise<CiphertextId> {
  return updateAccess(signer, ciphertextId, [
    allowDecryptAccess(address, chainId),
  ]);
}

/**
 * Grant run access to an address for a specific FHE program on a ciphertext
 *
 * Run access allows the address to execute a specific FHE program using this
 * ciphertext as an input parameter.
 *
 * This is a convenience wrapper around updateAccess() for single run grants.
 * For batch operations, use the advanced API: updateAccess(signer, ciphertextId, [changes])
 *
 * @param signer - Ethereum signer for authentication (must have admin access)
 * @param ciphertextId - The ciphertext identifier
 * @param address - Ethereum address to grant run access
 * @param libraryId - The SPF library identifier (program hash)
 * @param programName - The program entry point name
 * @param chainId - Optional chain ID for on-chain (contract) access
 * @returns Promise resolving to the new ciphertext ID
 * @throws {Error} If the access update fails or client not initialized
 *
 * @example
 * ```typescript
 * // Grant run access to an address for a specific program
 * const executorAddress = wallet2.getAddress();
 * const newCtId = await allowRun(
 *   wallet1,
 *   ctId,
 *   executorAddress,
 *   libraryId,
 *   asProgramName("tally_votes")
 * );
 *
 * // Grant on-chain run access for a smart contract
 * const contractAddress = asAddress("0x1234567890123456789012345678901234567890");
 * const newCtId = await allowRun(
 *   wallet1,
 *   ctId,
 *   contractAddress,
 *   libraryId,
 *   asProgramName("tally_votes"),
 *   1
 * );
 * ```
 */
export async function allowRun(
  signer: AnySigner,
  ciphertextId: CiphertextId,
  address: Address,
  libraryId: LibraryId,
  programName: ProgramName,
  chainId?: number
): Promise<CiphertextId> {
  return updateAccess(signer, ciphertextId, [
    allowRunAccess(address, libraryId, programName, chainId),
  ]);
}
