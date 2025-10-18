/**
 * Runtime validation for SPF authentication data
 *
 * These validators ensure that authentication objects are constructed correctly,
 * catching errors that may bypass the type system (e.g., through type assertions,
 * tests, or incorrect object construction).
 *
 * @module validation
 * @internal
 */

import type { ParameterAuthentication } from "./spf-client.js";
import type { AccessChangeAuthentication as AclAuth } from "./acl.js";

/**
 * Validate parameter authentication data structure
 *
 * Verifies that the authentication object has the correct structure based on its paramType.
 * Throws an error if validation fails.
 *
 * @param auth - Parameter authentication data to validate
 * @throws {Error} If validation fails
 *
 * @example
 * ```typescript
 * const auth: CiphertextParameterAuth = {
 *   paramType: "Ciphertext",
 *   plaintextValuesIfAny: [],
 *   ciphertextIdsIfAny: [ctId],
 * };
 * validateParameterAuth(auth); // OK
 * ```
 */
export function validateParameterAuth(auth: ParameterAuthentication): void {
  switch (auth.paramType) {
    case "Ciphertext":
      if (auth.ciphertextIdsIfAny.length !== 1) {
        throw new Error(
          `Ciphertext parameter must have exactly 1 ciphertext ID, got ${auth.ciphertextIdsIfAny.length}`
        );
      }
      if (auth.plaintextValuesIfAny.length !== 0) {
        throw new Error(
          `Ciphertext parameter must have 0 plaintext values, got ${auth.plaintextValuesIfAny.length}`
        );
      }
      if (auth.additionalInfoIfAny !== undefined) {
        throw new Error(
          `Ciphertext parameter must not have additionalInfoIfAny, got ${auth.additionalInfoIfAny}`
        );
      }
      break;

    case "CiphertextArray":
      if (auth.plaintextValuesIfAny.length !== 0) {
        throw new Error(
          `CiphertextArray parameter must have 0 plaintext values, got ${auth.plaintextValuesIfAny.length}`
        );
      }
      if (auth.additionalInfoIfAny !== undefined) {
        throw new Error(
          `CiphertextArray parameter must not have additionalInfoIfAny, got ${auth.additionalInfoIfAny}`
        );
      }
      break;

    case "OutputCiphertextArray":
      if (auth.ciphertextIdsIfAny.length !== 0) {
        throw new Error(
          `OutputCiphertextArray parameter must have 0 ciphertext IDs, got ${auth.ciphertextIdsIfAny.length}`
        );
      }
      if (auth.plaintextValuesIfAny.length !== 0) {
        throw new Error(
          `OutputCiphertextArray parameter must have 0 plaintext values, got ${auth.plaintextValuesIfAny.length}`
        );
      }
      if (auth.additionalInfoIfAny === undefined) {
        throw new Error(
          "OutputCiphertextArray parameter must have additionalInfoIfAny"
        );
      }
      break;

    case "Plaintext":
      if (auth.plaintextValuesIfAny.length !== 1) {
        throw new Error(
          `Plaintext parameter must have exactly 1 plaintext value, got ${auth.plaintextValuesIfAny.length}`
        );
      }
      if (auth.ciphertextIdsIfAny.length !== 0) {
        throw new Error(
          `Plaintext parameter must have 0 ciphertext IDs, got ${auth.ciphertextIdsIfAny.length}`
        );
      }
      if (auth.additionalInfoIfAny === undefined) {
        throw new Error("Plaintext parameter must have additionalInfoIfAny");
      }
      break;

    case "PlaintextArray":
      if (auth.plaintextValuesIfAny.length === 0) {
        throw new Error(
          "PlaintextArray parameter must have at least 1 plaintext value"
        );
      }
      if (auth.ciphertextIdsIfAny.length !== 0) {
        throw new Error(
          `PlaintextArray parameter must have 0 ciphertext IDs, got ${auth.ciphertextIdsIfAny.length}`
        );
      }
      if (auth.additionalInfoIfAny === undefined) {
        throw new Error("PlaintextArray parameter must have additionalInfoIfAny");
      }
      break;

    default:
      // TypeScript exhaustiveness check
      const _exhaustive: never = auth;
      throw new Error(`Unknown parameter type: ${(_exhaustive as ParameterAuthentication).paramType}`);
  }
}

/**
 * Validate ACL access change authentication data structure
 *
 * Verifies that the authentication object has the correct structure based on its accessType.
 * Throws an error if validation fails.
 *
 * @param auth - ACL authentication data to validate
 * @throws {Error} If validation fails
 *
 * @example
 * ```typescript
 * const auth: AdminAccessAuth = {
 *   accessType: "Admin",
 *   accessAssignee: address,
 *   chainIdIfAssigneeIsContractOrZero: 0,
 * };
 * validateAccessChangeAuth(auth); // OK
 * ```
 */
export function validateAccessChangeAuth(auth: AclAuth): void {
  switch (auth.accessType) {
    case "Admin":
      if ("additionalInfoIfAny" in auth) {
        throw new Error(
          `Admin access change must not have additionalInfoIfAny property`
        );
      }
      break;

    case "Run":
      if (!("additionalInfoIfAny" in auth)) {
        throw new Error("Run access change must have additionalInfoIfAny");
      }
      // Type guard: check if property exists and is a string
      const additionalInfo = (auth as { additionalInfoIfAny?: string }).additionalInfoIfAny;
      if (additionalInfo === undefined || typeof additionalInfo !== "string") {
        throw new Error("Run access change additionalInfoIfAny must be a non-empty string");
      }
      break;

    case "Decrypt":
      if ("additionalInfoIfAny" in auth) {
        throw new Error(
          `Decrypt access change must not have additionalInfoIfAny property`
        );
      }
      break;

    default:
      // TypeScript exhaustiveness check
      const _exhaustive: never = auth;
      throw new Error(`Unknown access type: ${(_exhaustive as AclAuth).accessType}`);
  }
}
