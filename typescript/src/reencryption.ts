import { keccak_256 } from "@noble/hashes/sha3";
import type { AnySigner, CiphertextId, ReencryptHandle, PollingOptions } from "./spf-client.js";
import { createIdentityHeader, asCiphertextId, asReencryptHandle, pollUntilComplete } from "./spf-client.js";
import { getEndpoint } from "@sunscreen/spf-client/spf-wasm-loader";
import { getAuthSecret } from "./internal/endpoint-state.js";

/**
 * Reencryption status - pending, running, or in progress
 */
export type ReencryptionStatusPending = {
  readonly status: "pending" | "running" | "in_progress";
};

/**
 * Reencryption status - success with reencrypted ciphertext ID
 */
export type ReencryptionStatusSuccess = {
  readonly status: "success";
  readonly payload: {
    readonly id: CiphertextId;
  };
};

/**
 * Reencryption status - failed with error message
 */
export type ReencryptionStatusFailed = {
  readonly status: "failed";
  readonly payload?: {
    readonly message?: string;
  };
};

/**
 * Discriminated union of all reencryption statuses
 */
export type ReencryptionStatus =
  | ReencryptionStatusPending
  | ReencryptionStatusSuccess
  | ReencryptionStatusFailed;

/**
 * Request re-encryption of a ciphertext using a one-time pad.
 *
 * The SPF service will re-encrypt the ciphertext under the provided public OTP,
 * enabling local decryption with the corresponding secret OTP.
 *
 * @param signer - Ethereum signer (for authentication)
 * @param ciphertextId - Ciphertext identifier (hex string, with or without 0x prefix)
 * @param publicOtp - Public one-time pad bytes (from generateOtp())
 * @returns Promise resolving to reencryption handle (same as reencrypted ciphertext ID)
 * @throws {Error} If reencryption request fails or client not initialized
 *
 * @example
 * ```typescript
 * await initialize();
 * const { publicOtp, secretOtp } = await generateOtp();
 * const reencryptHandle = await requestReencryption(signer, ciphertextId, publicOtp);
 * ```
 */
export async function requestReencryption(
  signer: AnySigner,
  ciphertextId: CiphertextId,
  publicOtp: Uint8Array,
): Promise<ReencryptHandle> {
  const endpoint = getEndpoint();
  // Create authentication header
  const identityHeader = await createIdentityHeader(
    signer,
    publicOtp,
    {
      ReencryptionAuthentication: [
        { name: "entity", type: "address" },
        { name: "timestampMillis", type: "uint64" },
        { name: "oneTimePadHash", type: "bytes32" },
      ],
    },
    {
      oneTimePadHash: keccak_256(publicOtp),
    }
  );

  const response = await fetch(
    `${endpoint}/recryption/${ciphertextId}`,
    {
      method: "POST",
      headers: {
        "spf-identity": identityHeader,
        "spf-auth": getAuthSecret()
      },
      body: publicOtp,
    },
  );

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(
      `Reencryption request failed (${response.status}): ${errorText}`,
    );
  }

  const reencryptHandle = await response.json();

  if (typeof reencryptHandle !== "string") {
    throw new Error(
      `Unexpected reencryption handle format: ${JSON.stringify(reencryptHandle)}`,
    );
  }

  return asReencryptHandle(reencryptHandle);
}

/**
 * Check the status of a reencryption request.
 *
 * @param reencryptHandle - Reencryption handle (from requestReencryption())
 * @returns Promise resolving to current reencryption status
 * @throws {Error} If status check fails or client not initialized
 *
 * @example
 * ```typescript
 * const status = await checkReencryptionStatus(reencryptHandle);
 *
 * if (status.status === 'success') {
 *   console.log('Reencrypted ciphertext ID:', status.payload.id);
 * }
 * ```
 */
export async function checkReencryptionStatus(
  reencryptHandle: ReencryptHandle,
): Promise<ReencryptionStatus> {
  const endpoint = getEndpoint();
  const response = await fetch(
    `${endpoint}/recryption/${reencryptHandle}`,
    {
      method: "GET",
      headers: {
        "spf-auth": getAuthSecret()
      }
    }
  );

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(
      `Reencryption status check failed (${response.status}): ${errorText}`,
    );
  }

  const data = await response.json();

  // Validate status format
  if (
    typeof data !== "object" ||
    data === null ||
    typeof (data as Record<string, unknown>)["status"] !== "string"
  ) {
    throw new Error(
      `Unexpected reencryption status format: ${JSON.stringify(data)}`,
    );
  }

  const obj = data as Record<string, unknown>;
  const status = obj["status"] as string;

  if (status === "success") {
    const payload = obj["payload"];
    if (
      typeof payload !== "object" ||
      payload === null ||
      typeof (payload as Record<string, unknown>)["id"] !== "string"
    ) {
      throw new Error(
        `Reencryption success payload missing or invalid id field: ${JSON.stringify(data)}`,
      );
    }
    const id = (payload as Record<string, unknown>)["id"] as string;
    const result: ReencryptionStatusSuccess = {
      status: "success",
      payload: {
        id: asCiphertextId(id),
      },
    };
    return result;
  }

  if (status === "failed") {
    const payload = obj["payload"];
    if (payload !== undefined && payload !== null && typeof payload === "object") {
      const result: ReencryptionStatusFailed = {
        status: "failed",
        payload: payload as { readonly message?: string },
      };
      return result;
    } else {
      const result: ReencryptionStatusFailed = {
        status: "failed",
      };
      return result;
    }
  }

  if (status === "pending" || status === "running" || status === "in_progress") {
    const result: ReencryptionStatusPending = {
      status: status as "pending" | "running" | "in_progress",
    };
    return result;
  }

  throw new Error(`Unknown reencryption status: ${status}`);
}

/**
 * Poll for reencryption completion with exponential backoff.
 *
 * Polls with exponential backoff (60ms → 30s max by default) until reencryption completes
 * (success or failure). Use AbortController for timeout and cancellation control.
 *
 * **Abort timing**: The signal is checked before each polling iteration. Status check
 * requests are fast (< 100ms typically), so abort is detected within ~50-200ms in practice.
 *
 * @param reencryptHandle - Reencryption handle (from requestReencryption())
 * @param signal - Optional AbortSignal to cancel the polling operation
 * @param options - Optional polling configuration (defaults to POLL_DEFAULTS)
 * @returns Promise resolving to reencrypted ciphertext ID
 * @throws {Error} If reencryption fails or operation is aborted
 *
 * @example
 * ```typescript
 * await initialize();
 * const reencryptHandle = await requestReencryption(signer, ciphertextId, publicOtp);
 *
 * // Poll until complete
 * const reencryptedCtId = await waitForReencryption(reencryptHandle);
 *
 * // With 60s timeout using AbortController
 * const controller = new AbortController();
 * const timeoutId = setTimeout(() => controller.abort(), 60000);
 * try {
 *   const reencryptedCtId = await waitForReencryption(reencryptHandle, controller.signal);
 * } finally {
 *   clearTimeout(timeoutId);
 * }
 *
 * // With custom polling (faster for testing)
 * const reencryptedCtId = await waitForReencryption(reencryptHandle, undefined, {
 *   initialIntervalMs: 10,
 *   maxIntervalMs: 1000
 * });
 * ```
 */
export async function waitForReencryption(
  reencryptHandle: ReencryptHandle,
  signal?: AbortSignal,
  options?: PollingOptions
): Promise<CiphertextId> {
  return pollUntilComplete(
    () => checkReencryptionStatus(reencryptHandle),
    (status) => {
      if (!status.payload?.id) {
        throw new Error(
          "Reencryption succeeded but no reencrypted ciphertext ID was returned",
        );
      }
      return status.payload.id;
    },
    signal,
    "Reencryption",
    options
  );
}
