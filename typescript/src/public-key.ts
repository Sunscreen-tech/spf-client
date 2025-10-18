import { getEndpoint } from "@sunscreen/spf-client/spf-wasm-loader";

// In-memory cache for the SPF public key
let cachedPublicKey: Uint8Array | null = null;
let cachedEndpoint: string | null = null;

/**
 * Fetch the SPF threshold network public key.
 *
 * The public key is required for client-side encryption and is cached
 * for the lifetime of the process to avoid repeated network requests.
 *
 * @returns Promise resolving to the public key bytes
 * @throws {Error} If the public key cannot be fetched or client not initialized
 *
 * @example
 * ```typescript
 * await initialize();
 * const publicKey = await getPublicKey();
 * const ciphertext = await encryptValue(42, 16);
 * ```
 */
export async function getPublicKey(): Promise<Uint8Array> {
  const endpoint = getEndpoint();
  // Return cached key if available and endpoint matches
  if (cachedPublicKey !== null && cachedEndpoint === endpoint) {
    return cachedPublicKey;
  }

  try {
    const response = await fetch(`${endpoint}/public_keys`);

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `Failed to fetch public key (${response.status}): ${errorText}`,
      );
    }

    const publicKeyBytes = new Uint8Array(await response.arrayBuffer());

    // Validate size (public key should not be empty)
    if (publicKeyBytes.length === 0) {
      throw new Error("Received empty public key from SPF service");
    }

    // Cache for future use
    cachedPublicKey = publicKeyBytes;
    cachedEndpoint = endpoint;

    return cachedPublicKey;
  } catch (error) {
    if (error instanceof Error) {
      error.message = `Public key fetch failed: ${error.message}`;
      throw error;
    }
    throw new Error(`Public key fetch failed: ${String(error)}`);
  }
}

/**
 * Clear the cached public key.
 * Mainly useful for testing purposes.
 *
 * @internal
 */
export function clearPublicKeyCache(): void {
  cachedPublicKey = null;
  cachedEndpoint = null;
}
