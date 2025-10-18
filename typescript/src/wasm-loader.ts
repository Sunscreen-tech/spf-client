import type * as WasmTypes from "../wasm-bindings/spf_client.js";
import { getPublicKey } from "./public-key.js";
import {
  getEndpoint,
  setEndpoint,
  clearEndpoint,
  getCurrentEndpoint,
} from "./internal/endpoint-state.js";

let wasmModule: typeof WasmTypes | null = null;
let initialized = false;

export async function getWasmModule(): Promise<typeof WasmTypes> {
  if (wasmModule !== null) {
    return wasmModule;
  }

  try {
    wasmModule = await import("../wasm-bindings/spf_client.js");
    return wasmModule;
  } catch (error) {
    if (error instanceof Error) {
      error.message = `Failed to load WASM module: ${error.message}`;
      throw error;
    }
    throw new Error(`Failed to load WASM module: ${String(error)}`);
  }
}

export async function initialize(endpoint: string = "https://spf.sunscreen.tech"): Promise<void> {
  const currentEndpoint = getCurrentEndpoint();

  // If already initialized with the same endpoint, skip reinitialization
  if (initialized && currentEndpoint === endpoint) {
    return;
  }

  // If initialized with a different endpoint, we need to clear and reinitialize
  if (initialized && currentEndpoint !== endpoint) {
    throw new Error(
      `WASM module already initialized with endpoint ${currentEndpoint}. ` +
      `Call clearWasmCache() before initializing with a different endpoint (${endpoint}).`
    );
  }

  const wasm = await getWasmModule();

  try {
    // Set endpoint before fetching public key (getPublicKey uses getEndpoint)
    // Import asSpfEndpoint from spf-client
    const { asSpfEndpoint } = await import("./spf-client.js");
    setEndpoint(asSpfEndpoint(endpoint));

    // Fetch public key using TypeScript (browser fetch or Node.js fetch)
    const publicKeyBytes = await getPublicKey();

    // Initialize WASM with the fetched public key bytes
    try {
      wasm.initialize_with_public_key(publicKeyBytes);
      initialized = true;
    } catch (error) {
      // If initialization fails due to already being initialized, check the error message
      const errorMsg = error instanceof Error ? error.message : String(error);
      if (errorMsg.includes("already initialized")) {
        throw new Error(
          `WASM module already initialized. Call clearWasmCache() before reinitializing.`
        );
      }
      throw error;
    }
  } catch (error) {
    // Reset endpoint on any initialization failure
    clearEndpoint();
    initialized = false;
    throw error;
  }
}

export async function preloadWasm(): Promise<void> {
  await getWasmModule();
}

export function clearWasmCache(): void {
  wasmModule = null;
  initialized = false;
  clearEndpoint();
}

export function isInitialized(): boolean {
  return initialized;
}

// Re-export getEndpoint from shared module
export { getEndpoint };
