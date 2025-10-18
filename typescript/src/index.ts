/**
 * Main entry point for spf-client (Node.js/default)
 *
 * This is the default export used when not in a browser environment.
 * For browser environments, the conditional export will use src/browser/index.ts instead.
 */

// Re-export everything from main client
export * from './spf-client.js';

// Re-export ACL module
export * from './acl.js';

// Re-export Node.js/bundler-compatible WASM functions
export {
  getWasmModule,
  initialize,
  preloadWasm,
  clearWasmCache,
  isInitialized,
} from '@sunscreen/spf-client/spf-wasm-loader';
