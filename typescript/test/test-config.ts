/**
 * Test configuration
 *
 * All tests default to the local SPF service endpoint.
 * This ensures tests do not accidentally hit production.
 *
 * To run tests against a different endpoint, set the TEST_ENDPOINT environment variable:
 *   TEST_ENDPOINT=https://spf.sunscreen.tech npm test
 *
 * Test isolation:
 * - Each test suite uses clearAllCaches() in afterEach hooks to prevent state contamination
 * - The WASM module and public key are cached per endpoint and cleared between tests
 * - Do not import endpoints directly from examples; always use this config or pass explicitly
 */
export const TEST_ENDPOINT = "http://localhost:8080";
