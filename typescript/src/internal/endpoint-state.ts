/**
 * Shared endpoint state management for SPF client initialization.
 * This module maintains the singleton endpoint configuration used across
 * both Node.js and browser WASM loaders.
 * @internal
 */

import type { SpfAuthSecret, SpfEndpoint } from "../spf-client.js";

let currentEndpoint: SpfEndpoint | null = null;
let currentAuthSecret: SpfAuthSecret | null = null;

/**
 * Get the currently configured endpoint.
 * @returns The endpoint URL
 * @throws {Error} If client not initialized
 * @internal
 */
export function getEndpoint(): string {
  if (currentEndpoint === null) {
    throw new Error(
      "SPF client not initialized. Call initialize(endpoint) before making API calls."
    );
  }
  return currentEndpoint;
}

/**
 * Set the endpoint. Should only be called during initialization.
 * @param endpoint - The endpoint URL to set
 * @internal
 */
export function setEndpoint(endpoint: SpfEndpoint): void {
  currentEndpoint = endpoint;
}

/**
 * Clear the endpoint state. Used for cleanup and testing.
 * @internal
 */
export function clearEndpoint(): void {
  currentEndpoint = null;
}

/**
 * Set the auth secret that will be attached to each request via the 'spf-auth'
 * header.
 * @param authSecret The secret
 * @internal
 */
export function setAuthSecret(authSecret: SpfAuthSecret): void {
  currentAuthSecret = authSecret;
}

/**
 * Get the current endpoint without throwing. Used for initialization checks.
 * @returns The endpoint URL or null if not set
 * @internal
 */
export function getCurrentEndpoint(): SpfEndpoint | null {
  return currentEndpoint;
}

/**
 * Gets the auth secret.
 * @returns The auth secret.
 */
export function getAuthSecret(): string {
  return currentAuthSecret || '';
}