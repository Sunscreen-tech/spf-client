import type { SignerModeType } from '../interfaces/SignerStrategy.js';

/**
 * Type guard for SignerModeType
 */
export function isSignerMode(value: unknown): value is SignerModeType {
  return value === 'web2' || value === 'web3';
}
