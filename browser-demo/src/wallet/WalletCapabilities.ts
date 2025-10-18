/**
 * Wallet Capabilities Types
 *
 * Type definitions for wallet detection and capabilities
 * following EIP-6963 and EIP-1193 standards
 */

import type { SignerModeType } from '../interfaces/SignerStrategy.js';

/**
 * EIP-1193 Provider Interface
 * @see https://eips.ethereum.org/EIPS/eip-1193
 */
export interface EIP1193Provider {
  /**
   * Make JSON-RPC request to provider
   */
  request(args: { method: string; params?: unknown[] | Record<string, unknown> }): Promise<unknown>;

  /**
   * Subscribe to provider events (optional)
   */
  on?(eventName: string, listener: (...args: unknown[]) => void): void;

  /**
   * Unsubscribe from provider events (optional)
   */
  removeListener?(eventName: string, listener: (...args: unknown[]) => void): void;

  // Common wallet-specific flags (not in EIP-1193 spec but widely used)
  isMetaMask?: boolean;
  isCoinbaseWallet?: boolean;
  isTrust?: boolean;
  isRainbow?: boolean;
}

/**
 * Wallet detection result
 */
export interface WalletDetectionResult {
  /** Is this a mobile device? */
  isMobile: boolean;

  /** Are Web3 wallets available? */
  hasWeb3Wallet: boolean;

  /** Detected wallet providers (EIP-6963) */
  providers: WalletProvider[];

  /** Legacy window.ethereum available? */
  hasLegacyProvider: boolean;

  /** Recommended mode based on detection */
  recommendedMode: SignerModeType;

  /** Should show mode selector? */
  showModeSelector: boolean;

  /** Detection method used */
  detectionMethod: 'eip6963' | 'legacy' | 'timeout';
}

/**
 * EIP-6963 Provider Detail
 */
export interface WalletProvider {
  info: {
    uuid: string;
    name: string;
    icon: string;
    rdns: string;
  };
  provider: EIP1193Provider;
}

/**
 * EIP-6963 Announce Event Detail
 */
export interface EIP6963ProviderDetail {
  info: {
    uuid: string;
    name: string;
    icon: string;
    rdns: string;
  };
  provider: EIP1193Provider;
}
