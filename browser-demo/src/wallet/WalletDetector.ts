/**
 * Wallet Detector - Modern EIP-6963 + Legacy Fallback
 *
 * Detection Strategy:
 * 1. Listen for EIP-6963 providers (immediate)
 * 2. Fallback to window.ethereum if no EIP-6963
 * 3. Determine mode based on device + wallet availability
 *
 * Works with any wallet app: MetaMask, Trust Wallet, Coinbase, Rainbow, etc.
 */

import { isMobileDevice } from './DeviceDetector.js';
import type {
  WalletDetectionResult,
  WalletProvider,
  EIP6963ProviderDetail,
} from './WalletCapabilities.js';

/**
 * Wallet Detector Class
 *
 * Detects wallet capabilities using modern EIP-6963 standard
 * with fallback to legacy window.ethereum
 */
export class WalletDetector {
  private abortController: AbortController | null = null;

  /**
   * Detect wallet capabilities and recommend mode
   *
   * @returns Promise<WalletDetectionResult>
   */
  async detect(): Promise<WalletDetectionResult> {
    // Abort any in-progress detection
    if (this.abortController) {
      this.abortController.abort();
    }

    const isMobile = isMobileDevice();

    // Try EIP-6963 first (modern approach)
    const eip6963Providers = await this.detectEIP6963();

    // Fallback to legacy window.ethereum
    const hasLegacyProvider = typeof window !== 'undefined' && !!window.ethereum;

    const hasWeb3Wallet = eip6963Providers.length > 0 || hasLegacyProvider;

    // Decision logic
    const result = this.determineMode(isMobile, hasWeb3Wallet);

    return {
      isMobile,
      hasWeb3Wallet,
      providers: eip6963Providers,
      hasLegacyProvider,
      ...result,
      detectionMethod:
        eip6963Providers.length > 0 ? 'eip6963' : hasLegacyProvider ? 'legacy' : 'timeout',
    };
  }

  /**
   * EIP-6963 Detection
   * Listen for announceProvider events (immediate)
   *
   * @returns Promise<WalletProvider[]>
   */
  private async detectEIP6963(): Promise<WalletProvider[]> {
    if (typeof window === 'undefined') {
      return [];
    }

    this.abortController = new AbortController();
    const signal = this.abortController.signal;

    return new Promise((resolve, reject) => {
      const providers: WalletProvider[] = [];
      const seenUUIDs = new Set<string>();

      const cleanup = (): void => {
        try {
          window.removeEventListener('eip6963:announceProvider', onAnnounce);
        } catch (error) {
          // Ignore cleanup errors
          console.warn('[WalletDetector] Error during cleanup:', error);
        }
      };

      // Handle abort
      signal.addEventListener('abort', () => {
        cleanup();
        reject(new Error('Detection aborted'));
      });

      const onAnnounce = (event: Event): void => {
        if (signal.aborted) return;

        const providerEvent = event as CustomEvent<EIP6963ProviderDetail>;
        const detail = providerEvent.detail;

        // Prevent duplicates
        if (seenUUIDs.has(detail.info.uuid)) {
          return;
        }

        seenUUIDs.add(detail.info.uuid);
        providers.push({
          info: detail.info,
          provider: detail.provider,
        });
      };

      try {
        // Listen for announcements
        window.addEventListener('eip6963:announceProvider', onAnnounce);

        // Dispatch request immediately after listener registration
        // Providers respond synchronously, so we resolve immediately after dispatch
        try {
          window.dispatchEvent(new Event('eip6963:requestProvider'));

          // Resolve immediately - EIP-6963 providers announce synchronously
          cleanup();
          resolve(providers);
        } catch (error) {
          console.warn('[WalletDetector] Error dispatching EIP-6963 request:', error);
          cleanup();
          resolve([]); // Fallback to empty array
        }
      } catch (error) {
        // Log error but don't fail - fallback to empty array
        console.warn('[WalletDetector] EIP-6963 detection failed:', error);
        cleanup();
        resolve([]);
      }
    });
  }

  /**
   * Determine recommended mode based on detection
   *
   * Logic:
   * - Mobile + wallet app browser: Force Web3, hide selector
   * - Mobile + no wallet: Force Web2, hide selector
   * - Desktop + no wallet: Force Web2, hide selector
   * - Desktop + wallet: Show selector, default Web3
   *
   * @param isMobile - Is this a mobile device?
   * @param hasWeb3Wallet - Are Web3 wallets available?
   * @returns Recommended mode and visibility
   */
  private determineMode(
    isMobile: boolean,
    hasWeb3Wallet: boolean
  ): Pick<WalletDetectionResult, 'recommendedMode' | 'showModeSelector'> {
    // Mobile + any wallet app browser: force Web3, hide selector
    if (isMobile && hasWeb3Wallet) {
      return {
        recommendedMode: 'web3',
        showModeSelector: false,
      };
    }

    // Mobile + no wallet: Force Web2, hide selector
    if (isMobile && !hasWeb3Wallet) {
      return {
        recommendedMode: 'web2',
        showModeSelector: false,
      };
    }

    // Desktop + no wallet: Force Web2, hide selector
    if (!isMobile && !hasWeb3Wallet) {
      return {
        recommendedMode: 'web2',
        showModeSelector: false,
      };
    }

    // Desktop + wallet: Show selector, default Web3
    return {
      recommendedMode: 'web3',
      showModeSelector: true,
    };
  }

  /**
   * Clean up all resources and abort any in-progress detection
   */
  cleanup(): void {
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }
  }
}
