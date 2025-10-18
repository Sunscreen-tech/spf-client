/**
 * Global type augmentations for browser APIs
 */

import type { EIP1193Provider } from '../wallet/WalletCapabilities.js';

declare global {
  interface Window {
    /**
     * Ethereum provider (injected by wallets)
     * @see https://docs.metamask.io/wallet/reference/provider-api/
     * @see https://eips.ethereum.org/EIPS/eip-1193
     */
    ethereum?: EIP1193Provider;
  }

  /**
   * EIP-6963: Multi Injected Provider Discovery
   * @see https://eips.ethereum.org/EIPS/eip-6963
   */
  interface WindowEventMap {
    /**
     * Announced when a wallet provider is detected
     */
    'eip6963:announceProvider': CustomEvent<{
      info: {
        uuid: string;
        name: string;
        icon: string;
        rdns: string;
      };
      provider: EIP1193Provider;
    }>;

    /**
     * Request providers to announce themselves
     */
    'eip6963:requestProvider': Event;
  }
}

export {};
