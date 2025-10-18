import type { AnySigner } from '@sunscreen/spf-client';

/**
 * Signer mode type - Web2 (generated keys) or Web3 (MetaMask)
 */
export type SignerModeType = 'web2' | 'web3';

/**
 * Signer strategy interface
 *
 * Defines the contract that both Web2 and Web3 signing strategies must implement.
 * This abstraction allows the workflow to be mode-agnostic.
 */
export interface SignerStrategy {
  /**
   * The mode this strategy implements
   */
  readonly mode: SignerModeType;

  /**
   * Initialize the strategy (e.g., connect to MetaMask or generate keys)
   */
  initialize(): Promise<void>;

  /**
   * Get the signer for user operations (encrypt, upload ciphertexts, grant access)
   * Returns AnySigner (supports both SpfSigner and ethers.Signer)
   */
  getUserSigner(): AnySigner;

  /**
   * Get the signer for runner operations (upload program, run program, decrypt results)
   *
   * Note: In Web2 mode, this returns a separate generated PrivateKeySigner
   *       In Web3 mode, this returns a generated PrivateKeySigner (not MetaMask)
   */
  getRunnerSigner(): AnySigner;

  /**
   * Get the user's Ethereum address (for display purposes)
   */
  getUserAddress(): string;

  /**
   * Get the runner's Ethereum address (for display purposes)
   */
  getRunnerAddress(): string;

  /**
   * Clean up resources (e.g., clear keys from memory)
   */
  cleanup(): Promise<void>;
}
