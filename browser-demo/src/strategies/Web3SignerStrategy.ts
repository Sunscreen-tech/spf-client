import { BrowserProvider } from 'ethers';
import type { Signer } from 'ethers';
import { PrivateKeySigner } from '@sunscreen/spf-client';
import type { SignerStrategy } from '../interfaces/SignerStrategy.js';

/**
 * Web3 signer strategy - hybrid MetaMask + PrivateKeySigner
 *
 * This strategy uses MetaMask for user operations (data ownership) and
 * a generated PrivateKeySigner for runner operations (computation).
 *
 * In the voting workflow, this reduces MetaMask popups to just 2:
 * - Upload user's vote ciphertext (MetaMask signature required)
 * - Grant run access to user's vote (MetaMask signature required)
 * All simulated votes and runner operations use generated keys (no popups)
 */
export class Web3SignerStrategy implements SignerStrategy {
  readonly mode = 'web3' as const;

  private userSigner: Signer | null = null;
  private userAddress: string = '';
  private runnerSigner: PrivateKeySigner | null = null;
  private runnerAddress: string = '';

  /**
   * Initialize by connecting to MetaMask and generating runner key
   */
  async initialize(): Promise<void> {
    // Check if MetaMask is installed
    if (!window.ethereum) {
      throw new Error('MetaMask not found. Please install MetaMask extension.');
    }

    // Connect to MetaMask for user operations
    const provider = new BrowserProvider(window.ethereum);
    const signer = await provider.getSigner();
    this.userSigner = signer;
    this.userAddress = await signer.getAddress();

    // Generate PrivateKeySigner for runner operations
    this.runnerSigner = PrivateKeySigner.random();
    this.runnerAddress = this.runnerSigner.getAddress() as string;
  }

  /**
   * Get the user signer (MetaMask - returns ethers.Signer)
   */
  getUserSigner(): Signer {
    if (!this.userSigner) {
      throw new Error('Web3 strategy not initialized. Call initialize() first.');
    }
    return this.userSigner;
  }

  /**
   * Get the runner signer (PrivateKeySigner)
   */
  getRunnerSigner(): PrivateKeySigner {
    if (!this.runnerSigner) {
      throw new Error('Web3 strategy not initialized. Call initialize() first.');
    }
    return this.runnerSigner;
  }

  /**
   * Get user address (MetaMask account)
   */
  getUserAddress(): string {
    if (!this.userAddress) {
      throw new Error('Web3 strategy not initialized. Call initialize() first.');
    }
    return this.userAddress;
  }

  /**
   * Get runner address (generated key)
   */
  getRunnerAddress(): string {
    if (!this.runnerAddress) {
      throw new Error('Web3 strategy not initialized. Call initialize() first.');
    }
    return this.runnerAddress;
  }

  /**
   * Clean up (clear signers from memory)
   */
  cleanup(): Promise<void> {
    this.userSigner = null;
    this.userAddress = '';
    this.runnerSigner = null;
    this.runnerAddress = '';
    return Promise.resolve();
  }
}
