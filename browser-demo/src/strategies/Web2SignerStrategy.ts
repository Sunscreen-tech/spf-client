import { PrivateKeySigner } from '@sunscreen/spf-client';
import type { SignerStrategy } from '../interfaces/SignerStrategy.js';

/**
 * Web2 signer strategy - uses generated private keys
 *
 * This strategy generates two independent Ethereum keys:
 * - User key: for encrypting data and managing ciphertext access
 * - Runner key: for uploading programs and executing FHE computations
 *
 * This separation demonstrates a realistic scenario where:
 * - Users own their encrypted data
 * - A separate service/runner executes computations on that data
 */
export class Web2SignerStrategy implements SignerStrategy {
  readonly mode = 'web2' as const;

  private userSigner: PrivateKeySigner | null = null;
  private runnerSigner: PrivateKeySigner | null = null;

  /**
   * Initialize by generating two random keys
   */
  initialize(): Promise<void> {
    // Generate two independent keys
    this.userSigner = PrivateKeySigner.random();
    this.runnerSigner = PrivateKeySigner.random();
    return Promise.resolve();
  }

  /**
   * Get the user signer (for data operations)
   */
  getUserSigner(): PrivateKeySigner {
    if (!this.userSigner) {
      throw new Error('Web2 strategy not initialized. Call initialize() first.');
    }
    return this.userSigner;
  }

  /**
   * Get the runner signer (for compute operations)
   */
  getRunnerSigner(): PrivateKeySigner {
    if (!this.runnerSigner) {
      throw new Error('Web2 strategy not initialized. Call initialize() first.');
    }
    return this.runnerSigner;
  }

  /**
   * Get user address
   */
  getUserAddress(): string {
    const signer = this.getUserSigner();
    return signer.getAddress() as string;
  }

  /**
   * Get runner address
   */
  getRunnerAddress(): string {
    const signer = this.getRunnerSigner();
    return signer.getAddress() as string;
  }

  /**
   * Clean up (clear keys from memory)
   */
  cleanup(): Promise<void> {
    this.userSigner = null;
    this.runnerSigner = null;
    return Promise.resolve();
  }
}
