import type { SignerStrategy, SignerModeType } from '../interfaces/SignerStrategy.js';
import { Web2SignerStrategy } from '../strategies/Web2SignerStrategy.js';
import { Web3SignerStrategy } from '../strategies/Web3SignerStrategy.js';

/**
 * Type for strategy change listeners
 */
type StrategyListener = (strategy: SignerStrategy | null) => void;

/**
 * SignerManager - manages signer strategies with observable pattern
 *
 * Responsibilities:
 * - Create appropriate strategy based on mode
 * - Manage current active strategy
 * - Notify listeners when strategy changes
 * - Handle cleanup when switching modes
 */
export class SignerManager {
  private currentStrategy: SignerStrategy | null = null;
  private listeners: Set<StrategyListener> = new Set();

  /**
   * Subscribe to strategy changes
   *
   * @param listener - Callback to invoke when strategy changes
   * @returns Unsubscribe function
   */
  subscribe(listener: StrategyListener): () => void {
    this.listeners.add(listener);

    // Return unsubscribe function
    return () => {
      this.listeners.delete(listener);
    };
  }

  /**
   * Switch to a new signer mode
   *
   * @param mode - The mode to switch to ('web2' or 'web3')
   */
  async switchMode(mode: SignerModeType): Promise<void> {
    // Clean up current strategy if exists
    if (this.currentStrategy) {
      await this.currentStrategy.cleanup();
      this.currentStrategy = null;
      this.notifyListeners();
    }

    // Create new strategy
    const strategy = this.createStrategy(mode);

    // Initialize the strategy
    await strategy.initialize();

    // Set as current and notify
    this.currentStrategy = strategy;
    this.notifyListeners();
  }

  /**
   * Auto-initialize based on wallet detection
   * Convenience method for automatic mode selection
   *
   * @param mode - Detected recommended mode
   */
  async autoInitialize(mode: SignerModeType): Promise<void> {
    await this.switchMode(mode);
  }

  /**
   * Get the current strategy
   *
   * @returns Current strategy or null if none active
   */
  getCurrentStrategy(): SignerStrategy | null {
    return this.currentStrategy;
  }

  /**
   * Create a strategy instance for the given mode
   *
   * @param mode - The mode to create strategy for
   * @returns New strategy instance (not initialized)
   */
  private createStrategy(mode: SignerModeType): SignerStrategy {
    switch (mode) {
      case 'web2':
        return new Web2SignerStrategy();
      case 'web3':
        return new Web3SignerStrategy();
      default:
        throw new Error(`Unknown signer mode: ${mode}`);
    }
  }

  /**
   * Notify all listeners of strategy change
   */
  private notifyListeners(): void {
    this.listeners.forEach(listener => {
      listener(this.currentStrategy);
    });
  }

  /**
   * Clean up all resources
   */
  async cleanup(): Promise<void> {
    if (this.currentStrategy) {
      await this.currentStrategy.cleanup();
      this.currentStrategy = null;
      this.notifyListeners();
    }
    this.listeners.clear();
  }
}
