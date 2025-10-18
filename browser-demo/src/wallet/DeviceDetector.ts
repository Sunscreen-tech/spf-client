/**
 * Device Detection Utilities
 *
 * Detects device type (mobile vs desktop) and wallet app browser context
 */

/**
 * Detect if running on mobile device
 * Uses multiple heuristics for reliability
 *
 * @returns true if mobile device detected
 */
export function isMobileDevice(): boolean {
  // Check 1: User agent (most reliable)
  const userAgent = navigator.userAgent.toLowerCase();
  const mobileKeywords = [
    'android',
    'webos',
    'iphone',
    'ipad',
    'ipod',
    'blackberry',
    'windows phone',
  ];
  const hasMobileUA = mobileKeywords.some((keyword) => userAgent.includes(keyword));

  // Check 2: Touch support (can be misleading on modern laptops)
  const hasTouchSupport = 'ontouchstart' in window || navigator.maxTouchPoints > 0;

  // Check 3: Screen width (fallback)
  const isSmallScreen = window.innerWidth <= 768;

  // Combine heuristics (prefer UA over touch)
  return hasMobileUA || (hasTouchSupport && isSmallScreen);
}

/**
 * Detect if running in any wallet app's in-app browser
 * Works with MetaMask, Trust Wallet, Coinbase Wallet, Rainbow, etc.
 *
 * This is determined by:
 * 1. Being on a mobile device
 * 2. Having window.ethereum injected
 *
 * @returns true if in wallet app browser
 */
export function isWalletAppBrowser(): boolean {
  // Must be mobile + have ethereum provider
  // All major wallet apps inject window.ethereum in their in-app browsers
  return isMobileDevice() && typeof window !== 'undefined' && !!window.ethereum;
}
