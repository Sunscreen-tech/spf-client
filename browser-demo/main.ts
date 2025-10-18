/**
 * Private FHE Voting Demo
 *
 * This demo showcases running an FHE voting program with two modes:
 * - Web2 Mode: Generate ephemeral keys in the browser (user + runner keys)
 * - Web3 Mode: Hybrid - MetaMask for user operations + generated key for runner
 *
 * Workflow:
 * 1. Initialize signer (Web2: generate keys, Web3: connect MetaMask + generate runner key)
 * 2. User casts a vote (approve or reject)
 * 3. Generate 8 random simulated votes (9 total votes - odd number prevents ties)
 * 4. Encrypt user's vote + 8 simulated votes separately
 * 5. Upload user's vote (user signs - MetaMask in Web3 mode)
 * 6. Upload 8 simulated votes (ephemeral signer - no MetaMask popup)
 * 7. Upload FHE voting program (no auth needed)
 * 8. Grant run access to user's vote (user signs - MetaMask in Web3 mode)
 * 9. Grant run access to 8 simulated votes (ephemeral signer - no MetaMask popup)
 * 10. Submit run (runner signs - generated key in Web3 mode)
 * 11. Wait for vote tallying
 * 12. Grant decrypt access to result (runner signs - generated key in Web3 mode)
 * 13. Request and wait for decryption (runner signs - generated key in Web3 mode)
 * 14. Display result: approved or rejected with vote counts
 *
 * Web3 mode popups (only 2 total):
 * - Upload user's vote ciphertext (MetaMask)
 * - Grant run access to user's vote ciphertext (MetaMask)
 * All simulated votes use ephemeral PrivateKeySigner (no popups)
 * All runner operations use PrivateKeySigner (no popups)
 */

import { initialize, clearWasmCache } from '@sunscreen/spf-client';
import { SignerManager } from './src/core/SignerManager.js';
import { WorkflowEngine } from './src/core/WorkflowEngine.js';
import type { SignerModeType, SignerStrategy } from './src/interfaces/SignerStrategy.js';
import { isSignerMode } from './src/utils/validation.js';
import { getErrorMessage } from './src/utils/errors.js';
import { WalletDetector } from './src/wallet/WalletDetector.js';
import type { WalletDetectionResult } from './src/wallet/WalletCapabilities.js';

// UI Elements
const endpointToggleContainer = document.querySelector('.endpoint-toggle') as HTMLDivElement;
const endpointToggle = document.getElementById('endpointToggle') as HTMLInputElement;
const endpointDisplay = document.getElementById('endpointDisplay') as HTMLSpanElement;
const modeSelectorSection = document.querySelector('[data-mode-selector]') as HTMLElement;
const modeRadios = document.querySelectorAll('input[name="mode"]') as NodeListOf<HTMLInputElement>;
const step1Section = document.getElementById('step1Section') as HTMLDivElement;
const step1Label = document.getElementById('step1Label') as HTMLSpanElement;
const initButton = document.getElementById('initButton') as HTMLButtonElement;
const voteRadios = document.querySelectorAll('input[name="vote"]') as NodeListOf<HTMLInputElement>;
const simulationModeRadios = document.querySelectorAll('input[name="simulationMode"]') as NodeListOf<HTMLInputElement>;
const runButton = document.getElementById('runButton') as HTMLButtonElement;
const statusLog = document.getElementById('statusLog') as HTMLDivElement;
const resultBox = document.getElementById('resultBox') as HTMLDivElement;
const resultValue = document.getElementById('resultValue') as HTMLDivElement;
const errorBox = document.getElementById('errorBox') as HTMLDivElement;

// State
let signerManager: SignerManager;
let workflowEngine: WorkflowEngine;
let isRunning = false;
let isTogglingEndpoint = false;
let currentEndpoint = 'https://spf.sunscreen.tech'; // Default to production (CORS now enabled)
let walletDetectionResult: WalletDetectionResult | null = null;
let keyboardShortcutHandler: ((e: KeyboardEvent) => void) | null = null;

/**
 * Add a status message to the log
 */
function addStatus(message: string, type: 'info' | 'success' | 'error' = 'info'): void {
  const entry = document.createElement('div');
  entry.className = `status-entry ${type}`;
  entry.textContent = message;

  statusLog.appendChild(entry);
  statusLog.scrollTop = statusLog.scrollHeight;

  // Also log to console for debugging
  if (type === 'error') {
    console.error(message);
  } else if (type === 'success') {
    console.log('✅', message);
  } else {
    console.log('▸', message);
  }
}

/**
 * Show error message
 */
function showError(message: string): void {
  errorBox.textContent = `Error: ${message}`;
  errorBox.classList.add('show');
  addStatus(message, 'error');
}

/**
 * Clear error message
 */
function clearError(): void {
  errorBox.classList.remove('show');
  errorBox.textContent = '';
}

/**
 * Set result box state
 */
function setResultState(state: 'pending' | 'processing' | 'approved' | 'rejected'): void {
  resultBox.classList.remove('pending', 'processing', 'approved', 'rejected');

  switch (state) {
    case 'pending':
      resultBox.classList.add('pending');
      resultValue.textContent = 'Not Running';
      break;
    case 'processing':
      resultBox.classList.add('processing');
      resultValue.textContent = 'Processing...';
      break;
    case 'approved':
      resultBox.classList.add('approved');
      resultValue.textContent = 'Approved';
      break;
    case 'rejected':
      resultBox.classList.add('rejected');
      resultValue.textContent = 'Rejected';
      break;
  }
}

/**
 * Get endpoint display text
 */
function getEndpointDisplayText(endpoint: string): string {
  if (endpoint === 'https://spf.sunscreen.tech') {
    return 'spf.sunscreen.tech (production)';
  }
  return 'localhost:8080 (local dev)';
}

/**
 * Get currently selected mode
 */
function getCurrentMode(): SignerModeType {
  const checkedRadio = Array.from(modeRadios).find(r => r.checked);
  const value = checkedRadio?.value || 'web2';

  if (!isSignerMode(value)) {
    throw new Error(`Invalid mode: ${value}`);
  }

  return value;
}

/**
 * Update UI based on selected mode (before initialization)
 */
function updateUIForMode(mode: SignerModeType): void {
  if (mode === 'web2') {
    step1Label.textContent = 'Initialize Keys';
    initButton.textContent = 'Generate Keys';
  } else {
    step1Label.textContent = 'Connect Wallet';
    initButton.textContent = 'Connect MetaMask';
  }

  // Show Step 1 section now that we know the correct text to display
  if (step1Section) {
    step1Section.style.visibility = 'visible';
  }

  // Reset button states
  initButton.disabled = false;
  voteRadios.forEach(radio => { (radio as HTMLInputElement).disabled = true; });
  simulationModeRadios.forEach(radio => { (radio as HTMLInputElement).disabled = true; });
  runButton.disabled = true;
}

/**
 * Update UI based on initialized strategy
 */
function updateUIForStrategy(strategy: SignerStrategy | null): void {
  if (!strategy) {
    // No strategy - reset to initial state
    initButton.disabled = false;
    initButton.textContent = getCurrentMode() === 'web2' ? 'Generate Keys' : 'Connect MetaMask';
    voteRadios.forEach(radio => { (radio as HTMLInputElement).disabled = true; });
    simulationModeRadios.forEach(radio => { (radio as HTMLInputElement).disabled = true; });
    runButton.disabled = true;
    return;
  }

  // Strategy initialized - show appropriate display and enable inputs
  if (strategy.mode === 'web2') {
    initButton.textContent = 'Keys Generated ✓';

    // Print addresses to status log
    addStatus(`User Address: ${strategy.getUserAddress()}`, 'success');
    addStatus(`Runner Address: ${strategy.getRunnerAddress()}`, 'success');
  } else {
    initButton.textContent = 'Connected ✓';

    // Print both addresses to status log (user from MetaMask, runner generated)
    addStatus(`User Address (MetaMask): ${strategy.getUserAddress()}`, 'success');
    addStatus(`Runner Address (Generated): ${strategy.getRunnerAddress()}`, 'success');
  }

  initButton.disabled = true;
  voteRadios.forEach(radio => { (radio as HTMLInputElement).disabled = false; });
  simulationModeRadios.forEach(radio => { (radio as HTMLInputElement).disabled = false; });
  runButton.disabled = false;
}

/**
 * Update UI based on wallet detection
 */
function updateUIForDetection(result: WalletDetectionResult): void {
  if (!modeSelectorSection) {
    console.warn('[updateUIForDetection] Mode selector section not found');
    return;
  }

  if (!result.showModeSelector) {
    // Hide mode selector completely
    modeSelectorSection.style.display = 'none';

    // Pre-select the recommended mode
    modeRadios.forEach((radio) => {
      if (radio.value === result.recommendedMode) {
        radio.checked = true;
      }
    });

    // Show info message
    if (result.isMobile && result.hasWeb3Wallet) {
      addStatus('Wallet app browser detected (auto-selecting Web3 mode)', 'success');
    } else if (result.isMobile) {
      addStatus('Mobile browser detected (Web3 wallets not available)', 'info');
    } else if (!result.hasWeb3Wallet) {
      addStatus('No Web3 wallet detected', 'info');
    }
  } else {
    // Show mode selector (desktop + wallet available)
    modeSelectorSection.style.display = 'block';

    // Pre-select recommended mode
    modeRadios.forEach((radio) => {
      if (radio.value === result.recommendedMode) {
        radio.checked = true;
      }
    });

    const walletCount = result.providers.length || 1;
    addStatus(`${walletCount} Web3 wallet(s) detected`, 'success');
  }

  // Update UI for the pre-selected mode
  updateUIForMode(result.recommendedMode);
}

/**
 * Handle mode change
 */
async function handleModeChange(): Promise<void> {
  const mode = getCurrentMode();

  // Clean up strategy but preserve listeners
  const currentStrategy = signerManager.getCurrentStrategy();
  if (currentStrategy) {
    try {
      await currentStrategy.cleanup();
    } catch (error) {
      console.warn('[handleModeChange] Cleanup failed:', error);
      // Continue anyway - mode change should proceed
    }
    // Note: We don't call signerManager.cleanup() because it would clear listeners
    // The next call to switchMode() will set the new strategy
  }

  // Reset UI for new mode
  updateUIForMode(mode);

  clearError();
  setResultState('pending');
  statusLog.innerHTML = '';
  addStatus(`Switched to ${mode === 'web2' ? 'Web2' : 'Web3'} mode`);
}

/**
 * Handle initialization button click
 */
async function handleInit(): Promise<void> {
  console.log('[DEBUG] handleInit called');
  try {
    clearError();
    setResultState('pending');
    statusLog.innerHTML = '';

    const mode = getCurrentMode();
    console.log('[DEBUG] Current mode:', mode);
    initButton.disabled = true;
    initButton.textContent = mode === 'web2' ? 'Generating...' : 'Connecting...';

    addStatus(`Initializing ${mode === 'web2' ? 'Web2' : 'Web3'} mode`);

    await signerManager.switchMode(mode);
    console.log('[DEBUG] Mode switched successfully');

    addStatus(`${mode === 'web2' ? 'Keys generated' : 'Connected to MetaMask'}`, 'success');
  } catch (error) {
    console.error('Initialization error:', error);
    showError(`Initialization failed: ${getErrorMessage(error)}`);
    initButton.disabled = false;
    initButton.textContent = getCurrentMode() === 'web2' ? 'Generate Keys' : 'Connect MetaMask';
  }
}

/**
 * Run the voting workflow
 */
async function runWorkflow(): Promise<void> {
  if (isRunning) return;

  try {
    isRunning = true;
    clearError();
    setResultState('pending');
    statusLog.innerHTML = '';
    runButton.disabled = true;
    runButton.textContent = 'Running...';

    // Get vote selection
    const checkedVote = Array.from(voteRadios).find(r => r.checked);
    if (!checkedVote) {
      throw new Error('Please select a vote');
    }
    const userVote = checkedVote.value === 'approve';

    // Get simulation mode selection
    const checkedMode = Array.from(simulationModeRadios).find(r => r.checked);
    const simulationMode = checkedMode?.value === 'tiebreaker' ? 'tiebreaker' : 'random';

    // Set processing state
    setResultState('processing');

    // Run voting workflow
    const result = await workflowEngine.runVotingWorkflow(userVote, simulationMode);

    // Update result box state
    setResultState(result.passed ? 'approved' : 'rejected');

    addStatus('Workflow completed successfully!', 'success');
  } catch (error) {
    showError(getErrorMessage(error));
    setResultState('pending');
  } finally {
    isRunning = false;
    runButton.disabled = false;
    runButton.textContent = 'Run Voting Program';
  }
}

/**
 * Handle endpoint toggle
 */
async function handleEndpointToggle(): Promise<void> {
  const isProduction = endpointToggle.checked;
  const newEndpoint = isProduction ? 'https://spf.sunscreen.tech' : 'http://localhost:8080';

  if (newEndpoint === currentEndpoint) {
    return;
  }

  // Guard against concurrent toggles
  if (isTogglingEndpoint) {
    addStatus('Endpoint switch already in progress', 'error');
    // Revert toggle to reflect actual state
    endpointToggle.checked = currentEndpoint === 'https://spf.sunscreen.tech';
    return;
  }

  try {
    isTogglingEndpoint = true;
    clearError();
    setResultState('pending');
    statusLog.innerHTML = '';

    addStatus(`Switching endpoint to ${getEndpointDisplayText(newEndpoint)}`);
    endpointToggle.disabled = true;

    // Clean up current state but preserve listeners
    const currentStrategy = signerManager?.getCurrentStrategy();
    if (currentStrategy) {
      await currentStrategy.cleanup();
    }

    // Clear WASM cache before reinitializing with different endpoint
    clearWasmCache();

    // Reinitialize with new endpoint
    currentEndpoint = newEndpoint;
    endpointDisplay.textContent = getEndpointDisplayText(newEndpoint);

    addStatus('Reinitializing WASM module');
    await initialize(currentEndpoint);
    addStatus('WASM reinitialized with new endpoint', 'success');

    // Recreate workflow engine
    workflowEngine = new WorkflowEngine(signerManager, addStatus);

    // Reset UI
    updateUIForMode(getCurrentMode());

    addStatus(`Switched to ${getEndpointDisplayText(newEndpoint)}`, 'success');
  } catch (error) {
    showError(`Failed to switch endpoint: ${getErrorMessage(error)}`);

    // Revert toggle on error
    endpointToggle.checked = currentEndpoint === 'https://spf.sunscreen.tech';
    endpointDisplay.textContent = getEndpointDisplayText(currentEndpoint);
  } finally {
    isTogglingEndpoint = false;
    endpointToggle.disabled = false;
  }
}

/**
 * Detect if localhost SPF server is running
 */
async function detectEndpoint(): Promise<string> {
  try {
    // Try localhost - will fail immediately if not running
    const response = await fetch('http://localhost:8080/public_keys');

    if (response.ok) {
      console.log('[DEBUG] Localhost SPF server detected');
      return 'http://localhost:8080';
    }
  } catch {
    // Localhost not available (network error, connection refused, etc.)
    console.log('[DEBUG] Localhost SPF server not available, using production');
  }

  return 'https://spf.sunscreen.tech'; // Production with CORS enabled
}

/**
 * Initialize the application
 */
async function init(): Promise<void> {
  try {
    console.log('[DEBUG] Starting initialization...');

    // Step 1: Detect wallet capabilities FIRST (before WASM init)
    addStatus('Detecting wallet capabilities...');
    const detector = new WalletDetector();

    try {
      walletDetectionResult = await detector.detect();
      console.log('[DEBUG] Detection result:', walletDetectionResult);
    } catch (error) {
      // Fallback to safe defaults if detection fails
      console.warn('[DEBUG] Wallet detection failed, using safe defaults:', error);
      walletDetectionResult = {
        isMobile: false,
        hasWeb3Wallet: false,
        providers: [],
        hasLegacyProvider: false,
        recommendedMode: 'web2',
        showModeSelector: true,
        detectionMethod: 'timeout',
      };
      addStatus('Wallet detection failed, defaulting to Web2 mode', 'info');
    }

    // Step 2: Update UI based on detection
    updateUIForDetection(walletDetectionResult);

    // Step 3: Auto-detect endpoint
    const detectedEndpoint = await detectEndpoint();
    currentEndpoint = detectedEndpoint;

    console.log('[DEBUG] Detected endpoint:', detectedEndpoint);
    console.log('[DEBUG] Current endpoint:', currentEndpoint);

    // Update toggle to match detected endpoint
    endpointToggle.checked = currentEndpoint === 'https://spf.sunscreen.tech';
    endpointDisplay.textContent = getEndpointDisplayText(currentEndpoint);

    console.log('[DEBUG] Trying endpoint:', currentEndpoint);
    console.log('[DEBUG] Toggle checked:', endpointToggle.checked);
    addStatus(`Connecting to ${getEndpointDisplayText(currentEndpoint)}...`);

    // Try to initialize with detected endpoint, fallback to production if it fails
    try {
      await initialize(currentEndpoint);
      console.log('[DEBUG] WASM initialized with', currentEndpoint);
      addStatus(`Connected to ${getEndpointDisplayText(currentEndpoint)}`, 'success');
    } catch (error) {
      // If localhost fails, fall back to production
      if (currentEndpoint !== 'https://spf.sunscreen.tech') {
        console.log('[DEBUG] Localhost failed, falling back to production');
        addStatus('Localhost unavailable, falling back to production', 'info');

        // Clear WASM cache before reinitializing with different endpoint
        clearWasmCache();

        currentEndpoint = 'https://spf.sunscreen.tech';
        endpointDisplay.textContent = getEndpointDisplayText(currentEndpoint);
        endpointToggle.checked = true;

        addStatus(`Connecting to ${getEndpointDisplayText(currentEndpoint)}...`);
        await initialize(currentEndpoint);
        console.log('[DEBUG] WASM initialized with production');
        addStatus(`Connected to ${getEndpointDisplayText(currentEndpoint)}`, 'success');
      } else {
        throw error; // Re-throw if production also fails
      }
    }

    addStatus('Ready to run voting demo');

    // Create managers
    signerManager = new SignerManager();
    workflowEngine = new WorkflowEngine(signerManager, addStatus);
    console.log('[DEBUG] Managers created');

    // Subscribe to strategy changes
    signerManager.subscribe((strategy) => {
      updateUIForStrategy(strategy);
    });

    // Wire up event listeners
    endpointToggle.addEventListener('change', () => void handleEndpointToggle());
    modeRadios.forEach((radio) => {
      radio.addEventListener('change', () => void handleModeChange());
    });
    initButton.addEventListener('click', () => void handleInit());
    runButton.addEventListener('click', () => void runWorkflow());
    console.log('[DEBUG] Event listeners attached');

    // Keyboard shortcut to toggle endpoint selector (Ctrl+Shift+E)
    keyboardShortcutHandler = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.shiftKey && e.key === 'E') {
        e.preventDefault();
        endpointToggleContainer.classList.toggle('visible');
        if (endpointToggleContainer.classList.contains('visible')) {
          addStatus('Developer mode: Endpoint toggle shown (Ctrl+Shift+E to hide)', 'info');
        }
      }
    };

    document.addEventListener('keydown', keyboardShortcutHandler);

    // Mode is pre-selected by detection, but user must manually click the init button
    // This prevents automatic key generation and gives users control

    // Cleanup on page unload
    window.addEventListener('beforeunload', cleanup);
  } catch (error) {
    showError(`Failed to initialize: ${getErrorMessage(error)}`);
  }
}

/**
 * Cleanup resources on page unload
 */
function cleanup(): void {
  // Remove keyboard shortcut listener
  if (keyboardShortcutHandler) {
    document.removeEventListener('keydown', keyboardShortcutHandler);
    keyboardShortcutHandler = null;
  }

  // Cleanup signer manager
  if (signerManager) {
    signerManager.cleanup().catch((error) => {
      console.warn('[cleanup] Signer manager cleanup failed:', error);
    });
  }
}

// Start the application
void init();
