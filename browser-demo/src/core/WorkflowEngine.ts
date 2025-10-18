import {
  encryptValue,
  uploadCiphertext,
  uploadProgram,
  submitRun,
  checkRunStatus,
  requestDecryption,
  waitForDecryption,
  deriveResultCiphertextId,
  createCiphertextArrayParameter,
  createPlaintextParameter,
  createOutputCiphertextArrayParameter,
  toNumber,
  PrivateKeySigner,
  asProgramName,
  asAddress,
  updateAccess,
  allowRunAccess,
  type LibraryId,
  type CiphertextId,
  type RunHandle,
  type DecryptHandle,
} from '@sunscreen/spf-client';
import type { SignerManager } from './SignerManager.js';
import { getErrorMessage } from '../utils/errors.js';

/**
 * Status callback type
 */
type StatusCallback = (message: string, type?: 'info' | 'success' | 'error') => void;

/**
 * WorkflowEngine - executes FHE workflows in a mode-agnostic way
 *
 * This engine doesn't know or care whether it's using Web2 or Web3 signers.
 * It simply requests the appropriate signers from the SignerManager and
 * executes the workflow.
 */
export class WorkflowEngine {
  private votingProgramLibraryId: LibraryId | null = null;

  constructor(
    private readonly signerManager: SignerManager,
    private readonly statusCallback: StatusCallback,
  ) {}

  /**
   * Load and upload the voting program (done once)
   */
  private async ensureVotingProgramLoaded(): Promise<LibraryId> {
    if (this.votingProgramLibraryId) {
      this.statusCallback('Using cached voting program ID', 'success');
      return this.votingProgramLibraryId;
    }

    this.statusCallback('Loading voting program from fixtures');

    let response: Response;
    try {
      response = await fetch('/fixtures/voting');
    } catch (error: unknown) {
      throw new Error(
        `Network error loading voting program: ${getErrorMessage(error)}`
      );
    }

    if (!response.ok) {
      throw new Error(`Failed to load voting program: ${response.status} ${response.statusText}`);
    }

    const programBytes = new Uint8Array(await response.arrayBuffer());
    this.statusCallback(`Loaded voting program (${programBytes.length} bytes)`, 'success');

    this.statusCallback(`Uploading voting program (${programBytes.length} bytes)`);

    // Upload voting program (with retries)
    let uploadAttempts = 0;
    const maxAttempts = 2;
    while (uploadAttempts < maxAttempts) {
      try {
        this.votingProgramLibraryId = (await uploadProgram(programBytes)) as LibraryId;
        break;
      } catch (error: unknown) {
        uploadAttempts++;
        if (uploadAttempts < maxAttempts) {
          this.statusCallback(`Upload voting program failed (attempt ${uploadAttempts}/${maxAttempts}), retrying`);
        } else {
          this.statusCallback(`Upload voting program failed after ${maxAttempts} attempts`, 'error');
          throw error;
        }
      }
    }

    this.statusCallback(`Voting program uploaded: ${this.votingProgramLibraryId}`, 'success');
    return this.votingProgramLibraryId;
  }

  /**
   * Retry helper for network operations
   */
  private async retryOperation<T>(
    operation: () => Promise<T>,
    operationName: string,
    maxRetries: number = 3,
  ): Promise<T> {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error: unknown) {
        if (attempt < maxRetries) {
          this.statusCallback(`${operationName} failed (attempt ${attempt}/${maxRetries}), retrying`);
        } else {
          this.statusCallback(`${operationName} failed after ${maxRetries} attempts`, 'error');
          throw error;
        }
      }
    }
    throw new Error(`${operationName} failed after ${maxRetries} attempts`);
  }

  /**
   * Run the complete FHE voting workflow
   *
   * @param userVote - User's vote (true = approve, false = reject)
   * @param simulationMode - 'random' for random votes, 'tiebreaker' for 4-4 split
   * @returns Object with voting result and vote counts
   */
  async runVotingWorkflow(userVote: boolean, simulationMode: 'random' | 'tiebreaker' = 'random'): Promise<{ passed: boolean; approveCount: number; rejectCount: number }> {
    // Get current strategy
    const strategy = this.signerManager.getCurrentStrategy();
    if (!strategy) {
      throw new Error('No signer strategy initialized');
    }

    const userSigner = strategy.getUserSigner();
    const runnerSigner = strategy.getRunnerSigner();
    const runnerAddress = strategy.getRunnerAddress();

    // Create ephemeral signer for simulated votes (reduces MetaMask popups in Web3 mode)
    const simulatedVotesSigner = PrivateKeySigner.random();

    this.statusCallback(`Starting voting workflow with your vote: ${userVote ? 'APPROVE' : 'REJECT'}`);

    // Step 1: Generate 8 votes based on simulation mode
    let otherVotes: boolean[];

    if (simulationMode === 'tiebreaker') {
      // Tie breaker mode: 4 approve, 4 reject
      otherVotes = [true, true, true, true, false, false, false, false];
      this.statusCallback('Tie breaker mode: 4 approve, 4 reject (you decide!)');
    } else {
      // Random mode: Use crypto.getRandomValues()
      const randomVotes = new Uint8Array(8);
      crypto.getRandomValues(randomVotes);
      otherVotes = Array.from(randomVotes).map(byte => byte % 2 === 1);
      this.statusCallback('Random mode: 8 random voters');
    }

    // Combine user vote with random votes
    const allVotes = [userVote, ...otherVotes];

    // Count votes for display
    const approveCount = allVotes.filter(v => v).length;
    const rejectCount = allVotes.length - approveCount;

    // Step 2: Convert votes to int8_t format (+1 for approve, -1 for reject)
    const voteValues = allVotes.map(vote => vote ? 1 : -1);

    // Step 3: Encrypt user's vote and simulated votes separately
    this.statusCallback('Encrypting your vote');
    const userVoteValue = voteValues[0];
    if (userVoteValue === undefined) {
      throw new Error('Missing user vote');
    }
    const userCiphertext = await encryptValue(userVoteValue, 8);
    this.statusCallback('Encrypted your vote', 'success');

    this.statusCallback('Encrypting 8 simulated votes');
    const simulatedCiphertexts: Uint8Array[] = [];
    for (let i = 1; i < voteValues.length; i++) {
      const voteValue = voteValues[i];
      if (voteValue === undefined) {
        throw new Error(`Missing vote at index ${i}`);
      }
      const ct = await encryptValue(voteValue, 8);
      simulatedCiphertexts.push(ct);
    }
    this.statusCallback(`Encrypted 8 simulated votes`, 'success');

    // Step 4: Upload user's vote (user signs - MetaMask in Web3 mode)
    this.statusCallback('Uploading your vote');
    const userCtId = (await this.retryOperation<CiphertextId>(
      () => uploadCiphertext(userSigner, userCiphertext),
      'Upload your vote',
    )) as CiphertextId;
    this.statusCallback(`Uploaded your vote: ${userCtId}`, 'success');

    // Step 5: Upload simulated votes (ephemeral signer - no MetaMask popup)
    this.statusCallback('Uploading 8 simulated votes');
    const simulatedCtIds: CiphertextId[] = [];
    for (let i = 0; i < simulatedCiphertexts.length; i++) {
      const ct = simulatedCiphertexts[i];
      if (ct === undefined) {
        throw new Error(`Missing simulated ciphertext at index ${i}`);
      }
      const ctId = (await this.retryOperation<CiphertextId>(
        () => uploadCiphertext(simulatedVotesSigner, ct),
        `Upload simulated vote ${i + 1}`,
      )) as CiphertextId;
      simulatedCtIds.push(ctId);
    }
    this.statusCallback(`Uploaded 8 simulated votes`, 'success');

    // Step 6: Load/upload voting program
    const libraryId = (await this.ensureVotingProgramLoaded()) as LibraryId;

    // Step 7: Grant run access to user's vote (user signs - MetaMask in Web3 mode)
    this.statusCallback(`Granting run access to your vote`);
    const userCtIdWithAcl = (await updateAccess(
      userSigner,
      userCtId,
      [allowRunAccess(asAddress(runnerAddress), libraryId, asProgramName('tally_votes'))],
    )) as CiphertextId;
    this.statusCallback(`ACL applied to your vote`, 'success');

    // Step 8: Grant run access to simulated votes (ephemeral signer - no MetaMask popup)
    this.statusCallback(`Granting run access to 8 simulated votes`);
    const simulatedCtIdsWithAcl: CiphertextId[] = [];
    for (let i = 0; i < simulatedCtIds.length; i++) {
      const ctId: CiphertextId | undefined = simulatedCtIds[i];
      if (ctId === undefined) {
        throw new Error(`Missing simulated ciphertext ID at index ${i}`);
      }
      const ctIdWithAcl = (await updateAccess(
        simulatedVotesSigner,
        ctId,
        [allowRunAccess(asAddress(runnerAddress), libraryId, asProgramName('tally_votes'))],
      )) as CiphertextId;
      simulatedCtIdsWithAcl.push(ctIdWithAcl);
    }
    this.statusCallback(`ACL applied to 8 simulated votes`, 'success');

    // Combine all ciphertext IDs with ACL (user vote first, then simulated)
    const ciphertextIdsWithAcl: CiphertextId[] = [userCtIdWithAcl, ...(simulatedCtIdsWithAcl as CiphertextId[])];

    // Step 9: Submit run (runner signs - no MetaMask popup)
    this.statusCallback('Submitting FHE voting program');
    const parametersWithAuth = [
      createCiphertextArrayParameter(ciphertextIdsWithAcl),
      createPlaintextParameter(16, 9), // uint16_t num_votes = 9
      createOutputCiphertextArrayParameter(8, 1), // bool output
    ];

    const runHandle = (await submitRun(
      runnerSigner,
      libraryId,
      asProgramName('tally_votes'),
      parametersWithAuth,
    )) as RunHandle;
    this.statusCallback(`Run submitted: ${runHandle}`, 'success');

    // Step 10: Wait for completion
    this.statusCallback('Waiting for vote tallying');

    let runStatus;
    while (true) {
      // Check status
      runStatus = await checkRunStatus(runHandle);

      // Break if completed
      if (runStatus.status === 'success' || runStatus.status === 'failed') {
        break;
      }

      // No polling delay - continuous checking for immediate feedback
    }

    if (runStatus.status !== 'success') {
      const errorDetails = runStatus.payload ? JSON.stringify(runStatus.payload, null, 2) : 'No details';
      throw new Error(`Run failed with status '${runStatus.status}': ${errorDetails}`);
    }
    this.statusCallback('Vote tallying complete!', 'success');

    // Step 11: Get result ciphertext ID
    const resultId = deriveResultCiphertextId(runHandle, 0) as CiphertextId;
    this.statusCallback(`Result ciphertext ID: ${resultId}`);

    // Step 12: Request decryption (runner signs - no MetaMask popup)
    this.statusCallback('Requesting threshold decryption');
    const decryptHandle = (await requestDecryption(runnerSigner, resultId)) as DecryptHandle;
    this.statusCallback(`Decryption requested: ${decryptHandle}`, 'success');

    // Step 13: Wait for decryption
    this.statusCallback('Waiting for threshold decryption');
    const resultBigInt = await waitForDecryption(
      decryptHandle,
      8,
      false, // unsigned (bool)
      undefined, // no abort signal
      undefined, // use default polling options (no explicit intervals)
    );
    this.statusCallback('Decryption complete!', 'success');

    // Convert bigint to number (0 or 1)
    const resultNum = toNumber(resultBigInt);
    const passed = resultNum === 1;

    return { passed, approveCount, rejectCount };
  }
}