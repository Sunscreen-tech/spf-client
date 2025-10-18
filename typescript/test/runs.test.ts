import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import {
  initialize,
  uploadProgram,
  uploadCiphertext,
  submitRun,
  checkRunStatus,
  waitForRun,
  createCiphertextArrayParameter,
  createPlaintextParameter,
  createOutputCiphertextArrayParameter,
  deriveResultCiphertextId,
  encryptValues,
  PrivateKeySigner,
} from "../src/spf-client.js";
import { TEST_ENDPOINT } from "./test-config.js";

describe("Run Operations (Voting Example)", () => {
  let wallet: PrivateKeySigner;
  let libraryId: string;
  let voteCiphertextIds: string[];
  let runHandle: string;
  let resultCiphertextId: string;

  beforeAll(async () => {
    // Initialize WASM and fetch public key
    await initialize(TEST_ENDPOINT);
  });

  it("should load test wallet", () => {
    // Generate test wallet dynamically
    wallet = PrivateKeySigner.random();

    expect(wallet.getAddress()).toBeTruthy();
    console.log(`Test wallet address: ${wallet.getAddress()}`);
  });

  it("should upload voting program", async () => {
    const programPath = join(__dirname, "fixtures/voting.spf");
    const programBytes = new Uint8Array(readFileSync(programPath));

    libraryId = await uploadProgram(programBytes);

    expect(libraryId).toMatch(/^0x[0-9a-f]{64}$/);
    console.log(`Library ID: ${libraryId}`);
  });

  it("should encrypt and upload votes", async () => {
    // Encrypt 4 votes: [1, -1, 1, 1] => sum = 2 > 0 => approved
    const voteValues = [1, -1, 1, 1];

    console.log("Encrypting votes...");
    const ciphertexts = await encryptValues(voteValues, 16);

    voteCiphertextIds = [];

    for (let i = 0; i < ciphertexts.length; i++) {
      const ciphertextId = await uploadCiphertext(wallet, ciphertexts[i]);
      voteCiphertextIds.push(ciphertextId);
      console.log(`Uploaded vote ${voteValues[i]}: ${ciphertextId}`);
    }

    expect(voteCiphertextIds.length).toBe(4);
    console.log(`Expected result: 1 + (-1) + 1 + 1 = 2 > 0 => approved`);
  });

  it("should submit voting run with 4 encrypted votes", async () => {
    const parameters = [
      // Parameter 0: Array of 4 encrypted votes
      createCiphertextArrayParameter(voteCiphertextIds),
      // Parameter 1: Number of votes (uint16_t)
      createPlaintextParameter(16, 4),
      // Parameter 2: Output - didTheIssuePass (bool, single value)
      createOutputCiphertextArrayParameter(8, 1),
    ];

    console.log(`Submitting run with 4 encrypted votes...`);

    runHandle = await submitRun(wallet, libraryId, "tally_votes", parameters);

    expect(runHandle).toMatch(/^0x[0-9a-f]{64}$/);
    console.log(`Run handle: ${runHandle}`);
  });

  it("should check run status immediately", async () => {
    const status = await checkRunStatus(runHandle);

    expect(status).toHaveProperty("status");
    expect(["in_progress", "success", "failed"]).toContain(status.status);
    console.log(`Initial status: ${status.status}`);
  });

  it("should wait for run to complete", async () => {
    console.log("Waiting for run to complete...");

    const result = await waitForRun(runHandle);

    expect(result.status).toBe("success");
    console.log(`Run completed with status: ${result.status}`);
    if (result.payload) {
      console.log(`Gas usage: ${result.payload.gas_usage}`);
    }
  });

  it("should derive result ciphertext ID", () => {
    // Result ciphertext ID = keccak256(runHandle || outputIndex)
    // Output index 0 for the first (and only) output
    resultCiphertextId = deriveResultCiphertextId(runHandle, 0);

    expect(resultCiphertextId).toMatch(/^0x[0-9a-f]{64}$/);
    console.log(`Result ciphertext ID: ${resultCiphertextId}`);
  });

  it("should verify run completed successfully", async () => {
    const status = await checkRunStatus(runHandle);

    expect(status.status).toBe("success");
    expect(status.payload).toHaveProperty("gas_usage");
    expect(status.payload.gas_usage).toBeGreaterThan(0);
    console.log(`Run successful with gas usage: ${status.payload.gas_usage}`);
  });
});
