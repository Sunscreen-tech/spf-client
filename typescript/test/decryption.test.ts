import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import {
  initialize,
  uploadProgram,
  uploadCiphertext,
  submitRun,
  waitForRun,
  createCiphertextArrayParameter,
  createPlaintextParameter,
  createOutputCiphertextArrayParameter,
  deriveResultCiphertextId,
  requestDecryption,
  waitForDecryption,
  encryptValues,
  PrivateKeySigner,
} from "../src/spf-client.js";
import { TEST_ENDPOINT } from "./test-config.js";

describe("Decryption & Verification", () => {
  let wallet: PrivateKeySigner;
  let resultCiphertextId: string;
  let decryptedValue: bigint;

  beforeAll(async () => {
    // Initialize WASM and fetch public key from endpoint
    await initialize(TEST_ENDPOINT);

    // Generate test wallet dynamically
    wallet = PrivateKeySigner.random();

    // Upload voting program
    const programPath = join(__dirname, "fixtures/voting.spf");
    const programBytes = new Uint8Array(readFileSync(programPath));
    const libraryId = await uploadProgram(programBytes);

    // Upload 4 encrypted votes: [1, -1, 1, 1] => sum = 2 > 0 => approved
    const votes = [1, -1, 1, 1];
    const voteCiphertexts = await encryptValues(votes, 8);
    const voteCiphertextIds: string[] = [];

    for (const voteBytes of voteCiphertexts) {
      const ciphertextId = await uploadCiphertext(wallet, voteBytes);
      voteCiphertextIds.push(ciphertextId);
    }

    // Submit voting run
    const parameters = [
      createCiphertextArrayParameter(voteCiphertextIds),
      createPlaintextParameter(16, 4), // num_votes as uint16
      createOutputCiphertextArrayParameter(8, 1), // bool output
    ];

    const runHandle = await submitRun(wallet, libraryId, "tally_votes", parameters);
    const runStatus = await waitForRun(runHandle);

    console.log(`Run status: ${runStatus.status}`);
    if (runStatus.status !== "success") {
      throw new Error(`Run failed: ${JSON.stringify(runStatus.payload)}`);
    }

    // Derive result ciphertext ID
    resultCiphertextId = deriveResultCiphertextId(runHandle, 0);
    console.log(`Result ciphertext ID: ${resultCiphertextId}`);

    // Grant ourselves decrypt access to the result ciphertext
    const { updateAccess, allowDecryptAccess } = await import("../src/acl.js");
    await updateAccess(wallet, resultCiphertextId, [
      allowDecryptAccess(wallet.getAddress()),
    ]);
    console.log(`Granted decrypt access to ${wallet.getAddress()}`);
  }, 120000); // 2 minute timeout for beforeAll

  it("should request decryption of voting result", async () => {
    const decryptHandle = await requestDecryption(wallet, resultCiphertextId);

    expect(decryptHandle).toBeTruthy();
    expect(typeof decryptHandle).toBe("string");
    console.log(`Decryption handle: ${decryptHandle}`);
  });

  it("should wait for decryption to complete", async () => {
    const decryptHandle = await requestDecryption(wallet, resultCiphertextId);
    console.log("Waiting for decryption to complete...");

    decryptedValue = await waitForDecryption(decryptHandle, 8, false);

    expect(decryptedValue).toBeTruthy();
    console.log(`Decrypted value: ${decryptedValue}`);
  });

  it("should verify voting result is approved", async () => {
    const decryptHandle = await requestDecryption(wallet, resultCiphertextId);
    const result = await waitForDecryption(decryptHandle, 8, false);

    console.log(`\n=================================`);
    console.log(`Voting result`);
    console.log(`=================================`);
    console.log(`Votes: [1, -1, 1, 1]`);
    console.log(`Sum: 1 + (-1) + 1 + 1 = 2`);
    console.log(`Condition: sum > 0 = true`);
    console.log(`Decrypted result: ${result}`);
    console.log(`Verdict: ${result === 1n ? "approved" : "rejected"}`);
    console.log(`=================================\n`);

    expect(result).toBe(1n);
  });
});
