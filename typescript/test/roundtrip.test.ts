import { describe, it, expect, beforeAll } from "vitest";
import {
  initialize,
  encryptValue,
  uploadCiphertext,
  requestDecryption,
  waitForDecryption,
  PrivateKeySigner,
} from "../src/spf-client.js";
import {
  updateAccess,
  allowDecryptAccess,
} from "../src/acl.js";
import { TEST_ENDPOINT } from "./test-config.js";

describe("Threshold Decryption Round-Trip", () => {
  let wallet: PrivateKeySigner;

  beforeAll(async () => {
    // Initialize WASM and fetch public key from local endpoint
    await initialize(TEST_ENDPOINT);

    // Generate test wallet dynamically
    wallet = PrivateKeySigner.random();
  });

  it("should complete threshold decryption for positive value", async () => {
    const originalValue = 42n;

    console.log(`\n1. Encrypting value: ${originalValue}`);
    const ciphertext = await encryptValue(originalValue, 16);

    console.log("2. Uploading ciphertext...");
    const ctId = await uploadCiphertext(wallet, ciphertext);
    console.log(`   Ciphertext ID: ${ctId}`);

    console.log("3. Granting decrypt access...");
    await updateAccess(wallet, ctId, [allowDecryptAccess(wallet.getAddress())]);

    console.log("4. Requesting threshold decryption...");
    const decryptHandle = await requestDecryption(wallet, ctId);
    console.log(`   Decrypt handle: ${decryptHandle}`);

    console.log("5. Waiting for threshold decryption...");
    const result = await waitForDecryption(decryptHandle, 16, false);

    console.log(`Decryption complete: ${originalValue} → ${result}`);
    expect(result).toBe(originalValue);
  }, 90000);

  it("should complete threshold decryption for negative value", async () => {
    const originalValue = -42n;

    const ciphertext = await encryptValue(originalValue, 16);
    const ctId = await uploadCiphertext(wallet, ciphertext);
    await updateAccess(wallet, ctId, [allowDecryptAccess(wallet.getAddress())]);

    const decryptHandle = await requestDecryption(wallet, ctId);
    const result = await waitForDecryption(decryptHandle, 16, true);

    console.log(`Signed decryption: ${originalValue} → ${result}`);
    expect(result).toBe(originalValue);
  }, 90000);
});
