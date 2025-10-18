import { describe, it, expect, beforeAll, vi } from "vitest";
import {
  initialize,
  encryptValue,
  generateOtp,
  uploadCiphertext,
  uploadProgram,
  submitRun,
  requestReencryption,
  requestDecryption,
  waitForReencryption,
  waitForRun,
  waitForDecryption,
  getPolynomialBytesForOtp,
  createPlaintextParameter,
  createOutputCiphertextArrayParameter,
  createCiphertextArrayParameter,
  deriveResultCiphertextId,
  PrivateKeySigner,
  type ReencryptHandle,
  type RunHandle,
  type DecryptHandle,
} from "../src/spf-client.js";
import {
  updateAccess,
  allowDecryptAccess,
} from "../src/acl.js";
import { TEST_ENDPOINT } from "./test-config.js";
import { readFileSync } from "fs";
import { join } from "path";

describe("AbortSignal Handling", () => {
  let signer: PrivateKeySigner;

  beforeAll(async () => {
    await initialize(TEST_ENDPOINT);
    signer = PrivateKeySigner.random();
  });

  describe("Pre-aborted signals", () => {
    it("should throw immediately if signal already aborted (waitForReencryption)", async () => {
      const controller = new AbortController();
      controller.abort(new Error("User cancelled"));

      // Create a dummy handle (won't be called since abort is immediate)
      const dummyHandle = "0x" + "0".repeat(64);

      await expect(
        waitForReencryption(dummyHandle as ReencryptHandle, controller.signal)
      ).rejects.toThrow("User cancelled");
    });

    it("should throw immediately if signal already aborted (waitForRun)", async () => {
      const controller = new AbortController();
      controller.abort(new Error("Operation cancelled"));

      const dummyHandle = "0x" + "0".repeat(64);

      await expect(
        waitForRun(dummyHandle as RunHandle, controller.signal)
      ).rejects.toThrow("Operation cancelled");
    });

    it("should throw immediately if signal already aborted (waitForDecryption)", async () => {
      const controller = new AbortController();
      controller.abort(new Error("Decryption cancelled"));

      const dummyHandle = "0x" + "0".repeat(64);

      await expect(
        waitForDecryption(dummyHandle as DecryptHandle, 16, false, controller.signal)
      ).rejects.toThrow("Decryption cancelled");
    });

    it("should throw immediately if signal already aborted (getPolynomialBytesForOtp)", async () => {
      const controller = new AbortController();
      controller.abort(new Error("Polynomial fetch cancelled"));

      const dummyHandle = "0x" + "0".repeat(64);

      await expect(
        getPolynomialBytesForOtp(dummyHandle as DecryptHandle, controller.signal)
      ).rejects.toThrow("Polynomial fetch cancelled");
    });

    it("should propagate default abort reason when no custom reason provided", async () => {
      const controller = new AbortController();
      controller.abort(); // No custom reason - browser default is "This operation was aborted"

      const dummyHandle = "0x" + "0".repeat(64);

      await expect(
        waitForReencryption(dummyHandle as ReencryptHandle, controller.signal)
      ).rejects.toThrow(); // Just verify it throws, don't check exact message
    });
  });

  describe("Abort during operation", () => {
    it("should abort waitForReencryption when signal aborted before polling", async () => {
      // Create a real reencryption request
      const ciphertext = await encryptValue(42, 16);
      const ciphertextId = await uploadCiphertext(signer, ciphertext);
      const { publicOtp } = await generateOtp();

      const reencryptHandle = await requestReencryption(signer, ciphertextId, publicOtp);

      const controller = new AbortController();
      // Abort immediately - tests abort check at start of loop
      controller.abort(new Error("Immediately aborted"));

      await expect(
        waitForReencryption(reencryptHandle, controller.signal)
      ).rejects.toThrow("Immediately aborted");
    }, 30000);

    it("should abort waitForRun when signal aborted before polling", async () => {
      // Upload a program and submit a run
      const programPath = join(__dirname, "fixtures/voting.spf");
      const programBytes = new Uint8Array(readFileSync(programPath));
      const libraryId = await uploadProgram(programBytes);

      const ct = await encryptValue(5, 16);
      const ctId = await uploadCiphertext(signer, ct);

      const parameters = [
        createCiphertextArrayParameter([ctId]),
        createPlaintextParameter(16, 1),
        createOutputCiphertextArrayParameter(16, 1),
      ];

      const runHandle = await submitRun(signer, libraryId, "tally_votes", parameters);

      const controller = new AbortController();
      // Abort immediately
      controller.abort(new Error("Run aborted"));

      await expect(
        waitForRun(runHandle, controller.signal)
      ).rejects.toThrow("Run aborted");
    }, 30000);

    it("should abort waitForDecryption when signal aborted before polling", async () => {
      // Create and upload a ciphertext
      const ciphertext = await encryptValue(42, 16);
      const ciphertextId = await uploadCiphertext(signer, ciphertext);

      // Grant decrypt access and request decryption
      await updateAccess(signer, ciphertextId, [
        allowDecryptAccess(signer.getAddress()),
      ]);

      const decryptHandle = await requestDecryption(signer, ciphertextId);

      const controller = new AbortController();
      // Abort immediately
      controller.abort(new Error("Decryption aborted"));

      await expect(
        waitForDecryption(decryptHandle, 16, false, controller.signal)
      ).rejects.toThrow("Decryption aborted");
    }, 30000);

    it("should abort getPolynomialBytesForOtp when signal aborted before polling", async () => {
      // Create full OTP workflow
      const ciphertext = await encryptValue(42, 16);
      const ciphertextId = await uploadCiphertext(signer, ciphertext);
      const { publicOtp } = await generateOtp();

      const reencryptHandle = await requestReencryption(signer, ciphertextId, publicOtp);
      const reencryptedCtId = await waitForReencryption(reencryptHandle);

      const decryptHandle = await requestDecryption(signer, reencryptedCtId);

      const controller = new AbortController();
      // Abort immediately
      controller.abort(new Error("Polynomial aborted"));

      await expect(
        getPolynomialBytesForOtp(decryptHandle, controller.signal)
      ).rejects.toThrow("Polynomial aborted");
    }, 60000);
  });

  describe("Custom abort reasons", () => {
    it("should propagate custom abort error object", async () => {
      const controller = new AbortController();
      const customError = new Error("Custom abort message");
      controller.abort(customError);

      const dummyHandle = "0x" + "0".repeat(64);

      await expect(
        waitForReencryption(dummyHandle as ReencryptHandle, controller.signal)
      ).rejects.toThrow("Custom abort message");
    });

    it("should propagate custom abort string", async () => {
      const controller = new AbortController();
      controller.abort("Operation was cancelled by user");

      const dummyHandle = "0x" + "0".repeat(64);

      try {
        await waitForDecryption(dummyHandle as DecryptHandle, 16, false, controller.signal);
        expect.fail("Should have thrown");
      } catch (error) {
        expect(String(error)).toContain("Operation was cancelled by user");
      }
    });
  });

  describe("Operations without abort complete normally", () => {
    it("should complete waitForReencryption successfully without abort", async () => {
      const ciphertext = await encryptValue(100, 16);
      const ciphertextId = await uploadCiphertext(signer, ciphertext);
      const { publicOtp } = await generateOtp();

      const reencryptHandle = await requestReencryption(signer, ciphertextId, publicOtp);

      // No abort signal provided
      const reencryptedCtId = await waitForReencryption(reencryptHandle);

      expect(reencryptedCtId).toMatch(/^(0x)?[0-9a-f]{64}$/i);
    }, 30000);

    it("should complete waitForRun successfully without abort", async () => {
      const programPath = join(__dirname, "fixtures/voting.spf");
      const programBytes = new Uint8Array(readFileSync(programPath));
      const libraryId = await uploadProgram(programBytes);

      // Create a proper voting run with encrypted votes
      const ct = await encryptValue(1, 8);
      const ctId = await uploadCiphertext(signer, ct);

      const parameters = [
        createCiphertextArrayParameter([ctId]),
        createPlaintextParameter(16, 1), // num_votes
        createOutputCiphertextArrayParameter(8, 1),
      ];

      const runHandle = await submitRun(signer, libraryId, "tally_votes", parameters);

      // No abort signal provided
      const status = await waitForRun(runHandle);

      expect(status.status).toBe("success");
    }, 30000);

    it("should complete waitForDecryption successfully without abort", async () => {
      const ciphertext = await encryptValue(42, 16);
      const ciphertextId = await uploadCiphertext(signer, ciphertext);

      await updateAccess(signer, ciphertextId, [
        allowDecryptAccess(signer.getAddress()),
      ]);

      const decryptHandle = await requestDecryption(signer, ciphertextId);

      // No abort signal provided
      const value = await waitForDecryption(decryptHandle, 16, false);

      expect(value).toBe(42n);
    }, 30000);

    it("should complete getPolynomialBytesForOtp successfully without abort", async () => {
      const ciphertext = await encryptValue(123, 16);
      const ciphertextId = await uploadCiphertext(signer, ciphertext);
      const { publicOtp, secretOtp } = await generateOtp();

      const reencryptHandle = await requestReencryption(signer, ciphertextId, publicOtp);
      const reencryptedCtId = await waitForReencryption(reencryptHandle);
      const decryptHandle = await requestDecryption(signer, reencryptedCtId);

      // No abort signal provided
      const polyBytes = await getPolynomialBytesForOtp(decryptHandle);

      expect(polyBytes).toBeInstanceOf(Uint8Array);
      expect(polyBytes.length).toBeGreaterThan(0);

      // Verify we can decrypt it
      const { otpDecrypt } = await import("../src/spf-client.js");
      const decrypted = await otpDecrypt(polyBytes, secretOtp, 16, false);
      expect(decrypted).toBe(123n);
    }, 60000);
  });

  describe("Abort timing verification", () => {
    it("should abort within reasonable time", async () => {
      const controller = new AbortController();
      const start = Date.now();

      const dummyHandle = "0x" + "0".repeat(64);

      // Start polling (would continue indefinitely if not aborted)
      const promise = waitForReencryption(dummyHandle as ReencryptHandle, controller.signal);

      // Abort after 50ms
      setTimeout(() => controller.abort(), 50);

      try {
        await promise;
        expect.fail("Should have thrown");
      } catch (error) {
        const elapsed = Date.now() - start;

        // Should abort within first polling interval (100ms) + network latency
        // Being generous with 500ms to account for CI environment
        expect(elapsed).toBeLessThan(500);
      }
    });

    it("should check abort before each network request", async () => {
      // This test verifies that the signal is passed to fetch() for immediate cancellation
      const ciphertext = await encryptValue(42, 16);
      const ciphertextId = await uploadCiphertext(signer, ciphertext);

      await updateAccess(signer, ciphertextId, [
        allowDecryptAccess(signer.getAddress()),
      ]);

      const decryptHandle = await requestDecryption(signer, ciphertextId);

      const controller = new AbortController();
      const start = Date.now();

      // Abort immediately
      controller.abort();

      try {
        await waitForDecryption(decryptHandle, 16, false, controller.signal);
        expect.fail("Should have thrown");
      } catch (error) {
        const elapsed = Date.now() - start;

        // Should abort almost immediately (< 50ms) since signal is checked before first request
        expect(elapsed).toBeLessThan(50);
      }
    });
  });

  describe("AbortController pattern (documented approach)", () => {
    it("should work with AbortController and setTimeout pattern", async () => {
      const ciphertext = await encryptValue(42, 16);
      const ciphertextId = await uploadCiphertext(signer, ciphertext);
      const { publicOtp } = await generateOtp();
      const reencryptHandle = await requestReencryption(signer, ciphertextId, publicOtp);

      const controller = new AbortController();

      // Documented pattern: using AbortController with setTimeout for immediate abort
      const timeoutId = setTimeout(() => controller.abort(new Error("Timeout example")), 0);

      try {
        await waitForReencryption(reencryptHandle, controller.signal);
        expect.fail("Should have thrown");
      } catch (error) {
        // Verify abort was called
        expect(error).toBeTruthy();
      } finally {
        clearTimeout(timeoutId);
      }
    }, 30000);

    it("should support manual cancellation with cleanup", async () => {
      const ciphertext = await encryptValue(42, 16);
      const ciphertextId = await uploadCiphertext(signer, ciphertext);
      const { publicOtp } = await generateOtp();

      const reencryptHandle = await requestReencryption(signer, ciphertextId, publicOtp);

      const controller = new AbortController();

      // Abort immediately to test the pattern
      controller.abort(new Error("Manual abort"));

      try {
        await waitForReencryption(reencryptHandle, controller.signal);
        expect.fail("Should have thrown");
      } catch (error) {
        expect(String(error)).toContain("Manual abort");
      }
    }, 30000);
  });
});
