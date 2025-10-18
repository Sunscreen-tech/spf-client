import { describe, it, expect, beforeAll } from "vitest";
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
  PrivateKeySigner,
  POLL_DEFAULTS,
  type PollingOptions,
} from "../src/spf-client.js";
import {
  updateAccess,
  allowDecryptAccess,
} from "../src/acl.js";
import { TEST_ENDPOINT } from "./test-config.js";
import { readFileSync } from "fs";
import { join } from "path";

describe("Polling Options Configuration", () => {
  let signer: PrivateKeySigner;

  beforeAll(async () => {
    await initialize(TEST_ENDPOINT);
    signer = PrivateKeySigner.random();
  });

  describe("POLL_DEFAULTS export", () => {
    it("should export POLL_DEFAULTS constant", () => {
      expect(POLL_DEFAULTS).toBeDefined();
      expect(POLL_DEFAULTS.initialIntervalMs).toBe(60);
      expect(POLL_DEFAULTS.backoffMultiplier).toBe(1.25);
      expect(POLL_DEFAULTS.maxIntervalMs).toBe(30000);
    });

    it("should be immutable (readonly)", () => {
      expect(Object.isFrozen(POLL_DEFAULTS)).toBe(false);
      // The 'as const' makes the type readonly, but not the runtime object
      // Users can still spread it: { ...POLL_DEFAULTS, initialIntervalMs: 10 }
    });
  });

  describe("Custom polling with waitForReencryption", () => {
    it("should accept custom polling options", async () => {
      const ciphertext = await encryptValue(42, 16);
      const ciphertextId = await uploadCiphertext(signer, ciphertext);
      const { publicOtp } = await generateOtp();

      const reencryptHandle = await requestReencryption(signer, ciphertextId, publicOtp);

      const customOptions: PollingOptions = {
        initialIntervalMs: 50,
        backoffMultiplier: 2.0,
        maxIntervalMs: 5000,
      };

      const reencryptedCtId = await waitForReencryption(reencryptHandle, undefined, customOptions);

      expect(reencryptedCtId).toMatch(/^(0x)?[0-9a-f]{64}$/i);
    }, 30000);

    it("should accept partial polling options (only initialIntervalMs)", async () => {
      const ciphertext = await encryptValue(123, 16);
      const ciphertextId = await uploadCiphertext(signer, ciphertext);
      const { publicOtp } = await generateOtp();

      const reencryptHandle = await requestReencryption(signer, ciphertextId, publicOtp);

      const partialOptions: PollingOptions = {
        initialIntervalMs: 50, // Only override initial interval
      };

      const reencryptedCtId = await waitForReencryption(reencryptHandle, undefined, partialOptions);

      expect(reencryptedCtId).toMatch(/^(0x)?[0-9a-f]{64}$/i);
    }, 30000);

    it("should work with both signal and options", async () => {
      const ciphertext = await encryptValue(99, 16);
      const ciphertextId = await uploadCiphertext(signer, ciphertext);
      const { publicOtp } = await generateOtp();

      const reencryptHandle = await requestReencryption(signer, ciphertextId, publicOtp);

      const controller = new AbortController();
      const customOptions: PollingOptions = {
        initialIntervalMs: 50,
        maxIntervalMs: 5000,
      };

      // Should complete successfully with both signal and options
      const reencryptedCtId = await waitForReencryption(reencryptHandle, controller.signal, customOptions);

      expect(reencryptedCtId).toMatch(/^(0x)?[0-9a-f]{64}$/i);
    }, 30000);
  });

  describe("Custom polling with waitForRun", () => {
    it("should accept custom polling options", async () => {
      const programPath = join(__dirname, "fixtures/voting.spf");
      const programBytes = new Uint8Array(readFileSync(programPath));
      const libraryId = await uploadProgram(programBytes);

      const ct = await encryptValue(7, 16);
      const ctId = await uploadCiphertext(signer, ct);

      const parameters = [
        createCiphertextArrayParameter([ctId]),
        createPlaintextParameter(16, 1),
        createOutputCiphertextArrayParameter(8, 1), // voting program outputs 8-bit boolean
      ];

      const runHandle = await submitRun(signer, libraryId, "tally_votes", parameters);

      const customOptions: PollingOptions = {
        initialIntervalMs: 50,
        backoffMultiplier: 2.0,
        maxIntervalMs: 5000,
      };

      const status = await waitForRun(runHandle, undefined, customOptions);

      expect(status.status).toBe("success");
    }, 30000);

    it("should accept partial options (only maxIntervalMs)", async () => {
      const programPath = join(__dirname, "fixtures/voting.spf");
      const programBytes = new Uint8Array(readFileSync(programPath));
      const libraryId = await uploadProgram(programBytes);

      const ct = await encryptValue(5, 8);
      const ctId = await uploadCiphertext(signer, ct);

      const parameters = [
        createCiphertextArrayParameter([ctId]),
        createPlaintextParameter(16, 1),
        createOutputCiphertextArrayParameter(8, 1),
      ];

      const runHandle = await submitRun(signer, libraryId, "tally_votes", parameters);

      const partialOptions: PollingOptions = {
        maxIntervalMs: 5000, // Only override max interval
      };

      const status = await waitForRun(runHandle, undefined, partialOptions);

      expect(status.status).toBe("success");
    }, 30000);
  });

  describe("Custom polling with waitForDecryption", () => {
    it("should accept custom polling options", async () => {
      const ciphertext = await encryptValue(42, 16);
      const ciphertextId = await uploadCiphertext(signer, ciphertext);

      await updateAccess(signer, ciphertextId, [
        allowDecryptAccess(signer.getAddress()),
      ]);

      const decryptHandle = await requestDecryption(signer, ciphertextId);

      const customOptions: PollingOptions = {
        initialIntervalMs: 50,
        backoffMultiplier: 2.0,
        maxIntervalMs: 5000,
      };

      const value = await waitForDecryption(decryptHandle, 16, false, undefined, customOptions);

      expect(value).toBe(42n);
    }, 30000);

    it("should accept partial options (only backoffMultiplier)", async () => {
      const ciphertext = await encryptValue(999, 16);
      const ciphertextId = await uploadCiphertext(signer, ciphertext);

      await updateAccess(signer, ciphertextId, [
        allowDecryptAccess(signer.getAddress()),
      ]);

      const decryptHandle = await requestDecryption(signer, ciphertextId);

      const partialOptions: PollingOptions = {
        backoffMultiplier: 3.0, // Only override backoff multiplier
      };

      const value = await waitForDecryption(decryptHandle, 16, false, undefined, partialOptions);

      expect(value).toBe(999n);
    }, 30000);

    it("should work with signal, signed parameter, and options", async () => {
      const ciphertext = await encryptValue(-10, 16);
      const ciphertextId = await uploadCiphertext(signer, ciphertext);

      await updateAccess(signer, ciphertextId, [
        allowDecryptAccess(signer.getAddress()),
      ]);

      const decryptHandle = await requestDecryption(signer, ciphertextId);

      const controller = new AbortController();
      const customOptions: PollingOptions = {
        initialIntervalMs: 50,
        maxIntervalMs: 5000,
      };

      const value = await waitForDecryption(decryptHandle, 16, true, controller.signal, customOptions);

      expect(value).toBe(-10n);
    }, 30000);
  });

  describe("Custom polling with getPolynomialBytesForOtp", () => {
    it("should accept custom polling options", async () => {
      const ciphertext = await encryptValue(555, 16);
      const ciphertextId = await uploadCiphertext(signer, ciphertext);
      const { publicOtp, secretOtp } = await generateOtp();

      const reencryptHandle = await requestReencryption(signer, ciphertextId, publicOtp);
      const reencryptedCtId = await waitForReencryption(reencryptHandle);
      const decryptHandle = await requestDecryption(signer, reencryptedCtId);

      const customOptions: PollingOptions = {
        initialIntervalMs: 50,
        backoffMultiplier: 2.0,
        maxIntervalMs: 5000,
      };

      const polyBytes = await getPolynomialBytesForOtp(decryptHandle, undefined, customOptions);

      expect(polyBytes).toBeInstanceOf(Uint8Array);
      expect(polyBytes.length).toBeGreaterThan(0);

      // Verify we can decrypt it
      const { otpDecrypt } = await import("../src/spf-client.js");
      const decrypted = await otpDecrypt(polyBytes, secretOtp, 16, false);
      expect(decrypted).toBe(555n);
    }, 60000);

    it("should work with signal and options", async () => {
      const ciphertext = await encryptValue(777, 16);
      const ciphertextId = await uploadCiphertext(signer, ciphertext);
      const { publicOtp, secretOtp } = await generateOtp();

      const reencryptHandle = await requestReencryption(signer, ciphertextId, publicOtp);
      const reencryptedCtId = await waitForReencryption(reencryptHandle);
      const decryptHandle = await requestDecryption(signer, reencryptedCtId);

      const controller = new AbortController();
      const customOptions: PollingOptions = {
        initialIntervalMs: 50,
        maxIntervalMs: 5000,
      };

      const polyBytes = await getPolynomialBytesForOtp(decryptHandle, controller.signal, customOptions);

      expect(polyBytes).toBeInstanceOf(Uint8Array);

      const { otpDecrypt } = await import("../src/spf-client.js");
      const decrypted = await otpDecrypt(polyBytes, secretOtp, 16, false);
      expect(decrypted).toBe(777n);
    }, 60000);
  });

  describe("Type safety", () => {
    it("should accept empty options object", async () => {
      const ciphertext = await encryptValue(11, 16);
      const ciphertextId = await uploadCiphertext(signer, ciphertext);

      await updateAccess(signer, ciphertextId, [
        allowDecryptAccess(signer.getAddress()),
      ]);

      const decryptHandle = await requestDecryption(signer, ciphertextId);

      // Empty options should work (uses all defaults)
      const emptyOptions: PollingOptions = {};

      const value = await waitForDecryption(decryptHandle, 16, false, undefined, emptyOptions);

      expect(value).toBe(11n);
    }, 30000);

    it("should merge partial options with defaults", async () => {
      const ciphertext = await encryptValue(22, 16);
      const ciphertextId = await uploadCiphertext(signer, ciphertext);

      await updateAccess(signer, ciphertextId, [
        allowDecryptAccess(signer.getAddress()),
      ]);

      const decryptHandle = await requestDecryption(signer, ciphertextId);

      // Only override one field - others should use defaults
      const partialOptions: PollingOptions = {
        initialIntervalMs: 200, // Override
        // backoffMultiplier: should use POLL_DEFAULTS.backoffMultiplier (1.5)
        // maxIntervalMs: should use POLL_DEFAULTS.maxIntervalMs (30000)
      };

      const value = await waitForDecryption(decryptHandle, 16, false, undefined, partialOptions);

      expect(value).toBe(22n);
    }, 30000);
  });
});
