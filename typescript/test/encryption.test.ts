import { describe, it, expect, beforeAll } from "vitest";
import {
  initialize,
  encryptValue,
  encryptValues,
  generateOtp,
} from "../src/spf-client.js";
import { TEST_ENDPOINT } from "./test-config.js";

describe("Encryption & OTP Operations", () => {
  beforeAll(async () => {
    // Initialize WASM and fetch public key from local endpoint
    await initialize(TEST_ENDPOINT);
  });

  describe("encryptValue - unsigned", () => {
    it("should encrypt 8-bit unsigned value", async () => {
      const ct = await encryptValue(42, 8);

      expect(ct).toBeInstanceOf(Uint8Array);
      expect(ct.length).toBeGreaterThan(0);
      console.log(`8-bit ciphertext: ${ct.length} bytes`);
    });

    it("should encrypt 16-bit unsigned value", async () => {
      const ct = await encryptValue(1000, 16);

      expect(ct).toBeInstanceOf(Uint8Array);
      expect(ct.length).toBeGreaterThan(0);
    });

    it("should encrypt 32-bit unsigned value", async () => {
      const ct = await encryptValue(100000, 32);

      expect(ct).toBeInstanceOf(Uint8Array);
      expect(ct.length).toBeGreaterThan(0);
    });

    it("should reject values exceeding bit width", async () => {
      await expect(encryptValue(256, 8)).rejects.toThrow(
        "exceeds maximum",
      );
      await expect(encryptValue(65536, 16)).rejects.toThrow(
        "exceeds maximum",
      );
    });

    it("should produce different ciphertexts for same value", async () => {
      const ct1 = await encryptValue(42, 16);
      const ct2 = await encryptValue(42, 16);

      // FHE is probabilistic - same plaintext encrypts to different ciphertexts
      expect(ct1).not.toEqual(ct2);
    });
  });

  describe("encryptValue - signed", () => {
    it("should auto-detect signed from negative value", async () => {
      const ct = await encryptValue(-1, 16);

      expect(ct).toBeInstanceOf(Uint8Array);
      expect(ct.length).toBeGreaterThan(0);
      console.log(`Signed value encrypted: ${ct.length} bytes`);
    });

    it("should encrypt positive value (auto-detects unsigned)", async () => {
      const ct = await encryptValue(42, 16);

      expect(ct).toBeInstanceOf(Uint8Array);
      expect(ct.length).toBeGreaterThan(0);
    });

    it("should respect signed range limits", async () => {
      // 8-bit signed: -128 to 127
      await expect(encryptValue(-129, 8)).rejects.toThrow(
        "out of range",
      );
      await expect(encryptValue(-128, 8)).resolves.toBeInstanceOf(Uint8Array);

      // 16-bit signed: -32768 to 32767
      await expect(encryptValue(-32769, 16)).rejects.toThrow(
        "out of range",
      );
      await expect(encryptValue(-32768, 16)).resolves.toBeInstanceOf(Uint8Array);
    });

    it("should encrypt boundary values correctly", async () => {
      // 16-bit signed boundaries
      const ctMin = await encryptValue(-32768, 16);
      const ctMax = await encryptValue(32767, 16);

      expect(ctMin).toBeInstanceOf(Uint8Array);
      expect(ctMax).toBeInstanceOf(Uint8Array);
      console.log("Signed boundary values encrypted");
    });
  });

  describe("encryptValues", () => {
    it("should encrypt multiple unsigned values", async () => {
      const values = [1, 2, 3, 4, 5];
      const cts = await encryptValues(values, 16);

      expect(cts).toHaveLength(5);
      cts.forEach((ct) => {
        expect(ct).toBeInstanceOf(Uint8Array);
        expect(ct.length).toBeGreaterThan(0);
      });
    });

    it("should encrypt multiple signed values", async () => {
      const values = [-1, 0, 1, -10, 10];
      const cts = await encryptValues(values, 16);

      expect(cts).toHaveLength(5);
      cts.forEach((ct) => {
        expect(ct).toBeInstanceOf(Uint8Array);
        expect(ct.length).toBeGreaterThan(0);
      });
      console.log("Multiple signed values encrypted");
    });

    it("should handle empty array", async () => {
      const cts = await encryptValues([], 16);
      expect(cts).toHaveLength(0);
    });
  });

  describe("generateOtp", () => {
    it("should generate OTP keypair", async () => {
      const { publicOtp, secretOtp } = await generateOtp();

      expect(publicOtp).toBeInstanceOf(Uint8Array);
      expect(secretOtp).toBeInstanceOf(Uint8Array);

      expect(publicOtp.length).toBeGreaterThan(0);
      expect(secretOtp.length).toBeGreaterThan(0);

      console.log(
        `OTP generated: public=${publicOtp.length}B, secret=${secretOtp.length}B`,
      );
    });

    it("should generate different OTP keypairs each time", async () => {
      const otp1 = await generateOtp();
      const otp2 = await generateOtp();

      expect(otp1.publicOtp).not.toEqual(otp2.publicOtp);
      expect(otp1.secretOtp).not.toEqual(otp2.secretOtp);
    });
  });
});
