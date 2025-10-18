import { describe, it, expect, beforeAll } from "vitest";
import {
  initialize,
  encryptValue,
  generateOtp,
  uploadCiphertext,
  requestReencryption,
  waitForReencryption,
  requestDecryption,
  getPolynomialBytesForOtp,
  otpDecrypt,
  PrivateKeySigner,
  type BitWidth,
} from "../src/spf-client.js";
import { TEST_ENDPOINT } from "./test-config.js";

describe("OTP Re-encryption Workflow", () => {
  let signer: PrivateKeySigner;

  beforeAll(async () => {
    // Initialize WASM and fetch public key
    await initialize(TEST_ENDPOINT);

    // Create random test signer
    signer = PrivateKeySigner.random();
  });

  it("should complete full OTP re-encryption workflow for unsigned value", async () => {
    const bitWidth: BitWidth = 16;
    const originalValue = 42;

    // Step 1: Encrypt the original value
    const ciphertext = await encryptValue(originalValue, bitWidth);
    expect(ciphertext).toBeInstanceOf(Uint8Array);

    // Step 2: Upload ciphertext to SPF
    const ciphertextId = await uploadCiphertext(signer, ciphertext);
    expect(ciphertextId).toMatch(/^0x[0-9a-f]{64}$/i);

    // Step 3: Generate OTP keypair
    const { publicOtp, secretOtp } = await generateOtp();
    expect(publicOtp).toBeInstanceOf(Uint8Array);
    expect(secretOtp).toBeInstanceOf(Uint8Array);

    // Step 4: Request re-encryption with public OTP
    const reencryptHandle = await requestReencryption(
      signer,
      ciphertextId,
      publicOtp,
    );
    expect(reencryptHandle).toBeTruthy();

    // Step 5: Wait for re-encryption to complete
    const reencryptedCtId = await waitForReencryption(reencryptHandle);
    expect(reencryptedCtId).toMatch(/^(0x)?[0-9a-f]{64}$/i);

    // Step 6: Request threshold decryption of reencrypted ciphertext
    const decryptHandle = await requestDecryption(signer, reencryptedCtId);
    expect(decryptHandle).toBeTruthy();

    // Step 7: Get OTP-encrypted polynomial bytes (NOT parsed plaintext)
    const otpEncryptedPoly = await getPolynomialBytesForOtp(decryptHandle);
    expect(otpEncryptedPoly).toBeInstanceOf(Uint8Array);
    expect(otpEncryptedPoly.length).toBeGreaterThan(0);

    // Step 8: Decrypt locally with secret OTP
    const decryptedValue = await otpDecrypt(
      otpEncryptedPoly,
      secretOtp,
      bitWidth,
      false,
    );
    expect(decryptedValue).toBe(BigInt(originalValue));

    console.log(
      `OTP re-encryption successful: ${originalValue} -> ${decryptedValue}`,
    );
  }, 60000); // 60 second timeout for full workflow

  it("should complete full OTP re-encryption workflow for signed value", async () => {
    const bitWidth: BitWidth = 16;
    const originalValue = -1;

    // Step 1: Encrypt the original value
    const ciphertext = await encryptValue(originalValue, bitWidth);
    expect(ciphertext).toBeInstanceOf(Uint8Array);

    // Step 2: Upload ciphertext to SPF
    const ciphertextId = await uploadCiphertext(signer, ciphertext);
    expect(ciphertextId).toMatch(/^0x[0-9a-f]{64}$/i);

    // Step 3: Generate OTP keypair
    const { publicOtp, secretOtp } = await generateOtp();

    // Step 4-5: Request and wait for re-encryption
    const reencryptHandle = await requestReencryption(
      signer,
      ciphertextId,
      publicOtp,
    );
    const reencryptedCtId = await waitForReencryption(reencryptHandle);

    // Step 6-7: Request decryption and get OTP-encrypted polynomial bytes
    const decryptHandle = await requestDecryption(signer, reencryptedCtId);
    const otpEncryptedPoly = await getPolynomialBytesForOtp(decryptHandle);

    // Step 8: Decrypt locally with secret OTP (signed=true)
    const decryptedValue = await otpDecrypt(
      otpEncryptedPoly,
      secretOtp,
      bitWidth,
      true,
    );
    expect(decryptedValue).toBe(BigInt(originalValue));

    console.log(
      `Signed OTP re-encryption successful: ${originalValue} -> ${decryptedValue}`,
    );
  }, 60000);

  it("should handle multiple OTP decryptions with different keypairs", async () => {
    const bitWidth: BitWidth = 16;
    const value1 = 100;
    const value2 = 200;

    // Encrypt two values
    const ct1 = await encryptValue(value1, bitWidth);
    const ct2 = await encryptValue(value2, bitWidth);

    // Upload both
    const ctId1 = await uploadCiphertext(signer, ct1);
    const ctId2 = await uploadCiphertext(signer, ct2);

    // Generate two different OTP keypairs
    const otp1 = await generateOtp();
    const otp2 = await generateOtp();

    // Re-encrypt both with their respective OTPs
    const reencryptHandle1 = await requestReencryption(signer, ctId1, otp1.publicOtp);
    const reencryptHandle2 = await requestReencryption(signer, ctId2, otp2.publicOtp);

    const reencryptedCtId1 = await waitForReencryption(reencryptHandle1);
    const reencryptedCtId2 = await waitForReencryption(reencryptHandle2);

    // Request threshold decryption for both
    const decryptHandle1 = await requestDecryption(signer, reencryptedCtId1);
    const decryptHandle2 = await requestDecryption(signer, reencryptedCtId2);

    // Get OTP-encrypted polynomials
    const poly1 = await getPolynomialBytesForOtp(decryptHandle1);
    const poly2 = await getPolynomialBytesForOtp(decryptHandle2);

    // Decrypt with respective secret OTPs
    const decrypted1 = await otpDecrypt(poly1, otp1.secretOtp, bitWidth, false);
    const decrypted2 = await otpDecrypt(poly2, otp2.secretOtp, bitWidth, false);

    expect(decrypted1).toBe(BigInt(value1));
    expect(decrypted2).toBe(BigInt(value2));

    // Verify that using wrong OTP produces incorrect result (not the original values)
    // Note: OTP decryption with wrong key doesn't throw - it produces garbage
    const wrongDecrypt1 = await otpDecrypt(poly1, otp2.secretOtp, bitWidth, false);
    expect(wrongDecrypt1).not.toBe(BigInt(value1));

    console.log("Multiple OTP decryptions successful");
  }, 120000); // 2 minute timeout for multiple operations
});
