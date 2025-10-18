import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import {
  initialize,
  encryptValue,
  uploadCiphertext,
  uploadProgram,
  checkCiphertextAccess,
  PrivateKeySigner,
  asProgramName,
  asAddress,
} from "../src/spf-client.js";
import {
  allowAdmin,
  allowDecrypt,
  allowRun,
} from "../src/acl.js";
import { TEST_ENDPOINT } from "./test-config.js";

describe("Simple ACL API", () => {
  let wallet1: PrivateKeySigner;
  let wallet2: PrivateKeySigner;
  let wallet3: PrivateKeySigner;

  beforeAll(async () => {
    await initialize(TEST_ENDPOINT);

    wallet1 = PrivateKeySigner.random();
    wallet2 = PrivateKeySigner.random();
    wallet3 = PrivateKeySigner.random();
  });

  describe("allowAdmin", () => {
    it("should grant admin access to specified address", async () => {
      const ciphertext = await encryptValue(42n, 16);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      console.log(`\n1. Uploaded ciphertext: ${ctId}`);
      console.log(`2. Granting admin access to wallet2: ${wallet2.getAddress()}`);

      const newCtId = await allowAdmin(wallet1, ctId, asAddress(wallet2.getAddress()));

      console.log("3. Checking admin access for wallet2...");
      const hasAccess = await checkCiphertextAccess(newCtId, {
        type: "admin",
        address: wallet2.getAddress(),
      });

      console.log(`   Result: ${hasAccess}`);
      expect(hasAccess).toBe(true);
    }, 60000);

    it("should grant admin access with chainId parameter", async () => {
      const ciphertext = await encryptValue(100n, 16);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      const newCtId = await allowAdmin(wallet1, ctId, asAddress(wallet2.getAddress()), 1);

      const hasAccess = await checkCiphertextAccess(newCtId, {
        type: "admin",
        address: wallet2.getAddress(),
        chainId: 1,
      });

      expect(hasAccess).toBe(true);
    }, 60000);

    it("should return new ciphertext ID", async () => {
      const ciphertext = await encryptValue(123n, 16);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      const newCtId = await allowAdmin(wallet1, ctId, asAddress(wallet2.getAddress()));

      expect(newCtId).toBeTruthy();
      expect(newCtId).not.toBe(ctId);
    }, 60000);
  });

  describe("allowDecrypt", () => {
    it("should grant decrypt access to specified address", async () => {
      const ciphertext = await encryptValue(456n, 32);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      console.log(`\n1. Uploaded ciphertext: ${ctId}`);
      console.log(`2. Granting decrypt access to wallet2: ${wallet2.getAddress()}`);

      const newCtId = await allowDecrypt(wallet1, ctId, asAddress(wallet2.getAddress()));

      console.log("3. Checking decrypt access for wallet2...");
      const hasAccess = await checkCiphertextAccess(newCtId, {
        type: "decrypt",
        address: wallet2.getAddress(),
      });

      console.log(`   Result: ${hasAccess}`);
      expect(hasAccess).toBe(true);
    }, 60000);

    it("should grant decrypt access with chainId parameter", async () => {
      const ciphertext = await encryptValue(789n, 32);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      const newCtId = await allowDecrypt(wallet1, ctId, asAddress(wallet2.getAddress()), 1);

      const hasAccess = await checkCiphertextAccess(newCtId, {
        type: "decrypt",
        address: wallet2.getAddress(),
        chainId: 1,
      });

      expect(hasAccess).toBe(true);
    }, 60000);

    it("should return new ciphertext ID", async () => {
      const ciphertext = await encryptValue(999n, 16);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      const newCtId = await allowDecrypt(wallet1, ctId, asAddress(wallet2.getAddress()));

      expect(newCtId).toBeTruthy();
      expect(newCtId).not.toBe(ctId);
    }, 60000);
  });

  describe("allowRun", () => {
    it("should grant run access to specified address", async () => {
      const ciphertext = await encryptValue(42n, 8);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      const programPath = join(__dirname, "fixtures/voting.spf");
      const programBytes = new Uint8Array(readFileSync(programPath));
      const libraryId = await uploadProgram(programBytes);

      console.log(`\n1. Uploaded ciphertext: ${ctId}`);
      console.log(`2. Uploaded program: ${libraryId}`);
      console.log(`3. Granting run access to wallet2 for tally_votes program`);

      const newCtId = await allowRun(
        wallet1,
        ctId,
        asAddress(wallet2.getAddress()),
        libraryId,
        asProgramName("tally_votes")
      );

      console.log("4. Checking run access for wallet2...");
      const hasAccess = await checkCiphertextAccess(newCtId, {
        type: "run",
        address: wallet2.getAddress(),
        libraryHash: libraryId,
        entryPoint: asProgramName("tally_votes"),
      });

      console.log(`   Result: ${hasAccess}`);
      expect(hasAccess).toBe(true);
    }, 60000);

    it("should grant run access with chainId parameter", async () => {
      const ciphertext = await encryptValue(100n, 8);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      const programPath = join(__dirname, "fixtures/voting.spf");
      const programBytes = new Uint8Array(readFileSync(programPath));
      const libraryId = await uploadProgram(programBytes);

      const newCtId = await allowRun(
        wallet1,
        ctId,
        asAddress(wallet2.getAddress()),
        libraryId,
        asProgramName("tally_votes"),
        1
      );

      const hasAccess = await checkCiphertextAccess(newCtId, {
        type: "run",
        address: wallet2.getAddress(),
        chainId: 1,
        libraryHash: libraryId,
        entryPoint: asProgramName("tally_votes"),
      });

      expect(hasAccess).toBe(true);
    }, 60000);

    it("should return new ciphertext ID", async () => {
      const ciphertext = await encryptValue(55n, 8);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      const programPath = join(__dirname, "fixtures/voting.spf");
      const programBytes = new Uint8Array(readFileSync(programPath));
      const libraryId = await uploadProgram(programBytes);

      const newCtId = await allowRun(
        wallet1,
        ctId,
        asAddress(wallet2.getAddress()),
        libraryId,
        asProgramName("tally_votes")
      );

      expect(newCtId).toBeTruthy();
      expect(newCtId).not.toBe(ctId);
    }, 60000);
  });

  describe("Comparison: Simple vs Advanced API", () => {
    it("should produce same result as advanced API for single grant", async () => {
      const ciphertext = await encryptValue(42n, 16);

      // Using simple API
      const ctId1 = await uploadCiphertext(wallet1, ciphertext);
      const result1 = await allowDecrypt(wallet1, ctId1, asAddress(wallet2.getAddress()));

      // Using advanced API
      const { updateAccess, allowDecryptAccess } = await import("../src/acl.js");
      const ctId2 = await uploadCiphertext(wallet1, ciphertext);
      const result2 = await updateAccess(wallet1, ctId2, [
        allowDecryptAccess(asAddress(wallet2.getAddress())),
      ]);

      // Both should grant access successfully
      const hasAccess1 = await checkCiphertextAccess(result1, {
        type: "decrypt",
        address: wallet2.getAddress(),
      });

      const hasAccess2 = await checkCiphertextAccess(result2, {
        type: "decrypt",
        address: wallet2.getAddress(),
      });

      expect(hasAccess1).toBe(true);
      expect(hasAccess2).toBe(true);
    }, 60000);

    it("should allow chaining multiple simple API calls", async () => {
      const ciphertext = await encryptValue(42n, 16);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      // Chain: grant admin to wallet2, then decrypt to wallet3
      const ctId2 = await allowAdmin(wallet1, ctId, asAddress(wallet2.getAddress()));
      const ctId3 = await allowDecrypt(wallet2, ctId2, asAddress(wallet3.getAddress()));

      // Verify wallet2 has admin
      const wallet2HasAdmin = await checkCiphertextAccess(ctId3, {
        type: "admin",
        address: wallet2.getAddress(),
      });

      // Verify wallet3 has decrypt
      const wallet3HasDecrypt = await checkCiphertextAccess(ctId3, {
        type: "decrypt",
        address: wallet3.getAddress(),
      });

      expect(wallet2HasAdmin).toBe(true);
      expect(wallet3HasDecrypt).toBe(true);
    }, 60000);
  });

  describe("Edge Cases", () => {
    it("should handle chainId boundary values", async () => {
      const ciphertext = await encryptValue(42n, 16);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      // chainId = 0 (default)
      const newCtId1 = await allowAdmin(
        wallet1,
        ctId,
        asAddress(wallet2.getAddress()),
        0
      );
      expect(newCtId1).toBeTruthy();

      // Large chainId
      const newCtId2 = await allowAdmin(
        wallet1,
        newCtId1,
        asAddress(wallet3.getAddress()),
        Number.MAX_SAFE_INTEGER
      );
      expect(newCtId2).toBeTruthy();
    }, 120000);

    it("should return different ciphertext ID after each grant", async () => {
      const ciphertext = await encryptValue(42n, 16);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      const ctId2 = await allowAdmin(wallet1, ctId, asAddress(wallet2.getAddress()));
      const ctId3 = await allowAdmin(wallet1, ctId2, asAddress(wallet3.getAddress()));

      expect(ctId).not.toBe(ctId2);
      expect(ctId2).not.toBe(ctId3);
      expect(ctId).not.toBe(ctId3);
    }, 120000);
  });
});
