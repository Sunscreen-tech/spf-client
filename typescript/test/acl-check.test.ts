import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import {
  initialize,
  encryptValue,
  uploadCiphertext,
  uploadProgram,
  checkCiphertextAccess,
  getCiphertextAccessSignature,
  PrivateKeySigner,
  asProgramName,
} from "../src/spf-client.js";
import {
  updateAccess,
  addAdminAccess,
  allowDecryptAccess,
  allowRunAccess,
} from "../src/acl.js";
import { TEST_ENDPOINT } from "./test-config.js";

describe("ACL Check Endpoint", () => {
  let wallet1: PrivateKeySigner;
  let wallet2: PrivateKeySigner;
  let wallet3: PrivateKeySigner;

  beforeAll(async () => {
    await initialize(TEST_ENDPOINT);

    wallet1 = PrivateKeySigner.random();
    wallet2 = PrivateKeySigner.random();
    wallet3 = PrivateKeySigner.random();
  });

  describe("Admin Access", () => {
    it("should grant admin access and verify with checkCiphertextAccess", async () => {
      const ciphertext = await encryptValue(42n, 16);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      console.log(`\n1. Uploaded ciphertext: ${ctId}`);
      console.log(
        `2. Granting admin access to wallet2: ${wallet2.getAddress()}`,
      );

      const ctId2 = await updateAccess(wallet1, ctId, [
        addAdminAccess(wallet2.getAddress()),
      ]);

      console.log("3. Checking admin access for wallet2...");
      const hasAdminAccess = await checkCiphertextAccess(ctId2, {
        type: "admin",
        address: wallet2.getAddress(),
      });

      console.log(`   Result: ${hasAdminAccess}`);
      expect(hasAdminAccess).toBe(true);
    }, 60000);

    it("should grant admin access and get access signature", async () => {
      const ciphertext = await encryptValue(100n, 16);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      const ctId2 = await updateAccess(wallet1, ctId, [
        addAdminAccess(wallet2.getAddress()),
      ]);

      console.log("Requesting admin access signature for wallet2...");
      const aclResponse = await getCiphertextAccessSignature(ctId2, {
        type: "admin",
        address: wallet2.getAddress(),
      });

      console.log(`   Signature: ${aclResponse.signature}`);
      console.log(`   Ciphertext ID: ${aclResponse.message.ciphertextId}`);

      expect(aclResponse.signature).toBeTruthy();
      expect(aclResponse.message.ciphertextId).toBe(ctId2);
    }, 60000);

    it("should deny admin access to non-admin address", async () => {
      const ciphertext = await encryptValue(42n, 16);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      const ctId2 = await updateAccess(wallet1, ctId, [
        addAdminAccess(wallet2.getAddress()),
      ]);

      console.log("Checking admin access for wallet3 (should fail)...");
      const hasAdminAccess = await checkCiphertextAccess(ctId2, {
        type: "admin",
        address: wallet3.getAddress(),
      });

      console.log(`   Result: ${hasAdminAccess}`);
      expect(hasAdminAccess).toBe(false);
    }, 60000);

    it("should allow admin to grant additional access", async () => {
      const ciphertext = await encryptValue(42n, 16);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      console.log("1. Granting admin access to wallet2...");
      const ctId2 = await updateAccess(wallet1, ctId, [
        addAdminAccess(wallet2.getAddress()),
      ]);

      console.log("2. Wallet2 granting decrypt access to wallet3...");
      const ctId3 = await updateAccess(wallet2, ctId2, [
        allowDecryptAccess(wallet3.getAddress()),
      ]);

      console.log("3. Checking decrypt access for wallet3...");
      const hasDecryptAccess = await checkCiphertextAccess(ctId3, {
        type: "decrypt",
        address: wallet3.getAddress(),
      });

      console.log(`   Result: ${hasDecryptAccess}`);
      expect(hasDecryptAccess).toBe(true);
    }, 60000);
  });

  describe("Decrypt Access", () => {
    it("should grant decrypt access and verify with checkCiphertextAccess", async () => {
      const ciphertext = await encryptValue(123n, 32);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      console.log(`\n1. Uploaded ciphertext: ${ctId}`);
      console.log(
        `2. Granting decrypt access to wallet2: ${wallet2.getAddress()}`,
      );

      const ctId2 = await updateAccess(wallet1, ctId, [
        allowDecryptAccess(wallet2.getAddress()),
      ]);

      console.log("3. Checking decrypt access for wallet2...");
      const hasDecryptAccess = await checkCiphertextAccess(ctId2, {
        type: "decrypt",
        address: wallet2.getAddress(),
      });

      console.log(`   Result: ${hasDecryptAccess}`);
      expect(hasDecryptAccess).toBe(true);
    }, 60000);

    it("should grant decrypt access and get access signature", async () => {
      const ciphertext = await encryptValue(456n, 32);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      const ctId2 = await updateAccess(wallet1, ctId, [
        allowDecryptAccess(wallet2.getAddress()),
      ]);

      console.log("Requesting decrypt access signature for wallet2...");
      const aclResponse = await getCiphertextAccessSignature(ctId2, {
        type: "decrypt",
        address: wallet2.getAddress(),
      });

      console.log(`   Signature: ${aclResponse.signature}`);
      console.log(`   Ciphertext ID: ${aclResponse.message.ciphertextId}`);

      expect(aclResponse.signature).toBeTruthy();
      expect(aclResponse.message.ciphertextId).toBe(ctId2);
    }, 60000);

    it("should deny decrypt access to non-authorized address", async () => {
      const ciphertext = await encryptValue(789n, 16);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      const ctId2 = await updateAccess(wallet1, ctId, [
        allowDecryptAccess(wallet2.getAddress()),
      ]);

      console.log("Checking decrypt access for wallet3 (should fail)...");
      const hasDecryptAccess = await checkCiphertextAccess(ctId2, {
        type: "decrypt",
        address: wallet3.getAddress(),
      });

      console.log(`   Result: ${hasDecryptAccess}`);
      expect(hasDecryptAccess).toBe(false);
    }, 60000);
  });

  describe("Run Access", () => {
    it("should grant run access and verify with checkCiphertextAccess", async () => {
      const ciphertext = await encryptValue(42n, 8);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      const programPath = join(__dirname, "fixtures/voting.spf");
      const programBytes = new Uint8Array(readFileSync(programPath));
      const libraryId = await uploadProgram(programBytes);

      console.log(`\n1. Uploaded ciphertext: ${ctId}`);
      console.log(`2. Uploaded program: ${libraryId}`);
      console.log(`3. Granting run access to wallet2 for tally_votes program`);

      const ctId2 = await updateAccess(wallet1, ctId, [
        allowRunAccess(
          wallet2.getAddress(),
          libraryId,
          asProgramName("tally_votes"),
        ),
      ]);

      console.log("4. Checking run access for wallet2...");
      const hasRunAccess = await checkCiphertextAccess(ctId2, {
        type: "run",
        address: wallet2.getAddress(),
        libraryHash: libraryId,
        entryPoint: asProgramName("tally_votes"),
      });

      console.log(`   Result: ${hasRunAccess}`);
      expect(hasRunAccess).toBe(true);
    }, 60000);

    it("should grant run access and get access signature", async () => {
      const ciphertext = await encryptValue(100n, 8);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      const programPath = join(__dirname, "fixtures/voting.spf");
      const programBytes = new Uint8Array(readFileSync(programPath));
      const libraryId = await uploadProgram(programBytes);

      const ctId2 = await updateAccess(wallet1, ctId, [
        allowRunAccess(
          wallet2.getAddress(),
          libraryId,
          asProgramName("tally_votes"),
        ),
      ]);

      console.log("Requesting run access signature for wallet2...");
      const aclResponse = await getCiphertextAccessSignature(ctId2, {
        type: "run",
        address: wallet2.getAddress(),
        libraryHash: libraryId,
        entryPoint: asProgramName("tally_votes"),
      });

      console.log(`   Signature: ${aclResponse.signature}`);
      console.log(`   Ciphertext ID: ${aclResponse.message.ciphertextId}`);

      expect(aclResponse.signature).toBeTruthy();
      expect(aclResponse.message.ciphertextId).toBe(ctId2);
    }, 60000);

    it("should deny run access to non-authorized address", async () => {
      const ciphertext = await encryptValue(42n, 8);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      const programPath = join(__dirname, "fixtures/voting.spf");
      const programBytes = new Uint8Array(readFileSync(programPath));
      const libraryId = await uploadProgram(programBytes);

      const ctId2 = await updateAccess(wallet1, ctId, [
        allowRunAccess(
          wallet2.getAddress(),
          libraryId,
          asProgramName("tally_votes"),
        ),
      ]);

      console.log("Checking run access for wallet3 (should fail)...");
      const hasRunAccess = await checkCiphertextAccess(ctId2, {
        type: "run",
        address: wallet3.getAddress(),
        libraryHash: libraryId,
        entryPoint: asProgramName("tally_votes"),
      });

      console.log(`   Result: ${hasRunAccess}`);
      expect(hasRunAccess).toBe(false);
    }, 60000);

    it("should deny run access for different program", async () => {
      const ciphertext = await encryptValue(42n, 8);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      const programPath = join(__dirname, "fixtures/voting.spf");
      const programBytes = new Uint8Array(readFileSync(programPath));
      const libraryId = await uploadProgram(programBytes);

      const ctId2 = await updateAccess(wallet1, ctId, [
        allowRunAccess(
          wallet2.getAddress(),
          libraryId,
          asProgramName("tally_votes"),
        ),
      ]);

      console.log("Checking run access for different program (should fail)...");
      const hasRunAccess = await checkCiphertextAccess(ctId2, {
        type: "run",
        address: wallet2.getAddress(),
        libraryHash: libraryId,
        entryPoint: asProgramName("different_program"),
      });

      console.log(`   Result: ${hasRunAccess}`);
      expect(hasRunAccess).toBe(false);
    }, 60000);
  });

  describe("Multiple Access Types", () => {
    it("should grant both admin and decrypt access in single update", async () => {
      const ciphertext = await encryptValue(42n, 16);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      console.log("Granting both admin and decrypt access to wallet2...");
      const ctId2 = await updateAccess(wallet1, ctId, [
        addAdminAccess(wallet2.getAddress()),
        allowDecryptAccess(wallet2.getAddress()),
      ]);

      console.log("Checking admin access for wallet2...");
      const hasAdminAccess = await checkCiphertextAccess(ctId2, {
        type: "admin",
        address: wallet2.getAddress(),
      });

      console.log("Checking decrypt access for wallet2...");
      const hasDecryptAccess = await checkCiphertextAccess(ctId2, {
        type: "decrypt",
        address: wallet2.getAddress(),
      });

      console.log(`   Admin access: ${hasAdminAccess}`);
      console.log(`   Decrypt access: ${hasDecryptAccess}`);

      expect(hasAdminAccess).toBe(true);
      expect(hasDecryptAccess).toBe(true);
    }, 60000);

    it("should grant access to multiple addresses", async () => {
      const ciphertext = await encryptValue(42n, 16);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      console.log("Granting decrypt access to both wallet2 and wallet3...");
      const ctId2 = await updateAccess(wallet1, ctId, [
        allowDecryptAccess(wallet2.getAddress()),
        allowDecryptAccess(wallet3.getAddress()),
      ]);

      console.log("Checking decrypt access for wallet2...");
      const wallet2HasAccess = await checkCiphertextAccess(ctId2, {
        type: "decrypt",
        address: wallet2.getAddress(),
      });

      console.log("Checking decrypt access for wallet3...");
      const wallet3HasAccess = await checkCiphertextAccess(ctId2, {
        type: "decrypt",
        address: wallet3.getAddress(),
      });

      console.log(`   Wallet2: ${wallet2HasAccess}`);
      console.log(`   Wallet3: ${wallet3HasAccess}`);

      expect(wallet2HasAccess).toBe(true);
      expect(wallet3HasAccess).toBe(true);
    }, 60000);
  });

  describe("Chain ID Support", () => {
    it("should check admin access with chain ID", async () => {
      const ciphertext = await encryptValue(42n, 16);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      const ctId2 = await updateAccess(wallet1, ctId, [
        addAdminAccess(wallet2.getAddress(), 1), // Grant on-chain access with chainId=1
      ]);

      console.log("Checking admin access for wallet2 with chainId=1...");
      const hasAccess = await checkCiphertextAccess(ctId2, {
        type: "admin",
        address: wallet2.getAddress(),
        chainId: 1,
      });

      console.log(`   Result: ${hasAccess}`);
      expect(hasAccess).toBe(true);
    }, 60000);

    it("should check decrypt access with chain ID", async () => {
      const ciphertext = await encryptValue(42n, 16);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      const ctId2 = await updateAccess(wallet1, ctId, [
        allowDecryptAccess(wallet2.getAddress(), 1), // Grant on-chain access with chainId=1
      ]);

      console.log("Checking decrypt access for wallet2 with chainId=1...");
      const hasAccess = await checkCiphertextAccess(ctId2, {
        type: "decrypt",
        address: wallet2.getAddress(),
        chainId: 1,
      });

      console.log(`   Result: ${hasAccess}`);
      expect(hasAccess).toBe(true);
    }, 60000);

    it("should check run access with chain ID", async () => {
      const ciphertext = await encryptValue(42n, 8);
      const ctId = await uploadCiphertext(wallet1, ciphertext);

      const programPath = join(__dirname, "fixtures/voting.spf");
      const programBytes = new Uint8Array(readFileSync(programPath));
      const libraryId = await uploadProgram(programBytes);

      const ctId2 = await updateAccess(wallet1, ctId, [
        allowRunAccess(
          wallet2.getAddress(),
          libraryId,
          asProgramName("tally_votes"),
          1, // Grant on-chain access with chainId=1
        ),
      ]);

      console.log("Checking run access for wallet2 with chainId=1...");
      const hasAccess = await checkCiphertextAccess(ctId2, {
        type: "run",
        address: wallet2.getAddress(),
        chainId: 1,
        libraryHash: libraryId,
        entryPoint: asProgramName("tally_votes"),
      });

      console.log(`   Result: ${hasAccess}`);
      expect(hasAccess).toBe(true);
    }, 60000);
  });
});
