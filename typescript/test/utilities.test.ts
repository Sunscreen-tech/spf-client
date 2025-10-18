import { describe, it, expect } from "vitest";
import { ethers } from "ethers";
import {
  createMetaData,
  encodeProgramName,
  deriveLibraryId,
  deriveCiphertextId,
  deriveResultCiphertextId,
} from "../src/spf-client.js";

describe("Basic Utilities & Encoding", () => {
  describe("createMetaData", () => {
    it("should create metaData with 0xFF padding", () => {
      const metadata = createMetaData([0x00]);
      expect(metadata).toBe(
        "0x00" + "ff".repeat(31),
      );
    });

    it("should handle multiple bytes", () => {
      const metadata = createMetaData([0x02, 16, 3]);
      expect(metadata).toMatch(/^0x021003ff/);
      expect(metadata.length).toBe(66); // 0x + 64 hex chars = 32 bytes
    });

    it("should handle plaintext metadata", () => {
      const metadata = createMetaData([0x03, 16]);
      expect(metadata).toMatch(/^0x0310ff/);
    });
  });

  describe("encodeProgramName", () => {
    it("should encode program name as bytes32", () => {
      const encoded = encodeProgramName("binary_voting");
      // "binary_voting" in hex + zeros
      expect(encoded).toMatch(/^0x62696e6172795f766f74696e67/);
      expect(encoded.length).toBe(66); // 0x + 64 hex chars
    });

    it("should pad short names with zeros", () => {
      const encoded = encodeProgramName("test");
      expect(encoded).toMatch(/^0x74657374/);
      expect(encoded).toMatch(/00+$/); // Ends with zeros
    });

    it("should throw on names too long", () => {
      const longName = "a".repeat(33);
      expect(() => encodeProgramName(longName)).toThrow(
        "Program name too long",
      );
    });
  });

  describe("deriveLibraryId", () => {
    it("should derive deterministic library ID", () => {
      const testBytes = new Uint8Array([1, 2, 3, 4, 5]);
      const id1 = deriveLibraryId(testBytes);
      const id2 = deriveLibraryId(testBytes);

      expect(id1).toBe(id2); // Deterministic
      expect(id1).toMatch(/^0x[0-9a-f]{64}$/); // 32-byte hex
      expect(id1).toBe(ethers.keccak256(testBytes)); // Matches keccak256
    });
  });

  describe("deriveCiphertextId", () => {
    it("should derive deterministic ciphertext ID", () => {
      const testBytes = new Uint8Array([10, 20, 30, 40, 50]);
      const id1 = deriveCiphertextId(testBytes);
      const id2 = deriveCiphertextId(testBytes);

      expect(id1).toBe(id2); // Deterministic
      expect(id1).toMatch(/^0x[0-9a-f]{64}$/); // 32-byte hex
    });
  });

  describe("deriveResultCiphertextId", () => {
    it("should derive result ID from run handle and index", () => {
      const runHandle =
        "0x4f7602fe26dd59529f1cb2209fb01a05f1573a80f4f3ba5a3d0034f074303e05";
      const resultId = deriveResultCiphertextId(runHandle, 0);

      expect(resultId).toMatch(/^0x[0-9a-f]{64}$/);

      // Verify formula: keccak256(runHandle || index)
      const runHandleBytes = ethers.getBytes(runHandle);
      const indexByte = new Uint8Array([0]);
      const expected = ethers.keccak256(
        ethers.concat([runHandleBytes, indexByte]),
      );
      expect(resultId).toBe(expected);
    });

    it("should handle different indices", () => {
      const runHandle =
        "0x4f7602fe26dd59529f1cb2209fb01a05f1573a80f4f3ba5a3d0034f074303e05";
      const result0 = deriveResultCiphertextId(runHandle, 0);
      const result1 = deriveResultCiphertextId(runHandle, 1);
      const result2 = deriveResultCiphertextId(runHandle, 2);

      expect(result0).not.toBe(result1);
      expect(result1).not.toBe(result2);
      expect(result0).not.toBe(result2);
    });
  });
});
