import { describe, it, expect } from "vitest";
import { ethers } from "ethers";
import {
  createCiphertextParameter,
  createCiphertextArrayParameter,
  createOutputCiphertextArrayParameter,
  createPlaintextParameter,
  createPlaintextArrayParameter,
  encodeSpfRun,
  createMetaData,
} from "../src/spf-client.js";

describe("SpfParameter Encoding", () => {
  describe("createCiphertextParameter", () => {
    it("should create type 0 parameter with single ciphertext", () => {
      const ciphertextId =
        "0xb1f6efd65778acb7a92b49034467ea6abedc9af4ce198ded85ddfd13fe45039d";
      const [param] = createCiphertextParameter(ciphertextId);

      expect(param.metaData).toBe(createMetaData([0x00]));
      expect(param.payload).toEqual([ciphertextId]);
      expect(param.payload.length).toBe(1);
    });
  });

  describe("createCiphertextArrayParameter", () => {
    it("should create type 1 parameter with multiple ciphertexts", () => {
      const ciphertextIds = [
        "0xb1f6efd65778acb7a92b49034467ea6abedc9af4ce198ded85ddfd13fe45039d",
        "0x4e27107de8cf8be7b48c3bc32f85739e2d8141eebd4e8144c722772530fb3054",
        "0x1d833c57b9b3129ce94c091b863f6021ca7cc83f4b985bf4f6ddb0165eb27c6e",
      ];
      const [param] = createCiphertextArrayParameter(ciphertextIds);

      expect(param.metaData).toBe(createMetaData([0x01]));
      expect(param.payload).toEqual(ciphertextIds);
      expect(param.payload.length).toBe(3);
    });

    it("should handle empty array", () => {
      const [param] = createCiphertextArrayParameter([]);
      expect(param.payload.length).toBe(0);
    });
  });

  describe("createOutputCiphertextArrayParameter", () => {
    it("should create type 2 parameter with bitWidth and size", () => {
      const [param] = createOutputCiphertextArrayParameter(16, 1);

      expect(param.metaData).toBe(createMetaData([0x02, 16, 1]));
      expect(param.payload).toEqual([]);
    });

    it("should support different bit widths", () => {
      const [param8] = createOutputCiphertextArrayParameter(8, 1);
      const [param16] = createOutputCiphertextArrayParameter(16, 1);
      const [param32] = createOutputCiphertextArrayParameter(32, 1);
      const [param64] = createOutputCiphertextArrayParameter(64, 1);

      expect(param8.metaData).toBe(createMetaData([0x02, 8, 1]));
      expect(param16.metaData).toBe(createMetaData([0x02, 16, 1]));
      expect(param32.metaData).toBe(createMetaData([0x02, 32, 1]));
      expect(param64.metaData).toBe(createMetaData([0x02, 64, 1]));
    });

    it("should support different sizes", () => {
      const [param] = createOutputCiphertextArrayParameter(16, 5);
      expect(param.metaData).toBe(createMetaData([0x02, 16, 5]));
    });

    it("should reject invalid bit widths", () => {
      expect(() => createOutputCiphertextArrayParameter(12 as any, 1)).toThrow(
        "Invalid bit width: 12. Must be 8, 16, 32, or 64",
      );
    });

    it("should reject invalid sizes", () => {
      expect(() => createOutputCiphertextArrayParameter(16, 0)).toThrow(
        "size must be between 1 and 255",
      );
      expect(() => createOutputCiphertextArrayParameter(16, 256)).toThrow(
        "size must be between 1 and 255",
      );
    });
  });

  describe("createPlaintextParameter", () => {
    it("should create type 3 parameter with value", () => {
      const [param] = createPlaintextParameter(16, 42);

      expect(param.metaData).toBe(createMetaData([0x03, 16]));
      expect(param.payload.length).toBe(1);

      // Verify value is encoded in lower 16 bytes
      const value = ethers.toBigInt(param.payload[0]);
      expect(Number(value)).toBe(42);
    });

    it("should handle large values", () => {
      const [param] = createPlaintextParameter(64, 1234567890n);

      const value = ethers.toBigInt(param.payload[0]);
      expect(value).toBe(1234567890n);
    });

    it("should support different bit widths", () => {
      const [param8] = createPlaintextParameter(8, 255);
      const [param16] = createPlaintextParameter(16, 65535);
      const [param32] = createPlaintextParameter(32, 4294967295);
      const [param64] = createPlaintextParameter(64, 18446744073709551615n);

      expect(param8.metaData).toBe(createMetaData([0x03, 8]));
      expect(param16.metaData).toBe(createMetaData([0x03, 16]));
      expect(param32.metaData).toBe(createMetaData([0x03, 32]));
      expect(param64.metaData).toBe(createMetaData([0x03, 64]));
    });

    it("should reject invalid bit widths", () => {
      expect(() => createPlaintextParameter(12 as any, 42)).toThrow(
        "Invalid bit width: 12. Must be 8, 16, 32, or 64",
      );
    });
  });

  describe("createPlaintextArrayParameter", () => {
    it("should create type 4 parameter with multiple values", () => {
      const values = [10, 20, 30];
      const [param] = createPlaintextArrayParameter(16, values);

      expect(param.metaData).toBe(createMetaData([0x04, 16]));
      expect(param.payload.length).toBe(3);

      // Verify each value
      const decodedValues = param.payload.map((p) => Number(ethers.toBigInt(p)));
      expect(decodedValues).toEqual([10, 20, 30]);
    });

    it("should reject empty array", () => {
      expect(() => createPlaintextArrayParameter(16, [])).toThrow(
        "PlaintextArray parameter must have at least 1 plaintext value",
      );
    });

    it("should handle bigint values", () => {
      const values = [1n, 2n, 3n];
      const [param] = createPlaintextArrayParameter(64, values);

      const decodedValues = param.payload.map((p) => ethers.toBigInt(p));
      expect(decodedValues).toEqual([1n, 2n, 3n]);
    });

    it("should reject invalid bit widths", () => {
      expect(() => createPlaintextArrayParameter(12 as any, [1, 2, 3])).toThrow(
        "Invalid bit width: 12. Must be 8, 16, 32, or 64",
      );
    });
  });

  describe("encodeSpfRun", () => {
    it("should encode SpfRun with mixed parameter types", () => {
      const libraryId =
        "0x4f7602fe26dd59529f1cb2209fb01a05f1573a80f4f3ba5a3d0034f074303e05";
      const programName = "binary_voting";

      const parametersWithAuth = [
        createCiphertextArrayParameter([
          "0xb1f6efd65778acb7a92b49034467ea6abedc9af4ce198ded85ddfd13fe45039d",
          "0x4e27107de8cf8be7b48c3bc32f85739e2d8141eebd4e8144c722772530fb3054",
        ]),
        createPlaintextParameter(16, 2),
        createOutputCiphertextArrayParameter(16, 1),
      ];

      // Extract just the parameters (first element of each tuple)
      const parameters = parametersWithAuth.map(([param]) => param);

      const encoded = encodeSpfRun(libraryId, programName, parameters);

      // Should be valid hex string
      expect(encoded).toMatch(/^0x[0-9a-f]+$/);
      expect(encoded.length).toBeGreaterThan(0);

      // Decode and verify structure
      const abiCoder = ethers.AbiCoder.defaultAbiCoder();
      const types = [
        "tuple(bytes32 spfLibrary, bytes32 program, tuple(uint256 metaData, bytes32[] payload)[] parameters)",
      ];
      const decoded = abiCoder.decode(types, encoded);

      expect(decoded[0].spfLibrary).toBe(libraryId);
      expect(decoded[0].parameters.length).toBe(3);
    });

    it("should encode SpfRun with no parameters", () => {
      const libraryId =
        "0x4f7602fe26dd59529f1cb2209fb01a05f1573a80f4f3ba5a3d0034f074303e05";
      const programName = "test";

      const encoded = encodeSpfRun(libraryId, programName, []);

      expect(encoded).toMatch(/^0x[0-9a-f]+$/);

      // Decode and verify
      const abiCoder = ethers.AbiCoder.defaultAbiCoder();
      const types = [
        "tuple(bytes32 spfLibrary, bytes32 program, tuple(uint256 metaData, bytes32[] payload)[] parameters)",
      ];
      const decoded = abiCoder.decode(types, encoded);

      expect(decoded[0].parameters.length).toBe(0);
    });
  });
});
