import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import {
  initialize,
  uploadProgram,
  downloadProgram,
  deriveLibraryId,
} from "../src/spf-client.js";
import { TEST_ENDPOINT } from "./test-config.js";

describe("Program Operations", () => {
  beforeAll(async () => {
    await initialize(TEST_ENDPOINT);
  });
  let programBytes: Uint8Array;
  let expectedLibraryId: string;
  let uploadedLibraryId: string;

  it("should load voting program from fixtures", () => {
    const programPath = join(__dirname, "fixtures/voting.spf");
    programBytes = new Uint8Array(readFileSync(programPath));

    expect(programBytes.length).toBeGreaterThan(0);
    console.log(`Loaded program: ${programBytes.length} bytes`);
  });

  it("should compute expected library ID", () => {
    expectedLibraryId = deriveLibraryId(programBytes);

    expect(expectedLibraryId).toMatch(/^0x[0-9a-f]{64}$/);
    console.log(`Expected library ID: ${expectedLibraryId}`);
  });

  it("should upload program to SPF service", async () => {
    uploadedLibraryId = await uploadProgram(programBytes);

    expect(uploadedLibraryId).toMatch(/^0x[0-9a-f]{64}$/);
    console.log(`Uploaded library ID: ${uploadedLibraryId}`);
  });

  it("should verify library ID matches expected hash", () => {
    expect(uploadedLibraryId.toLowerCase()).toBe(
      expectedLibraryId.toLowerCase(),
    );
  });

  it("should download program from SPF service", async () => {
    const downloadedBytes = await downloadProgram(uploadedLibraryId);

    expect(downloadedBytes.length).toBe(programBytes.length);
    console.log(`Downloaded program: ${downloadedBytes.length} bytes`);
  });

  it("should verify downloaded bytes match original", async () => {
    const downloadedBytes = await downloadProgram(uploadedLibraryId);

    // Compare byte by byte
    expect(downloadedBytes.length).toBe(programBytes.length);
    for (let i = 0; i < programBytes.length; i++) {
      expect(downloadedBytes[i]).toBe(programBytes[i]);
    }
  });

  it("should handle download of non-existent program", async () => {
    const fakeId =
      "0x0000000000000000000000000000000000000000000000000000000000000000";

    await expect(downloadProgram(fakeId)).rejects.toThrow();
  });
});
