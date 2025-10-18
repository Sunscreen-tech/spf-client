import { describe, it, expect, beforeAll } from "vitest";
import { ethers } from "ethers";
import { sha256 } from "@noble/hashes/sha2";
import {
  encodeExternalAddress,
  encodeTimestamp,
  createMessageToSign,
  createIdentityHeader,
  PrivateKeySigner,
} from "../src/spf-client.js";

describe("Authentication System", () => {
  let wallet: PrivateKeySigner;

  beforeAll(() => {
    // Generate test wallet dynamically
    wallet = PrivateKeySigner.random();
  });

  describe("encodeExternalAddress", () => {
    it("should encode address in 33-byte format", () => {
      const address = wallet.getAddress();
      const encoded = encodeExternalAddress(address);

      expect(encoded.length).toBe(33);
      expect(encoded[0]).toBe(0x01); // External address type

      // Bytes 1-12 should be zeros (padding)
      for (let i = 1; i <= 12; i++) {
        expect(encoded[i]).toBe(0);
      }

      // Bytes 13-32 should be the address
      const addressBytes = ethers.getBytes(address);
      for (let i = 0; i < 20; i++) {
        expect(encoded[13 + i]).toBe(addressBytes[i]);
      }
    });
  });

  describe("encodeTimestamp", () => {
    it("should encode timestamp as 8-byte big-endian", () => {
      const timestamp = 1234567890123;
      const encoded = encodeTimestamp(timestamp);

      expect(encoded.length).toBe(8);

      // Verify big-endian encoding
      const view = new DataView(encoded.buffer);
      const decoded = view.getBigUint64(0, false); // false = big-endian
      expect(Number(decoded)).toBe(timestamp);
    });

    it("should handle small timestamps", () => {
      const timestamp = 1000;
      const encoded = encodeTimestamp(timestamp);

      expect(encoded.length).toBe(8);

      const view = new DataView(encoded.buffer);
      const decoded = view.getBigUint64(0, false);
      expect(Number(decoded)).toBe(timestamp);
    });
  });

  describe("createMessageToSign", () => {
    it("should concatenate address + timestamp + body", async () => {
      const address = wallet.getAddress();
      const timestamp = 1234567890;
      const body = new Uint8Array([1, 2, 3, 4, 5]);

      const message = await createMessageToSign(address, timestamp, body);

      // Should be 33 + 8 + 5 = 46 bytes
      expect(message.length).toBe(33 + 8 + 5);

      // Verify first byte is 0x01 (external address)
      expect(message[0]).toBe(0x01);

      // Verify last 5 bytes are the body
      expect(message.slice(-5)).toEqual(body);
    });

    it("should handle empty body", async () => {
      const address = wallet.getAddress();
      const message = await createMessageToSign(address, 1000, new Uint8Array(0));

      // Should be 33 + 8 + 0 = 41 bytes
      expect(message.length).toBe(41);
    });
  });

  describe("createIdentityHeader", () => {
    it("should create valid base64-encoded identity header", async () => {
      const body = new Uint8Array([1, 2, 3]);
      const header = await createIdentityHeader(wallet, body);

      // Should be base64
      expect(typeof header).toBe("string");
      expect(header.length).toBeGreaterThan(0);

      // Decode and verify structure
      const decoded = JSON.parse(Buffer.from(header, "base64").toString());

      expect(decoded.entity.entity_type).toBe("external_address");
      expect(decoded.entity.addr.toLowerCase()).toBe(
        wallet.getAddress().toLowerCase(),
      );
      expect(typeof decoded.timestamp_millis).toBe("number");
      expect(decoded.signature.signature_type).toBe("raw_ecdsa");
      expect(decoded.signature.value).toMatch(/^0x[0-9a-f]+$/);
    });

    it("should create valid signatures", async () => {
      const body = new Uint8Array([10, 20, 30]);
      const header = await createIdentityHeader(wallet, body);

      // Decode the header
      const decoded = JSON.parse(Buffer.from(header, "base64").toString());

      // Recreate the message
      const message = await createMessageToSign(
        decoded.entity.addr,
        decoded.timestamp_millis,
        body,
      );

      // Verify signature
      const recovered = ethers.recoverAddress(sha256(message), decoded.signature.value);
      expect(recovered.toLowerCase()).toBe(wallet.getAddress().toLowerCase());
    });

    it("should handle empty request body", async () => {
      const emptyBody = new Uint8Array(0);
      const header = await createIdentityHeader(wallet, emptyBody);

      const decoded = JSON.parse(Buffer.from(header, "base64").toString());
      expect(decoded.entity.addr.toLowerCase()).toBe(
        wallet.getAddress().toLowerCase(),
      );
    });
  });
});
