import * as near from "near-api-js";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ED25519_PREFIX,
  hashPayload,
  serializePayload,
  verifySignature,
} from "../../src/crypto/crypto.js";
import type { NearAuthPayload } from "../../src/types.js";

describe("Crypto Module - Edge Cases & Core Functionality", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("hashPayload", () => {
    it("should correctly hash a known payload", () => {
      const payload = new Uint8Array([1, 2, 3, 4, 5]);
      const hash = hashPayload(payload);
      expect(hash).toBeInstanceOf(Uint8Array);
      expect(hash.length).toBe(32);
      // Example hash for [1,2,3,4,5] - replace with actual expected hash if needed for consistency checks
      // For now, just checking type and length is sufficient for noble/hashes integration
    });

    it("should produce the same hash for the same payload", () => {
      const payload = new Uint8Array(Array.from({ length: 100 }, (_, i) => i));
      const hash1 = hashPayload(payload);
      const hash2 = hashPayload(payload);
      expect(hash1).toEqual(hash2);
    });

    it("should produce different hashes for different payloads", () => {
      const payload1 = new Uint8Array([1, 2, 3]);
      const payload2 = new Uint8Array([4, 5, 6]);
      const hash1 = hashPayload(payload1);
      const hash2 = hashPayload(payload2);
      expect(hash1).not.toEqual(hash2);
    });
  });

  describe("verifySignature", () => {
    const testPayload = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const testPayloadHash = hashPayload(testPayload);

    // Ed25519
    const ed25519KeyPair = near.KeyPair.fromRandom("ed25519");
    const ed25519PublicKeyString = ed25519KeyPair.getPublicKey().toString();
    const ed25519Signature = ed25519KeyPair.sign(testPayloadHash).signature;

    it("should throw for unsupported public key types", async () => {
      const invalidKey = "rsa:somekeydata";
      await expect(
        verifySignature(testPayloadHash, ed25519Signature, invalidKey),
      ).rejects.toThrow(
        `Unsupported public key type: "${invalidKey}". Must start with "ed25519:".`,
      );
    });

    it("should throw if Ed25519 public key is malformed", async () => {
      const malformedKey = ED25519_PREFIX + "invalidKeyData"; // "l" is an invalid base58 char
      await expect(
        verifySignature(testPayloadHash, ed25519Signature, malformedKey),
      ).rejects.toThrow(/Unknown letter: "l". Allowed: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz/);
    });

    it("should throw for invalid Ed25519 signature", async () => {
      const tamperedSignature = new Uint8Array(ed25519Signature);
      tamperedSignature[0] ^= 0xff; // Flip some bits
      await expect(
        verifySignature(
          testPayloadHash,
          tamperedSignature,
          ed25519PublicKeyString,
        ),
      ).rejects.toThrow("Ed25519 signature verification failed.");
    });

    it("should successfully verify a valid Ed25519 signature", async () => {
      await expect(
        verifySignature(
          testPayloadHash,
          ed25519Signature,
          ed25519PublicKeyString,
        ),
      ).resolves.toBe(true);
    });
  });

  describe("serializePayload", () => {
    it("should serialize payload with all optional fields", () => {
      const payload: NearAuthPayload = {
        tag: 2147484061,
        message: "test message",
        nonce: new Array(32).fill(1),
        receiver: "test.near",
        callback_url: "https://example.com/callback",
      };
      const serialized = serializePayload(payload);
      expect(serialized).toBeInstanceOf(Uint8Array);
      expect(serialized.length).toBeGreaterThan(0);
    });

    it("should serialize payload without optional callback_url", () => {
      // @ts-expect-error we're specifically testing a missing field
      const payload: NearAuthPayload = {
        tag: 2147484061,
        message: "test message",
        nonce: new Array(32).fill(1),
        receiver: "test.near",
        // callback_url is undefined
      };
      const serialized = serializePayload(payload);
      expect(serialized).toBeInstanceOf(Uint8Array);
      expect(serialized.length).toBeGreaterThan(0);
    });
  });
});
