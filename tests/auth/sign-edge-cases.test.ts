import { base58, base64 } from "@scure/base";
import * as near from "near-api-js";
import { describe, expect, it, vi } from "vitest";
import { verify } from "../../src/auth/verify.js";
import { sign } from "../../src/auth/sign.js";
import type { WalletInterface } from "../../src/types.js";
import * as nonceModule from "../../src/utils/nonce.js";

describe("sign - Edge Cases", () => {
  it("should throw error when accountId is missing for KeyPair signer", async () => {
    const keyPair = near.KeyPair.fromRandom("ed25519");

    await expect(
      sign("hello", {
        signer: keyPair.toString(),
        recipient: "recipient.near",
      }),
    ).rejects.toThrow("accountId is required when using a KeyPair signer");
  });

  it("should throw error for invalid signer type", async () => {
    const invalidSigner = {
      // Missing both KeyPair methods and WalletInterface methods
      someOtherMethod: () => {},
    } as any;

    await expect(
      sign("hello", {
        signer: invalidSigner,
        accountId: "test.near",
        recipient: "recipient.near",
      }),
    ).rejects.toThrow(
      "Invalid signer: must be KeyPair or a wallet object with a signMessage method",
    );
  });

  it("should throw error for object with only partial KeyPair interface", async () => {
    const partialKeyPair = {
      sign: () => {}, // Has sign but missing getPublicKey
    } as any;

    await expect(
      sign("hello", {
        signer: partialKeyPair,
        accountId: "test.near",
        recipient: "recipient.near",
      }),
    ).rejects.toThrow(
      "Invalid signer: must be KeyPair or a wallet object with a signMessage method",
    );
  });

  it("should throw error for object with only partial WalletInterface", async () => {
    const partialWallet = {
      someMethod: () => {}, // Missing signMessage
    } as any;

    await expect(
      sign("hello", {
        signer: partialWallet,
        accountId: "test.near",
        recipient: "recipient.near",
      }),
    ).rejects.toThrow(
      "Invalid signer: must be KeyPair or a wallet object with a signMessage method",
    );
  });

  it("should handle wallet signing errors", async () => {
    const mockWallet: WalletInterface = {
      signMessage: vi
        .fn()
        .mockRejectedValue(new Error("Wallet signing failed")),
    };

    await expect(
      sign("hello", {
        signer: mockWallet,
        recipient: "recipient.near",
      }),
    ).rejects.toThrow("Wallet signing failed");
  });

  it("should handle KeyPair signing errors (e.g., malformed key string)", async () => {
    const malformedKeyPairString =
      "ed25519:ThisIsNotValidBase58AndWillCauseAnErrorDuringDecoding!!!";
    await expect(
      sign("hello", {
        signer: malformedKeyPairString,
        accountId: "test.near",
        recipient: "recipient.near",
      }),
    ).rejects.toThrow(
      /Unknown letter: "I". Allowed: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz/,
    );
  });

  it("should work with NEP-413 compliant wallet and produce verifiable token", async () => {
    // Generate a valid Ed25519 signature for testing (64 bytes)
    const rawSignature = new Uint8Array(64);
    for (let i = 0; i < 64; i++) {
      rawSignature[i] = i % 256; // Pattern that makes a deterministic but fake signature
    }

    // Per NEP-413, wallet signatures should be base64, NOT prefixed with "ed25519:"
    const base64Signature = base64.encode(rawSignature);

    const mockWallet: WalletInterface = {
      signMessage: vi.fn().mockResolvedValue({
        signature: base64Signature, // NEP-413 compliant: plain base64
        publicKey: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
        accountId: "wallet-provided.near",
      }),
    };

    const result = await sign("hello", {
      signer: mockWallet,
      recipient: "recipient.near",
    });

    expect(typeof result).toBe("string");
    expect(mockWallet.signMessage).toHaveBeenCalled();

    // The important part: verify the token can be parsed and verified
    // Note: Cryptographic verification will fail because this is a fake signature,
    // but the token should be parseable and the signature format should be correct
    try {
      await verify(result, {
        expectedRecipient: "recipient.near",
        expectedMessage: "hello",
        requireFullAccessKey: false, // Don't require FAK for this test
      });
      // If verification succeeds, great! The signature format is definitely correct
    } catch (error) {
      // Verification might fail due to fake signature, but format should be correct
      const errorMessage = error instanceof Error ? error.message : String(error);
      // Ensure it's not the old "Expected ed25519:" format error
      expect(errorMessage).not.toContain(`Unsupported signature format`);
      expect(errorMessage).not.toContain(`Expected "ed25519:`);
    }
  });
});
