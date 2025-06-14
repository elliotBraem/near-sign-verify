import { base58 } from "@scure/base";
import * as near from "near-api-js";
import { describe, expect, it, vi } from "vitest";
import { sign } from "../../src/auth/sign.js";
import type { WalletInterface } from "../../src/types.js";

describe("sign - Edge Cases", () => {
  it("should throw error when accountId is missing for KeyPair signer", async () => {
    const keyPair = near.KeyPair.fromRandom("ed25519");

    await expect(
      sign({
        signer: keyPair.toString(),
        message: "hello",
        recipient: "recipient.near",
      }),
    ).rejects.toThrow("accountId is required when using a KeyPair signer");
  });

  it("should throw error for invalid signer type", async () => {
    const invalidSigner = {
      // Missing both KeyPair methods and WalletInterface methods
      someOtherMethod: () => { },
    } as any;

    await expect(
      sign({
        signer: invalidSigner,
        accountId: "test.near",
        message: "hello",
        recipient: "recipient.near",
      }),
    ).rejects.toThrow(
      "Invalid signer: must be KeyPair or a wallet object with a signMessage method",
    );
  });

  it("should throw error for object with only partial KeyPair interface", async () => {
    const partialKeyPair = {
      sign: () => { }, // Has sign but missing getPublicKey
    } as any;

    await expect(
      sign({
        signer: partialKeyPair,
        accountId: "test.near",
        message: "hello",
        recipient: "recipient.near",
      }),
    ).rejects.toThrow(
      "Invalid signer: must be KeyPair or a wallet object with a signMessage method",
    );
  });

  it("should throw error for object with only partial WalletInterface", async () => {
    const partialWallet = {
      someMethod: () => { }, // Missing signMessage
    } as any;

    await expect(
      sign({
        signer: partialWallet,
        accountId: "test.near",
        message: "hello",
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
      sign({
        signer: mockWallet,
        recipient: "recipient.near",
        message: "hello",
      }),
    ).rejects.toThrow("Wallet signing failed");
  });

  it("should handle KeyPair signing errors (e.g., malformed key string)", async () => {
    const malformedKeyPairString =
      "ed25519:ThisIsNotValidBase58AndWillCauseAnErrorDuringDecoding!!!";
    await expect(
      sign({
        signer: malformedKeyPairString,
        accountId: "test.near",
        message: "hello",
        recipient: "recipient.near",
      }),
    ).rejects.toThrow(/Unknown letter: "I". Allowed: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz/);
  });

  it("should work with wallet that provides accountId", async () => {
    const rawSignature = new Uint8Array(64).fill(1);
    const base58Signature = base58.encode(rawSignature);
    const mockWallet: WalletInterface = {
      signMessage: vi.fn().mockResolvedValue({
        signature: `ed25519:${base58Signature}`,
        publicKey: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
        accountId: "wallet-provided.near",
      }),
    };

    const result = await sign({
      signer: mockWallet,
      message: "hello",
      recipient: "recipient.near",
    });

    expect(typeof result).toBe("string");
    expect(mockWallet.signMessage).toHaveBeenCalled();
  });
});
