import { describe, expect, it, vi } from "vitest";
import { sign } from "../../src/auth/sign.js";
import { KeyPair } from "@near-js/crypto";
import type { WalletInterface } from "../../src/types.js";

describe("sign - Edge Cases", () => {
  it("should throw error when accountId is missing for KeyPair signer", async () => {
    const keyPair = KeyPair.fromRandom("ed25519");

    await expect(sign({
      signer: keyPair.toString(),
      // accountId missing
      recipient: "recipient.near",
    })).rejects.toThrow("accountId is required when using a KeyPair signer");
  });

  it("should throw error for invalid signer type", async () => {
    const invalidSigner = {
      // Missing both KeyPair methods and WalletInterface methods
      someOtherMethod: () => {},
    } as any;

    await expect(sign({
      signer: invalidSigner,
      accountId: "test.near",
      recipient: "recipient.near",
    })).rejects.toThrow("Invalid signer: must be KeyPair or a wallet object with a signMessage method");
  });

  it("should throw error for object with only partial KeyPair interface", async () => {
    const partialKeyPair = {
      sign: () => {}, // Has sign but missing getPublicKey
    } as any;

    await expect(sign({
      signer: partialKeyPair,
      accountId: "test.near",
      recipient: "recipient.near",
    })).rejects.toThrow("Invalid signer: must be KeyPair or a wallet object with a signMessage method");
  });

  it("should throw error for object with only partial WalletInterface", async () => {
    const partialWallet = {
      someMethod: () => {}, // Missing signMessage
    } as any;

    await expect(sign({
      signer: partialWallet,
      accountId: "test.near",
      recipient: "recipient.near",
    })).rejects.toThrow("Invalid signer: must be KeyPair or a wallet object with a signMessage method");
  });

  it("should handle wallet signing errors", async () => {
    const mockWallet: WalletInterface = {
      signMessage: vi.fn().mockRejectedValue(new Error("Wallet signing failed")),
    };

    await expect(sign({
      signer: mockWallet,
      recipient: "recipient.near",
    })).rejects.toThrow("Wallet signing failed");
  });

  it("should handle KeyPair signing errors", async () => {
    const mockKeyPair = {
      sign: vi.fn().mockImplementation(() => {
        throw new Error("KeyPair signing failed");
      }),
      getPublicKey: vi.fn().mockReturnValue({
        toString: () => "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
      }),
    } as any;

    await expect(sign({
      signer: mockKeyPair,
      accountId: "test.near",
      recipient: "recipient.near",
    })).rejects.toThrow("KeyPair signing failed");
  });

  it("should work with wallet that provides accountId", async () => {
    const mockWallet: WalletInterface = {
      signMessage: vi.fn().mockResolvedValue({
        signature: new Uint8Array(64).fill(1),
        publicKey: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
        accountId: "wallet-provided.near",
      }),
    };

    const result = await sign({
      signer: mockWallet,
      recipient: "recipient.near",
    });

    expect(typeof result).toBe("string");
    expect(mockWallet.signMessage).toHaveBeenCalled();
  });
});
