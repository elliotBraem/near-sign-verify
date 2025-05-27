import { describe, expect, it } from "vitest";
import { createMessage } from "../../src/utils/createMessage.js";

describe("createMessage - Edge Cases", () => {
  it("should handle empty string data", () => {
    const result = createMessage({
      recipient: "test.near",
      data: "", // Empty string
    });

    expect(result.message).toContain('"data":""');
    expect(result.nonce).toBeInstanceOf(Uint8Array);
    expect(result.nonce.length).toBe(32);
  });

  it("should handle null data (should be included as null)", () => {
    const result = createMessage({
      recipient: "test.near",
      data: null as any, // null is not undefined, so it gets included
    });

    const parsedMessage = JSON.parse(result.message);
    expect(parsedMessage.data).toBeNull();
    expect(result.nonce).toBeInstanceOf(Uint8Array);
  });

  it("should handle undefined data (should be excluded)", () => {
    const result = createMessage({
      recipient: "test.near",
      data: undefined,
    });

    const parsedMessage = JSON.parse(result.message);
    expect(parsedMessage.data).toBeUndefined();
    expect(result.nonce).toBeInstanceOf(Uint8Array);
  });

  it("should handle complex nested object data", () => {
    const complexData = {
      user: {
        id: 123,
        profile: {
          name: "Test User",
          settings: {
            theme: "dark",
            notifications: true,
          },
        },
      },
      actions: ["read", "write"],
      metadata: {
        timestamp: Date.now(),
        version: "1.0.0",
      },
    };

    const result = createMessage({
      recipient: "test.near",
      data: complexData,
    });

    const parsedMessage = JSON.parse(result.message);
    expect(parsedMessage.data).toEqual(complexData);
    expect(result.nonce).toBeInstanceOf(Uint8Array);
  });

  it("should handle data with special characters and unicode", () => {
    const specialData = {
      text: "Hello 世界! 🌍 Special chars: @#$%^&*()[]{}|\\:;\"'<>,.?/~`",
      emoji: "🚀🎉💯",
      unicode: "Ñoño café naïve résumé",
    };

    const result = createMessage({
      recipient: "test.near",
      data: specialData,
    });

    const parsedMessage = JSON.parse(result.message);
    expect(parsedMessage.data).toEqual(specialData);
    expect(result.nonce).toBeInstanceOf(Uint8Array);
  });

  it("should handle very long recipient names", () => {
    const longRecipient = "a".repeat(100) + ".near";

    const result = createMessage({
      recipient: longRecipient,
      data: "test",
    });

    const parsedMessage = JSON.parse(result.message);
    expect(parsedMessage.recipient).toBe(longRecipient);
    expect(result.nonce).toBeInstanceOf(Uint8Array);
  });

  it("should handle data with circular references gracefully", () => {
    const circularData: any = { name: "test" };
    circularData.self = circularData; // Create circular reference

    // This should throw an error due to circular reference in JSON.stringify
    expect(() => createMessage({
      recipient: "test.near",
      data: circularData,
    })).toThrow();
  });

  it("should preserve exact timestamp precision", () => {
    const result1 = createMessage({
      recipient: "test.near",
      data: "test1",
    });

    // Small delay to ensure different timestamps
    const start = Date.now();
    while (Date.now() === start) {
      // Wait for at least 1ms difference
    }

    const result2 = createMessage({
      recipient: "test.near",
      data: "test2",
    });

    const message1 = JSON.parse(result1.message);
    const message2 = JSON.parse(result2.message);

    expect(message1.timestamp).not.toBe(message2.timestamp);
    expect(message2.timestamp).toBeGreaterThan(message1.timestamp);
  });

  it("should handle array data", () => {
    const arrayData = [1, "two", { three: 3 }, [4, 5]];

    const result = createMessage({
      recipient: "test.near",
      data: arrayData,
    });

    const parsedMessage = JSON.parse(result.message);
    expect(parsedMessage.data).toEqual(arrayData);
    expect(result.nonce).toBeInstanceOf(Uint8Array);
  });

  it("should handle object data with boolean and number values", () => {
    const objectWithPrimitives = {
      booleanValue: true,
      numberValue: 42,
      stringValue: "test",
    };

    const result = createMessage({
      recipient: "test.near",
      data: objectWithPrimitives,
    });

    const parsedMessage = JSON.parse(result.message);
    expect(parsedMessage.data).toEqual(objectWithPrimitives);
    expect(parsedMessage.data.booleanValue).toBe(true);
    expect(parsedMessage.data.numberValue).toBe(42);
  });
});
