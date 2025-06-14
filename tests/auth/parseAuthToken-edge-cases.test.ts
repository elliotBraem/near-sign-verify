import { describe, expect, it } from "vitest";
import { parseAuthToken } from "../../src/auth/parseAuthToken.js";
import { base64 } from "@scure/base";

describe("parseAuthToken - Edge Cases", () => {
  it("should handle invalid base64 token format", () => {
    const invalidToken = "not-valid-base64!@#";

    expect(() => parseAuthToken(invalidToken)).toThrow("Invalid auth token:");
  });

  it("should handle completely malformed tokens", () => {
    // Create invalid base64 that doesn't represent valid zorsh data
    const malformedToken = base64.encode(new Uint8Array([1, 2, 3, 4, 5]));

    expect(() => parseAuthToken(malformedToken)).toThrow("Invalid auth token:");
  });

  it("should handle non-Error exceptions", () => {
    // Create an invalid token that will cause a non-Error exception
    const invalidToken = "not-valid-base64-!@#$%";

    expect(() => parseAuthToken(invalidToken)).toThrow("Invalid auth token:");
  });

  it("should handle empty token", () => {
    expect(() => parseAuthToken("")).toThrow("Invalid auth token:");
  });

  it("should handle malformed base64", () => {
    const malformedBase64 = "SGVsbG8gV29ybGQ!"; // Invalid base64 character
    expect(() => parseAuthToken(malformedBase64)).toThrow(
      "Invalid auth token:",
    );
  });
});
