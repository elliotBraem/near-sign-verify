import { describe, expect, it } from "vitest";
import { createValidationErrorMessage } from "../../src/utils/validation.js";
import { z } from "zod";

describe("validation", () => {
  it("should format single validation error", () => {
    const schema = z.object({
      name: z.string(),
      age: z.number(),
    });

    try {
      schema.parse({ name: "John", age: "not-a-number" });
    } catch (error) {
      if (error instanceof z.ZodError) {
        const message = createValidationErrorMessage(error);
        expect(message).toContain("age:");
        expect(message).toContain("Expected number, received string");
      }
    }
  });

  it("should format multiple validation errors", () => {
    const schema = z.object({
      name: z.string(),
      age: z.number(),
      email: z.string().email(),
    });

    try {
      schema.parse({
        name: 123, // Should be string
        age: "not-a-number", // Should be number
        email: "invalid-email", // Should be valid email
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        const message = createValidationErrorMessage(error);
        expect(message).toContain("name:");
        expect(message).toContain("age:");
        expect(message).toContain("email:");
        // Zod may generate additional validation errors, so check for at least 3
        expect(message.split(", ").length).toBeGreaterThanOrEqual(3);
      }
    }
  });

  it("should handle nested object validation errors", () => {
    const schema = z.object({
      user: z.object({
        profile: z.object({
          name: z.string(),
        }),
      }),
    });

    try {
      schema.parse({
        user: {
          profile: {
            name: 123, // Should be string
          },
        },
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        const message = createValidationErrorMessage(error);
        expect(message).toContain("user.profile.name:");
        expect(message).toContain("Expected string, received number");
      }
    }
  });

  it("should handle array validation errors", () => {
    const schema = z.object({
      items: z.array(z.string()),
    });

    try {
      schema.parse({
        items: ["valid", 123, "also-valid"], // Middle item should be string
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        const message = createValidationErrorMessage(error);
        expect(message).toContain("items.1:");
        expect(message).toContain("Expected string, received number");
      }
    }
  });

  it("should handle empty path validation errors", () => {
    const schema = z.string();

    try {
      schema.parse(123); // Should be string
    } catch (error) {
      if (error instanceof z.ZodError) {
        const message = createValidationErrorMessage(error);
        expect(message).toContain(": Expected string, received number");
      }
    }
  });
});
