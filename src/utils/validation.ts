import { z } from "zod";

export const createValidationErrorMessage = (validationError: z.ZodError) =>
  validationError.issues
    .map((issue) => `${issue.path.join(".")}: ${issue.message}`)
    .join(", ");
