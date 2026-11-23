import { z } from "zod";

export const RegisterUserSchema = z.object({
      fullName: z
            .string()
            .trim()
            .min(2, "Full name must be at least 2 characters")
            .max(60, "Full name is too long"),
      email: z.string().trim().toLowerCase().email("Invalid email address"),
      password: z
            .string()
            .min(8, "Password must be at least 8 characters")
            .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
            .regex(/[0-9]/, "Password must contain at least one number"),
});

export type RegisterUserInput = z.infer<typeof RegisterUserSchema>;