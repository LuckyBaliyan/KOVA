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
      phone: z
            .string()
            .trim()
            .regex(/^[+0-9\s-]{8,15}$/, "Invalid phone number")
            .optional()
            .or(z.literal("")),
});


export const LoginSchema = z.object({
      email: z.string().trim().toLowerCase().email("Invalid email address"),
      password: z.string().min(1, "Password is required"),
});

export type RegisterUserInput = z.infer<typeof RegisterUserSchema>;
export type LoginInput = z.infer<typeof LoginSchema>;